import crypto from "crypto";
import { Request, Response as ExpressResponse } from "express";
import { extractApiKey } from "../api-key";
import { Config, isDebugLevel } from "../config";
import {
  AccountFailureKind,
  AccountManager,
  UsageData,
} from "../accounts/manager";
import { applyCloaking, uncloakToolName } from "./cloaking";
import { callClaudeAPI, callClaudeCountTokens } from "./claude-api";

/**
 * Walk a non-stream Claude response and revert any tool_use names that were
 * cloaked outbound by applyCloaking. The client only ever sees original names.
 */
function uncloakResponseInPlace(data: any): void {
  if (!data || !Array.isArray(data.content)) return;
  for (const block of data.content) {
    if (block && block.type === "tool_use" && typeof block.name === "string") {
      block.name = uncloakToolName(block.name);
    }
  }
}

/**
 * Rewrite a single SSE `data:` line if it carries a content_block_start with
 * a cloaked tool_use name. Returns the original line untouched if there's
 * nothing to rewrite (or the line isn't valid JSON we recognize).
 */
function uncloakSseDataLine(line: string): string {
  if (!line.startsWith("data:")) return line;
  const raw = line.slice(5).trim();
  if (!raw || raw === "[DONE]") return line;
  let parsed: any;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return line;
  }
  if (
    parsed?.type === "content_block_start" &&
    parsed?.content_block?.type === "tool_use" &&
    typeof parsed.content_block.name === "string"
  ) {
    const orig = parsed.content_block.name;
    const reverted = uncloakToolName(orig);
    if (orig !== reverted) {
      parsed.content_block.name = reverted;
      return "data: " + JSON.stringify(parsed);
    }
  }
  return line;
}

const MAX_RETRIES = 3;
const RETRYABLE_STATUSES = new Set([429, 500, 502, 503, 504]);

function classifyFailure(status: number): AccountFailureKind {
  if (status === 429) return "rate_limit";
  if (status === 401) return "auth";
  if (status === 403) return "forbidden";
  return "server";
}

// POST /v1/messages — Claude native format passthrough
export function createMessagesHandler(config: Config, manager: AccountManager) {
  return async (req: Request, res: ExpressResponse): Promise<void> => {
    try {
      const body = req.body;
      if (
        !body.messages ||
        !Array.isArray(body.messages) ||
        body.messages.length === 0
      ) {
        res.status(400).json({
          error: {
            message: "messages is required and must be a non-empty array",
          },
        });
        return;
      }

      // Debug: log incoming request body
      if (isDebugLevel(config.debug, "verbose")) {
        console.log("[DEBUG] Incoming /v1/messages body:");
        console.log(JSON.stringify(body, null, 2));
      }

      const stream = !!body.stream;
      const apiKey = extractApiKey(req.headers);
      const apiKeyHash = crypto
        .createHash("sha256")
        .update(apiKey)
        .digest("hex");

      // Always apply auth2api's own cloaking — never pass through upstream
      // client headers (even from claude-cli). This ensures consistent billing
      // headers and avoids conflicts when OpenClaw (which sends user-agent:
      // claude-cli/xxx) connects through auth2api.
      const passthroughHeaders: Record<string, string> | undefined = undefined;
      const overrideSessionId: string | undefined = undefined;

      let lastStatus = 500;
      let lastErrBody = "";
      const refreshedAccounts = new Set<string>();
      for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
        const { account, total } = manager.getNextAccount();
        if (!account) {
          const status = total === 0 ? 503 : 429;
          const message =
            total === 0
              ? "No available account"
              : "Rate limited on the configured account";
          res.status(status).json({ error: { message } });
          return;
        }

        manager.recordAttempt(account.token.email);

        // Apply per-account cloaking (clone body so each attempt is fresh)
        const claudeBody = applyCloaking(
          structuredClone(body),
          account.deviceId,
          account.accountUuid,
          apiKeyHash,
          config.cloaking,
          overrideSessionId,
        );

        // Debug: log final request body after cloaking
        if (isDebugLevel(config.debug, "verbose")) {
          console.log("[DEBUG] Final /v1/messages body after cloaking:");
          console.log(JSON.stringify(claudeBody, null, 2));
        }

        let upstreamResp: globalThis.Response;
        try {
          upstreamResp = await callClaudeAPI(
            account.token.accessToken,
            claudeBody,
            stream,
            config.timeouts,
            config.cloaking,
            apiKeyHash,
            passthroughHeaders,
          );
        } catch (err: any) {
          manager.recordFailure(account.token.email, "network", err.message);
          if (isDebugLevel(config.debug, "errors")) {
            console.error(
              `Messages attempt ${attempt + 1} network failure: ${err.message}`,
            );
          }
          if (attempt < MAX_RETRIES - 1) {
            await new Promise((r) => setTimeout(r, (attempt + 1) * 1000));
            continue;
          }
          res.status(502).json({
            error: { message: "Upstream network error" },
          });
          return;
        }

        if (upstreamResp.ok) {
          if (stream) {
            // Pipe SSE directly — no translation needed
            res.setHeader("Content-Type", "text/event-stream");
            res.setHeader("Cache-Control", "no-cache");
            res.setHeader("Connection", "keep-alive");
            res.setHeader("X-Accel-Buffering", "no");
            res.flushHeaders();

            const reader = upstreamResp.body?.getReader();
            if (!reader) {
              res.end();
              return;
            }

            let clientDisconnected = false;
            const usage: UsageData = {
              inputTokens: 0,
              outputTokens: 0,
              cacheCreationInputTokens: 0,
              cacheReadInputTokens: 0,
            };
            let sseBuffer = "";
            let currentEvent = "";
            res.on("close", () => {
              clientDisconnected = true;
              reader.cancel().catch(() => {});
            });

            try {
              while (!clientDisconnected) {
                const { done, value } = await reader.read();
                if (done) break;
                const chunk = Buffer.from(value);

                // Buffer by line: write only complete lines so we can rewrite
                // tool_use names mid-stream. Partial trailing line stays in
                // sseBuffer until the next chunk completes it.
                sseBuffer += chunk.toString();
                const lines = sseBuffer.split("\n");
                sseBuffer = lines.pop() ?? "";

                let outBuf = "";
                for (const line of lines) {
                  let outLine = line;
                  if (line.startsWith("event:")) {
                    currentEvent = line.slice(6).trim();
                  } else if (line.startsWith("data:")) {
                    const raw = line.slice(5).trim();
                    if (raw && raw !== "[DONE]") {
                      try {
                        const data = JSON.parse(raw);
                        if (currentEvent === "message_start") {
                          const u = data.message?.usage;
                          usage.inputTokens = u?.input_tokens || 0;
                          usage.cacheCreationInputTokens =
                            u?.cache_creation_input_tokens || 0;
                          usage.cacheReadInputTokens =
                            u?.cache_read_input_tokens || 0;
                        } else if (currentEvent === "message_delta") {
                          usage.outputTokens = data.usage?.output_tokens || 0;
                        }
                      } catch {
                        /* ignore parse errors */
                      }
                    }
                    // Revert any cloaked tool_use names so the client never
                    // sees the cc_ prefix.
                    outLine = uncloakSseDataLine(line);
                  }
                  outBuf += outLine + "\n";
                }
                if (outBuf) res.write(outBuf);
              }
              // Flush any remaining partial line so we don't drop bytes.
              if (!clientDisconnected && sseBuffer) {
                res.write(sseBuffer);
                sseBuffer = "";
              }
              if (!clientDisconnected) {
                manager.recordSuccess(account.token.email);
                manager.recordUsage(account.token.email, usage);
              }
            } catch (err) {
              if (!clientDisconnected) {
                manager.recordFailure(
                  account.token.email,
                  "network",
                  "stream terminated before completion",
                );
              }
              if (!clientDisconnected) console.error("Stream pipe error:", err);
            } finally {
              if (!clientDisconnected) res.end();
            }
          } else {
            // Forward JSON response directly
            const data = await upstreamResp.json();
            uncloakResponseInPlace(data);
            manager.recordSuccess(account.token.email);
            manager.recordUsage(account.token.email, {
              inputTokens: data.usage?.input_tokens || 0,
              outputTokens: data.usage?.output_tokens || 0,
              cacheCreationInputTokens:
                data.usage?.cache_creation_input_tokens || 0,
              cacheReadInputTokens: data.usage?.cache_read_input_tokens || 0,
            });
            res.json(data);
          }
          return;
        }

        lastStatus = upstreamResp.status;
        try {
          lastErrBody = await upstreamResp.text();
          if (isDebugLevel(config.debug, "errors")) {
            console.error(
              `Messages attempt ${attempt + 1} failed (${lastStatus}): ${lastErrBody}`,
            );
          }
        } catch {
          /* ignore */
        }

        if (lastStatus === 401) {
          const refreshed = await manager.refreshAccount(account.token.email);
          if (refreshed && !refreshedAccounts.has(account.token.email)) {
            refreshedAccounts.add(account.token.email);
            attempt--;
            continue;
          }
        } else {
          manager.recordFailure(
            account.token.email,
            classifyFailure(lastStatus),
          );
        }
        if (!RETRYABLE_STATUSES.has(lastStatus)) break;
        if (attempt < MAX_RETRIES - 1) {
          await new Promise((r) => setTimeout(r, (attempt + 1) * 1000));
        }
      }

      try {
        const parsed = lastErrBody ? JSON.parse(lastErrBody) : null;
        if (parsed && typeof parsed === "object") {
          res.status(lastStatus).json(parsed);
        } else {
          res
            .status(lastStatus)
            .json({ error: { message: "Upstream request failed" } });
        }
      } catch {
        res
          .status(lastStatus)
          .json({ error: { message: "Upstream request failed" } });
      }
    } catch (err: any) {
      console.error("Messages handler error:", err.message);
      res.status(500).json({
        error: { message: "Internal server error" },
      });
    }
  };
}

// POST /v1/messages/count_tokens — passthrough
export function createCountTokensHandler(
  config: Config,
  manager: AccountManager,
) {
  return async (req: Request, res: ExpressResponse): Promise<void> => {
    try {
      const apiKey = extractApiKey(req.headers);
      const apiKeyHash = crypto
        .createHash("sha256")
        .update(apiKey)
        .digest("hex");

      let lastStatus = 500;
      let lastErrBody = "";
      const refreshedAccounts = new Set<string>();
      for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
        const { account, total } = manager.getNextAccount();
        if (!account) {
          const status = total === 0 ? 503 : 429;
          const message =
            total === 0
              ? "No available account"
              : "Rate limited on the configured account";
          res.status(status).json({ error: { message } });
          return;
        }

        manager.recordAttempt(account.token.email);

        let upstreamResp: globalThis.Response;
        try {
          upstreamResp = await callClaudeCountTokens(
            account.token.accessToken,
            req.body,
            config.timeouts,
            config.cloaking,
            apiKeyHash,
          );
        } catch (err: any) {
          manager.recordFailure(account.token.email, "network", err.message);
          if (isDebugLevel(config.debug, "errors")) {
            console.error(
              `Count tokens attempt ${attempt + 1} network failure: ${err.message}`,
            );
          }
          if (attempt < MAX_RETRIES - 1) {
            await new Promise((r) => setTimeout(r, (attempt + 1) * 1000));
            continue;
          }
          res.status(502).json({
            error: { message: "Upstream network error" },
          });
          return;
        }

        if (upstreamResp.ok) {
          manager.recordSuccess(account.token.email);
          const data = await upstreamResp.json();
          res.json(data);
          return;
        }

        lastStatus = upstreamResp.status;
        lastErrBody = await upstreamResp.text().catch(() => "");
        if (lastStatus === 401) {
          const refreshed = await manager.refreshAccount(account.token.email);
          if (refreshed && !refreshedAccounts.has(account.token.email)) {
            refreshedAccounts.add(account.token.email);
            attempt--;
            continue;
          }
        } else {
          manager.recordFailure(
            account.token.email,
            classifyFailure(lastStatus),
          );
        }

        if (!RETRYABLE_STATUSES.has(lastStatus)) break;
        if (attempt < MAX_RETRIES - 1) {
          await new Promise((r) => setTimeout(r, (attempt + 1) * 1000));
        }
      }

      try {
        const parsed = lastErrBody ? JSON.parse(lastErrBody) : null;
        if (parsed && typeof parsed === "object") {
          res.status(lastStatus).json(parsed);
        } else {
          res
            .status(lastStatus)
            .json({ error: { message: "Upstream request failed" } });
        }
      } catch {
        res
          .status(lastStatus)
          .json({ error: { message: "Upstream request failed" } });
      }
    } catch (err: any) {
      console.error("Count tokens error:", err.message);
      res.status(500).json({
        error: { message: "Internal server error" },
      });
    }
  };
}
