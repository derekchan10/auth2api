import crypto from "crypto";
import { Request, Response as ExpressResponse } from "express";
import { Config } from "../config";
import { AccountManager } from "../accounts/manager";
import { extractApiKey } from "../api-key";
import { callClaudeAPI } from "./claude-api";
import { applyCloaking } from "./cloaking";
import { detectTrigger, SendFn, SendResult } from "./detect-fp";

/**
 * Minimal smoke payload — used by baseline mode to check the end-to-end path
 * (OAuth token + cloaking headers + upstream reachability) with prompt content
 * that is as close to noise as possible, so any failure points at the
 * transport/headers rather than at the prompt text.
 */
const BASELINE_BODY = {
  model: "claude-sonnet-4-6",
  max_tokens: 16,
  messages: [{ role: "user", content: "Hi" }],
};

/**
 * Map an upstream HTTP response to a Verdict used by detect-fp.
 *
 * Rule of thumb:
 *  - 2xx                              → ok         (not a trigger)
 *  - 401 / 403 / 429 / network / 5xx  → error      (transport — diagnosis is moot)
 *  - any other 4xx                    → blocked    (upstream content rejection)
 *
 * This intentionally treats auth/rate-limit/network as "error" rather than
 * "blocked" so that detect-fp doesn't mis-minimize account issues into
 * spurious "trigger" fragments.
 */
function classifyResponse(status: number, bodyText: string): SendResult {
  if (status >= 200 && status < 300) return { verdict: "ok", status };
  if (status === 401 || status === 403 || status === 429) {
    return {
      verdict: "error",
      status,
      detail: `auth/rate-limit: ${bodyText.slice(0, 200)}`,
    };
  }
  if (status >= 500) {
    return {
      verdict: "error",
      status,
      detail: `upstream 5xx: ${bodyText.slice(0, 200)}`,
    };
  }
  return { verdict: "blocked", status, detail: bodyText.slice(0, 500) };
}

interface DiagnoseRequest {
  mode?: "baseline" | "detect";
  /** For detect mode — the Claude-format body that is currently getting blocked. */
  body?: any;
  /** Whether to run applyCloaking() before sending. Defaults to false so
   * detect mode finds the *raw* trigger instead of the already-sanitized one. */
  cloak?: boolean;
  /** Safety cap on upstream calls during ddmin. */
  maxCalls?: number;
}

export function createDiagnoseHandler(
  config: Config,
  manager: AccountManager,
) {
  return async (req: Request, res: ExpressResponse): Promise<void> => {
    try {
      const {
        mode = "baseline",
        body: inputBody,
        cloak = false,
        maxCalls = 60,
      }: DiagnoseRequest = req.body || {};

      const apiKey = extractApiKey(req.headers) || "";
      const apiKeyHash = crypto
        .createHash("sha256")
        .update(apiKey)
        .digest("hex");

      const { account, total } = manager.getNextAccount();
      if (!account) {
        res.status(total === 0 ? 503 : 429).json({
          error: {
            message:
              total === 0
                ? "No available account"
                : "Rate limited on the configured account",
          },
        });
        return;
      }

      const send: SendFn = async (trial: any) => {
        const finalBody = cloak
          ? applyCloaking(
              structuredClone(trial),
              account.deviceId,
              account.accountUuid,
              apiKeyHash,
              config.cloaking,
            )
          : structuredClone(trial);
        // Force non-stream so we can read the full error body deterministically.
        finalBody.stream = false;
        try {
          const resp = await callClaudeAPI(
            account.token.accessToken,
            finalBody,
            false,
            config.timeouts,
            config.cloaking,
            apiKeyHash,
          );
          const text = await resp.text().catch(() => "");
          return classifyResponse(resp.status, text);
        } catch (err: any) {
          return {
            verdict: "error",
            detail: `fetch error: ${err?.message ?? String(err)}`,
          };
        }
      };

      if (mode === "baseline") {
        const result = await send(BASELINE_BODY);
        res.json({
          mode: "baseline",
          account: account.token.email,
          cloaking_applied: cloak,
          ...result,
        });
        return;
      }

      if (mode === "detect") {
        if (!inputBody || typeof inputBody !== "object") {
          res
            .status(400)
            .json({ error: { message: "detect mode requires `body`" } });
          return;
        }
        const result = await detectTrigger(inputBody, send, { maxCalls });
        res.json({
          mode: "detect",
          account: account.token.email,
          cloaking_applied: cloak,
          ...result,
        });
        return;
      }

      res.status(400).json({ error: { message: `unknown mode: ${mode}` } });
    } catch (err: any) {
      res
        .status(500)
        .json({ error: { message: err?.message ?? "diagnose failed" } });
    }
  };
}
