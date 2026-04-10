/**
 * auth2api diagnostic runbook.
 *
 * Mirrors the flow from fix-openclaw (baseline → isolate → verify) against a
 * running local auth2api instance. Intended for the case where upstream starts
 * rejecting requests and you need to know whether it's a transport issue, a
 * headers-level cloaking gap, a content-level trigger that SANITIZE_RULES
 * doesn't catch, or a stale session.
 *
 * Usage:
 *   tsx scripts/diagnose.ts                         # baseline + account check
 *   tsx scripts/diagnose.ts --body=./blocked.json   # full isolation flow
 *   tsx scripts/diagnose.ts --reset-session         # rotate session then exit
 *   tsx scripts/diagnose.ts --url=http://127.0.0.1:8317 --key=sk-...
 *
 * The --body file should contain a Claude-format request body that is
 * *currently being blocked*. After isolation, the script prints the minimal
 * triggering lines — copy the offending phrase into SANITIZE_RULES in
 * src/proxy/cloaking.ts as a new rule.
 */

import fs from "fs";
import path from "path";
import yaml from "js-yaml";

interface Args {
  url: string;
  key: string;
  bodyPath: string | null;
  resetSession: boolean;
  maxCalls: number;
}

function parseArgs(): Args {
  const args: Args = {
    url: "http://127.0.0.1:8317",
    key: "",
    bodyPath: null,
    resetSession: false,
    maxCalls: 60,
  };
  for (const arg of process.argv.slice(2)) {
    if (arg.startsWith("--url=")) args.url = arg.slice(6);
    else if (arg.startsWith("--key=")) args.key = arg.slice(6);
    else if (arg.startsWith("--body=")) args.bodyPath = arg.slice(7);
    else if (arg.startsWith("--max-calls=")) {
      args.maxCalls = Number(arg.slice(12));
    } else if (arg === "--reset-session") args.resetSession = true;
    else if (arg === "--help" || arg === "-h") {
      console.log(
        "Usage: tsx scripts/diagnose.ts [--url=...] [--key=...] [--body=path] [--reset-session] [--max-calls=60]",
      );
      process.exit(0);
    }
  }
  return args;
}

function loadKeyFromConfig(): string {
  const configPath = path.resolve("config.yaml");
  if (!fs.existsSync(configPath)) return "";
  try {
    const parsed = yaml.load(fs.readFileSync(configPath, "utf-8")) as any;
    const keys: string[] = parsed?.["api-keys"] ?? [];
    return keys[0] || "";
  } catch {
    return "";
  }
}

async function http(
  url: string,
  opts: { method?: string; key: string; body?: any } = { key: "" },
): Promise<{ status: number; data: any; text: string }> {
  const resp = await fetch(url, {
    method: opts.method ?? "GET",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${opts.key}`,
    },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const text = await resp.text();
  let data: any = null;
  try {
    data = JSON.parse(text);
  } catch {
    /* non-JSON */
  }
  return { status: resp.status, data, text };
}

function header(title: string): void {
  console.log("\n" + "═".repeat(60));
  console.log(title);
  console.log("═".repeat(60));
}

async function main(): Promise<void> {
  const args = parseArgs();
  if (!args.key) args.key = loadKeyFromConfig();
  if (!args.key) {
    console.error(
      "No API key found. Pass --key=... or run from a directory with config.yaml.",
    );
    process.exit(2);
  }

  // Step 0 — health
  header("Step 0 — server health");
  try {
    const h = await http(`${args.url}/health`, { key: args.key });
    if (h.status !== 200) {
      console.error(`  health returned ${h.status} — is auth2api running?`);
      process.exit(2);
    }
    console.log("  ok");
  } catch (err: any) {
    console.error(`  cannot reach ${args.url}: ${err.message}`);
    process.exit(2);
  }

  // Optional: reset session and exit
  if (args.resetSession) {
    header("Rotating session");
    const r = await http(`${args.url}/admin/reset-session`, {
      method: "POST",
      key: args.key,
    });
    console.log(`  status=${r.status} ${r.text}`);
    return;
  }

  // Step 1 — account state
  header("Step 1 — account state");
  const acct = await http(`${args.url}/admin/accounts`, { key: args.key });
  if (acct.status !== 200) {
    console.error(`  /admin/accounts returned ${acct.status}: ${acct.text}`);
    process.exit(2);
  }
  const snaps = acct.data?.accounts ?? [];
  for (const s of snaps) {
    const cooldown =
      s.cooldownUntil > Date.now()
        ? ` COOLDOWN(${Math.ceil((s.cooldownUntil - Date.now()) / 1000)}s)`
        : "";
    console.log(
      `  ${s.email} available=${s.available} failures=${s.failureCount} lastError=${s.lastError ?? "-"}${cooldown}`,
    );
  }
  if (snaps.length === 0) {
    console.error("  no accounts configured");
    process.exit(2);
  }

  // Step 2 — baseline WITH cloaking (end-to-end sanity)
  header("Step 2 — baseline (cloaked) — end-to-end sanity");
  const base = await http(`${args.url}/admin/diagnose`, {
    method: "POST",
    key: args.key,
    body: { mode: "baseline", cloak: true },
  });
  console.log(`  verdict=${base.data?.verdict} status=${base.data?.status}`);
  if (base.data?.detail) {
    console.log(`  detail=${base.data.detail.slice(0, 300)}`);
  }
  if (base.data?.verdict !== "ok") {
    if (base.data?.verdict === "blocked") {
      console.error(
        "  → cloaked baseline is being blocked. This is a headers/cloaking-layer issue.",
      );
      console.error(
        "    Check src/proxy/claude-api.ts buildHeaders and src/proxy/cloaking.ts applyCloaking.",
      );
      console.error(
        "    Compare against a real Claude Code CLI capture (mitmproxy).",
      );
    } else {
      console.error(
        "  → transport/auth error. Not a content issue — check the account token, network, or run --reset-session.",
      );
    }
    if (!args.bodyPath) process.exit(1);
    console.error("  continuing anyway because --body was provided");
  } else {
    console.log("  → cloaking path is healthy");
  }

  if (!args.bodyPath) {
    header("Done");
    console.log(
      "No --body supplied, skipping trigger isolation. Pass --body=path/to/blocked.json to run ddmin.",
    );
    return;
  }

  // Step 3 — detect trigger in RAW body (no cloaking)
  header("Step 3 — detect trigger (raw, no cloaking)");
  const rawBody = JSON.parse(fs.readFileSync(args.bodyPath, "utf-8"));
  const rawDetect = await http(`${args.url}/admin/diagnose`, {
    method: "POST",
    key: args.key,
    body: {
      mode: "detect",
      body: rawBody,
      cloak: false,
      maxCalls: args.maxCalls,
    },
  });
  if (rawDetect.status !== 200) {
    console.error(`  detect failed: ${rawDetect.status} ${rawDetect.text}`);
    process.exit(1);
  }
  const d = rawDetect.data;
  console.log(
    `  triggered=${d.triggered} blockIndex=${d.blockIndex} calls=${d.calls}`,
  );
  for (const line of d.log ?? []) console.log(`  | ${line}`);
  if (!d.triggered) {
    console.log(
      "  → raw body is not actually blocked upstream. Re-capture a failing request and retry.",
    );
    return;
  }
  if ((d.triggerLines ?? []).length === 0) {
    console.log(
      "  → upstream rejected but ddmin could not isolate to a single block.",
    );
    console.log(
      "    Likely causes: interaction between blocks, or a non-content signal",
    );
    console.log(
      "    (request length, tools shape, metadata). See Step 6B in the runbook.",
    );
    return;
  }

  console.log("\n  MINIMAL TRIGGER LINES:");
  console.log("  ┌" + "─".repeat(58));
  for (const line of d.triggerLines) {
    console.log(`  │ ${line}`);
  }
  console.log("  └" + "─".repeat(58));

  // Step 4 — verify current SANITIZE_RULES catch it
  header("Step 4 — verify current SANITIZE_RULES catch it (cloaked)");
  const verify = await http(`${args.url}/admin/diagnose`, {
    method: "POST",
    key: args.key,
    body: {
      mode: "detect",
      body: rawBody,
      cloak: true,
      maxCalls: args.maxCalls,
    },
  });
  const v = verify.data;
  console.log(`  triggered=${v?.triggered}`);
  if (v?.triggered === false) {
    console.log("  → current SANITIZE_RULES already neutralize this trigger.");
    console.log("    No code change needed — the issue is elsewhere.");
  } else {
    console.log(
      "  → current SANITIZE_RULES do NOT catch this trigger. Add a rule:",
    );
    console.log(
      "\n    In src/proxy/cloaking.ts, append to SANITIZE_RULES (before brand rules):",
    );
    console.log("    [");
    const sample = d.triggerLines.find((l: string) => l.trim().length > 0) ?? d.triggerLines[0];
    const escaped = sample.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    console.log(`      /${escaped}/gi,`);
    console.log(`      "<neutral replacement>",`);
    console.log("    ],");
  }

  header("Done");
}

main().catch((err) => {
  console.error("diagnose error:", err);
  process.exit(1);
});
