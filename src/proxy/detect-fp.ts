/**
 * Delta-debugging minimizer for upstream content blocks.
 *
 * Given a Claude-format request body that is being rejected by upstream and a
 * send function, binary-searches the `system` blocks (and their lines) to
 * isolate the smallest fragment that still reproduces the block. The caller
 * decides what counts as "blocked" by returning a Verdict — detect-fp itself
 * is transport-agnostic.
 *
 * Why ddmin instead of plain halving: the real upstream detector can match on
 * a single sentence buried inside one block. Naive halving gets stuck when the
 * trigger lives on a boundary; ddmin's complement-reduction is robust to that.
 */

export type Verdict = "ok" | "blocked" | "error";

export interface SendResult {
  verdict: Verdict;
  status?: number;
  detail?: string;
}

export type SendFn = (body: any) => Promise<SendResult>;

export interface DetectOptions {
  /** Hard cap on total upstream calls, to bound cost. */
  maxCalls?: number;
  onStep?: (msg: string) => void;
}

export interface DetectResult {
  triggered: boolean;
  /** Minimum set of lines from `system[blockIndex]` that still trips upstream. */
  triggerLines: string[];
  /** Index into the normalized system array, or -1 if no single block reproduces. */
  blockIndex: number;
  calls: number;
  log: string[];
}

function normalizeSystem(body: any): any[] {
  if (Array.isArray(body.system)) return body.system;
  if (typeof body.system === "string" && body.system.length > 0) {
    return [{ type: "text", text: body.system }];
  }
  return [];
}

function setBlockText(body: any, idx: number, text: string): any {
  const clone = structuredClone(body);
  if (Array.isArray(clone.system)) {
    clone.system[idx] = { ...clone.system[idx], text };
  } else {
    clone.system = text;
  }
  return clone;
}

async function ddmin(
  lines: string[],
  test: (subset: string[]) => Promise<boolean>,
  log: (m: string) => void,
): Promise<string[]> {
  let current = lines.slice();
  let n = 2;
  const MAX_ROUNDS = 40;

  for (let round = 0; round < MAX_ROUNDS; round++) {
    if (current.length < 2) break;
    const chunk = Math.max(1, Math.floor(current.length / n));
    let reduced = false;

    for (let i = 0; i < n; i++) {
      const start = i * chunk;
      const end = i === n - 1 ? current.length : start + chunk;
      const complement = current.slice(0, start).concat(current.slice(end));
      if (complement.length === 0) continue;
      log(
        `  ddmin round=${round} n=${n} complement=${i + 1}/${n} size=${complement.length}`,
      );
      if (await test(complement)) {
        current = complement;
        n = Math.max(n - 1, 2);
        reduced = true;
        break;
      }
    }

    if (!reduced) {
      if (n >= current.length) break;
      n = Math.min(n * 2, current.length);
    }
  }

  return current;
}

export async function detectTrigger(
  body: any,
  sendFn: SendFn,
  opts: DetectOptions = {},
): Promise<DetectResult> {
  const log: string[] = [];
  const push = (m: string) => {
    log.push(m);
    opts.onStep?.(m);
  };

  const maxCalls = opts.maxCalls ?? 60;
  let calls = 0;

  const call = async (trial: any): Promise<boolean> => {
    if (calls >= maxCalls) {
      throw new Error(`detect-fp: maxCalls (${maxCalls}) exhausted`);
    }
    calls++;
    const r = await sendFn(trial);
    if (r.verdict === "error") {
      throw new Error(
        `detect-fp: transport error at call ${calls}: ${r.detail ?? ""}`,
      );
    }
    return r.verdict === "blocked";
  };

  push("baseline: sending original body");
  if (!(await call(body))) {
    push("baseline: upstream accepted the request — nothing to diagnose");
    return {
      triggered: false,
      triggerLines: [],
      blockIndex: -1,
      calls,
      log,
    };
  }
  push("baseline: BLOCKED — isolating trigger");

  const systemArr = normalizeSystem(body);
  if (systemArr.length === 0) {
    push(
      "body has no system blocks — trigger is in messages/tools, not system",
    );
    return {
      triggered: true,
      triggerLines: [],
      blockIndex: -1,
      calls,
      log,
    };
  }

  // Locate which system block carries the trigger.
  let suspectIdx = 0;
  if (systemArr.length > 1) {
    push(`system has ${systemArr.length} blocks — probing each`);
    let found = -1;
    for (let i = 0; i < systemArr.length; i++) {
      const trial = structuredClone(body);
      trial.system = [systemArr[i]];
      if (await call(trial)) {
        found = i;
        push(`  block[${i}] alone reproduces the block`);
        break;
      }
    }
    if (found < 0) {
      push(
        "no single block reproduces alone — trigger is an interaction across blocks",
      );
      return {
        triggered: true,
        triggerLines: [],
        blockIndex: -1,
        calls,
        log,
      };
    }
    suspectIdx = found;
  }

  const suspectText =
    typeof systemArr[suspectIdx]?.text === "string"
      ? (systemArr[suspectIdx].text as string)
      : "";
  const lines = suspectText.split("\n");
  push(`ddmin on block[${suspectIdx}] (${lines.length} lines)`);

  const minimal = await ddmin(
    lines,
    (subset) => call(setBlockText(body, suspectIdx, subset.join("\n"))),
    push,
  );

  push(`minimal trigger: ${minimal.length} line(s)`);
  return {
    triggered: true,
    triggerLines: minimal,
    blockIndex: suspectIdx,
    calls,
    log,
  };
}
