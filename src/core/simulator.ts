import crypto from "crypto";
import type { GatewayContext } from "./context";
import type { Rule, Rules } from "./types";
import { evaluateRule, policiesReadBody, resolveField, splitShadow } from "./policy";
import { matcherFor } from "./rules";
import { workspaceFilter } from "./protection";

/**
 * Policy Time-Machine: replays the last N recorded requests through a ruleset (the current one,
 * or a candidate you have not saved yet) and reports, request by request, what would have
 * happened differently.
 *
 * Every audit row written by the rule pipeline (v2+) carries a redacted request snapshot (body,
 * query, headers, caller). The replay applies, in the gateway's own order and on the recorded
 * timestamps:
 *
 *   rule lookup (default deny) -> per-rule / global rate limit (60 s sliding window per caller)
 *   -> payload policies -> shadow modes -> duplicate protection -> spending budget
 *
 * Budgets and duplicate protection are replayed with an in-memory ledger that starts empty at the
 * oldest replayed request, so they only "see" the requests in the replay window. Operating modes
 * (lockdown, approval-only, business hours) are not replayed: they describe the shop, not the
 * rules. Fields the redactor masked (emails, phones, secrets) are compared in their masked form.
 */

export type SimOutcome = "ALLOW" | "BLOCK" | "REQUIRE_APPROVAL" | "RATE_LIMITED";

export interface SimulationRow {
  logId: number;
  timestamp: string;
  method: string;
  path: string;
  historical: SimOutcome;
  simulated: SimOutcome;
  /** Why the replay decided what it did ("tier:huge", "default-deny", "budget", ...). */
  reason: string;
  /** What a SHADOW_* rule would have done, when the simulated outcome came from one. */
  shadow: "BLOCK" | "APPROVAL" | null;
  amount: number | null;
  caller: string;
}

export interface SimulationReport {
  workspaceId: number | null;
  /** Rows in the window that had a snapshot and were replayed. */
  evaluated: number;
  /** Rows replayed whose body was needed but not recorded (too large / rate-limited before parsing). */
  unevaluable: number;
  /** Rows in the window without a snapshot (written before v2, or refusals that never reached the rules). */
  skippedNoSnapshot: number;
  historical: Record<SimOutcome, number>;
  simulated: Record<SimOutcome, number>;
  changed: number;
  transitions: Array<{ from: SimOutcome; to: SimOutcome; count: number }>;
  /** Requests that went through (or waited) but would now be blocked. */
  wouldBlock: number;
  /** Requests that ran without a human but would now wait for approval. */
  wouldHold: number;
  /** Requests that went through but would now be rate-limited. */
  wouldRateLimit: number;
  /** Requests that were refused or held but would now run without a human. */
  wouldAllow: number;
  /** SHADOW_* verdicts among the simulated ALLOWs. */
  shadow: { wouldBlock: number; wouldHold: number };
  moneyNewlyBlocked: number;
  /** Changed rows (newest first), at most `maxRows`. */
  rows: SimulationRow[];
  from: string | null;
  to: string | null;
  usedCandidateRules: boolean;
}

interface LogRow {
  id: number;
  timestamp: string;
  method: string;
  path: string;
  status: string;
  amount: number | null;
  request_snapshot: string | null;
  workspace_id: number | null;
}

interface Snapshot {
  kind?: string;
  body?: unknown;
  bodyUnknown?: boolean;
  truncated?: boolean;
  query?: unknown;
  headers?: Record<string, string>;
  caller?: string;
}

const HISTORICAL: Record<string, SimOutcome | undefined> = {
  ALLOWED: "ALLOW",
  BLOCKED: "BLOCK",
  QUEUED: "REQUIRE_APPROVAL",
  RATE_LIMITED: "RATE_LIMITED",
};

const zero = (): Record<SimOutcome, number> => ({ ALLOW: 0, BLOCK: 0, REQUIRE_APPROVAL: 0, RATE_LIMITED: 0 });

export async function simulateHistory(
  ctx: GatewayContext,
  opts: { workspaceId: number | null; limit: number; rules?: Rules; maxRows?: number }
): Promise<SimulationReport> {
  const limit = Math.min(Math.max(Math.trunc(opts.limit) || 500, 1), 5000);
  const maxRows = opts.maxRows ?? 200;
  const wf = workspaceFilter(opts.workspaceId);
  // The entry rows of the rule pipeline (decisions are separate APPROVED / REJECTED rows).
  const rows = (
    await ctx.db.all<LogRow>(
      `SELECT id, timestamp, method, path, status, amount, request_snapshot, workspace_id FROM agent_logs
       WHERE status IN ('ALLOWED', 'BLOCKED', 'QUEUED', 'RATE_LIMITED')${wf.sql}
       ORDER BY id DESC LIMIT ?`,
      [...wf.params, limit]
    )
  ).reverse();

  // One ruleset per workspace (or the candidate), compiled once.
  const wsId = opts.workspaceId;
  const matchers = new Map<number, (m: string, p: string) => { key: string; rule: Rule } | undefined>();
  const candidate = opts.rules ? matcherFor(opts.rules) : null;
  const lookup = (rowWs: number, method: string, path: string): { key: string; rule: Rule } | undefined => {
    if (candidate) return candidate(method, path);
    let m = matchers.get(rowWs);
    if (!m) {
      m = matcherFor(ctx.workspaces.rules(rowWs));
      matchers.set(rowWs, m);
    }
    return m(method, path);
  };
  const globalLimit = ctx.config.load().rateLimitPerMinute;

  const report: SimulationReport = {
    workspaceId: wsId,
    evaluated: 0,
    unevaluable: 0,
    skippedNoSnapshot: 0,
    historical: zero(),
    simulated: zero(),
    changed: 0,
    transitions: [],
    wouldBlock: 0,
    wouldHold: 0,
    wouldRateLimit: 0,
    wouldAllow: 0,
    shadow: { wouldBlock: 0, wouldHold: 0 },
    moneyNewlyBlocked: 0,
    rows: [],
    from: rows.length ? rows[0].timestamp : null,
    to: rows.length ? rows[rows.length - 1].timestamp : null,
    usedCandidateRules: Boolean(opts.rules),
  };
  const transitions = new Map<string, number>();
  const rateWindows = new Map<string, number[]>();
  const spend = new Map<string, Array<{ ts: number; amount: number; caller: string }>>();
  const seen = new Map<string, number>(); // dedupe fingerprint -> last ts
  const changedRows: SimulationRow[] = [];

  for (const row of rows) {
    const historical = HISTORICAL[row.status];
    if (!historical) continue;
    if (!row.request_snapshot) {
      report.skippedNoSnapshot++;
      continue;
    }
    let snap: Snapshot;
    try {
      snap = JSON.parse(row.request_snapshot) as Snapshot;
    } catch {
      report.skippedNoSnapshot++;
      continue;
    }
    const rowWs = row.workspace_id ?? 1;
    const ts = Date.parse(row.timestamp);
    const caller = typeof snap.caller === "string" ? snap.caller : "unknown";
    const entry = lookup(rowWs, row.method, row.path);
    const bodyKnown = !snap.bodyUnknown && !snap.truncated;
    let simulated: SimOutcome;
    let reason: string;
    let shadow: "BLOCK" | "APPROVAL" | null = null;

    // 1. Rate limit (sliding 60 s window per caller, per rule bucket when the rule sets one).
    const custom = typeof entry?.rule.rateLimit === "number" && entry.rule.rateLimit > 0 ? entry.rule.rateLimit : null;
    const bucket = custom ? `${caller}|${entry!.key}` : `${caller}|*`;
    const hits = (rateWindows.get(bucket) ?? []).filter((t) => t > ts - 60_000);
    hits.push(ts);
    rateWindows.set(bucket, hits);
    const limitHit = hits.length > (custom ?? globalLimit);

    if (limitHit) {
      simulated = "RATE_LIMITED";
      reason = `rate limit ${custom ?? globalLimit}/min`;
    } else if (!entry) {
      simulated = "BLOCK";
      reason = "default-deny";
    } else if (!bodyKnown && policiesReadBody(entry.rule)) {
      report.unevaluable++;
      continue;
    } else {
      const input = { body: snap.body ?? undefined, query: snap.query ?? {}, headers: snap.headers ?? {} };
      const split = splitShadow(evaluateRule(entry.rule, input));
      shadow = split.shadow;
      simulated = split.decision.mode === "ALLOW" ? "ALLOW" : split.decision.mode === "BLOCK" ? "BLOCK" : "REQUIRE_APPROVAL";
      reason = split.decision.matched;

      // 2. Duplicate protection.
      const dd = entry.rule.dedupe;
      if (dd && simulated !== "BLOCK" && bodyKnown) {
        const values: unknown[] = [];
        let identifiable = true;
        for (const f of dd.fields) {
          const r = resolveField(input, f);
          if (!r.found || (typeof r.value === "object" && r.value !== null)) {
            identifiable = false;
            break;
          }
          values.push(r.value);
        }
        if (identifiable) {
          const fp = crypto.createHash("sha256").update(`${rowWs}|${entry.key}\n${JSON.stringify(values)}`).digest("hex");
          const last = seen.get(fp);
          if (last !== undefined && last >= ts - dd.windowMinutes * 60_000) {
            simulated = dd.onDuplicate === "BLOCK" ? "BLOCK" : "REQUIRE_APPROVAL";
            reason = "duplicate";
          } else {
            seen.set(fp, ts);
          }
        }
      }

      // 3. Spending budget (only for what would run without a human).
      const b = entry.rule.budget;
      if (b && simulated === "ALLOW") {
        const amount = bodyKnown ? resolveField(input, b.field) : { found: false as const };
        if (!amount.found || typeof amount.value !== "number" || !Number.isFinite(amount.value) || amount.value < 0) {
          simulated = b.onExceed === "BLOCK" ? "BLOCK" : "REQUIRE_APPROVAL";
          reason = "budget (amount unreadable)";
        } else {
          const key = `${rowWs}|${entry.key}`;
          const ledger = (spend.get(key) ?? []).filter((e) => e.ts >= ts - b.windowMinutes * 60_000);
          const used = ledger.filter((e) => b.per === "global" || e.caller === caller).reduce((n, e) => n + e.amount, 0);
          if (used + amount.value > b.max) {
            simulated = b.onExceed === "BLOCK" ? "BLOCK" : "REQUIRE_APPROVAL";
            reason = "budget";
          } else {
            ledger.push({ ts, amount: amount.value, caller });
          }
          spend.set(key, ledger);
        }
      }
    }

    report.evaluated++;
    report.historical[historical]++;
    report.simulated[simulated]++;
    if (simulated === "ALLOW" && shadow === "BLOCK") report.shadow.wouldBlock++;
    if (simulated === "ALLOW" && shadow === "APPROVAL") report.shadow.wouldHold++;
    if (simulated !== historical) {
      report.changed++;
      const k = `${historical}>${simulated}`;
      transitions.set(k, (transitions.get(k) ?? 0) + 1);
      if (simulated === "BLOCK") {
        report.wouldBlock++;
        if (historical === "ALLOW") report.moneyNewlyBlocked += row.amount ?? 0;
      } else if (simulated === "REQUIRE_APPROVAL" && historical === "ALLOW") report.wouldHold++;
      else if (simulated === "RATE_LIMITED") report.wouldRateLimit++;
      else if (simulated === "ALLOW") report.wouldAllow++;
      changedRows.push({ logId: row.id, timestamp: row.timestamp, method: row.method, path: row.path, historical, simulated, reason, shadow, amount: row.amount, caller });
    }
  }

  report.transitions = [...transitions.entries()]
    .map(([k, count]) => {
      const [from, to] = k.split(">") as [SimOutcome, SimOutcome];
      return { from, to, count };
    })
    .sort((a, b) => b.count - a.count);
  report.rows = changedRows.reverse().slice(0, maxRows);
  report.moneyNewlyBlocked = Math.round(report.moneyNewlyBlocked * 100) / 100;
  return report;
}
