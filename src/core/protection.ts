import type { GatewayContext } from "./context";
import type { EmergencyState, LogStatus } from "./types";
import { LOG_STATUSES } from "./types";
import type { BudgetUsage } from "./guards";
import { DEFAULT_WORKSPACE_ID } from "./constants";

/** What the gateway did for the shop over a time window: the numbers an owner cares about. */
export interface ProtectionSummary {
  windowHours: number;
  since: string;
  /** null = every workspace. */
  workspaceId: number | null;
  counts: Record<LogStatus, number>;
  /** Sum of request amounts that were blocked or rejected (money an agent tried to move and could not). */
  moneyProtected: number;
  /** Sum of request amounts that went through (auto-allowed or approved). */
  moneyExecuted: number;
  pending: number;
  /** Effective mode (the stricter of the global switch and the workspace's own). */
  emergency: EmergencyState;
  /** The global switch, for context when a workspace is selected. */
  globalEmergency: EmergencyState;
  /** SHADOW_* rules: requests that were let through but would have been blocked / held. */
  shadow: { wouldBlock: number; wouldHold: number };
  budgets: BudgetUsage[];
  topBlocked: Array<{ method: string; path: string; count: number }>;
  topCallers: Array<{ caller: string; blocked: number }>;
}

/** SQL filter for one workspace (rows from before v2 have NULL = the default workspace). */
export function workspaceFilter(workspaceId: number | null | undefined, column = "workspace_id"): { sql: string; params: unknown[] } {
  if (workspaceId === null || workspaceId === undefined) return { sql: "", params: [] };
  if (workspaceId === DEFAULT_WORKSPACE_ID) return { sql: ` AND COALESCE(${column}, 1) = 1`, params: [] };
  return { sql: ` AND ${column} = ?`, params: [workspaceId] };
}

export async function buildSummary(ctx: GatewayContext, hours: number, workspaceId: number | null = null): Promise<ProtectionSummary> {
  const sinceMs = Date.now() - hours * 3600_000;
  const since = new Date(sinceMs).toISOString();
  const wf = workspaceFilter(workspaceId);
  const counts = Object.fromEntries(LOG_STATUSES.map((s) => [s, 0])) as Record<LogStatus, number>;
  const rows = await ctx.db.all<{ status: LogStatus; n: number }>(`SELECT status, COUNT(*) AS n FROM agent_logs WHERE timestamp >= ?${wf.sql} GROUP BY status`, [since, ...wf.params]);
  for (const r of rows) if (LOG_STATUSES.includes(r.status)) counts[r.status] = r.n;

  const money = await ctx.db.get<{ protected: number | null; executed: number | null }>(
    `SELECT SUM(CASE WHEN status IN ('BLOCKED', 'REJECTED') THEN amount END) AS protected,
            SUM(CASE WHEN status IN ('ALLOWED', 'APPROVED') THEN amount END) AS executed
     FROM agent_logs WHERE timestamp >= ? AND amount IS NOT NULL${wf.sql}`,
    [since, ...wf.params]
  );
  const shadow = await ctx.db.get<{ block: number | null; hold: number | null }>(
    `SELECT SUM(CASE WHEN shadow = 'BLOCK' THEN 1 ELSE 0 END) AS block, SUM(CASE WHEN shadow = 'APPROVAL' THEN 1 ELSE 0 END) AS hold
     FROM agent_logs WHERE timestamp >= ? AND shadow IS NOT NULL${wf.sql}`,
    [since, ...wf.params]
  );
  const pf = workspaceFilter(workspaceId);
  const pending = await ctx.db.get<{ n: number }>(`SELECT COUNT(*) AS n FROM pending_actions WHERE status = 'PENDING'${pf.sql}`, pf.params);
  const topBlocked = await ctx.db.all<{ method: string; path: string; count: number }>(
    `SELECT method, path, COUNT(*) AS count FROM agent_logs
     WHERE timestamp >= ? AND status IN ('BLOCKED', 'RATE_LIMITED', 'REJECTED', 'RESPONSE_BLOCKED')${wf.sql}
     GROUP BY method, path ORDER BY count DESC LIMIT 5`,
    [since, ...wf.params]
  );
  const topCallers = await ctx.db.all<{ caller: string; blocked: number }>(
    `SELECT COALESCE(agent_key, caller_ip, user_agent, 'unknown') AS caller, COUNT(*) AS blocked FROM agent_logs
     WHERE timestamp >= ? AND status IN ('BLOCKED', 'RATE_LIMITED', 'REJECTED', 'RESPONSE_BLOCKED')${wf.sql}
     GROUP BY caller ORDER BY blocked DESC LIMIT 5`,
    [since, ...wf.params]
  );
  const round = (n: number | null | undefined): number => Math.round((n ?? 0) * 100) / 100;
  const globalEmergency = ctx.emergency.current();
  const ws = workspaceId !== null ? ctx.workspaces.get(workspaceId) : undefined;
  let emergency: EmergencyState = globalEmergency;
  if (ws && !ws.isDefault && ws.mode !== "normal" && (globalEmergency.mode === "normal" || (globalEmergency.mode === "approval_only" && ws.mode === "lockdown"))) {
    emergency = { mode: ws.mode, reason: ws.modeReason, changedBy: ws.modeChangedBy, changedAt: ws.modeChangedAt };
  }
  return {
    windowHours: hours,
    since,
    workspaceId,
    counts,
    moneyProtected: round(money?.protected),
    moneyExecuted: round(money?.executed),
    pending: pending?.n ?? 0,
    emergency,
    globalEmergency,
    shadow: { wouldBlock: shadow?.block ?? 0, wouldHold: shadow?.hold ?? 0 },
    budgets: await ctx.guards.usage(workspaceId),
    topBlocked,
    topCallers,
  };
}

const fmt = (n: number): string => n.toLocaleString("en-US", { maximumFractionDigits: 2 });

export function modeLabel(mode: EmergencyState["mode"]): string {
  return mode === "lockdown" ? "🔴 LOCKDOWN (all agent requests refused)" : mode === "approval_only" ? "🟠 APPROVAL-ONLY (every write needs a human)" : "🟢 Normal";
}

/** Plain-text lines for chat messages (digest, /status). */
export function summaryLines(s: ProtectionSummary): string[] {
  const c = s.counts;
  const lines = [
    `Mode: ${modeLabel(s.emergency.mode)}${s.emergency.reason ? ` · ${s.emergency.reason}` : ""}`,
    `Last ${s.windowHours}h: ${c.ALLOWED} allowed · ${c.BLOCKED} blocked · ${c.RATE_LIMITED} rate-limited · ${c.APPROVED} approved · ${c.REJECTED} rejected`,
    `Money protected: ${fmt(s.moneyProtected)} · executed: ${fmt(s.moneyExecuted)}`,
    `Waiting for approval: ${s.pending}`,
  ];
  if (c.RESPONSE_BLOCKED + c.RESPONSE_SCRUBBED > 0) {
    lines.push(`Response guard: ${c.RESPONSE_BLOCKED} responses withheld · ${c.RESPONSE_SCRUBBED} scrubbed`);
  }
  if (s.shadow.wouldBlock + s.shadow.wouldHold > 0) {
    lines.push(`Shadow rules: ${s.shadow.wouldBlock} would have been blocked · ${s.shadow.wouldHold} would have been held`);
  }
  for (const b of s.budgets) {
    lines.push(
      `Budget ${b.workspaceId !== DEFAULT_WORKSPACE_ID ? `[${b.workspaceSlug}] ` : ""}${b.ruleKey}: ${fmt(b.spent)} / ${fmt(b.max)} per ${b.windowMinutes} min${b.per === "caller" ? " (per agent)" : ""}`
    );
  }
  if (s.topBlocked.length) lines.push(`Most blocked: ${s.topBlocked.map((t) => `${t.method} ${t.path} ×${t.count}`).join(", ")}`);
  return lines;
}
