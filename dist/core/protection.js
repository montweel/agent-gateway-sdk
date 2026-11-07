"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.workspaceFilter = workspaceFilter;
exports.buildSummary = buildSummary;
exports.modeLabel = modeLabel;
exports.summaryLines = summaryLines;
const types_1 = require("./types");
const constants_1 = require("./constants");
/** SQL filter for one workspace (rows from before v2 have NULL = the default workspace). */
function workspaceFilter(workspaceId, column = "workspace_id") {
    if (workspaceId === null || workspaceId === undefined)
        return { sql: "", params: [] };
    if (workspaceId === constants_1.DEFAULT_WORKSPACE_ID)
        return { sql: ` AND COALESCE(${column}, 1) = 1`, params: [] };
    return { sql: ` AND ${column} = ?`, params: [workspaceId] };
}
async function buildSummary(ctx, hours, workspaceId = null) {
    const sinceMs = Date.now() - hours * 3600000;
    const since = new Date(sinceMs).toISOString();
    const wf = workspaceFilter(workspaceId);
    const counts = Object.fromEntries(types_1.LOG_STATUSES.map((s) => [s, 0]));
    const rows = await ctx.db.all(`SELECT status, COUNT(*) AS n FROM agent_logs WHERE timestamp >= ?${wf.sql} GROUP BY status`, [since, ...wf.params]);
    for (const r of rows)
        if (types_1.LOG_STATUSES.includes(r.status))
            counts[r.status] = r.n;
    const money = await ctx.db.get(`SELECT SUM(CASE WHEN status IN ('BLOCKED', 'REJECTED') THEN amount END) AS protected,
            SUM(CASE WHEN status IN ('ALLOWED', 'APPROVED') THEN amount END) AS executed
     FROM agent_logs WHERE timestamp >= ? AND amount IS NOT NULL${wf.sql}`, [since, ...wf.params]);
    const shadow = await ctx.db.get(`SELECT SUM(CASE WHEN shadow = 'BLOCK' THEN 1 ELSE 0 END) AS block, SUM(CASE WHEN shadow = 'APPROVAL' THEN 1 ELSE 0 END) AS hold
     FROM agent_logs WHERE timestamp >= ? AND shadow IS NOT NULL${wf.sql}`, [since, ...wf.params]);
    const pf = workspaceFilter(workspaceId);
    const pending = await ctx.db.get(`SELECT COUNT(*) AS n FROM pending_actions WHERE status = 'PENDING'${pf.sql}`, pf.params);
    const topBlocked = await ctx.db.all(`SELECT method, path, COUNT(*) AS count FROM agent_logs
     WHERE timestamp >= ? AND status IN ('BLOCKED', 'RATE_LIMITED', 'REJECTED', 'RESPONSE_BLOCKED')${wf.sql}
     GROUP BY method, path ORDER BY count DESC LIMIT 5`, [since, ...wf.params]);
    const topCallers = await ctx.db.all(`SELECT COALESCE(agent_key, caller_ip, user_agent, 'unknown') AS caller, COUNT(*) AS blocked FROM agent_logs
     WHERE timestamp >= ? AND status IN ('BLOCKED', 'RATE_LIMITED', 'REJECTED', 'RESPONSE_BLOCKED')${wf.sql}
     GROUP BY caller ORDER BY blocked DESC LIMIT 5`, [since, ...wf.params]);
    const round = (n) => Math.round((n ?? 0) * 100) / 100;
    const globalEmergency = ctx.emergency.current();
    const ws = workspaceId !== null ? ctx.workspaces.get(workspaceId) : undefined;
    let emergency = globalEmergency;
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
const fmt = (n) => n.toLocaleString("en-US", { maximumFractionDigits: 2 });
function modeLabel(mode) {
    return mode === "lockdown" ? "🔴 LOCKDOWN (all agent requests refused)" : mode === "approval_only" ? "🟠 APPROVAL-ONLY (every write needs a human)" : "🟢 Normal";
}
/** Plain-text lines for chat messages (digest, /status). */
function summaryLines(s) {
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
        lines.push(`Budget ${b.workspaceId !== constants_1.DEFAULT_WORKSPACE_ID ? `[${b.workspaceSlug}] ` : ""}${b.ruleKey}: ${fmt(b.spent)} / ${fmt(b.max)} per ${b.windowMinutes} min${b.per === "caller" ? " (per agent)" : ""}`);
    }
    if (s.topBlocked.length)
        lines.push(`Most blocked: ${s.topBlocked.map((t) => `${t.method} ${t.path} ×${t.count}`).join(", ")}`);
    return lines;
}
