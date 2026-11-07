"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.buildSummary = buildSummary;
exports.modeLabel = modeLabel;
exports.summaryLines = summaryLines;
const STATUSES = ["ALLOWED", "BLOCKED", "QUEUED", "RATE_LIMITED", "APPROVED", "REJECTED"];
async function buildSummary(ctx, hours) {
    const sinceMs = Date.now() - hours * 3600000;
    const since = new Date(sinceMs).toISOString();
    const counts = Object.fromEntries(STATUSES.map((s) => [s, 0]));
    const rows = await ctx.db.all("SELECT status, COUNT(*) AS n FROM agent_logs WHERE timestamp >= ? GROUP BY status", [since]);
    for (const r of rows)
        if (STATUSES.includes(r.status))
            counts[r.status] = r.n;
    const money = await ctx.db.get(`SELECT SUM(CASE WHEN status IN ('BLOCKED', 'REJECTED') THEN amount END) AS protected,
            SUM(CASE WHEN status IN ('ALLOWED', 'APPROVED') THEN amount END) AS executed
     FROM agent_logs WHERE timestamp >= ? AND amount IS NOT NULL`, [since]);
    const pending = await ctx.db.get("SELECT COUNT(*) AS n FROM pending_actions WHERE status = 'PENDING'");
    const topBlocked = await ctx.db.all(`SELECT method, path, COUNT(*) AS count FROM agent_logs
     WHERE timestamp >= ? AND status IN ('BLOCKED', 'RATE_LIMITED', 'REJECTED')
     GROUP BY method, path ORDER BY count DESC LIMIT 5`, [since]);
    const topCallers = await ctx.db.all(`SELECT COALESCE(agent_key, caller_ip, user_agent, 'unknown') AS caller, COUNT(*) AS blocked FROM agent_logs
     WHERE timestamp >= ? AND status IN ('BLOCKED', 'RATE_LIMITED', 'REJECTED')
     GROUP BY caller ORDER BY blocked DESC LIMIT 5`, [since]);
    const round = (n) => Math.round((n ?? 0) * 100) / 100;
    return {
        windowHours: hours,
        since,
        counts,
        moneyProtected: round(money?.protected),
        moneyExecuted: round(money?.executed),
        pending: pending?.n ?? 0,
        emergency: ctx.emergency.current(),
        budgets: await ctx.guards.usage(),
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
    for (const b of s.budgets) {
        lines.push(`Budget ${b.ruleKey}: ${fmt(b.spent)} / ${fmt(b.max)} per ${b.windowMinutes} min${b.per === "caller" ? " (per agent)" : ""}`);
    }
    if (s.topBlocked.length)
        lines.push(`Most blocked: ${s.topBlocked.map((t) => `${t.method} ${t.path} ×${t.count}`).join(", ")}`);
    return lines;
}
