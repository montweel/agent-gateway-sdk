"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DIGEST_WINDOW_HOURS = void 0;
exports.buildDigest = buildDigest;
exports.formatMoney = formatMoney;
exports.digestSentence = digestSentence;
const protection_1 = require("./protection");
/**
 * Zero-LLM "money saved" digest: one SQLite aggregation over the last 24 hours of agent_logs,
 * turned into a plain-English sentence by a fixed template. Nothing leaves the machine.
 *
 *   total requests   every request an agent sent (ALLOWED, BLOCKED, QUEUED, RATE_LIMITED rows;
 *                    a human's later APPROVED / REJECTED decision is not a second request)
 *   risky calls      BLOCKED by a rule / policy / budget / kill-switch, RATE_LIMITED, or
 *                    REJECTED by a human
 *   money prevented  the amount / price of those risky calls: the amount recorded with the row,
 *                    else body.amount / body.price from its redacted request snapshot
 */
exports.DIGEST_WINDOW_HOURS = 24;
/** A row the approval service wrote for a human's decision (not a new agent request). */
const DECISION_ROW = "COALESCE(user_agent, '') LIKE 'decided_by:%'";
/** A non-negative number stored as a JSON / SQLite number (never text like "5"). */
const isMoney = (expr) => `(typeof(${expr}) IN ('integer', 'real') AND ${expr} >= 0)`;
async function buildDigest(ctx, workspaceId = null, now = Date.now()) {
    const since = new Date(now - exports.DIGEST_WINDOW_HOURS * 3600000).toISOString();
    const wf = (0, protection_1.workspaceFilter)(workspaceId);
    const row = await ctx.db.get(`WITH w AS (
       SELECT status,
              ${DECISION_ROW} AS is_decision,
              amount,
              CASE WHEN request_snapshot IS NOT NULL AND json_valid(request_snapshot) THEN json_extract(request_snapshot, '$.body.amount') END AS snap_amount,
              CASE WHEN request_snapshot IS NOT NULL AND json_valid(request_snapshot) THEN json_extract(request_snapshot, '$.body.price') END AS snap_price
       FROM agent_logs
       WHERE timestamp >= ?${wf.sql}
     ),
     v AS (
       SELECT status,
              is_decision,
              (status IN ('BLOCKED', 'RATE_LIMITED') AND NOT is_decision) OR status = 'REJECTED' AS risky,
              CASE
                WHEN ${isMoney("amount")} THEN amount
                WHEN ${isMoney("snap_amount")} THEN snap_amount
                WHEN ${isMoney("snap_price")} THEN snap_price
              END AS value
       FROM w
     )
     SELECT
       SUM(CASE WHEN status IN ('ALLOWED', 'BLOCKED', 'QUEUED', 'RATE_LIMITED') AND NOT is_decision THEN 1 ELSE 0 END) AS total,
       SUM(CASE WHEN status = 'BLOCKED' AND NOT is_decision THEN 1 ELSE 0 END) AS blocked,
       SUM(CASE WHEN status = 'RATE_LIMITED' THEN 1 ELSE 0 END) AS rate_limited,
       SUM(CASE WHEN status = 'REJECTED' THEN 1 ELSE 0 END) AS rejected,
       SUM(CASE WHEN risky THEN value END) AS money,
       SUM(CASE WHEN risky AND value IS NOT NULL THEN 1 ELSE 0 END) AS with_amount
     FROM v`, [since, ...wf.params]);
    await ctx.approvals.expireStale().catch(() => undefined);
    const pf = (0, protection_1.workspaceFilter)(workspaceId);
    const pending = await ctx.db.get(`SELECT COUNT(*) AS n FROM pending_actions WHERE status = 'PENDING'${pf.sql}`, pf.params);
    const totalRequests = row?.total ?? 0;
    const blocked = row?.blocked ?? 0;
    const rateLimited = row?.rate_limited ?? 0;
    const rejected = row?.rejected ?? 0;
    const moneyPrevented = Math.round((row?.money ?? 0) * 100) / 100;
    const pendingApprovals = pending?.n ?? 0;
    const digest = {
        windowHours: exports.DIGEST_WINDOW_HOURS,
        since,
        generatedAt: new Date(now).toISOString(),
        workspaceId,
        totalRequests,
        blocked,
        rateLimited,
        rejected,
        riskyCalls: blocked + rateLimited + rejected,
        moneyPrevented,
        riskyCallsWithAmount: row?.with_amount ?? 0,
        pendingApprovals,
    };
    return { ...digest, summary: digestSentence(digest) };
}
const plural = (n, one, many) => `${n.toLocaleString("en-US")} ${n === 1 ? one : many}`;
function formatMoney(n) {
    return `$${n.toLocaleString("en-US", { minimumFractionDigits: Number.isInteger(n) ? 0 : 2, maximumFractionDigits: 2 })}`;
}
/** The template. Deterministic: same numbers in, same sentence out. */
function digestSentence(d) {
    const parts = [];
    if (d.totalRequests === 0 && d.riskyCalls === 0) {
        parts.push(`Mont saw no agent actions in the last ${d.windowHours} hours.`);
    }
    else {
        let sentence = `In the last ${d.windowHours} hours, Mont processed ${plural(d.totalRequests, "action", "actions")} and blocked ${plural(d.riskyCalls, "risky call", "risky calls")}`;
        const breakdown = [];
        if (d.blocked)
            breakdown.push(`${d.blocked.toLocaleString("en-US")} by your rules`);
        if (d.rateLimited)
            breakdown.push(`${d.rateLimited.toLocaleString("en-US")} for going too fast`);
        if (d.rejected)
            breakdown.push(`${d.rejected.toLocaleString("en-US")} rejected by you`);
        if (breakdown.length > 1)
            sentence += ` (${breakdown.join(", ")})`;
        sentence +=
            d.moneyPrevented > 0
                ? `, preventing an estimated ${formatMoney(d.moneyPrevented)} in unauthorized actions.`
                : d.riskyCalls > 0
                    ? " (none of them carried a dollar amount)."
                    : ".";
        parts.push(sentence);
    }
    parts.push(d.pendingApprovals === 0
        ? "Nothing is waiting for your approval."
        : `You have ${plural(d.pendingApprovals, "action", "actions")} pending approval.`);
    return parts.join(" ");
}
