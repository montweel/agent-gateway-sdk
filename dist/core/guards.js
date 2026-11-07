"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateDedupe = exports.validateBudget = void 0;
exports.extractAmount = extractAmount;
exports.callerIdOf = callerIdOf;
exports.createGuards = createGuards;
const crypto_1 = __importDefault(require("crypto"));
var policy_1 = require("./policy");
Object.defineProperty(exports, "validateBudget", { enumerable: true, get: function () { return policy_1.validateBudget; } });
Object.defineProperty(exports, "validateDedupe", { enumerable: true, get: function () { return policy_1.validateDedupe; } });
const policy_2 = require("./policy");
const utils_1 = require("./utils");
/**
 * Stateful guards that look across requests (policies only see one request at a time):
 *
 *   budget  "agents may auto-refund at most $300 per hour" - 20 refunds of $90 each would
 *           pass a per-request "amount <= 100" tier, but not this.
 *   dedupe  "never the same refund twice" - a looping agent re-issuing a refund for the same
 *           orderId is refused (or held) while the first one is allowed, queued or executed.
 *
 * Both are persistent (SQLite guard_ledger, survive restarts) and race-free inside a process:
 * check-and-record for a rule runs under a per-rule lock, so a burst of 50 concurrent requests
 * cannot all see "budget left" before any of them is recorded. Every failure fails closed.
 */
/** Best-effort money value of a request body, used for audit rows and "money protected" totals. */
function extractAmount(body) {
    if (typeof body !== "object" || body === null || Array.isArray(body))
        return null;
    const b = body;
    for (const k of ["amount", "total", "price", "value", "refund_amount", "refundAmount"]) {
        const v = b[k];
        if (typeof v === "number" && Number.isFinite(v) && v >= 0)
            return v;
    }
    // One level down: { refund: { amount } }, { order: { total } } ...
    for (const v of Object.values(b)) {
        if (typeof v === "object" && v !== null && !Array.isArray(v)) {
            const inner = v;
            for (const k of ["amount", "total"]) {
                const x = inner[k];
                if (typeof x === "number" && Number.isFinite(x) && x >= 0)
                    return x;
            }
        }
    }
    return null;
}
/** Identity used for per-caller budgets: the agent key when there is one, else the IP bucket. */
function callerIdOf(caller) {
    return caller.agentKeyId !== null ? `key:${caller.agentKeyId}` : `ip:${caller.ip}`;
}
function createGuards(ctx) {
    const locks = new Map();
    const timed = (p, label) => (0, utils_1.withTimeout)(p, ctx.dbTimeoutMs, label);
    /** FIFO lock per key. Resolves with a release function. */
    async function lock(key) {
        const prev = locks.get(key) ?? Promise.resolve();
        let release;
        const mine = new Promise((r) => (release = r));
        const chained = prev.then(() => mine);
        locks.set(key, chained);
        await prev;
        let released = false;
        return () => {
            if (released)
                return;
            released = true;
            release();
            if (locks.get(key) === chained)
                locks.delete(key);
        };
    }
    function fingerprintOf(ruleKey, spec, body) {
        const values = [];
        for (const f of spec.fields) {
            const r = (0, policy_2.resolveField)({ body, query: {}, headers: {} }, f);
            if (!r.found || (typeof r.value === "object" && r.value !== null))
                return null; // cannot identify the action
            values.push(r.value);
        }
        return crypto_1.default.createHash("sha256").update(`${ruleKey}\n${JSON.stringify(values)}`).digest("hex");
    }
    async function spent(ruleKey, spec, callerId) {
        const since = Date.now() - spec.windowMinutes * 60000;
        const row = await timed(ctx.db.get(`SELECT SUM(amount) AS s FROM guard_ledger WHERE rule_key = ? AND kind = 'spend' AND ts >= ?${callerId ? " AND caller = ?" : ""}`, callerId ? [ruleKey, since, callerId] : [ruleKey, since]), "budget lookup");
        return row?.s ?? 0;
    }
    async function evaluate(ruleKey, rule, decision, body, callerId) {
        const passthrough = { decision, reason: null, commit: async () => undefined, release: () => undefined };
        if (!ruleKey || !rule || (!rule.budget && !rule.dedupe) || decision.mode === "BLOCK")
            return passthrough;
        const release = await lock(ruleKey);
        try {
            let current = decision;
            let reason = null;
            let fingerprint = null;
            let spendAmount = null;
            // ---- duplicate protection ----
            if (rule.dedupe) {
                fingerprint = fingerprintOf(ruleKey, rule.dedupe, body);
                if (fingerprint) {
                    const since = Date.now() - rule.dedupe.windowMinutes * 60000;
                    // A duplicate of something allowed, waiting, executing or executed. Rejected / expired
                    // attempts do not count, so a legitimately retried action is not refused forever.
                    const dup = await timed(ctx.db.get(`SELECT g.id FROM guard_ledger g LEFT JOIN pending_actions p ON p.id = g.action_id
               WHERE g.rule_key = ? AND g.kind = 'dedupe' AND g.fingerprint = ? AND g.ts >= ?
                 AND (g.action_id IS NULL OR p.status IN ('PENDING', 'EXECUTING', 'APPROVED', 'FAILED'))
               LIMIT 1`, [ruleKey, fingerprint, since]), "duplicate lookup");
                    if (dup) {
                        current = { mode: rule.dedupe.onDuplicate, matched: "duplicate" };
                        reason = `Duplicate of an action already sent in the last ${rule.dedupe.windowMinutes} minutes (${rule.dedupe.fields.join(", ")}).`;
                    }
                }
            }
            // ---- spending budget (only for what would run without a human) ----
            if (rule.budget && current.mode === "ALLOW") {
                const spec = rule.budget;
                const amount = (0, policy_2.resolveField)({ body, query: {}, headers: {} }, spec.field);
                if (!amount.found || typeof amount.value !== "number" || !Number.isFinite(amount.value) || amount.value < 0) {
                    // Fail closed: an amount we cannot read cannot be checked against the budget.
                    current = { mode: spec.onExceed, matched: "budget" };
                    reason = `${spec.field} is missing or not a number, so the spending budget cannot be checked.`;
                }
                else {
                    const used = await spent(ruleKey, spec, spec.per === "caller" ? callerId : null);
                    if (used + amount.value > spec.max) {
                        current = { mode: spec.onExceed, matched: "budget" };
                        reason = `Spending budget reached: ${used} of ${spec.max} used in the last ${spec.windowMinutes} minutes; this request adds ${amount.value}.`;
                        ctx.alerts.event("budget", ruleKey, `Spending budget reached on ${ruleKey}`, [
                            `Used ${used} of ${spec.max} in the last ${spec.windowMinutes} min${spec.per === "caller" ? ` by ${callerId}` : ""}.`,
                            `Requests over budget now ${spec.onExceed === "BLOCK" ? "are blocked" : "need your approval"}.`,
                        ]);
                    }
                    else {
                        spendAmount = amount.value;
                    }
                }
            }
            const finalDecision = current;
            return {
                decision: finalDecision,
                reason,
                async commit(actionId) {
                    const now = Date.now();
                    if (fingerprint && finalDecision.mode !== "BLOCK") {
                        await timed(ctx.db.run("INSERT INTO guard_ledger (rule_key, kind, caller, fingerprint, amount, action_id, ts) VALUES (?, 'dedupe', ?, ?, NULL, ?, ?)", [
                            ruleKey,
                            callerId,
                            fingerprint,
                            actionId,
                            now,
                        ]), "duplicate record");
                    }
                    if (spendAmount !== null && finalDecision.mode === "ALLOW") {
                        await timed(ctx.db.run("INSERT INTO guard_ledger (rule_key, kind, caller, fingerprint, amount, action_id, ts) VALUES (?, 'spend', ?, NULL, ?, ?, ?)", [
                            ruleKey,
                            callerId,
                            spendAmount,
                            actionId,
                            now,
                        ]), "budget record");
                    }
                },
                release,
            };
        }
        catch (err) {
            release();
            throw err;
        }
    }
    async function recordApproved(ruleKey, rule, body, actionId, callerId) {
        if (!rule.budget)
            return;
        const amount = (0, policy_2.resolveField)({ body, query: {}, headers: {} }, rule.budget.field);
        if (!amount.found || typeof amount.value !== "number" || !Number.isFinite(amount.value) || amount.value < 0)
            return;
        await ctx.db.run("INSERT INTO guard_ledger (rule_key, kind, caller, fingerprint, amount, action_id, ts) VALUES (?, 'spend', ?, NULL, ?, ?, ?)", [
            ruleKey,
            callerId,
            amount.value,
            actionId,
            Date.now(),
        ]);
    }
    async function usage() {
        const rules = ctx.rules.load();
        const out = [];
        for (const [key, rule] of Object.entries(rules)) {
            if (!rule.budget)
                continue;
            const spec = rule.budget;
            const since = Date.now() - spec.windowMinutes * 60000;
            let used;
            if (spec.per === "global") {
                used = await spent(key, spec, null);
            }
            else {
                const row = await ctx.db.get("SELECT MAX(t) AS s FROM (SELECT SUM(amount) AS t FROM guard_ledger WHERE rule_key = ? AND kind = 'spend' AND ts >= ? GROUP BY caller)", [key, since]);
                used = row?.s ?? 0;
            }
            out.push({ ruleKey: key, field: spec.field, max: spec.max, windowMinutes: spec.windowMinutes, per: spec.per, onExceed: spec.onExceed, spent: used, remaining: Math.max(0, spec.max - used) });
        }
        return out;
    }
    return { evaluate, recordApproved, usage };
}
