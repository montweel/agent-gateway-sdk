"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.simulateHistory = simulateHistory;
const crypto_1 = __importDefault(require("crypto"));
const policy_1 = require("./policy");
const rules_1 = require("./rules");
const protection_1 = require("./protection");
const HISTORICAL = {
    ALLOWED: "ALLOW",
    BLOCKED: "BLOCK",
    QUEUED: "REQUIRE_APPROVAL",
    RATE_LIMITED: "RATE_LIMITED",
};
const zero = () => ({ ALLOW: 0, BLOCK: 0, REQUIRE_APPROVAL: 0, RATE_LIMITED: 0 });
async function simulateHistory(ctx, opts) {
    const limit = Math.min(Math.max(Math.trunc(opts.limit) || 500, 1), 5000);
    const maxRows = opts.maxRows ?? 200;
    const wf = (0, protection_1.workspaceFilter)(opts.workspaceId);
    // The entry rows of the rule pipeline (decisions are separate APPROVED / REJECTED rows).
    const rows = (await ctx.db.all(`SELECT id, timestamp, method, path, status, amount, request_snapshot, workspace_id FROM agent_logs
       WHERE status IN ('ALLOWED', 'BLOCKED', 'QUEUED', 'RATE_LIMITED')${wf.sql}
       ORDER BY id DESC LIMIT ?`, [...wf.params, limit])).reverse();
    // One ruleset per workspace (or the candidate), compiled once.
    const wsId = opts.workspaceId;
    const matchers = new Map();
    const candidate = opts.rules ? (0, rules_1.matcherFor)(opts.rules) : null;
    const lookup = (rowWs, method, path) => {
        if (candidate)
            return candidate(method, path);
        let m = matchers.get(rowWs);
        if (!m) {
            m = (0, rules_1.matcherFor)(ctx.workspaces.rules(rowWs));
            matchers.set(rowWs, m);
        }
        return m(method, path);
    };
    const globalLimit = ctx.config.load().rateLimitPerMinute;
    const report = {
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
    const transitions = new Map();
    const rateWindows = new Map();
    const spend = new Map();
    const seen = new Map(); // dedupe fingerprint -> last ts
    const changedRows = [];
    for (const row of rows) {
        const historical = HISTORICAL[row.status];
        if (!historical)
            continue;
        if (!row.request_snapshot) {
            report.skippedNoSnapshot++;
            continue;
        }
        let snap;
        try {
            snap = JSON.parse(row.request_snapshot);
        }
        catch {
            report.skippedNoSnapshot++;
            continue;
        }
        const rowWs = row.workspace_id ?? 1;
        const ts = Date.parse(row.timestamp);
        const caller = typeof snap.caller === "string" ? snap.caller : "unknown";
        const entry = lookup(rowWs, row.method, row.path);
        const bodyKnown = !snap.bodyUnknown && !snap.truncated;
        let simulated;
        let reason;
        let shadow = null;
        // 1. Rate limit (sliding 60 s window per caller, per rule bucket when the rule sets one).
        const custom = typeof entry?.rule.rateLimit === "number" && entry.rule.rateLimit > 0 ? entry.rule.rateLimit : null;
        const bucket = custom ? `${caller}|${entry.key}` : `${caller}|*`;
        const hits = (rateWindows.get(bucket) ?? []).filter((t) => t > ts - 60000);
        hits.push(ts);
        rateWindows.set(bucket, hits);
        const limitHit = hits.length > (custom ?? globalLimit);
        if (limitHit) {
            simulated = "RATE_LIMITED";
            reason = `rate limit ${custom ?? globalLimit}/min`;
        }
        else if (!entry) {
            simulated = "BLOCK";
            reason = "default-deny";
        }
        else if (!bodyKnown && (0, policy_1.policiesReadBody)(entry.rule)) {
            report.unevaluable++;
            continue;
        }
        else {
            const input = { body: snap.body ?? undefined, query: snap.query ?? {}, headers: snap.headers ?? {} };
            const split = (0, policy_1.splitShadow)((0, policy_1.evaluateRule)(entry.rule, input));
            shadow = split.shadow;
            simulated = split.decision.mode === "ALLOW" ? "ALLOW" : split.decision.mode === "BLOCK" ? "BLOCK" : "REQUIRE_APPROVAL";
            reason = split.decision.matched;
            // 2. Duplicate protection.
            const dd = entry.rule.dedupe;
            if (dd && simulated !== "BLOCK" && bodyKnown) {
                const values = [];
                let identifiable = true;
                for (const f of dd.fields) {
                    const r = (0, policy_1.resolveField)(input, f);
                    if (!r.found || (typeof r.value === "object" && r.value !== null)) {
                        identifiable = false;
                        break;
                    }
                    values.push(r.value);
                }
                if (identifiable) {
                    const fp = crypto_1.default.createHash("sha256").update(`${rowWs}|${entry.key}\n${JSON.stringify(values)}`).digest("hex");
                    const last = seen.get(fp);
                    if (last !== undefined && last >= ts - dd.windowMinutes * 60000) {
                        simulated = dd.onDuplicate === "BLOCK" ? "BLOCK" : "REQUIRE_APPROVAL";
                        reason = "duplicate";
                    }
                    else {
                        seen.set(fp, ts);
                    }
                }
            }
            // 3. Spending budget (only for what would run without a human).
            const b = entry.rule.budget;
            if (b && simulated === "ALLOW") {
                const amount = bodyKnown ? (0, policy_1.resolveField)(input, b.field) : { found: false };
                if (!amount.found || typeof amount.value !== "number" || !Number.isFinite(amount.value) || amount.value < 0) {
                    simulated = b.onExceed === "BLOCK" ? "BLOCK" : "REQUIRE_APPROVAL";
                    reason = "budget (amount unreadable)";
                }
                else {
                    const key = `${rowWs}|${entry.key}`;
                    const ledger = (spend.get(key) ?? []).filter((e) => e.ts >= ts - b.windowMinutes * 60000);
                    const used = ledger.filter((e) => b.per === "global" || e.caller === caller).reduce((n, e) => n + e.amount, 0);
                    if (used + amount.value > b.max) {
                        simulated = b.onExceed === "BLOCK" ? "BLOCK" : "REQUIRE_APPROVAL";
                        reason = "budget";
                    }
                    else {
                        ledger.push({ ts, amount: amount.value, caller });
                    }
                    spend.set(key, ledger);
                }
            }
        }
        report.evaluated++;
        report.historical[historical]++;
        report.simulated[simulated]++;
        if (simulated === "ALLOW" && shadow === "BLOCK")
            report.shadow.wouldBlock++;
        if (simulated === "ALLOW" && shadow === "APPROVAL")
            report.shadow.wouldHold++;
        if (simulated !== historical) {
            report.changed++;
            const k = `${historical}>${simulated}`;
            transitions.set(k, (transitions.get(k) ?? 0) + 1);
            if (simulated === "BLOCK") {
                report.wouldBlock++;
                if (historical === "ALLOW")
                    report.moneyNewlyBlocked += row.amount ?? 0;
            }
            else if (simulated === "REQUIRE_APPROVAL" && historical === "ALLOW")
                report.wouldHold++;
            else if (simulated === "RATE_LIMITED")
                report.wouldRateLimit++;
            else if (simulated === "ALLOW")
                report.wouldAllow++;
            changedRows.push({ logId: row.id, timestamp: row.timestamp, method: row.method, path: row.path, historical, simulated, reason, shadow, amount: row.amount, caller });
        }
    }
    report.transitions = [...transitions.entries()]
        .map(([k, count]) => {
        const [from, to] = k.split(">");
        return { from, to, count };
    })
        .sort((a, b) => b.count - a.count);
    report.rows = changedRows.reverse().slice(0, maxRows);
    report.moneyNewlyBlocked = Math.round(report.moneyNewlyBlocked * 100) / 100;
    return report;
}
