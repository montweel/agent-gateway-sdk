"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.registerAuditRoutes = registerAuditRoutes;
const constants_1 = require("../constants");
const simulator_1 = require("../simulator");
const utils_1 = require("../utils");
const scope_1 = require("./scope");
/**
 *   GET  /audit/verify          walks the hash-chained audit ledger and proves it was not modified
 *                               (Pro / Agency). Seals any rows written in the last moment first.
 *   GET  /audit/head            the current chain head (any user; write it down / it is in the digest)
 *   POST /simulate/history      { limit?: 1-5000, rules?: <candidate rules> } -> what the last N recorded
 *                               requests would have done under these rules (current rules when omitted)
 */
function registerAuditRoutes(router, ctx) {
    router.get("/audit/verify", async (_req, res) => {
        if (!ctx.license.current().features.auditVerification) {
            (0, scope_1.sendLicenseRequired)(res, "auditVerification", "Tamper-evident ledger verification is a Mont Pro feature. Every row is still hash-chained; activate a key to verify it.");
            return;
        }
        try {
            await ctx.ledger.sealPending();
            res.json(await ctx.ledger.verify());
        }
        catch (err) {
            (0, utils_1.sendInternalError)(res, "Audit verify error", err, "Could not verify the audit ledger.");
        }
    });
    router.get("/audit/head", async (_req, res) => {
        try {
            await ctx.ledger.sealPending();
            res.json({ head: await ctx.ledger.head() });
        }
        catch (err) {
            (0, utils_1.sendInternalError)(res, "Audit head error", err, "Could not read the audit ledger head.");
        }
    });
    router.post("/simulate/history", async (req, res) => {
        const scoped = (0, scope_1.readScope)(ctx, req, res);
        if (scoped === undefined)
            return;
        // Candidate rules belong to one workspace; without candidates, "all" replays every workspace with its own rules.
        const body = (req.body ?? {});
        let workspaceId = scoped?.id ?? null;
        if (body.rules !== undefined && workspaceId === null) {
            const ws = (0, scope_1.requireWorkspace)(ctx, req, res);
            if (!ws)
                return;
            workspaceId = ws.id;
        }
        if (body.limit !== undefined && (!Number.isInteger(body.limit) || body.limit < 1 || body.limit > 5000)) {
            (0, utils_1.sendError)(res, 400, "Bad Request", "limit must be a whole number from 1 to 5000.");
            return;
        }
        let candidate;
        if (body.rules !== undefined) {
            if (typeof body.rules !== "object" || body.rules === null || Array.isArray(body.rules)) {
                (0, utils_1.sendError)(res, 400, "Bad Request", "rules must be an object like rules.json.");
                return;
            }
            candidate = {};
            for (const [rawKey, value] of Object.entries(body.rules)) {
                const parsed = (0, utils_1.parseRuleKey)(rawKey);
                if ("error" in parsed) {
                    (0, utils_1.sendError)(res, 400, "Bad Request", `Invalid endpoint "${rawKey}". ${parsed.error}`);
                    return;
                }
                const problem = (0, utils_1.validateRulePath)(parsed.path);
                if (problem) {
                    (0, utils_1.sendError)(res, 400, "Bad Request", `Invalid endpoint "${rawKey}". ${problem}`);
                    return;
                }
                const mode = typeof value === "object" && value !== null ? value.mode : undefined;
                if (typeof value === "object" && value !== null && (typeof mode !== "string" || !constants_1.RULE_MODES.includes(mode))) {
                    (0, utils_1.sendError)(res, 400, "Bad Request", `mode for "${rawKey}" must be one of ${constants_1.RULE_MODES.join(", ")}.`);
                    return;
                }
                const rule = (0, utils_1.normalizeRule)(value);
                if (!rule) {
                    (0, utils_1.sendError)(res, 400, "Bad Request", `Rule "${rawKey}" must be true/false or { mode, ... }.`);
                    return;
                }
                if (/\[(policies|guards) invalid: enforced as BLOCK\]/.test(rule.description)) {
                    (0, utils_1.sendError)(res, 400, "Bad Request", `Rule "${rawKey}" has invalid policies, budget or dedupe settings.`);
                    return;
                }
                candidate[(0, utils_1.ruleKey)(parsed.method, parsed.path)] = rule;
            }
        }
        try {
            res.json(await (0, simulator_1.simulateHistory)(ctx, { workspaceId, limit: body.limit ?? 500, rules: candidate }));
        }
        catch (err) {
            (0, utils_1.sendInternalError)(res, "Simulation error", err, "Could not replay the history.");
        }
    });
}
