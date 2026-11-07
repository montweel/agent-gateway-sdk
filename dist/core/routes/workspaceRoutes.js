"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.registerWorkspaceRoutes = registerWorkspaceRoutes;
const workspaces_1 = require("../workspaces");
const protection_1 = require("../protection");
const operatingMode_1 = require("../operatingMode");
const utils_1 = require("../utils");
const scope_1 = require("./scope");
/**
 * Multi-tenant workspaces (an agency's client stores).
 *
 *   GET    /workspaces                       list (+ license limit, entitlement per workspace)
 *   GET    /workspaces/overview?hours=24     "All Clients" numbers per workspace
 *   POST   /workspaces                       { name, slug?, upstreamUrl?, requireKey?, telegramChatId?, slackChannel?, timezone?, schedule? }  (admin)
 *                                            -> { workspace, apiKey }   (the key is shown once)
 *   PATCH  /workspaces/:slug                 same fields (admin; slug cannot change)
 *   POST   /workspaces/:slug/rotate-key      new mws_ key, the old one stops working at once (admin)
 *   DELETE /workspaces/:slug                 (admin; not the default one; not while approvals wait)
 */
function registerWorkspaceRoutes(router, ctx) {
    const view = (ws) => {
        const license = ctx.license.current();
        return { ...ws, entitled: ctx.workspaces.isEntitled(ws.id, license.maxWorkspaces), effectiveMode: (0, operatingMode_1.effectiveMode)(ctx, ws) };
    };
    const parseUpstream = (v) => (0, utils_1.parseTargetUrl)(v, ctx.port);
    const admin = (req, res) => {
        if (req.user?.role !== "admin") {
            (0, utils_1.sendError)(res, 403, "Forbidden", "Only administrators can manage workspaces.");
            return false;
        }
        return true;
    };
    const find = (slug, res) => {
        const ws = typeof slug === "string" ? ctx.workspaces.bySlug(slug) : undefined;
        if (!ws)
            (0, utils_1.sendError)(res, 404, "Not Found", `Unknown workspace "${String(slug)}".`);
        return ws;
    };
    const handle = (res, err, context) => {
        if (err instanceof workspaces_1.WorkspaceInputError)
            (0, utils_1.sendError)(res, 400, "Bad Request", err.message);
        else
            (0, utils_1.sendInternalError)(res, context, err, "Could not update the workspace.");
    };
    router.get("/workspaces", async (_req, res) => {
        try {
            await ctx.workspaces.refresh();
            const license = ctx.license.current();
            res.json({
                workspaces: ctx.workspaces.list().map(view),
                license: { tier: license.tier, maxWorkspaces: license.maxWorkspaces, multiWorkspace: license.features.multiWorkspace },
            });
        }
        catch (err) {
            (0, utils_1.sendInternalError)(res, "Workspaces error", err, "Could not load workspaces.");
        }
    });
    router.get("/workspaces/overview", async (req, res) => {
        try {
            const hours = Math.min(Math.max(Math.trunc(Number(req.query.hours)) || 24, 1), 24 * 31);
            const out = [];
            for (const ws of ctx.workspaces.list()) {
                const s = await (0, protection_1.buildSummary)(ctx, hours, ws.id);
                out.push({
                    workspace: view(ws),
                    counts: s.counts,
                    moneyProtected: s.moneyProtected,
                    moneyExecuted: s.moneyExecuted,
                    pending: s.pending,
                    shadow: s.shadow,
                    budgets: s.budgets,
                });
            }
            const totals = out.reduce((t, w) => ({
                moneyProtected: t.moneyProtected + w.moneyProtected,
                moneyExecuted: t.moneyExecuted + w.moneyExecuted,
                pending: t.pending + w.pending,
                blocked: t.blocked + w.counts.BLOCKED + w.counts.RATE_LIMITED + w.counts.RESPONSE_BLOCKED,
                allowed: t.allowed + w.counts.ALLOWED + w.counts.APPROVED,
            }), { moneyProtected: 0, moneyExecuted: 0, pending: 0, blocked: 0, allowed: 0 });
            res.json({ windowHours: hours, globalEmergency: ctx.emergency.current(), totals, workspaces: out });
        }
        catch (err) {
            (0, utils_1.sendInternalError)(res, "Workspace overview error", err, "Could not build the overview.");
        }
    });
    router.post("/workspaces", async (req, res) => {
        if (!admin(req, res))
            return;
        const license = ctx.license.current();
        // The default workspace counts as one: Community = 1 workspace in total.
        if (ctx.workspaces.list().length + 1 > license.maxWorkspaces) {
            (0, scope_1.sendLicenseRequired)(res, "multiWorkspace", license.features.multiWorkspace
                ? `Your ${license.tier} license covers ${license.maxWorkspaces} workspaces (the default one included). Upgrade to add more clients.`
                : "Multiple workspaces (one per client store) are a Mont Pro / Agency feature. Activate a license key to add clients.");
            return;
        }
        try {
            const body = (req.body ?? {});
            const { workspace, apiKey } = await ctx.workspaces.create(body, parseUpstream);
            res.status(201).json({ success: true, workspace: view(workspace), apiKey });
        }
        catch (err) {
            handle(res, err, "Create workspace error");
        }
    });
    router.patch("/workspaces/:slug", async (req, res) => {
        if (!admin(req, res))
            return;
        const ws = find(req.params.slug, res);
        if (!ws)
            return;
        try {
            const updated = await ctx.workspaces.update(ws.id, (req.body ?? {}), parseUpstream);
            res.json({ success: true, workspace: view(updated) });
        }
        catch (err) {
            handle(res, err, "Update workspace error");
        }
    });
    router.post("/workspaces/:slug/rotate-key", async (req, res) => {
        if (!admin(req, res))
            return;
        const ws = find(req.params.slug, res);
        if (!ws)
            return;
        try {
            const { workspace, apiKey } = await ctx.workspaces.rotateKey(ws.id);
            res.json({ success: true, workspace: view(workspace), apiKey });
        }
        catch (err) {
            handle(res, err, "Rotate workspace key error");
        }
    });
    router.delete("/workspaces/:slug", async (req, res) => {
        if (!admin(req, res))
            return;
        const ws = find(req.params.slug, res);
        if (!ws)
            return;
        try {
            const waiting = await ctx.db.get("SELECT COUNT(*) AS n FROM pending_actions WHERE workspace_id = ? AND status IN ('PENDING', 'EXECUTING')", [ws.id]);
            if ((waiting?.n ?? 0) > 0) {
                (0, utils_1.sendError)(res, 409, "Conflict", `Workspace "${ws.slug}" still has ${waiting?.n} request(s) waiting for a decision. Approve or reject them first.`);
                return;
            }
            await ctx.workspaces.remove(ws.id);
            res.json({ success: true, slug: ws.slug });
        }
        catch (err) {
            handle(res, err, "Delete workspace error");
        }
    });
}
