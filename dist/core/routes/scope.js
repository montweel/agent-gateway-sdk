"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.readScope = readScope;
exports.requireWorkspace = requireWorkspace;
exports.actorOf = actorOf;
exports.sendLicenseRequired = sendLicenseRequired;
const constants_1 = require("../constants");
const utils_1 = require("../utils");
/**
 * Admin API workspace scope. The dashboard's Workspace Switcher sends the selected client as the
 * x-mont-workspace header (scripts may use ?workspace=<slug> instead):
 *
 *   absent or "all"  -> every workspace (lists, summaries, exports)
 *   "<slug>"         -> that workspace only
 *
 * Endpoints that act on ONE workspace (rules, presets, emergency, history replay) use
 * requireWorkspace: absent = the default workspace, "all" = 400.
 */
function selector(req) {
    const header = req.get(constants_1.WORKSPACE_HEADER)?.trim();
    if (header)
        return header.toLowerCase();
    const q = req.query.workspace;
    return typeof q === "string" && q.trim() ? q.trim().toLowerCase() : null;
}
/** undefined = response already sent (unknown workspace). null = all workspaces. */
function readScope(ctx, req, res) {
    const s = selector(req);
    if (s === null || s === "all")
        return null;
    const ws = ctx.workspaces.bySlug(s);
    if (!ws) {
        (0, utils_1.sendError)(res, 404, "Not Found", `Unknown workspace "${s}".`);
        return undefined;
    }
    return ws;
}
/** undefined = response already sent. */
function requireWorkspace(ctx, req, res) {
    const s = selector(req);
    if (s === null)
        return ctx.workspaces.defaultWorkspace();
    if (s === "all") {
        (0, utils_1.sendError)(res, 400, "Bad Request", "Pick one workspace for this action (x-mont-workspace: <slug>), not all of them.");
        return undefined;
    }
    const ws = ctx.workspaces.bySlug(s);
    if (!ws) {
        (0, utils_1.sendError)(res, 404, "Not Found", `Unknown workspace "${s}".`);
        return undefined;
    }
    return ws;
}
function actorOf(req) {
    return req.user ? (req.user.sso ? `sso:${req.user.username}` : req.user.username) : "admin";
}
/** 402 with the same `proRequired` marker the dashboard already understands. */
function sendLicenseRequired(res, feature, message) {
    (0, utils_1.sendError)(res, 402, "Payment Required", message, { proRequired: true, feature, upgradeUrl: "https://montweel.com/#license-renewal" });
}
