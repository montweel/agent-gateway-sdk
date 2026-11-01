"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.registerAgentKeyRoutes = registerAgentKeyRoutes;
const utils_1 = require("../utils");
const KEY_NAME_REGEX = /^[a-zA-Z0-9._@ -]{1,64}$/;
const MAX_AGENT_KEYS = 500;
const COMMUNITY_MAX_AGENT_KEYS = 2;
/** Agent API keys. Admin-only: the list shows prefixes, never full keys. */
function registerAgentKeyRoutes(router, ctx) {
    const { db, auth, agentKeys, license } = ctx;
    router.get("/agent-keys", async (req, res) => {
        if (!auth.requireAdmin(req, res))
            return;
        try {
            res.json(await agentKeys.list());
        }
        catch (err) {
            (0, utils_1.sendInternalError)(res, "List agent keys error", err, "Could not load agent keys.");
        }
    });
    router.post("/agent-keys", async (req, res) => {
        if (!auth.requireAdmin(req, res))
            return;
        try {
            const rawName = req.body?.name;
            const name = typeof rawName === "string" ? rawName.trim() : "";
            if (!KEY_NAME_REGEX.test(name)) {
                (0, utils_1.sendError)(res, 400, "Bad Request", "name must be 1–64 characters: letters, numbers, spaces, '.', '_', '@' or '-'.");
                return;
            }
            const count = await db.get("SELECT COUNT(*) as count FROM agent_keys");
            if ((count?.count ?? 0) >= COMMUNITY_MAX_AGENT_KEYS && !(await license.isPro())) {
                const message = "Community Edition is limited to 2 Agent API keys. Renew your free Mont Pro key (no payment details required) to unlock unlimited keys.";
                res.status(403).json({ error: message, message, proRequired: true });
                return;
            }
            if ((count?.count ?? 0) >= MAX_AGENT_KEYS) {
                (0, utils_1.sendError)(res, 409, "Conflict", `You can have at most ${MAX_AGENT_KEYS} agent keys. Delete unused ones first.`);
                return;
            }
            const created = await agentKeys.create(name);
            res.status(201).json({
                success: true,
                id: created.id,
                name: created.name,
                keyPrefix: created.keyPrefix,
                createdAt: created.createdAt,
                // Shown exactly once. Only a SHA-256 hash is stored, so it cannot be recovered later.
                key: created.key,
            });
        }
        catch (err) {
            (0, utils_1.sendInternalError)(res, "Create agent key error", err, "Could not create the agent key.");
        }
    });
    router.delete("/agent-keys/:id", async (req, res) => {
        if (!auth.requireAdmin(req, res))
            return;
        try {
            const id = Number(req.params.id);
            if (!Number.isInteger(id) || id < 1) {
                (0, utils_1.sendError)(res, 400, "Bad Request", "Invalid agent key id.");
                return;
            }
            if (!(await agentKeys.remove(id))) {
                (0, utils_1.sendError)(res, 404, "Not Found", "Agent key not found.");
                return;
            }
            res.json({ success: true, id });
        }
        catch (err) {
            (0, utils_1.sendInternalError)(res, "Delete agent key error", err, "Could not delete the agent key.");
        }
    });
}
