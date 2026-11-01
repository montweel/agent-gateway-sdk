import type { Response, Router } from "express";
import type { GatewayContext } from "../context";
import type { AuthenticatedRequest } from "../types";
import { sendError, sendInternalError, sendProRequired } from "../utils";

const KEY_NAME_REGEX = /^[a-zA-Z0-9._@ -]{1,64}$/;
const MAX_AGENT_KEYS = 500;
const COMMUNITY_MAX_AGENT_KEYS = 2;

/** Agent API keys. Admin-only: the list shows prefixes, never full keys. */
export function registerAgentKeyRoutes(router: Router, ctx: GatewayContext): void {
  const { db, auth, agentKeys, license } = ctx;

  router.get("/agent-keys", async (req: AuthenticatedRequest, res: Response) => {
    if (!auth.requireAdmin(req, res)) return;
    try {
      res.json(await agentKeys.list());
    } catch (err) {
      sendInternalError(res, "List agent keys error", err, "Could not load agent keys.");
    }
  });

  router.post("/agent-keys", async (req: AuthenticatedRequest, res: Response) => {
    if (!auth.requireAdmin(req, res)) return;
    try {
      const rawName = (req.body as { name?: unknown } | undefined)?.name;
      const name = typeof rawName === "string" ? rawName.trim() : "";
      if (!KEY_NAME_REGEX.test(name)) {
        sendError(
          res,
          400,
          "Bad Request",
          "name must be 1–64 characters: letters, numbers, spaces, '.', '_', '@' or '-'."
        );
        return;
      }

      const count = await db.get<{ count: number }>("SELECT COUNT(*) as count FROM agent_keys");
      if ((count?.count ?? 0) >= COMMUNITY_MAX_AGENT_KEYS && !(await license.isPro())) {
        sendProRequired(res, "more than 2 Agent API keys");
        return;
      }
      if ((count?.count ?? 0) >= MAX_AGENT_KEYS) {
        sendError(res, 409, "Conflict", `You can have at most ${MAX_AGENT_KEYS} agent keys. Delete unused ones first.`);
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
    } catch (err) {
      sendInternalError(res, "Create agent key error", err, "Could not create the agent key.");
    }
  });

  router.delete("/agent-keys/:id", async (req: AuthenticatedRequest, res: Response) => {
    if (!auth.requireAdmin(req, res)) return;
    try {
      const id = Number(req.params.id);
      if (!Number.isInteger(id) || id < 1) {
        sendError(res, 400, "Bad Request", "Invalid agent key id.");
        return;
      }
      if (!(await agentKeys.remove(id))) {
        sendError(res, 404, "Not Found", "Agent key not found.");
        return;
      }
      res.json({ success: true, id });
    } catch (err) {
      sendInternalError(res, "Delete agent key error", err, "Could not delete the agent key.");
    }
  });
}
