import type { Request, Response } from "express";
import type { GatewayContext } from "../context";
import type { AuthenticatedRequest } from "../types";
import type { Workspace } from "../workspaces";
import { WORKSPACE_HEADER } from "../constants";
import { sendError } from "../utils";

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
function selector(req: Request): string | null {
  const header = req.get(WORKSPACE_HEADER)?.trim();
  if (header) return header.toLowerCase();
  const q = req.query.workspace;
  return typeof q === "string" && q.trim() ? q.trim().toLowerCase() : null;
}

/** undefined = response already sent (unknown workspace). null = all workspaces. */
export function readScope(ctx: GatewayContext, req: Request, res: Response): Workspace | null | undefined {
  const s = selector(req);
  if (s === null || s === "all") return null;
  const ws = ctx.workspaces.bySlug(s);
  if (!ws) {
    sendError(res, 404, "Not Found", `Unknown workspace "${s}".`);
    return undefined;
  }
  return ws;
}

/** undefined = response already sent. */
export function requireWorkspace(ctx: GatewayContext, req: Request, res: Response): Workspace | undefined {
  const s = selector(req);
  if (s === null) return ctx.workspaces.defaultWorkspace();
  if (s === "all") {
    sendError(res, 400, "Bad Request", "Pick one workspace for this action (x-mont-workspace: <slug>), not all of them.");
    return undefined;
  }
  const ws = ctx.workspaces.bySlug(s);
  if (!ws) {
    sendError(res, 404, "Not Found", `Unknown workspace "${s}".`);
    return undefined;
  }
  return ws;
}

export function actorOf(req: AuthenticatedRequest): string {
  return req.user ? (req.user.sso ? `sso:${req.user.username}` : req.user.username) : "admin";
}

/** 402 with the same `proRequired` marker the dashboard already understands. */
export function sendLicenseRequired(res: Response, feature: string, message: string): void {
  sendError(res, 402, "Payment Required", message, { proRequired: true, feature, upgradeUrl: "https://montweel.com/#license-renewal" });
}
