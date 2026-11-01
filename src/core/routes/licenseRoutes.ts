import type { Response, Router } from "express";
import type { GatewayContext } from "../context";
import type { AuthenticatedRequest } from "../types";
import { verifyLicenseKey } from "../license";
import { sendError, sendInternalError } from "../utils";

/** License status (any signed-in user) and key management (admin only). */
export function registerLicenseRoutes(router: Router, ctx: GatewayContext): void {
  const { auth, license } = ctx;

  router.get("/license", async (_req: AuthenticatedRequest, res: Response) => {
    try {
      res.json(await license.resolveLicenseStatus());
    } catch (err) {
      sendInternalError(res, "License status error", err, "Could not read the license status.");
    }
  });

  router.post("/license", async (req: AuthenticatedRequest, res: Response) => {
    if (!auth.requireAdmin(req, res)) return;
    try {
      const licenseKey = (req.body as { licenseKey?: unknown } | undefined)?.licenseKey;
      if (typeof licenseKey !== "string" || licenseKey.trim() === "") {
        sendError(res, 400, "Bad Request", "licenseKey must be a MONT-... key.");
        return;
      }
      const result = verifyLicenseKey(licenseKey);
      if (!result.ok) {
        sendError(res, 400, "Bad Request", result.reason);
        return;
      }
      await license.saveLicenseKey(licenseKey);
      res.json(await license.resolveLicenseStatus());
    } catch (err) {
      sendInternalError(res, "Save license error", err, "Could not save the license key.");
    }
  });

  router.delete("/license", async (req: AuthenticatedRequest, res: Response) => {
    if (!auth.requireAdmin(req, res)) return;
    try {
      await license.removeLicenseKey();
      res.json(await license.resolveLicenseStatus());
    } catch (err) {
      sendInternalError(res, "Remove license error", err, "Could not remove the license key.");
    }
  });

  // Dev/test helper: ?state=expired (trial began 8 days ago) or ?state=active (trial begins now).
  // Also accepts { "state": "expired" | "active" } or { "expired": boolean } in the body.
  router.post("/license/simulate-trial-expiry", async (req: AuthenticatedRequest, res: Response) => {
    if (process.env.NODE_ENV === "production") {
      sendError(res, 404, "Not Found", "Not available in production.");
      return;
    }
    if (!auth.requireAdmin(req, res)) return;
    try {
      const body = (req.body ?? {}) as { state?: unknown; expired?: unknown };
      const state = typeof req.query.state === "string" ? req.query.state : body.state;
      let expired: boolean;
      if (state === "expired") expired = true;
      else if (state === "active") expired = false;
      else if (typeof body.expired === "boolean") expired = body.expired;
      else {
        sendError(res, 400, "Bad Request", 'Use ?state=expired or ?state=active (or { "expired": true|false }).');
        return;
      }
      await license.simulateTrial(expired);
      res.json(await license.resolveLicenseStatus());
    } catch (err) {
      sendInternalError(res, "Simulate trial error", err, "Could not change the trial state.");
    }
  });
}
