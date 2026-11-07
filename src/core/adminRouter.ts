import express from "express";
import type { NextFunction, Request, Response, Router } from "express";
import type { GatewayContext } from "./context";
import { JSON_BODY_LIMIT } from "./constants";
import { sendCaughtError, sendError } from "./utils";
import { registerPublicAuthRoutes, registerSelfServiceRoutes } from "./routes/authRoutes";
import { registerUserRoutes } from "./routes/userRoutes";
import { registerSettingsRoutes } from "./routes/settingsRoutes";
import { registerLogRoutes } from "./routes/logRoutes";
import { registerApprovalRoutes } from "./routes/approvalRoutes";
import { registerAgentKeyRoutes } from "./routes/agentKeyRoutes";
import { registerLicenseRoutes } from "./routes/licenseRoutes";
import { registerMetricsRoutes } from "./routes/metricsRoutes";
import { registerSetupRoutes } from "./routes/setupRoutes";
import { registerProtectionRoutes } from "./routes/protectionRoutes";
import { registerWorkspaceRoutes } from "./routes/workspaceRoutes";
import { registerAuditRoutes } from "./routes/auditRoutes";

/**
 * Admin API. Mount it BEFORE the gateway so it is never intercepted.
 * Order matters: public auth routes, then the auth/RBAC middleware, then everything else.
 */
export function createAdminRouter(ctx: GatewayContext): Router {
  const router = express.Router();

  // Wait for the database before serving any admin request.
  router.use((_req: Request, res: Response, next: NextFunction) => {
    ctx.ready.then(
      () => next(),
      (err: unknown) => {
        console.error("Database is not ready:", err);
        sendError(res, 500, "Internal Server Error", "The gateway database failed to start.");
      }
    );
  });

  // Admin responses contain credentials, request bodies and user lists: never cache them.
  router.use((_req: Request, res: Response, next: NextFunction) => {
    res.setHeader("Cache-Control", "no-store");
    next();
  });

  router.use(express.json({ limit: JSON_BODY_LIMIT }));

  registerPublicAuthRoutes(router, ctx);

  router.use((req: Request, res: Response, next: NextFunction) => {
    void ctx.auth.middleware(req, res, next);
  });

  registerSelfServiceRoutes(router, ctx);
  registerUserRoutes(router, ctx);
  registerSettingsRoutes(router, ctx);
  registerLogRoutes(router, ctx);
  registerApprovalRoutes(router, ctx);
  registerAgentKeyRoutes(router, ctx);
  registerLicenseRoutes(router, ctx);
  registerMetricsRoutes(router, ctx);
  registerSetupRoutes(router, ctx);
  registerProtectionRoutes(router, ctx);
  registerWorkspaceRoutes(router, ctx);
  registerAuditRoutes(router, ctx);

  router.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    sendCaughtError(res, err);
  });

  return router;
}
