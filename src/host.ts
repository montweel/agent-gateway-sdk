/**
 * Shared hosting helpers for server.ts (example app) and cli.ts (standalone proxy).
 */
import express from "express";
import type { Express, NextFunction, Request, Response } from "express";
import type { Server } from "http";
import cors from "cors";
import fs from "fs";
import path from "path";
import type { AgentGateway } from "./gateway";

// The built React dashboard (run `npm run build` inside dashboard/ first).
export const DASHBOARD_DIST = path.resolve(__dirname, "..", "dashboard", "dist");

// Locks the dashboard down: no inline scripts, no framing, same-origin API only.
const DASHBOARD_CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'", // React inline style attributes (chart bar heights)
  "img-src 'self' data:",
  "connect-src 'self'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join("; ");

function securityHeaders(_req: Request, res: Response, next: NextFunction): void {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  next();
}

export function allowedCorsOrigins(isProduction: boolean): string[] {
  const fromEnv = (process.env.CORS_ORIGINS ?? "")
    .split(",")
    .map((o: string) => o.trim())
    .filter(Boolean);
  if (fromEnv.length > 0) return fromEnv;
  return isProduction ? [] : ["http://localhost:5173"];
}

/** Security headers and proxy trust shared by every listener. */
export function createBaseApp(): Express {
  const app = express();
  app.disable("x-powered-by");
  app.use(securityHeaders);

  // Trust the first-hop reverse proxy (e.g., Nginx, Cloudflare, AWS ALB)
  // so rate limiting and request protocols read the correct client IP via X-Forwarded-For.
  if (process.env.TRUST_PROXY === "true") {
    app.set("trust proxy", 1);
  }
  return app;
}

/** Admin API (always before the gateway so it is never intercepted) and the dashboard. */
export function mountAdmin(app: Express, gateway: AgentGateway, isProduction: boolean): void {
  // Lets the dashboard dev server (http://localhost:5173) call this API.
  // Production deployments serve the built dashboard from this same origin, so no CORS is needed.
  const origins = allowedCorsOrigins(isProduction);
  if (origins.length > 0) {
    app.use("/api/agent-admin", cors({ origin: origins }));
  }

  app.use("/api/agent-admin", gateway.adminRouter);

  if (fs.existsSync(path.join(DASHBOARD_DIST, "index.html"))) {
    app.use(
      "/agent-admin",
      (_req: Request, res: Response, next: NextFunction) => {
        res.setHeader("Content-Security-Policy", DASHBOARD_CSP);
        next();
      },
      express.static(DASHBOARD_DIST)
    );
  } else {
    console.warn("Dashboard not built yet. Run: cd dashboard && npm run build");
    app.use("/agent-admin", (_req: Request, res: Response) => {
      res.status(503).type("text/plain").send("The dashboard has not been built yet.\nRun: cd dashboard && npm run build");
    });
  }
}

export function listen(app: Express, port: number, host: string, label: string): Promise<Server> {
  return new Promise((resolve, reject) => {
    const server = app.listen(port, host, () => {
      console.log(`${label} listening at http://${host}:${port}`);
      resolve(server);
    });
    server.once("error", reject);
  });
}

/** Close servers and the database cleanly on Ctrl+C / SIGTERM; force exit after 10 s. */
export function installShutdown(servers: Server[], gateway: AgentGateway): void {
  let shuttingDown = false;
  const shutdown = (): void => {
    if (shuttingDown) return;
    shuttingDown = true;
    const force = setTimeout(() => process.exit(1), 10_000);
    force.unref();
    Promise.all(servers.map((server) => new Promise<void>((resolve) => server.close(() => resolve()))))
      .then(() => gateway.close())
      .catch((err: unknown) => console.error("Error closing the gateway:", err))
      .finally(() => process.exit(0));
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}
