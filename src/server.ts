/**
 * Example consumer app for agent-gateway-sdk.
 * This is what a user of your package would write in their own project.
 *
 * Environment variables:
 *   PORT          listen port (default 3000)
 *   HOST          bind address (default 127.0.0.1; use 0.0.0.0 in Docker / behind a proxy)
 *   TRUST_PROXY   "true" when running behind exactly one reverse proxy (Nginx, ALB, ...)
 *   CORS_ORIGINS  comma-separated allowed browser origins for the admin API
 *                 (dev default: http://localhost:5173; none in production)
 *   ADMIN_PORT    serve the admin API + dashboard on a separate port. The public
 *                 PORT then exposes only /api/* and /.well-known/agent.json.
 *   ADMIN_HOST    bind address for ADMIN_PORT (default 127.0.0.1)
 *   SETUP_TOKEN, ADMIN_TOKEN, VIEWER_TOKEN  see gateway.ts
 */
import express from "express";
import type { Express, NextFunction, Request, Response } from "express";
import type { Server } from "http";
import cors from "cors";
import fs from "fs";
import path from "path";
import { createAgentGateway } from "./gateway";
import { sendCaughtError } from "./core/utils";

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || "127.0.0.1";
const IS_PRODUCTION = process.env.NODE_ENV === "production";

// The built React dashboard (run `npm run build` inside dashboard/ first).
const DASHBOARD_DIST = path.resolve(__dirname, "..", "dashboard", "dist");

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

function allowedCorsOrigins(): string[] {
  const fromEnv = (process.env.CORS_ORIGINS ?? "")
    .split(",")
    .map((o: string) => o.trim())
    .filter(Boolean);
  if (fromEnv.length > 0) return fromEnv;
  return IS_PRODUCTION ? [] : ["http://localhost:5173"];
}

/** Security headers, proxy trust and CORS shared by every listener. */
function createBaseApp(): Express {
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
function mountAdmin(app: Express, gateway: ReturnType<typeof createAgentGateway>): void {
  // Lets the dashboard dev server (http://localhost:5173) call this API.
  // Production deployments serve the built dashboard from this same origin, so no CORS is needed.
  const origins = allowedCorsOrigins();
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
      res
        .status(503)
        .type("text/plain")
        .send("The dashboard has not been built yet.\nRun: cd dashboard && npm run build");
    });
  }
}

function listen(app: Express, port: number, host: string, label: string): Promise<Server> {
  return new Promise((resolve, reject) => {
    const server = app.listen(port, host, () => {
      console.log(`${label} listening at http://${host}:${port}`);
      resolve(server);
    });
    server.once("error", reject);
  });
}

async function main(): Promise<void> {
  // 1. Create the gateway and wait for its database to be ready (and migrated).
  const gateway = createAgentGateway({ port: PORT });
  await gateway.ready;

  const app = createBaseApp();

  // 2. Public discovery manifest for agents: GET /.well-known/agent.json
  app.use(gateway.discoveryRouter);

  // 3. Admin API + dashboard. With ADMIN_PORT set they live on a second listener
  //    that can be bound to localhost or a private network; the public port then
  //    cannot reach them at all.
  let adminApp: Express | null = null;
  if (gateway.adminListener) {
    adminApp = createBaseApp();
    mountAdmin(adminApp, gateway);
    if (gateway.adminListener.port === PORT) {
      throw new Error("ADMIN_PORT must be different from PORT.");
    }
  } else {
    mountAdmin(app, gateway);
  }

  // 4. The gateway guards every /api/* request that reaches it.
  app.use("/api", gateway.agentGateway);

  // 5. Normal non-API routes (not guarded by the gateway)
  app.get("/", (_req: Request, res: Response) => {
    res.send(
      gateway.adminListener
        ? "Welcome to the homepage."
        : "Welcome to the homepage. Admin dashboard: /agent-admin/"
    );
  });

  // 6. Mock API routes (only reached when the gateway lets the request through)
  app.use(express.json());
  app.get("/api/get-flights", (_req: Request, res: Response) => {
    res.json({
      flights: [
        { id: "AI101", from: "PNQ", to: "DEL", departs: "2026-10-12T08:30:00+05:30", price: 5400 },
        { id: "6E202", from: "PNQ", to: "BOM", departs: "2026-10-12T11:15:00+05:30", price: 2100 },
        { id: "UK303", from: "PNQ", to: "BLR", departs: "2026-10-13T06:45:00+05:30", price: 3800 },
      ],
    });
  });

  
  app.post("/api/book-flight", (_req: Request, res: Response) => {
    res.json({ success: true, message: "Flight booked successfully (dummy response).", bookingDetails: _req.body ?? null, });
  });

  app.delete("/api/users", (req: Request, res: Response) => {
    res.json({
      success: true,
      message: "User deleted successfully after admin approval.",
      deletedUser: req.body ?? null,
    });
  });

  // Last-resort error handler: never let Express's default handler send a stack
  // trace (it does whenever NODE_ENV is not "production"). Placed after every route.
  const finalErrorHandler = (err: unknown, _req: Request, res: Response, _next: NextFunction): void => {
    sendCaughtError(res, err);
  };
  app.use(finalErrorHandler);
  if (adminApp) adminApp.use(finalErrorHandler);

  console.log("By using this SDK you agree to TERMS.md (see https://montweel.com).");

  // 7. Start listening
  const servers: Server[] = [await listen(app, PORT, HOST, "agent-gateway-sdk (public)")];
  if (adminApp && gateway.adminListener) {
    const { port, host } = gateway.adminListener;
    servers.push(await listen(adminApp, port, host, "agent-gateway-sdk (admin)"));
    console.log(`Admin dashboard: http://${host}:${port}/agent-admin/`);
  } else {
    console.log(`Admin dashboard: http://${HOST}:${PORT}/agent-admin/`);
  }

  // Close the server and database cleanly on Ctrl+C or a stop signal.
  // If connections hang, force the exit after 10 seconds.
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

// A stray rejected promise must be logged, not crash a gateway that is guarding traffic.
process.on("unhandledRejection", (reason: unknown) => {
  console.error("Unhandled promise rejection:", reason);
});

main().catch((err: unknown) => {
  console.error("Startup failed:", err);
  process.exit(1);
});
