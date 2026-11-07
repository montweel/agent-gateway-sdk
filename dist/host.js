"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.DASHBOARD_DIST = void 0;
exports.allowedCorsOrigins = allowedCorsOrigins;
exports.createBaseApp = createBaseApp;
exports.mountAdmin = mountAdmin;
exports.listen = listen;
exports.installShutdown = installShutdown;
/**
 * Shared hosting helpers for server.ts (example app) and cli.ts (standalone proxy).
 */
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
// The built React dashboard (run `npm run build` inside dashboard/ first).
exports.DASHBOARD_DIST = path_1.default.resolve(__dirname, "..", "dashboard", "dist");
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
function securityHeaders(_req, res, next) {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "no-referrer");
    next();
}
function allowedCorsOrigins(isProduction) {
    const fromEnv = (process.env.CORS_ORIGINS ?? "")
        .split(",")
        .map((o) => o.trim())
        .filter(Boolean);
    if (fromEnv.length > 0)
        return fromEnv;
    return isProduction ? [] : ["http://localhost:5173"];
}
/** Security headers and proxy trust shared by every listener. */
function createBaseApp() {
    const app = (0, express_1.default)();
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
function mountAdmin(app, gateway, isProduction) {
    // Lets the dashboard dev server (http://localhost:5173) call this API.
    // Production deployments serve the built dashboard from this same origin, so no CORS is needed.
    const origins = allowedCorsOrigins(isProduction);
    if (origins.length > 0) {
        app.use("/api/agent-admin", (0, cors_1.default)({ origin: origins }));
    }
    app.use("/api/agent-admin", gateway.adminRouter);
    if (fs_1.default.existsSync(path_1.default.join(exports.DASHBOARD_DIST, "index.html"))) {
        app.use("/agent-admin", (_req, res, next) => {
            res.setHeader("Content-Security-Policy", DASHBOARD_CSP);
            next();
        }, express_1.default.static(exports.DASHBOARD_DIST));
    }
    else {
        console.warn("Dashboard not built yet. Run: cd dashboard && npm run build");
        app.use("/agent-admin", (_req, res) => {
            res.status(503).type("text/plain").send("The dashboard has not been built yet.\nRun: cd dashboard && npm run build");
        });
    }
}
function listen(app, port, host, label) {
    return new Promise((resolve, reject) => {
        const server = app.listen(port, host, () => {
            console.log(`${label} listening at http://${host}:${port}`);
            resolve(server);
        });
        server.once("error", reject);
    });
}
/** Close servers and the database cleanly on Ctrl+C / SIGTERM; force exit after 10 s. */
function installShutdown(servers, gateway) {
    let shuttingDown = false;
    const shutdown = () => {
        if (shuttingDown)
            return;
        shuttingDown = true;
        const force = setTimeout(() => process.exit(1), 10000);
        force.unref();
        Promise.all(servers.map((server) => new Promise((resolve) => server.close(() => resolve()))))
            .then(() => gateway.close())
            .catch((err) => console.error("Error closing the gateway:", err))
            .finally(() => process.exit(0));
    };
    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);
}
