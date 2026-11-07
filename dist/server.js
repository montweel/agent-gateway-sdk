"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
/**
 * Example consumer app for agent-gateway-sdk (Express middleware mode).
 * This is what a user of your package would write in their own project.
 * For the no-code standalone reverse proxy, see cli.ts (`npx agent-gateway-sdk start`).
 *
 * Environment variables:
 *   PORT          listen port (default 3000)
 *   HOST          bind address (default 127.0.0.1; use 0.0.0.0 in Docker / behind a proxy)
 *   TRUST_PROXY   "true" when running behind exactly one reverse proxy (Nginx, ALB, ...)
 *   CORS_ORIGINS  comma-separated allowed browser origins for the admin API
 *                 (dev default: http://localhost:5173; none in production)
 *   ADMIN_PORT    serve the admin API + dashboard on a separate port. The public
 *                 PORT then exposes only /api/*, /_mont/approvals/* and /.well-known/agent.json.
 *   ADMIN_HOST    bind address for ADMIN_PORT (default 127.0.0.1)
 *   SETUP_TOKEN, ADMIN_TOKEN, VIEWER_TOKEN  see gateway.ts
 */
const express_1 = __importDefault(require("express"));
const gateway_1 = require("./gateway");
const utils_1 = require("./core/utils");
const host_1 = require("./host");
const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || "127.0.0.1";
const IS_PRODUCTION = process.env.NODE_ENV === "production";
async function main() {
    // 1. Create the gateway and wait for its database to be ready (and migrated).
    const gateway = (0, gateway_1.createAgentGateway)({ port: PORT });
    await gateway.ready;
    const app = (0, host_1.createBaseApp)();
    // 2. Public discovery manifest for agents: GET /.well-known/agent.json
    app.use(gateway.discoveryRouter);
    // 3. Signed one-click Approve / Reject pages for phone notifications.
    app.use(gateway.approvalCallbackRouter);
    // 4. Admin API + dashboard. With ADMIN_PORT set they live on a second listener
    //    that can be bound to localhost or a private network; the public port then
    //    cannot reach them at all.
    let adminApp = null;
    if (gateway.adminListener) {
        adminApp = (0, host_1.createBaseApp)();
        (0, host_1.mountAdmin)(adminApp, gateway, IS_PRODUCTION);
        if (gateway.adminListener.port === PORT) {
            throw new Error("ADMIN_PORT must be different from PORT.");
        }
    }
    else {
        (0, host_1.mountAdmin)(app, gateway, IS_PRODUCTION);
    }
    // 5. The gateway guards every /api/* request that reaches it.
    app.use("/api", gateway.agentGateway);
    // 6. Normal non-API routes (not guarded by the gateway)
    app.get("/", (_req, res) => {
        res.send(gateway.adminListener ? "Welcome to the homepage." : "Welcome to the homepage. Admin dashboard: /agent-admin/");
    });
    // 7. Mock API routes (only reached when the gateway lets the request through)
    app.use(express_1.default.json());
    app.get("/api/get-flights", (_req, res) => {
        res.json({
            flights: [
                { id: "AI101", from: "PNQ", to: "DEL", departs: "2026-10-12T08:30:00+05:30", price: 5400 },
                { id: "6E202", from: "PNQ", to: "BOM", departs: "2026-10-12T11:15:00+05:30", price: 2100 },
                { id: "UK303", from: "PNQ", to: "BLR", departs: "2026-10-13T06:45:00+05:30", price: 3800 },
            ],
        });
    });
    app.post("/api/book-flight", (req, res) => {
        res.json({ success: true, message: "Flight booked successfully (dummy response).", bookingDetails: req.body ?? null });
    });
    app.post("/api/refund", (req, res) => {
        res.json({ success: true, message: "Refund issued (dummy response).", refund: req.body ?? null });
    });
    app.delete("/api/users", (req, res) => {
        res.json({
            success: true,
            message: "User deleted successfully after admin approval.",
            deletedUser: req.body ?? null,
        });
    });
    // Last-resort error handler: never let Express's default handler send a stack
    // trace (it does whenever NODE_ENV is not "production"). Placed after every route.
    const finalErrorHandler = (err, _req, res, _next) => {
        (0, utils_1.sendCaughtError)(res, err);
    };
    app.use(finalErrorHandler);
    if (adminApp)
        adminApp.use(finalErrorHandler);
    console.log("By using this SDK you agree to TERMS.md (see https://montweel.com).");
    // 8. Start listening
    const servers = [await (0, host_1.listen)(app, PORT, HOST, "agent-gateway-sdk (public)")];
    if (adminApp && gateway.adminListener) {
        const { port, host } = gateway.adminListener;
        servers.push(await (0, host_1.listen)(adminApp, port, host, "agent-gateway-sdk (admin)"));
        console.log(`Admin dashboard: http://${host}:${port}/agent-admin/`);
    }
    else {
        console.log(`Admin dashboard: http://${HOST}:${PORT}/agent-admin/`);
    }
    (0, host_1.installShutdown)(servers, gateway);
}
// A stray rejected promise must be logged, not crash a gateway that is guarding traffic.
process.on("unhandledRejection", (reason) => {
    console.error("Unhandled promise rejection:", reason);
});
main().catch((err) => {
    console.error("Startup failed:", err);
    process.exit(1);
});
