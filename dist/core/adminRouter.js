"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createAdminRouter = createAdminRouter;
const express_1 = __importDefault(require("express"));
const constants_1 = require("./constants");
const utils_1 = require("./utils");
const authRoutes_1 = require("./routes/authRoutes");
const userRoutes_1 = require("./routes/userRoutes");
const settingsRoutes_1 = require("./routes/settingsRoutes");
const logRoutes_1 = require("./routes/logRoutes");
const approvalRoutes_1 = require("./routes/approvalRoutes");
const agentKeyRoutes_1 = require("./routes/agentKeyRoutes");
const licenseRoutes_1 = require("./routes/licenseRoutes");
const metricsRoutes_1 = require("./routes/metricsRoutes");
const setupRoutes_1 = require("./routes/setupRoutes");
const protectionRoutes_1 = require("./routes/protectionRoutes");
/**
 * Admin API. Mount it BEFORE the gateway so it is never intercepted.
 * Order matters: public auth routes, then the auth/RBAC middleware, then everything else.
 */
function createAdminRouter(ctx) {
    const router = express_1.default.Router();
    // Wait for the database before serving any admin request.
    router.use((_req, res, next) => {
        ctx.ready.then(() => next(), (err) => {
            console.error("Database is not ready:", err);
            (0, utils_1.sendError)(res, 500, "Internal Server Error", "The gateway database failed to start.");
        });
    });
    // Admin responses contain credentials, request bodies and user lists: never cache them.
    router.use((_req, res, next) => {
        res.setHeader("Cache-Control", "no-store");
        next();
    });
    router.use(express_1.default.json({ limit: constants_1.JSON_BODY_LIMIT }));
    (0, authRoutes_1.registerPublicAuthRoutes)(router, ctx);
    router.use((req, res, next) => {
        void ctx.auth.middleware(req, res, next);
    });
    (0, authRoutes_1.registerSelfServiceRoutes)(router, ctx);
    (0, userRoutes_1.registerUserRoutes)(router, ctx);
    (0, settingsRoutes_1.registerSettingsRoutes)(router, ctx);
    (0, logRoutes_1.registerLogRoutes)(router, ctx);
    (0, approvalRoutes_1.registerApprovalRoutes)(router, ctx);
    (0, agentKeyRoutes_1.registerAgentKeyRoutes)(router, ctx);
    (0, licenseRoutes_1.registerLicenseRoutes)(router, ctx);
    (0, metricsRoutes_1.registerMetricsRoutes)(router, ctx);
    (0, setupRoutes_1.registerSetupRoutes)(router, ctx);
    (0, protectionRoutes_1.registerProtectionRoutes)(router, ctx);
    router.use((err, _req, res, _next) => {
        (0, utils_1.sendCaughtError)(res, err);
    });
    return router;
}
