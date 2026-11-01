"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createDiscoveryRouter = createDiscoveryRouter;
const express_1 = __importDefault(require("express"));
const utils_1 = require("./utils");
/** Public discovery manifest: GET /.well-known/agent.json */
function createDiscoveryRouter(ctx) {
    const router = express_1.default.Router();
    router.get("/.well-known/agent.json", (_req, res) => {
        const config = ctx.config.load();
        const endpoints = Object.entries(ctx.rules.load())
            .filter(([, rule]) => rule.mode === "ALLOW" || rule.mode === "REQUIRE_APPROVAL")
            .map(([key, rule]) => {
            const parsed = (0, utils_1.parseRuleKey)(key);
            const methodAndPath = "error" in parsed ? { method: "ANY", path: key } : { method: parsed.method ?? "ANY", path: parsed.path };
            return {
                ...methodAndPath,
                mode: rule.mode,
                description: rule.description,
                rateLimit: rule.rateLimit ?? null,
            };
        });
        res.json({ rateLimitPerMinute: config.rateLimitPerMinute, endpoints });
    });
    return router;
}
