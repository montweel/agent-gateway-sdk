"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.registerMetricsRoutes = registerMetricsRoutes;
const utils_1 = require("../utils");
/**
 * GET /metrics: Prometheus text exposition. Team Pro only.
 * Lives on the admin router, so it sits behind the normal auth middleware
 * (scrapers can send `Authorization: Bearer <static viewer token>`).
 */
function registerMetricsRoutes(router, ctx) {
    const { db, license } = ctx;
    router.get("/metrics", async (_req, res) => {
        try {
            if (!(await license.isPro())) {
                (0, utils_1.sendProRequired)(res, "the /metrics Prometheus endpoint");
                return;
            }
            const byStatus = await db.all("SELECT status, COUNT(*) AS count FROM agent_logs GROUP BY status");
            const pending = await db.get("SELECT COUNT(*) AS count FROM pending_actions WHERE status = 'PENDING'");
            const lines = [
                "# HELP agent_gateway_requests_total Requests handled by the gateway, by outcome (retained audit window).",
                "# TYPE agent_gateway_requests_total gauge",
                ...byStatus.map((r) => `agent_gateway_requests_total{status="${r.status}"} ${r.count}`),
                "# HELP agent_gateway_pending_approvals Actions waiting for human approval.",
                "# TYPE agent_gateway_pending_approvals gauge",
                `agent_gateway_pending_approvals ${pending?.count ?? 0}`,
                "",
            ];
            res.type("text/plain; version=0.0.4").send(lines.join("\n"));
        }
        catch (err) {
            (0, utils_1.sendInternalError)(res, "Metrics error", err, "Could not collect metrics.");
        }
    });
}
