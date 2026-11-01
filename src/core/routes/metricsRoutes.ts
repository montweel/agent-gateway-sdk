import type { Request, Response, Router } from "express";
import type { GatewayContext } from "../context";
import { sendInternalError, sendProRequired } from "../utils";

/**
 * GET /metrics: Prometheus text exposition. Team Pro only.
 * Lives on the admin router, so it sits behind the normal auth middleware
 * (scrapers can send `Authorization: Bearer <static viewer token>`).
 */
export function registerMetricsRoutes(router: Router, ctx: GatewayContext): void {
  const { db, license } = ctx;

  router.get("/metrics", async (_req: Request, res: Response) => {
    try {
      if (!(await license.isPro())) {
        sendProRequired(res, "the /metrics Prometheus endpoint");
        return;
      }

      const byStatus = await db.all<{ status: string; count: number }>(
        "SELECT status, COUNT(*) AS count FROM agent_logs GROUP BY status"
      );
      const pending = await db.get<{ count: number }>("SELECT COUNT(*) AS count FROM pending_actions WHERE status = 'PENDING'");

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
    } catch (err) {
      sendInternalError(res, "Metrics error", err, "Could not collect metrics.");
    }
  });
}
