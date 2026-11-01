import express from "express";
import type { Request, Response, Router } from "express";
import type { GatewayContext } from "./context";
import { parseRuleKey } from "./utils";

/** Public discovery manifest: GET /.well-known/agent.json */
export function createDiscoveryRouter(ctx: GatewayContext): Router {
  const router = express.Router();

  router.get("/.well-known/agent.json", async (_req: Request, res: Response) => {
    // Agent discovery is free and open in every tier (no license check).
    const config = ctx.config.load();
    const endpoints = Object.entries(ctx.rules.load())
      .filter(([, rule]) => rule.mode === "ALLOW" || rule.mode === "REQUIRE_APPROVAL")
      .map(([key, rule]) => {
        const parsed = parseRuleKey(key);
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
