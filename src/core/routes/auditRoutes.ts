import type { Response, Router } from "express";
import type { GatewayContext } from "../context";
import type { AuthenticatedRequest, RuleMode, Rules } from "../types";
import { RULE_MODES } from "../constants";
import { simulateHistory } from "../simulator";
import { normalizeRule, parseRuleKey, ruleKey, sendError, sendInternalError, validateRulePath } from "../utils";
import { readScope, requireWorkspace, sendLicenseRequired } from "./scope";

/**
 *   GET  /audit/verify          walks the hash-chained audit ledger and proves it was not modified
 *                               (Pro / Agency). Seals any rows written in the last moment first.
 *   GET  /audit/head            the current chain head (any user; write it down / it is in the digest)
 *   POST /simulate/history      { limit?: 1-5000, rules?: <candidate rules> } -> what the last N recorded
 *                               requests would have done under these rules (current rules when omitted)
 */
export function registerAuditRoutes(router: Router, ctx: GatewayContext): void {
  router.get("/audit/verify", async (_req: AuthenticatedRequest, res: Response) => {
    if (!ctx.license.current().features.auditVerification) {
      sendLicenseRequired(res, "auditVerification", "Tamper-evident ledger verification is a Mont Pro feature. Every row is still hash-chained; activate a key to verify it.");
      return;
    }
    try {
      await ctx.ledger.sealPending();
      res.json(await ctx.ledger.verify());
    } catch (err) {
      sendInternalError(res, "Audit verify error", err, "Could not verify the audit ledger.");
    }
  });

  router.get("/audit/head", async (_req: AuthenticatedRequest, res: Response) => {
    try {
      await ctx.ledger.sealPending();
      res.json({ head: await ctx.ledger.head() });
    } catch (err) {
      sendInternalError(res, "Audit head error", err, "Could not read the audit ledger head.");
    }
  });

  router.post("/simulate/history", async (req: AuthenticatedRequest, res: Response) => {
    const scoped = readScope(ctx, req, res);
    if (scoped === undefined) return;
    // Candidate rules belong to one workspace; without candidates, "all" replays every workspace with its own rules.
    const body = (req.body ?? {}) as { limit?: unknown; rules?: unknown };
    let workspaceId: number | null = scoped?.id ?? null;
    if (body.rules !== undefined && workspaceId === null) {
      const ws = requireWorkspace(ctx, req, res);
      if (!ws) return;
      workspaceId = ws.id;
    }
    if (body.limit !== undefined && (!Number.isInteger(body.limit) || (body.limit as number) < 1 || (body.limit as number) > 5000)) {
      sendError(res, 400, "Bad Request", "limit must be a whole number from 1 to 5000.");
      return;
    }
    let candidate: Rules | undefined;
    if (body.rules !== undefined) {
      if (typeof body.rules !== "object" || body.rules === null || Array.isArray(body.rules)) {
        sendError(res, 400, "Bad Request", "rules must be an object like rules.json.");
        return;
      }
      candidate = {};
      for (const [rawKey, value] of Object.entries(body.rules as Record<string, unknown>)) {
        const parsed = parseRuleKey(rawKey);
        if ("error" in parsed) {
          sendError(res, 400, "Bad Request", `Invalid endpoint "${rawKey}". ${parsed.error}`);
          return;
        }
        const problem = validateRulePath(parsed.path);
        if (problem) {
          sendError(res, 400, "Bad Request", `Invalid endpoint "${rawKey}". ${problem}`);
          return;
        }
        const mode = typeof value === "object" && value !== null ? (value as { mode?: unknown }).mode : undefined;
        if (typeof value === "object" && value !== null && (typeof mode !== "string" || !RULE_MODES.includes(mode as RuleMode))) {
          sendError(res, 400, "Bad Request", `mode for "${rawKey}" must be one of ${RULE_MODES.join(", ")}.`);
          return;
        }
        const rule = normalizeRule(value);
        if (!rule) {
          sendError(res, 400, "Bad Request", `Rule "${rawKey}" must be true/false or { mode, ... }.`);
          return;
        }
        if (/\[(policies|guards) invalid: enforced as BLOCK\]/.test(rule.description)) {
          sendError(res, 400, "Bad Request", `Rule "${rawKey}" has invalid policies, budget or dedupe settings.`);
          return;
        }
        candidate[ruleKey(parsed.method, parsed.path)] = rule;
      }
    }
    try {
      res.json(await simulateHistory(ctx, { workspaceId, limit: (body.limit as number | undefined) ?? 500, rules: candidate }));
    } catch (err) {
      sendInternalError(res, "Simulation error", err, "Could not replay the history.");
    }
  });
}
