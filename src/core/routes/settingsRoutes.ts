import type { Request, Response, Router } from "express";
import type { GatewayContext } from "../context";
import type { AuthenticatedRequest, GatewayConfig, RuleMode, Rules } from "../types";
import { HEADER_NAME_REGEX, RULE_MODES } from "../constants";
import {
  MAX_RULE_RATE_LIMIT,
  isValidRuleRateLimit,
  parseRuleKey,
  parseTargetUrl,
  ruleKey,
  sendError,
  sendInternalError,
  sendProRequired,
  validateRulePath,
} from "../utils";
import type { BudgetSpec, DedupeSpec, PolicyTier, Rule } from "../types";
import { validateBudget, validateDedupe, validatePolicies } from "../policy";
import { requireWorkspace } from "./scope";

/** Adds rateLimit to a rule only when it is a real limit, so rules.json stays clean. */
function withRateLimit(rule: Rule, rateLimit: number | null | undefined): Rule {
  return typeof rateLimit === "number" ? { ...rule, rateLimit } : rule;
}

/** Adds policies only when there are some, so rules.json stays clean. */
function withPolicies(rule: Rule, policies: PolicyTier[] | undefined): Rule {
  return policies && policies.length > 0 ? { ...rule, policies } : rule;
}

function withGuards(rule: Rule, budget: BudgetSpec | undefined, dedupe: DedupeSpec | undefined): Rule {
  const out: Rule = { ...rule };
  if (budget) out.budget = budget;
  if (dedupe) out.dedupe = dedupe;
  return out;
}

function parseHeaderName(
  res: Response,
  value: unknown,
  field: string,
  example: string
): string | null {
  if (typeof value !== "string") {
    sendError(res, 400, "Bad Request", `${field} must be a string.`);
    return null;
  }
  const clean = value.trim().toLowerCase();
  if (!clean || !HEADER_NAME_REGEX.test(clean)) {
    sendError(
      res,
      400,
      "Bad Request",
      `${field} must be a valid HTTP header name (letters, numbers, and hyphens, e.g. "${example}").`
    );
    return null;
  }
  return clean;
}

/** Gateway settings (/config) and access rules (/rules). */
export function registerSettingsRoutes(router: Router, ctx: GatewayContext): void {
  const { config: configStore, port, license } = ctx;

  // ---- Config ----
  router.get("/config", (req: AuthenticatedRequest, res: Response) => {
    const { ssoSharedSecret, ...config } = configStore.load();
    const role = req.user?.role ?? "admin";
    res.json({
      ...config,
      // The shared secret lets anyone impersonate any user through the SSO headers,
      // so only administrators ever receive it.
      ...(role === "admin" ? { ssoSharedSecret } : {}),
      ssoSharedSecretConfigured: ssoSharedSecret !== "",
      ssoProxySecretConfigured: ssoSharedSecret !== "", // older dashboards read this name
      authEnabled: true,
      role,
      userRole: role,
      user: req.user,
    });
  });

  router.post("/config", async (req: Request, res: Response) => {
    const body = req.body as unknown;
    if (typeof body !== "object" || body === null || Array.isArray(body)) {
      sendError(res, 400, "Bad Request", "Body must be a JSON object.");
      return;
    }
    const input = body as {
      targetUrl?: unknown;
      rateLimitPerMinute?: unknown;
      requireAgentApiKey?: unknown;
      rotateSsoSharedSecret?: unknown;
      ssoTrustProxyHeader?: unknown;
      ssoUserHeader?: unknown;
      ssoRoleHeader?: unknown;
    };
    const current: GatewayConfig = configStore.load();
    const updated: GatewayConfig = { ...current };

    if (input.targetUrl !== undefined) {
      if (typeof input.targetUrl !== "string") {
        sendError(res, 400, "Bad Request", "targetUrl must be a string.");
        return;
      }
      const parsed = parseTargetUrl(input.targetUrl, port);
      if (!parsed.ok) {
        sendError(res, 400, "Bad Request", parsed.message);
        return;
      }
      updated.targetUrl = parsed.url;
    }

    if (input.rateLimitPerMinute !== undefined) {
      const n = input.rateLimitPerMinute;
      if (typeof n !== "number" || !Number.isInteger(n) || n < 1 || n > 1_000_000) {
        sendError(res, 400, "Bad Request", "rateLimitPerMinute must be a whole number from 1 to 1,000,000.");
        return;
      }
      updated.rateLimitPerMinute = n;
    }

    if (input.requireAgentApiKey !== undefined) {
      if (typeof input.requireAgentApiKey !== "boolean") {
        sendError(res, 400, "Bad Request", "requireAgentApiKey must be a boolean.");
        return;
      }
      updated.requireAgentApiKey = input.requireAgentApiKey;
    }

    if (input.ssoTrustProxyHeader !== undefined) {
      if (typeof input.ssoTrustProxyHeader !== "boolean") {
        sendError(res, 400, "Bad Request", "ssoTrustProxyHeader must be a boolean.");
        return;
      }
      updated.ssoTrustProxyHeader = input.ssoTrustProxyHeader;
    }

    if (input.ssoUserHeader !== undefined) {
      const clean = parseHeaderName(res, input.ssoUserHeader, "ssoUserHeader", "x-forwarded-user");
      if (clean === null) return;
      updated.ssoUserHeader = clean;
    }

    if (input.ssoRoleHeader !== undefined) {
      const clean = parseHeaderName(res, input.ssoRoleHeader, "ssoRoleHeader", "x-forwarded-role");
      if (clean === null) return;
      updated.ssoRoleHeader = clean;
    }

    // Trusted Identity Proxy (SSO) is a Pro feature. Re-saving an unchanged SSO setup
    // (the dashboard form always sends every field) stays allowed so a lapsed license
    // never blocks ordinary settings changes.
    const ssoChanged =
      (updated.ssoTrustProxyHeader && !current.ssoTrustProxyHeader) ||
      (updated.ssoTrustProxyHeader &&
        (updated.ssoUserHeader !== current.ssoUserHeader || updated.ssoRoleHeader !== current.ssoRoleHeader)) ||
      (input.rotateSsoSharedSecret === true && updated.ssoTrustProxyHeader);
    if (ssoChanged && !(await license.isPro())) {
      sendProRequired(res, "reverse-proxy SSO (x-forwarded-user / x-forwarded-role)");
      return;
    }

    try {
      configStore.save(updated); // creates the shared secret if SSO trust was just switched on
      if (input.rotateSsoSharedSecret === true && updated.ssoTrustProxyHeader) configStore.rotateSsoSharedSecret();
      const warnings: string[] = [];
      if (updated.requireAgentApiKey) {
        warnings.push("Agent keys are now required. Make sure your agents have one before they next call the gateway.");
      }
      res.json({ success: true, config: configStore.load(), warnings });
    } catch (err) {
      sendInternalError(res, "Failed to save config", err, "Could not write config.json.");
    }
  });

  // ---- Rules (per workspace: x-mont-workspace header, default workspace = rules.json) ----
  router.get("/rules", (req: Request, res: Response) => {
    const ws = requireWorkspace(ctx, req, res);
    if (!ws) return;
    res.json(ctx.workspaces.rules(ws.id));
  });

  router.post("/rules", async (req: Request, res: Response) => {
    const ws = requireWorkspace(ctx, req, res);
    if (!ws) return;
    const body = req.body as unknown;
    if (typeof body !== "object" || body === null || Array.isArray(body)) {
      sendError(res, 400, "Bad Request", 'Body must be a JSON object like { "/api/some-path": { "mode": "ALLOW" } }.');
      return;
    }
    const entries = Object.entries(body as Record<string, unknown>);
    if (entries.length === 0) {
      sendError(res, 400, "Bad Request", "Body is empty.");
      return;
    }

    const current = ctx.workspaces.rules(ws.id);
    const updates: Rules = {};

    for (const [rawKey, value] of entries) {
      // A key is "/api/x" (any method) or "POST /api/x" (that method only).
      const parsedKey = parseRuleKey(rawKey);
      if ("error" in parsedKey) {
        sendError(res, 400, "Bad Request", `Invalid endpoint "${rawKey}". ${parsedKey.error}`);
        return;
      }
      const pathProblem = validateRulePath(parsedKey.path);
      if (pathProblem) {
        sendError(res, 400, "Bad Request", `Invalid endpoint "${rawKey}". ${pathProblem}`);
        return;
      }
      const endpoint = ruleKey(parsedKey.method, parsedKey.path);
      if (parsedKey.path.startsWith("/api/agent-admin")) {
        sendError(res, 400, "Bad Request", "Admin routes bypass the gateway, so rules cannot apply to them.");
        return;
      }
      const existing = Object.prototype.hasOwnProperty.call(current, endpoint) ? current[endpoint] : undefined;

      if (typeof value === "boolean") {
        updates[endpoint] = withGuards(
          withPolicies(
            withRateLimit({ mode: value ? "ALLOW" : "BLOCK", description: existing?.description ?? "" }, existing?.rateLimit),
            existing?.policies
          ),
          existing?.budget,
          existing?.dedupe
        );
      } else if (typeof value === "object" && value !== null && !Array.isArray(value)) {
        const v = value as { mode?: unknown; description?: unknown; rateLimit?: unknown; policies?: unknown; budget?: unknown; dedupe?: unknown };
        if (typeof v.mode !== "string" || !RULE_MODES.includes(v.mode as RuleMode)) {
          sendError(res, 400, "Bad Request", `mode for "${endpoint}" must be ALLOW, BLOCK, REQUIRE_APPROVAL, SHADOW_BLOCK or SHADOW_APPROVAL.`);
          return;
        }
        const desc = v.description;
        if (desc !== undefined && typeof desc !== "string") {
          sendError(res, 400, "Bad Request", `description for "${endpoint}" must be a string.`);
          return;
        }
        if (typeof desc === "string" && desc.length > 500) {
          sendError(res, 400, "Bad Request", `description for "${endpoint}" must be 500 characters or fewer.`);
          return;
        }
        // rateLimit: omitted = keep the existing value, null = clear (use global), number = set.
        if (v.rateLimit !== undefined && v.rateLimit !== null && !isValidRuleRateLimit(v.rateLimit)) {
          sendError(
            res,
            400,
            "Bad Request",
            `rateLimit for "${endpoint}" must be null or a whole number from 1 to ${MAX_RULE_RATE_LIMIT.toLocaleString("en-US")}.`
          );
          return;
        }
        // policies: omitted = keep the existing tiers, null or [] = clear, list = replace.
        let policies: PolicyTier[] | undefined = existing?.policies;
        if (v.policies !== undefined) {
          const checked = validatePolicies(v.policies);
          if (!checked.ok) {
            sendError(res, 400, "Bad Request", `Invalid policies for "${endpoint}": ${checked.message}`);
            return;
          }
          policies = checked.policies;
        }
        // budget / dedupe: omitted = keep, null = remove, object = replace.
        let budget = existing?.budget;
        if (v.budget !== undefined) {
          const b = validateBudget(v.budget);
          if (!b.ok) {
            sendError(res, 400, "Bad Request", `Invalid budget for "${endpoint}": ${b.message}`);
            return;
          }
          budget = b.value;
        }
        let dedupe = existing?.dedupe;
        if (v.dedupe !== undefined) {
          const d = validateDedupe(v.dedupe);
          if (!d.ok) {
            sendError(res, 400, "Bad Request", `Invalid dedupe for "${endpoint}": ${d.message}`);
            return;
          }
          dedupe = d.value;
        }
        updates[endpoint] = withGuards(
          withPolicies(
            withRateLimit(
              {
                mode: v.mode as RuleMode,
                description: typeof desc === "string" ? desc : existing?.description ?? "",
              },
              v.rateLimit === undefined ? existing?.rateLimit : (v.rateLimit as number | null)
            ),
            policies
          ),
          budget,
          dedupe
        );
      } else {
        sendError(res, 400, "Bad Request", `Value for "${endpoint}" must be true/false or { mode, description }.`);
        return;
      }
    }

    try {
      const rules: Rules = { ...current, ...updates };
      await ctx.workspaces.saveRules(ws.id, rules);
      const warnings = Object.entries(updates)
        .filter(([, r]) => r.policies && r.policies.length > 0 && r.mode === "ALLOW")
        .map(
          ([k]) =>
            `"${k}" falls back to ALLOW when no policy tier matches (for example when a field is missing). ` +
            "Use REQUIRE_APPROVAL or BLOCK as the fallback for fail-closed behaviour."
        );
      for (const [k, r] of Object.entries(updates)) {
        const shadowTiers = (r.policies ?? []).some((t) => t.mode === "SHADOW_BLOCK" || t.mode === "SHADOW_APPROVAL");
        if (r.mode === "SHADOW_BLOCK" || r.mode === "SHADOW_APPROVAL" || shadowTiers) {
          warnings.push(`"${k}" uses a SHADOW mode: matching requests are let through and only logged as "would have been blocked / held". Switch to BLOCK or REQUIRE_APPROVAL to enforce it.`);
        }
      }
      res.json({ success: true, rules, warnings, workspace: ws.slug });
    } catch (err) {
      sendInternalError(res, "Failed to save rules", err, "Could not save the rules.");
    }
  });

  router.delete("/rules", async (req: Request, res: Response) => {
    const ws = requireWorkspace(ctx, req, res);
    if (!ws) return;
    const bodyPath = (req.body as { path?: unknown } | undefined)?.path;
    const queryPath = req.query.path;
    const raw = typeof bodyPath === "string" ? bodyPath : typeof queryPath === "string" ? queryPath : "";

    if (!raw.trim()) {
      sendError(res, 400, "Bad Request", 'Provide the endpoint as { "path": "/api/..." } in the body or ?path= in the URL.');
      return;
    }

    const parsedKey = parseRuleKey(raw);
    if ("error" in parsedKey) {
      sendError(res, 400, "Bad Request", parsedKey.error);
      return;
    }
    const endpoint = ruleKey(parsedKey.method, parsedKey.path);
    const rules = ctx.workspaces.rules(ws.id);
    if (!Object.prototype.hasOwnProperty.call(rules, endpoint)) {
      sendError(res, 404, "Not Found", `No rule exists for "${endpoint}".`);
      return;
    }

    try {
      delete rules[endpoint];
      await ctx.workspaces.saveRules(ws.id, rules);
      res.json({ success: true, rules, workspace: ws.slug });
    } catch (err) {
      sendInternalError(res, "Failed to save rules", err, "Could not save the rules.");
    }
  });
}
