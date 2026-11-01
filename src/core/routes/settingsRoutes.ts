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
import type { Rule } from "../types";

/** Adds rateLimit to a rule only when it is a real limit, so rules.json stays clean. */
function withRateLimit(rule: Rule, rateLimit: number | null | undefined): Rule {
  return typeof rateLimit === "number" ? { ...rule, rateLimit } : rule;
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
  const { config: configStore, rules: rulesStore, port, license } = ctx;

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

  // ---- Rules ----
  router.get("/rules", (_req: Request, res: Response) => {
    res.json(rulesStore.load());
  });

  router.post("/rules", (req: Request, res: Response) => {
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

    const current = rulesStore.load();
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
        updates[endpoint] = withRateLimit(
          { mode: value ? "ALLOW" : "BLOCK", description: existing?.description ?? "" },
          existing?.rateLimit
        );
      } else if (typeof value === "object" && value !== null && !Array.isArray(value)) {
        const v = value as { mode?: unknown; description?: unknown; rateLimit?: unknown };
        if (typeof v.mode !== "string" || !RULE_MODES.includes(v.mode as RuleMode)) {
          sendError(res, 400, "Bad Request", `mode for "${endpoint}" must be ALLOW, BLOCK or REQUIRE_APPROVAL.`);
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
        updates[endpoint] = withRateLimit(
          {
            mode: v.mode as RuleMode,
            description: typeof desc === "string" ? desc : existing?.description ?? "",
          },
          v.rateLimit === undefined ? existing?.rateLimit : (v.rateLimit as number | null)
        );
      } else {
        sendError(res, 400, "Bad Request", `Value for "${endpoint}" must be true/false or { mode, description }.`);
        return;
      }
    }

    try {
      const rules: Rules = { ...current, ...updates };
      rulesStore.save(rules);
      res.json({ success: true, rules });
    } catch (err) {
      sendInternalError(res, "Failed to save rules", err, "Could not write rules.json.");
    }
  });

  router.delete("/rules", (req: Request, res: Response) => {
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
    const rules = rulesStore.load();
    if (!Object.prototype.hasOwnProperty.call(rules, endpoint)) {
      sendError(res, 404, "Not Found", `No rule exists for "${endpoint}".`);
      return;
    }

    try {
      delete rules[endpoint];
      rulesStore.save(rules);
      res.json({ success: true, rules });
    } catch (err) {
      sendInternalError(res, "Failed to save rules", err, "Could not write rules.json.");
    }
  });
}
