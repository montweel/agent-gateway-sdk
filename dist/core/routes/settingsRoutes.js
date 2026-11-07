"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.registerSettingsRoutes = registerSettingsRoutes;
const constants_1 = require("../constants");
const utils_1 = require("../utils");
const policy_1 = require("../policy");
/** Adds rateLimit to a rule only when it is a real limit, so rules.json stays clean. */
function withRateLimit(rule, rateLimit) {
    return typeof rateLimit === "number" ? { ...rule, rateLimit } : rule;
}
/** Adds policies only when there are some, so rules.json stays clean. */
function withPolicies(rule, policies) {
    return policies && policies.length > 0 ? { ...rule, policies } : rule;
}
function withGuards(rule, budget, dedupe) {
    const out = { ...rule };
    if (budget)
        out.budget = budget;
    if (dedupe)
        out.dedupe = dedupe;
    return out;
}
function parseHeaderName(res, value, field, example) {
    if (typeof value !== "string") {
        (0, utils_1.sendError)(res, 400, "Bad Request", `${field} must be a string.`);
        return null;
    }
    const clean = value.trim().toLowerCase();
    if (!clean || !constants_1.HEADER_NAME_REGEX.test(clean)) {
        (0, utils_1.sendError)(res, 400, "Bad Request", `${field} must be a valid HTTP header name (letters, numbers, and hyphens, e.g. "${example}").`);
        return null;
    }
    return clean;
}
/** Gateway settings (/config) and access rules (/rules). */
function registerSettingsRoutes(router, ctx) {
    const { config: configStore, rules: rulesStore, port, license } = ctx;
    // ---- Config ----
    router.get("/config", (req, res) => {
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
    router.post("/config", async (req, res) => {
        const body = req.body;
        if (typeof body !== "object" || body === null || Array.isArray(body)) {
            (0, utils_1.sendError)(res, 400, "Bad Request", "Body must be a JSON object.");
            return;
        }
        const input = body;
        const current = configStore.load();
        const updated = { ...current };
        if (input.targetUrl !== undefined) {
            if (typeof input.targetUrl !== "string") {
                (0, utils_1.sendError)(res, 400, "Bad Request", "targetUrl must be a string.");
                return;
            }
            const parsed = (0, utils_1.parseTargetUrl)(input.targetUrl, port);
            if (!parsed.ok) {
                (0, utils_1.sendError)(res, 400, "Bad Request", parsed.message);
                return;
            }
            updated.targetUrl = parsed.url;
        }
        if (input.rateLimitPerMinute !== undefined) {
            const n = input.rateLimitPerMinute;
            if (typeof n !== "number" || !Number.isInteger(n) || n < 1 || n > 1000000) {
                (0, utils_1.sendError)(res, 400, "Bad Request", "rateLimitPerMinute must be a whole number from 1 to 1,000,000.");
                return;
            }
            updated.rateLimitPerMinute = n;
        }
        if (input.requireAgentApiKey !== undefined) {
            if (typeof input.requireAgentApiKey !== "boolean") {
                (0, utils_1.sendError)(res, 400, "Bad Request", "requireAgentApiKey must be a boolean.");
                return;
            }
            updated.requireAgentApiKey = input.requireAgentApiKey;
        }
        if (input.ssoTrustProxyHeader !== undefined) {
            if (typeof input.ssoTrustProxyHeader !== "boolean") {
                (0, utils_1.sendError)(res, 400, "Bad Request", "ssoTrustProxyHeader must be a boolean.");
                return;
            }
            updated.ssoTrustProxyHeader = input.ssoTrustProxyHeader;
        }
        if (input.ssoUserHeader !== undefined) {
            const clean = parseHeaderName(res, input.ssoUserHeader, "ssoUserHeader", "x-forwarded-user");
            if (clean === null)
                return;
            updated.ssoUserHeader = clean;
        }
        if (input.ssoRoleHeader !== undefined) {
            const clean = parseHeaderName(res, input.ssoRoleHeader, "ssoRoleHeader", "x-forwarded-role");
            if (clean === null)
                return;
            updated.ssoRoleHeader = clean;
        }
        // Trusted Identity Proxy (SSO) is a Pro feature. Re-saving an unchanged SSO setup
        // (the dashboard form always sends every field) stays allowed so a lapsed license
        // never blocks ordinary settings changes.
        const ssoChanged = (updated.ssoTrustProxyHeader && !current.ssoTrustProxyHeader) ||
            (updated.ssoTrustProxyHeader &&
                (updated.ssoUserHeader !== current.ssoUserHeader || updated.ssoRoleHeader !== current.ssoRoleHeader)) ||
            (input.rotateSsoSharedSecret === true && updated.ssoTrustProxyHeader);
        if (ssoChanged && !(await license.isPro())) {
            (0, utils_1.sendProRequired)(res, "reverse-proxy SSO (x-forwarded-user / x-forwarded-role)");
            return;
        }
        try {
            configStore.save(updated); // creates the shared secret if SSO trust was just switched on
            if (input.rotateSsoSharedSecret === true && updated.ssoTrustProxyHeader)
                configStore.rotateSsoSharedSecret();
            const warnings = [];
            if (updated.requireAgentApiKey) {
                warnings.push("Agent keys are now required. Make sure your agents have one before they next call the gateway.");
            }
            res.json({ success: true, config: configStore.load(), warnings });
        }
        catch (err) {
            (0, utils_1.sendInternalError)(res, "Failed to save config", err, "Could not write config.json.");
        }
    });
    // ---- Rules ----
    router.get("/rules", (_req, res) => {
        res.json(rulesStore.load());
    });
    router.post("/rules", (req, res) => {
        const body = req.body;
        if (typeof body !== "object" || body === null || Array.isArray(body)) {
            (0, utils_1.sendError)(res, 400, "Bad Request", 'Body must be a JSON object like { "/api/some-path": { "mode": "ALLOW" } }.');
            return;
        }
        const entries = Object.entries(body);
        if (entries.length === 0) {
            (0, utils_1.sendError)(res, 400, "Bad Request", "Body is empty.");
            return;
        }
        const current = rulesStore.load();
        const updates = {};
        for (const [rawKey, value] of entries) {
            // A key is "/api/x" (any method) or "POST /api/x" (that method only).
            const parsedKey = (0, utils_1.parseRuleKey)(rawKey);
            if ("error" in parsedKey) {
                (0, utils_1.sendError)(res, 400, "Bad Request", `Invalid endpoint "${rawKey}". ${parsedKey.error}`);
                return;
            }
            const pathProblem = (0, utils_1.validateRulePath)(parsedKey.path);
            if (pathProblem) {
                (0, utils_1.sendError)(res, 400, "Bad Request", `Invalid endpoint "${rawKey}". ${pathProblem}`);
                return;
            }
            const endpoint = (0, utils_1.ruleKey)(parsedKey.method, parsedKey.path);
            if (parsedKey.path.startsWith("/api/agent-admin")) {
                (0, utils_1.sendError)(res, 400, "Bad Request", "Admin routes bypass the gateway, so rules cannot apply to them.");
                return;
            }
            const existing = Object.prototype.hasOwnProperty.call(current, endpoint) ? current[endpoint] : undefined;
            if (typeof value === "boolean") {
                updates[endpoint] = withGuards(withPolicies(withRateLimit({ mode: value ? "ALLOW" : "BLOCK", description: existing?.description ?? "" }, existing?.rateLimit), existing?.policies), existing?.budget, existing?.dedupe);
            }
            else if (typeof value === "object" && value !== null && !Array.isArray(value)) {
                const v = value;
                if (typeof v.mode !== "string" || !constants_1.RULE_MODES.includes(v.mode)) {
                    (0, utils_1.sendError)(res, 400, "Bad Request", `mode for "${endpoint}" must be ALLOW, BLOCK or REQUIRE_APPROVAL.`);
                    return;
                }
                const desc = v.description;
                if (desc !== undefined && typeof desc !== "string") {
                    (0, utils_1.sendError)(res, 400, "Bad Request", `description for "${endpoint}" must be a string.`);
                    return;
                }
                if (typeof desc === "string" && desc.length > 500) {
                    (0, utils_1.sendError)(res, 400, "Bad Request", `description for "${endpoint}" must be 500 characters or fewer.`);
                    return;
                }
                // rateLimit: omitted = keep the existing value, null = clear (use global), number = set.
                if (v.rateLimit !== undefined && v.rateLimit !== null && !(0, utils_1.isValidRuleRateLimit)(v.rateLimit)) {
                    (0, utils_1.sendError)(res, 400, "Bad Request", `rateLimit for "${endpoint}" must be null or a whole number from 1 to ${utils_1.MAX_RULE_RATE_LIMIT.toLocaleString("en-US")}.`);
                    return;
                }
                // policies: omitted = keep the existing tiers, null or [] = clear, list = replace.
                let policies = existing?.policies;
                if (v.policies !== undefined) {
                    const checked = (0, policy_1.validatePolicies)(v.policies);
                    if (!checked.ok) {
                        (0, utils_1.sendError)(res, 400, "Bad Request", `Invalid policies for "${endpoint}": ${checked.message}`);
                        return;
                    }
                    policies = checked.policies;
                }
                // budget / dedupe: omitted = keep, null = remove, object = replace.
                let budget = existing?.budget;
                if (v.budget !== undefined) {
                    const b = (0, policy_1.validateBudget)(v.budget);
                    if (!b.ok) {
                        (0, utils_1.sendError)(res, 400, "Bad Request", `Invalid budget for "${endpoint}": ${b.message}`);
                        return;
                    }
                    budget = b.value;
                }
                let dedupe = existing?.dedupe;
                if (v.dedupe !== undefined) {
                    const d = (0, policy_1.validateDedupe)(v.dedupe);
                    if (!d.ok) {
                        (0, utils_1.sendError)(res, 400, "Bad Request", `Invalid dedupe for "${endpoint}": ${d.message}`);
                        return;
                    }
                    dedupe = d.value;
                }
                updates[endpoint] = withGuards(withPolicies(withRateLimit({
                    mode: v.mode,
                    description: typeof desc === "string" ? desc : existing?.description ?? "",
                }, v.rateLimit === undefined ? existing?.rateLimit : v.rateLimit), policies), budget, dedupe);
            }
            else {
                (0, utils_1.sendError)(res, 400, "Bad Request", `Value for "${endpoint}" must be true/false or { mode, description }.`);
                return;
            }
        }
        try {
            const rules = { ...current, ...updates };
            rulesStore.save(rules);
            const warnings = Object.entries(updates)
                .filter(([, r]) => r.policies && r.policies.length > 0 && r.mode === "ALLOW")
                .map(([k]) => `"${k}" falls back to ALLOW when no policy tier matches (for example when a field is missing). ` +
                "Use REQUIRE_APPROVAL or BLOCK as the fallback for fail-closed behaviour.");
            res.json({ success: true, rules, warnings });
        }
        catch (err) {
            (0, utils_1.sendInternalError)(res, "Failed to save rules", err, "Could not write rules.json.");
        }
    });
    router.delete("/rules", (req, res) => {
        const bodyPath = req.body?.path;
        const queryPath = req.query.path;
        const raw = typeof bodyPath === "string" ? bodyPath : typeof queryPath === "string" ? queryPath : "";
        if (!raw.trim()) {
            (0, utils_1.sendError)(res, 400, "Bad Request", 'Provide the endpoint as { "path": "/api/..." } in the body or ?path= in the URL.');
            return;
        }
        const parsedKey = (0, utils_1.parseRuleKey)(raw);
        if ("error" in parsedKey) {
            (0, utils_1.sendError)(res, 400, "Bad Request", parsedKey.error);
            return;
        }
        const endpoint = (0, utils_1.ruleKey)(parsedKey.method, parsedKey.path);
        const rules = rulesStore.load();
        if (!Object.prototype.hasOwnProperty.call(rules, endpoint)) {
            (0, utils_1.sendError)(res, 404, "Not Found", `No rule exists for "${endpoint}".`);
            return;
        }
        try {
            delete rules[endpoint];
            rulesStore.save(rules);
            res.json({ success: true, rules });
        }
        catch (err) {
            (0, utils_1.sendInternalError)(res, "Failed to save rules", err, "Could not write rules.json.");
        }
    });
}
