import fs from "fs";
import type { Request, Response } from "express";
import type { Rule, RuleMode } from "./types";
import {
  MAX_RULE_PATH_LENGTH,
  NO_BODY_METHODS,
  REDACTED,
  RULE_METHODS,
  RULE_MODES,
  SENSITIVE_QUERY_KEYS,
  SENSITIVE_KEYS,
  UNSAVED_HEADERS,
} from "./constants";
import { ScryptBusyError } from "./crypto";
import { normalizePolicies, validateBudget, validateDedupe } from "./policy";

export function sendError(
  res: Response,
  status: number,
  error: string,
  message: string,
  extra?: Record<string, unknown>
): void {
  res.status(status).json({ error, message, ...extra });
}

export const UPGRADE_URL = "https://montweel.com/#license-renewal";

export const PRO_REQUIRED_MESSAGE =
  "Pro feature — claim your free 90-day trial key (no payment card required) or upgrade at https://montweel.com";

/**
 * Team Pro gate. Deliberately NOT an error status: replies 200 with `proRequired: true` so
 * clients can show an upgrade prompt instead of a failure. `feature` is kept for call-site clarity.
 */
export function sendProRequired(res: Response, _feature?: string): void {
  res.status(200).json({ proRequired: true, message: PRO_REQUIRED_MESSAGE, upgradeUrl: UPGRADE_URL });
}

export function sendCaughtError(res: Response, err: unknown): void {
  if (res.headersSent) return;
  const e = err as { status?: unknown; message?: unknown } | null;
  const status = typeof e?.status === "number" && e.status >= 400 && e.status < 500 ? e.status : 500;
  if (status === 500) {
    console.error("Unhandled error:", err);
    sendError(res, 500, "Internal Server Error", "Unexpected error.");
    return;
  }
  const names: Record<number, string> = {
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    408: "Request Timeout",
    413: "Payload Too Large",
    415: "Unsupported Media Type",
    429: "Too Many Requests",
  };
  sendError(res, status, names[status] ?? "Bad Request", typeof e?.message === "string" ? e.message : "Invalid request.");
}

/** Logs the real error server-side and sends a generic message to the client. */
export function sendInternalError(res: Response, context: string, err: unknown, clientMessage: string): void {
  if (err instanceof ScryptBusyError) {
    if (!res.headersSent) {
      res.setHeader("Retry-After", "2");
      sendError(res, 429, "Too Many Requests", err.message);
    }
    return;
  }
  console.error(`${context}:`, err);
  if (!res.headersSent) sendError(res, 500, "Internal Server Error", clientMessage);
}

export function normalizePath(p: string): string {
  return p.length > 1 ? p.replace(/\/+$/, "") : p;
}

// Files may hold secrets (config.json can contain static tokens), so keep them owner-only.
export function writeJsonAtomic(filePath: string, data: unknown): void {
  const tmpPath = filePath + ".tmp";
  fs.writeFileSync(tmpPath, JSON.stringify(data, null, 2), { encoding: "utf-8", mode: 0o600 });
  fs.renameSync(tmpPath, filePath);
}

export function parseJsonObject(text: string | null): Record<string, string> {
  if (!text) return {};
  try {
    const parsed: unknown = JSON.parse(text);
    if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
      return parsed as Record<string, string>;
    }
  } catch {
    // ignore bad JSON
  }
  return {};
}

const BLOCKED_TARGET_HOSTS = new Set([
  "169.254.169.254", // AWS / Azure / GCP instance metadata
  "metadata.google.internal",
  "100.100.100.200", // Alibaba Cloud metadata
  "fd00:ec2::254", // AWS IPv6 metadata
]);

export function parseTargetUrl(
  value: string,
  gatewayPort: number
): { ok: true; url: string } | { ok: false; message: string } {
  const trimmed = value.trim().replace(/\/+$/, "");
  if (trimmed === "") return { ok: true, url: "" };

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return { ok: false, message: "targetUrl must be a full URL like https://api.example.com" };
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { ok: false, message: "targetUrl must start with http:// or https://" };
  }
  if (parsed.username || parsed.password) {
    return { ok: false, message: "targetUrl must not contain embedded credentials." };
  }

  const hostname = parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (BLOCKED_TARGET_HOSTS.has(hostname) || hostname.startsWith("169.254.")) {
    return { ok: false, message: "targetUrl cannot point at a cloud metadata / link-local address." };
  }

  const urlPort = parsed.port || (parsed.protocol === "https:" ? "443" : "80");
  const localHosts = ["localhost", "127.0.0.1", "0.0.0.0", "::1"];
  if (localHosts.includes(hostname) && urlPort === String(gatewayPort)) {
    return {
      ok: false,
      message: `targetUrl cannot point at this gateway itself (localhost:${gatewayPort}).`,
    };
  }
  return { ok: true, url: trimmed };
}

/**
 * Returns an error message when a rule path is unsafe, or null when it is fine.
 * Rules match the request path byte-for-byte, so anything ambiguous is refused:
 * traversal ("..", encoded dots/slashes), whitespace, control characters, "\\".
 */
export function validateRulePath(endpoint: string): string | null {
  if (!endpoint.startsWith("/api/")) return 'Endpoints must start with "/api/".';
  if (endpoint.length > MAX_RULE_PATH_LENGTH) return `Endpoints must be ${MAX_RULE_PATH_LENGTH} characters or fewer.`;
  if (endpoint.includes("..")) return 'Endpoints cannot contain "..".';
  if (/\s/.test(endpoint)) return "Endpoints cannot contain whitespace.";
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(endpoint)) return "Endpoints cannot contain control characters.";
  if (endpoint.includes("\\") || /%2e|%2f|%5c|%00/i.test(endpoint)) {
    return "Endpoints cannot contain backslashes or encoded dots, slashes or null bytes.";
  }
  if (endpoint.includes("?") || endpoint.includes("#")) {
    return "Leave out query strings; rules match the path only.";
  }
  return null;
}

function isSensitiveKey(key: string): boolean {
  const k = key.toLowerCase().replace(/[_-]/g, "");
  return SENSITIVE_KEYS.some((s) => k.includes(s));
}

/** Deep copy of a parsed JSON value with sensitive keys replaced by "[REDACTED]". */
export function redactSensitive(value: unknown, depth = 0): unknown {
  if (depth > 20) return REDACTED; // absurdly deep: do not risk leaking something below
  if (Array.isArray(value)) return value.map((v) => redactSensitive(v, depth + 1));
  if (typeof value === "object" && value !== null) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = isSensitiveKey(k) ? REDACTED : redactSensitive(v, depth + 1);
    }
    return out;
  }
  return value;
}

/** Rule key for a method-specific rule, e.g. "POST /api/flights". */
export function ruleKey(method: string | null, endpoint: string): string {
  return method ? `${method} ${endpoint}` : endpoint;
}

/**
 * Splits a rule key into its method (null = any method) and path. Accepts
 * "/api/x" and "POST /api/x" (method case-insensitive, "ANY /api/x" = "/api/x").
 * Returns an error message when the key is unusable. The returned `path` still
 * needs validateRulePath().
 */
export function parseRuleKey(raw: string): { method: string | null; path: string } | { error: string } {
  const trimmed = raw.trim();
  const space = trimmed.search(/\s/);
  if (space === -1) return { method: null, path: normalizePath(trimmed) };

  const word = trimmed.slice(0, space).toUpperCase();
  const rest = trimmed.slice(space).trim();
  if (word === "ANY") return { method: null, path: normalizePath(rest) };
  if (!RULE_METHODS.includes(word)) {
    return { error: `Unknown method "${trimmed.slice(0, space)}". Use ${RULE_METHODS.slice(0, 5).join(", ")} or leave the method out.` };
  }
  return { method: word, path: normalizePath(rest) };
}

/** Replaces the values of sensitive query parameters, leaving everything else byte-for-byte. */
export function redactQueryString(url: string): string {
  const q = url.indexOf("?");
  if (q === -1) return url;
  const hash = url.indexOf("#", q);
  const queryEnd = hash === -1 ? url.length : hash;
  const query = url.slice(q + 1, queryEnd);

  const redacted = query
    .split("&")
    .map((pair) => {
      const eq = pair.indexOf("=");
      if (eq === -1) return pair;
      let name = pair.slice(0, eq);
      try {
        name = decodeURIComponent(name.replace(/\+/g, " "));
      } catch {
        // keep the raw name
      }
      const k = name.toLowerCase().replace(/[_-]/g, "");
      const sensitive = SENSITIVE_QUERY_KEYS.some((s) => k === s || k.endsWith(s));
      return sensitive ? `${pair.slice(0, eq)}=${encodeURIComponent(REDACTED)}` : pair;
    })
    .join("&");

  return url.slice(0, q + 1) + redacted + url.slice(queryEnd);
}

/** Parsed query object with sensitive parameter values replaced by "[REDACTED]". */
export function redactQueryObject(query: unknown): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (typeof query !== "object" || query === null) return out;
  for (const [k, v] of Object.entries(query as Record<string, unknown>)) {
    const name = k.toLowerCase().replace(/[_-]/g, "");
    const sensitive = SENSITIVE_QUERY_KEYS.some((s) => name === s || name.endsWith(s)) || isSensitiveKey(k);
    out[k] = sensitive ? REDACTED : redactSensitive(v);
  }
  return out;
}

export const MAX_RULE_RATE_LIMIT = 1_000_000;

export function isValidRuleRateLimit(n: unknown): n is number {
  return typeof n === "number" && Number.isInteger(n) && n >= 1 && n <= MAX_RULE_RATE_LIMIT;
}

export function normalizeRule(value: unknown): Rule | null {
  if (value === true) return { mode: "ALLOW", description: "" };
  if (value === false) return { mode: "BLOCK", description: "" };

  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    const v = value as { mode?: unknown; description?: unknown; rateLimit?: unknown; policies?: unknown; budget?: unknown; dedupe?: unknown };
    const mode =
      typeof v.mode === "string" && RULE_MODES.includes(v.mode as RuleMode)
        ? (v.mode as RuleMode)
        : "BLOCK";
    const rule: Rule = { mode, description: typeof v.description === "string" ? v.description : "" };
    if (isValidRuleRateLimit(v.rateLimit)) rule.rateLimit = v.rateLimit;
    const policies = normalizePolicies(v.policies);
    if (policies === "invalid") {
      // Fail closed: a rule whose policies cannot be trusted is enforced as BLOCK.
      return { ...rule, mode: "BLOCK", description: `${rule.description} [policies invalid: enforced as BLOCK]`.trim() };
    }
    if (policies) rule.policies = policies;
    const budget = validateBudget(v.budget);
    const dedupe = validateDedupe(v.dedupe);
    if (!budget.ok || !dedupe.ok) {
      // Fail closed: a cap we cannot read must not silently disappear.
      const message = !budget.ok ? budget.message : !dedupe.ok ? dedupe.message : "";
      console.error(`Invalid budget/dedupe in rules.json (${message}); the rule is enforced as BLOCK.`);
      return { ...rule, mode: "BLOCK", policies: undefined, description: `${rule.description} [guards invalid: enforced as BLOCK]`.trim() };
    }
    if (budget.value) rule.budget = budget.value;
    if (dedupe.value) rule.dedupe = dedupe.value;
    return rule;
  }
  return null;
}

/** Thrown by withTimeout. The interceptor turns it into a fail-closed 503. */
export class DbTimeoutError extends Error {
  constructor(label: string, ms: number) {
    super(`${label} did not finish within ${ms} ms.`);
    this.name = "DbTimeoutError";
  }
}

/** Rejects with DbTimeoutError when `promise` takes longer than `ms`. The original keeps running. */
export function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new DbTimeoutError(label, ms)), ms);
    timer.unref();
  });
  return Promise.race([promise, timeout]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}

/**
 * The single exit for "something went wrong while deciding": the request is refused and
 * never forwarded. 503 with Retry-After when we can still answer; if a response had already
 * started, the connection is destroyed so the client cannot mistake a partial reply for success.
 */
export function failClosed(res: Response, context: string, err: unknown): void {
  console.error(`[agent-gateway] FAIL-CLOSED (${context}):`, err);
  if (res.headersSent) {
    res.destroy();
    return;
  }
  res.setHeader("Retry-After", "5");
  sendError(
    res,
    503,
    "Service Unavailable",
    "The gateway could not safely evaluate this request, so it was refused and not forwarded. Retry shortly."
  );
}

/** Field names that the approval inspector and notifications flag as high-risk (substring, case-insensitive). */
export const HIGH_RISK_FIELDS = ["amount", "price", "delete", "email", "destination"];

/** Dot paths (body.*) of every key in a JSON value that looks high-risk, with its value. */
export function findHighRiskFields(value: unknown, prefix = "body", depth = 0, out: Array<{ path: string; value: unknown }> = []): Array<{ path: string; value: unknown }> {
  if (depth > 12 || out.length >= 50) return out;
  if (Array.isArray(value)) {
    value.forEach((v, i) => findHighRiskFields(v, `${prefix}.${i}`, depth + 1, out));
  } else if (typeof value === "object" && value !== null) {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      const p = `${prefix}.${k}`;
      const lower = k.toLowerCase();
      if (HIGH_RISK_FIELDS.some((r) => lower.includes(r)) && (typeof v !== "object" || v === null)) {
        out.push({ path: p, value: v });
      }
      findHighRiskFields(v, p, depth + 1, out);
    }
  }
  return out;
}

export function extractBody(req: Request): string | null {
  if (NO_BODY_METHODS.includes(req.method)) return null;
  const body: unknown = req.body;
  if (body === undefined || body === null) return null;
  if (typeof body === "object" && Object.keys(body as object).length === 0) {
    return req.is("application/json") ? "{}" : null;
  }
  return JSON.stringify(body);
}

/** Like extractBody, but safe to store: sensitive JSON values are redacted. */
export function extractRedactedBody(req: Request): string | null {
  if (NO_BODY_METHODS.includes(req.method)) return null;
  const body: unknown = req.body;
  if (body === undefined || body === null) return null;
  if (typeof body === "object" && Object.keys(body as object).length === 0) {
    return req.is("application/json") ? "{}" : null;
  }
  return JSON.stringify(redactSensitive(body));
}

export function sanitizeHeaders(req: Request): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(req.headers)) {
    const k = key.toLowerCase();
    if (value === undefined || UNSAVED_HEADERS.has(k)) continue;
    out[k] = Array.isArray(value) ? value.join(", ") : (value as string);
  }
  return out;
}

/** Escapes % _ \ so user input is matched literally inside a LIKE ... ESCAPE '\' clause. */
export function escapeLike(input: string): string {
  return input.replace(/[\\%_]/g, (c) => `\\${c}`);
}

export function truncate(value: string, max: number): string {
  return value.length > max ? value.slice(0, max) : value;
}
