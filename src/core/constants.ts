import type { GatewayConfig, RuleMode } from "./types";

export const RULE_MODES: RuleMode[] = ["ALLOW", "BLOCK", "REQUIRE_APPROVAL"];

// The header NAME is fixed. Its VALUE is a random secret created per gateway
// instance, so an outside caller cannot bypass the gateway by adding the header.
export const REPLAY_HEADER = "x-gateway-internal-replay";
export const SSO_SECRET_HEADER = "x-gateway-sso-secret";
export const HOPS_HEADER = "x-gateway-hops";
export const AGENT_KEY_HEADER = "x-agent-key";
export const AGENT_KEY_PREFIX = "agk_";
export const SETUP_TOKEN_HEADER = "x-setup-token";

export const RATE_WINDOW_MS = 60_000;
export const LOGIN_WINDOW_MS = 15 * 60_000; // 15 minutes
export const LOGIN_MAX_FAILURES = 10;
export const SESSION_TTL_MS = 24 * 60 * 60_000; // 24 hours
export const UPSTREAM_TIMEOUT_MS = 30_000;
export const MAX_UPSTREAM_BYTES = 10 * 1024 * 1024; // 10 MB cap on upstream responses
export const MAX_HOPS = 3; // x-gateway-hops loop guard
export const PENDING_TTL_MS = 24 * 60 * 60_000; // queued approvals expire after 24 hours
export const OTP_TTL_MS = 24 * 60 * 60_000; // one-time passwords expire after 24 hours
export const SESSION_TOUCH_INTERVAL_MS = 5 * 60_000; // sliding-session DB write throttle
export const MAX_LOG_ROWS = 10_000; // agent_logs retention
export const MAX_CONCURRENT_SCRYPT = 4;
export const MAX_RULE_PATH_LENGTH = 256;
export const LOGIN_MAX_FAILURES_PER_USER = 5; // per ip + username

// Abuse limits
export const JSON_BODY_LIMIT = "1mb";
export const MAX_TRACKED_IPS = 100_000; // cap on in-memory limiter maps
export const MAX_PENDING_ACTIONS = 1_000; // cap on queued approvals
export const MAX_PENDING_BODY_BYTES = 256 * 1024; // largest body that can be queued for approval
export const MAX_PENDING_DISPLAY_CHARS = 32 * 1024; // redacted copy shown to approvers is truncated to this
export const MAX_DECIDED_PENDING_ROWS = 5_000; // retention for decided/expired approvals
export const MAX_LOG_PATH_LENGTH = 2_048;
export const MAX_LOG_UA_LENGTH = 256;

export const DEFAULT_CONFIG: GatewayConfig = {
  targetUrl: "",
  rateLimitPerMinute: 60,
  requireAgentApiKey: false,
  ssoTrustProxyHeader: false,
  ssoSharedSecret: "",
  ssoUserHeader: "x-forwarded-user",
  ssoRoleHeader: "x-forwarded-role",
};

export const NO_BODY_METHODS = ["GET", "HEAD"];
export const USERNAME_REGEX = /^[a-zA-Z0-9._@-]{2,64}$/;
export const SSO_USERNAME_REGEX = /^[a-zA-Z0-9._@+-]{1,128}$/;
export const HEADER_NAME_REGEX = /^[a-z0-9-]+$/;

// Unambiguous alphabet for one-time passwords (no 0/O, 1/l/I)
export const BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

// JSON keys whose values are replaced with REDACTED before a body is stored.
// Matched case-insensitively after removing "_" and "-", and as a substring
// ("accessToken", "client_secret", "X-Api-Key" all match).
export const SENSITIVE_KEYS = ["password", "secret", "token", "apikey", "authorization", "cvv", "cardnumber"];
export const REDACTED = "[REDACTED]";

// Query-string parameters whose values are hidden in stored paths. A name matches
// when, lower-cased with "_" and "-" removed, it equals or ends with one of these
// ("api_key" -> "apikey", "access_token" -> "accesstoken").
export const SENSITIVE_QUERY_KEYS = ["token", "key", "secret", "password", "apikey", "auth"];

// Methods a rule key can be pinned to ("POST /api/flights"). A key without a
// method ("/api/flights") applies to every method that has no pinned rule.
export const RULE_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

export const OTP_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Hop-by-hop headers must never be forwarded by a proxy.
export const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

// Headers we never forward upstream (they are gateway-internal credentials).
export const NEVER_FORWARD = new Set([
  "host",
  "content-length",
  "accept-encoding",
  "x-admin-token",
  REPLAY_HEADER,
  SSO_SECRET_HEADER,
  SETUP_TOKEN_HEADER,
  AGENT_KEY_HEADER,
  // Identity headers set by an SSO proxy. They must never reach the upstream
  // where they could be mistaken for a verified identity.
  "x-forwarded-user",
  "x-forwarded-role",
  HOPS_HEADER, // re-added by the proxy with the incremented value
]);

// Headers we do NOT save in pending_actions (sensitive or irrelevant).
export const UNSAVED_HEADERS = new Set([
  ...HOP_BY_HOP,
  ...NEVER_FORWARD,
  "authorization",
  "cookie",
  "x-api-key",
  "x-auth-token",
  "x-csrf-token",
  "x-amz-security-token",
]);
