"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SENSITIVE_KEYS = exports.BASE62 = exports.HEADER_NAME_REGEX = exports.SSO_USERNAME_REGEX = exports.USERNAME_REGEX = exports.NO_BODY_METHODS = exports.DEFAULT_CONFIG = exports.CALLBACK_MAX_FAILURES = exports.MAX_NOTIFY_PAYLOAD_CHARS = exports.ROLLBACK_TIMEOUT_MS = exports.NOTIFY_TIMEOUT_MS = exports.APPROVAL_CALLBACK_PREFIX = exports.MAX_AGENT_REASON_LENGTH = exports.AGENT_REASON_HEADER = exports.DB_OPERATION_TIMEOUT_MS = exports.MAX_LOG_UA_LENGTH = exports.MAX_LOG_PATH_LENGTH = exports.MAX_DECIDED_PENDING_ROWS = exports.MAX_PENDING_DISPLAY_CHARS = exports.MAX_PENDING_BODY_BYTES = exports.MAX_PENDING_ACTIONS = exports.MAX_TRACKED_IPS = exports.JSON_BODY_LIMIT = exports.LOGIN_MAX_FAILURES_PER_USER = exports.MAX_RULE_PATH_LENGTH = exports.MAX_CONCURRENT_SCRYPT = exports.MAX_LOG_ROWS = exports.SESSION_TOUCH_INTERVAL_MS = exports.OTP_TTL_MS = exports.PENDING_TTL_MS = exports.MAX_HOPS = exports.MAX_UPSTREAM_BYTES = exports.UPSTREAM_TIMEOUT_MS = exports.SESSION_TTL_MS = exports.LOGIN_MAX_FAILURES = exports.LOGIN_WINDOW_MS = exports.RATE_WINDOW_MS = exports.SETUP_TOKEN_HEADER = exports.AGENT_KEY_PREFIX = exports.AGENT_KEY_HEADER = exports.HOPS_HEADER = exports.SSO_SECRET_HEADER = exports.REPLAY_HEADER = exports.MAX_SNAPSHOT_CHARS = exports.DEFAULT_WORKSPACE_SLUG = exports.DEFAULT_WORKSPACE_ID = exports.WORKSPACE_PATH_PREFIX = exports.WORKSPACE_KEY_PREFIX = exports.WORKSPACE_HEADER = exports.RULE_MODES = void 0;
exports.UNSAVED_HEADERS = exports.NEVER_FORWARD = exports.HOP_BY_HOP = exports.OTP_ALPHABET = exports.MCP_TOOL_PATH_PREFIX = exports.MCP_RULE_METHOD = exports.RULE_METHODS = exports.SENSITIVE_QUERY_KEYS = exports.REDACTED = void 0;
exports.RULE_MODES = ["ALLOW", "BLOCK", "REQUIRE_APPROVAL", "SHADOW_BLOCK", "SHADOW_APPROVAL"];
// v2.0 multi-tenant workspaces
exports.WORKSPACE_HEADER = "x-mont-workspace";
exports.WORKSPACE_KEY_PREFIX = "mws_";
/** Path-prefix routing: /api/w/<slug>/... is the same request as /api/... in workspace <slug>. */
exports.WORKSPACE_PATH_PREFIX = "/api/w/";
exports.DEFAULT_WORKSPACE_ID = 1;
exports.DEFAULT_WORKSPACE_SLUG = "default";
/** Largest request snapshot (redacted JSON) kept in the audit log for the policy time-machine. */
exports.MAX_SNAPSHOT_CHARS = 16 * 1024;
// The header NAME is fixed. Its VALUE is a random secret created per gateway
// instance, so an outside caller cannot bypass the gateway by adding the header.
exports.REPLAY_HEADER = "x-gateway-internal-replay";
exports.SSO_SECRET_HEADER = "x-gateway-sso-secret";
exports.HOPS_HEADER = "x-gateway-hops";
exports.AGENT_KEY_HEADER = "x-agent-key";
exports.AGENT_KEY_PREFIX = "agk_";
exports.SETUP_TOKEN_HEADER = "x-setup-token";
exports.RATE_WINDOW_MS = 60000;
exports.LOGIN_WINDOW_MS = 15 * 60000; // 15 minutes
exports.LOGIN_MAX_FAILURES = 10;
exports.SESSION_TTL_MS = 24 * 60 * 60000; // 24 hours
exports.UPSTREAM_TIMEOUT_MS = 30000;
exports.MAX_UPSTREAM_BYTES = 10 * 1024 * 1024; // 10 MB cap on upstream responses
exports.MAX_HOPS = 3; // x-gateway-hops loop guard
exports.PENDING_TTL_MS = 24 * 60 * 60000; // queued approvals expire after 24 hours
exports.OTP_TTL_MS = 24 * 60 * 60000; // one-time passwords expire after 24 hours
exports.SESSION_TOUCH_INTERVAL_MS = 5 * 60000; // sliding-session DB write throttle
exports.MAX_LOG_ROWS = 10000; // agent_logs retention
exports.MAX_CONCURRENT_SCRYPT = 4;
exports.MAX_RULE_PATH_LENGTH = 256;
exports.LOGIN_MAX_FAILURES_PER_USER = 5; // per ip + username
// Abuse limits
exports.JSON_BODY_LIMIT = "1mb";
exports.MAX_TRACKED_IPS = 100000; // cap on in-memory limiter maps
exports.MAX_PENDING_ACTIONS = 1000; // cap on queued approvals
exports.MAX_PENDING_BODY_BYTES = 256 * 1024; // largest body that can be queued for approval
exports.MAX_PENDING_DISPLAY_CHARS = 32 * 1024; // redacted copy shown to approvers is truncated to this
exports.MAX_DECIDED_PENDING_ROWS = 5000; // retention for decided/expired approvals
exports.MAX_LOG_PATH_LENGTH = 2048;
exports.MAX_LOG_UA_LENGTH = 256;
// v1.1: fail-closed, approvals, notifications
exports.DB_OPERATION_TIMEOUT_MS = 4000; // a hung/locked SQLite op fails the request closed after this
exports.AGENT_REASON_HEADER = "x-agent-reason";
exports.MAX_AGENT_REASON_LENGTH = 1000;
exports.APPROVAL_CALLBACK_PREFIX = "/_mont/approvals";
exports.NOTIFY_TIMEOUT_MS = 5000;
exports.ROLLBACK_TIMEOUT_MS = 10000;
exports.MAX_NOTIFY_PAYLOAD_CHARS = 2500;
exports.CALLBACK_MAX_FAILURES = 20; // bad signatures per IP per 15 minutes before lockout
exports.DEFAULT_CONFIG = {
    targetUrl: "",
    rateLimitPerMinute: 60,
    requireAgentApiKey: false,
    ssoTrustProxyHeader: false,
    ssoSharedSecret: "",
    ssoUserHeader: "x-forwarded-user",
    ssoRoleHeader: "x-forwarded-role",
};
exports.NO_BODY_METHODS = ["GET", "HEAD"];
exports.USERNAME_REGEX = /^[a-zA-Z0-9._@-]{2,64}$/;
exports.SSO_USERNAME_REGEX = /^[a-zA-Z0-9._@+-]{1,128}$/;
exports.HEADER_NAME_REGEX = /^[a-z0-9-]+$/;
// Unambiguous alphabet for one-time passwords (no 0/O, 1/l/I)
exports.BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
// JSON keys whose values are replaced with REDACTED before a body is stored.
// Matched case-insensitively after removing "_" and "-", and as a substring
// ("accessToken", "client_secret", "X-Api-Key" all match).
exports.SENSITIVE_KEYS = ["password", "secret", "token", "apikey", "authorization", "cvv", "cardnumber"];
exports.REDACTED = "[REDACTED]";
// Query-string parameters whose values are hidden in stored paths. A name matches
// when, lower-cased with "_" and "-" removed, it equals or ends with one of these
// ("api_key" -> "apikey", "access_token" -> "accesstoken").
exports.SENSITIVE_QUERY_KEYS = ["token", "key", "secret", "password", "apikey", "auth"];
// Methods a rule key can be pinned to ("POST /api/flights"). A key without a
// method ("/api/flights") applies to every method that has no pinned rule.
// "MCP" is a pseudo-method for MCP tools/call rules ("MCP /api/mcp/tools/<tool>"); no HTTP request can carry it.
exports.RULE_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "MCP"];
exports.MCP_RULE_METHOD = "MCP";
exports.MCP_TOOL_PATH_PREFIX = "/api/mcp/tools/";
exports.OTP_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
// Hop-by-hop headers must never be forwarded by a proxy.
exports.HOP_BY_HOP = new Set([
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
exports.NEVER_FORWARD = new Set([
    "host",
    "content-length",
    "accept-encoding",
    "x-admin-token",
    exports.REPLAY_HEADER,
    exports.SSO_SECRET_HEADER,
    exports.SETUP_TOKEN_HEADER,
    exports.AGENT_KEY_HEADER,
    exports.WORKSPACE_HEADER,
    // Identity headers set by an SSO proxy. They must never reach the upstream
    // where they could be mistaken for a verified identity.
    "x-forwarded-user",
    "x-forwarded-role",
    exports.HOPS_HEADER,
]);
// Headers we do NOT save in pending_actions (sensitive or irrelevant).
exports.UNSAVED_HEADERS = new Set([
    ...exports.HOP_BY_HOP,
    ...exports.NEVER_FORWARD,
    "authorization",
    "cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-amz-security-token",
]);
