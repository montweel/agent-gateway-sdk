import type { Request, RequestHandler, Router } from "express";

// =====================================================================
// Public types
// =====================================================================
/**
 * SHADOW_BLOCK / SHADOW_APPROVAL ("dry run"): the request is ALLOWED and forwarded, but the
 * audit row records what the rule would have done, so a new policy can be watched against
 * live traffic before it is enforced.
 */
export type RuleMode = "ALLOW" | "BLOCK" | "REQUIRE_APPROVAL" | "SHADOW_BLOCK" | "SHADOW_APPROVAL";
export type UserRole = "admin" | "viewer";

/**
 * Payload policy operators. Numeric operators need a finite number: body values must
 * already be JSON numbers (no string coercion, so "250" never compares as 250), while
 * query and header values are strings and are compared as numbers only when they are
 * canonical decimal strings.
 */
export type PolicyOperator = ">" | "<" | ">=" | "<=" | "===" | "!==" | "contains" | "in" | "regex" | "exists";

export interface PolicyCondition {
  /** Dot path rooted at body, query or headers, e.g. "body.amount", "body.items.0.price", "headers.x-agent-reason". */
  field: string;
  op: PolicyOperator;
  /** Comparison value. Number for > < >= <=, primitive for === !==, array for in, string for regex/contains, boolean for exists. */
  value?: unknown;
  /** Regex flags. Only "i" is accepted. */
  flags?: string;
}

/** One tier: every condition must hold (AND). Tiers are checked in order and the first match decides. */
export interface PolicyTier {
  name?: string;
  when: PolicyCondition[];
  mode: RuleMode;
}

export interface Rule {
  /** The decision when the rule has no policies, or when no policy tier matches. */
  mode: RuleMode;
  description: string;
  /** Max requests per minute per client IP for this rule. null/undefined = use the global limit. */
  rateLimit?: number | null;
  /** Optional payload-level tiers evaluated against the parsed request (first match wins). */
  policies?: PolicyTier[];
  /** Cumulative spending cap for requests this rule would ALLOW (e.g. max $300 of refunds per hour). */
  budget?: BudgetSpec;
  /** Refuses the same action twice (e.g. a second refund for the same orderId). */
  dedupe?: DedupeSpec;
}
export type Rules = Record<string, Rule>;

export interface BudgetSpec {
  /** Number field to add up, e.g. "body.amount". Must be a JSON number (missing / text = treated as over budget). */
  field: string;
  /** Maximum total within the window. */
  max: number;
  /** Rolling window, 1 minute to 30 days. */
  windowMinutes: number;
  /** "global": one budget for all agents. "caller": one budget per agent key (or IP when no key). */
  per: "global" | "caller";
  /** What happens to a request that would go over budget. */
  onExceed: "REQUIRE_APPROVAL" | "BLOCK";
}

export interface DedupeSpec {
  /** Fields that identify "the same action", e.g. ["body.orderId"]. */
  fields: string[];
  windowMinutes: number;
  onDuplicate: "BLOCK" | "REQUIRE_APPROVAL";
}

export type EmergencyMode = "normal" | "approval_only" | "lockdown";

export interface EmergencyState {
  mode: EmergencyMode;
  reason: string | null;
  changedBy: string | null;
  changedAt: string | null;
}

export interface ScheduleSettings {
  /** When on, requests the rules would ALLOW are held for approval outside business hours (reads stay allowed). */
  enabled: boolean;
  /** 0 = Sunday ... 6 = Saturday, in `timezone`. */
  days: number[];
  /** "HH:MM" 24h, local to `timezone`. */
  start: string;
  end: string;
}

export interface AlertSettings {
  /** Security alerts (attack bursts, budget exceeded, emergency mode changes) to the enabled channels. */
  enabled: boolean;
  /** Alert when at least this many requests are BLOCKED / RATE_LIMITED ... */
  burstThreshold: number;
  /** ... within this many minutes. */
  burstWindowMinutes: number;
  /** Local hour (0-23, in `timezone`) for the daily digest; null = off. */
  digestHour: number | null;
}

export interface NotificationSettings {
  slack: {
    enabled: boolean;
    /**
     * "webhook": incoming-webhook message with signed links (needs a Public URL).
     * "socket":  bot posts with Approve / Reject buttons; taps arrive over an outbound
     *            Socket Mode WebSocket, so no public URL or tunnel is needed.
     */
    mode: "webhook" | "socket";
    webhookUrl: string;
    /** xoxb- bot token (socket mode): chat.postMessage / chat.update. */
    botToken: string;
    /** xapp- app-level token with connections:write (socket mode). */
    appToken: string;
    /** Channel id (C0123...) the bot posts approvals to (socket mode). */
    channelId: string;
    /** Optional comma-separated Slack user ids allowed to decide. Empty = anyone in the channel. */
    approverIds: string;
  };
  telegram: {
    enabled: boolean;
    /**
     * "polling": inline Approve / Reject buttons; the gateway long-polls getUpdates, so no
     *            public URL or tunnel is needed.
     * "links":   URL buttons that open the signed confirmation page (needs a Public URL).
     */
    mode: "polling" | "links";
    botToken: string;
    chatId: string;
    /** Optional comma-separated Telegram user ids allowed to decide. Empty = anyone in the chat. */
    approverIds: string;
  };
  webhook: { enabled: boolean; url: string; secret: string };
}

/** v1.1 settings stored in SQLite (system_settings). Edited from the No-Code Setup tab. */
export interface GatewaySettings {
  /** Port the standalone proxy (`agent-gateway-sdk start`) listens on. Applied on the next start. */
  listenPort: number | null;
  /**
   * Public base URL that reaches the gateway's public listener (e.g. a tunnel URL).
   * Needed to put signed Approve / Reject links in phone notifications.
   */
  publicBaseUrl: string;
  notifications: NotificationSettings;
  rollback: { url: string; secret: string };
  /** Toggles for the PII scrubber. Secrets, auth headers and card numbers are always redacted. */
  privacy: PrivacySettings;
  /** IANA time zone for business hours and the daily digest, e.g. "America/New_York". */
  timezone: string;
  schedule: ScheduleSettings;
  alerts: AlertSettings;
  /** Outbound exfiltration breaker for upstream responses (see responseGuard.ts). */
  responseGuard: ResponseGuardSettings;
}

export interface ResponseGuardSettings {
  /** Off by default: turning it on can change what agents receive. */
  enabled: boolean;
  /** Any JSON array longer than this is a "bulk dump" (e.g. 1,000 customer rows). */
  maxArrayItems: number;
  /** "block": 502 Response Policy Violation. "truncate": cut the array to maxArrayItems. */
  onLargeArray: "block" | "truncate";
  /** "scrub": mask secrets / card numbers in-flight. "block": 502 Response Policy Violation. */
  onSecret: "scrub" | "block";
}

export interface PrivacySettings {
  /** Mask email addresses (j***@example.com) in stored payloads, logs and notifications. */
  redactEmails: boolean;
  /** Mask phone numbers in stored payloads, logs and notifications. */
  redactPhones: boolean;
}

export interface GatewayConfig {
  targetUrl: string;
  rateLimitPerMinute: number;
  /** When true, /api/* requests need a valid agent key (x-agent-key or Bearer agk_...). */
  requireAgentApiKey: boolean;
  ssoTrustProxyHeader: boolean;
  /**
   * Secret your identity proxy must send in `x-gateway-sso-secret`. Generated
   * automatically (32 random bytes, hex) when SSO header trust is enabled.
   * Never sent to viewers.
   */
  ssoSharedSecret: string;
  ssoUserHeader: string;
  ssoRoleHeader: string;
}

export interface AuthUser {
  id: number;
  username: string;
  role: UserRole;
  mustChangePassword: boolean;
  sso?: boolean;
}

export interface AgentGatewayOptions {
  /**
   * The port your app listens on. Used to stop targetUrl from pointing back at
   * the gateway, and to replay approved requests into your own app when no
   * targetUrl is set. Default: 3000.
   */
  port?: number;
  /** Where rules are stored. Default: ./rules.json in the working directory. */
  rulesPath?: string;
  /** Where config is stored. Default: ./config.json in the working directory. */
  configPath?: string;
  /** SQLite database file. Default: ./logs.db in the working directory. */
  dbPath?: string;
  /**
   * Optional static Admin token for CI/CD scripts or headless automation.
   * Default: ADMIN_TOKEN env var, then "adminToken" in config.json.
   */
  adminToken?: string;
  /**
   * Optional static Viewer token for read-only headless automation.
   * Default: VIEWER_TOKEN env var, then "viewerToken" in config.json.
   */
  viewerToken?: string;
  /**
   * First-boot setup key. While no users exist, the owner account can be
   * created from localhost without it, but from any other address the request
   * must carry this value as `setupToken`. Default: SETUP_TOKEN env var, else
   * a random key printed in the startup banner.
   */
  setupToken?: string;
  /**
   * Run the admin API and dashboard on a separate listener (your server.ts
   * creates it from `gateway.adminListener`). Default: ADMIN_PORT env var.
   */
  adminPort?: number;
  /** Bind address for the admin listener. Default: ADMIN_HOST env var, else 127.0.0.1. */
  adminHost?: string;
  /**
   * Longest time the interceptor waits for one SQLite operation (lock waits included)
   * before it fails the request closed with 503. Default: 4000 ms.
   */
  dbOperationTimeoutMs?: number;
  /** Telegram Bot API base URL (a self-hosted Bot API server, or a test double). Default: https://api.telegram.org */
  telegramApiBase?: string;
  /** Slack Web API base URL (test doubles). Default: https://slack.com/api */
  slackApiBase?: string;
  /** Telegram getUpdates long-poll timeout in seconds (0 = short polling). Default: 25. */
  telegramPollTimeoutSec?: number;
  /** How often security alerts / the digest schedule are checked. Default: 60000 ms. */
  alertCheckIntervalMs?: number;
  /** How often the emergency mode is re-read from SQLite (other processes may change it). Default: 2000 ms. */
  emergencyRefreshMs?: number;
  /**
   * Mont license key supplied by the host application (e.g. from a secret manager).
   * Takes precedence over MONT_LICENSE_KEY and a key activated in the dashboard.
   */
  licenseKey?: string;
  /** Machine install anchor used by the trial clock. Default: ~/.montweel/anchor.json */
  licenseAnchorFile?: string;
  /** How often workspaces (rules, modes, keys) are re-read from SQLite for other processes' changes. Default: 2000 ms. */
  workspaceRefreshMs?: number;
}

export interface AgentGateway {
  /** The interceptor. Mount it on "/api". */
  agentGateway: RequestHandler;
  /** The admin API. Mount it on "/api/agent-admin", BEFORE the gateway. */
  adminRouter: Router;
  /** Serves GET /.well-known/agent.json. Mount it at the root. */
  discoveryRouter: Router;
  /**
   * Signed one-click Approve / Reject links from phone notifications
   * (GET/POST /_mont/approvals/:id/confirm). Mount it at the root of the PUBLIC listener.
   */
  approvalCallbackRouter: Router;
  /** Guard for MCP tools/call messages (used by mcpProxy.ts; usable by custom transports). */
  mcp: import("./toolGuard").McpGuard;
  /** Resolves once the database is ready (and migrated). Await it before listening. */
  ready: Promise<void>;
  /** Where the admin listener should bind, or null to serve the admin API on the public port. */
  adminListener: { port: number; host: string } | null;
  /** Stops background timers and closes the database. */
  close: () => Promise<void>;
}

// =====================================================================
// Internal types
// =====================================================================
export type LogStatus =
  | "ALLOWED"
  | "BLOCKED"
  | "QUEUED"
  | "RATE_LIMITED"
  | "APPROVED"
  | "REJECTED"
  /** The request ran, but its upstream response was withheld (502 Response Policy Violation). */
  | "RESPONSE_BLOCKED"
  /** The request ran; secrets were masked / bulk arrays truncated in the response. */
  | "RESPONSE_SCRUBBED";

export const LOG_STATUSES: LogStatus[] = ["ALLOWED", "BLOCKED", "QUEUED", "RATE_LIMITED", "APPROVED", "REJECTED", "RESPONSE_BLOCKED", "RESPONSE_SCRUBBED"];

export type PendingStatus = "PENDING" | "EXECUTING" | "APPROVED" | "REJECTED" | "FAILED" | "EXPIRED";

export interface PendingRow {
  id: number;
  timestamp: string;
  method: string;
  path: string;
  headers: string | null;
  body: string | null;
  status: PendingStatus;
  response_preview: string | null;
  decided_by: string | null;
  expires_at: number | null;
  agent_key: string | null;
  /** AES-256-GCM "iv:tag:ciphertext" of the unredacted request. NULL once decided. Never sent to clients. */
  encrypted_payload: string | null;
  /** Redacted query parameters as a JSON object. */
  query_json: string | null;
  /** Client IP bucket (IPv4, or the IPv6 /64) the request came from. */
  caller_ip: string | null;
  caller_ua: string | null;
  agent_key_id: number | null;
  agent_key_prefix: string | null;
  /** Free-text justification the agent sent in x-agent-reason. */
  agent_reason: string | null;
  /** Which policy tier (or the base rule) put this request in the queue. */
  matched_policy: string | null;
  revoked_at: string | null;
  revoked_by: string | null;
  rollback_status: string | null;
  /** "http" (replayed on approval) or "mcp" (held open by the MCP proxy and released on approval). */
  kind: string | null;
  /** "<hostname>:<pid>:<nonce>" of the process holding an MCP call open. */
  owner: string | null;
  /** Workspace (client) the request belongs to. NULL on rows from before v2 (= default workspace). */
  workspace_id: number | null;
  /** Redacted JSON of the body the approver edited ("Edit & Approve"), or NULL. */
  modified_body: string | null;
  /** Redacted JSON of the query the approver edited, or NULL. */
  modified_query: string | null;
  /** AES-256-GCM copy of the approver's edited payload, for the process that executes it. Wiped once decided. */
  patch_encrypted: string | null;
}

export interface BlockedCallerRow {
  id: number;
  kind: "agent_key" | "ip";
  value: string;
  label: string | null;
  reason: string | null;
  source_action_id: number | null;
  created_by: string;
  created_at: string;
}

export interface UserRow {
  id: number;
  username: string;
  password_hash: string;
  role: UserRole;
  must_change_password: number;
  otp_expires_at: number | null;
  created_at: string;
}

export interface SessionLookupRow {
  token_hash: string;
  expires_at: number;
  id: number;
  username: string;
  role: UserRole;
  must_change_password: number;
}

export interface AgentKeyRow {
  id: number;
  name: string;
  key_prefix: string;
  key_hash: string;
  created_at: string;
  last_used_at: string | null;
}

export interface AuthenticatedRequest extends Request {
  user?: AuthUser;
  sessionTokenHash?: string;
}
