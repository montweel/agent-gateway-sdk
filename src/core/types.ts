import type { Request, RequestHandler, Router } from "express";

// =====================================================================
// Public types
// =====================================================================
export type RuleMode = "ALLOW" | "BLOCK" | "REQUIRE_APPROVAL";
export type UserRole = "admin" | "viewer";

export interface Rule {
  mode: RuleMode;
  description: string;
  /** Max requests per minute per client IP for this rule. null/undefined = use the global limit. */
  rateLimit?: number | null;
}
export type Rules = Record<string, Rule>;

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
}

export interface AgentGateway {
  /** The interceptor. Mount it on "/api". */
  agentGateway: RequestHandler;
  /** The admin API. Mount it on "/api/agent-admin", BEFORE the gateway. */
  adminRouter: Router;
  /** Serves GET /.well-known/agent.json. Mount it at the root. */
  discoveryRouter: Router;
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
export type LogStatus = "ALLOWED" | "BLOCKED" | "QUEUED" | "RATE_LIMITED" | "APPROVED" | "REJECTED";

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
