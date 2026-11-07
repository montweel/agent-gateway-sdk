import type { AgentKeyStore } from "./agentKeys";
import type { ApprovalService } from "./approvals";
import type { AuthService } from "./auth";
import type { CallerBlocklist } from "./callerBlocklist";
import type { ConfigStore } from "./config";
import type { Db } from "./db";
import type { LicenseService } from "./license";
import type { ApprovalBridges, Notifier } from "./notify";
import type { Limiters } from "./rateLimit";
import type { RulesStore } from "./rules";
import type { SettingsStore } from "./settingsStore";
import type { UserCountCache } from "./userCount";
import type { Redactor } from "./redactor";
import type { McpWaiter } from "./toolGuard";
import type { Guards } from "./guards";
import type { EmergencyStore } from "./operatingMode";
import type { Alerts } from "./alerts";
import type { WorkspaceStore } from "./workspaces";
import type { AuditLedger } from "./auditLedger";

/** First-boot owner creation key. Lives in memory only; cleared once an owner exists. */
export interface SetupState {
  token: string | undefined;
}

/** Everything the middleware and admin routes share. Built once in createAgentGateway. */
export interface GatewayContext {
  port: number;
  /** Random per-instance secret that marks an internal replay of an approved request. */
  replaySecret: string;
  ready: Promise<void>;
  /** Longest wait for one SQLite operation on the request path before failing closed. */
  dbTimeoutMs: number;
  db: Db;
  config: ConfigStore;
  /** rules.json: the default workspace's rules. Other workspaces' rules live in SQLite (ctx.workspaces). */
  rules: RulesStore;
  limiters: Limiters;
  auth: AuthService;
  agentKeys: AgentKeyStore;
  license: LicenseService;
  userCount: UserCountCache;
  setup: SetupState;
  /** v1.1 settings stored in SQLite (listen port, public URL, notification channels, rollback webhook). */
  settings: SettingsStore;
  /** Persistent kill-switch list of agent keys / IPs. */
  blocklist: CallerBlocklist;
  notifier: Notifier;
  approvals: ApprovalService;
  /** PII & secret scrubber applied before anything is stored or sent out. */
  redactor: Redactor;
  /** MCP tool calls currently held open waiting for a decision (action id -> waiter). */
  mcpWaiters: Map<number, McpWaiter>;
  /** "<hostname>:<pid>:<nonce>": identifies this process as the owner of held MCP calls and worker leases. */
  instanceId: string;
  /** Outbound Telegram long-poll / Slack Socket Mode workers. */
  bridges: ApprovalBridges;
  /** Spending budgets and duplicate-action protection. */
  guards: Guards;
  /** Lockdown / approval-only switch (shared through SQLite). */
  emergency: EmergencyStore;
  /** Security alerts and the daily digest. */
  alerts: Alerts;
  /** v2.0 multi-tenant workspaces (client stores). */
  workspaces: WorkspaceStore;
  /** v2.0 hash-chained, tamper-evident audit ledger over agent_logs. */
  ledger: AuditLedger;
}
