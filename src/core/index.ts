/**
 * agent-gateway-sdk: gateway core
 *
 * Module map:
 *   types.ts        public + internal types
 *   constants.ts    limits, header names, default config
 *   utils.ts        pure helpers (errors, paths, header sanitising, URL checks)
 *   crypto.ts       password hashing, constant-time compare, token generation
 *   fileCache.ts    mtime-checked in-memory cache for rules.json / config.json
 *   config.ts       config.json store + static tokens + SSO shared secret
 *   rules.ts        rules.json store
 *   userCount.ts    cached users count (first-boot detection)
 *   agentKeys.ts    agent API keys (hashed)
 *   license.ts      offline Ed25519 Mont Pro license check + 7-day trial
 *   db.ts           SQLite wrapper, schema, migrations
 *   rateLimit.ts    gateway rate limiter + login brute-force guard
 *   auth.ts         sessions, SSO header trust, RBAC middleware
 *   proxy.ts        forwards allowed requests to targetUrl
 *   interceptor.ts  the /api/* guard (rate limit -> key -> kill-switch -> rules/policies -> block/queue/allow)
 *   policy.ts       deterministic payload policy engine (body/query/headers tiers)
 *   approvals.ts    approval state machine, replay, revoke & block, rollback webhook
 *   approvalSigning.ts  HMAC-SHA256 one-click approval links
 *   approvalCallback.ts public confirm pages for those links
 *   notify.ts       Slack / Telegram / webhook notifications (native fetch)
 *   settingsStore.ts    v1.1 settings in SQLite (listen port, public URL, channels, rollback)
 *   callerBlocklist.ts  persistent kill-switch list of agent keys / IPs
 *   adminRouter.ts  admin API; handlers live in routes/*
 *   discovery.ts    GET /.well-known/agent.json
 *   workspaces.ts   v2.0 multi-tenant workspaces (client stores): rules, upstream, mode, routing, keys
 *   auditLedger.ts  v2.0 SHA-256 hash-chained, tamper-evident audit ledger
 *   simulator.ts    v2.0 policy time-machine (replay history through a ruleset)
 *   responseGuard.ts v2.0 outbound exfiltration breaker (bulk dumps, secrets in responses)
 *   payloadPatch.ts v2.0 Edit & Approve merge of approver edits into the original request
 */
import crypto from "crypto";
import path from "path";
import type { AgentGateway, AgentGatewayOptions } from "./types";
import type { GatewayContext, SetupState } from "./context";
import { DB_OPERATION_TIMEOUT_MS, MAX_DECIDED_PENDING_ROWS, MAX_LOG_ROWS, RATE_WINDOW_MS } from "./constants";
import { createSettingsStore } from "./settingsStore";
import { createCallerBlocklist } from "./callerBlocklist";
import { createNotifier } from "./notify";
import { createApprovalService } from "./approvals";
import { createApprovalCallbackRouter } from "./approvalCallback";
import { createApprovalBridges } from "./notify";
import { createRedactor } from "./redactor";
import { newInstanceId, reapOrphanedMcp } from "./instance";
import { createMcpGuard } from "./toolGuard";
import { createGuards } from "./guards";
import { createEmergencyStore } from "./operatingMode";
import { createAlerts } from "./alerts";
import { modeLabel } from "./protection";
import { randomBase62 } from "./crypto";
import { createAgentKeyStore } from "./agentKeys";
import { createUserCountCache } from "./userCount";
import { createAuthService } from "./auth";
import { createConfigStore } from "./config";
import { createDatabase } from "./db";
import { createLicenseService } from "./license";
import { createLimiters } from "./rateLimit";
import { createRulesStore } from "./rules";
import { createInterceptor } from "./interceptor";
import { createAdminRouter } from "./adminRouter";
import { createDiscoveryRouter } from "./discovery";
import { createWorkspaceStore } from "./workspaces";
import { createAuditLedger } from "./auditLedger";

export type {
  AgentGateway,
  AgentGatewayOptions,
  AuthUser,
  GatewayConfig,
  GatewaySettings,
  PolicyCondition,
  PolicyOperator,
  PolicyTier,
  Rule,
  RuleMode,
  Rules,
  UserRole,
} from "./types";
export { evaluateRule, validatePolicies } from "./policy";
export { signWebhookBody } from "./notify";
export { readPersistedListenPort } from "./settingsStore";
export { createRedactor } from "./redactor";
export type { Redactor } from "./redactor";
export { POLICY_PRESETS, applyPreset } from "./presets";
export type { McpGuard, GuardResult, WaitResult, ToolCallRequest, ExecuteOverride } from "./toolGuard";
export { verifyLicenseKey, signLicenseV2, featuresFor } from "./license";
export type { LicenseStatus, LicenseTier, LicenseFeatures } from "./license";
export { computeRowHash, GENESIS_HASH } from "./auditLedger";
export type { VerifyReport } from "./auditLedger";
export type { Workspace } from "./workspaces";
export type { SimulationReport } from "./simulator";
export { inspectResponseBody, inspectMcpResult } from "./responseGuard";

export function createAgentGateway(options: AgentGatewayOptions = {}): AgentGateway {
  const port = options.port ?? 3000;
  const rulesPath = options.rulesPath ?? path.resolve(process.cwd(), "rules.json");
  const configPath = options.configPath ?? path.resolve(process.cwd(), "config.json");
  const dbPath = options.dbPath ?? path.resolve(process.cwd(), "logs.db");

  const db = createDatabase(dbPath);
  const config = createConfigStore(configPath, options);
  const rules = createRulesStore(rulesPath);
  const limiters = createLimiters();
  const userCount = createUserCountCache(db);
  const license = createLicenseService(db, {
    licenseFile: path.join(path.dirname(dbPath), "mont-state.json"),
    anchorFile: options.licenseAnchorFile,
    licenseKey: options.licenseKey,
  });
  const workspaces = createWorkspaceStore(
    db,
    rules,
    typeof options.workspaceRefreshMs === "number" && options.workspaceRefreshMs >= 50 ? options.workspaceRefreshMs : 2_000
  );
  const ledger = createAuditLedger(db);
  const auth = createAuthService(db, config, userCount, limiters, license);
  const agentKeys = createAgentKeyStore(db);
  const settings = createSettingsStore(db);
  const blocklist = createCallerBlocklist(db);
  const redactor = createRedactor(() => settings.privacy());
  const endpoints = {
    telegramApiBase: (options.telegramApiBase ?? "https://api.telegram.org").replace(/\/+$/, ""),
    slackApiBase: (options.slackApiBase ?? "https://slack.com/api").replace(/\/+$/, ""),
    telegramPollTimeoutSec:
      typeof options.telegramPollTimeoutSec === "number" && options.telegramPollTimeoutSec >= 0 ? Math.min(50, options.telegramPollTimeoutSec) : 25,
  };
  const notifier = createNotifier(settings, redactor, endpoints, () => license.current().features);
  const instanceId = newInstanceId();
  const emergency = createEmergencyStore(
    db,
    typeof options.emergencyRefreshMs === "number" && options.emergencyRefreshMs >= 50 ? options.emergencyRefreshMs : 2_000
  );
  const alertIntervalMs = typeof options.alertCheckIntervalMs === "number" && options.alertCheckIntervalMs >= 50 ? options.alertCheckIntervalMs : 60_000;
  const setup: SetupState = { token: undefined };
  const dbTimeoutMs =
    typeof options.dbOperationTimeoutMs === "number" && options.dbOperationTimeoutMs > 0
      ? options.dbOperationTimeoutMs
      : DB_OPERATION_TIMEOUT_MS;

  // Optional dedicated admin listener (the host app binds it; see server.ts).
  const envAdminPort = Number(process.env.ADMIN_PORT);
  const adminPort =
    options.adminPort ?? (Number.isInteger(envAdminPort) && envAdminPort > 0 ? envAdminPort : undefined);
  const adminListener = adminPort
    ? { port: adminPort, host: options.adminHost ?? (process.env.ADMIN_HOST || "127.0.0.1") }
    : null;

  async function initialise(): Promise<void> {
    await db.init();
    // Restore trial start + license key from mont-state.json / ~/.montweel/anchor.json if logs.db was deleted.
    await license.restoreState();
    await license.refresh();
    // If either of these cannot be read, `ready` rejects and every /api/* request fails closed (503).
    await settings.load();
    await blocklist.load();
    await emergency.load();
    await workspaces.load();
    // Held MCP calls of processes that died can never run: expire them (live processes' calls are kept).
    await reapOrphanedMcp(db, instanceId);

    // Startup notices
    const usersTotal = await userCount.get();
    const { adminToken, viewerToken } = config.resolveStaticTokens();
    const cfg = config.load();
    const adminUrl = adminListener
      ? `http://${adminListener.host}:${adminListener.port}/agent-admin/`
      : `http://localhost:${port}/agent-admin/`;

    if (usersTotal === 0 && !adminToken && !viewerToken && !cfg.ssoTrustProxyHeader) {
      // First boot: whoever creates the owner account owns the gateway. From this
      // machine that is allowed freely; from anywhere else the setup key is required.
      const fromEnv = options.setupToken ?? process.env.SETUP_TOKEN;
      setup.token = fromEnv && fromEnv.trim() !== "" ? fromEnv.trim() : `setup_${randomBase62(16)}`;
      const lines = [
        "",
        "================================================================",
        "  agent-gateway: FIRST-BOOT SETUP",
        "  No admin account exists yet.",
        `  Open: ${adminUrl}`,
        fromEnv ? "  Setup key: the SETUP_TOKEN you configured" : `  Setup key: ${setup.token}`,
        "  Opening the dashboard from this machine needs no key; from any",
        "  other address, enter the setup key to create the owner account.",
        "================================================================",
        "",
      ];
      console.log(lines.join("\n"));
    }
    if (cfg.requireAgentApiKey) {
      console.log("[agent-gateway] Agent API keys are required for /api/* requests.");
    }
  }

  const ready: Promise<void> = initialise();
  ready.catch(() => undefined);

  const ctx = {
    port,
    replaySecret: crypto.randomBytes(32).toString("hex"),
    ready,
    dbTimeoutMs,
    db,
    config,
    rules,
    limiters,
    auth,
    agentKeys,
    license,
    userCount,
    setup,
    settings,
    blocklist,
    notifier,
    redactor,
    mcpWaiters: new Map(),
    instanceId,
    emergency,
    workspaces,
    ledger,
  } as Omit<GatewayContext, "approvals" | "bridges" | "guards" | "alerts"> as GatewayContext;
  ctx.approvals = createApprovalService(ctx);
  ctx.bridges = createApprovalBridges(ctx, endpoints);
  ctx.guards = createGuards(ctx);
  ctx.alerts = createAlerts(ctx, alertIntervalMs);
  settings.onChange(() => ctx.bridges.kick());
  emergency.onChange((state, previous) => {
    console.log(`[agent-gateway] Emergency mode: ${previous.mode} -> ${state.mode}${state.changedBy ? ` (by ${state.changedBy})` : ""}`);
    // "!" key = send exactly once per change, across all processes.
    ctx.alerts.event("emergency", `!${state.changedAt ?? Date.now()}`, `Gateway mode changed: ${modeLabel(state.mode)}`, [
      `By ${state.changedBy ?? "unknown"}${state.reason ? `: ${state.reason}` : ""}`,
      state.mode === "normal" ? "Agent traffic is flowing under your normal rules again." : "Send /resume (Telegram) or use the dashboard to return to normal.",
    ]);
  });
  workspaces.onModeChange((ws, previous) => {
    console.log(`[agent-gateway] Workspace "${ws.slug}" mode: ${previous} -> ${ws.mode}${ws.modeChangedBy ? ` (by ${ws.modeChangedBy})` : ""}`);
    ctx.alerts.event("emergency", `!ws:${ws.id}:${ws.modeChangedAt ?? Date.now()}`, `[${ws.name}] mode changed: ${modeLabel(ws.mode)}`, [
      `By ${ws.modeChangedBy ?? "unknown"}${ws.modeReason ? `: ${ws.modeReason}` : ""}`,
      ws.mode === "normal" ? `${ws.name}'s agents are running under their normal rules again.` : `Only ${ws.name} is affected; other clients are unchanged.`,
    ]);
  });
  // Background workers start once the database is ready (Telegram / Slack idle until configured).
  let closed = false;
  ready.then(
    () => {
      if (closed) return;
      ctx.bridges.start();
      emergency.start();
      ctx.alerts.start();
      workspaces.start();
      license.start();
      ledger.start(1_000);
      ledger.kick(); // seal anything written before this start (e.g. a v1.x database)
    },
    () => undefined
  );
  const mcp = createMcpGuard(ctx);

  // Periodic cleanup of limiter maps and expired sessions.
  const cleanupTimer = setInterval(() => {
    limiters.sweep();
    const now = Date.now();
    const quiet = (err: unknown): void => console.error("Cleanup error:", err);
    void db.run("DELETE FROM sessions WHERE expires_at <= ?", [now]).catch(quiet);
    // Keep only the newest MAX_LOG_ROWS audit rows, through the ledger's retention checkpoint so
    // the hash chain still verifies after old rows are removed.
    void ledger.prune(MAX_LOG_ROWS).catch(quiet);
    void db
      .run(
        `UPDATE pending_actions SET status = 'EXPIRED', encrypted_payload = NULL, patch_encrypted = NULL
         WHERE status IN ('PENDING', 'FAILED') AND expires_at IS NOT NULL AND expires_at <= ?`,
        [now]
      )
      .catch(quiet);
    // Budget / duplicate ledger: the longest window is 30 days.
    void db.run("DELETE FROM guard_ledger WHERE ts < ?", [now - 31 * 24 * 3600_000]).catch(quiet);
    // Decided/expired approvals hold request bodies: keep only the newest N so the table cannot grow forever.
    void db
      .run(
        `DELETE FROM pending_actions
         WHERE status NOT IN ('PENDING', 'EXECUTING', 'FAILED')
           AND id <= (SELECT id FROM pending_actions
                      WHERE status NOT IN ('PENDING', 'EXECUTING', 'FAILED')
                      ORDER BY id DESC LIMIT 1 OFFSET ?)`,
        [MAX_DECIDED_PENDING_ROWS]
      )
      .catch(quiet);
  }, RATE_WINDOW_MS);
  cleanupTimer.unref();

  return {
    agentGateway: createInterceptor(ctx),
    adminRouter: createAdminRouter(ctx),
    discoveryRouter: createDiscoveryRouter(ctx),
    approvalCallbackRouter: createApprovalCallbackRouter(ctx),
    mcp,
    adminListener,
    ready,
    close: async () => {
      if (closed) return db.close();
      closed = true;
      clearInterval(cleanupTimer);
      emergency.stop();
      ctx.alerts.stop();
      workspaces.stop();
      license.stop();
      await ctx.bridges.stop();
      // Held MCP calls die with this process: make sure they can never be approved later.
      for (const id of [...ctx.mcpWaiters.keys()]) {
        await db
          .run("UPDATE pending_actions SET status = 'EXPIRED', encrypted_payload = NULL, response_preview = ? WHERE id = ? AND status = 'PENDING'", [
            "Expired: the gateway shut down while this MCP tool call was waiting; it was never executed.",
            id,
          ])
          .catch(() => undefined);
      }
      ctx.mcpWaiters.clear();
      // Seal what this process wrote, then stop the sealer before the database closes.
      await ready.then(() => ledger.sealPending()).catch(() => undefined);
      ledger.stop();
      await db.close();
    },
  };
}
