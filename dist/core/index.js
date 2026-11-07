"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.inspectMcpResult = exports.inspectResponseBody = exports.GENESIS_HASH = exports.computeRowHash = exports.featuresFor = exports.signLicenseV2 = exports.verifyLicenseKey = exports.applyPreset = exports.POLICY_PRESETS = exports.createRedactor = exports.readPersistedListenPort = exports.signWebhookBody = exports.validatePolicies = exports.evaluateRule = void 0;
exports.createAgentGateway = createAgentGateway;
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
const crypto_1 = __importDefault(require("crypto"));
const path_1 = __importDefault(require("path"));
const constants_1 = require("./constants");
const settingsStore_1 = require("./settingsStore");
const callerBlocklist_1 = require("./callerBlocklist");
const notify_1 = require("./notify");
const approvals_1 = require("./approvals");
const approvalCallback_1 = require("./approvalCallback");
const notify_2 = require("./notify");
const redactor_1 = require("./redactor");
const instance_1 = require("./instance");
const toolGuard_1 = require("./toolGuard");
const guards_1 = require("./guards");
const operatingMode_1 = require("./operatingMode");
const alerts_1 = require("./alerts");
const protection_1 = require("./protection");
const crypto_2 = require("./crypto");
const agentKeys_1 = require("./agentKeys");
const userCount_1 = require("./userCount");
const auth_1 = require("./auth");
const config_1 = require("./config");
const db_1 = require("./db");
const license_1 = require("./license");
const rateLimit_1 = require("./rateLimit");
const rules_1 = require("./rules");
const interceptor_1 = require("./interceptor");
const adminRouter_1 = require("./adminRouter");
const discovery_1 = require("./discovery");
const workspaces_1 = require("./workspaces");
const auditLedger_1 = require("./auditLedger");
var policy_1 = require("./policy");
Object.defineProperty(exports, "evaluateRule", { enumerable: true, get: function () { return policy_1.evaluateRule; } });
Object.defineProperty(exports, "validatePolicies", { enumerable: true, get: function () { return policy_1.validatePolicies; } });
var notify_3 = require("./notify");
Object.defineProperty(exports, "signWebhookBody", { enumerable: true, get: function () { return notify_3.signWebhookBody; } });
var settingsStore_2 = require("./settingsStore");
Object.defineProperty(exports, "readPersistedListenPort", { enumerable: true, get: function () { return settingsStore_2.readPersistedListenPort; } });
var redactor_2 = require("./redactor");
Object.defineProperty(exports, "createRedactor", { enumerable: true, get: function () { return redactor_2.createRedactor; } });
var presets_1 = require("./presets");
Object.defineProperty(exports, "POLICY_PRESETS", { enumerable: true, get: function () { return presets_1.POLICY_PRESETS; } });
Object.defineProperty(exports, "applyPreset", { enumerable: true, get: function () { return presets_1.applyPreset; } });
var license_2 = require("./license");
Object.defineProperty(exports, "verifyLicenseKey", { enumerable: true, get: function () { return license_2.verifyLicenseKey; } });
Object.defineProperty(exports, "signLicenseV2", { enumerable: true, get: function () { return license_2.signLicenseV2; } });
Object.defineProperty(exports, "featuresFor", { enumerable: true, get: function () { return license_2.featuresFor; } });
var auditLedger_2 = require("./auditLedger");
Object.defineProperty(exports, "computeRowHash", { enumerable: true, get: function () { return auditLedger_2.computeRowHash; } });
Object.defineProperty(exports, "GENESIS_HASH", { enumerable: true, get: function () { return auditLedger_2.GENESIS_HASH; } });
var responseGuard_1 = require("./responseGuard");
Object.defineProperty(exports, "inspectResponseBody", { enumerable: true, get: function () { return responseGuard_1.inspectResponseBody; } });
Object.defineProperty(exports, "inspectMcpResult", { enumerable: true, get: function () { return responseGuard_1.inspectMcpResult; } });
function createAgentGateway(options = {}) {
    const port = options.port ?? 3000;
    const rulesPath = options.rulesPath ?? path_1.default.resolve(process.cwd(), "rules.json");
    const configPath = options.configPath ?? path_1.default.resolve(process.cwd(), "config.json");
    const dbPath = options.dbPath ?? path_1.default.resolve(process.cwd(), "logs.db");
    const db = (0, db_1.createDatabase)(dbPath);
    const config = (0, config_1.createConfigStore)(configPath, options);
    const rules = (0, rules_1.createRulesStore)(rulesPath);
    const limiters = (0, rateLimit_1.createLimiters)();
    const userCount = (0, userCount_1.createUserCountCache)(db);
    const license = (0, license_1.createLicenseService)(db, {
        licenseFile: path_1.default.join(path_1.default.dirname(dbPath), "mont-state.json"),
        anchorFile: options.licenseAnchorFile,
        licenseKey: options.licenseKey,
    });
    const workspaces = (0, workspaces_1.createWorkspaceStore)(db, rules, typeof options.workspaceRefreshMs === "number" && options.workspaceRefreshMs >= 50 ? options.workspaceRefreshMs : 2000);
    const ledger = (0, auditLedger_1.createAuditLedger)(db);
    const auth = (0, auth_1.createAuthService)(db, config, userCount, limiters, license);
    const agentKeys = (0, agentKeys_1.createAgentKeyStore)(db);
    const settings = (0, settingsStore_1.createSettingsStore)(db);
    const blocklist = (0, callerBlocklist_1.createCallerBlocklist)(db);
    const redactor = (0, redactor_1.createRedactor)(() => settings.privacy());
    const endpoints = {
        telegramApiBase: (options.telegramApiBase ?? "https://api.telegram.org").replace(/\/+$/, ""),
        slackApiBase: (options.slackApiBase ?? "https://slack.com/api").replace(/\/+$/, ""),
        telegramPollTimeoutSec: typeof options.telegramPollTimeoutSec === "number" && options.telegramPollTimeoutSec >= 0 ? Math.min(50, options.telegramPollTimeoutSec) : 25,
    };
    const notifier = (0, notify_1.createNotifier)(settings, redactor, endpoints, () => license.current().features);
    const instanceId = (0, instance_1.newInstanceId)();
    const emergency = (0, operatingMode_1.createEmergencyStore)(db, typeof options.emergencyRefreshMs === "number" && options.emergencyRefreshMs >= 50 ? options.emergencyRefreshMs : 2000);
    const alertIntervalMs = typeof options.alertCheckIntervalMs === "number" && options.alertCheckIntervalMs >= 50 ? options.alertCheckIntervalMs : 60000;
    const setup = { token: undefined };
    const dbTimeoutMs = typeof options.dbOperationTimeoutMs === "number" && options.dbOperationTimeoutMs > 0
        ? options.dbOperationTimeoutMs
        : constants_1.DB_OPERATION_TIMEOUT_MS;
    // Optional dedicated admin listener (the host app binds it; see server.ts).
    const envAdminPort = Number(process.env.ADMIN_PORT);
    const adminPort = options.adminPort ?? (Number.isInteger(envAdminPort) && envAdminPort > 0 ? envAdminPort : undefined);
    const adminListener = adminPort
        ? { port: adminPort, host: options.adminHost ?? (process.env.ADMIN_HOST || "127.0.0.1") }
        : null;
    async function initialise() {
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
        await (0, instance_1.reapOrphanedMcp)(db, instanceId);
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
            setup.token = fromEnv && fromEnv.trim() !== "" ? fromEnv.trim() : `setup_${(0, crypto_2.randomBase62)(16)}`;
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
    const ready = initialise();
    ready.catch(() => undefined);
    const ctx = {
        port,
        replaySecret: crypto_1.default.randomBytes(32).toString("hex"),
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
    };
    ctx.approvals = (0, approvals_1.createApprovalService)(ctx);
    ctx.bridges = (0, notify_2.createApprovalBridges)(ctx, endpoints);
    ctx.guards = (0, guards_1.createGuards)(ctx);
    ctx.alerts = (0, alerts_1.createAlerts)(ctx, alertIntervalMs);
    settings.onChange(() => ctx.bridges.kick());
    emergency.onChange((state, previous) => {
        console.log(`[agent-gateway] Emergency mode: ${previous.mode} -> ${state.mode}${state.changedBy ? ` (by ${state.changedBy})` : ""}`);
        // "!" key = send exactly once per change, across all processes.
        ctx.alerts.event("emergency", `!${state.changedAt ?? Date.now()}`, `Gateway mode changed: ${(0, protection_1.modeLabel)(state.mode)}`, [
            `By ${state.changedBy ?? "unknown"}${state.reason ? `: ${state.reason}` : ""}`,
            state.mode === "normal" ? "Agent traffic is flowing under your normal rules again." : "Send /resume (Telegram) or use the dashboard to return to normal.",
        ]);
    });
    workspaces.onModeChange((ws, previous) => {
        console.log(`[agent-gateway] Workspace "${ws.slug}" mode: ${previous} -> ${ws.mode}${ws.modeChangedBy ? ` (by ${ws.modeChangedBy})` : ""}`);
        ctx.alerts.event("emergency", `!ws:${ws.id}:${ws.modeChangedAt ?? Date.now()}`, `[${ws.name}] mode changed: ${(0, protection_1.modeLabel)(ws.mode)}`, [
            `By ${ws.modeChangedBy ?? "unknown"}${ws.modeReason ? `: ${ws.modeReason}` : ""}`,
            ws.mode === "normal" ? `${ws.name}'s agents are running under their normal rules again.` : `Only ${ws.name} is affected; other clients are unchanged.`,
        ]);
    });
    // Background workers start once the database is ready (Telegram / Slack idle until configured).
    let closed = false;
    ready.then(() => {
        if (closed)
            return;
        ctx.bridges.start();
        emergency.start();
        ctx.alerts.start();
        workspaces.start();
        license.start();
        ledger.start(1000);
        ledger.kick(); // seal anything written before this start (e.g. a v1.x database)
    }, () => undefined);
    const mcp = (0, toolGuard_1.createMcpGuard)(ctx);
    // Periodic cleanup of limiter maps and expired sessions.
    const cleanupTimer = setInterval(() => {
        limiters.sweep();
        const now = Date.now();
        const quiet = (err) => console.error("Cleanup error:", err);
        void db.run("DELETE FROM sessions WHERE expires_at <= ?", [now]).catch(quiet);
        // Keep only the newest MAX_LOG_ROWS audit rows, through the ledger's retention checkpoint so
        // the hash chain still verifies after old rows are removed.
        void ledger.prune(constants_1.MAX_LOG_ROWS).catch(quiet);
        void db
            .run(`UPDATE pending_actions SET status = 'EXPIRED', encrypted_payload = NULL, patch_encrypted = NULL
         WHERE status IN ('PENDING', 'FAILED') AND expires_at IS NOT NULL AND expires_at <= ?`, [now])
            .catch(quiet);
        // Budget / duplicate ledger: the longest window is 30 days.
        void db.run("DELETE FROM guard_ledger WHERE ts < ?", [now - 31 * 24 * 3600000]).catch(quiet);
        // Decided/expired approvals hold request bodies: keep only the newest N so the table cannot grow forever.
        void db
            .run(`DELETE FROM pending_actions
         WHERE status NOT IN ('PENDING', 'EXECUTING', 'FAILED')
           AND id <= (SELECT id FROM pending_actions
                      WHERE status NOT IN ('PENDING', 'EXECUTING', 'FAILED')
                      ORDER BY id DESC LIMIT 1 OFFSET ?)`, [constants_1.MAX_DECIDED_PENDING_ROWS])
            .catch(quiet);
    }, constants_1.RATE_WINDOW_MS);
    cleanupTimer.unref();
    return {
        agentGateway: (0, interceptor_1.createInterceptor)(ctx),
        adminRouter: (0, adminRouter_1.createAdminRouter)(ctx),
        discoveryRouter: (0, discovery_1.createDiscoveryRouter)(ctx),
        approvalCallbackRouter: (0, approvalCallback_1.createApprovalCallbackRouter)(ctx),
        mcp,
        adminListener,
        ready,
        close: async () => {
            if (closed)
                return db.close();
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
