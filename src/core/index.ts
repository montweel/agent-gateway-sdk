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
 *   interceptor.ts  the /api/* guard (rate limit -> rules -> block/queue/allow)
 *   adminRouter.ts  admin API; handlers live in routes/*
 *   discovery.ts    GET /.well-known/agent.json
 */
import crypto from "crypto";
import path from "path";
import type { AgentGateway, AgentGatewayOptions } from "./types";
import type { GatewayContext, SetupState } from "./context";
import { MAX_DECIDED_PENDING_ROWS, MAX_LOG_ROWS, RATE_WINDOW_MS } from "./constants";
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

export type {
  AgentGateway,
  AgentGatewayOptions,
  AuthUser,
  GatewayConfig,
  Rule,
  RuleMode,
  Rules,
  UserRole,
} from "./types";

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
  const license = createLicenseService(db, { licenseFile: path.join(path.dirname(dbPath), "mont-state.json") });
  const auth = createAuthService(db, config, userCount, limiters, license);
  const agentKeys = createAgentKeyStore(db);
  const setup: SetupState = { token: undefined };

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

  const ctx: GatewayContext = {
    port,
    replaySecret: crypto.randomBytes(32).toString("hex"),
    ready,
    db,
    config,
    rules,
    limiters,
    auth,
    agentKeys,
    license,
    userCount,
    setup,
  };

  // Periodic cleanup of limiter maps and expired sessions.
  const cleanupTimer = setInterval(() => {
    limiters.sweep();
    const now = Date.now();
    const quiet = (err: unknown): void => console.error("Cleanup error:", err);
    void db.run("DELETE FROM sessions WHERE expires_at <= ?", [now]).catch(quiet);
    // Keep only the newest MAX_LOG_ROWS audit rows.
    void db
      .run(
        `DELETE FROM agent_logs
         WHERE id <= (SELECT id FROM agent_logs ORDER BY id DESC LIMIT 1 OFFSET ?)`,
        [MAX_LOG_ROWS]
      )
      .catch(quiet);
    void db
      .run(
        `UPDATE pending_actions SET status = 'EXPIRED', encrypted_payload = NULL
         WHERE status IN ('PENDING', 'FAILED') AND expires_at IS NOT NULL AND expires_at <= ?`,
        [now]
      )
      .catch(quiet);
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
    adminListener,
    ready,
    close: () => {
      clearInterval(cleanupTimer);
      return db.close();
    },
  };
}
