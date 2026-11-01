import type { AgentKeyStore } from "./agentKeys";
import type { AuthService } from "./auth";
import type { ConfigStore } from "./config";
import type { Db } from "./db";
import type { LicenseService } from "./license";
import type { Limiters } from "./rateLimit";
import type { RulesStore } from "./rules";
import type { UserCountCache } from "./userCount";

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
  db: Db;
  config: ConfigStore;
  rules: RulesStore;
  limiters: Limiters;
  auth: AuthService;
  agentKeys: AgentKeyStore;
  license: LicenseService;
  userCount: UserCountCache;
  setup: SetupState;
}
