import type { AgentGatewayOptions, GatewayConfig } from "./types";
import { DEFAULT_CONFIG, HEADER_NAME_REGEX } from "./constants";
import { randomHex } from "./crypto";
import { createFileCache } from "./fileCache";
import { writeJsonAtomic } from "./utils";

interface RawConfigFile extends Partial<GatewayConfig> {
  adminToken?: unknown;
  viewerToken?: unknown;
  [key: string]: unknown;
}

interface ParsedConfig {
  raw: RawConfigFile;
  parseError: boolean;
}

export interface ConfigStore {
  /** Cached; re-read only when config.json changes on disk. Returns a fresh copy. */
  load(): GatewayConfig;
  /** Writes the gateway settings while preserving extra keys (adminToken/viewerToken). */
  save(config: GatewayConfig): void;
  /** A new random SSO shared secret, saved immediately. */
  rotateSsoSharedSecret(): string;
  /**
   * 32-byte hex key (AES-256-GCM) that encrypts queued requests until they are
   * decided. Created on first use and kept in config.json. It is not part of
   * GatewayConfig, so it can never be returned by GET /config.
   */
  replayEncryptionKey(): string;
  resolveStaticTokens(): {
    adminToken: string | undefined;
    viewerToken: string | undefined;
    configCorrupted: boolean;
  };
}

function cleanHeaderName(value: unknown, fallback: string): string {
  if (typeof value !== "string") return fallback;
  const v = value.trim().toLowerCase();
  return HEADER_NAME_REGEX.test(v) ? v : fallback;
}

const newSecret = (): string => randomHex(32);
const validSecret = (v: unknown): v is string => typeof v === "string" && v.length >= 32;

export function createConfigStore(configPath: string, options: AgentGatewayOptions): ConfigStore {
  const cache = createFileCache<ParsedConfig>(configPath, (text) => {
    if (text === null) return { raw: {}, parseError: false };
    try {
      const parsed: unknown = JSON.parse(text);
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
        return { raw: {}, parseError: true };
      }
      return { raw: parsed as RawConfigFile, parseError: false };
    } catch (err) {
      console.error("Could not parse config.json:", err);
      return { raw: {}, parseError: true };
    }
  });

  // Used only if the generated secret cannot be written to disk.
  let memorySecret: string | undefined;

  function persist(merged: RawConfigFile): void {
    writeJsonAtomic(configPath, merged);
    cache.invalidate();
  }

  function load(): GatewayConfig {
    const { raw, parseError } = cache.get();
    const trust = Boolean(raw.ssoTrustProxyHeader);

    let secret = validSecret(raw.ssoSharedSecret) ? raw.ssoSharedSecret : "";
    if (trust && !secret) {
      // SSO trust was switched on without a secret (or the file was edited by
      // hand): create one now so the headers are never trusted unauthenticated.
      secret = memorySecret ?? newSecret();
      if (!parseError) {
        try {
          persist({ ...raw, ssoSharedSecret: secret });
          memorySecret = undefined;
        } catch (err) {
          console.error("Could not save the generated SSO shared secret:", err);
          memorySecret = secret;
        }
      } else {
        memorySecret = secret;
      }
    }

    return {
      targetUrl: typeof raw.targetUrl === "string" ? raw.targetUrl.trim().replace(/\/+$/, "") : "",
      rateLimitPerMinute:
        typeof raw.rateLimitPerMinute === "number" &&
        Number.isInteger(raw.rateLimitPerMinute) &&
        raw.rateLimitPerMinute > 0
          ? raw.rateLimitPerMinute
          : DEFAULT_CONFIG.rateLimitPerMinute,
      requireAgentApiKey: raw.requireAgentApiKey === true,
      ssoTrustProxyHeader: trust,
      ssoSharedSecret: secret,
      ssoUserHeader: cleanHeaderName(raw.ssoUserHeader, DEFAULT_CONFIG.ssoUserHeader),
      ssoRoleHeader: cleanHeaderName(raw.ssoRoleHeader, DEFAULT_CONFIG.ssoRoleHeader),
    };
  }

  function save(config: GatewayConfig): void {
    const { raw } = cache.get();
    const secret = config.ssoTrustProxyHeader && !validSecret(config.ssoSharedSecret) ? newSecret() : config.ssoSharedSecret;
    const merged: RawConfigFile = {
      ...raw,
      targetUrl: config.targetUrl,
      rateLimitPerMinute: config.rateLimitPerMinute,
      requireAgentApiKey: config.requireAgentApiKey,
      ssoTrustProxyHeader: config.ssoTrustProxyHeader,
      ssoUserHeader: config.ssoUserHeader,
      ssoRoleHeader: config.ssoRoleHeader,
    };
    if (secret) merged.ssoSharedSecret = secret;
    persist(merged);
    memorySecret = undefined;
  }

  let memoryReplayKey: string | undefined;
  const validKey = (v: unknown): v is string => typeof v === "string" && /^[0-9a-f]{64}$/i.test(v);

  function replayEncryptionKey(): string {
    const { raw, parseError } = cache.get();
    if (validKey(raw.replayEncryptionKey)) return raw.replayEncryptionKey;
    if (memoryReplayKey) return memoryReplayKey;

    const key = newSecret(); // 32 random bytes as hex
    if (parseError) {
      // Never overwrite a config file we could not read. Keep the key in memory
      // (queued requests will not survive a restart, which is the safe failure).
      memoryReplayKey = key;
      return key;
    }
    try {
      persist({ ...raw, replayEncryptionKey: key });
    } catch (err) {
      console.error("Could not save the replay encryption key:", err);
      memoryReplayKey = key;
    }
    return key;
  }

  function rotateSsoSharedSecret(): string {
    const { raw } = cache.get();
    const secret = newSecret();
    persist({ ...raw, ssoSharedSecret: secret });
    return secret;
  }

  function resolveStaticTokens() {
    const { raw, parseError } = cache.get();
    const cfgAdmin =
      typeof raw.adminToken === "string" && raw.adminToken.trim() !== "" ? raw.adminToken.trim() : undefined;
    const cfgViewer =
      typeof raw.viewerToken === "string" && raw.viewerToken.trim() !== "" ? raw.viewerToken.trim() : undefined;

    return {
      adminToken: options.adminToken ?? process.env.ADMIN_TOKEN ?? cfgAdmin,
      viewerToken: options.viewerToken ?? process.env.VIEWER_TOKEN ?? cfgViewer,
      configCorrupted: parseError,
    };
  }

  return { load, save, rotateSsoSharedSecret, replayEncryptionKey, resolveStaticTokens };
}
