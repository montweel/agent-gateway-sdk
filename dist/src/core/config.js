"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createConfigStore = createConfigStore;
const constants_1 = require("./constants");
const crypto_1 = require("./crypto");
const fileCache_1 = require("./fileCache");
const utils_1 = require("./utils");
function cleanHeaderName(value, fallback) {
    if (typeof value !== "string")
        return fallback;
    const v = value.trim().toLowerCase();
    return constants_1.HEADER_NAME_REGEX.test(v) ? v : fallback;
}
const newSecret = () => (0, crypto_1.randomHex)(32);
const validSecret = (v) => typeof v === "string" && v.length >= 32;
function createConfigStore(configPath, options) {
    const cache = (0, fileCache_1.createFileCache)(configPath, (text) => {
        if (text === null)
            return { raw: {}, parseError: false };
        try {
            const parsed = JSON.parse(text);
            if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
                return { raw: {}, parseError: true };
            }
            return { raw: parsed, parseError: false };
        }
        catch (err) {
            console.error("Could not parse config.json:", err);
            return { raw: {}, parseError: true };
        }
    });
    // Used only if the generated secret cannot be written to disk.
    let memorySecret;
    function persist(merged) {
        (0, utils_1.writeJsonAtomic)(configPath, merged);
        cache.invalidate();
    }
    function load() {
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
                }
                catch (err) {
                    console.error("Could not save the generated SSO shared secret:", err);
                    memorySecret = secret;
                }
            }
            else {
                memorySecret = secret;
            }
        }
        return {
            targetUrl: typeof raw.targetUrl === "string" ? raw.targetUrl.trim().replace(/\/+$/, "") : "",
            rateLimitPerMinute: typeof raw.rateLimitPerMinute === "number" &&
                Number.isInteger(raw.rateLimitPerMinute) &&
                raw.rateLimitPerMinute > 0
                ? raw.rateLimitPerMinute
                : constants_1.DEFAULT_CONFIG.rateLimitPerMinute,
            requireAgentApiKey: raw.requireAgentApiKey === true,
            ssoTrustProxyHeader: trust,
            ssoSharedSecret: secret,
            ssoUserHeader: cleanHeaderName(raw.ssoUserHeader, constants_1.DEFAULT_CONFIG.ssoUserHeader),
            ssoRoleHeader: cleanHeaderName(raw.ssoRoleHeader, constants_1.DEFAULT_CONFIG.ssoRoleHeader),
        };
    }
    function save(config) {
        const { raw } = cache.get();
        const secret = config.ssoTrustProxyHeader && !validSecret(config.ssoSharedSecret) ? newSecret() : config.ssoSharedSecret;
        const merged = {
            ...raw,
            targetUrl: config.targetUrl,
            rateLimitPerMinute: config.rateLimitPerMinute,
            requireAgentApiKey: config.requireAgentApiKey,
            ssoTrustProxyHeader: config.ssoTrustProxyHeader,
            ssoUserHeader: config.ssoUserHeader,
            ssoRoleHeader: config.ssoRoleHeader,
        };
        if (secret)
            merged.ssoSharedSecret = secret;
        persist(merged);
        memorySecret = undefined;
    }
    let memoryReplayKey;
    const validKey = (v) => typeof v === "string" && /^[0-9a-f]{64}$/i.test(v);
    function replayEncryptionKey() {
        const { raw, parseError } = cache.get();
        if (validKey(raw.replayEncryptionKey))
            return raw.replayEncryptionKey;
        if (memoryReplayKey)
            return memoryReplayKey;
        const key = newSecret(); // 32 random bytes as hex
        if (parseError) {
            // Never overwrite a config file we could not read. Keep the key in memory
            // (queued requests will not survive a restart, which is the safe failure).
            memoryReplayKey = key;
            return key;
        }
        try {
            persist({ ...raw, replayEncryptionKey: key });
        }
        catch (err) {
            console.error("Could not save the replay encryption key:", err);
            memoryReplayKey = key;
        }
        return key;
    }
    function rotateSsoSharedSecret() {
        const { raw } = cache.get();
        const secret = newSecret();
        persist({ ...raw, ssoSharedSecret: secret });
        return secret;
    }
    function resolveStaticTokens() {
        const { raw, parseError } = cache.get();
        const cfgAdmin = typeof raw.adminToken === "string" && raw.adminToken.trim() !== "" ? raw.adminToken.trim() : undefined;
        const cfgViewer = typeof raw.viewerToken === "string" && raw.viewerToken.trim() !== "" ? raw.viewerToken.trim() : undefined;
        return {
            adminToken: options.adminToken ?? process.env.ADMIN_TOKEN ?? cfgAdmin,
            viewerToken: options.viewerToken ?? process.env.VIEWER_TOKEN ?? cfgViewer,
            configCorrupted: parseError,
        };
    }
    return { load, save, rotateSsoSharedSecret, replayEncryptionKey, resolveStaticTokens };
}
