"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.MONT_LICENSE_PORTAL_URL = void 0;
exports.verifyLicenseKey = verifyLicenseKey;
exports.createLicenseService = createLicenseService;
const crypto_1 = __importDefault(require("crypto"));
const installAnchor_1 = require("./installAnchor");
/**
 * Offline Mont Pro licensing. A license is `MONT-<base64url payload>.<base64url signature>`:
 * an Ed25519 signature over the base64url payload string, checked against the embedded
 * public key. Nothing is ever sent over the network. Keys are minted with
 * scripts/license-tool.ts.
 *
 * Resolution order: a signed key (MONT_LICENSE_KEY env, else the stored one), then the
 * free 7-day trial that starts on first boot. Community Edition is the fallback and
 * only ever gates the extras listed in the admin routes, never the proxy itself.
 */
/** Public half of the signing key (base64url SPKI DER). MONT_PUBLIC_KEY overrides it for testing. */
const DEFAULT_PUBLIC_KEY = "MCowBQYDK2VwAyEAbZJnW0z-pj5aAkMlquawZNeLFjlBOo2C_g8Byy1-vVY";
exports.MONT_LICENSE_PORTAL_URL = process.env.MONT_LICENSE_PORTAL_URL || "https://getmont.dev/license";
const DAY_MS = 24 * 60 * 60 * 1000;
const TRIAL_MS = 7 * DAY_MS;
const LICENSE_PREFIX = "MONT-";
const SETTING_TRIAL_STARTED = "trial_started_at";
const SETTING_LICENSE_KEY = "license_key";
const KEY_EXPIRED_REASON = "Your 30-day Mont Pro key has expired. Renew for free on our website (no payment details needed).";
const TAMPERED_REASON = "Install records for this gateway were modified or copied from another machine, so the free trial is disabled. Enter a valid license key to use Pro features.";
const TRIAL_EXPIRED_REASON = "Your 7-day initial Pro trial has ended. Renew Pro freely for the next 3 months on our website â€” no payment details needed.";
let publicKeyCache;
function getPublicKey() {
    const raw = process.env.MONT_PUBLIC_KEY?.trim() || DEFAULT_PUBLIC_KEY;
    if (publicKeyCache?.raw !== raw) {
        publicKeyCache = {
            raw,
            key: crypto_1.default.createPublicKey({ key: Buffer.from(raw, "base64url"), format: "der", type: "spki" }),
        };
    }
    return publicKeyCache.key;
}
/** Checks format, signature and payload shape. Does NOT check expiry. */
function verifyLicenseKey(licenseKey) {
    const key = licenseKey.trim();
    const dot = key.indexOf(".");
    if (!key.startsWith(LICENSE_PREFIX) || dot < 0) {
        return { ok: false, reason: "That is not a Mont license key. It should look like MONT-<payload>.<signature>." };
    }
    const encoded = key.slice(LICENSE_PREFIX.length, dot);
    const signature = key.slice(dot + 1);
    if (!encoded || !signature)
        return { ok: false, reason: "The license key is incomplete." };
    try {
        const sigOk = crypto_1.default.verify(null, Buffer.from(encoded), getPublicKey(), Buffer.from(signature, "base64url"));
        if (!sigOk)
            return { ok: false, reason: "The license key signature is not valid." };
        const p = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
        if (p.tier !== "PRO" ||
            typeof p.org !== "string" ||
            typeof p.email !== "string" ||
            typeof p.iat !== "number" ||
            typeof p.exp !== "number") {
            return { ok: false, reason: "The license key payload is malformed." };
        }
        return { ok: true, payload: { org: p.org, email: p.email, tier: "PRO", iat: p.iat, exp: p.exp } };
    }
    catch {
        return { ok: false, reason: "The license key could not be read." };
    }
}
const daysLeft = (expMs, now) => Math.max(0, Math.ceil((expMs - now) / DAY_MS));
function createLicenseService(db, options) {
    const licenseFile = options.licenseFile;
    const anchorFile = options.anchorFile ?? (0, installAnchor_1.defaultAnchorPath)();
    async function getSetting(key) {
        return (await db.get("SELECT value FROM system_settings WHERE key = ?", [key]))?.value;
    }
    async function setSetting(key, value) {
        await db.run("INSERT INTO system_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", [key, value]);
    }
    /**
     * Reconciles logs.db, license.json and the machine anchor. Returns the earliest trusted
     * firstSeenAt, or tampered=true when either file fails its HMAC. Missing or stale copies
     * are rewritten from the earliest value; a tampered file is left as evidence.
     */
    async function syncInstallState(now) {
        const anchor = (0, installAnchor_1.readStateFile)(anchorFile);
        const lic = (0, installAnchor_1.readStateFile)(licenseFile);
        const dbRaw = Number(await getSetting(SETTING_TRIAL_STARTED));
        const times = [];
        if (anchor.state === "ok")
            times.push(anchor.firstSeenAt);
        if (lic.state === "ok")
            times.push(lic.firstSeenAt);
        if (Number.isFinite(dbRaw) && dbRaw > 0)
            times.push(dbRaw);
        const firstSeenAt = times.length ? Math.min(...times) : now;
        const tampered = anchor.state === "tampered" || lic.state === "tampered";
        const dbKey = await getSetting(SETTING_LICENSE_KEY);
        const fileKey = lic.state === "ok" ? lic.licenseKey : undefined;
        const licenseKey = dbKey ?? fileKey;
        if (dbRaw !== firstSeenAt)
            await setSetting(SETTING_TRIAL_STARTED, String(firstSeenAt));
        if (!dbKey && fileKey)
            await setSetting(SETTING_LICENSE_KEY, fileKey);
        if (anchor.state === "missing" || (anchor.state === "ok" && anchor.firstSeenAt !== firstSeenAt)) {
            (0, installAnchor_1.writeStateFile)(anchorFile, { firstSeenAt });
        }
        if (lic.state === "missing" || (lic.state === "ok" && (lic.firstSeenAt !== firstSeenAt || lic.licenseKey !== licenseKey))) {
            (0, installAnchor_1.writeStateFile)(licenseFile, { firstSeenAt, licenseKey });
        }
        return { tampered, firstSeenAt };
    }
    function statusFromKey(licenseKey, source, now) {
        const result = verifyLicenseKey(licenseKey);
        if (!result.ok)
            return undefined; // a bad or tampered key never grants anything
        const { payload } = result;
        const active = now < payload.exp;
        return {
            valid: active,
            expired: !active,
            isTrial: false,
            tier: active ? "PRO" : "COMMUNITY",
            org: payload.org,
            email: payload.email,
            issuedAt: new Date(payload.iat).toISOString(),
            expiresAt: new Date(payload.exp).toISOString(),
            daysRemaining: active ? daysLeft(payload.exp, now) : 0,
            source,
            reason: active ? undefined : KEY_EXPIRED_REASON,
            renewalUrl: exports.MONT_LICENSE_PORTAL_URL,
        };
    }
    async function resolveLicenseStatus() {
        const now = Date.now();
        const install = await syncInstallState(now);
        // Priority 1: a signed key. An active one wins; otherwise report the expired one.
        const candidates = [
            { key: process.env.MONT_LICENSE_KEY?.trim(), source: "ENV" },
            { key: await getSetting(SETTING_LICENSE_KEY), source: "DB" },
        ];
        let expiredKey;
        for (const { key, source } of candidates) {
            if (!key)
                continue;
            const status = statusFromKey(key, source, now);
            if (!status)
                continue;
            if (status.valid)
                return status;
            expiredKey ?? (expiredKey = status);
        }
        if (expiredKey)
            return expiredKey;
        // Tampered install records: no trial, a valid license key is required.
        if (install.tampered) {
            return {
                valid: false,
                expired: true,
                isTrial: true,
                tier: "COMMUNITY",
                daysRemaining: 0,
                source: "TRIAL_EXPIRED",
                reason: TAMPERED_REASON,
                renewalUrl: exports.MONT_LICENSE_PORTAL_URL,
            };
        }
        // Priority 2: the free trial that began on first boot (earliest trusted timestamp).
        const trialExpiresAt = install.firstSeenAt + TRIAL_MS;
        if (now < trialExpiresAt) {
            return {
                valid: true,
                expired: false,
                isTrial: true,
                tier: "PRO",
                org: "7-Day Free Pro Trial",
                expiresAt: new Date(trialExpiresAt).toISOString(),
                daysRemaining: daysLeft(trialExpiresAt, now),
                source: "TRIAL",
                renewalUrl: exports.MONT_LICENSE_PORTAL_URL,
            };
        }
        return {
            valid: false,
            expired: true,
            isTrial: true,
            tier: "COMMUNITY",
            expiresAt: new Date(trialExpiresAt).toISOString(),
            daysRemaining: 0,
            source: "TRIAL_EXPIRED",
            reason: TRIAL_EXPIRED_REASON,
            renewalUrl: exports.MONT_LICENSE_PORTAL_URL,
        };
    }
    /** Rewrites every store from scratch (dev helper and key changes); clears any tamper flag. */
    async function overwriteAll(firstSeenAt, licenseKey) {
        await setSetting(SETTING_TRIAL_STARTED, String(firstSeenAt));
        (0, installAnchor_1.writeStateFile)(anchorFile, { firstSeenAt });
        (0, installAnchor_1.writeStateFile)(licenseFile, { firstSeenAt, licenseKey });
    }
    return {
        resolveLicenseStatus,
        isPro: async () => (await resolveLicenseStatus()).tier === "PRO",
        restoreState: async () => {
            await syncInstallState(Date.now());
        },
        saveLicenseKey: async (licenseKey) => {
            const key = licenseKey.trim();
            await setSetting(SETTING_LICENSE_KEY, key);
            const lic = (0, installAnchor_1.readStateFile)(licenseFile);
            if (lic.state === "tampered")
                return; // leave the evidence; the DB copy still applies
            const { firstSeenAt } = await syncInstallState(Date.now());
            (0, installAnchor_1.writeStateFile)(licenseFile, { firstSeenAt, licenseKey: key });
        },
        removeLicenseKey: async () => {
            await db.run("DELETE FROM system_settings WHERE key = ?", [SETTING_LICENSE_KEY]);
            const lic = (0, installAnchor_1.readStateFile)(licenseFile);
            if (lic.state === "ok")
                (0, installAnchor_1.writeStateFile)(licenseFile, { firstSeenAt: lic.firstSeenAt });
        },
        simulateTrial: (expired) => overwriteAll(Date.now() - (expired ? 8 * DAY_MS : 0), undefined),
    };
}
