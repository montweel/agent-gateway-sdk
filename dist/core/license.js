"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.MAX_LICENSED_WORKSPACES = exports.AGENCY_DEFAULT_MAX_WORKSPACES = exports.PRO_DEFAULT_MAX_WORKSPACES = exports.COMMUNITY_MAX_WORKSPACES = exports.LICENSE_TIERS = exports.MONT_LICENSE_PORTAL_URL = void 0;
exports.featuresFor = featuresFor;
exports.verifyLicenseKey = verifyLicenseKey;
exports.signLicenseV2 = signLicenseV2;
exports.createLicenseService = createLicenseService;
const crypto_1 = __importDefault(require("crypto"));
const installAnchor_1 = require("./installAnchor");
/**
 * Offline, zero-phone-home Mont licensing (Ed25519, node:crypto only).
 *
 * Two key formats are accepted, both verified against the embedded public key:
 *   v2  MONT-V2.<base64url payload>.<base64url signature>
 *       payload  = { v: 2, tier: "PRO" | "AGENCY", orgName, maxWorkspaces, expiresAt, iat, email? }
 *       signature = Ed25519 over the ASCII string "MONT-V2.<base64url payload>" (version-bound)
 *       minted with scripts/keygen.ts
 *   v1  MONT-<base64url payload>.<base64url signature>   (Mont Pro keys issued before v2)
 *       payload  = { org, email, tier: "PRO" | "TRIAL", iat, exp }, signature over the payload string
 *       minted with scripts/license-tool.ts
 *
 * Resolution order: a signed key (host option, then MONT_LICENSE_KEY env, then the one activated
 * in the dashboard), then the free 7-day trial that starts on first boot. COMMUNITY is the
 * fallback; it never gates the proxy itself, only the Pro / Agency extras (see LicenseFeatures).
 */
/**
 * Public half of the Ed25519 signing key (base64url SPKI DER). MONT_PUBLIC_KEY overrides it for testing.
 *
 * Signing (e.g. the montweel.com Cloudflare Pages function minting 90-day trial keys) uses the
 * matching PKCS#8 private key, base64url-encoded, stored as a secret named MONT_PRIVATE_KEY:
 *   payload   = base64url(JSON {org, email, tier:"PRO", iat, exp})   (iat/exp in ms)
 *   signature = base64url(Ed25519 sign over the ASCII payload string)
 *   key       = "MONT-" + payload + "." + signature
 * CLI: `npx tsx scripts/license-tool.ts sign --org=X --email=Y --days=90`. To verify that a private key
 * matches this public key: `npx tsx scripts/license-tool.ts check-key [--key=<private>]`.
 */
const DEFAULT_PUBLIC_KEY = "MCowBQYDK2VwAyEAbZJnW0z-pj5aAkMlquawZNeLFjlBOo2C_g8Byy1-vVY";
exports.MONT_LICENSE_PORTAL_URL = process.env.MONT_LICENSE_PORTAL_URL || "https://montweel.com/#license-renewal";
const DAY_MS = 24 * 60 * 60 * 1000;
const TRIAL_MS = 7 * DAY_MS;
const LICENSE_PREFIX = "MONT-";
const SETTING_TRIAL_STARTED = "trial_started_at";
const SETTING_LICENSE_KEY = "license_key";
const SETTING_TRIAL_KEY_HASH = "trial_key_hash";
/** 7-day instant trial + 90-day trial key + 3-day grace: the latest a free trial key can first be used. */
const TRIAL_KEY_WINDOW_MS = 100 * DAY_MS;
const FREE_TRIAL_CTA = "Activate your free 90-day Team Pro trial key at montweel.com/#license-renewal — no credit card or payment required.";
const KEY_EXPIRED_REASON = `Your Mont Pro key has expired. ${FREE_TRIAL_CTA}`;
const TAMPERED_REASON = `Install records for this gateway were modified or copied from another machine, so the instant trial is disabled. ${FREE_TRIAL_CTA}`;
const TRIAL_KEY_USED_REASON = "This machine already used its free 90-day trial key, so another trial key can't be added. Upgrade to a paid Team Pro key at https://montweel.com.";
const TRIAL_KEY_WINDOW_REASON = "Free 90-day trial keys must be activated within 100 days of first install, and that window has passed. Upgrade to a paid Team Pro key at https://montweel.com.";
const TRIAL_EXPIRED_REASON = `Your 7-day instant Pro trial has ended. ${FREE_TRIAL_CTA}`;
exports.LICENSE_TIERS = ["COMMUNITY", "PRO", "AGENCY"];
exports.COMMUNITY_MAX_WORKSPACES = 1;
exports.PRO_DEFAULT_MAX_WORKSPACES = 3;
exports.AGENCY_DEFAULT_MAX_WORKSPACES = 25;
exports.MAX_LICENSED_WORKSPACES = 10000;
function featuresFor(tier, maxWorkspaces) {
    const paid = tier !== "COMMUNITY";
    return {
        multiWorkspace: paid && maxWorkspaces > 1,
        interactiveApprovals: paid,
        rollbackWebhooks: paid,
        payloadPatching: paid,
        auditVerification: paid,
    };
}
const V2_PREFIX = "MONT-V2.";
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
const B64URL = /^[A-Za-z0-9_-]+$/;
/** MONT-V2.<payload>.<signature>; the signature covers "MONT-V2.<payload>". */
function verifyV2(key) {
    const rest = key.slice(V2_PREFIX.length);
    const parts = rest.split(".");
    if (parts.length !== 2 || !parts[0] || !parts[1] || !B64URL.test(parts[0]) || !B64URL.test(parts[1])) {
        return { ok: false, reason: "The license key is incomplete. A v2 key looks like MONT-V2.<payload>.<signature>." };
    }
    const [encoded, signature] = parts;
    try {
        const sig = Buffer.from(signature, "base64url");
        // Canonical encoding only: a re-encoded signature must be byte-identical.
        if (sig.length !== 64 || sig.toString("base64url") !== signature)
            return { ok: false, reason: "The license key signature is not valid." };
        if (!crypto_1.default.verify(null, Buffer.from(`${V2_PREFIX}${encoded}`), getPublicKey(), sig)) {
            return { ok: false, reason: "The license key signature is not valid." };
        }
        const p = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
        const tier = p.tier;
        const maxWorkspaces = p.maxWorkspaces;
        if (p.v !== 2 ||
            (tier !== "PRO" && tier !== "AGENCY") ||
            typeof p.orgName !== "string" ||
            p.orgName.trim() === "" ||
            typeof p.expiresAt !== "number" ||
            !Number.isFinite(p.expiresAt) ||
            typeof p.iat !== "number" ||
            !Number.isInteger(maxWorkspaces) ||
            maxWorkspaces < 1 ||
            maxWorkspaces > exports.MAX_LICENSED_WORKSPACES ||
            (p.email !== undefined && typeof p.email !== "string")) {
            return { ok: false, reason: "The license key payload is malformed." };
        }
        return {
            ok: true,
            payload: {
                org: p.orgName,
                email: typeof p.email === "string" ? p.email : "",
                tier,
                trial: p.trial === true,
                iat: p.iat,
                exp: p.expiresAt,
                maxWorkspaces: maxWorkspaces,
                version: 2,
            },
        };
    }
    catch {
        return { ok: false, reason: "The license key could not be read." };
    }
}
/** Checks format, signature and payload shape. Does NOT check expiry. */
function verifyLicenseKey(licenseKey) {
    const key = licenseKey.trim();
    if (key.startsWith(V2_PREFIX))
        return verifyV2(key);
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
        if ((p.tier !== "PRO" && p.tier !== "TRIAL") ||
            typeof p.org !== "string" ||
            typeof p.email !== "string" ||
            typeof p.iat !== "number" ||
            typeof p.exp !== "number") {
            return { ok: false, reason: "The license key payload is malformed." };
        }
        const trial = p.tier === "TRIAL" || p.trial === true;
        return {
            ok: true,
            payload: { org: p.org, email: p.email, tier: "PRO", trial, iat: p.iat, exp: p.exp, maxWorkspaces: exports.PRO_DEFAULT_MAX_WORKSPACES, version: 1 },
        };
    }
    catch {
        return { ok: false, reason: "The license key could not be read." };
    }
}
/**
 * Signs a v2 license (used by scripts/keygen.ts and the test suite). Needs the Ed25519 private
 * key (PKCS#8 DER, base64url, or a KeyObject): the gateway itself only ever holds the public key.
 */
function signLicenseV2(input, privateKey) {
    if (input.tier !== "PRO" && input.tier !== "AGENCY")
        throw new Error('tier must be "PRO" or "AGENCY".');
    if (!input.orgName.trim())
        throw new Error("orgName is required.");
    if (!Number.isInteger(input.maxWorkspaces) || input.maxWorkspaces < 1 || input.maxWorkspaces > exports.MAX_LICENSED_WORKSPACES) {
        throw new Error(`maxWorkspaces must be a whole number from 1 to ${exports.MAX_LICENSED_WORKSPACES}.`);
    }
    if (!Number.isFinite(input.expiresAt))
        throw new Error("expiresAt must be a timestamp in ms.");
    const key = typeof privateKey === "string" ? crypto_1.default.createPrivateKey({ key: Buffer.from(privateKey.trim(), "base64url"), format: "der", type: "pkcs8" }) : privateKey;
    const payload = {
        v: 2,
        tier: input.tier,
        orgName: input.orgName.trim(),
        maxWorkspaces: input.maxWorkspaces,
        expiresAt: Math.trunc(input.expiresAt),
        iat: Math.trunc(input.iat ?? Date.now()),
    };
    if (input.email)
        payload.email = input.email;
    const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
    const signature = crypto_1.default.sign(null, Buffer.from(`${V2_PREFIX}${encoded}`), key).toString("base64url");
    return `${V2_PREFIX}${encoded}.${signature}`;
}
const daysLeft = (expMs, now) => Math.max(0, Math.ceil((expMs - now) / DAY_MS));
const COMMUNITY_FEATURES = featuresFor("COMMUNITY", exports.COMMUNITY_MAX_WORKSPACES);
function createLicenseService(db, options) {
    const licenseFile = options.licenseFile;
    const anchorFile = options.anchorFile ?? (0, installAnchor_1.defaultAnchorPath)();
    let cached = {
        valid: false,
        expired: false,
        isTrial: false,
        tier: "COMMUNITY",
        source: "TRIAL_EXPIRED",
        renewalUrl: exports.MONT_LICENSE_PORTAL_URL,
        maxWorkspaces: exports.COMMUNITY_MAX_WORKSPACES,
        features: COMMUNITY_FEATURES,
    };
    let refreshTimer;
    /** Community fields for any status that grants nothing. */
    const community = (s) => ({
        ...s,
        tier: "COMMUNITY",
        maxWorkspaces: exports.COMMUNITY_MAX_WORKSPACES,
        features: COMMUNITY_FEATURES,
    });
    async function getSetting(key) {
        return (await db.get("SELECT value FROM system_settings WHERE key = ?", [key]))?.value;
    }
    async function setSetting(key, value) {
        await db.run("INSERT INTO system_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", [key, value]);
    }
    /**
     * Reconciles logs.db, mont-state.json and the machine anchor. Returns the earliest trusted
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
        // A claimed trial key sticks once ANY trusted store has it, so deleting one copy changes nothing.
        const dbTrial = (await getSetting(SETTING_TRIAL_KEY_HASH)) || undefined;
        const trialKeyHash = (anchor.state === "ok" ? anchor.trialKeyHash : undefined) ??
            (lic.state === "ok" ? lic.trialKeyHash : undefined) ??
            dbTrial;
        if (dbRaw !== firstSeenAt)
            await setSetting(SETTING_TRIAL_STARTED, String(firstSeenAt));
        if (!dbKey && fileKey)
            await setSetting(SETTING_LICENSE_KEY, fileKey);
        if (trialKeyHash && dbTrial !== trialKeyHash)
            await setSetting(SETTING_TRIAL_KEY_HASH, trialKeyHash);
        if (anchor.state === "missing" ||
            (anchor.state === "ok" && (anchor.firstSeenAt !== firstSeenAt || anchor.trialKeyHash !== trialKeyHash))) {
            (0, installAnchor_1.writeStateFile)(anchorFile, { firstSeenAt, trialKeyHash });
        }
        if (lic.state === "missing" ||
            (lic.state === "ok" &&
                (lic.firstSeenAt !== firstSeenAt || lic.licenseKey !== licenseKey || lic.trialKeyHash !== trialKeyHash))) {
            (0, installAnchor_1.writeStateFile)(licenseFile, { firstSeenAt, licenseKey, trialKeyHash });
        }
        return { tampered, firstSeenAt, trialKeyHash };
    }
    /** Records the one trial key this machine may use, in every store. */
    async function claimTrialKey(firstSeenAt, hash) {
        await setSetting(SETTING_TRIAL_KEY_HASH, hash);
        (0, installAnchor_1.writeStateFile)(anchorFile, { firstSeenAt, trialKeyHash: hash });
        if ((0, installAnchor_1.readStateFile)(licenseFile).state !== "tampered") {
            (0, installAnchor_1.writeStateFile)(licenseFile, { firstSeenAt, licenseKey: await getSetting(SETTING_LICENSE_KEY), trialKeyHash: hash });
        }
    }
    async function statusFromKey(licenseKey, source, now, install) {
        const result = verifyLicenseKey(licenseKey);
        if (!result.ok)
            return undefined; // a bad or tampered key never grants anything
        const { payload } = result;
        let active = now < payload.exp;
        let reason = active ? undefined : KEY_EXPIRED_REASON;
        // Free trial keys: one per machine, and only claimable within 100 days of first install.
        // Paid keys skip this and run until `exp`.
        if (active && payload.trial) {
            const hash = crypto_1.default.createHash("sha256").update(licenseKey.trim()).digest("hex");
            if (install.trialKeyHash && install.trialKeyHash !== hash) {
                active = false;
                reason = TRIAL_KEY_USED_REASON;
            }
            else if (!install.trialKeyHash) {
                if (now > install.firstSeenAt + TRIAL_KEY_WINDOW_MS) {
                    active = false;
                    reason = TRIAL_KEY_WINDOW_REASON;
                }
                else {
                    await claimTrialKey(install.firstSeenAt, hash);
                }
            }
        }
        const base = {
            valid: active,
            expired: !active,
            isTrial: false,
            org: payload.org,
            email: payload.email,
            issuedAt: new Date(payload.iat).toISOString(),
            expiresAt: new Date(payload.exp).toISOString(),
            daysRemaining: active ? daysLeft(payload.exp, now) : 0,
            source,
            reason,
            renewalUrl: exports.MONT_LICENSE_PORTAL_URL,
            keyVersion: payload.version,
        };
        if (!active)
            return community(base);
        return { ...base, tier: payload.tier, maxWorkspaces: payload.maxWorkspaces, features: featuresFor(payload.tier, payload.maxWorkspaces) };
    }
    async function resolveLicenseStatus() {
        const status = await resolveUncached();
        cached = status;
        return status;
    }
    async function resolveUncached() {
        const now = Date.now();
        const install = await syncInstallState(now);
        // Priority 1: a signed key. An active one wins; otherwise report the expired one.
        const candidates = [
            { key: options.licenseKey?.trim(), source: "OPTION" },
            { key: process.env.MONT_LICENSE_KEY?.trim(), source: "ENV" },
            { key: await getSetting(SETTING_LICENSE_KEY), source: "DB" },
        ];
        let expiredKey;
        for (const { key, source } of candidates) {
            if (!key)
                continue;
            const status = await statusFromKey(key, source, now, install);
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
            return community({
                valid: false,
                expired: true,
                isTrial: true,
                tier: "COMMUNITY",
                daysRemaining: 0,
                source: "TRIAL_EXPIRED",
                reason: TAMPERED_REASON,
                renewalUrl: exports.MONT_LICENSE_PORTAL_URL,
            });
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
                maxWorkspaces: exports.PRO_DEFAULT_MAX_WORKSPACES,
                features: featuresFor("PRO", exports.PRO_DEFAULT_MAX_WORKSPACES),
            };
        }
        return community({
            valid: false,
            expired: true,
            isTrial: true,
            tier: "COMMUNITY",
            expiresAt: new Date(trialExpiresAt).toISOString(),
            daysRemaining: 0,
            source: "TRIAL_EXPIRED",
            reason: TRIAL_EXPIRED_REASON,
            renewalUrl: exports.MONT_LICENSE_PORTAL_URL,
        });
    }
    /** Rewrites every store from scratch (dev helper and key changes); clears any tamper flag. */
    async function overwriteAll(firstSeenAt, licenseKey) {
        await db.run("DELETE FROM system_settings WHERE key = ?", [SETTING_TRIAL_KEY_HASH]);
        await setSetting(SETTING_TRIAL_STARTED, String(firstSeenAt));
        (0, installAnchor_1.writeStateFile)(anchorFile, { firstSeenAt });
        (0, installAnchor_1.writeStateFile)(licenseFile, { firstSeenAt, licenseKey });
    }
    return {
        resolveLicenseStatus,
        isPro: async () => (await resolveLicenseStatus()).tier !== "COMMUNITY",
        current: () => cached,
        refresh: resolveLicenseStatus,
        start(intervalMs = 60000) {
            if (refreshTimer)
                return;
            refreshTimer = setInterval(() => {
                resolveLicenseStatus().catch((err) => console.error("License refresh failed:", err));
            }, intervalMs);
            refreshTimer.unref();
        },
        stop() {
            if (refreshTimer)
                clearInterval(refreshTimer);
            refreshTimer = undefined;
        },
        restoreState: async () => {
            await syncInstallState(Date.now());
        },
        saveLicenseKey: async (licenseKey) => {
            const key = licenseKey.trim();
            await setSetting(SETTING_LICENSE_KEY, key);
            const lic = (0, installAnchor_1.readStateFile)(licenseFile);
            if (lic.state !== "tampered") {
                // (a tampered file is left as evidence; the DB copy still applies)
                const { firstSeenAt, trialKeyHash } = await syncInstallState(Date.now());
                (0, installAnchor_1.writeStateFile)(licenseFile, { firstSeenAt, licenseKey: key, trialKeyHash });
            }
            await resolveLicenseStatus();
        },
        removeLicenseKey: async () => {
            await db.run("DELETE FROM system_settings WHERE key = ?", [SETTING_LICENSE_KEY]);
            const lic = (0, installAnchor_1.readStateFile)(licenseFile);
            if (lic.state === "ok")
                (0, installAnchor_1.writeStateFile)(licenseFile, { firstSeenAt: lic.firstSeenAt, trialKeyHash: lic.trialKeyHash });
            await resolveLicenseStatus();
        },
        simulateTrial: async (expired) => {
            await overwriteAll(Date.now() - (expired ? 8 * DAY_MS : 0), undefined);
            await resolveLicenseStatus();
        },
    };
}
