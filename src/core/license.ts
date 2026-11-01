import crypto from "crypto";
import type { Db } from "./db";
import { defaultAnchorPath, readStateFile, writeStateFile } from "./installAnchor";

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

export const MONT_LICENSE_PORTAL_URL = process.env.MONT_LICENSE_PORTAL_URL || "https://montweel.com/#license-renewal";

const DAY_MS = 24 * 60 * 60 * 1000;
const TRIAL_MS = 7 * DAY_MS;
const LICENSE_PREFIX = "MONT-";

const SETTING_TRIAL_STARTED = "trial_started_at";
const SETTING_LICENSE_KEY = "license_key";
const SETTING_TRIAL_KEY_HASH = "trial_key_hash";

/** 7-day instant trial + 90-day trial key + 3-day grace: the latest a free trial key can first be used. */
const TRIAL_KEY_WINDOW_MS = 100 * DAY_MS;

const FREE_TRIAL_CTA =
  "Activate your free 90-day Team Pro trial key at montweel.com/#license-renewal — no credit card or payment required.";
const KEY_EXPIRED_REASON = `Your Mont Pro key has expired. ${FREE_TRIAL_CTA}`;
const TAMPERED_REASON = `Install records for this gateway were modified or copied from another machine, so the instant trial is disabled. ${FREE_TRIAL_CTA}`;
const TRIAL_KEY_USED_REASON =
  "This machine already used its free 90-day trial key, so another trial key can't be added. Upgrade to a paid Team Pro key at https://montweel.com.";
const TRIAL_KEY_WINDOW_REASON =
  "Free 90-day trial keys must be activated within 100 days of first install, and that window has passed. Upgrade to a paid Team Pro key at https://montweel.com.";
const TRIAL_EXPIRED_REASON = `Your 7-day instant Pro trial has ended. ${FREE_TRIAL_CTA}`;

export interface LicenseStatus {
  valid: boolean;
  expired: boolean;
  isTrial: boolean;
  tier: "COMMUNITY" | "PRO";
  org?: string;
  email?: string;
  issuedAt?: string;
  expiresAt?: string;
  daysRemaining?: number;
  source: "ENV" | "DB" | "TRIAL" | "TRIAL_EXPIRED";
  reason?: string;
  renewalUrl: string;
}

export interface LicensePayload {
  org: string;
  email: string;
  tier: "PRO";
  /** Free 90-day trial key (signed as `trial: true` or `tier: "TRIAL"`): one per machine, see statusFromKey. */
  trial: boolean;
  iat: number;
  exp: number;
}

export type VerifyResult = { ok: true; payload: LicensePayload } | { ok: false; reason: string };

let publicKeyCache: { raw: string; key: crypto.KeyObject } | undefined;

function getPublicKey(): crypto.KeyObject {
  const raw = process.env.MONT_PUBLIC_KEY?.trim() || DEFAULT_PUBLIC_KEY;
  if (publicKeyCache?.raw !== raw) {
    publicKeyCache = {
      raw,
      key: crypto.createPublicKey({ key: Buffer.from(raw, "base64url"), format: "der", type: "spki" }),
    };
  }
  return publicKeyCache.key;
}

/** Checks format, signature and payload shape. Does NOT check expiry. */
export function verifyLicenseKey(licenseKey: string): VerifyResult {
  const key = licenseKey.trim();
  const dot = key.indexOf(".");
  if (!key.startsWith(LICENSE_PREFIX) || dot < 0) {
    return { ok: false, reason: "That is not a Mont license key. It should look like MONT-<payload>.<signature>." };
  }
  const encoded = key.slice(LICENSE_PREFIX.length, dot);
  const signature = key.slice(dot + 1);
  if (!encoded || !signature) return { ok: false, reason: "The license key is incomplete." };

  try {
    const sigOk = crypto.verify(null, Buffer.from(encoded), getPublicKey(), Buffer.from(signature, "base64url"));
    if (!sigOk) return { ok: false, reason: "The license key signature is not valid." };

    const p = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")) as Partial<
      Omit<LicensePayload, "tier">
    > & { tier?: string };
    if (
      (p.tier !== "PRO" && p.tier !== "TRIAL") ||
      typeof p.org !== "string" ||
      typeof p.email !== "string" ||
      typeof p.iat !== "number" ||
      typeof p.exp !== "number"
    ) {
      return { ok: false, reason: "The license key payload is malformed." };
    }
    const trial = p.tier === "TRIAL" || p.trial === true;
    return { ok: true, payload: { org: p.org, email: p.email, tier: "PRO", trial, iat: p.iat, exp: p.exp } };
  } catch {
    return { ok: false, reason: "The license key could not be read." };
  }
}

const daysLeft = (expMs: number, now: number): number => Math.max(0, Math.ceil((expMs - now) / DAY_MS));

export interface LicenseService {
  resolveLicenseStatus(): Promise<LicenseStatus>;
  isPro(): Promise<boolean>;
  /** Stores a key that already passed verifyLicenseKey. */
  saveLicenseKey(licenseKey: string): Promise<void>;
  removeLicenseKey(): Promise<void>;
  /** Startup: restore trial start + license key from mont-state.json / ~/.montweel/anchor.json into logs.db. */
  restoreState(): Promise<void>;
  /** Dev/test helper: restart the trial now, or backdate it so it ended yesterday. */
  simulateTrial(expired: boolean): Promise<void>;
}

export interface LicenseServiceOptions {
  /** mont-state.json location (default: next to logs.db is chosen by the caller). */
  licenseFile: string;
  /** Machine anchor location (default: ~/.montweel/anchor.json). */
  anchorFile?: string;
}

export function createLicenseService(db: Db, options: LicenseServiceOptions): LicenseService {
  const licenseFile = options.licenseFile;
  const anchorFile = options.anchorFile ?? defaultAnchorPath();

  async function getSetting(key: string): Promise<string | undefined> {
    return (await db.get<{ value: string }>("SELECT value FROM system_settings WHERE key = ?", [key]))?.value;
  }

  async function setSetting(key: string, value: string): Promise<void> {
    await db.run(
      "INSERT INTO system_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
      [key, value]
    );
  }

  /**
   * Reconciles logs.db, mont-state.json and the machine anchor. Returns the earliest trusted
   * firstSeenAt, or tampered=true when either file fails its HMAC. Missing or stale copies
   * are rewritten from the earliest value; a tampered file is left as evidence.
   */
  async function syncInstallState(
    now: number
  ): Promise<{ tampered: boolean; firstSeenAt: number; trialKeyHash?: string }> {
    const anchor = readStateFile(anchorFile);
    const lic = readStateFile(licenseFile);
    const dbRaw = Number(await getSetting(SETTING_TRIAL_STARTED));
    const times: number[] = [];
    if (anchor.state === "ok") times.push(anchor.firstSeenAt);
    if (lic.state === "ok") times.push(lic.firstSeenAt);
    if (Number.isFinite(dbRaw) && dbRaw > 0) times.push(dbRaw);

    const firstSeenAt = times.length ? Math.min(...times) : now;
    const tampered = anchor.state === "tampered" || lic.state === "tampered";

    const dbKey = await getSetting(SETTING_LICENSE_KEY);
    const fileKey = lic.state === "ok" ? lic.licenseKey : undefined;
    const licenseKey = dbKey ?? fileKey;

    // A claimed trial key sticks once ANY trusted store has it, so deleting one copy changes nothing.
    const dbTrial = (await getSetting(SETTING_TRIAL_KEY_HASH)) || undefined;
    const trialKeyHash =
      (anchor.state === "ok" ? anchor.trialKeyHash : undefined) ??
      (lic.state === "ok" ? lic.trialKeyHash : undefined) ??
      dbTrial;

    if (dbRaw !== firstSeenAt) await setSetting(SETTING_TRIAL_STARTED, String(firstSeenAt));
    if (!dbKey && fileKey) await setSetting(SETTING_LICENSE_KEY, fileKey);
    if (trialKeyHash && dbTrial !== trialKeyHash) await setSetting(SETTING_TRIAL_KEY_HASH, trialKeyHash);
    if (
      anchor.state === "missing" ||
      (anchor.state === "ok" && (anchor.firstSeenAt !== firstSeenAt || anchor.trialKeyHash !== trialKeyHash))
    ) {
      writeStateFile(anchorFile, { firstSeenAt, trialKeyHash });
    }
    if (
      lic.state === "missing" ||
      (lic.state === "ok" &&
        (lic.firstSeenAt !== firstSeenAt || lic.licenseKey !== licenseKey || lic.trialKeyHash !== trialKeyHash))
    ) {
      writeStateFile(licenseFile, { firstSeenAt, licenseKey, trialKeyHash });
    }
    return { tampered, firstSeenAt, trialKeyHash };
  }

  /** Records the one trial key this machine may use, in every store. */
  async function claimTrialKey(firstSeenAt: number, hash: string): Promise<void> {
    await setSetting(SETTING_TRIAL_KEY_HASH, hash);
    writeStateFile(anchorFile, { firstSeenAt, trialKeyHash: hash });
    if (readStateFile(licenseFile).state !== "tampered") {
      writeStateFile(licenseFile, { firstSeenAt, licenseKey: await getSetting(SETTING_LICENSE_KEY), trialKeyHash: hash });
    }
  }

  async function statusFromKey(
    licenseKey: string,
    source: "ENV" | "DB",
    now: number,
    install: { firstSeenAt: number; trialKeyHash?: string }
  ): Promise<LicenseStatus | undefined> {
    const result = verifyLicenseKey(licenseKey);
    if (!result.ok) return undefined; // a bad or tampered key never grants anything
    const { payload } = result;
    let active = now < payload.exp;
    let reason: string | undefined = active ? undefined : KEY_EXPIRED_REASON;

    // Free trial keys: one per machine, and only claimable within 100 days of first install.
    // Paid keys skip this and run until `exp`.
    if (active && payload.trial) {
      const hash = crypto.createHash("sha256").update(licenseKey.trim()).digest("hex");
      if (install.trialKeyHash && install.trialKeyHash !== hash) {
        active = false;
        reason = TRIAL_KEY_USED_REASON;
      } else if (!install.trialKeyHash) {
        if (now > install.firstSeenAt + TRIAL_KEY_WINDOW_MS) {
          active = false;
          reason = TRIAL_KEY_WINDOW_REASON;
        } else {
          await claimTrialKey(install.firstSeenAt, hash);
        }
      }
    }
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
      reason,
      renewalUrl: MONT_LICENSE_PORTAL_URL,
    };
  }

  async function resolveLicenseStatus(): Promise<LicenseStatus> {
    const now = Date.now();
    const install = await syncInstallState(now);

    // Priority 1: a signed key. An active one wins; otherwise report the expired one.
    const candidates: { key: string | undefined; source: "ENV" | "DB" }[] = [
      { key: process.env.MONT_LICENSE_KEY?.trim(), source: "ENV" },
      { key: await getSetting(SETTING_LICENSE_KEY), source: "DB" },
    ];
    let expiredKey: LicenseStatus | undefined;
    for (const { key, source } of candidates) {
      if (!key) continue;
      const status = await statusFromKey(key, source, now, install);
      if (!status) continue;
      if (status.valid) return status;
      expiredKey ??= status;
    }
    if (expiredKey) return expiredKey;

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
        renewalUrl: MONT_LICENSE_PORTAL_URL,
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
        renewalUrl: MONT_LICENSE_PORTAL_URL,
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
      renewalUrl: MONT_LICENSE_PORTAL_URL,
    };
  }

  /** Rewrites every store from scratch (dev helper and key changes); clears any tamper flag. */
  async function overwriteAll(firstSeenAt: number, licenseKey: string | undefined): Promise<void> {
    await db.run("DELETE FROM system_settings WHERE key = ?", [SETTING_TRIAL_KEY_HASH]);
    await setSetting(SETTING_TRIAL_STARTED, String(firstSeenAt));
    writeStateFile(anchorFile, { firstSeenAt });
    writeStateFile(licenseFile, { firstSeenAt, licenseKey });
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
      const lic = readStateFile(licenseFile);
      if (lic.state === "tampered") return; // leave the evidence; the DB copy still applies
      const { firstSeenAt, trialKeyHash } = await syncInstallState(Date.now());
      writeStateFile(licenseFile, { firstSeenAt, licenseKey: key, trialKeyHash });
    },
    removeLicenseKey: async () => {
      await db.run("DELETE FROM system_settings WHERE key = ?", [SETTING_LICENSE_KEY]);
      const lic = readStateFile(licenseFile);
      if (lic.state === "ok") writeStateFile(licenseFile, { firstSeenAt: lic.firstSeenAt, trialKeyHash: lic.trialKeyHash });
    },
    simulateTrial: (expired) => overwriteAll(Date.now() - (expired ? 8 * DAY_MS : 0), undefined),
  };
}
