import crypto from "crypto";
import fs from "fs";
import os from "os";
import path from "path";

/**
 * Tamper-evident install-state files that live OUTSIDE logs.db, so deleting the database
 * never resets the trial clock or drops the active license.
 *
 *   ~/.montweel/anchor.json   machine-level anchor: { firstSeenAt, hmac }
 *   <dbDir>/mont-state.json     { firstSeenAt, licenseKey?, hmac }
 *
 * The HMAC is keyed from os.hostname() + os.platform(), so a copied file from another
 * machine fails verification. This is tamper-EVIDENT, not tamper-proof: the key derivation
 * is in the source. It stops casual edits and deleting logs.db, not a determined attacker.
 */

export type AnchorRead =
  | { state: "missing" }
  | { state: "tampered" }
  | { state: "ok"; firstSeenAt: number; licenseKey?: string; trialKeyHash?: string };

export interface InstallState {
  firstSeenAt: number;
  licenseKey?: string;
  /**
   * SHA-256 of the one free 90-day trial key this machine has claimed. Its presence is the
   * "trialKeyClaimed" flag: any other trial key is refused, so trial keys cannot be stacked.
   */
  trialKeyHash?: string;
}

function hmacFor(firstSeenAt: number, licenseKey: string | undefined, trialKeyHash?: string): string {
  const machine = `${os.hostname()}|${os.platform()}`;
  const key = crypto.createHash("sha256").update(`montweel-install-anchor|${machine}`).digest();
  // The trial suffix is only appended when set, so files written before it existed still verify.
  const trial = trialKeyHash ? `|trial:${trialKeyHash}` : "";
  return crypto.createHmac("sha256", key).update(`${firstSeenAt}|${licenseKey ?? ""}|${machine}${trial}`).digest("hex");
}

export function defaultAnchorPath(): string {
  return path.join(os.homedir(), ".montweel", "anchor.json");
}

export function readStateFile(file: string): AnchorRead {
  let raw: string;
  try {
    raw = fs.readFileSync(file, "utf8");
  } catch {
    return { state: "missing" };
  }
  try {
    const data = JSON.parse(raw) as { firstSeenAt?: unknown; licenseKey?: unknown; trialKeyHash?: unknown; hmac?: unknown };
    const licenseKey = typeof data.licenseKey === "string" ? data.licenseKey : undefined;
    const trialKeyHash = typeof data.trialKeyHash === "string" && data.trialKeyHash ? data.trialKeyHash : undefined;
    if (typeof data.firstSeenAt !== "number" || !Number.isFinite(data.firstSeenAt) || typeof data.hmac !== "string") {
      return { state: "tampered" };
    }
    const expected = Buffer.from(hmacFor(data.firstSeenAt, licenseKey, trialKeyHash));
    const actual = Buffer.from(data.hmac);
    if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) return { state: "tampered" };
    return { state: "ok", firstSeenAt: data.firstSeenAt, licenseKey, trialKeyHash };
  } catch {
    return { state: "tampered" };
  }
}

/** Best-effort write: a read-only home directory must never stop the gateway from booting. */
export function writeStateFile(file: string, state: InstallState): void {
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const body = {
      firstSeenAt: state.firstSeenAt,
      licenseKey: state.licenseKey,
      trialKeyHash: state.trialKeyHash,
      hmac: hmacFor(state.firstSeenAt, state.licenseKey, state.trialKeyHash),
    };
    fs.writeFileSync(file, JSON.stringify(body, null, 2), "utf8");
  } catch (err) {
    console.warn(`[mont] could not write ${file}: ${(err as Error).message}`);
  }
}
