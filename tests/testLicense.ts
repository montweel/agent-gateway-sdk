/**
 * Test-mode licensing. Importing this module (before any gateway is created):
 *   - generates a throwaway Ed25519 key pair and points the gateway at its public half
 *     (MONT_PUBLIC_KEY), so tests never need the real signing key
 *   - clears MONT_LICENSE_KEY so the developer's own key cannot leak into a test
 * Then mint keys with testLicense(). Gateways in tests get `licenseKey: TEST_AGENCY_KEY` and a
 * temp `licenseAnchorFile` by default (see helpers.ts), so ~/.montweel is never touched.
 */
import crypto from "crypto";
import { signLicenseV2 } from "../src/core/license";

const pair = crypto.generateKeyPairSync("ed25519");
export const TEST_PUBLIC_KEY = pair.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
export const TEST_PRIVATE_KEY = pair.privateKey;
process.env.MONT_PUBLIC_KEY = TEST_PUBLIC_KEY;
delete process.env.MONT_LICENSE_KEY;

const DAY = 24 * 3600_000;

export function testLicense(
  tier: "PRO" | "AGENCY" = "AGENCY",
  opts: { maxWorkspaces?: number; days?: number; orgName?: string; expiresAt?: number } = {}
): string {
  return signLicenseV2(
    {
      tier,
      orgName: opts.orgName ?? "Mont Test Suite",
      maxWorkspaces: opts.maxWorkspaces ?? (tier === "AGENCY" ? 50 : 3),
      expiresAt: opts.expiresAt ?? Date.now() + (opts.days ?? 30) * DAY,
    },
    TEST_PRIVATE_KEY
  );
}

export const TEST_AGENCY_KEY = testLicense("AGENCY");
