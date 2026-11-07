/**
 * Mont v2 offline license generator (Ed25519, node:crypto only, never touches the network).
 *
 *   npx tsx scripts/keygen.ts generate-keys [--out=.keys]
 *       Creates a new Ed25519 key pair. Embed the PUBLIC key in src/core/license.ts
 *       (DEFAULT_PUBLIC_KEY); keep the private key secret.
 *
 *   npx tsx scripts/keygen.ts sign --tier=AGENCY --org="Acme Automation" [--max-workspaces=20]
 *                                  [--days=365 | --expires=2027-12-31] [--email=ops@acme.com]
 *       Prints a MONT-V2.<payload>.<signature> license. Defaults: PRO = 3 workspaces,
 *       AGENCY = 25 workspaces, 365 days.
 *
 *   npx tsx scripts/keygen.ts verify <MONT-V2...>
 *       Checks the signature against the embedded public key (or MONT_PUBLIC_KEY) and prints the payload.
 *
 * Private key lookup for `sign`: --key=<base64url PKCS#8> > MONT_PRIVATE_KEY env > .keys/private.key
 * (the same key scripts/license-tool.ts uses for v1 keys, so one key pair signs both formats).
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
  AGENCY_DEFAULT_MAX_WORKSPACES,
  MAX_LICENSED_WORKSPACES,
  PRO_DEFAULT_MAX_WORKSPACES,
  signLicenseV2,
  verifyLicenseKey,
} from "../src/core/license";

const DAY_MS = 24 * 60 * 60 * 1000;
const DEFAULT_KEY_DIR = path.resolve(process.cwd(), ".keys");

function parseArgs(argv: string[]): { command: string | undefined; positional: string[]; flags: Record<string, string> } {
  const flags: Record<string, string> = {};
  const positional: string[] = [];
  for (const arg of argv.slice(1)) {
    const m = /^--([^=]+)(?:=(.*))?$/.exec(arg);
    if (m) flags[m[1]] = m[2] ?? "true";
    else positional.push(arg);
  }
  return { command: argv[0], positional, flags };
}

function fail(message: string): never {
  console.error(message);
  process.exit(1);
}

function generateKeys(outDir: string): void {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const pub = publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const priv = privateKey.export({ format: "der", type: "pkcs8" }).toString("base64url");
  fs.mkdirSync(outDir, { recursive: true });
  const privFile = path.join(outDir, "private.key");
  if (fs.existsSync(privFile)) fail(`${privFile} already exists. Move it away first: replacing it invalidates every key you issued.`);
  fs.writeFileSync(privFile, `${priv}\n`, { mode: 0o600 });
  fs.writeFileSync(path.join(outDir, "public.key"), `${pub}\n`);
  console.log(`Keys written to ${outDir}`);
  console.log(`\nMONT_PRIVATE_KEY (keep secret):\n${priv}`);
  console.log(`\nPUBLIC KEY (embed as DEFAULT_PUBLIC_KEY in src/core/license.ts):\n${pub}`);
}

function loadPrivateKey(flags: Record<string, string>): crypto.KeyObject {
  let raw = flags.key && flags.key !== "true" ? flags.key : process.env.MONT_PRIVATE_KEY;
  if (!raw) {
    const file = path.join(DEFAULT_KEY_DIR, "private.key");
    if (fs.existsSync(file)) raw = fs.readFileSync(file, "utf8");
  }
  if (!raw || !raw.trim()) fail("No private key. Pass --key=, set MONT_PRIVATE_KEY, or run `generate-keys` to create .keys/private.key.");
  try {
    return crypto.createPrivateKey({ key: Buffer.from(raw.trim(), "base64url"), format: "der", type: "pkcs8" });
  } catch {
    fail("The private key could not be read (expected base64url PKCS#8 DER).");
  }
}

function sign(flags: Record<string, string>): void {
  const tier = (flags.tier ?? "PRO").toUpperCase();
  if (tier !== "PRO" && tier !== "AGENCY") fail('--tier must be PRO or AGENCY (COMMUNITY needs no key).');
  const org = flags.org;
  if (!org || org === "true") fail('Usage: sign --tier=AGENCY --org="Acme Automation" [--max-workspaces=20] [--days=365]');

  const maxWorkspaces = flags["max-workspaces"] !== undefined ? Number(flags["max-workspaces"]) : tier === "AGENCY" ? AGENCY_DEFAULT_MAX_WORKSPACES : PRO_DEFAULT_MAX_WORKSPACES;
  if (!Number.isInteger(maxWorkspaces) || maxWorkspaces < 1 || maxWorkspaces > MAX_LICENSED_WORKSPACES) {
    fail(`--max-workspaces must be a whole number from 1 to ${MAX_LICENSED_WORKSPACES}.`);
  }

  const backdate = Number(flags.backdate ?? 0);
  if (!Number.isFinite(backdate) || backdate < 0) fail("--backdate must be zero or a positive number of days.");
  const iat = Date.now() - backdate * DAY_MS;

  let expiresAt: number;
  if (flags.expires) {
    const d = new Date(flags.expires);
    if (Number.isNaN(d.getTime())) fail("--expires must be a date such as 2027-12-31.");
    expiresAt = d.getTime();
  } else {
    const days = Number(flags.days ?? 365);
    if (!Number.isFinite(days) || days <= 0) fail("--days must be a positive number.");
    expiresAt = iat + days * DAY_MS;
  }

  const key = signLicenseV2(
    { tier, orgName: org, maxWorkspaces, expiresAt, iat, email: flags.email && flags.email !== "true" ? flags.email : undefined },
    loadPrivateKey(flags)
  );
  console.log(key);
}

function verify(positional: string[]): void {
  const key = positional[0];
  if (!key) fail("Usage: verify <MONT-V2...>");
  const result = verifyLicenseKey(key);
  if (!result.ok) fail(`INVALID: ${result.reason}`);
  const p = result.payload;
  const expired = Date.now() >= p.exp;
  console.log(
    JSON.stringify(
      {
        valid: !expired,
        version: p.version,
        tier: p.tier,
        orgName: p.org,
        email: p.email || undefined,
        maxWorkspaces: p.maxWorkspaces,
        issuedAt: new Date(p.iat).toISOString(),
        expiresAt: new Date(p.exp).toISOString(),
        expired,
      },
      null,
      2
    )
  );
  if (expired) process.exit(2);
}

const { command, positional, flags } = parseArgs(process.argv.slice(2));
if (command === "generate-keys") generateKeys(flags.out ? path.resolve(flags.out) : DEFAULT_KEY_DIR);
else if (command === "sign") sign(flags);
else if (command === "verify") verify(positional);
else
  fail(
    [
      "Usage:",
      "  keygen.ts generate-keys [--out=.keys]",
      '  keygen.ts sign --tier=PRO|AGENCY --org="Name" [--max-workspaces=N] [--days=365 | --expires=YYYY-MM-DD] [--email=x]',
      "  keygen.ts verify <MONT-V2...>",
    ].join("\n")
  );
