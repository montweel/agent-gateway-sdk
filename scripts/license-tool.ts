/**
 * Mont license tool (offline, Ed25519, node:crypto only).
 *
 *   npx tsx scripts/license-tool.ts generate-keys [--out=.keys]
 *   npx tsx scripts/license-tool.ts sign --org="Acme Corp" --email="admin@acme.com" --days=90 [--trial]
 *   npx tsx scripts/license-tool.ts check-key   (private key matches the public key in src/core/license.ts?)
 *
 * Private key lookup for `sign`: --key=<base64url> > MONT_PRIVATE_KEY env > .keys/private.key
 * Test helper: --backdate=<days> shifts the issue time into the past (use it to mint an expired key).
 *
 * A license is `MONT-<base64url payload>.<base64url signature>`; the signature covers the
 * base64url payload string. Keys are DER (PKCS#8 private / SPKI public), base64url-encoded.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const DAY_MS = 24 * 60 * 60 * 1000;
const DEFAULT_KEY_DIR = path.resolve(process.cwd(), ".keys");

function parseArgs(argv: string[]): { command: string | undefined; flags: Record<string, string> } {
  const flags: Record<string, string> = {};
  for (const arg of argv.slice(1)) {
    const m = /^--([^=]+)(?:=(.*))?$/.exec(arg);
    if (m) flags[m[1]] = m[2] ?? "true";
  }
  return { command: argv[0], flags };
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
  fs.writeFileSync(path.join(outDir, "private.key"), priv + "\n", { mode: 0o600 });
  fs.writeFileSync(path.join(outDir, "public.key"), pub + "\n");

  console.log("Keys written to", outDir);
  console.log("\nMONT_PRIVATE_KEY (keep secret, e.g. a Cloudflare Pages secret):\n" + priv);
  console.log("\nPUBLIC_KEY (embed in src/core/license.ts):\n" + pub);
}

function loadPrivateKey(flags: Record<string, string>): crypto.KeyObject {
  let raw = flags.key || process.env.MONT_PRIVATE_KEY;
  if (!raw) {
    const file = path.join(DEFAULT_KEY_DIR, "private.key");
    if (fs.existsSync(file)) raw = fs.readFileSync(file, "utf8");
  }
  if (!raw || !raw.trim()) {
    fail("No private key. Pass --key=, set MONT_PRIVATE_KEY, or run `generate-keys` to create .keys/private.key.");
  }
  return crypto.createPrivateKey({ key: Buffer.from(raw.trim(), "base64url"), format: "der", type: "pkcs8" });
}

function sign(flags: Record<string, string>): void {
  const org = flags.org;
  const email = flags.email;
  if (!org || org === "true" || !email || email === "true") {
    fail('Usage: sign --org="Acme Corp" --email="admin@acme.com" --days=30');
  }
  const days = Number(flags.days ?? 30);
  const backdate = Number(flags.backdate ?? 0);
  if (!Number.isFinite(days) || days <= 0) fail("--days must be a positive number.");
  if (!Number.isFinite(backdate) || backdate < 0) fail("--backdate must be zero or a positive number of days.");

  const iat = Date.now() - backdate * DAY_MS;
  // --trial marks a free 90-day trial key (one per machine, activate within 100 days of first install).
  const payload = {
    org,
    email,
    tier: "PRO" as const,
    ...(flags.trial ? { trial: true as const } : {}),
    iat,
    exp: iat + days * DAY_MS,
  };
  const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = crypto.sign(null, Buffer.from(encoded), loadPrivateKey(flags)).toString("base64url");

  console.log(`MONT-${encoded}.${signature}`);
}

/** Confirms the private key matches the public key embedded in src/core/license.ts (or MONT_PUBLIC_KEY). */
function checkKey(flags: Record<string, string>): void {
  const src = fs.readFileSync(path.resolve(__dirname, "../src/core/license.ts"), "utf8");
  const embedded = process.env.MONT_PUBLIC_KEY?.trim() || /DEFAULT_PUBLIC_KEY\s*=\s*"([^"]+)"/.exec(src)?.[1];
  if (!embedded) fail("Could not find DEFAULT_PUBLIC_KEY in src/core/license.ts.");
  const derived = crypto
    .createPublicKey(loadPrivateKey(flags))
    .export({ format: "der", type: "spki" })
    .toString("base64url");
  if (derived === embedded) console.log("OK: private key matches the embedded public key.\n" + embedded);
  else fail(`MISMATCH.\n  embedded: ${embedded}\n  derived:  ${derived}`);
}

const { command, flags } = parseArgs(process.argv.slice(2));
if (command === "generate-keys") generateKeys(flags.out ? path.resolve(flags.out) : DEFAULT_KEY_DIR);
else if (command === "sign") sign(flags);
else if (command === "check-key") checkKey(flags);
else
  fail(
    "Usage:\n  license-tool.ts generate-keys\n  license-tool.ts sign --org=<org> --email=<email> --days=<n>\n  license-tool.ts check-key [--key=<private>]"
  );
