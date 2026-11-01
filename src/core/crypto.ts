import crypto from "crypto";
import { BASE62, MAX_CONCURRENT_SCRYPT, OTP_ALPHABET } from "./constants";

/** Thrown when too many password hashes are already running. Routes answer 429. */
export class ScryptBusyError extends Error {
  constructor() {
    super("The server is busy verifying passwords. Please retry in a moment.");
    this.name = "ScryptBusyError";
  }
}

// Async scrypt so password hashing never blocks the event loop. At most
// MAX_CONCURRENT_SCRYPT run at once: each uses ~16 MB and a libuv thread, so an
// unbounded flood of logins would otherwise starve the whole process.
let activeScrypt = 0;
function scryptAsync(password: string, salt: string, keylen: number): Promise<Buffer> {
  if (activeScrypt >= MAX_CONCURRENT_SCRYPT) return Promise.reject(new ScryptBusyError());
  activeScrypt += 1;
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, keylen, (err: Error | null, key: Buffer) => {
      activeScrypt -= 1;
      if (err) reject(err);
      else resolve(key);
    });
  });
}

export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.randomBytes(16).toString("hex");
  const derived = (await scryptAsync(password, salt, 64)).toString("hex");
  return `${salt}:${derived}`;
}

export async function verifyPassword(password: string, storedHash: string): Promise<boolean> {
  const parts = storedHash.split(":");
  if (parts.length !== 2) return false;
  const [salt, keyHex] = parts;
  if (!salt || !keyHex) return false;
  try {
    const keyBuf = Buffer.from(keyHex, "hex");
    const derivedBuf = await scryptAsync(password, salt, 64);
    if (keyBuf.length !== derivedBuf.length) return false;
    return crypto.timingSafeEqual(keyBuf, derivedBuf);
  } catch (err) {
    if (err instanceof ScryptBusyError) throw err; // not a wrong password: tell the caller to retry
    return false;
  }
}

// A well-formed hash nobody can match. Verifying against it when a username
// does not exist keeps response time the same as for a real user (no
// username enumeration through timing).
const DUMMY_HASH = `${"00".repeat(16)}:${"00".repeat(64)}`;
export async function verifyAgainstDummy(password: string): Promise<void> {
  await verifyPassword(password, DUMMY_HASH);
}

export function safeEqualStrings(a: string, b: string): boolean {
  const ha = crypto.createHash("sha256").update(a).digest();
  const hb = crypto.createHash("sha256").update(b).digest();
  return crypto.timingSafeEqual(ha, hb);
}

export function sha256Hex(value: string): string {
  return crypto.createHash("sha256").update(value).digest("hex");
}

export function randomHex(bytes: number): string {
  return crypto.randomBytes(bytes).toString("hex");
}

// 12 characters from a 58-symbol alphabet (~70 bits), unbiased via randomInt.
export function generateTemporaryPassword(): string {
  let chars = "";
  for (let i = 0; i < 12; i++) {
    chars += OTP_ALPHABET[crypto.randomInt(OTP_ALPHABET.length)];
  }
  return `tmp_${chars}`;
}

/** `length` random characters from a base62 alphabet, unbiased via randomInt. */
export function randomBase62(length: number): string {
  let out = "";
  for (let i = 0; i < length; i++) out += BASE62[crypto.randomInt(BASE62.length)];
  return out;
}

const ENC_ALGORITHM = "aes-256-gcm";

/** AES-256-GCM. Output is "iv:authTag:ciphertext", each part hex. `keyHex` is 32 bytes (64 hex chars). */
export function encryptPayload(plaintext: string, keyHex: string): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ENC_ALGORITHM, Buffer.from(keyHex, "hex"), iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return `${iv.toString("hex")}:${cipher.getAuthTag().toString("hex")}:${ciphertext.toString("hex")}`;
}

/** Throws if the payload was tampered with or the key is wrong (GCM authentication fails). */
export function decryptPayload(payload: string, keyHex: string): string {
  const parts = payload.split(":");
  if (parts.length !== 3) throw new Error("Malformed encrypted payload.");
  const [iv, tag, ciphertext] = parts.map((p) => Buffer.from(p, "hex"));
  const decipher = crypto.createDecipheriv(ENC_ALGORITHM, Buffer.from(keyHex, "hex"), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
}
