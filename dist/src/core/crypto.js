"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ScryptBusyError = void 0;
exports.hashPassword = hashPassword;
exports.verifyPassword = verifyPassword;
exports.verifyAgainstDummy = verifyAgainstDummy;
exports.safeEqualStrings = safeEqualStrings;
exports.sha256Hex = sha256Hex;
exports.randomHex = randomHex;
exports.generateTemporaryPassword = generateTemporaryPassword;
exports.randomBase62 = randomBase62;
exports.encryptPayload = encryptPayload;
exports.decryptPayload = decryptPayload;
const crypto_1 = __importDefault(require("crypto"));
const constants_1 = require("./constants");
/** Thrown when too many password hashes are already running. Routes answer 429. */
class ScryptBusyError extends Error {
    constructor() {
        super("The server is busy verifying passwords. Please retry in a moment.");
        this.name = "ScryptBusyError";
    }
}
exports.ScryptBusyError = ScryptBusyError;
// Async scrypt so password hashing never blocks the event loop. At most
// MAX_CONCURRENT_SCRYPT run at once: each uses ~16 MB and a libuv thread, so an
// unbounded flood of logins would otherwise starve the whole process.
let activeScrypt = 0;
function scryptAsync(password, salt, keylen) {
    if (activeScrypt >= constants_1.MAX_CONCURRENT_SCRYPT)
        return Promise.reject(new ScryptBusyError());
    activeScrypt += 1;
    return new Promise((resolve, reject) => {
        crypto_1.default.scrypt(password, salt, keylen, (err, key) => {
            activeScrypt -= 1;
            if (err)
                reject(err);
            else
                resolve(key);
        });
    });
}
async function hashPassword(password) {
    const salt = crypto_1.default.randomBytes(16).toString("hex");
    const derived = (await scryptAsync(password, salt, 64)).toString("hex");
    return `${salt}:${derived}`;
}
async function verifyPassword(password, storedHash) {
    const parts = storedHash.split(":");
    if (parts.length !== 2)
        return false;
    const [salt, keyHex] = parts;
    if (!salt || !keyHex)
        return false;
    try {
        const keyBuf = Buffer.from(keyHex, "hex");
        const derivedBuf = await scryptAsync(password, salt, 64);
        if (keyBuf.length !== derivedBuf.length)
            return false;
        return crypto_1.default.timingSafeEqual(keyBuf, derivedBuf);
    }
    catch (err) {
        if (err instanceof ScryptBusyError)
            throw err; // not a wrong password: tell the caller to retry
        return false;
    }
}
// A well-formed hash nobody can match. Verifying against it when a username
// does not exist keeps response time the same as for a real user (no
// username enumeration through timing).
const DUMMY_HASH = `${"00".repeat(16)}:${"00".repeat(64)}`;
async function verifyAgainstDummy(password) {
    await verifyPassword(password, DUMMY_HASH);
}
function safeEqualStrings(a, b) {
    const ha = crypto_1.default.createHash("sha256").update(a).digest();
    const hb = crypto_1.default.createHash("sha256").update(b).digest();
    return crypto_1.default.timingSafeEqual(ha, hb);
}
function sha256Hex(value) {
    return crypto_1.default.createHash("sha256").update(value).digest("hex");
}
function randomHex(bytes) {
    return crypto_1.default.randomBytes(bytes).toString("hex");
}
// 12 characters from a 58-symbol alphabet (~70 bits), unbiased via randomInt.
function generateTemporaryPassword() {
    let chars = "";
    for (let i = 0; i < 12; i++) {
        chars += constants_1.OTP_ALPHABET[crypto_1.default.randomInt(constants_1.OTP_ALPHABET.length)];
    }
    return `tmp_${chars}`;
}
/** `length` random characters from a base62 alphabet, unbiased via randomInt. */
function randomBase62(length) {
    let out = "";
    for (let i = 0; i < length; i++)
        out += constants_1.BASE62[crypto_1.default.randomInt(constants_1.BASE62.length)];
    return out;
}
const ENC_ALGORITHM = "aes-256-gcm";
/** AES-256-GCM. Output is "iv:authTag:ciphertext", each part hex. `keyHex` is 32 bytes (64 hex chars). */
function encryptPayload(plaintext, keyHex) {
    const iv = crypto_1.default.randomBytes(12);
    const cipher = crypto_1.default.createCipheriv(ENC_ALGORITHM, Buffer.from(keyHex, "hex"), iv);
    const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    return `${iv.toString("hex")}:${cipher.getAuthTag().toString("hex")}:${ciphertext.toString("hex")}`;
}
/** Throws if the payload was tampered with or the key is wrong (GCM authentication fails). */
function decryptPayload(payload, keyHex) {
    const parts = payload.split(":");
    if (parts.length !== 3)
        throw new Error("Malformed encrypted payload.");
    const [iv, tag, ciphertext] = parts.map((p) => Buffer.from(p, "hex"));
    const decipher = crypto_1.default.createDecipheriv(ENC_ALGORITHM, Buffer.from(keyHex, "hex"), iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
}
