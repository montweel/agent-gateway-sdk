"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.defaultAnchorPath = defaultAnchorPath;
exports.readStateFile = readStateFile;
exports.writeStateFile = writeStateFile;
const crypto_1 = __importDefault(require("crypto"));
const fs_1 = __importDefault(require("fs"));
const os_1 = __importDefault(require("os"));
const path_1 = __importDefault(require("path"));
function hmacFor(firstSeenAt, licenseKey, trialKeyHash) {
    const machine = `${os_1.default.hostname()}|${os_1.default.platform()}`;
    const key = crypto_1.default.createHash("sha256").update(`montweel-install-anchor|${machine}`).digest();
    // The trial suffix is only appended when set, so files written before it existed still verify.
    const trial = trialKeyHash ? `|trial:${trialKeyHash}` : "";
    return crypto_1.default.createHmac("sha256", key).update(`${firstSeenAt}|${licenseKey ?? ""}|${machine}${trial}`).digest("hex");
}
function defaultAnchorPath() {
    return path_1.default.join(os_1.default.homedir(), ".montweel", "anchor.json");
}
function readStateFile(file) {
    let raw;
    try {
        raw = fs_1.default.readFileSync(file, "utf8");
    }
    catch {
        return { state: "missing" };
    }
    try {
        const data = JSON.parse(raw);
        const licenseKey = typeof data.licenseKey === "string" ? data.licenseKey : undefined;
        const trialKeyHash = typeof data.trialKeyHash === "string" && data.trialKeyHash ? data.trialKeyHash : undefined;
        if (typeof data.firstSeenAt !== "number" || !Number.isFinite(data.firstSeenAt) || typeof data.hmac !== "string") {
            return { state: "tampered" };
        }
        const expected = Buffer.from(hmacFor(data.firstSeenAt, licenseKey, trialKeyHash));
        const actual = Buffer.from(data.hmac);
        if (expected.length !== actual.length || !crypto_1.default.timingSafeEqual(expected, actual))
            return { state: "tampered" };
        return { state: "ok", firstSeenAt: data.firstSeenAt, licenseKey, trialKeyHash };
    }
    catch {
        return { state: "tampered" };
    }
}
/** Best-effort write: a read-only home directory must never stop the gateway from booting. */
function writeStateFile(file, state) {
    try {
        fs_1.default.mkdirSync(path_1.default.dirname(file), { recursive: true });
        const body = {
            firstSeenAt: state.firstSeenAt,
            licenseKey: state.licenseKey,
            trialKeyHash: state.trialKeyHash,
            hmac: hmacFor(state.firstSeenAt, state.licenseKey, state.trialKeyHash),
        };
        fs_1.default.writeFileSync(file, JSON.stringify(body, null, 2), "utf8");
    }
    catch (err) {
        console.warn(`[mont] could not write ${file}: ${err.message}`);
    }
}
