"use strict";
/**
 * Credentials are write-only through the admin API: responses carry a mask, never the value.
 *
 *   maskSecret("123456789:AAH...xyz9") -> "••••••••xyz9"   (last 4 kept so admins can tell which one is set)
 *   isMasked(v)                         a value that starts with the mask is "unchanged": saving it back
 *                                       keeps the stored secret instead of overwriting it with bullets
 *
 * Admins who need the real value (e.g. to copy a gateway-generated signing secret into the receiving
 * system) ask for it explicitly with GET /secrets/:field, admin only, never cached.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.SECRET_MASK = void 0;
exports.maskSecret = maskSecret;
exports.isMasked = isMasked;
exports.maskUrl = maskUrl;
exports.SECRET_MASK = "••••••••";
function maskSecret(value) {
    if (!value)
        return "";
    return value.length <= 8 ? exports.SECRET_MASK : `${exports.SECRET_MASK}${value.slice(-4)}`;
}
function isMasked(value) {
    return typeof value === "string" && value.startsWith(exports.SECRET_MASK);
}
/** A URL reduced to its origin, for viewers: "https://hooks.zapier.com/••••••••". */
function maskUrl(value) {
    if (!value)
        return "";
    try {
        return `${new URL(value).origin}/${exports.SECRET_MASK}`;
    }
    catch {
        return exports.SECRET_MASK;
    }
}
