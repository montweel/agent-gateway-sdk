"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.UpstreamTooLargeError = void 0;
exports.isTimeoutError = isTimeoutError;
exports.readCapped = readCapped;
exports.proxyToTarget = proxyToTarget;
const constants_1 = require("./constants");
const utils_1 = require("./utils");
const SKIP_RESPONSE_HEADERS = new Set([
    ...constants_1.HOP_BY_HOP,
    "content-encoding",
    "content-length",
    "set-cookie",
]);
class UpstreamTooLargeError extends Error {
    constructor() {
        super(`The upstream response is larger than ${constants_1.MAX_UPSTREAM_BYTES / (1024 * 1024)} MB.`);
        this.name = "UpstreamTooLargeError";
    }
}
exports.UpstreamTooLargeError = UpstreamTooLargeError;
function isTimeoutError(err) {
    const name = err?.name;
    return name === "TimeoutError" || name === "AbortError";
}
/** Reads an upstream body, giving up (and cancelling the transfer) once it exceeds `max` bytes. */
async function readCapped(upstream, max = constants_1.MAX_UPSTREAM_BYTES) {
    const declared = Number(upstream.headers.get("content-length"));
    if (Number.isFinite(declared) && declared > max) {
        await upstream.body?.cancel().catch(() => undefined);
        throw new UpstreamTooLargeError();
    }
    if (!upstream.body)
        return Buffer.alloc(0);
    const reader = upstream.body.getReader();
    const chunks = [];
    let total = 0;
    for (;;) {
        const { done, value } = await reader.read();
        if (done)
            break;
        total += value.byteLength;
        if (total > max) {
            await reader.cancel().catch(() => undefined);
            throw new UpstreamTooLargeError();
        }
        chunks.push(value);
    }
    return Buffer.concat(chunks);
}
async function proxyToTarget(req, res, targetUrl, config) {
    const url = targetUrl + req.originalUrl;
    // Identity headers (the standard ones plus whatever this install configured for
    // SSO) and gateway credentials are removed, so the upstream never sees a value
    // a caller could have forged or a secret that was meant for the gateway.
    const strip = new Set([...constants_1.NEVER_FORWARD, config.ssoUserHeader, config.ssoRoleHeader]);
    const headers = new Headers();
    for (const [key, value] of Object.entries(req.headers)) {
        const k = key.toLowerCase();
        if (value === undefined || constants_1.HOP_BY_HOP.has(k) || strip.has(k))
            continue;
        const v = Array.isArray(value) ? value.join(", ") : value;
        // "Authorization: Bearer agk_..." is the gateway's own credential, not the upstream's.
        if (k === "authorization" && v.toLowerCase().startsWith(`bearer ${constants_1.AGENT_KEY_PREFIX}`))
            continue;
        headers.set(k, v);
    }
    // Loop guard: each hop through a gateway adds one; the interceptor rejects at MAX_HOPS.
    const hops = Number.parseInt(req.get(constants_1.HOPS_HEADER) ?? "0", 10);
    headers.set(constants_1.HOPS_HEADER, String((Number.isFinite(hops) && hops > 0 ? hops : 0) + 1));
    const body = (0, utils_1.extractBody)(req);
    try {
        const upstream = await fetch(url, {
            method: req.method,
            headers,
            body: body ?? undefined,
            redirect: "manual",
            signal: AbortSignal.timeout(constants_1.UPSTREAM_TIMEOUT_MS),
        });
        // Read (and size-check) the whole body before committing to a status, so an
        // oversized or broken response can still become a clean 502/504.
        const payload = await readCapped(upstream);
        res.status(upstream.status);
        upstream.headers.forEach((value, key) => {
            if (!SKIP_RESPONSE_HEADERS.has(key.toLowerCase()))
                res.setHeader(key, value);
        });
        const withCookies = upstream.headers;
        const cookies = withCookies.getSetCookie?.() ?? [];
        if (cookies.length > 0)
            res.setHeader("set-cookie", cookies);
        res.send(payload);
    }
    catch (err) {
        if (res.headersSent)
            return;
        if (isTimeoutError(err)) {
            console.error("Proxy timeout:", url);
            (0, utils_1.sendError)(res, 504, "Gateway Timeout", "The target server did not respond in time.");
        }
        else if (err instanceof UpstreamTooLargeError) {
            (0, utils_1.sendError)(res, 502, "Bad Gateway", err.message);
        }
        else {
            console.error("Proxy error:", err);
            (0, utils_1.sendError)(res, 502, "Bad Gateway", "Could not reach the target server.");
        }
    }
}
