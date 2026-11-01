"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createAuthService = createAuthService;
const rateLimit_1 = require("./rateLimit");
const constants_1 = require("./constants");
const crypto_1 = require("./crypto");
const utils_1 = require("./utils");
function createAuthService(db, config, userCount, limiters) {
    async function createSession(userId) {
        const rawToken = (0, crypto_1.randomHex)(32);
        await db.run("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)", [
            (0, crypto_1.sha256Hex)(rawToken),
            userId,
            Date.now() + constants_1.SESSION_TTL_MS,
        ]);
        return rawToken;
    }
    function extractToken(req) {
        const headerToken = req.get("x-admin-token")?.trim();
        if (headerToken)
            return headerToken;
        const authHeader = req.get("authorization")?.trim();
        if (authHeader && authHeader.toLowerCase().startsWith("bearer ")) {
            const bearer = authHeader.slice(7).trim();
            if (bearer)
                return bearer;
        }
        return undefined;
    }
    /** Returns the SSO identity if (and only if) the request legitimately came through the identity proxy. */
    function resolveSsoUser(req, cfg) {
        if (!cfg.ssoTrustProxyHeader)
            return null;
        // The identity proxy must prove who it is with the shared secret, compared in
        // constant time. Without this anyone who can reach the gateway directly could
        // forge the identity headers. No secret configured means the headers are not trusted.
        if (!cfg.ssoSharedSecret)
            return null;
        const supplied = req.get(constants_1.SSO_SECRET_HEADER) ?? "";
        if (!(0, crypto_1.safeEqualStrings)(supplied, cfg.ssoSharedSecret))
            return null;
        const rawUser = req.get(cfg.ssoUserHeader)?.trim();
        if (!rawUser || !constants_1.SSO_USERNAME_REGEX.test(rawUser))
            return null;
        const rawRole = req.get(cfg.ssoRoleHeader)?.trim().toLowerCase();
        const role = rawRole === "admin" ? "admin" : "viewer";
        return { id: 0, username: rawUser, role, mustChangePassword: false, sso: true };
    }
    async function resolveRequestAuth(req) {
        const cfg = config.load();
        const { adminToken, viewerToken, configCorrupted } = config.resolveStaticTokens();
        const usersTotal = await userCount.get();
        const ssoActive = cfg.ssoTrustProxyHeader;
        // 1. Enterprise reverse-proxy SSO header passthrough
        const ssoUser = resolveSsoUser(req, cfg);
        if (ssoUser) {
            return { user: ssoUser, needsSetup: false, ssoActive, configCorrupted };
        }
        // 2. Session token (SQLite sessions joined with users)
        const token = extractToken(req);
        if (token) {
            const tokenHash = (0, crypto_1.sha256Hex)(token);
            const sessionRow = await db.get(`SELECT s.token_hash, s.expires_at, u.id, u.username, u.role, u.must_change_password
         FROM sessions s
         JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = ?`, [tokenHash]);
            if (sessionRow) {
                if (sessionRow.expires_at > Date.now()) {
                    // Sliding 24h session extension, written at most once per SESSION_TOUCH_INTERVAL_MS
                    // (otherwise every polling request from the dashboard would be a DB write).
                    const now = Date.now();
                    if (sessionRow.expires_at - now < constants_1.SESSION_TTL_MS - constants_1.SESSION_TOUCH_INTERVAL_MS) {
                        await db
                            .run("UPDATE sessions SET expires_at = ? WHERE token_hash = ?", [now + constants_1.SESSION_TTL_MS, tokenHash])
                            .catch(() => undefined);
                    }
                    return {
                        user: {
                            id: sessionRow.id,
                            username: sessionRow.username,
                            role: sessionRow.role,
                            mustChangePassword: Boolean(sessionRow.must_change_password),
                        },
                        sessionTokenHash: tokenHash,
                        needsSetup: false,
                        ssoActive,
                        configCorrupted,
                    };
                }
                await db.run("DELETE FROM sessions WHERE token_hash = ?", [tokenHash]).catch(() => undefined);
            }
            // 3. Optional static env/config token (CI scripts, headless automation).
            //    Wrong guesses are counted per IP and per IP + "static" so a long-lived
            //    token cannot be brute forced. Session tokens are 256-bit random and are
            //    not counted (an expired dashboard session is not an attack).
            const staticConfigured = Boolean(adminToken || viewerToken);
            const ip = (0, rateLimit_1.bucketIp)(req.ip ?? req.socket.remoteAddress ?? "unknown");
            const ipKey = ip;
            const tokenKey = `${ip}:static`;
            if (staticConfigured) {
                const lockIp = limiters.checkLoginLockout(ipKey);
                const lockTok = limiters.checkLoginLockout(tokenKey, constants_1.LOGIN_MAX_FAILURES_PER_USER);
                if (lockIp.locked || lockTok.locked) {
                    return {
                        user: null,
                        needsSetup: false,
                        ssoActive,
                        configCorrupted,
                        locked: { retryAfterSec: Math.max(lockIp.retryAfterSec, lockTok.retryAfterSec) },
                    };
                }
            }
            if (adminToken && (0, crypto_1.safeEqualStrings)(token, adminToken)) {
                return {
                    user: { id: -1, username: "api-token-admin", role: "admin", mustChangePassword: false },
                    needsSetup: false,
                    ssoActive,
                    configCorrupted,
                };
            }
            if (viewerToken && (0, crypto_1.safeEqualStrings)(token, viewerToken)) {
                return {
                    user: { id: -2, username: "api-token-viewer", role: "viewer", mustChangePassword: false },
                    needsSetup: false,
                    ssoActive,
                    configCorrupted,
                };
            }
            if (staticConfigured) {
                limiters.recordLoginFailure(ipKey);
                limiters.recordLoginFailure(tokenKey);
            }
        }
        const needsSetup = !configCorrupted && usersTotal === 0 && !adminToken && !viewerToken && !cfg.ssoTrustProxyHeader;
        return { user: null, needsSetup, ssoActive, configCorrupted };
    }
    async function middleware(req, res, next) {
        try {
            const resolved = await resolveRequestAuth(req);
            if (resolved.configCorrupted) {
                (0, utils_1.sendError)(res, 500, "Configuration Error", "config.json contains invalid JSON. Fix or delete config.json to continue.");
                return;
            }
            if (resolved.locked) {
                res.setHeader("Retry-After", String(resolved.locked.retryAfterSec));
                (0, utils_1.sendError)(res, 429, "Too Many Requests", "Too many failed token attempts. Please wait and try again.");
                return;
            }
            if (!resolved.user) {
                (0, utils_1.sendError)(res, 401, "Unauthorized", resolved.needsSetup
                    ? "Initial owner setup is required. Open the dashboard to create your admin account."
                    : "Please sign in to access the gateway console.", { authEnabled: true, needsSetup: resolved.needsSetup, role: "none" });
                return;
            }
            req.user = resolved.user;
            req.sessionTokenHash = resolved.sessionTokenHash;
            // Forced password reset: only change-password, logout and status are allowed.
            if (req.user.mustChangePassword) {
                const allowedDuringReset = (req.method === "POST" && (req.path === "/auth/change-password" || req.path === "/auth/logout")) ||
                    (req.method === "GET" && req.path === "/auth/status");
                if (!allowedDuringReset) {
                    (0, utils_1.sendError)(res, 403, "Password Reset Required", "You signed in with a one-time password. Please set a new permanent password first.", { mustChangePassword: true });
                    return;
                }
            }
            // Viewer read-only restriction
            if (req.user.role === "viewer") {
                const isSelfServiceAuth = req.method === "POST" && (req.path === "/auth/change-password" || req.path === "/auth/logout");
                const isReadMethod = req.method === "GET" || req.method === "HEAD";
                if (!isReadMethod && !isSelfServiceAuth) {
                    (0, utils_1.sendError)(res, 403, "Forbidden", "Read-only viewers cannot modify rules, settings, or approve actions.");
                    return;
                }
            }
            next();
        }
        catch (err) {
            console.error("Auth middleware error:", err);
            (0, utils_1.sendError)(res, 500, "Internal Server Error", "Authentication check failed.");
        }
    }
    function requireAdmin(req, res) {
        if (req.user?.role !== "admin") {
            (0, utils_1.sendError)(res, 403, "Forbidden", "Only administrators can manage team accounts.");
            return false;
        }
        return true;
    }
    return { createSession, resolveRequestAuth, middleware, requireAdmin };
}
