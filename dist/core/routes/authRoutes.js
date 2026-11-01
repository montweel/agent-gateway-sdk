"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.registerPublicAuthRoutes = registerPublicAuthRoutes;
exports.registerSelfServiceRoutes = registerSelfServiceRoutes;
const constants_1 = require("../constants");
const crypto_1 = require("../crypto");
const rateLimit_1 = require("../rateLimit");
const utils_1 = require("../utils");
const USERNAME_HELP = "Username must be 2–64 characters and contain only letters, numbers, '.', '_', '@', or '-'.";
function clientIp(req) {
    return (0, rateLimit_1.bucketIp)(req.ip ?? req.socket.remoteAddress ?? "unknown");
}
/**
 * True only for a direct connection from this machine. The socket address is
 * used (not req.ip) and any forwarding header disqualifies the request: behind
 * a reverse proxy on the same host every remote client would otherwise look
 * like 127.0.0.1 and skip the setup key.
 */
function isLoopbackRequest(req) {
    if (req.get("x-forwarded-for") || req.get("forwarded") || req.get("x-real-ip"))
        return false;
    const addr = req.socket.remoteAddress ?? "";
    return addr === "127.0.0.1" || addr === "::1" || addr === "::ffff:127.0.0.1";
}
/** Routes reachable WITHOUT a session: status, first-boot setup, login. */
function registerPublicAuthRoutes(router, ctx) {
    const { db, auth, limiters, userCount, setup } = ctx;
    router.get("/auth/status", async (req, res) => {
        try {
            const resolved = await auth.resolveRequestAuth(req);
            if (resolved.configCorrupted) {
                (0, utils_1.sendError)(res, 500, "Configuration Error", "config.json contains invalid JSON. Fix or delete config.json to continue.");
                return;
            }
            // Remote callers must present the key printed in the server console;
            // a caller on the same machine does not need it.
            const requiresSetupToken = resolved.needsSetup && !isLoopbackRequest(req);
            res.json({
                needsSetup: resolved.needsSetup,
                requiresSetupToken,
                setupTokenRequired: requiresSetupToken, // older dashboards read this name
                authenticated: resolved.user !== null,
                user: resolved.user ?? undefined,
                ssoActive: resolved.ssoActive,
            });
        }
        catch (err) {
            (0, utils_1.sendInternalError)(res, "Auth status error", err, "Could not check authentication status.");
        }
    });
    // First-boot owner creation. Only possible while the gateway has no users, no
    // static tokens and no SSO, i.e. exactly when the dashboard offers setup.
    router.post("/auth/setup", async (req, res) => {
        try {
            const resolved = await auth.resolveRequestAuth(req);
            if (!resolved.needsSetup) {
                (0, utils_1.sendError)(res, 409, "Conflict", "Initial owner setup is not available. Please sign in.");
                return;
            }
            const body = req.body;
            if (!isLoopbackRequest(req)) {
                // Wrong guesses are throttled like passwords are.
                const key = `setup:${clientIp(req)}`;
                const lock = limiters.checkLoginLockout(key);
                if (lock.locked) {
                    res.setHeader("Retry-After", String(lock.retryAfterSec));
                    (0, utils_1.sendError)(res, 429, "Too Many Requests", "Too many setup attempts. Please wait and try again.");
                    return;
                }
                const expected = setup.token;
                const supplied = typeof body?.setupToken === "string" ? body.setupToken.trim() : (req.get(constants_1.SETUP_TOKEN_HEADER) ?? "").trim();
                if (!expected || !supplied || !(0, crypto_1.safeEqualStrings)(supplied, expected)) {
                    limiters.recordLoginFailure(key);
                    (0, utils_1.sendError)(res, 403, "Forbidden", "A valid setup key is required. It is printed in the server console when the gateway starts.");
                    return;
                }
            }
            const username = typeof body?.username === "string" ? body.username.trim() : "";
            const password = typeof body?.password === "string" ? body.password : "";
            if (!constants_1.USERNAME_REGEX.test(username)) {
                (0, utils_1.sendError)(res, 400, "Bad Request", USERNAME_HELP);
                return;
            }
            if (password.length < 8 || password.length > 128) {
                (0, utils_1.sendError)(res, 400, "Bad Request", "Password must be between 8 and 128 characters.");
                return;
            }
            const passwordHash = await (0, crypto_1.hashPassword)(password);
            // Atomic: the row is only inserted if the table is still empty, so two
            // simultaneous setup calls cannot both become owner.
            let inserted;
            try {
                inserted = await db.run(`INSERT INTO users (username, password_hash, role, must_change_password, created_at)
           SELECT ?, ?, 'admin', 0, ? WHERE NOT EXISTS (SELECT 1 FROM users)`, [username, passwordHash, new Date().toISOString()]);
            }
            catch {
                (0, utils_1.sendError)(res, 409, "Conflict", "Owner account was already created.");
                return;
            }
            if (inserted.changes === 0) {
                (0, utils_1.sendError)(res, 409, "Conflict", "Owner account was already created.");
                return;
            }
            userCount.invalidate();
            setup.token = undefined; // the key has done its job
            const token = await auth.createSession(inserted.lastID);
            res.status(201).json({
                success: true,
                token,
                user: { id: inserted.lastID, username, role: "admin", mustChangePassword: false },
            });
        }
        catch (err) {
            (0, utils_1.sendInternalError)(res, "Setup error", err, "Could not create owner account.");
        }
    });
    router.post("/auth/login", async (req, res) => {
        try {
            const ip = clientIp(req);
            const body = req.body;
            const username = typeof body?.username === "string" ? body.username.trim() : "";
            const password = typeof body?.password === "string" ? body.password : "";
            if (!username || !password || password.length > 1024) {
                (0, utils_1.sendError)(res, 400, "Bad Request", "Username and password are required.");
                return;
            }
            // Two counters: one per IP (stops password spraying across many usernames)
            // and one per IP + username (stops hammering one account).
            const userKey = `${ip}:${username.toLowerCase()}`;
            const lockIp = limiters.checkLoginLockout(ip);
            const lockUser = limiters.checkLoginLockout(userKey, constants_1.LOGIN_MAX_FAILURES_PER_USER);
            if (lockIp.locked || lockUser.locked) {
                const wait = Math.max(lockIp.retryAfterSec, lockUser.retryAfterSec);
                res.setHeader("Retry-After", String(wait));
                (0, utils_1.sendError)(res, 429, "Too Many Requests", `Too many failed sign-in attempts. Please wait ${wait} seconds and try again.`);
                return;
            }
            const row = await db.get("SELECT * FROM users WHERE username = ?", [username]);
            let valid = false;
            if (row)
                valid = await (0, crypto_1.verifyPassword)(password, row.password_hash);
            else
                await (0, crypto_1.verifyAgainstDummy)(password); // same cost as a real check: no timing oracle
            if (!row || !valid) {
                limiters.recordLoginFailure(ip);
                limiters.recordLoginFailure(userKey);
                (0, utils_1.sendError)(res, 401, "Unauthorized", "Invalid username or password.");
                return;
            }
            // One-time passwords stop working after 24 hours (checked only after the
            // password matched, so it reveals nothing to a guesser).
            if (row.must_change_password && row.otp_expires_at !== null && row.otp_expires_at <= Date.now()) {
                (0, utils_1.sendError)(res, 401, "Unauthorized", "This one-time password has expired. Ask an administrator to reset your password.");
                return;
            }
            // Only the per-account counter is cleared. Clearing the IP counter would let
            // someone with one valid account reset their budget for guessing others.
            limiters.clearLoginFailures(userKey);
            const token = await auth.createSession(row.id);
            res.json({
                success: true,
                token,
                user: {
                    id: row.id,
                    username: row.username,
                    role: row.role,
                    mustChangePassword: Boolean(row.must_change_password),
                },
            });
        }
        catch (err) {
            (0, utils_1.sendInternalError)(res, "Login error", err, "Sign-in failed.");
        }
    });
}
/** Routes for any signed-in user: logout and change-password. */
function registerSelfServiceRoutes(router, ctx) {
    const { db, limiters } = ctx;
    router.post("/auth/logout", async (req, res) => {
        try {
            if (req.sessionTokenHash) {
                await db.run("DELETE FROM sessions WHERE token_hash = ?", [req.sessionTokenHash]);
            }
            res.json({ success: true });
        }
        catch (err) {
            (0, utils_1.sendInternalError)(res, "Logout error", err, "Could not sign out.");
        }
    });
    router.post("/auth/change-password", async (req, res) => {
        try {
            const user = req.user;
            if (user.id <= 0) {
                (0, utils_1.sendError)(res, 400, "Bad Request", "SSO or static API token accounts cannot change passwords inside the gateway.");
                return;
            }
            // Guessing the current password through a stolen session is still brute force: throttle it.
            const throttleKey = `pw:${user.id}`;
            const lock = limiters.checkLoginLockout(throttleKey);
            if (lock.locked) {
                res.setHeader("Retry-After", String(lock.retryAfterSec));
                (0, utils_1.sendError)(res, 429, "Too Many Requests", "Too many failed attempts. Please wait and try again.");
                return;
            }
            const body = req.body;
            const currentPassword = typeof body?.currentPassword === "string" ? body.currentPassword : "";
            const newPassword = typeof body?.newPassword === "string" ? body.newPassword : "";
            if (!currentPassword || !newPassword) {
                (0, utils_1.sendError)(res, 400, "Bad Request", "Both currentPassword and newPassword are required.");
                return;
            }
            if (newPassword.length < 8 || newPassword.length > 128) {
                (0, utils_1.sendError)(res, 400, "Bad Request", "New password must be between 8 and 128 characters.");
                return;
            }
            if (currentPassword === newPassword) {
                (0, utils_1.sendError)(res, 400, "Bad Request", "New password must be different from your current/temporary password.");
                return;
            }
            const row = await db.get("SELECT * FROM users WHERE id = ?", [user.id]);
            if (!row || !(await (0, crypto_1.verifyPassword)(currentPassword, row.password_hash))) {
                limiters.recordLoginFailure(throttleKey);
                (0, utils_1.sendError)(res, 401, "Unauthorized", "Current password is incorrect.");
                return;
            }
            limiters.clearLoginFailures(throttleKey);
            if (row.must_change_password && row.otp_expires_at !== null && row.otp_expires_at <= Date.now()) {
                (0, utils_1.sendError)(res, 401, "Unauthorized", "This one-time password has expired. Ask an administrator to reset it.");
                return;
            }
            const newHash = await (0, crypto_1.hashPassword)(newPassword);
            await db.run("UPDATE users SET password_hash = ?, must_change_password = 0, otp_expires_at = NULL WHERE id = ?", [newHash, user.id]);
            // Revoke every other session while keeping the current one alive.
            if (req.sessionTokenHash) {
                await db.run("DELETE FROM sessions WHERE user_id = ? AND token_hash != ?", [user.id, req.sessionTokenHash]);
            }
            res.json({
                success: true,
                user: { id: row.id, username: row.username, role: row.role, mustChangePassword: false },
            });
        }
        catch (err) {
            (0, utils_1.sendInternalError)(res, "Change password error", err, "Could not update password.");
        }
    });
}
