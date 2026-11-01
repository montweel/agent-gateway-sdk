import type { NextFunction, Request, Response } from "express";
import type { AuthenticatedRequest, AuthUser, SessionLookupRow, UserRole } from "./types";
import type { Db } from "./db";
import type { ConfigStore } from "./config";
import type { Limiters } from "./rateLimit";
import type { LicenseService } from "./license";
import type { UserCountCache } from "./userCount";
import { bucketIp } from "./rateLimit";
import {
  LOGIN_MAX_FAILURES_PER_USER,
  SESSION_TOUCH_INTERVAL_MS,
  SESSION_TTL_MS,
  SSO_SECRET_HEADER,
  SSO_USERNAME_REGEX,
} from "./constants";
import { randomHex, safeEqualStrings, sha256Hex } from "./crypto";
import { sendError } from "./utils";

export interface ResolvedAuth {
  user: AuthUser | null;
  sessionTokenHash?: string;
  needsSetup: boolean;
  ssoActive: boolean;
  configCorrupted: boolean;
  /** Set when too many wrong static tokens came from this client. */
  locked?: { retryAfterSec: number };
}

export interface AuthService {
  createSession(userId: number): Promise<string>;
  resolveRequestAuth(req: Request): Promise<ResolvedAuth>;
  /** Express middleware: authenticates, enforces password reset and viewer read-only rules. */
  middleware(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void>;
  /** Sends 403 and returns false when the caller is not an admin. */
  requireAdmin(req: AuthenticatedRequest, res: Response): boolean;
}

export function createAuthService(
  db: Db,
  config: ConfigStore,
  userCount: UserCountCache,
  limiters: Limiters,
  license: LicenseService
): AuthService {
  async function createSession(userId: number): Promise<string> {
    const rawToken = randomHex(32);
    await db.run("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)", [
      sha256Hex(rawToken),
      userId,
      Date.now() + SESSION_TTL_MS,
    ]);
    return rawToken;
  }

  function extractToken(req: Request): string | undefined {
    const headerToken = req.get("x-admin-token")?.trim();
    if (headerToken) return headerToken;
    const authHeader = req.get("authorization")?.trim();
    if (authHeader && authHeader.toLowerCase().startsWith("bearer ")) {
      const bearer = authHeader.slice(7).trim();
      if (bearer) return bearer;
    }
    return undefined;
  }

  /** Returns the SSO identity if (and only if) the request legitimately came through the identity proxy. */
  function resolveSsoUser(req: Request, cfg: ReturnType<ConfigStore["load"]>): AuthUser | null {
    if (!cfg.ssoTrustProxyHeader) return null;

    // The identity proxy must prove who it is with the shared secret, compared in
    // constant time. Without this anyone who can reach the gateway directly could
    // forge the identity headers. No secret configured means the headers are not trusted.
    if (!cfg.ssoSharedSecret) return null;
    const supplied = req.get(SSO_SECRET_HEADER) ?? "";
    if (!safeEqualStrings(supplied, cfg.ssoSharedSecret)) return null;

    const rawUser = req.get(cfg.ssoUserHeader)?.trim();
    if (!rawUser || !SSO_USERNAME_REGEX.test(rawUser)) return null;

    const rawRole = req.get(cfg.ssoRoleHeader)?.trim().toLowerCase();
    const role: UserRole = rawRole === "admin" ? "admin" : "viewer";
    return { id: 0, username: rawUser, role, mustChangePassword: false, sso: true };
  }

  async function resolveRequestAuth(req: Request): Promise<ResolvedAuth> {
    const cfg = config.load();
    const { adminToken, viewerToken, configCorrupted } = config.resolveStaticTokens();
    const usersTotal = await userCount.get();
    // Reverse-proxy SSO is a Team Pro feature: without an active trial or license the
    // identity headers are ignored and the gateway falls back to local accounts.
    const ssoActive = cfg.ssoTrustProxyHeader && (await license.isPro());

    // 1. Enterprise reverse-proxy SSO header passthrough
    const ssoUser = ssoActive ? resolveSsoUser(req, cfg) : null;
    if (ssoUser) {
      return { user: ssoUser, needsSetup: false, ssoActive, configCorrupted };
    }

    // 2. Session token (SQLite sessions joined with users)
    const token = extractToken(req);
    if (token) {
      const tokenHash = sha256Hex(token);
      const sessionRow = await db.get<SessionLookupRow>(
        `SELECT s.token_hash, s.expires_at, u.id, u.username, u.role, u.must_change_password
         FROM sessions s
         JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = ?`,
        [tokenHash]
      );

      if (sessionRow) {
        if (sessionRow.expires_at > Date.now()) {
          // Sliding 24h session extension, written at most once per SESSION_TOUCH_INTERVAL_MS
          // (otherwise every polling request from the dashboard would be a DB write).
          const now = Date.now();
          if (sessionRow.expires_at - now < SESSION_TTL_MS - SESSION_TOUCH_INTERVAL_MS) {
            await db
              .run("UPDATE sessions SET expires_at = ? WHERE token_hash = ?", [now + SESSION_TTL_MS, tokenHash])
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
      const ip = bucketIp(req.ip ?? req.socket.remoteAddress ?? "unknown");
      const ipKey = ip;
      const tokenKey = `${ip}:static`;
      if (staticConfigured) {
        const lockIp = limiters.checkLoginLockout(ipKey);
        const lockTok = limiters.checkLoginLockout(tokenKey, LOGIN_MAX_FAILURES_PER_USER);
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
      if (adminToken && safeEqualStrings(token, adminToken)) {
        return {
          user: { id: -1, username: "api-token-admin", role: "admin", mustChangePassword: false },
          needsSetup: false,
          ssoActive,
          configCorrupted,
        };
      }
      if (viewerToken && safeEqualStrings(token, viewerToken)) {
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

    const needsSetup = !configCorrupted && usersTotal === 0 && !adminToken && !viewerToken && !ssoActive;
    return { user: null, needsSetup, ssoActive, configCorrupted };
  }

  async function middleware(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const resolved = await resolveRequestAuth(req);
      if (resolved.configCorrupted) {
        sendError(
          res,
          500,
          "Configuration Error",
          "config.json contains invalid JSON. Fix or delete config.json to continue."
        );
        return;
      }

      if (resolved.locked) {
        res.setHeader("Retry-After", String(resolved.locked.retryAfterSec));
        sendError(res, 429, "Too Many Requests", "Too many failed token attempts. Please wait and try again.");
        return;
      }

      if (!resolved.user) {
        sendError(
          res,
          401,
          "Unauthorized",
          resolved.needsSetup
            ? "Initial owner setup is required. Open the dashboard to create your admin account."
            : "Please sign in to access the gateway console.",
          { authEnabled: true, needsSetup: resolved.needsSetup, role: "none" }
        );
        return;
      }

      req.user = resolved.user;
      req.sessionTokenHash = resolved.sessionTokenHash;

      // Forced password reset: only change-password, logout and status are allowed.
      if (req.user.mustChangePassword) {
        const allowedDuringReset =
          (req.method === "POST" && (req.path === "/auth/change-password" || req.path === "/auth/logout")) ||
          (req.method === "GET" && req.path === "/auth/status");

        if (!allowedDuringReset) {
          sendError(
            res,
            403,
            "Password Reset Required",
            "You signed in with a one-time password. Please set a new permanent password first.",
            { mustChangePassword: true }
          );
          return;
        }
      }

      // Viewer read-only restriction
      if (req.user.role === "viewer") {
        const isSelfServiceAuth =
          req.method === "POST" && (req.path === "/auth/change-password" || req.path === "/auth/logout");
        const isReadMethod = req.method === "GET" || req.method === "HEAD";

        if (!isReadMethod && !isSelfServiceAuth) {
          sendError(res, 403, "Forbidden", "Read-only viewers cannot modify rules, settings, or approve actions.");
          return;
        }
      }

      next();
    } catch (err) {
      console.error("Auth middleware error:", err);
      sendError(res, 500, "Internal Server Error", "Authentication check failed.");
    }
  }

  function requireAdmin(req: AuthenticatedRequest, res: Response): boolean {
    if (req.user?.role !== "admin") {
      sendError(res, 403, "Forbidden", "Only administrators can manage team accounts.");
      return false;
    }
    return true;
  }

  return { createSession, resolveRequestAuth, middleware, requireAdmin };
}
