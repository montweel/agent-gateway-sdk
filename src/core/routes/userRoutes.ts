import type { Response, Router } from "express";
import type { GatewayContext } from "../context";
import type { AuthenticatedRequest, UserRole, UserRow } from "../types";
import { OTP_TTL_MS, USERNAME_REGEX } from "../constants";
import { generateTemporaryPassword, hashPassword } from "../crypto";
import { sendError, sendInternalError, sendProRequired } from "../utils";

const USERNAME_HELP = "Username must be 2–64 characters and contain only letters, numbers, '.', '_', '@', or '-'.";

function parseUserId(raw: string | string[] | undefined): number | null {
  if (typeof raw !== "string") return null;
  const id = Number(raw);
  return Number.isInteger(id) && id >= 1 ? id : null;
}

/** Team & user management. Every route is admin-only. */
export function registerUserRoutes(router: Router, ctx: GatewayContext): void {
  const { db, auth, userCount } = ctx;

  async function adminCount(): Promise<number> {
    const row = await db.get<{ count: number }>("SELECT COUNT(*) as count FROM users WHERE role = 'admin'");
    return row?.count ?? 0;
  }

  router.get("/users", async (req: AuthenticatedRequest, res: Response) => {
    if (!auth.requireAdmin(req, res)) return;
    try {
      const rows = await db.all<{
        id: number;
        username: string;
        role: UserRole;
        must_change_password: number;
        created_at: string;
      }>("SELECT id, username, role, must_change_password, created_at FROM users ORDER BY id ASC");

      res.json(
        rows.map((r) => ({
          id: r.id,
          username: r.username,
          role: r.role,
          mustChangePassword: Boolean(r.must_change_password),
          createdAt: r.created_at,
        }))
      );
    } catch (err) {
      sendInternalError(res, "List users error", err, "Could not load users.");
    }
  });

  router.post("/users", async (req: AuthenticatedRequest, res: Response) => {
    if (!auth.requireAdmin(req, res)) return;
    try {
      // Multi-user RBAC (extra Admin / Read-Only Auditor accounts) is a Team Pro feature.
      // Existing accounts keep working, and their roles stay enforced, if a license lapses.
      if (!(await ctx.license.isPro())) {
        sendProRequired(res, "multi-user RBAC (Admin & Read-Only Auditor accounts)");
        return;
      }
      const body = req.body as { username?: unknown; role?: unknown } | undefined;
      const username = typeof body?.username === "string" ? body.username.trim() : "";
      const role = body?.role;

      if (!USERNAME_REGEX.test(username)) {
        sendError(res, 400, "Bad Request", USERNAME_HELP);
        return;
      }
      if (role !== "admin" && role !== "viewer") {
        sendError(res, 400, "Bad Request", 'role must be "admin" or "viewer".');
        return;
      }

      const existing = await db.get<{ id: number }>("SELECT id FROM users WHERE username = ?", [username]);
      if (existing) {
        sendError(res, 409, "Conflict", `A user named "${username}" already exists.`);
        return;
      }

      const temporaryPassword = generateTemporaryPassword();
      const passwordHash = await hashPassword(temporaryPassword);
      const createdAt = new Date().toISOString();

      const inserted = await db.run(
        `INSERT INTO users (username, password_hash, role, must_change_password, otp_expires_at, created_at)
         VALUES (?, ?, ?, 1, ?, ?)`,
        [username, passwordHash, role, Date.now() + OTP_TTL_MS, createdAt]
      );
      userCount.invalidate();

      res.status(201).json({
        success: true,
        user: { id: inserted.lastID, username, role, mustChangePassword: true, createdAt },
        temporaryPassword,
        expiresInHours: OTP_TTL_MS / 3_600_000,
      });
    } catch (err) {
      sendInternalError(res, "Create user error", err, "Could not create user.");
    }
  });

  // Reset a user's password to a fresh one-time password and revoke their sessions
  router.post("/users/:id/reset-password", async (req: AuthenticatedRequest, res: Response) => {
    if (!auth.requireAdmin(req, res)) return;
    try {
      const targetId = parseUserId(req.params.id);
      if (targetId === null) {
        sendError(res, 400, "Bad Request", "Invalid user id.");
        return;
      }

      const target = await db.get<UserRow>("SELECT * FROM users WHERE id = ?", [targetId]);
      if (!target) {
        sendError(res, 404, "Not Found", "User not found.");
        return;
      }

      const temporaryPassword = generateTemporaryPassword();
      const passwordHash = await hashPassword(temporaryPassword);

      await db.run(
        "UPDATE users SET password_hash = ?, must_change_password = 1, otp_expires_at = ? WHERE id = ?",
        [passwordHash, Date.now() + OTP_TTL_MS, targetId]
      );
      await db.run("DELETE FROM sessions WHERE user_id = ?", [targetId]);

      res.json({
        success: true,
        id: target.id,
        username: target.username,
        temporaryPassword,
        expiresInHours: OTP_TTL_MS / 3_600_000,
      });
    } catch (err) {
      sendInternalError(res, "Reset password error", err, "Could not reset user password.");
    }
  });

  router.patch("/users/:id", async (req: AuthenticatedRequest, res: Response) => {
    if (!auth.requireAdmin(req, res)) return;
    try {
      const targetId = parseUserId(req.params.id);
      const role = (req.body as { role?: unknown } | undefined)?.role;
      if (targetId === null) {
        sendError(res, 400, "Bad Request", "Invalid user id.");
        return;
      }
      if (role !== "admin" && role !== "viewer") {
        sendError(res, 400, "Bad Request", 'role must be "admin" or "viewer".');
        return;
      }
      if (req.user?.id === targetId && role !== "admin") {
        sendError(res, 400, "Bad Request", "You cannot demote your own account.");
        return;
      }

      const target = await db.get<UserRow>("SELECT * FROM users WHERE id = ?", [targetId]);
      if (!target) {
        sendError(res, 404, "Not Found", "User not found.");
        return;
      }

      if (target.role === "admin" && role === "viewer" && (await adminCount()) <= 1) {
        sendError(res, 400, "Bad Request", "Cannot demote the last remaining administrator.");
        return;
      }

      await db.run("UPDATE users SET role = ? WHERE id = ?", [role, targetId]);
      res.json({
        success: true,
        user: {
          id: target.id,
          username: target.username,
          role,
          mustChangePassword: Boolean(target.must_change_password),
          createdAt: target.created_at,
        },
      });
    } catch (err) {
      sendInternalError(res, "Update user role error", err, "Could not update user role.");
    }
  });

  router.delete("/users/:id", async (req: AuthenticatedRequest, res: Response) => {
    if (!auth.requireAdmin(req, res)) return;
    try {
      const targetId = parseUserId(req.params.id);
      if (targetId === null) {
        sendError(res, 400, "Bad Request", "Invalid user id.");
        return;
      }
      if (req.user?.id === targetId) {
        sendError(res, 400, "Bad Request", "You cannot delete your own currently signed-in account.");
        return;
      }

      const target = await db.get<UserRow>("SELECT * FROM users WHERE id = ?", [targetId]);
      if (!target) {
        sendError(res, 404, "Not Found", "User not found.");
        return;
      }

      if (target.role === "admin" && (await adminCount()) <= 1) {
        sendError(res, 400, "Bad Request", "Cannot delete the last remaining administrator.");
        return;
      }

      await db.run("DELETE FROM sessions WHERE user_id = ?", [targetId]);
      await db.run("DELETE FROM users WHERE id = ?", [targetId]);
      userCount.invalidate();

      res.json({ success: true, id: targetId });
    } catch (err) {
      sendInternalError(res, "Delete user error", err, "Could not delete user.");
    }
  });
}
