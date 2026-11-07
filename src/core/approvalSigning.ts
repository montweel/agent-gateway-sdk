import crypto from "crypto";
import { APPROVAL_CALLBACK_PREFIX } from "./constants";

/**
 * HMAC-SHA256 signed one-click approval links.
 *
 * The MAC covers: version, action id, decision, expiry, and the action's queued-at
 * timestamp (looked up server-side, never in the URL). Binding the timestamp means a
 * link can only ever act on the exact row it was issued for, even if ids are reused.
 * Links are effectively single-use: once an action is decided it is no longer PENDING.
 */
export type CallbackDecision = "APPROVE" | "REJECT";

export interface SignedLinkFields {
  id: number;
  decision: CallbackDecision;
  /** Expiry, unix ms. */
  exp: number;
  /** pending_actions.timestamp of the action. */
  queuedAt: string;
}

function mac(secret: string, f: SignedLinkFields): Buffer {
  const message = `mont-approval:v1:${f.id}:${f.decision}:${f.exp}:${f.queuedAt}`;
  return crypto.createHmac("sha256", Buffer.from(secret, "hex")).update(message, "utf8").digest();
}

export function signApprovalLink(secret: string, fields: SignedLinkFields): string {
  return mac(secret, fields).toString("base64url");
}

export type VerifyResult = { ok: true } | { ok: false; reason: "malformed" | "expired" | "bad_signature" };

export function verifyApprovalLink(secret: string, fields: SignedLinkFields, signature: string, now = Date.now()): VerifyResult {
  if (
    // id 0 is the Setup tab's test notification: it verifies but never matches an action.
    !Number.isInteger(fields.id) ||
    fields.id < 0 ||
    (fields.decision !== "APPROVE" && fields.decision !== "REJECT") ||
    !Number.isInteger(fields.exp) ||
    typeof signature !== "string" ||
    !/^[A-Za-z0-9_-]{43}$/.test(signature)
  ) {
    return { ok: false, reason: "malformed" };
  }
  const expected = mac(secret, fields);
  const supplied = Buffer.from(signature, "base64url");
  // Reject non-canonical encodings (the last base64 char carries 2 padding bits), so each MAC has exactly one valid spelling.
  if (supplied.toString("base64url") !== signature) return { ok: false, reason: "malformed" };
  // Check the signature before the expiry so a forged link never learns anything from timing or messages.
  if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) {
    return { ok: false, reason: "bad_signature" };
  }
  if (fields.exp <= now) return { ok: false, reason: "expired" };
  return { ok: true };
}

export function parseCallbackDecision(value: unknown): CallbackDecision | null {
  if (value === "APPROVE" || value === "REJECT") return value;
  return null;
}

// ---------------------------------------------------------------------------
// In-chat button tokens (Telegram callback_data / Slack button value).
// Format: "mont:<A|R>:<id>:<mac>" where mac = first 22 base64url chars (132 bits) of
// HMAC-SHA256(secret, "mont-button:v1:<id>:<decision>:<queuedAt>"). At most ~45 bytes,
// inside Telegram's 64-byte callback_data limit. Bound to the exact queued row.
// ---------------------------------------------------------------------------
const BUTTON_MAC_CHARS = 22;

function buttonMac(secret: string, id: number, decision: CallbackDecision, queuedAt: string): string {
  return crypto
    .createHmac("sha256", Buffer.from(secret, "hex"))
    .update(`mont-button:v1:${id}:${decision}:${queuedAt}`, "utf8")
    .digest("base64url")
    .slice(0, BUTTON_MAC_CHARS);
}

export function signButtonToken(secret: string, id: number, decision: CallbackDecision, queuedAt: string): string {
  return `mont:${decision === "APPROVE" ? "A" : "R"}:${id}:${buttonMac(secret, id, decision, queuedAt)}`;
}

/** Parses a token without trusting it. Verify with verifyButtonToken once the row's queuedAt is known. */
export function parseButtonToken(token: unknown): { id: number; decision: CallbackDecision; mac: string } | null {
  if (typeof token !== "string") return null;
  const m = /^mont:([AR]):(\d{1,10}):([A-Za-z0-9_-]{22})$/.exec(token);
  if (!m) return null;
  const id = Number(m[2]);
  if (!Number.isSafeInteger(id) || id < 1) return null;
  return { id, decision: m[1] === "A" ? "APPROVE" : "REJECT", mac: m[3] };
}

export function verifyButtonToken(secret: string, parsed: { id: number; decision: CallbackDecision; mac: string }, queuedAt: string): boolean {
  const expected = Buffer.from(buttonMac(secret, parsed.id, parsed.decision, queuedAt));
  const supplied = Buffer.from(parsed.mac);
  return supplied.length === expected.length && crypto.timingSafeEqual(supplied, expected);
}

/** Full confirmation URL, e.g. https://gw.example.com/_mont/approvals/12/confirm?d=APPROVE&exp=...&sig=... */
export function buildApprovalLink(publicBaseUrl: string, secret: string, fields: SignedLinkFields): string {
  const base = publicBaseUrl.replace(/\/+$/, "");
  const sig = signApprovalLink(secret, fields);
  const params = new URLSearchParams({ d: fields.decision, exp: String(fields.exp), sig });
  return `${base}${APPROVAL_CALLBACK_PREFIX}/${fields.id}/confirm?${params.toString()}`;
}
