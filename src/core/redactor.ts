/**
 * Deterministic PII & secret scrubber.
 *
 * Every value the gateway STORES (SQLite: pending_actions, agent_logs) or SENDS to a third
 * party (Slack, Telegram, webhooks, rollback webhook, confirmation pages) goes through this
 * module first. Policy evaluation and approved replays use the original request, which only
 * ever exists in memory or AES-256-GCM encrypted.
 *
 * Always redacted:
 *   - headers: Authorization, Proxy-Authorization, Cookie, Set-Cookie, X-Api-Key, X-Auth-Token,
 *     X-Agent-Key, X-Admin-Token, CSRF / AWS session tokens, gateway-internal headers
 *   - JSON keys containing password, secret, token, api key, authorization, cookie, cvv/cvc,
 *     card number, private/access key, session id; keys equal to pin, ssn, pan
 *   - card numbers anywhere in strings or numbers (13-19 digits, Luhn-valid)
 *   - well-known credential formats in any string: Bearer tokens, JWTs, Stripe sk_/rk_ keys,
 *     GitHub ghp_/gho_/... tokens, Slack xox?-/xapp- tokens, AWS AKIA keys, Telegram bot tokens,
 *     Mont agk_ keys
 * Toggleable (Gateway Setup -> Privacy, both on by default):
 *   - emails: j***@example.com (domain kept: it matters when judging an exfiltration attempt)
 *   - phones: [REDACTED:phone ••12] for phone-like keys and +E.164-style values
 *
 * Pure and deterministic: the same input and options always give the same output.
 */
import type { PrivacySettings } from "./types";

export const REDACTED = "[REDACTED]";
export const REDACTED_CARD = "[REDACTED:card]";
export const REDACTED_SECRET = "[REDACTED:secret]";

const MAX_DEPTH = 20;

// Matched after lower-casing and removing "_", "-" and ".".
const SECRET_KEY_SUBSTRINGS = [
  "password",
  "passwd",
  "secret",
  "token",
  "apikey",
  "authorization",
  "cookie",
  "cvv",
  "cvc",
  "cardnumber",
  "creditcard",
  "privatekey",
  "accesskey",
  "sessionid",
  "signature",
];
const SECRET_KEY_EXACT = new Set(["pin", "ssn", "pan", "auth", "otp", "card"]);
const EMAIL_KEY = /^(?:mail|.*email.*)$/;
const PHONE_KEY_SUBSTRINGS = ["phone", "mobile", "msisdn", "whatsapp", "cellnumber", "telephone"];
const PHONE_KEY_EXACT = new Set(["tel", "cell", "fax"]);

const SECRET_HEADERS = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
  "x-api-key",
  "x-auth-token",
  "x-agent-key",
  "x-admin-token",
  "x-csrf-token",
  "x-xsrf-token",
  "x-amz-security-token",
  "x-gateway-sso-secret",
  "x-gateway-internal-replay",
  "x-setup-token",
]);
const DROPPED_HEADERS = new Set(["connection", "keep-alive", "te", "trailer", "transfer-encoding", "upgrade", "content-length"]);

const SECRET_PATTERNS: RegExp[] = [
  /\bBearer\s+[A-Za-z0-9._~+/-]{8,}=*/gi,
  /\bBasic\s+[A-Za-z0-9+/]{8,}=*/g,
  /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}/g, // JWT
  /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{8,}/g, // Stripe secret / restricted keys
  /\bwhsec_[A-Za-z0-9]{16,}/g, // Stripe webhook secrets
  /\bgh[pousr]_[A-Za-z0-9]{20,}/g, // GitHub tokens
  /\bgithub_pat_[A-Za-z0-9_]{20,}/g,
  /\bxox[abposr]-[A-Za-z0-9-]{10,}/g, // Slack tokens
  /\bxapp-[A-Za-z0-9-]{10,}/g,
  /\bAKIA[0-9A-Z]{16}\b/g, // AWS access key id
  /\b\d{6,12}:[A-Za-z0-9_-]{30,}\b/g, // Telegram bot token
  /\bagk_[A-Za-z0-9]{8,}/g, // Mont agent keys
  /\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}/g, // OpenAI / Anthropic style keys
];

// 13-19 digits, optionally grouped with single spaces or dashes.
const CARD_CANDIDATE = /(?<![\d.])\d(?:[ -]?\d){12,18}(?![\d.])/g;
const EMAIL_VALUE = /([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})/g;
// The same address percent-encoded inside a URL (jane%40example.com).
const EMAIL_VALUE_ENCODED = /([A-Za-z0-9._+-])[A-Za-z0-9._+-]*%40([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})/gi;
// International-format numbers: a "+" then 8-15 digits with optional separators.
const PHONE_VALUE = /(?<![\w+])\+\d(?:[\s().-]?\d){7,14}(?!\d)/g;

export function luhnValid(digits: string): boolean {
  if (!/^\d{13,19}$/.test(digits)) return false;
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

/** Luhn-valid AND starts with a real card network prefix (2-6), so ms timestamps (1…) never match. */
export function looksLikeCard(digits: string): boolean {
  return /^[2-6]/.test(digits) && luhnValid(digits);
}

/**
 * Secrets and card numbers only (no email / phone masking): what the outbound response guard
 * treats as "must never leave". Returns the masked text and how many values were masked.
 */
export function scrubSecrets(value: string): { text: string; hits: number } {
  let hits = 0;
  let out = value;
  for (const re of SECRET_PATTERNS) {
    out = out.replace(re, () => {
      hits++;
      return REDACTED_SECRET;
    });
  }
  out = out.replace(CARD_CANDIDATE, (m) => {
    if (!looksLikeCard(m.replace(/[ -]/g, ""))) return m;
    hits++;
    return REDACTED_CARD;
  });
  return { text: out, hits };
}

function normKey(key: string): string {
  return key.toLowerCase().replace(/[_\-.\s]/g, "");
}

export function isSecretKey(key: string): boolean {
  const k = normKey(key);
  return SECRET_KEY_EXACT.has(k) || SECRET_KEY_SUBSTRINGS.some((s) => k.includes(s));
}

function isEmailKey(key: string): boolean {
  return EMAIL_KEY.test(normKey(key));
}

function isPhoneKey(key: string): boolean {
  const k = normKey(key);
  return PHONE_KEY_EXACT.has(k) || PHONE_KEY_SUBSTRINGS.some((s) => k.includes(s));
}

function maskPhone(value: string): string {
  const digits = value.replace(/\D/g, "");
  return digits.length >= 4 ? `[REDACTED:phone ••${digits.slice(-2)}]` : "[REDACTED:phone]";
}

export interface Redactor {
  /** Deep copy of a JSON value with secrets / PII masked. */
  json(value: unknown): unknown;
  /** Masks secrets / PII inside free text (paths, user agents, agent reasons, raw bodies). */
  text(value: string): string;
  /** Header map safe to store: credentials masked, hop-by-hop dropped, values scrubbed. */
  headers(headers: Record<string, string | string[] | undefined>): Record<string, string>;
  /** JSON text in, redacted JSON text out. Non-JSON text is scrubbed as free text. */
  jsonText(text: string | null): string | null;
}

export function createRedactor(options: () => PrivacySettings): Redactor {
  function text(value: string): string {
    const opts = options();
    let out = value;
    for (const re of SECRET_PATTERNS) out = out.replace(re, REDACTED_SECRET);
    out = out.replace(CARD_CANDIDATE, (m) => (looksLikeCard(m.replace(/[ -]/g, "")) ? REDACTED_CARD : m));
    if (opts.redactEmails) {
      out = out.replace(EMAIL_VALUE, (_m, first: string, domain: string) => `${first}***@${domain}`);
      out = out.replace(EMAIL_VALUE_ENCODED, (_m, first: string, domain: string) => `${first}***%40${domain}`);
    }
    if (opts.redactPhones) out = out.replace(PHONE_VALUE, (m) => maskPhone(m));
    return out;
  }

  function scalar(value: unknown, key: string | null): unknown {
    const opts = options();
    if (key !== null) {
      if (isSecretKey(key)) return value === null || value === "" ? value : REDACTED;
      if (opts.redactPhones && isPhoneKey(key) && (typeof value === "string" || typeof value === "number")) {
        return maskPhone(String(value));
      }
      if (opts.redactEmails && isEmailKey(key) && typeof value === "string" && !value.includes("@")) {
        // An "email" field that is not an address still is the customer's identifier; keep it masked.
        return value === "" ? value : REDACTED;
      }
    }
    if (typeof value === "string") return text(value);
    if (typeof value === "number" && Number.isSafeInteger(value) && looksLikeCard(String(Math.abs(value)))) return REDACTED_CARD;
    return value;
  }

  function walk(value: unknown, key: string | null, depth: number): unknown {
    if (depth > MAX_DEPTH) return REDACTED;
    if (Array.isArray(value)) {
      if (key !== null && isSecretKey(key)) return REDACTED;
      return value.map((v) => walk(v, key, depth + 1));
    }
    if (typeof value === "object" && value !== null) {
      if (key !== null && isSecretKey(key)) return REDACTED;
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) out[k] = walk(v, k, depth + 1);
      return out;
    }
    return scalar(value, key);
  }

  function headers(h: Record<string, string | string[] | undefined>): Record<string, string> {
    const out: Record<string, string> = {};
    for (const [rawKey, v] of Object.entries(h)) {
      if (v === undefined) continue;
      const k = rawKey.toLowerCase();
      if (DROPPED_HEADERS.has(k)) continue;
      const value = Array.isArray(v) ? v.join(", ") : v;
      out[k] = SECRET_HEADERS.has(k) || isSecretKey(k) ? REDACTED : text(value);
    }
    return out;
  }

  function jsonText(t: string | null): string | null {
    if (t === null) return null;
    try {
      return JSON.stringify(walk(JSON.parse(t), null, 0));
    } catch {
      return text(t);
    }
  }

  return { json: (v) => walk(v, null, 0), text, headers, jsonText };
}
