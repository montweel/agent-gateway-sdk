import type { ResponseGuardSettings } from "./types";
import { REDACTED, isSecretKey, looksLikeCard, scrubSecrets } from "./redactor";

/**
 * Outbound exfiltration breaker. Inspects what an upstream API (or MCP tool) sends BACK before the
 * agent sees it, because a prompt-injected agent's goal is usually to read data out, not to write:
 *
 *   bulk dump   any JSON array longer than maxArrayItems (an agent coaxing "list customers" into
 *               returning 1,000 rows)                     -> block (502) or truncate
 *   secrets     API keys, bearer tokens, JWTs, private keys in well-known formats, Luhn-valid card
 *               numbers, and string values under secret-looking keys ("password", "api_key",
 *               "access_token", ...)                       -> scrub in-flight or block (502)
 *
 * Deterministic and pure: the same response and settings always give the same verdict. JSON
 * bodies are inspected structurally; text bodies are scanned for secrets; binary bodies pass.
 */

export interface ResponseFinding {
  kind: "large_array" | "secret";
  /** JSON path ("$.customers", "$.items[3].api_key") or "$" for text bodies. */
  path: string;
  /** Array length (large_array) or number of masked values (secret). */
  count: number;
}

export type ResponseVerdict =
  | { action: "pass"; findings: [] }
  | { action: "modified"; findings: ResponseFinding[]; body: Buffer }
  | { action: "block"; findings: ResponseFinding[] };

const MAX_FINDINGS = 50;
const PAGINATION_KEY = /page|cursor|continuation/i;
const MAX_DEPTH = 64;

/** Walks a parsed JSON value. Mutates nothing: returns a new value when something changed. */
export function inspectJsonValue(
  value: unknown,
  opts: Pick<ResponseGuardSettings, "maxArrayItems" | "onLargeArray">
): { value: unknown; findings: ResponseFinding[]; changed: boolean } {
  const findings: ResponseFinding[] = [];
  let changed = false;
  const note = (f: ResponseFinding): void => {
    if (findings.length < MAX_FINDINGS) findings.push(f);
  };

  function walk(v: unknown, path: string, key: string | null, depth: number): unknown {
    if (depth > MAX_DEPTH) return v;
    if (Array.isArray(v)) {
      let arr = v;
      if (arr.length > opts.maxArrayItems) {
        note({ kind: "large_array", path, count: arr.length });
        if (opts.onLargeArray === "truncate") {
          arr = arr.slice(0, opts.maxArrayItems);
          changed = true;
        }
      }
      let local = false;
      const out = arr.map((item, i) => {
        const next = walk(item, `${path}[${i}]`, key, depth + 1);
        if (next !== item) local = true;
        return next;
      });
      return local || arr !== v ? out : v;
    }
    if (typeof v === "object" && v !== null) {
      let local = false;
      const out: Record<string, unknown> = {};
      for (const [k, child] of Object.entries(v as Record<string, unknown>)) {
        const next = walk(child, `${path}.${k}`, k, depth + 1);
        if (next !== child) local = true;
        out[k] = next;
      }
      return local ? out : v;
    }
    if (typeof v === "string") {
      // A secret-looking key holding a credential-sized string (pagination cursors excepted:
      // "next_page_token" is not a credential and masking it would break paging).
      if (key !== null && isSecretKey(key) && !PAGINATION_KEY.test(key) && v.length >= 8) {
        note({ kind: "secret", path, count: 1 });
        changed = true;
        return REDACTED;
      }
      const s = scrubSecrets(v);
      if (s.hits > 0) {
        note({ kind: "secret", path, count: s.hits });
        changed = true;
        return s.text;
      }
      return v;
    }
    if (typeof v === "number" && Number.isSafeInteger(v) && looksLikeCard(String(Math.abs(v)))) {
      note({ kind: "secret", path, count: 1 });
      changed = true;
      return REDACTED;
    }
    return v;
  }

  const out = walk(value, "$", null, 0);
  return { value: out, findings, changed };
}

function decide(findings: ResponseFinding[], settings: ResponseGuardSettings): "block" | "modify" {
  const largeArray = findings.some((f) => f.kind === "large_array");
  const secret = findings.some((f) => f.kind === "secret");
  if (largeArray && settings.onLargeArray === "block") return "block";
  if (secret && settings.onSecret === "block") return "block";
  return "modify";
}

const isJsonType = (ct: string): boolean => /^application\/(?:[\w.+-]+\+)?json\b/i.test(ct) || /^application\/json/i.test(ct);
const isTextType = (ct: string): boolean => /^text\//i.test(ct) && !/^text\/event-stream/i.test(ct);

/** Inspects an HTTP response body (already fully buffered and decompressed). */
export function inspectResponseBody(contentType: string | null, body: Buffer, settings: ResponseGuardSettings): ResponseVerdict {
  if (!settings.enabled || body.length === 0) return { action: "pass", findings: [] };
  const ct = (contentType ?? "").toLowerCase();
  if (isJsonType(ct)) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(body.toString("utf8"));
    } catch {
      return inspectText(body, settings); // claims JSON but is not: still scan it for secrets
    }
    const r = inspectJsonValue(parsed, settings);
    if (r.findings.length === 0) return { action: "pass", findings: [] };
    if (decide(r.findings, settings) === "block") return { action: "block", findings: r.findings };
    return { action: "modified", findings: r.findings, body: Buffer.from(JSON.stringify(r.value), "utf8") };
  }
  if (isTextType(ct)) return inspectText(body, settings);
  return { action: "pass", findings: [] };
}

function inspectText(body: Buffer, settings: ResponseGuardSettings): ResponseVerdict {
  const s = scrubSecrets(body.toString("utf8"));
  if (s.hits === 0) return { action: "pass", findings: [] };
  const findings: ResponseFinding[] = [{ kind: "secret", path: "$", count: s.hits }];
  if (settings.onSecret === "block") return { action: "block", findings };
  return { action: "modified", findings, body: Buffer.from(s.text, "utf8") };
}

/** Inspects a JSON value (an MCP tool result). */
export function inspectValue(value: unknown, settings: ResponseGuardSettings): { action: "pass" | "modified" | "block"; findings: ResponseFinding[]; value: unknown } {
  if (!settings.enabled) return { action: "pass", findings: [], value };
  const r = inspectJsonValue(value, settings);
  if (r.findings.length === 0) return { action: "pass", findings: [], value };
  // JSON-encoded text inside MCP content blocks ({ type: "text", text: "[{...}, ...]" }) is checked too.
  if (decide(r.findings, settings) === "block") return { action: "block", findings: r.findings, value };
  return { action: "modified", findings: r.findings, value: r.value };
}

/**
 * MCP tool results usually carry their data as JSON text inside content blocks. Parses those
 * (when they are JSON) so a 1,000-row dump inside a text block is seen as an array too.
 */
export function inspectMcpResult(result: unknown, settings: ResponseGuardSettings): { action: "pass" | "modified" | "block"; findings: ResponseFinding[]; result: unknown } {
  if (!settings.enabled || typeof result !== "object" || result === null) return { action: "pass", findings: [], result };
  const r = result as Record<string, unknown>;
  const findings: ResponseFinding[] = [];
  let changed = false;
  let blocked = false;
  const next: Record<string, unknown> = { ...r };

  if (Array.isArray(r.content)) {
    next.content = r.content.map((block, i) => {
      if (typeof block !== "object" || block === null) return block;
      const b = block as Record<string, unknown>;
      if (b.type !== "text" || typeof b.text !== "string") {
        const v = inspectValue(b, settings);
        findings.push(...v.findings.map((f) => ({ ...f, path: f.path.replace(/^\$/, `$.content[${i}]`) })));
        if (v.action === "block") blocked = true;
        if (v.action === "modified") {
          changed = true;
          return v.value;
        }
        return block;
      }
      let parsed: unknown;
      let isJson = false;
      const trimmed = b.text.trim();
      if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
        try {
          parsed = JSON.parse(trimmed);
          isJson = true;
        } catch {
          isJson = false;
        }
      }
      if (isJson) {
        const v = inspectValue(parsed, settings);
        findings.push(...v.findings.map((f) => ({ ...f, path: f.path.replace(/^\$/, `$.content[${i}].text`) })));
        if (v.action === "block") blocked = true;
        if (v.action === "modified") {
          changed = true;
          return { ...b, text: JSON.stringify(v.value) };
        }
        return block;
      }
      const s = scrubSecrets(b.text);
      if (s.hits > 0) {
        findings.push({ kind: "secret", path: `$.content[${i}].text`, count: s.hits });
        if (settings.onSecret === "block") blocked = true;
        changed = true;
        return { ...b, text: s.text };
      }
      return block;
    });
  }
  if (r.structuredContent !== undefined) {
    const v = inspectValue(r.structuredContent, settings);
    findings.push(...v.findings.map((f) => ({ ...f, path: f.path.replace(/^\$/, "$.structuredContent") })));
    if (v.action === "block") blocked = true;
    if (v.action === "modified") {
      changed = true;
      next.structuredContent = v.value;
    }
  }
  if (findings.length === 0) return { action: "pass", findings: [], result };
  if (blocked) return { action: "block", findings, result };
  return { action: changed ? "modified" : "pass", findings, result: changed ? next : result };
}

export function describeFindings(findings: ResponseFinding[]): string {
  const arrays = findings.filter((f) => f.kind === "large_array");
  const secrets = findings.filter((f) => f.kind === "secret");
  const parts: string[] = [];
  if (arrays.length) parts.push(`bulk data (${arrays.map((a) => `${a.path}: ${a.count} items`).slice(0, 3).join(", ")})`);
  if (secrets.length) parts.push(`${secrets.reduce((n, s) => n + s.count, 0)} secret value(s) (${secrets.map((s) => s.path).slice(0, 3).join(", ")})`);
  return parts.join("; ");
}

export function validateResponseGuard(raw: unknown, current: ResponseGuardSettings): { ok: true; value: ResponseGuardSettings } | { ok: false; message: string } {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return { ok: false, message: "responseGuard must be an object." };
  const r = raw as Record<string, unknown>;
  const next = { ...current };
  if (r.enabled !== undefined) {
    if (typeof r.enabled !== "boolean") return { ok: false, message: "responseGuard.enabled must be true or false." };
    next.enabled = r.enabled;
  }
  if (r.maxArrayItems !== undefined) {
    if (!Number.isInteger(r.maxArrayItems) || (r.maxArrayItems as number) < 1 || (r.maxArrayItems as number) > 1_000_000) {
      return { ok: false, message: "responseGuard.maxArrayItems must be a whole number from 1 to 1,000,000." };
    }
    next.maxArrayItems = r.maxArrayItems as number;
  }
  if (r.onLargeArray !== undefined) {
    if (r.onLargeArray !== "block" && r.onLargeArray !== "truncate") return { ok: false, message: 'responseGuard.onLargeArray must be "block" or "truncate".' };
    next.onLargeArray = r.onLargeArray;
  }
  if (r.onSecret !== undefined) {
    if (r.onSecret !== "scrub" && r.onSecret !== "block") return { ok: false, message: 'responseGuard.onSecret must be "scrub" or "block".' };
    next.onSecret = r.onSecret;
  }
  return { ok: true, value: next };
}
