import type { GatewayContext } from "./context";
import type { LogStatus } from "./types";
import {
  MAX_LOG_PATH_LENGTH,
  MAX_LOG_UA_LENGTH,
  MAX_PENDING_ACTIONS,
  MAX_PENDING_BODY_BYTES,
  MAX_PENDING_DISPLAY_CHARS,
  PENDING_TTL_MS,
} from "./constants";
import { encryptPayload } from "./crypto";
import { DbTimeoutError, redactQueryObject, redactQueryString, truncate, withTimeout } from "./utils";

/**
 * Audit logging and the approval queue, shared by the HTTP interceptor and the MCP tool guard.
 * Everything written here passes through ctx.redactor first: SQLite never holds a raw secret,
 * card number or (unless switched off) email / phone. The only unredacted copy of a queued
 * request is the AES-256-GCM encrypted replay payload, wiped as soon as the action is decided.
 */

/** Who sent the request, as far as the gateway can tell. */
export interface Caller {
  /** bucketIp() of the client address (IPv4 as is, IPv6 as its /64), or "stdio" for local MCP. */
  ip: string;
  userAgent: string;
  agentKeyName: string | null;
  agentKeyId: number | null;
  agentKeyPrefix: string | null;
}

export interface AuditEntry {
  method: string;
  path: string;
  status: LogStatus;
  caller: Caller | null;
  userAgent: string;
  actionId?: number | null;
  detail?: string | null;
  /** Money value of the request (body.amount etc.), for "money protected" totals. */
  amount?: number | null;
}

export interface Audit {
  /** Throws on failure (including timeouts). Use before anything is forwarded or queued. */
  logStrict(e: AuditEntry): Promise<void>;
  /** Best-effort, for refusals: the request is refused whether or not the row lands. */
  logRefusal(e: AuditEntry): Promise<void>;
}

export function createAudit(ctx: GatewayContext): Audit {
  async function logStrict(e: AuditEntry): Promise<void> {
    const write = ctx.db.run(
      `INSERT INTO agent_logs (timestamp, method, path, status, user_agent, agent_key, action_id, caller_ip, detail, amount)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        new Date().toISOString(),
        e.method,
        truncate(ctx.redactor.text(e.path), MAX_LOG_PATH_LENGTH),
        e.status,
        truncate(ctx.redactor.text(e.userAgent), MAX_LOG_UA_LENGTH),
        e.caller?.agentKeyName ?? null,
        e.actionId ?? null,
        e.caller?.ip ?? null,
        e.detail ? ctx.redactor.text(e.detail) : null,
        e.amount ?? null,
      ]
    );
    try {
      await withTimeout(write, ctx.dbTimeoutMs, "audit log write");
    } catch (err) {
      // The request is about to be refused. If the timed-out row still lands later, it must
      // not claim the request was ALLOWED/QUEUED.
      if (err instanceof DbTimeoutError && (e.status === "ALLOWED" || e.status === "QUEUED")) {
        write.then(
          (r) =>
            ctx.db
              .run("UPDATE agent_logs SET status = 'BLOCKED', detail = ? WHERE id = ?", [
                "Refused (fail-closed): the audit write timed out, so the request was not forwarded.",
                r.lastID,
              ])
              .catch(() => undefined),
          () => undefined
        );
      }
      throw err;
    }
  }

  async function logRefusal(e: AuditEntry): Promise<void> {
    try {
      await logStrict(e);
    } catch (err) {
      console.error("Failed to write log for a refused request:", err);
    }
  }

  return { logStrict, logRefusal };
}

export interface QueueRequest {
  kind: "http" | "mcp";
  method: string;
  /** Original path including the query string. Encrypted for replay; shown redacted. */
  originalPath: string;
  /** Path without query (audit log). */
  cleanPath: string;
  /** Original body text (JSON), encrypted for replay. */
  originalBody: string | null;
  query: unknown;
  headers: Record<string, string | string[] | undefined>;
  caller: Caller;
  agentReason: string | null;
  /** PolicyDecision.matched */
  matched: string;
  amount?: number | null;
}

export type QueueResult =
  | { ok: true; id: number; queuedAt: string; expiresAt: number }
  | { ok: false; status: number; error: string; message: string; retryAfter?: number };

export async function queuePending(ctx: GatewayContext, audit: Audit, q: QueueRequest): Promise<QueueResult> {
  const timed = <T>(p: Promise<T>, label: string): Promise<T> => withTimeout(p, ctx.dbTimeoutMs, label);
  const r = ctx.redactor;

  const pending = await timed(
    ctx.db.get<{ count: number }>("SELECT COUNT(*) as count FROM pending_actions WHERE status = 'PENDING'"),
    "approval queue count"
  );
  if ((pending?.count ?? 0) >= MAX_PENDING_ACTIONS) {
    await audit.logRefusal({ method: q.method, path: q.cleanPath, status: "BLOCKED", caller: q.caller, userAgent: q.caller.userAgent, detail: "approval queue full" });
    return { ok: false, status: 503, error: "Service Unavailable", message: "The approval queue is full. Try again later.", retryAfter: 60 };
  }

  // Queued requests are stored until decided, so cap their size.
  if (q.originalBody !== null && Buffer.byteLength(q.originalBody) > MAX_PENDING_BODY_BYTES) {
    await audit.logRefusal({ method: q.method, path: q.cleanPath, status: "BLOCKED", caller: q.caller, userAgent: q.caller.userAgent, detail: "approval body too large" });
    return {
      ok: false,
      status: 413,
      error: "Payload Too Large",
      message: `Requests that need approval can have a body of at most ${MAX_PENDING_BODY_BYTES / 1024} KB.`,
    };
  }

  const encryptedPayload = encryptPayload(JSON.stringify({ path: q.originalPath, body: q.originalBody }), ctx.config.replayEncryptionKey());
  const redactedBody = r.jsonText(q.originalBody);
  const displayBody =
    redactedBody !== null && redactedBody.length > MAX_PENDING_DISPLAY_CHARS
      ? `${redactedBody.slice(0, MAX_PENDING_DISPLAY_CHARS)}â€¦ [truncated]`
      : redactedBody;
  const query = r.json(redactQueryObject(q.query)) as Record<string, unknown>;
  const agentReason = q.agentReason ? r.text(q.agentReason) : null;
  const queuedAt = new Date().toISOString();
  const expiresAt = Date.now() + PENDING_TTL_MS;
  const displayPath = truncate(r.text(redactQueryString(q.originalPath)), MAX_LOG_PATH_LENGTH);
  const userAgent = truncate(r.text(q.caller.userAgent), MAX_LOG_UA_LENGTH);

  const insert = ctx.db.run(
    `INSERT INTO pending_actions
       (timestamp, method, path, headers, body, status, expires_at, agent_key, encrypted_payload,
        query_json, caller_ip, caller_ua, agent_key_id, agent_key_prefix, agent_reason, matched_policy, kind, owner)
     VALUES (?, ?, ?, ?, ?, 'PENDING', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      queuedAt,
      q.method,
      displayPath,
      JSON.stringify(r.headers(q.headers)),
      displayBody,
      expiresAt,
      q.caller.agentKeyName,
      encryptedPayload,
      JSON.stringify(query),
      q.caller.ip,
      userAgent,
      q.caller.agentKeyId,
      q.caller.agentKeyPrefix,
      agentReason,
      q.matched,
      q.kind,
      q.kind === "mcp" ? ctx.instanceId : null,
    ]
  );

  // If the insert outlives the timeout, or anything after it fails, the agent is told the
  // request failed, so the queued row must never be approvable: expire it when it lands.
  const discard = (id: number): void => {
    void ctx.db
      .run(
        "UPDATE pending_actions SET status = 'EXPIRED', encrypted_payload = NULL, response_preview = ? WHERE id = ? AND status = 'PENDING'",
        ["Discarded: the gateway failed while queueing this request and told the agent it was refused.", id]
      )
      .catch((err: unknown) => console.error("Could not discard a half-queued action:", err));
  };

  let inserted: { lastID: number };
  try {
    inserted = await timed(insert, "approval queue insert");
  } catch (err) {
    if (err instanceof DbTimeoutError) insert.then((res) => discard(res.lastID), () => undefined);
    throw err;
  }

  try {
    await audit.logStrict({
      method: q.method,
      path: q.cleanPath,
      status: "QUEUED",
      caller: q.caller,
      userAgent: q.caller.userAgent,
      actionId: inserted.lastID,
      detail: q.kind === "mcp" ? `mcp ${q.matched}` : q.matched,
      amount: q.amount ?? null,
    });
  } catch (err) {
    discard(inserted.lastID);
    throw err;
  }

  // Phone / chat notifications. Fire-and-forget: they can never change the outcome.
  void ctx.notifier.notifyPending({
    id: inserted.lastID,
    queuedAt,
    expiresAt,
    method: q.method,
    path: displayPath,
    body: displayBody,
    query,
    callerIp: q.caller.ip,
    callerUa: userAgent,
    agentKey: q.caller.agentKeyName,
    agentKeyPrefix: q.caller.agentKeyPrefix,
    agentReason,
    matchedPolicy: q.matched,
  });

  return { ok: true, id: inserted.lastID, queuedAt, expiresAt };
}

/** Marks an action that is no longer queued-for-real (agent gone, error after insert) as EXPIRED. */
export function discardPending(ctx: GatewayContext, id: number, reason: string): Promise<void> {
  return ctx.db
    .run(
      "UPDATE pending_actions SET status = 'EXPIRED', encrypted_payload = NULL, response_preview = ? WHERE id = ? AND status = 'PENDING'",
      [reason, id]
    )
    .then(() => undefined);
}
