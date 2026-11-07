import type { Request, Response } from "express";
import {
  AGENT_KEY_PREFIX,
  HOPS_HEADER,
  HOP_BY_HOP,
  MAX_UPSTREAM_BYTES,
  NEVER_FORWARD,
  UPSTREAM_TIMEOUT_MS,
  WORKSPACE_KEY_PREFIX,
} from "./constants";
import type { GatewayConfig } from "./types";
import { extractBody, sendError } from "./utils";

const SKIP_RESPONSE_HEADERS = new Set([
  ...HOP_BY_HOP,
  "content-encoding",
  "content-length",
  "set-cookie",
]);

type FetchResponse = Awaited<ReturnType<typeof fetch>>;

export class UpstreamTooLargeError extends Error {
  constructor() {
    super(`The upstream response is larger than ${MAX_UPSTREAM_BYTES / (1024 * 1024)} MB.`);
    this.name = "UpstreamTooLargeError";
  }
}

/** Raised when the agent's own connection closes before the upstream answered. */
export class ClientAbortedError extends Error {
  constructor() {
    super("The client disconnected before the upstream responded.");
    this.name = "ClientAbortedError";
  }
}

export function isTimeoutError(err: unknown): boolean {
  const name = (err as { name?: unknown } | null)?.name;
  return name === "TimeoutError" || name === "AbortError";
}

/** Reads an upstream body, giving up (and cancelling the transfer) once it exceeds `max` bytes. */
export async function readCapped(upstream: FetchResponse, max: number = MAX_UPSTREAM_BYTES): Promise<Buffer> {
  const declared = Number(upstream.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > max) {
    await upstream.body?.cancel().catch(() => undefined);
    throw new UpstreamTooLargeError();
  }
  if (!upstream.body) return Buffer.alloc(0);

  const reader = upstream.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel().catch(() => undefined);
      throw new UpstreamTooLargeError();
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks);
}

export type InspectOutcome =
  | { action: "pass" }
  | { action: "modified"; body: Buffer }
  | { action: "block"; message: string; violations: unknown[] };

export interface ProxyOptions {
  /** Path + query sent upstream. Default: req.originalUrl (workspace path prefixes are already stripped here). */
  forwardUrl?: string;
  /**
   * Outbound response guard: sees the complete, decompressed upstream body before the agent
   * does, and may replace it or withhold it (502 Response Policy Violation).
   */
  inspectResponse?: (status: number, contentType: string | null, body: Buffer) => Promise<InspectOutcome>;
}

/**
 * Forwards an ALLOWED request to targetUrl.
 *
 * Fail-closed behaviour:
 *   - Nothing is sent upstream if the client has already disconnected.
 *   - If the client disconnects while the upstream call is in flight, the upstream call is aborted.
 *   - The whole upstream response is read (and size-capped) BEFORE any status or header is
 *     written, so an upstream that dies mid-response becomes a clean 502/504, never a
 *     truncated 200 that an agent could mistake for success. That is also what lets the
 *     response guard inspect it.
 */
export async function proxyToTarget(
  req: Request,
  res: Response,
  targetUrl: string,
  config: GatewayConfig,
  options: ProxyOptions = {}
): Promise<void> {
  const url = targetUrl + (options.forwardUrl ?? req.originalUrl);

  // Identity headers (the standard ones plus whatever this install configured for
  // SSO) and gateway credentials are removed, so the upstream never sees a value
  // a caller could have forged or a secret that was meant for the gateway.
  const strip = new Set<string>([...NEVER_FORWARD, config.ssoUserHeader, config.ssoRoleHeader]);

  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    const k = key.toLowerCase();
    if (value === undefined || HOP_BY_HOP.has(k) || strip.has(k)) continue;
    const v = Array.isArray(value) ? value.join(", ") : (value as string);
    // "Authorization: Bearer agk_... / mws_..." is the gateway's own credential, not the upstream's.
    if (k === "authorization" && (v.toLowerCase().startsWith(`bearer ${AGENT_KEY_PREFIX}`) || v.toLowerCase().startsWith(`bearer ${WORKSPACE_KEY_PREFIX}`))) continue;
    headers.set(k, v);
  }

  // Loop guard: each hop through a gateway adds one; the interceptor rejects at MAX_HOPS.
  const hops = Number.parseInt(req.get(HOPS_HEADER) ?? "0", 10);
  headers.set(HOPS_HEADER, String((Number.isFinite(hops) && hops > 0 ? hops : 0) + 1));

  const body = extractBody(req);

  // Abort the upstream call if the agent goes away mid-request.
  const clientAbort = new AbortController();
  const onClose = (): void => {
    if (!res.writableFinished) clientAbort.abort(new ClientAbortedError());
  };
  res.once("close", onClose);

  // req.destroyed is true once the body was consumed, so check the socket instead.
  const clientGone = (): boolean => Boolean(req.socket?.destroyed) || res.destroyed || res.headersSent || res.writableEnded;
  if (clientGone()) {
    res.off("close", onClose);
    return;
  }

  try {
    const upstream = await fetch(url, {
      method: req.method,
      headers,
      body: body ?? undefined,
      redirect: "manual",
      signal: AbortSignal.any([AbortSignal.timeout(UPSTREAM_TIMEOUT_MS), clientAbort.signal]),
    });

    // Read (and size-check) the whole body before committing to a status, so an
    // oversized or broken response can still become a clean 502/504.
    let payload = await readCapped(upstream);
    let guarded: "scrubbed" | null = null;
    if (options.inspectResponse) {
      const verdict = await options.inspectResponse(upstream.status, upstream.headers.get("content-type"), payload);
      if (verdict.action === "block") {
        if (clientGone()) return;
        res.setHeader("x-mont-response-guard", "blocked");
        sendError(res, 502, "Response Policy Violation", verdict.message, { violations: verdict.violations });
        return;
      }
      if (verdict.action === "modified") {
        payload = verdict.body;
        guarded = "scrubbed";
      }
    }

    if (clientGone()) return;
    res.status(upstream.status);
    upstream.headers.forEach((value: string, key: string) => {
      const k = key.toLowerCase();
      if (SKIP_RESPONSE_HEADERS.has(k)) return;
      // A changed body invalidates validators computed over the original bytes.
      if (guarded && (k === "etag" || k === "content-md5" || k === "digest")) return;
      res.setHeader(key, value);
    });
    if (guarded) res.setHeader("x-mont-response-guard", guarded);
    const withCookies = upstream.headers as Headers & { getSetCookie?: () => string[] };
    const cookies = withCookies.getSetCookie?.() ?? [];
    if (cookies.length > 0) res.setHeader("set-cookie", cookies);

    res.send(payload);
  } catch (err) {
    if (clientAbort.signal.aborted) {
      console.error("Proxy aborted: the client disconnected mid-request:", url);
      if (!res.headersSent) res.destroy();
      return;
    }
    if (res.headersSent) {
      res.destroy();
      return;
    }
    if (isTimeoutError(err)) {
      console.error("Proxy timeout:", url);
      sendError(res, 504, "Gateway Timeout", "The target server did not respond in time.");
    } else if (err instanceof UpstreamTooLargeError) {
      sendError(res, 502, "Bad Gateway", err.message);
    } else {
      console.error("Proxy error:", err);
      sendError(res, 502, "Bad Gateway", "Could not reach the target server, or it failed mid-response.");
    }
  } finally {
    res.off("close", onClose);
  }
}
