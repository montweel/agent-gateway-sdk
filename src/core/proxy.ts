import type { Request, Response } from "express";
import {
  AGENT_KEY_PREFIX,
  HOPS_HEADER,
  HOP_BY_HOP,
  MAX_UPSTREAM_BYTES,
  NEVER_FORWARD,
  UPSTREAM_TIMEOUT_MS,
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

export async function proxyToTarget(
  req: Request,
  res: Response,
  targetUrl: string,
  config: GatewayConfig
): Promise<void> {
  const url = targetUrl + req.originalUrl;

  // Identity headers (the standard ones plus whatever this install configured for
  // SSO) and gateway credentials are removed, so the upstream never sees a value
  // a caller could have forged or a secret that was meant for the gateway.
  const strip = new Set<string>([...NEVER_FORWARD, config.ssoUserHeader, config.ssoRoleHeader]);

  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    const k = key.toLowerCase();
    if (value === undefined || HOP_BY_HOP.has(k) || strip.has(k)) continue;
    const v = Array.isArray(value) ? value.join(", ") : (value as string);
    // "Authorization: Bearer agk_..." is the gateway's own credential, not the upstream's.
    if (k === "authorization" && v.toLowerCase().startsWith(`bearer ${AGENT_KEY_PREFIX}`)) continue;
    headers.set(k, v);
  }

  // Loop guard: each hop through a gateway adds one; the interceptor rejects at MAX_HOPS.
  const hops = Number.parseInt(req.get(HOPS_HEADER) ?? "0", 10);
  headers.set(HOPS_HEADER, String((Number.isFinite(hops) && hops > 0 ? hops : 0) + 1));

  const body = extractBody(req);

  try {
    const upstream = await fetch(url, {
      method: req.method,
      headers,
      body: body ?? undefined,
      redirect: "manual",
      signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
    });

    // Read (and size-check) the whole body before committing to a status, so an
    // oversized or broken response can still become a clean 502/504.
    const payload = await readCapped(upstream);

    res.status(upstream.status);
    upstream.headers.forEach((value: string, key: string) => {
      if (!SKIP_RESPONSE_HEADERS.has(key.toLowerCase())) res.setHeader(key, value);
    });
    const withCookies = upstream.headers as Headers & { getSetCookie?: () => string[] };
    const cookies = withCookies.getSetCookie?.() ?? [];
    if (cookies.length > 0) res.setHeader("set-cookie", cookies);

    res.send(payload);
  } catch (err) {
    if (res.headersSent) return;
    if (isTimeoutError(err)) {
      console.error("Proxy timeout:", url);
      sendError(res, 504, "Gateway Timeout", "The target server did not respond in time.");
    } else if (err instanceof UpstreamTooLargeError) {
      sendError(res, 502, "Bad Gateway", err.message);
    } else {
      console.error("Proxy error:", err);
      sendError(res, 502, "Bad Gateway", "Could not reach the target server.");
    }
  }
}
