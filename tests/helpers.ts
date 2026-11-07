/** Shared test harness: real gateways on temp folders, fake third-party services, a tiny WebSocket server. */
import crypto from "crypto";
import fs from "fs";
import http from "http";
import type { AddressInfo } from "net";
import type { Duplex } from "stream";
import os from "os";
import path from "path";
import express from "express";
import type { Express, Request, Response } from "express";
import sqlite3 from "sqlite3";
import { createAgentGateway } from "../src/gateway";
import type { AgentGateway, AgentGatewayOptions, Rules } from "../src/gateway";

export const ADMIN_TOKEN = "v12-suite-admin-token-0123456789abcdef";

const cleanups: Array<() => Promise<void>> = [];
export function onCleanup(fn: () => Promise<void>): void {
  cleanups.push(fn);
}
export async function runCleanups(): Promise<void> {
  for (const c of cleanups.splice(0).reverse()) {
    const t = Date.now();
    await c().catch(() => undefined);
    if (process.env.MONT_TEST_TIMING) console.error(`cleanup ${Date.now() - t}ms: ${c.toString().slice(0, 80).replace(/\s+/g, " ")}`);
  }
}

export function listen(server: http.Server): Promise<number> {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve((server.address() as AddressInfo).port)));
}

export function closeServer(server: http.Server): Promise<void> {
  return new Promise((resolve) => {
    server.closeAllConnections?.();
    server.close(() => resolve());
  });
}

export const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

export async function waitFor<T>(fn: () => Promise<T | undefined | null | false> | T | undefined | null | false, timeoutMs = 8000, label = "condition"): Promise<T> {
  const start = Date.now();
  for (;;) {
    const v = await fn();
    if (v) return v as T;
    if (Date.now() - start > timeoutMs) throw new Error(`Timed out waiting for ${label}`);
    await sleep(40);
  }
}

export interface Harness {
  base: string;
  port: number;
  dir: string;
  dbPath: string;
  app: Express;
  gateway: AgentGateway;
  hits: Array<{ key: string; body: unknown; headers: http.IncomingHttpHeaders }>;
  admin(method: string, p: string, body?: unknown): Promise<{ status: number; data: any }>;
  close(): Promise<void>;
}

export function tempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "mont-v12-"));
}

/**
 * A gateway in Express middleware mode. `mount` runs before the protected catch-all handler,
 * so tests can add MCP proxies etc. Pass `dir` to share a data folder with another harness.
 */
export async function makeHarness(opts: {
  rules?: Rules;
  dir?: string;
  rateLimitPerMinute?: number;
  gatewayOptions?: Partial<AgentGatewayOptions>;
  mount?: (app: Express, gateway: AgentGateway) => void;
}): Promise<Harness> {
  const dir = opts.dir ?? tempDir();
  const rulesPath = path.join(dir, "rules.json");
  const configPath = path.join(dir, "config.json");
  const dbPath = path.join(dir, "logs.db");
  if (opts.rules) fs.writeFileSync(rulesPath, JSON.stringify(opts.rules, null, 2));
  if (!fs.existsSync(configPath)) {
    fs.writeFileSync(configPath, JSON.stringify({ targetUrl: "", rateLimitPerMinute: opts.rateLimitPerMinute ?? 1000 }));
  }

  const app = express();
  const server = http.createServer(app);
  const port = await listen(server);
  const gateway = createAgentGateway({ port, rulesPath, configPath, dbPath, adminToken: ADMIN_TOKEN, ...opts.gatewayOptions });
  await gateway.ready;

  const hits: Harness["hits"] = [];
  app.use("/api/agent-admin", gateway.adminRouter);
  app.use(gateway.approvalCallbackRouter);
  opts.mount?.(app, gateway);
  app.use("/api", gateway.agentGateway);
  app.all(/^\/api\/.*/, (req: Request, res: Response) => {
    hits.push({ key: `${req.method} ${req.path}`, body: req.body ?? null, headers: req.headers });
    res.json({ ok: true, executed: `${req.method} ${req.path}` });
  });

  const base = `http://127.0.0.1:${port}`;
  let closed = false;
  const h: Harness = {
    base,
    port,
    dir,
    dbPath,
    app,
    gateway,
    hits,
    async admin(method, p, body) {
      const res = await fetch(`${base}/api/agent-admin${p}`, {
        method,
        headers: { "x-admin-token": ADMIN_TOKEN, ...(body !== undefined ? { "content-type": "application/json" } : {}) },
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
      return { status: res.status, data: await res.json().catch(() => null) };
    },
    async close() {
      if (closed) return;
      closed = true;
      await closeServer(server);
      await gateway.close().catch(() => undefined);
      if (!opts.dir) fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    },
  };
  // close() also deletes the folder (after the database is closed) when the harness created it.
  onCleanup(() => h.close());
  return h;
}

export function postJson(url: string, body: unknown, headers: Record<string, string> = {}, signal?: AbortSignal): Promise<globalThis.Response> {
  return fetch(url, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body), signal });
}

export function sqliteAll<T>(dbPath: string, sql: string, params: unknown[] = []): Promise<T[]> {
  return new Promise((resolve, reject) => {
    const db = new sqlite3.Database(dbPath, sqlite3.OPEN_READWRITE, (err) => {
      if (err) return reject(err);
      db.all(sql, params, (e: Error | null, rows: unknown[]) => {
        db.close(() => (e ? reject(e) : resolve(rows as T[])));
      });
    });
  });
}

export async function sqliteGet<T>(dbPath: string, sql: string, params: unknown[] = []): Promise<T | undefined> {
  return (await sqliteAll<T>(dbPath, sql, params))[0];
}

export function sqliteRun(dbPath: string, sql: string, params: unknown[] = []): Promise<void> {
  return new Promise((resolve, reject) => {
    const db = new sqlite3.Database(dbPath, sqlite3.OPEN_READWRITE, (err) => {
      if (err) return reject(err);
      db.run(sql, params, (e: Error | null) => {
        db.close(() => (e ? reject(e) : resolve()));
      });
    });
  });
}

export async function pendingStatus(dbPath: string, id: number): Promise<string | undefined> {
  return (await sqliteGet<{ status: string }>(dbPath, "SELECT status FROM pending_actions WHERE id = ?", [id]))?.status;
}

// ---------------------------------------------------------------------------
// Minimal RFC 6455 WebSocket server (text frames, close), enough to emulate Slack Socket Mode.
// ---------------------------------------------------------------------------
export interface WsConnection {
  send(text: string): void;
  received: string[];
  close(): void;
}

function encodeFrame(opcode: number, payload: Buffer): Buffer {
  const len = payload.length;
  let header: Buffer;
  if (len < 126) header = Buffer.from([0x80 | opcode, len]);
  else if (len < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x80 | opcode;
    header[1] = 126;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x80 | opcode;
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(len), 2);
  }
  return Buffer.concat([header, payload]);
}

export function attachWebSocketServer(server: http.Server, wsPath: string, onConnection: (c: WsConnection) => void): void {
  server.on("upgrade", (req: http.IncomingMessage, socket: Duplex) => {
    if (!req.url?.startsWith(wsPath)) {
      socket.destroy();
      return;
    }
    const key = req.headers["sec-websocket-key"];
    const accept = crypto.createHash("sha1").update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest("base64");
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);

    let buf = Buffer.alloc(0);
    const conn: WsConnection = {
      received: [],
      send: (text) => socket.write(encodeFrame(0x1, Buffer.from(text, "utf8"))),
      close: () => {
        socket.write(encodeFrame(0x8, Buffer.alloc(0)));
        socket.end();
      },
    };
    socket.on("data", (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      for (;;) {
        if (buf.length < 2) return;
        const opcode = buf[0] & 0x0f;
        const masked = (buf[1] & 0x80) !== 0;
        let len = buf[1] & 0x7f;
        let offset = 2;
        if (len === 126) {
          if (buf.length < 4) return;
          len = buf.readUInt16BE(2);
          offset = 4;
        } else if (len === 127) {
          if (buf.length < 10) return;
          len = Number(buf.readBigUInt64BE(2));
          offset = 10;
        }
        const maskLen = masked ? 4 : 0;
        if (buf.length < offset + maskLen + len) return;
        const mask = masked ? buf.subarray(offset, offset + 4) : null;
        const payload = Buffer.from(buf.subarray(offset + maskLen, offset + maskLen + len));
        if (mask) for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i % 4];
        buf = buf.subarray(offset + maskLen + len);
        if (opcode === 0x1) conn.received.push(payload.toString("utf8"));
        else if (opcode === 0x8) {
          socket.write(encodeFrame(0x8, Buffer.alloc(0)));
          socket.end();
          return;
        } else if (opcode === 0x9) socket.write(encodeFrame(0xa, payload));
      }
    });
    socket.on("error", () => undefined);
    onConnection(conn);
  });
}

// ---------------------------------------------------------------------------
// Fake Telegram Bot API (getUpdates long-poll + sendMessage etc.)
// ---------------------------------------------------------------------------
export interface FakeTelegram {
  base: string;
  sent: Array<Record<string, any>>;
  calls: Array<{ method: string; body: Record<string, any> }>;
  push(update: Record<string, any>): void;
  polls(): number;
}

export async function fakeTelegram(token: string): Promise<FakeTelegram> {
  const queue: Array<Record<string, any>> = [];
  const sent: Array<Record<string, any>> = [];
  const calls: Array<{ method: string; body: Record<string, any> }> = [];
  let nextUpdate = 1;
  let pollCount = 0;
  const app = express();
  app.use(express.json());
  app.get(`/bot${token}/getUpdates`, async (req: Request, res: Response) => {
    pollCount++;
    const offset = Number(req.query.offset ?? 0);
    while (queue.length && queue[0].update_id < offset) queue.shift();
    if (queue.length === 0) await sleep(100);
    res.json({ ok: true, result: queue.filter((u) => u.update_id >= offset) });
  });
  app.post(`/bot${token}/:method`, (req: Request, res: Response) => {
    const method = String(req.params.method);
    calls.push({ method, body: req.body });
    if (method === "sendMessage") {
      sent.push(req.body);
      res.json({ ok: true, result: { message_id: sent.length, chat: { id: Number(req.body.chat_id) } } });
      return;
    }
    res.json({ ok: true, result: true });
  });
  app.use((_req: Request, res: Response) => res.status(404).json({ ok: false, description: "Not Found" }));
  const server = http.createServer(app);
  const port = await listen(server);
  onCleanup(() => closeServer(server));
  return {
    base: `http://127.0.0.1:${port}`,
    sent,
    calls,
    push: (u) => queue.push({ update_id: nextUpdate++, ...u }),
    polls: () => pollCount,
  };
}
