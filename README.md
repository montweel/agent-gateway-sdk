# Mont (`agent-gateway-sdk`) — The Firewall Between AI Agents and Your APIs
[![npm version](https://img.shields.io/npm/v/agent-gateway-sdk?style=flat-square&color=cb3837)](https://www.npmjs.com/package/agent-gateway-sdk)
[![Website](https://img.shields.io/badge/Website-montweel.com-6366f1?style=flat-square)](https://montweel.com)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D20.17-10b981?style=flat-square)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-3b82f6?style=flat-square)](https://www.typescriptlang.org/)
[![Database](https://img.shields.io/badge/Storage-Embedded%20SQLite%20WAL-f59e0b?style=flat-square)](https://www.sqlite.org/)
[![Docker](https://img.shields.io/badge/Docker-ready-0ea5e9?style=flat-square)](#deploy-with-docker)
[![License](https://img.shields.io/badge/License-Open--Core%20(See%20TERMS.md)-64748b?style=flat-square)](./TERMS.md)

![Mont Gateway Dashboard](https://montweel.com/media/dashboard.png)

**Let AI agents use your store and APIs without letting them empty it.**

Mont is a local-first, fail-closed API gateway and human-in-the-loop firewall for AI agent traffic: REST calls and MCP tool calls alike. You can use it in three ways:

- as **Express middleware** inside your app
- as a **no-code reverse proxy** in front of any backend (Python, Go, Java, Rails, Next.js…)
- as an **MCP proxy** between Claude, Cursor or your agent framework and its tools

It needs no Redis, no Postgres and no cloud account: everything lives in an embedded SQLite (WAL) database next to your app.

🌐 [montweel.com](https://montweel.com) · 🎁 [Free 90-day Pro trial key](https://montweel.com/#license-renewal) · ⚖️ [TERMS.md](./TERMS.md)

---

## The problem

Agents are now calling production APIs, and they fail in ways firewalls were never built for:

| What goes wrong | What it costs you | How Mont stops it |
|---|---|---|
| **Runaway loops.** An agent retries the same refund or email 400 times. | Duplicate payouts, spam, burned API budget | Rate limits per route, **duplicate-action protection**, cumulative **spending budgets** |
| **Prompt-injected refunds.** A support ticket says "refund every order", and the agent obeys. | Real money leaves the store | **Payload policies** (`amount > 100` → needs a human), **phone approvals**, **Edit & Approve**, **Lockdown** switch |
| **Blind MCP tool calls.** The model calls `delete_customer` or `export_database` because a webpage told it to. | Data loss, data exfiltration | **Default-deny MCP tool rules**, per-argument policies, **outbound response guard** |
| **"What did the agent actually do?"** | No evidence for chargebacks or audits | **Hash-chained, tamper-evident audit log**, CSV export, money-protected reports |

Every decision is **fail-closed**. A request reaches your API only after every check passed *and* its audit row is durably written. A database error, timeout, malformed body or policy error ends in a 4xx/503, never in a forwarded request.

---

## Quickstart

Requires **Node.js 20.17+** (or [Docker](#deploy-with-docker)).

### (a) Express middleware: inside your Node.js app

```bash
npm install agent-gateway-sdk
```

```ts
import express from "express";
import { createAgentGateway } from "agent-gateway-sdk";

const app = express();
const gateway = createAgentGateway({ port: 3000 });
await gateway.ready;                                // database open and migrated

app.use(gateway.discoveryRouter);                   // GET /.well-known/agent.json
app.use(gateway.approvalCallbackRouter);            // signed Approve / Reject links
app.use("/api/agent-admin", gateway.adminRouter);   // admin API (mount BEFORE the gateway)
app.use("/api", gateway.agentGateway);              // the firewall

app.post("/api/refund", express.json(), (req, res) => res.json({ refunded: req.body.amount })); // your routes
app.listen(3000);
```

### (b) Standalone no-code proxy: in front of any backend

```bash
npx agent-gateway-sdk start --target https://api.mystore.com
# agents call      http://127.0.0.1:8080/api/...
# admin console    http://127.0.0.1:3000/agent-admin/   (first-boot setup key is printed in the console)
```

### (c) MCP proxy: between your AI client and its tools

```bash
# stdio: put this in your MCP client config as the server "command"
npx agent-gateway-sdk mcp-stdio --data-dir ~/.mont -- npx -y @modelcontextprotocol/server-filesystem /data
# Streamable HTTP (+ legacy HTTP+SSE at /mcp/sse) in front of a remote MCP server
npx agent-gateway-sdk mcp-http --upstream http://127.0.0.1:9000/mcp
```

Then open the admin console. **Gateway Setup** walks you through the rest without code:
- your upstream URL
- a one-click policy pack (E-commerce, FinTech, CRUD)
- phone approvals
- budgets
- business hours

**Try the disaster first:** run `npm run demo:shopify` in a clone of this repo. It shows a prompt-injected support bot refunding every order, first without Mont and then with it.

---

## Feature & tier overview

Licenses are offline Ed25519 keys and nothing phones home. Every new install gets an instant 7-day Pro trial, and a [free 90-day Pro trial key](https://montweel.com/#license-renewal) needs no credit card.

| | **Community** (free forever) | **Pro** | **Agency** |
|---|:---:|:---:|:---:|
| Fail-closed firewall, reverse proxy, MCP proxy (stdio, Streamable HTTP, legacy SSE) | ✅ | ✅ | ✅ |
| Route rules, wildcard rules, payload policies, rate limits | ✅ | ✅ | ✅ |
| **Spending Budgets** & duplicate-action protection | ✅ | ✅ | ✅ |
| Approval queue + dashboard approvals, signed approval links | ✅ | ✅ | ✅ |
| Lockdown / Approval-only switch, business hours, alerts & daily digest | ✅ | ✅ | ✅ |
| PII & secret scrubber, outbound response guard, CSV export | ✅ | ✅ | ✅ |
| Shadow (dry-run) rules & Policy Time-Machine replay | ✅ | ✅ | ✅ |
| **Hash-Chained Audit Ledger**: every row chained | ✅ | ✅ | ✅ |
| Hash-Chained Audit Ledger: one-click integrity **verification** | — | ✅ | ✅ |
| **Zero-Tunnel Telegram / Slack buttons** & Telegram bot commands | — (alerts arrive; approve in the dashboard) | ✅ | ✅ |
| **Edit & Approve** (change a payload before it runs) | — | ✅ | ✅ |
| Compensating rollback webhook on Revoke | — | ✅ | ✅ |
| **Multi-Workspace** (one install, many client stores) | 1 workspace | 3 workspaces | 25 workspaces (or as licensed) |
| Agent API keys | 2 | 500 | 500 |
| Team accounts (Admin / Read-only auditor), SSO header trust, Prometheus metrics, 7-day analytics | — | ✅ | ✅ |
| Price | $0 | $30/mo or $250/yr | [montweel.com](https://montweel.com) |

Activate a key in **Gateway Setup → License & Plan** and it takes effect immediately. You can also set `MONT_LICENSE_KEY`, or pass `licenseKey` to `createAgentGateway()`. If a license lapses, paid features switch off cleanly. Workspaces beyond the plan are refused (`402`), and their traffic is never forwarded unguarded.

---

## How it protects you

### 1. Rules: default deny, decided per route and per payload

Rule keys are `"/api/x"` (any method), `"POST /api/x"` (one method), or wildcards such as `"POST /api/*refund*"`. MCP tools use the pseudo-method `MCP` (`"MCP /api/mcp/tools/refund_order"`). A request that matches no rule is **blocked**.

| Mode | Effect |
|---|---|
| `ALLOW` | Forward to your API |
| `REQUIRE_APPROVAL` | Hold until a human approves (expires after 24 h) |
| `BLOCK` | Refuse with 403 |
| `SHADOW_BLOCK` / `SHADOW_APPROVAL` | **Dry run:** forward, but log what the rule *would* have done |

**Payload policies** inspect `body.*`, `query.*` and `headers.*` with `> < >= <= === !== contains in regex exists`. The first matching tier wins. Numbers are never coerced (`"250"` is not 250), and routes whose policies read the body only accept JSON.

```json
"POST /api/refund": {
  "mode": "REQUIRE_APPROVAL",
  "rateLimit": 30,
  "policies": [
    { "name": "small", "when": [{ "field": "body.amount", "op": "<=", "value": 100 }],  "mode": "ALLOW" },
    { "name": "huge",  "when": [{ "field": "body.amount", "op": ">",  "value": 1000 }], "mode": "BLOCK" }
  ],
  "budget": { "field": "body.amount", "max": 300, "windowMinutes": 60, "per": "global", "onExceed": "REQUIRE_APPROVAL" },
  "dedupe": { "fields": ["body.orderId"], "windowMinutes": 1440, "onDuplicate": "BLOCK" }
}
```

- **Spending budgets** cap the *total* an agent can move on its own. Twenty $90 refunds all pass an "≤ $100" tier; a $300/hour budget stops the fourth. Budgets can be global or per agent, are stored in SQLite, and are race-free under bursts. A missing or text amount counts as over budget.
- **Duplicate protection** refuses (or holds) a second action with the same field values while the first is allowed, waiting or done. A rejected attempt doesn't block a legitimate retry.
- **Starter policy packs** (E-commerce & Shopify, Stripe & FinTech, Internal CRUD) install in one click.

### 2. Humans in the loop, from anywhere

- **Approval queue with a payload inspector.** You see the redacted body and query, high-risk fields flagged (`amount`, `email`, `destination`…), the caller's key, IP and User-Agent, and the agent's own `x-agent-reason`.
- **Phone approvals:**
  - *Zero-tunnel (Pro):* Telegram inline buttons via outbound long-polling, or Slack buttons via Socket Mode. No public URL, ngrok or open port.
  - *Signed links:* Slack, Telegram or a custom webhook with HMAC-signed Approve / Reject links. Links open a confirmation page, so chat link previews can't approve anything.
- **Edit & Approve (Pro).** Lower a hallucinated `"amount": 250` to `50`, fix an address, change a query parameter, or edit MCP tool arguments, then approve.
  - Fields you didn't touch keep their *real* values, even the ones shown masked.
  - The rule is re-checked against your edit.
  - The edited body goes out with a fresh `Content-Length`.
  - The original and modified payloads are both audited (redacted).
- **Revoke & Block Caller.** On any approved action, this blocks the agent key and/or IP, auto-rejects its queued requests, and (Pro) calls your **compensating rollback webhook** (HMAC-signed, idempotency key included).
- **Emergency switch.**
  - **Lockdown** refuses every agent request (nothing waiting can be approved).
  - **Approval-only** holds every write and lets reads through.
  - Flip it from the dashboard, the API or Telegram (`/lockdown`, `/approvalonly`, `/resume`, `/status`, `/pending`). Every gateway process sharing the database follows within about 2 seconds.
- **Business hours.** Outside your opening hours (time-zone and DST aware), writes wait for a human.
- **Alerts & daily digest.** You're told about attack bursts, budgets reached and mode changes, and get a morning summary of money protected vs executed. Each alert is sent once, even across processes.

### 3. MCP tool-call firewall

Every JSON-RPC `tools/call` gets the same rules, payload policies (on `params.arguments` as `body.*`), budgets, approvals and audit trail.

```json
"MCP /api/mcp/tools/search_orders": { "mode": "ALLOW" },
"MCP /api/mcp/tools/refund_order":  { "mode": "REQUIRE_APPROVAL",
  "policies": [{ "when": [{ "field": "body.amount", "op": "<=", "value": 100 }], "mode": "ALLOW" }] },
"MCP /api/mcp/tools/*delete*":      { "mode": "BLOCK" }
```

- Unlisted tools are blocked. HTTP rules such as `/api/*` never apply to MCP tools.
- Refusals come back as tool results with `isError: true`, so the model can read why.
- A call that needs approval is held open until a human decides. If the wait times out or the agent disconnects, the call expires and can never run later.
- **Transports:**
  - stdio: `mcp-stdio`
  - Streamable HTTP: `mcp-http`
  - legacy HTTP+SSE for older clients: `GET /mcp/sse` + `POST /mcp/messages?sessionId=…`
- **Programmatic use:** `createMcpHttpProxy(gateway, { upstreamUrl })`, `startMcpStdioProxy(gateway, { command, args })`, or `gateway.mcp.check(...)`.

### 4. Data protection in both directions

- **PII & secret scrubber.** Nothing is stored in SQLite or sent to Slack, Telegram or webhooks without passing through it.
  - *Always removed:* auth headers, cookies, passwords, tokens, API keys (Stripe, GitHub, Slack, AWS, OpenAI/Anthropic, JWT…) and Luhn-valid card numbers.
  - *Masked by default:* emails and phone numbers.
  - Rules still evaluate the real values, and approved requests replay from an AES-256-GCM encrypted original.
- **Outbound response guard** (opt-in). Mont inspects what your API or MCP tool sends *back* before the agent sees it.
  - **Bulk dumps:** a JSON array longer than your limit (e.g. 1,000 customer rows) is withheld with `502 Response Policy Violation`, or truncated.
  - **Secrets:** they are scrubbed in-flight, or the response is withheld.
  - It works in proxy mode, middleware mode and on every MCP transport.

### 5. Proof: a tamper-evident audit ledger

- **Hash chain.** Every audit row is chained:
  `row_hash = SHA-256(prev_hash + id, timestamp, caller, route, decision, redacted payload, …)`.
  - **Verify Ledger Integrity** (Pro) re-hashes the chain and pinpoints any edited, deleted, inserted or truncated row.
  - Retention pruning keeps the chain verifiable.
  - Several gateway processes can share one database safely.
  - The daily digest carries the chain head, giving you an off-box copy.
- **Money protected** shows how much agents tried to move and were stopped, next to what was executed.
- **CSV export** for accounting and chargeback disputes (formula-injection safe).
- **Shadow rules & Policy Time-Machine.** Try a policy as `SHADOW_*` on live traffic, or click **Test Rules Against History**. The last N real requests are replayed through your rules, including rate limits, budgets and duplicate protection, and you see exactly which ones would now be blocked, held or rate-limited.

### 6. Agencies: many client stores, one install (Agency)

Each **workspace** has its own rules, budgets, upstream URL, emergency switch, business hours, approval chat or Slack channel, and `mws_…` API key. That key is required by default, so one client's agent can never act on another client's store.

| Agents select a workspace with | Example |
|---|---|
| Path prefix | `POST /api/w/acme/refund` (forwarded upstream as `/api/refund`) |
| Header | `x-mont-workspace: acme` |
| Bearer key | `Authorization: Bearer mws_…` |

- **Dashboard:** a **Workspace Switcher** in the top bar and an **All Clients Overview** with mode, money protected, refusals, waiting approvals and shadow hits per client.
- **Approvals per client:** each client's approvals go to its own chat, and a button tapped in the wrong chat is refused.
- **MCP:** `mcp-http --workspace <slug>`, `/w/<slug>/mcp`, or `mcp-stdio --workspace <slug>`.

---

## Deploy with Docker

```bash
docker compose up -d
```

`docker-compose.yml` runs the standalone proxy with these defaults:
- the agent-facing proxy on **:8080**
- the admin console on **127.0.0.1:3000** (local only by default)
- data in a named volume mounted at **/data** (SQLite WAL, rules, config)
- a non-root user, a read-only root filesystem and no Linux capabilities
- a health check

To run it next to existing containers:
1. Join their network (see the commented `networks:` block).
2. Point Mont at `http://your-api:4000` in Gateway Setup.

On first boot, `docker compose logs mont` shows the setup key, or you can set `SETUP_TOKEN`.

```bash
docker build -t montweel/agent-gateway:2.0.0 .
docker run -d -p 8080:8080 -p 127.0.0.1:3000:3000 -v mont-data:/data montweel/agent-gateway:2.0.0
```

The image is multi-stage on Node 20 Alpine. Slack Socket Mode's WebSocket client is enabled with `--experimental-websocket` (it is built in from Node 22).

**Other hosts:** Mont runs anywhere Node does: AWS ECS/EC2, Render, Fly.io, Railway, Kubernetes or a VPS. Mount a persistent volume for the data folder.

**Behind an SSO / OAuth2 proxy (Pro):**
1. Enable *Trust identity proxy headers* in Settings.
2. Have the proxy send `x-forwarded-user`, `x-forwarded-role` and the generated `x-gateway-sso-secret`.
3. Keep the admin listener on a private interface.

---

## Configuration

| Variable | Purpose | Default |
|---|---|---|
| `PORT` / `HOST` | Agent-facing listen port / bind address (`0.0.0.0` in containers) | `8080` (CLI) / `127.0.0.1` |
| `ADMIN_PORT` / `ADMIN_HOST` | Admin API + dashboard listener | `3000` / `127.0.0.1` |
| `TRUST_PROXY` | `true` behind exactly one reverse proxy (client IPs from `X-Forwarded-For`) | off |
| `CORS_ORIGINS` | Browser origins allowed to call the admin API | dev: `http://localhost:5173` |
| `SETUP_TOKEN` | First-boot setup key (create the owner from another machine) | random, printed at startup |
| `ADMIN_TOKEN` / `VIEWER_TOKEN` | Static tokens for CI/CD and read-only automation | unset |
| `MONT_LICENSE_KEY` | `MONT-V2.…` Pro / Agency key (or a v1 `MONT-…` Pro key) | unset |
| `MONT_AGENT_KEY` | (`mcp-stdio`) the local client's `agk_…` agent key or `mws_…` workspace key | unset |

**SDK options** (`createAgentGateway({...})`):
- `port`
- `rulesPath`, `configPath`, `dbPath`
- `adminPort`, `adminHost`
- `adminToken`, `viewerToken`, `setupToken`
- `dbOperationTimeoutMs`
- `licenseKey`, `licenseAnchorFile`
- `telegramApiBase`, `slackApiBase`

**Admin API** (all under `/api/agent-admin`, scoped with `x-mont-workspace`):

| Area | Endpoints |
|---|---|
| Rules & approvals | `rules`, `approvals/:id/decide`, `approvals/:id/revoke` |
| Logs & ledger | `logs`, `logs/export.csv`, `audit/verify`, `simulate/history` |
| Protection | `protection/summary`, `emergency`, `guards/usage` |
| Workspaces & setup | `workspaces`, `setup`, `setup/presets/:id/apply`, `license` |

**Signing license keys** (needs your Ed25519 private key; never leaves your machine):

```bash
npm run keygen -- sign --tier=AGENCY --org="Acme Automation" --max-workspaces=20 --days=365
npm run keygen -- verify MONT-V2.eyJ2Ijoy...
```

---

## Development

```bash
npm install && npm --prefix dashboard install
npm run typecheck      # gateway + tools
npm test               # 4 suites, 58 tests: fail-closed chaos, v1.2, v1.3 shop kit, v2.0 enterprise
npm run build:all      # dist/ + dashboard/dist/
npm run dev            # gateway with reload; dashboard: npm --prefix dashboard run dev
```

Tests run real gateways on temporary folders with a throwaway license key pair, and never touch your `~/.montweel` install anchor.

---

## Search keywords

ai-agents · agent-gateway · api-firewall · mcp · mcp-proxy · human-in-the-loop · prompt-injection · ai-safety · rate-limiter · spending-limits · audit-log · tamper-evident · reverse-proxy · sqlite · local-first · zero-infrastructure · multi-tenant · shopify · stripe · nodejs · typescript · express-middleware

---

## Legal & Terms of Use

The Mont Agent Gateway SDK is provided strictly "AS IS" without warranty of any kind or SLA. By downloading, installing, deploying, or using this software, you agree to the complete terms, disclaimers, and liability limitations in [TERMS.md](./TERMS.md).

**Website:** <https://montweel.com> · **Support:** support@montweel.com
