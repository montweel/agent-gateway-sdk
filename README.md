# Mont (`agent-gateway-sdk`) — Zero-Infrastructure AI Agent API Gateway & Firewall
[![npm version](https://img.shields.io/npm/v/agent-gateway-sdk?style=flat-square&color=cb3837)](https://www.npmjs.com/package/agent-gateway-sdk)
[![Website](https://img.shields.io/badge/Website-montweel.com-6366f1?style=flat-square)](https://montweel.com)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D20.17-10b981?style=flat-square)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-3b82f6?style=flat-square)](https://www.typescriptlang.org/)
[![Database](https://img.shields.io/badge/Storage-Embedded%20SQLite%20WAL-f59e0b?style=flat-square)](https://www.sqlite.org/)
[![License](https://img.shields.io/badge/License-Open--Core%20(See%20TERMS.md)-64748b?style=flat-square)](./TERMS.md)
![Mont Gateway Dashboard](https://montweel.com/media/dashboard.png)

**Open your product and APIs to autonomous AI agents—safely, visibly, and in under 60 seconds.**

**Mont** (`agent-gateway-sdk`) is a lightweight, **local-first API gateway, reverse proxy, and human-in-the-loop firewall for AI agent traffic**. It drops into your existing Node.js / Express application as middleware—or runs as a standalone reverse proxy in front of any backend (Python, Go, Java, Next.js, FastAPI, Rails)—with **zero external infrastructure**. No Redis, no external Postgres, and no complex DevOps required.

🌐 **Website & Free 90-Day Pro Trial Key:** [https://montweel.com](https://montweel.com)
⚖️ **Terms & License:** [TERMS.md](./TERMS.md)
    Local-first alternative to cloud AI proxies
---

## Why Mont?

Autonomous AI agents, LLM tool-callers, and MCP clients are rapidly replacing traditional browser sessions. Opening your APIs to agentic traffic without a dedicated governance layer exposes your backend to runaway loops, unauthorized mutations, and billing spikes.

Mont sits between AI agents and your routes to give you instant control:

- **Zero Infrastructure by Default:** Powered by embedded **SQLite in WAL (Write-Ahead Logging) mode**. Rules, rate limits, agent API keys, and audit logs run in-process on local disk.
- **Deploy Anywhere (Local or Cloud):** Run it on a laptop in 1 minute, or deploy it in production on **AWS, Render, Railway, Fly.io, DigitalOcean, Docker, or Kubernetes** right alongside your app.
- **Human-in-the-Loop Safety:** Pause sensitive `POST` / `DELETE` / checkout actions with `REQUIRE_APPROVAL` rules and approve or reject them with one click in the built-in Admin Dashboard.
- **Agent Discovery Out of the Box:** Serves a machine-readable `/.well-known/agent.json` discovery manifest so trusted AI agents know how to authenticate and interact with your APIs.

---

## Core Features

### 1. API Firewall & Per-Route Access Rules

Define route rules (a path such as `/api/x` for any method, or `POST /api/x` for one method) with three enforcement modes. A method-specific rule wins over a path-only rule, and **a request that matches no rule is blocked**.

- **`ALLOW`**: Pass the agent request to your upstream route.
- **`REQUIRE_APPROVAL`**: Hold sensitive agent actions (e.g., `POST /api/payments`, `DELETE /api/users`) in a pending queue until a human admin approves or rejects them. Undecided actions expire after 24 hours.
- **`BLOCK`**: Reject the request before it touches your application logic.

### 2. Sliding-Window Rate Limiting

Protect your upstream APIs and LLM budgets from runaway agent loops. A global per-minute limit applies per client IP, and any rule can set its own `rateLimit` (requests per minute) with a separate bucket. It is stored in-process, so no Redis cluster is needed.

### 3. Built-In Local Admin Dashboard (`/agent-admin`)

Manage rules, inspect agent audit logs, issue or revoke agent keys, and approve held requests from a zero-setup web UI. The dashboard and admin API (`/api/agent-admin`) can run on the public port or on a separate, private listener (`ADMIN_PORT`).

### 4. Standalone Reverse Proxy Mode

Not using Node.js for your main backend? Run Mont as a standalone **reverse proxy** in front of any upstream server. Set the **Target URL** in the dashboard (stored as `targetUrl` in `config.json`). Mont inspects, rate-limits, and logs incoming `/api/*` agent traffic before forwarding allowed requests to your Python, Go, Ruby, or Java services.

### 5. Agent API Keys

Turn on `requireAgentApiKey` and every `/api/*` request must carry a valid key, either as `x-agent-key: agk_...` or `Authorization: Bearer agk_...`. Create and revoke keys in the dashboard.

### 6. OAuth2 / Reverse-Proxy SSO Authentication *(Team Pro)*

Deploying behind **Cloudflare Access, OAuth2 Proxy, Nginx, Traefik, Authelia, or Okta**? Enable *Trust identity proxy headers* in Settings. Mont then reads the user from `x-forwarded-user` and the role from `x-forwarded-role` (`admin`, anything else is a read-only viewer). Both header names are configurable. Mont generates a random `ssoSharedSecret`, and your proxy **must send it in the `x-gateway-sso-secret` header**, otherwise the identity headers are ignored.

### 7. Multi-User RBAC & Prometheus `/metrics` *(Team Pro)*

- **Role-Based Access Control:** Give full rule/approval control to **Admins** and **Read-Only Auditor** accounts to security and compliance teammates.
- **Prometheus Metrics:** `GET /api/agent-admin/metrics` exposes `agent_gateway_requests_total` (by outcome) and `agent_gateway_pending_approvals` for Grafana, Datadog, or Zabbix. It requires an authenticated admin/viewer session or static token.

---

## 60-Second Quick Start

Requires **Node.js 20.17+**.

### Option A: Install as an SDK in Your Node.js / Express App

```bash
npm install agent-gateway-sdk
```

```ts
import express from "express";
import { createAgentGateway } from "agent-gateway-sdk";

const PORT = 3000;
const app = express();

const gateway = createAgentGateway({ port: PORT });
await gateway.ready; // database is open and migrated

app.use(gateway.discoveryRouter);                  // GET /.well-known/agent.json
app.use("/api/agent-admin", gateway.adminRouter);  // admin API: mount BEFORE the gateway
app.use("/api", gateway.agentGateway);             // the firewall / interceptor

app.use(express.json());
app.get("/api/get-flights", (_req, res) => res.json({ flights: [] })); // your routes

app.listen(PORT, () => console.log(`Mont gateway on http://localhost:${PORT}`));
```

Rules and config are stored in `rules.json` / `config.json` and the SQLite database in `logs.db`, all in the working directory (override with the `rulesPath`, `configPath`, and `dbPath` options). Call `await gateway.close()` on shutdown.

The `adminRouter` is the admin **API**. The prebuilt dashboard UI is in `dashboard/dist`; `src/server.ts` shows how to serve it at `/agent-admin` with a strict Content-Security-Policy.

### Option B: Run as a Standalone Reverse Proxy (Any Language / Cloud Stack)

Clone the repository and run Mont in front of any existing API server:

```bash
git clone https://github.com/montweel/agent-gateway-sdk.git
cd agent-gateway-sdk
npm install
npm start
```

Open `http://127.0.0.1:3000/agent-admin/` to create the owner account (the first-boot setup key is printed in the console banner), set your **Target URL**, create your first agent API key, and add route rules.

---

## Configuration (Environment Variables)

| Variable | Purpose | Default |
|---|---|---|
| `PORT` | Public listen port | `3000` |
| `HOST` | Bind address (use `0.0.0.0` in Docker or behind a proxy) | `127.0.0.1` |
| `TRUST_PROXY` | Set to `true` when behind exactly one reverse proxy so client IPs come from `X-Forwarded-For` | off |
| `CORS_ORIGINS` | Comma-separated browser origins allowed to call the admin API | `http://localhost:5173` in dev, none in production |
| `ADMIN_PORT` / `ADMIN_HOST` | Serve the admin API and dashboard on a separate listener | off / `127.0.0.1` |
| `SETUP_TOKEN` | First-boot setup key (needed to create the owner from another machine) | random, printed at startup |
| `ADMIN_TOKEN` / `VIEWER_TOKEN` | Static tokens for CI/CD and read-only automation | unset |
| `MONT_LICENSE_KEY` | Team Pro license key | unset |

---

## Cloud & Reverse-Proxy SSO Deployment

Mont needs no external infrastructure, but it is built for production environments (Docker, AWS ECS/EC2, Render, Fly.io, Railway, or a Linux VPS).

**Persistent volume (containers):** mount a persistent volume on the working directory so `logs.db` (SQLite WAL), `rules.json`, `config.json`, and `mont-state.json` survive restarts. Set `HOST=0.0.0.0`.

**Behind OAuth2 / reverse-proxy SSO (Team Pro):** configure your proxy to send verified identity headers *and* the shared secret shown in the dashboard Settings tab:

```nginx
location /agent-admin/ {
    proxy_pass http://127.0.0.1:3000;
    proxy_set_header x-forwarded-user $upstream_http_x_auth_request_email;
    proxy_set_header x-forwarded-role "admin";          # or "viewer" for Read-Only Auditors
    proxy_set_header x-gateway-sso-secret "<ssoSharedSecret from Settings>";
}
location /api/agent-admin/ {
    proxy_pass http://127.0.0.1:3000;
    proxy_set_header x-forwarded-user $upstream_http_x_auth_request_email;
    proxy_set_header x-forwarded-role "admin";
    proxy_set_header x-gateway-sso-secret "<ssoSharedSecret from Settings>";
}
```

Then enable *Trust identity proxy headers* in Settings. Keep `ADMIN_PORT` on a private interface so the admin API is not reachable around your proxy.

---

## Community (Free Forever) vs. Team Pro

Every new installation includes an instant 7-day Team Pro trial, plus a free 90-day Team Pro trial key at [montweel.com/#license-renewal](https://montweel.com/#license-renewal) (no credit card required). Install state is kept in `logs.db`, `mont-state.json` and `~/.montweel/anchor.json`; tampering with these disables the trial until a valid key is entered.

| Feature | Community Edition ($0 forever) | Team Pro ($30/mo or $250/yr) |
|---|---|---|
| Core API firewall & reverse proxy | ✅ | ✅ |
| Access rules (`ALLOW`, `REQUIRE_APPROVAL`, `BLOCK`) | ✅ | ✅ |
| Sliding-window rate limiting | ✅ | ✅ |
| Embedded SQLite WAL persistence | ✅ | ✅ |
| Local admin dashboard (`/agent-admin`) | ✅ | ✅ |
| `/.well-known/agent.json` discovery manifest | ✅ | ✅ |
| Agent API keys | Up to 2 active keys | Up to 500 keys |
| Dashboard activity window | 24 hours | 24 hours and 7 days |
| Reverse-proxy SSO (`x-forwarded-user`, `x-forwarded-role`) | — | ✅ |
| Multi-user RBAC (Admin & Read-Only Auditor) | Single owner account | ✅ |
| Prometheus `/metrics` endpoint | — | ✅ |

👉 Claim your free 90-day Team Pro trial key: <https://montweel.com/#license-renewal>

---

## Search Keywords & Topics

ai-agents · agent-gateway · api-gateway · api-firewall · mcp · autonomous-agents · human-in-the-loop · rate-limiter · reverse-proxy · sqlite · local-first · zero-infrastructure · sso · rbac · prometheus-metrics · nodejs · typescript · express-middleware

---

## Legal & Terms of Use

The Mont Agent Gateway SDK is provided strictly "AS IS" without warranty of any kind or SLA. By downloading, installing, deploying, or using this software, you agree to the complete terms, disclaimers, and liability limitations in [TERMS.md](./TERMS.md).

**Website:** <https://montweel.com> · **Support:** support@montweel.com
