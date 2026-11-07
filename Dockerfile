# syntax=docker/dockerfile:1.7
#
# Mont Agent Gateway: standalone no-code proxy + admin console.
#
#   docker build -t montweel/agent-gateway:2.0.0 .
#   docker run -d -p 8080:8080 -p 127.0.0.1:3000:3000 -v mont-data:/data montweel/agent-gateway:2.0.0
#
# Agents call  http://<host>:8080/api/...      Admin console  http://127.0.0.1:3000/agent-admin/
# Everything that must survive a restart (logs.db + WAL, rules.json, config.json, mont-state.json)
# lives in the /data volume.

ARG NODE_VERSION=20

# ---------------------------------------------------------------------------
# 1. Build: compile the gateway (tsc) and the React dashboard (vite), then drop dev dependencies.
# ---------------------------------------------------------------------------
FROM node:${NODE_VERSION}-alpine AS build
# sqlite3 is a native addon: toolchain in case no prebuilt musl binary matches.
RUN apk add --no-cache python3 make g++
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY dashboard/package.json dashboard/package-lock.json ./dashboard/
RUN npm --prefix dashboard ci --no-audit --no-fund

COPY tsconfig.json ./
COPY src ./src
COPY dashboard ./dashboard
RUN npm run build:all \
 && npm prune --omit=dev --no-audit --no-fund

# ---------------------------------------------------------------------------
# 2. Runtime: production files only, non-root, data on a volume.
# ---------------------------------------------------------------------------
FROM node:${NODE_VERSION}-alpine AS runtime
RUN apk add --no-cache tini

ENV NODE_ENV=production \
    # Bind inside the container; publish the admin port on 127.0.0.1 only (see docker-compose.yml).
    HOST=0.0.0.0 \
    PORT=8080 \
    ADMIN_HOST=0.0.0.0 \
    ADMIN_PORT=3000 \
    # Slack Socket Mode uses the built-in WebSocket client (behind a flag on Node 20, default on 22+).
    NODE_OPTIONS=--experimental-websocket

WORKDIR /app
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist ./dist
COPY --from=build --chown=node:node /app/dashboard/dist ./dashboard/dist
COPY --chown=node:node package.json README.md TERMS.md ./

RUN mkdir -p /data /home/node/.montweel && chown -R node:node /data /home/node/.montweel
USER node
VOLUME ["/data"]
EXPOSE 8080 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:3000/agent-admin/ || exit 1

# tini forwards SIGTERM so the gateway closes SQLite cleanly (WAL checkpoint, ledger sealed).
ENTRYPOINT ["/sbin/tini", "--", "node", "dist/cli.js"]
CMD ["start", "--data-dir", "/data"]
