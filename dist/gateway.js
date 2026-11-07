"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.gateToolCall = exports.startMcpStdioProxy = exports.createMcpHttpProxy = exports.applyPreset = exports.POLICY_PRESETS = exports.createRedactor = exports.readPersistedListenPort = exports.signWebhookBody = exports.validatePolicies = exports.evaluateRule = exports.createAgentGateway = void 0;
/**
 * agent-gateway-sdk: public entry point.
 *
 * The implementation lives in ./core (see the module map in core/index.ts).
 * This file only re-exports the public API so `import ... from "./gateway"`
 * keeps working.
 *
 * Usage (see server.ts for a full example):
 *
 *   const gateway = createAgentGateway({ port: 3000 });
 *   await gateway.ready;
 *
 *   app.use(gateway.discoveryRouter);                 // GET /.well-known/agent.json
 *   app.use("/api/agent-admin", gateway.adminRouter); // admin API (mount BEFORE the gateway)
 *   app.use(gateway.approvalCallbackRouter);          // signed phone Approve/Reject links (/_mont/approvals/*)
 *   app.use("/api", gateway.agentGateway);            // the interceptor
 *
 * Standalone reverse proxy (no code): `npx agent-gateway-sdk start --target https://api.example.com`
 *
 * rules.json payload policies (v1.1), first matching tier wins, else the rule's mode:
 *   "POST /api/refund": { "mode": "REQUIRE_APPROVAL", "policies": [
 *     { "name": "small", "when": [{ "field": "body.amount", "op": "<=", "value": 100 }], "mode": "ALLOW" },
 *     { "name": "huge",  "when": [{ "field": "body.amount", "op": ">",  "value": 1000 }], "mode": "BLOCK" } ] }
 *
 *   // Optional: serve the admin API + dashboard on their own listener
 *   if (gateway.adminListener) { ...mount adminRouter on a second app and listen(adminListener.port, adminListener.host) }
 *
 * Security-relevant options / environment variables:
 *   SETUP_TOKEN / setupToken   first-boot setup key. Without it a random one is printed in
 *                              the console banner. Needed only when creating the owner from
 *                              another machine (sent as { setupToken } in POST /auth/setup).
 *   ADMIN_PORT / adminPort     separate admin listener (default off)
 *   ADMIN_HOST / adminHost     its bind address (default 127.0.0.1)
 *   ADMIN_TOKEN / VIEWER_TOKEN optional static tokens for automation
 *
 * rules.json keys: "/api/x" (any method) or "POST /api/x" (that method only). A method rule
 * wins over the path-only rule; no match means BLOCK.
 *
 * config.json (editable from the dashboard):
 *   requireAgentApiKey         true = /api/* needs x-agent-key or Authorization: Bearer agk_...
 *   ssoTrustProxyHeader        trust identity headers from your SSO proxy. A random
 *                              ssoSharedSecret is generated; the proxy must send it as
 *                              x-gateway-sso-secret.
 */
var core_1 = require("./core");
Object.defineProperty(exports, "createAgentGateway", { enumerable: true, get: function () { return core_1.createAgentGateway; } });
Object.defineProperty(exports, "evaluateRule", { enumerable: true, get: function () { return core_1.evaluateRule; } });
Object.defineProperty(exports, "validatePolicies", { enumerable: true, get: function () { return core_1.validatePolicies; } });
Object.defineProperty(exports, "signWebhookBody", { enumerable: true, get: function () { return core_1.signWebhookBody; } });
Object.defineProperty(exports, "readPersistedListenPort", { enumerable: true, get: function () { return core_1.readPersistedListenPort; } });
Object.defineProperty(exports, "createRedactor", { enumerable: true, get: function () { return core_1.createRedactor; } });
Object.defineProperty(exports, "POLICY_PRESETS", { enumerable: true, get: function () { return core_1.POLICY_PRESETS; } });
Object.defineProperty(exports, "applyPreset", { enumerable: true, get: function () { return core_1.applyPreset; } });
var mcpProxy_1 = require("./mcpProxy");
Object.defineProperty(exports, "createMcpHttpProxy", { enumerable: true, get: function () { return mcpProxy_1.createMcpHttpProxy; } });
Object.defineProperty(exports, "startMcpStdioProxy", { enumerable: true, get: function () { return mcpProxy_1.startMcpStdioProxy; } });
Object.defineProperty(exports, "gateToolCall", { enumerable: true, get: function () { return mcpProxy_1.gateToolCall; } });
