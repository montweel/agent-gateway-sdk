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
export {
  createAgentGateway,
  evaluateRule,
  validatePolicies,
  signWebhookBody,
  readPersistedListenPort,
  createRedactor,
  POLICY_PRESETS,
  applyPreset,
  verifyLicenseKey,
  signLicenseV2,
  featuresFor,
  computeRowHash,
  GENESIS_HASH,
  inspectResponseBody,
  inspectMcpResult,
} from "./core";
export type {
  Redactor,
  McpGuard,
  GuardResult,
  WaitResult,
  ToolCallRequest,
  ExecuteOverride,
  LicenseStatus,
  LicenseTier,
  LicenseFeatures,
  VerifyReport,
  Workspace,
  SimulationReport,
} from "./core";
export { createMcpHttpProxy, startMcpStdioProxy, gateToolCall, parseSse } from "./mcpProxy";
export type { McpHttpProxyOptions, McpStdioProxyOptions, McpStdioProxy } from "./mcpProxy";
export type {
  AgentGateway,
  AgentGatewayOptions,
  AuthUser,
  GatewayConfig,
  GatewaySettings,
  PolicyCondition,
  PolicyOperator,
  PolicyTier,
  Rule,
  RuleMode,
  Rules,
  UserRole,
} from "./core";
