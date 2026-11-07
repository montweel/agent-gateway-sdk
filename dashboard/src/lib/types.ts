export type Mode = 'ALLOW' | 'REQUIRE_APPROVAL' | 'BLOCK'
export type LogStatus = 'ALLOWED' | 'BLOCKED' | 'QUEUED' | 'APPROVED' | 'REJECTED' | 'RATE_LIMITED'
export type ApprovalStatus = 'PENDING' | 'EXECUTING' | 'APPROVED' | 'REJECTED' | 'FAILED' | 'EXPIRED'
export type Decision = 'APPROVE' | 'REJECT' | 'RETRY'
export type Tab = 'rules' | 'approvals' | 'logs' | 'analytics' | 'team' | 'setup' | 'settings'
export type UserRole = 'admin' | 'viewer'

export interface AuthUser {
  id: number
  username: string
  role: UserRole
  mustChangePassword: boolean
  sso?: boolean
}

export interface AuthStatusResponse {
  needsSetup: boolean
  /** True when the owner must be created with the setup key from the server console. */
  requiresSetupToken?: boolean
  setupTokenRequired?: boolean
  authenticated: boolean
  user?: AuthUser
  ssoActive?: boolean
}

export type PolicyOperator = '>' | '<' | '>=' | '<=' | '===' | '!==' | 'contains' | 'in' | 'regex' | 'exists'

export interface PolicyCondition {
  field: string
  op: PolicyOperator
  value?: unknown
  flags?: string
}

export interface PolicyTier {
  name?: string
  when: PolicyCondition[]
  mode: Mode
}

export interface Rule {
  mode: Mode
  description: string
  /** Max requests per minute per IP for this rule; null/undefined = global limit. */
  rateLimit?: number | null
  /** Payload tiers, first match wins; otherwise `mode` applies. */
  policies?: PolicyTier[]
  budget?: BudgetSpec
  dedupe?: DedupeSpec
}

export interface BudgetSpec {
  field: string
  max: number
  windowMinutes: number
  per: 'global' | 'caller'
  onExceed: 'REQUIRE_APPROVAL' | 'BLOCK'
}

export interface DedupeSpec {
  fields: string[]
  windowMinutes: number
  onDuplicate: 'BLOCK' | 'REQUIRE_APPROVAL'
}

export type EmergencyMode = 'normal' | 'approval_only' | 'lockdown'
export interface EmergencyState {
  mode: EmergencyMode
  reason: string | null
  changedBy: string | null
  changedAt: string | null
}

export interface BudgetUsage {
  ruleKey: string
  field: string
  max: number
  windowMinutes: number
  per: 'global' | 'caller'
  onExceed: string
  spent: number
  remaining: number
}

export interface ProtectionSummary {
  windowHours: number
  since: string
  counts: Record<LogStatus, number>
  moneyProtected: number
  moneyExecuted: number
  pending: number
  emergency: EmergencyState
  budgets: BudgetUsage[]
  topBlocked: { method: string; path: string; count: number }[]
  topCallers: { caller: string; blocked: number }[]
}
export type Rules = Record<string, Rule>

export interface LogRow {
  id: number
  timestamp: string
  method: string
  path: string
  status: LogStatus
  user_agent: string | null
  agent_key?: string | null
  action_id?: number | null
  caller_ip?: string | null
  detail?: string | null
}

export interface HourlyBucket {
  hour: string
  ALLOWED: number
  BLOCKED: number
  QUEUED: number
  RATE_LIMITED: number
  APPROVED: number
  REJECTED: number
  total: number
}

export interface EndpointStat {
  method: string
  path: string
  total: number
  allowed: number
  intervened: number
}

export interface AgentStat {
  agent: string
  total: number
  allowed: number
  intervened: number
}

export interface LicenseStatus {
  valid: boolean
  expired: boolean
  isTrial: boolean
  tier: 'COMMUNITY' | 'PRO'
  org?: string
  email?: string
  issuedAt?: string
  expiresAt?: string
  daysRemaining?: number
  source: 'ENV' | 'DB' | 'TRIAL' | 'TRIAL_EXPIRED'
  reason?: string
  renewalUrl: string
}

/** Body of a Pro-gated call the current license does not cover (HTTP 200, never 403). */
export interface ProRequiredResponse {
  proRequired: true
  message: string
  upgradeUrl: string
}

export function isProRequired(data: unknown): data is ProRequiredResponse {
  return typeof data === 'object' && data !== null && (data as { proRequired?: unknown }).proRequired === true
}

export interface AnalyticsResponse {
  /** Set when the 7-day window was requested without Pro; the data is the 24h window. */
  proRequired?: boolean
  statusTotals: { status: LogStatus; count: number }[]
  hourly: HourlyBucket[]
  topEndpoints?: EndpointStat[]
  topAgents?: AgentStat[]
}

export interface Approval {
  id: number
  timestamp: string
  method: string
  path: string
  headers: string | null
  body: string | null
  status: ApprovalStatus
  response_preview: string | null
  decided_by?: string | null
  expires_at?: number | null
  agent_key?: string | null
  query_json?: string | null
  caller_ip?: string | null
  caller_ua?: string | null
  agent_key_id?: number | null
  agent_key_prefix?: string | null
  agent_reason?: string | null
  matched_policy?: string | null
  revoked_at?: string | null
  revoked_by?: string | null
  rollback_status?: string | null
  /** "mcp" for held MCP tool calls, "http" (or null) for HTTP requests. */
  kind?: string | null
}

export interface RevokeResponse {
  success: boolean
  id: number
  revokedAt: string
  revokedBy: string
  blocked: BlockedCaller[]
  autoRejected: number[]
  rollbackStatus: string
}

export interface BlockedCaller {
  id: number
  kind: 'agent_key' | 'ip'
  value: string
  label: string | null
  reason: string | null
  source_action_id: number | null
  created_by: string
  created_at: string
}

export interface GatewaySettings {
  listenPort: number | null
  publicBaseUrl: string
  notifications: {
    slack: {
      enabled: boolean
      mode: 'webhook' | 'socket'
      webhookUrl: string
      botToken: string
      appToken: string
      channelId: string
      approverIds: string
    }
    telegram: { enabled: boolean; mode: 'polling' | 'links'; botToken: string; chatId: string; approverIds: string }
    webhook: { enabled: boolean; url: string; secret: string }
  }
  rollback: { url: string; secret: string }
  privacy: { redactEmails: boolean; redactPhones: boolean }
  timezone: string
  schedule: { enabled: boolean; days: number[]; start: string; end: string }
  alerts: { enabled: boolean; burstThreshold: number; burstWindowMinutes: number; digestHour: number | null }
}

export type BridgeState = 'disabled' | 'connecting' | 'connected' | 'standby' | 'error'
export interface BridgeStatus {
  state: BridgeState
  detail: string | null
  lastEventAt: string | null
}

export interface SetupResponse {
  gateway: { targetUrl: string; rateLimitPerMinute: number; gatewayPort: number }
  settings: GatewaySettings
  callbackPathPrefix: string
  bridges?: { telegram: BridgeStatus; slack: BridgeStatus }
  emergency?: EmergencyState
  withinBusinessHours?: boolean
  warnings?: string[]
}

export interface PolicyPreset {
  id: string
  name: string
  summary: string
  highlights: string[]
  rules: Rules
}

export interface ApplyPresetResponse {
  success: boolean
  preset: string
  mode: 'merge' | 'replace'
  added: string[]
  replaced: string[]
  rules: Rules
}

export interface NotifyResult {
  channel: 'slack' | 'telegram' | 'webhook'
  ok: boolean
  status?: number
  error?: string
}

export interface GatewayConfig {
  targetUrl: string
  rateLimitPerMinute: number
  requireAgentApiKey?: boolean
  ssoTrustProxyHeader?: boolean
  /** Only sent to administrators. */
  ssoSharedSecret?: string
  ssoSharedSecretConfigured?: boolean
  ssoUserHeader?: string
  ssoRoleHeader?: string
}

export interface TeamUser {
  id: number
  username: string
  role: UserRole
  mustChangePassword: boolean
  createdAt: string
}

export interface DecideResponse {
  success: boolean
  id: number
  status: ApprovalStatus
  decided_by?: string
  replayStatus?: number
  response_preview?: string
  warning?: string
}

export interface AgentKey {
  id: number
  name: string
  keyPrefix: string
  createdAt: string
  lastUsedAt: string | null
}
