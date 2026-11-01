export type Mode = 'ALLOW' | 'REQUIRE_APPROVAL' | 'BLOCK'
export type LogStatus = 'ALLOWED' | 'BLOCKED' | 'QUEUED' | 'APPROVED' | 'REJECTED' | 'RATE_LIMITED'
export type ApprovalStatus = 'PENDING' | 'EXECUTING' | 'APPROVED' | 'REJECTED' | 'FAILED' | 'EXPIRED'
export type Decision = 'APPROVE' | 'REJECT' | 'RETRY'
export type Tab = 'rules' | 'approvals' | 'logs' | 'analytics' | 'team' | 'settings'
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

export interface Rule {
  mode: Mode
  description: string
  /** Max requests per minute per IP for this rule; null/undefined = global limit. */
  rateLimit?: number | null
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
