import type { ApprovalStatus, LogStatus } from './types'

/** Badge colours (rendered by <Badge> in components/ui.tsx). */
export type Tone = 'green' | 'red' | 'amber' | 'violet' | 'slate'

export const LOG_TONES: Record<LogStatus, Tone> = {
  ALLOWED: 'green',
  BLOCKED: 'red',
  QUEUED: 'amber',
  RATE_LIMITED: 'violet',
  APPROVED: 'green',
  REJECTED: 'red',
  RESPONSE_BLOCKED: 'red',
  RESPONSE_SCRUBBED: 'amber',
}

export const APPROVAL_TONES: Record<ApprovalStatus, Tone> = {
  PENDING: 'amber',
  EXECUTING: 'violet',
  APPROVED: 'green',
  REJECTED: 'red',
  FAILED: 'red',
  EXPIRED: 'slate',
}
