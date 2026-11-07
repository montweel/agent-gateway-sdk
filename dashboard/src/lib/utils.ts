import type { Mode, Rules } from './types'

export function formatTime(ts: string): string {
  const d = new Date(ts)
  if (Number.isNaN(d.getTime())) return ts
  return d.toLocaleString('en-IN', {
    day: '2-digit',
    month: 'short',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

export function formatBucketLabel(isoTime: string, windowType: string): string {
  const d = new Date(isoTime)
  if (Number.isNaN(d.getTime())) return isoTime
  if (windowType === '1w') {
    return d.toLocaleDateString('en-IN', { month: 'short', day: 'numeric' })
  }
  return d.toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit', hour12: false })
}

export function prettyJson(text: string | null): string | null {
  if (!text) return null
  try {
    return JSON.stringify(JSON.parse(text), null, 2)
  } catch {
    return text
  }
}

const own = (rules: Rules, key: string): boolean => Object.prototype.hasOwnProperty.call(rules, key)

/**
 * Methods a rule can be pinned to. "ANY" means a path-only rule that matches every HTTP method.
 * "MCP" rules govern MCP tools/call (path /api/mcp/tools/<tool name>).
 */
export const RULE_METHOD_OPTIONS = ['ANY', 'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'MCP'] as const
export type RuleMethod = (typeof RULE_METHOD_OPTIONS)[number]

/** Rules key: "/api/x" for any method, "POST /api/x" for one method (mirrors the server). */
export function ruleKey(method: string, path: string): string {
  const m = method.toUpperCase()
  return m === 'ANY' || m === '' ? path : `${m} ${path}`
}

/** Splits a rules key. Method is "ANY" for path-only keys. */
export function splitRuleKey(key: string): { method: string; path: string } {
  const space = key.indexOf(' ')
  if (space === -1) return { method: 'ANY', path: key }
  return { method: key.slice(0, space).toUpperCase(), path: key.slice(space + 1).trim() }
}

/** "*" matches any characters; everything else is literal (mirrors the server). */
function patternMatches(pattern: string, path: string): boolean {
  const body = pattern
    .split('*')
    .map((part) => part.replace(/[.+?^${}()|[\]\\]/g, '\\$&'))
    .join('[^?#]*')
  return new RegExp(`^${body}$`).test(path)
}

/** True if a request with this method and path matches a rule (exact keys, then "*" wildcard keys). */
export function hasRule(rules: Rules, method: string, path: string): boolean {
  const m = method.toUpperCase()
  if (own(rules, ruleKey(m, path)) || (m !== 'MCP' && own(rules, path))) return true
  return Object.keys(rules).some((key) => {
    if (!key.includes('*')) return false
    const { method: km, path: kp } = splitRuleKey(key)
    if (km === 'ANY' ? m === 'MCP' : km !== m) return false
    return patternMatches(kp, path)
  })
}

/** Safe methods start as ALLOW; anything that changes data starts as REQUIRE_APPROVAL. */
export function suggestedMode(method: string): Mode {
  return ['GET', 'HEAD', 'OPTIONS'].includes(method.toUpperCase()) ? 'ALLOW' : 'REQUIRE_APPROVAL'
}

export const INPUT_CLASS =
  'w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 shadow-sm placeholder:text-slate-400 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 disabled:bg-slate-50 disabled:text-slate-500 disabled:cursor-not-allowed'

export const MODE_ORDER: Mode[] = ['ALLOW', 'REQUIRE_APPROVAL', 'BLOCK']
export const READ_ONLY_HINT = 'Read-only viewers cannot modify rules, settings, or approve actions.'

export const MODE_META: Record<Mode, { label: string; title: string; active: string }> = {
  ALLOW: {
    label: 'Allow',
    title: 'Requests go straight through',
    active: 'bg-emerald-500 text-white shadow-sm',
  },
  REQUIRE_APPROVAL: {
    label: 'Approval',
    title: 'Requests are queued until an admin approves them',
    active: 'bg-amber-500 text-white shadow-sm',
  },
  BLOCK: {
    label: 'Block',
    title: 'Requests are rejected with 403',
    active: 'bg-red-500 text-white shadow-sm',
  },
}
