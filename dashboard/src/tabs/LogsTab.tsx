import { Fragment, useEffect, useMemo, useRef, useState } from 'react'
import { ArrowRight, ChevronDown, ChevronRight, Download, FileCheck2, Filter, Plus, Search, ShieldOff, UserCheck, UserRound, X } from 'lucide-react'
import { api, errorMessage } from '../lib/api'
import { useDebouncedValue } from '../hooks/useDebouncedValue'
import type { RulesApi } from '../hooks/useRules'
import type { LogRow, RevokeResponse, Rules } from '../lib/types'
import { formatTime, hasRule, INPUT_CLASS, READ_ONLY_HINT, ruleKey, suggestedMode } from '../lib/utils'
import { Badge, ErrorBanner, MethodBadge, PageHeader, RefreshButton, Spinner, SuccessBanner } from '../components/ui'
import { LOG_TONES } from '../lib/tones'
import { RevokeModal } from '../components/RevokeModal'
import type { RevokeTarget } from '../components/RevokeModal'
import { LedgerVerifyBadge } from '../components/LedgerVerifyBadge'
import { LogDetailPanel } from '../components/LogDetailPanel'
import { EndUserBadge } from '../components/EndUserBadge'
import { AuditorPackModal } from '../components/AuditorPackModal'
import { ProBadge } from '../components/LicenseCard'

/**
 * Calls that matched no rule and were refused by default deny. The gateway writes exactly
 * these details (interceptor.ts for HTTP, toolGuard.ts for MCP tool calls); the /logs
 * `unknown=1` filter matches the same rows.
 */
const UNKNOWN_DETAILS = new Set(['default-deny', 'mcp default-deny'])
const isUnknownEndpoint = (log: LogRow): boolean => log.status === 'BLOCKED' && UNKNOWN_DETAILS.has(log.detail ?? '')

/** Filters another tab can open the Audit Logs with (e.g. a row in Analytics). */
export interface LogsFilter {
  method?: string
  /** Exact path match (the "Endpoint Path Contains" box is a substring search). */
  path?: string
  /** Exact User-Agent, as Analytics labels it ("Unknown Agent" = none recorded). */
  userAgent?: string
  /** Approval / request id. */
  actionId?: number
  /** ISO start time, e.g. the start of the Analytics window. */
  from?: string
}

const KNOWN_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'MCP']

/** ISO -> the value a datetime-local input expects (local time, minutes). */
function toLocalInput(iso: string | undefined): string {
  if (!iso) return ''
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return ''
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`
}

export function LogsTab({
  rulesApi,
  readOnly,
  initialFilter = null,
  onCreateRule,
  onOpenApproval,
  isPro = true,
  onOpenLicense,
}: {
  rulesApi: RulesApi
  readOnly: boolean
  initialFilter?: LogsFilter | null
  /** Open the rule editor with a new rule pre-filled for this method and path. */
  onCreateRule?: (method: string, path: string) => void
  /** Open Pending Approvals on this request id. */
  onOpenApproval?: (id: number) => void
  /** The Auditor Evidence Pack is Pro. */
  isPro?: boolean
  onOpenLicense?: () => void
}) {
  const { rules, setRules, loading: rulesLoading, reload: reloadRules } = rulesApi
  const [logs, setLogs] = useState<LogRow[]>([])
  const [error, setError] = useState<string | null>(null)
  const [adding, setAdding] = useState<Set<string>>(new Set())
  const [revokeTarget, setRevokeTarget] = useState<RevokeTarget | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [exporting, setExporting] = useState(false)
  const [expanded, setExpanded] = useState<Set<number>>(new Set())
  const [packOpen, setPackOpen] = useState(false)
  const requestId = useRef(0)

  function toggleExpanded(id: number) {
    setExpanded((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  // Filter state
  const [statusFilter, setStatusFilter] = useState('')
  const [methodFilter, setMethodFilter] = useState(initialFilter?.method?.toUpperCase() ?? '')
  const [searchFilter, setSearchFilter] = useState('')
  const [fromFilter, setFromFilter] = useState(toLocalInput(initialFilter?.from))
  const [toFilter, setToFilter] = useState('')
  const [limitFilter, setLimitFilter] = useState('100')
  const [shadowOnly, setShadowOnly] = useState(false)
  const [unknownOnly, setUnknownOnly] = useState(false)
  const [actionIdFilter, setActionIdFilter] = useState(initialFilter?.actionId ? String(initialFilter.actionId) : '')
  const [exactPath, setExactPath] = useState(initialFilter?.path ?? '')
  const [userAgentFilter, setUserAgentFilter] = useState(initialFilter?.userAgent ?? '')

  // Typing in the search boxes should not fire one request per keystroke.
  const debouncedSearch = useDebouncedValue(searchFilter.trim(), 300)
  const debouncedActionId = useDebouncedValue(actionIdFilter.trim().replace(/^#/, ''), 300)
  const actionIdInvalid = actionIdFilter.trim() !== '' && !/^#?\d+$/.test(actionIdFilter.trim())

  const hasActiveFilters = Boolean(
    statusFilter ||
      methodFilter ||
      searchFilter.trim() ||
      fromFilter ||
      toFilter ||
      limitFilter !== '100' ||
      shadowOnly ||
      unknownOnly ||
      actionIdFilter.trim() ||
      exactPath ||
      userAgentFilter
  )

  const params = useMemo(() => {
    const p: Record<string, string> = {}
    if (statusFilter) p.status = statusFilter
    if (methodFilter) p.method = methodFilter
    if (debouncedSearch) p.search = debouncedSearch
    if (fromFilter) {
      const d = new Date(fromFilter)
      if (!Number.isNaN(d.getTime())) p.from = d.toISOString()
    }
    if (toFilter) {
      const d = new Date(toFilter)
      if (!Number.isNaN(d.getTime())) p.to = d.toISOString()
    }
    if (limitFilter) p.limit = limitFilter
    if (shadowOnly) p.shadow = '1'
    if (unknownOnly) p.unknown = '1'
    if (debouncedActionId) p.action_id = debouncedActionId
    if (exactPath) p.path = exactPath
    if (userAgentFilter) p.user_agent = userAgentFilter
    return p
  }, [statusFilter, methodFilter, debouncedSearch, fromFilter, toFilter, limitFilter, shadowOnly, unknownOnly, debouncedActionId, exactPath, userAgentFilter])
  // A manual refresh bumps this, which re-runs the fetch effect for the same filters.
  const [reloadToken, setReloadToken] = useState(0)
  const requestKey = `${JSON.stringify(params)}#${reloadToken}`

  // "Loading" = the rows on screen are not the answer to the current request yet. Derived instead of
  // set when the fetch starts, so the effect only ever sets state once the request has settled.
  const [loadedKey, setLoadedKey] = useState<string | null>(null)
  const loading = loadedKey !== requestKey

  useEffect(() => {
    const thisRequest = ++requestId.current
    api.get<LogRow[]>('/logs', { params }).then(
      (res) => {
        if (thisRequest !== requestId.current) return // a newer request superseded this one
        setLogs(res.data)
        setError(null)
        setLoadedKey(requestKey)
      },
      (err: unknown) => {
        if (thisRequest !== requestId.current) return
        setError(errorMessage(err))
        setLoadedKey(requestKey)
      }
    )
  }, [params, requestKey])

  function load() {
    setReloadToken((t) => t + 1)
  }

  async function refreshAll() {
    load()
    await reloadRules()
  }

  function clearFilters() {
    setStatusFilter('')
    setMethodFilter('')
    setSearchFilter('')
    setFromFilter('')
    setToFilter('')
    setLimitFilter('100')
    setShadowOnly(false)
    setUnknownOnly(false)
    setActionIdFilter('')
    setExactPath('')
    setUserAgentFilter('')
  }

  async function quickAdd(path: string, method: string) {
    if (readOnly) return
    // The rule is pinned to this log row's method: GET starts as ALLOW, anything that
    // changes data as REQUIRE_APPROVAL. Edit or widen it to ANY in Access Rules.
    const mode = suggestedMode(method)
    const key = ruleKey(method, path)
    setAdding((prev) => new Set(prev).add(key))
    try {
      const res = await api.post<{ success: boolean; rules: Rules }>('/rules', {
        [key]: { mode, description: '' },
      })
      setRules(res.data.rules)
      setError(null)
    } catch (err) {
      setError(`Could not add ${key}: ${errorMessage(err)}`)
    } finally {
      setAdding((prev) => {
        const next = new Set(prev)
        next.delete(key)
        return next
      })
    }
  }

  // Revocations are logged as BLOCKED rows that point at the same action.
  const revokedActions = new Set(
    logs.filter((l) => l.status === 'BLOCKED' && l.action_id && l.detail?.startsWith('Revoked approval')).map((l) => l.action_id as number)
  )

  async function exportCsv() {
    setExporting(true)
    try {
      // Same filters as the table (the server applies them identically to the export).
      const params: Record<string, string> = {}
      if (statusFilter) params.status = statusFilter
      if (methodFilter) params.method = methodFilter
      if (debouncedSearch) params.search = debouncedSearch
      if (fromFilter) params.from = new Date(fromFilter).toISOString()
      if (toFilter) params.to = new Date(toFilter).toISOString()
      if (shadowOnly) params.shadow = '1'
      if (unknownOnly) params.unknown = '1'
      if (debouncedActionId) params.action_id = debouncedActionId
      if (exactPath) params.path = exactPath
      if (userAgentFilter) params.user_agent = userAgentFilter
      const res = await api.get<Blob>('/logs/export.csv', { params, responseType: 'blob' })
      const url = URL.createObjectURL(res.data)
      const a = document.createElement('a')
      a.href = url
      a.download = `mont-audit-${new Date().toISOString().slice(0, 10)}.csv`
      document.body.appendChild(a)
      a.click()
      a.remove()
      URL.revokeObjectURL(url)
    } catch (err) {
      setError(`Could not export: ${errorMessage(err)}`)
    } finally {
      setExporting(false)
    }
  }

  function onRevoked(result: RevokeResponse) {
    setRevokeTarget(null)
    const blocked = result.blocked.map((b) => `${b.kind === 'ip' ? 'IP' : 'agent key'} ${b.label ?? b.value}`).join(' and ')
    setNotice(
      `Approval #${result.id} revoked. Blocked ${blocked || 'the caller'}; auto-rejected ${result.autoRejected.length} queued request(s); rollback webhook: ${result.rollbackStatus}.`
    )
    load()
  }

  return (
    <>
      <PageHeader
        title="Audit Logs"
        subtitle="Inspect and filter agent traffic. Revoke any approved action and block its caller in one click."
        action={
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => void exportCsv()}
              disabled={exporting}
              title="Download the filtered audit log as CSV (for accounting or chargeback disputes)"
              className="inline-flex shrink-0 items-center gap-2 rounded-lg border border-slate-200 bg-white px-3.5 py-2 text-sm font-medium text-slate-700 shadow-sm transition hover:bg-slate-50 disabled:opacity-60"
            >
              {exporting ? <Spinner /> : <Download className="h-4 w-4" aria-hidden="true" />}
              Export CSV
            </button>
            <button
              type="button"
              onClick={() => (isPro ? setPackOpen(true) : onOpenLicense?.())}
              title={
                isPro
                  ? 'Download an auditor attestation report or a checksummed JSON evidence bundle'
                  : 'The Auditor Evidence Pack is a Mont Pro feature. Click to activate a key.'
              }
              className="inline-flex shrink-0 items-center gap-2 rounded-lg border border-slate-200 bg-white px-3.5 py-2 text-sm font-medium text-slate-700 shadow-sm transition hover:bg-slate-50"
            >
              <FileCheck2 className="h-4 w-4 text-indigo-600" aria-hidden="true" />
              Export Auditor Pack
              {!isPro && <ProBadge />}
            </button>
            <RefreshButton onClick={() => void refreshAll()} loading={loading} />
          </div>
        }
      />

      {error && <ErrorBanner message={error} onDismiss={() => setError(null)} />}
      {notice && <SuccessBanner message={notice} onDismiss={() => setNotice(null)} />}

      <LedgerVerifyBadge />

      <div className="mb-5 rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <div className="mb-3 flex items-center justify-between">
          <span className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-slate-500">
            <Filter className="h-3.5 w-3.5 text-indigo-500" aria-hidden="true" />
            Filter Audit Logs
          </span>
          {hasActiveFilters && (
            <button
              type="button"
              onClick={clearFilters}
              className="inline-flex items-center gap-1 text-xs font-medium text-indigo-600 hover:text-indigo-800"
            >
              <X className="h-3.5 w-3.5" aria-hidden="true" />
              Clear filters
            </button>
          )}
        </div>

        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-6">
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-slate-600">Status</span>
            <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} className={INPUT_CLASS}>
              <option value="">All statuses</option>
              <option value="ALLOWED">ALLOWED</option>
              <option value="QUEUED">QUEUED</option>
              <option value="BLOCKED">BLOCKED</option>
              <option value="RATE_LIMITED">RATE LIMITED</option>
              <option value="APPROVED">APPROVED</option>
              <option value="REJECTED">REJECTED</option>
              <option value="RESPONSE_BLOCKED">RESPONSE BLOCKED</option>
              <option value="RESPONSE_SCRUBBED">RESPONSE SCRUBBED</option>
            </select>
          </label>

          <label className="block">
            <span className="mb-1 block text-xs font-medium text-slate-600">HTTP Method</span>
            <select value={methodFilter} onChange={(e) => setMethodFilter(e.target.value)} className={INPUT_CLASS}>
              <option value="">All methods</option>
              <option value="GET">GET</option>
              <option value="POST">POST</option>
              <option value="PUT">PUT</option>
              <option value="PATCH">PATCH</option>
              <option value="DELETE">DELETE</option>
              <option value="MCP">MCP (tool calls)</option>
              {methodFilter && !KNOWN_METHODS.includes(methodFilter) && <option value={methodFilter}>{methodFilter}</option>}
            </select>
          </label>

          <label className="block">
            <span className="mb-1 block text-xs font-medium text-slate-600">Request ID</span>
            <input
              type="text"
              inputMode="numeric"
              value={actionIdFilter}
              onChange={(e) => setActionIdFilter(e.target.value)}
              placeholder="e.g. 736"
              title="The #number shown in Telegram / Slack alerts and Pending Approvals"
              aria-invalid={actionIdInvalid}
              className={`${INPUT_CLASS} font-mono ${actionIdInvalid ? 'border-red-400' : ''}`}
            />
          </label>

          <label className="block">
            <span className="mb-1 block text-xs font-medium text-slate-600">Endpoint Path Contains</span>
            <div className="relative">
              <Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-slate-400" aria-hidden="true" />
              <input
                type="text"
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
                placeholder="/api/book-flight"
                className={`${INPUT_CLASS} pl-9 font-mono`}
              />
            </div>
          </label>

          <label className="block">
            <span className="mb-1 block text-xs font-medium text-slate-600">From Date/Time</span>
            <input
              type="datetime-local"
              value={fromFilter}
              onChange={(e) => setFromFilter(e.target.value)}
              className={INPUT_CLASS}
            />
          </label>

          <label className="block">
            <span className="mb-1 block text-xs font-medium text-slate-600">To Date/Time</span>
            <input
              type="datetime-local"
              value={toFilter}
              onChange={(e) => setToFilter(e.target.value)}
              className={INPUT_CLASS}
            />
          </label>
        </div>

        {(exactPath || userAgentFilter) && (
          <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
            <span className="font-medium text-slate-500">Opened from Analytics:</span>
            {exactPath && (
              <span className="inline-flex items-center gap-1 rounded-full bg-indigo-50 py-0.5 pl-2.5 pr-1 font-medium text-indigo-800 ring-1 ring-inset ring-indigo-200">
                path is <span className="font-mono">{exactPath}</span>
                <button type="button" onClick={() => setExactPath('')} aria-label="Remove the exact path filter" className="rounded-full p-0.5 hover:bg-indigo-100">
                  <X className="h-3 w-3" aria-hidden="true" />
                </button>
              </span>
            )}
            {userAgentFilter && (
              <span className="inline-flex max-w-full items-center gap-1 rounded-full bg-indigo-50 py-0.5 pl-2.5 pr-1 font-medium text-indigo-800 ring-1 ring-inset ring-indigo-200">
                User-Agent is <span className="truncate font-mono" title={userAgentFilter}>{userAgentFilter}</span>
                <button type="button" onClick={() => setUserAgentFilter('')} aria-label="Remove the User-Agent filter" className="rounded-full p-0.5 hover:bg-indigo-100">
                  <X className="h-3 w-3" aria-hidden="true" />
                </button>
              </span>
            )}
          </div>
        )}

        <div className="mt-3 flex flex-wrap items-center justify-between gap-2 border-t border-slate-100 pt-2.5 text-xs text-slate-500">
          <span className="flex flex-wrap items-center gap-3">
            <span>
              Showing <strong className="font-semibold text-slate-800">{logs.length}</strong> matching log entries
            </span>
            <label className="inline-flex items-center gap-1.5">
              <input type="checkbox" checked={shadowOnly} onChange={(e) => setShadowOnly(e.target.checked)} className="h-3.5 w-3.5 rounded border-slate-300" />
              Only shadow-mode hits (would have been blocked / held)
            </label>
            <label className="inline-flex items-center gap-1.5">
              <input type="checkbox" checked={unknownOnly} onChange={(e) => setUnknownOnly(e.target.checked)} className="h-3.5 w-3.5 rounded border-slate-300" />
              Only unknown endpoints (no rule matched)
            </label>
          </span>
          <div className="flex items-center gap-2">
            <label htmlFor="max-rows">Max rows:</label>
            <select
              id="max-rows"
              value={limitFilter}
              onChange={(e) => setLimitFilter(e.target.value)}
              className="rounded-md border border-slate-200 bg-white px-2 py-1 text-xs font-medium text-slate-700"
            >
              {['50', '100', '250', '500', '1000'].map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      <div className="w-full max-w-full overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
        {/* Fixed layout: the table is exactly as wide as this box (long paths and chips wrap instead of
            widening it), so the expanded row, the Actions column and the page never run off-screen.
            Below the minimum width it scrolls sideways inside this box only. */}
        <div className="w-full max-w-full overflow-x-auto">
          <table className="w-full min-w-[52rem] table-fixed divide-y divide-slate-200">
            <colgroup>
              <col className="w-[12rem]" />
              <col className="w-[6rem]" />
              <col />
              <col className="w-[10.5rem]" />
              <col className="w-[6rem]" />
              <col className="w-[10.5rem]" />
            </colgroup>
            <thead className="bg-slate-50">
              <tr>
                {['Timestamp', 'Request ID', 'Path', 'Status', 'Method', 'Actions'].map((h) => (
                  <th
                    key={h}
                    scope="col"
                    className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500"
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {loading ? (
                [0, 1, 2, 3, 4].map((i) => (
                  <tr key={i} className="animate-pulse">
                    {[40, 12, 48, 24, 16, 20].map((w, j) => (
                      <td key={j} className="px-4 py-4">
                        <div className="h-4 max-w-full rounded bg-slate-200" style={{ width: `${w * 3}px` }} />
                      </td>
                    ))}
                  </tr>
                ))
              ) : logs.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-16 text-center text-sm text-slate-500">
                    {hasActiveFilters ? 'No audit logs match the selected filters.' : 'No requests logged yet.'}
                  </td>
                </tr>
              ) : (
                logs.map((log) => {
                  const unregistered = !rulesLoading && !hasRule(rules, log.method, log.path)
                  const isAdding = adding.has(ruleKey(log.method, log.path))
                  const suggested = suggestedMode(log.method)
                  const unknown = isUnknownEndpoint(log)
                  const open = expanded.has(log.id)
                  return (
                    <Fragment key={log.id}>
                    <tr className={`transition ${unknown ? 'bg-orange-50/40 hover:bg-orange-50' : 'hover:bg-slate-50'} ${open ? 'bg-slate-50' : ''}`}>
                      <td className="whitespace-nowrap px-4 py-3.5 text-sm text-slate-600">
                        <button
                          type="button"
                          onClick={() => toggleExpanded(log.id)}
                          aria-expanded={open}
                          title={open ? 'Hide details' : 'Show payloads, attribution and ledger hash'}
                          className="-ml-2 inline-flex items-center gap-1 rounded-md px-1 py-0.5 hover:bg-slate-100 hover:text-slate-900"
                        >
                          {open ? <ChevronDown className="h-4 w-4 text-slate-400" aria-hidden="true" /> : <ChevronRight className="h-4 w-4 text-slate-400" aria-hidden="true" />}
                          {formatTime(log.timestamp)}
                        </button>
                      </td>
                      <td className="whitespace-nowrap px-4 py-3.5 font-mono text-sm">
                        {log.action_id ? (
                          onOpenApproval ? (
                            <button
                              type="button"
                              onClick={() => onOpenApproval(log.action_id as number)}
                              title={`Open request #${log.action_id} in Pending Approvals`}
                              className="rounded-md bg-slate-100 px-1.5 py-0.5 font-semibold text-indigo-700 hover:bg-indigo-50 hover:underline"
                            >
                              #{log.action_id}
                            </button>
                          ) : (
                            <span className="text-slate-700">#{log.action_id}</span>
                          )
                        ) : (
                          <span className="text-slate-300" title="Only requests that went to approval have a request ID">—</span>
                        )}
                      </td>
                      <td className="min-w-0 px-4 py-3.5">
                        <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
                          <span className="min-w-0 break-all font-mono text-sm text-slate-900">{log.path}</span>
                          {log.workspace_slug && log.workspace_slug !== 'default' && (
                            <span className="rounded-md bg-indigo-50 px-1.5 py-0.5 text-xs font-medium text-indigo-700">{log.workspace_slug}</span>
                          )}
                          {log.shadow && (
                            <span
                              className="rounded-md bg-slate-800 px-1.5 py-0.5 text-xs font-semibold text-white"
                              title="A SHADOW rule let this through; enforced, it would have done this"
                            >
                              shadow: would {log.shadow === 'BLOCK' ? 'block' : 'hold'}
                            </span>
                          )}
                          {log.modified_payload && (
                            <span className="rounded-md bg-indigo-100 px-1.5 py-0.5 text-xs font-semibold text-indigo-800" title={log.modified_payload}>
                              edited by approver
                            </span>
                          )}
                          {log.agent_key && (
                            <span className="rounded-md bg-slate-100 px-1.5 py-0.5 text-xs font-medium text-slate-600">
                              {log.agent_key}
                            </span>
                          )}
                          {log.end_user && (
                            <span className="inline-flex min-w-0 max-w-full flex-wrap items-center gap-1">
                              <span
                                className="inline-flex min-w-0 max-w-full items-center gap-1 rounded-md bg-sky-50 px-1.5 py-0.5 text-xs font-medium text-sky-800"
                                title={`On behalf of ${log.end_user}`}
                              >
                                <UserRound className="h-3 w-3 shrink-0" aria-hidden="true" />
                                <span className="truncate">{log.end_user}</span>
                              </span>
                              <EndUserBadge verified={Boolean(log.end_user_verified)} />
                            </span>
                          )}
                          {log.approved_by && (log.status === 'APPROVED' || log.status === 'REJECTED') && (
                            <span
                              className={`inline-flex min-w-0 max-w-full items-center gap-1 rounded-md px-1.5 py-0.5 text-xs font-medium ${
                                log.status === 'APPROVED' ? 'bg-emerald-50 text-emerald-800' : 'bg-red-50 text-red-800'
                              }`}
                              title={`${log.status === 'APPROVED' ? 'Approved' : 'Rejected'} by ${log.approved_by}`}
                            >
                              <UserCheck className="h-3 w-3 shrink-0" aria-hidden="true" />
                              {/* Compact in the list (full name on hover and in the expanded row). */}
                              <span className="truncate">
                                {log.status === 'APPROVED' ? 'approved by' : 'rejected by'} {log.approved_by}
                              </span>
                            </span>
                          )}
                          {unregistered && (
                            <button
                              type="button"
                              onClick={() => void quickAdd(log.path, log.method)}
                              disabled={isAdding || readOnly}
                              title={readOnly ? READ_ONLY_HINT : `Add “${log.method} ${log.path}” as ${suggested}`}
                              className="inline-flex items-center gap-1 rounded-md border border-indigo-200 bg-indigo-50 px-2 py-1 text-xs font-semibold text-indigo-700 transition hover:bg-indigo-100 disabled:cursor-not-allowed disabled:opacity-60"
                            >
                              {isAdding ? <Spinner className="h-3 w-3" /> : <Plus className="h-3 w-3" aria-hidden="true" />}
                              Add to Rules
                            </button>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-3.5">
                        {unknown ? (
                          <span
                            title="No rule matched this endpoint, so the gateway blocked it (default deny). The agent was told 403 Forbidden."
                            className="inline-flex items-center gap-1.5 rounded-full border border-dashed border-orange-400 bg-orange-50 px-2.5 py-0.5 text-xs font-semibold text-orange-800"
                          >
                            <span className="h-1.5 w-1.5 rounded-full bg-orange-500" aria-hidden="true" />
                            UNKNOWN ENDPOINT
                          </span>
                        ) : (
                          <Badge tone={LOG_TONES[log.status] ?? 'slate'}>{log.status.replace(/_/g, ' ')}</Badge>
                        )}
                      </td>
                      <td className="whitespace-nowrap px-4 py-3.5">
                        <MethodBadge method={log.method} />
                      </td>
                      <td className="whitespace-nowrap px-4 py-3.5">
                        {log.status === 'APPROVED' && log.action_id ? (
                          revokedActions.has(log.action_id) ? (
                            <span className="text-xs font-medium text-red-700">Revoked</span>
                          ) : (
                            <button
                              type="button"
                              onClick={() =>
                                setRevokeTarget({
                                  actionId: log.action_id as number,
                                  method: log.method,
                                  path: log.path,
                                  agentKey: log.agent_key,
                                  callerIp: log.caller_ip,
                                })
                              }
                              disabled={readOnly}
                              title={readOnly ? READ_ONLY_HINT : 'Block the caller, reject its queued requests and fire the rollback webhook'}
                              className="inline-flex items-center gap-1 rounded-md border border-red-200 bg-red-50 px-2 py-1 text-xs font-semibold text-red-700 transition hover:bg-red-100 disabled:cursor-not-allowed disabled:opacity-60"
                            >
                              <ShieldOff className="h-3 w-3" aria-hidden="true" />
                              Revoke &amp; Block
                            </button>
                          )
                        ) : unknown ? (
                          unregistered && onCreateRule ? (
                            <button
                              type="button"
                              onClick={() => onCreateRule(log.method, log.path)}
                              disabled={readOnly}
                              title={readOnly ? READ_ONLY_HINT : `Open the rule editor with ${log.method} ${log.path} filled in`}
                              className="inline-flex items-center gap-1 rounded-md bg-orange-600 px-2 py-1 text-xs font-semibold text-white shadow-sm transition hover:bg-orange-500 disabled:cursor-not-allowed disabled:opacity-60"
                            >
                              Create Rule
                              <ArrowRight className="h-3 w-3" aria-hidden="true" />
                            </button>
                          ) : (
                            <span className="text-xs text-slate-500">{unregistered ? 'No rule matched' : 'Rule added since'}</span>
                          )
                        ) : log.detail ? (
                          <span className="block max-w-full truncate text-xs text-slate-500" title={log.detail}>
                            {log.detail}
                          </span>
                        ) : null}
                      </td>
                    </tr>
                    {open && (
                      <tr className="bg-slate-50">
                        <td colSpan={6} className="min-w-0 border-t border-slate-100 px-4 py-4">
                          <LogDetailPanel id={log.id} />
                        </td>
                      </tr>
                    )}
                    </Fragment>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {packOpen && (
        <AuditorPackModal
          agents={[...new Set(logs.map((l) => l.agent_key).filter((a): a is string => Boolean(a)))].sort()}
          onClose={() => setPackOpen(false)}
          onOpenLicense={onOpenLicense}
        />
      )}

      {revokeTarget && <RevokeModal target={revokeTarget} onClose={() => setRevokeTarget(null)} onDone={onRevoked} />}
    </>
  )
}
