import { useCallback, useEffect, useRef, useState } from 'react'
import { Filter, Plus, Search, X } from 'lucide-react'
import { api, errorMessage } from '../lib/api'
import { useDebouncedValue } from '../hooks/useDebouncedValue'
import type { RulesApi } from '../hooks/useRules'
import type { LogRow, Rules } from '../lib/types'
import { formatTime, hasRule, INPUT_CLASS, READ_ONLY_HINT, ruleKey, suggestedMode } from '../lib/utils'
import { Badge, ErrorBanner, LOG_TONES, MethodBadge, PageHeader, RefreshButton, Spinner } from '../components/ui'


export function LogsTab({ rulesApi, readOnly }: { rulesApi: RulesApi; readOnly: boolean }) {
  const { rules, setRules, loading: rulesLoading, reload: reloadRules } = rulesApi
  const [logs, setLogs] = useState<LogRow[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [adding, setAdding] = useState<Set<string>>(new Set())
  const requestId = useRef(0)

  // Filter state
  const [statusFilter, setStatusFilter] = useState('')
  const [methodFilter, setMethodFilter] = useState('')
  const [searchFilter, setSearchFilter] = useState('')
  const [fromFilter, setFromFilter] = useState('')
  const [toFilter, setToFilter] = useState('')
  const [limitFilter, setLimitFilter] = useState('100')

  // Typing in the search box should not fire one request per keystroke.
  const debouncedSearch = useDebouncedValue(searchFilter.trim(), 300)

  const hasActiveFilters = Boolean(
    statusFilter || methodFilter || searchFilter.trim() || fromFilter || toFilter || limitFilter !== '100'
  )

  const load = useCallback(async () => {
    const thisRequest = ++requestId.current
    setLoading(true)
    try {
      const params: Record<string, string> = {}
      if (statusFilter) params.status = statusFilter
      if (methodFilter) params.method = methodFilter
      if (debouncedSearch) params.search = debouncedSearch
      if (fromFilter) {
        const d = new Date(fromFilter)
        if (!Number.isNaN(d.getTime())) params.from = d.toISOString()
      }
      if (toFilter) {
        const d = new Date(toFilter)
        if (!Number.isNaN(d.getTime())) params.to = d.toISOString()
      }
      if (limitFilter) params.limit = limitFilter

      const res = await api.get<LogRow[]>('/logs', { params })
      if (thisRequest !== requestId.current) return // a newer request superseded this one
      setLogs(res.data)
      setError(null)
    } catch (err) {
      if (thisRequest !== requestId.current) return
      setError(errorMessage(err))
    } finally {
      if (thisRequest === requestId.current) setLoading(false)
    }
  }, [statusFilter, methodFilter, debouncedSearch, fromFilter, toFilter, limitFilter])

  useEffect(() => {
    void load()
  }, [load])

  async function refreshAll() {
    await Promise.all([load(), reloadRules()])
  }

  function clearFilters() {
    setStatusFilter('')
    setMethodFilter('')
    setSearchFilter('')
    setFromFilter('')
    setToFilter('')
    setLimitFilter('100')
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

  return (
    <>
      <PageHeader
        title="Audit Logs"
        subtitle="Inspect and filter agent traffic by status, HTTP method, endpoint path, and timestamp."
        action={<RefreshButton onClick={() => void refreshAll()} loading={loading} />}
      />

      {error && <ErrorBanner message={error} onDismiss={() => setError(null)} />}

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
            </select>
          </label>

          <label className="block sm:col-span-2">
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

        <div className="mt-3 flex flex-wrap items-center justify-between gap-2 border-t border-slate-100 pt-2.5 text-xs text-slate-500">
          <span>
            Showing <strong className="font-semibold text-slate-800">{logs.length}</strong> matching log entries
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

      <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-slate-200">
            <thead className="bg-slate-50">
              <tr>
                {['Timestamp', 'Path', 'Status', 'Method'].map((h) => (
                  <th
                    key={h}
                    scope="col"
                    className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500"
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
                    {[40, 48, 24, 16].map((w, j) => (
                      <td key={j} className="px-6 py-4">
                        <div className="h-4 rounded bg-slate-200" style={{ width: `${w * 3}px` }} />
                      </td>
                    ))}
                  </tr>
                ))
              ) : logs.length === 0 ? (
                <tr>
                  <td colSpan={4} className="px-6 py-16 text-center text-sm text-slate-500">
                    {hasActiveFilters ? 'No audit logs match the selected filters.' : 'No requests logged yet.'}
                  </td>
                </tr>
              ) : (
                logs.map((log) => {
                  const unregistered = !rulesLoading && !hasRule(rules, log.method, log.path)
                  const isAdding = adding.has(ruleKey(log.method, log.path))
                  const suggested = suggestedMode(log.method)
                  return (
                    <tr key={log.id} className="transition hover:bg-slate-50">
                      <td className="whitespace-nowrap px-6 py-3.5 text-sm text-slate-600">
                        {formatTime(log.timestamp)}
                      </td>
                      <td className="whitespace-nowrap px-6 py-3.5">
                        <div className="flex items-center gap-3">
                          <span className="font-mono text-sm text-slate-900">{log.path}</span>
                          {log.agent_key && (
                            <span className="rounded-md bg-slate-100 px-1.5 py-0.5 text-xs font-medium text-slate-600">
                              {log.agent_key}
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
                      <td className="whitespace-nowrap px-6 py-3.5">
                        <Badge tone={LOG_TONES[log.status] ?? 'slate'}>{log.status.replace('_', ' ')}</Badge>
                      </td>
                      <td className="whitespace-nowrap px-6 py-3.5">
                        <MethodBadge method={log.method} />
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </>
  )
}
