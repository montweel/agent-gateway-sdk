import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Activity, BarChart3, Bot, EyeOff, Filter, ShieldAlert } from 'lucide-react'
import { api, errorMessage } from '../lib/api'
import type { HourlyBucket, AnalyticsResponse, LogStatus } from '../lib/types'
import { formatBucketLabel } from '../lib/utils'
import { ProBadge } from '../components/LicenseCard'
import { ErrorBanner, MethodBadge, PageHeader, RefreshButton } from '../components/ui'

type WindowId = '1h' | '2h' | '24h' | '1w'
const WINDOWS: { id: WindowId; label: string }[] = [
  { id: '1h', label: '1h' },
  { id: '2h', label: '2h' },
  { id: '24h', label: '24h' },
  { id: '1w', label: '1w' },
]

const CHART_SERIES: {
  status: LogStatus
  label: string
  swatch: string
  textColor: string
}[] = [
  { status: 'ALLOWED', label: 'Allowed', swatch: 'bg-emerald-500', textColor: 'text-emerald-300' },
  { status: 'QUEUED', label: 'Queued', swatch: 'bg-amber-500', textColor: 'text-amber-300' },
  { status: 'BLOCKED', label: 'Blocked', swatch: 'bg-red-500', textColor: 'text-red-300' },
  { status: 'RATE_LIMITED', label: 'Rate Limited', swatch: 'bg-violet-500', textColor: 'text-violet-300' },
  { status: 'APPROVED', label: 'Approved', swatch: 'bg-green-600', textColor: 'text-green-300' },
  { status: 'REJECTED', label: 'Rejected', swatch: 'bg-rose-500', textColor: 'text-rose-300' },
]

export function AnalyticsTab({ isPro, onOpenLicense }: { isPro: boolean; onOpenLicense: () => void }) {
  const [windowParam, setWindowParam] = useState<WindowId>('24h')
  const [analytics, setAnalytics] = useState<AnalyticsResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [hiddenStatuses, setHiddenStatuses] = useState<Set<LogStatus>>(new Set())
  const requestId = useRef(0)

  const toggleStatus = (status: LogStatus) => {
    setHiddenStatuses((prev) => {
      const next = new Set(prev)
      if (next.has(status)) {
        next.delete(status)
      } else {
        next.add(status)
      }
      return next
    })
  }

  const toggleAnomaliesOnly = () => {
    setHiddenStatuses((prev) => {
      const next = new Set(prev)
      if (next.has('ALLOWED')) {
        next.delete('ALLOWED')
      } else {
        next.add('ALLOWED')
      }
      return next
    })
  }

  const loadAnalytics = useCallback(async () => {
    const thisRequest = ++requestId.current
    setLoading(true)
    try {
      const res = await api.get<AnalyticsResponse>('/logs/analytics', { params: { window: windowParam } })
      if (thisRequest !== requestId.current) return
      setAnalytics(res.data)
      setError(null)
    } catch (err) {
      if (thisRequest !== requestId.current) return
      setError(errorMessage(err))
    } finally {
      if (thisRequest === requestId.current) setLoading(false)
    }
  }, [windowParam])

  useEffect(() => {
    void loadAnalytics()
  }, [loadAnalytics])

  const summary = useMemo(() => {
    const counts: Record<LogStatus, number> = {
      ALLOWED: 0,
      BLOCKED: 0,
      QUEUED: 0,
      RATE_LIMITED: 0,
      APPROVED: 0,
      REJECTED: 0,
    }
    if (analytics?.statusTotals) {
      for (const item of analytics.statusTotals) {
        if (item.status in counts) counts[item.status] = item.count
      }
    }
    const total =
      counts.ALLOWED +
      counts.BLOCKED +
      counts.QUEUED +
      counts.RATE_LIMITED +
      counts.APPROVED +
      counts.REJECTED
    return { ...counts, total }
  }, [analytics])

  const hourly = analytics?.hourly ?? []
  const topEndpoints = analytics?.topEndpoints ?? []
  const topAgents = analytics?.topAgents ?? []

  // Helper to compute visible total for a bucket based on active legend toggles
  const getVisibleBucketTotal = useCallback(
    (b: HourlyBucket) => {
      let sum = 0
      for (const s of CHART_SERIES) {
        if (!hiddenStatuses.has(s.status)) {
          sum += b[s.status] ?? 0
        }
      }
      return sum
    },
    [hiddenStatuses]
  )

  const maxVisibleBucketTotal = useMemo(
    () => Math.max(...hourly.map((h) => getVisibleBucketTotal(h)), 1),
    [hourly, getVisibleBucketTotal]
  )

  const visibleSummaryTotal = useMemo(() => {
    let sum = 0
    for (const s of CHART_SERIES) {
      if (!hiddenStatuses.has(s.status)) {
        sum += summary[s.status] ?? 0
      }
    }
    return sum
  }, [summary, hiddenStatuses])

  const cards = [
    { label: 'Total Requests', value: summary.total, color: 'text-slate-900' },
    { label: 'Allowed', value: summary.ALLOWED, color: 'text-emerald-600' },
    { label: 'Queued / Approval', value: summary.QUEUED, color: 'text-amber-600' },
    { label: 'Blocked', value: summary.BLOCKED, color: 'text-red-600' },
    { label: 'Rate Limited', value: summary.RATE_LIMITED, color: 'text-violet-600' },
    { label: 'Approved', value: summary.APPROVED, color: 'text-green-600' },
    { label: 'Rejected', value: summary.REJECTED, color: 'text-rose-600' },
  ]

  return (
    <>
      <PageHeader
        title="Traffic Analytics"
        subtitle="Inspect agent request distribution, block rates, and traffic trends over time."
        action={
          <div className="flex items-center gap-3">
            <div className="inline-flex rounded-lg bg-slate-200 p-1" role="group" aria-label="Time window">
              {WINDOWS.map((w) => {
                const locked = w.id === '1w' && !isPro
                return (
                  <button
                    key={w.id}
                    onClick={() => (locked ? onOpenLicense() : setWindowParam(w.id))}
                    aria-pressed={windowParam === w.id}
                    title={locked ? 'Pro feature: renew your free Mont Pro key to unlock the 7-day window' : undefined}
                    className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1 text-xs font-semibold transition ${
                      windowParam === w.id
                        ? 'bg-white text-slate-900 shadow-sm'
                        : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    {w.label}
                    {locked && <ProBadge />}
                  </button>
                )
              })}
            </div>
            <RefreshButton onClick={() => void loadAnalytics()} loading={loading} />
          </div>
        }
      />

      {error && <ErrorBanner message={error} onDismiss={() => setError(null)} />}

      <div className="mb-6 grid grid-cols-2 gap-4 sm:grid-cols-4 lg:grid-cols-7">
        {cards.map((c) => (
          <div key={c.label} className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
            <p className="text-sm text-slate-500">{c.label}</p>
            <p className={`mt-1 text-3xl font-semibold ${c.color}`}>{loading ? '–' : c.value}</p>
          </div>
        ))}
      </div>

      {/* 1. Interactive Traffic Volume Breakdown Chart (Option 3) */}
      <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-900">
              <BarChart3 className="h-4 w-4 text-indigo-600" aria-hidden="true" />
              Traffic Volume Breakdown ({windowParam.toUpperCase()} Window)
            </h2>
            <p className="mt-0.5 text-xs text-slate-500">
              Click any status pill to toggle visibility and dynamically rescale the chart around anomalies.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2 text-xs">
            <button
              type="button"
              onClick={toggleAnomaliesOnly}
              className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 font-medium transition ${
                hiddenStatuses.has('ALLOWED')
                  ? 'border-indigo-200 bg-indigo-50 text-indigo-700'
                  : 'border-slate-200 bg-slate-50 text-slate-600 hover:bg-slate-100'
              }`}
              title="Hide routine Allowed requests to zoom in on security & governance events"
            >
              <Filter className="h-3 w-3" />
              {hiddenStatuses.has('ALLOWED') ? 'Showing Governance / Anomalies' : 'Hide Allowed'}
            </button>

            <div className="mx-1 h-4 w-px bg-slate-200" />

            {CHART_SERIES.map(({ status, swatch, label }) => {
              const isHidden = hiddenStatuses.has(status)
              return (
                <button
                  key={status}
                  type="button"
                  onClick={() => toggleStatus(status)}
                  aria-pressed={!isHidden}
                  className={`flex items-center gap-1.5 rounded-md border px-2.5 py-1 transition ${
                    isHidden
                      ? 'border-slate-200 bg-slate-50 text-slate-400 line-through opacity-60'
                      : 'border-slate-200 bg-white text-slate-700 shadow-2xs hover:bg-slate-50'
                  }`}
                >
                  <span className={`h-2.5 w-2.5 rounded-xs ${isHidden ? 'bg-slate-300' : swatch}`} />
                  <span>{label}</span>
                </button>
              )
            })}
          </div>
        </div>

        {loading && !analytics ? (
          <div className="mt-8 h-64 animate-pulse rounded-lg bg-slate-100" />
        ) : hourly.length === 0 || summary.total === 0 ? (
          <div className="mt-8 flex h-64 flex-col items-center justify-center rounded-lg border border-dashed border-slate-200 bg-slate-50/50 text-xs text-slate-400">
            <Activity className="mb-2 h-6 w-6 text-slate-300" aria-hidden="true" />
            No traffic recorded in the selected {windowParam} timeframe.
          </div>
        ) : visibleSummaryTotal === 0 ? (
          <div className="mt-8 flex h-64 flex-col items-center justify-center rounded-lg border border-dashed border-slate-200 bg-slate-50/50 text-xs text-slate-400">
            <EyeOff className="mb-2 h-6 w-6 text-slate-300" aria-hidden="true" />
            No requests match the currently selected status filters.
          </div>
        ) : (
          <div className="mt-8">
            <div className="flex h-60 items-end gap-2 border-b border-slate-200 pb-2 pt-6">
              {hourly.map((bucket) => {
                const visibleTotal = getVisibleBucketTotal(bucket)
                const heightPct =
                  visibleTotal > 0 ? Math.max(Math.round((visibleTotal / maxVisibleBucketTotal) * 100), 8) : 0
                const pct = (status: LogStatus, n: number) =>
                  !hiddenStatuses.has(status) && visibleTotal > 0 ? (n / visibleTotal) * 100 : 0

                const allowedPct = pct('ALLOWED', bucket.ALLOWED)
                const queuedPct = pct('QUEUED', bucket.QUEUED)
                const blockedPct = pct('BLOCKED', bucket.BLOCKED)
                const ratePct = pct('RATE_LIMITED', bucket.RATE_LIMITED)
                const approvedPct = pct('APPROVED', bucket.APPROVED)
                const rejectedPct = pct('REJECTED', bucket.REJECTED)

                return (
                  <div key={bucket.hour} className="group relative flex h-full flex-1 flex-col items-center justify-end">
                    <div className="pointer-events-none absolute -top-3 z-30 hidden -translate-y-full rounded-lg bg-slate-900 px-3 py-2 text-xs text-white shadow-xl group-hover:block">
                      <p className="font-semibold text-slate-200">{formatBucketLabel(bucket.hour, windowParam)}</p>
                      <div className="mt-1.5 space-y-1 whitespace-nowrap">
                        {!hiddenStatuses.has('ALLOWED') && bucket.ALLOWED > 0 && (
                          <p className="text-emerald-300">Allowed: {bucket.ALLOWED}</p>
                        )}
                        {!hiddenStatuses.has('QUEUED') && bucket.QUEUED > 0 && (
                          <p className="text-amber-300">Queued: {bucket.QUEUED}</p>
                        )}
                        {!hiddenStatuses.has('BLOCKED') && bucket.BLOCKED > 0 && (
                          <p className="text-red-300">Blocked: {bucket.BLOCKED}</p>
                        )}
                        {!hiddenStatuses.has('RATE_LIMITED') && bucket.RATE_LIMITED > 0 && (
                          <p className="text-violet-300">Rate Limited: {bucket.RATE_LIMITED}</p>
                        )}
                        {!hiddenStatuses.has('APPROVED') && (bucket.APPROVED ?? 0) > 0 && (
                          <p className="text-green-300">Approved: {bucket.APPROVED}</p>
                        )}
                        {!hiddenStatuses.has('REJECTED') && (bucket.REJECTED ?? 0) > 0 && (
                          <p className="text-rose-300">Rejected: {bucket.REJECTED}</p>
                        )}
                        <p className="border-t border-slate-700 pt-1 font-semibold text-white">
                          Visible Total: {visibleTotal}
                        </p>
                      </div>
                    </div>

                    {visibleTotal > 0 ? (
                      <div
                        className="flex w-full max-w-[36px] flex-col overflow-hidden rounded-t transition-all group-hover:brightness-110"
                        style={{ height: `${heightPct}%` }}
                      >
                        {rejectedPct > 0 && <div style={{ height: `${rejectedPct}%` }} className="w-full bg-rose-500" />}
                        {approvedPct > 0 && <div style={{ height: `${approvedPct}%` }} className="w-full bg-green-600" />}
                        {ratePct > 0 && <div style={{ height: `${ratePct}%` }} className="w-full bg-violet-500" />}
                        {blockedPct > 0 && <div style={{ height: `${blockedPct}%` }} className="w-full bg-red-500" />}
                        {queuedPct > 0 && <div style={{ height: `${queuedPct}%` }} className="w-full bg-amber-500" />}
                        {allowedPct > 0 && <div style={{ height: `${allowedPct}%` }} className="w-full bg-emerald-500" />}
                      </div>
                    ) : (
                      <div className="h-1.5 w-full max-w-[36px] rounded-t bg-slate-100" />
                    )}

                    <span className="mt-2 max-w-[45px] truncate font-mono text-[10px] text-slate-400">
                      {formatBucketLabel(bucket.hour, windowParam)}
                    </span>
                  </div>
                )
              })}
            </div>
          </div>
        )}
      </div>

      {/* 2. Top Targeted Endpoints & Top Active Agents Breakdown Tables (Option 2) */}
      <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Top Targeted Endpoints */}
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
          <div className="mb-4">
            <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-900">
              <ShieldAlert className="h-4 w-4 text-indigo-600" aria-hidden="true" />
              Top Targeted Endpoints ({windowParam.toUpperCase()})
            </h2>
            <p className="mt-0.5 text-xs text-slate-500">
              API routes ranked by request volume and security intervention rate (Blocked, Queued, Rejected, Rate Limited).
            </p>
          </div>

          {topEndpoints.length === 0 ? (
            <div className="flex h-40 items-center justify-center rounded-lg border border-dashed border-slate-200 bg-slate-50/50 text-xs text-slate-400">
              No endpoint activity in this window.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-200 text-slate-500">
                    <th className="pb-2 font-medium">Endpoint</th>
                    <th className="pb-2 text-right font-medium">Total</th>
                    <th className="pb-2 text-right font-medium">Allowed / Appr.</th>
                    <th className="pb-2 text-right font-medium">Intervened</th>
                    <th className="pb-2 text-right font-medium">Intervention %</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {topEndpoints.map((ep) => {
                    const rate = ep.total > 0 ? Math.round((ep.intervened / ep.total) * 100) : 0
                    return (
                      <tr key={`${ep.method}:${ep.path}`} className="hover:bg-slate-50/80">
                        <td className="py-2.5 pr-3">
                          <div className="flex items-center gap-2">
                            <MethodBadge method={ep.method} />
                            <span className="font-mono font-medium text-slate-800">{ep.path}</span>
                          </div>
                        </td>
                        <td className="py-2.5 text-right font-semibold text-slate-900">{ep.total}</td>
                        <td className="py-2.5 text-right text-emerald-600 font-medium">{ep.allowed}</td>
                        <td className="py-2.5 text-right text-rose-600 font-medium">{ep.intervened}</td>
                        <td className="py-2.5 text-right">
                          <span
                            className={`inline-block rounded-full px-2 py-0.5 text-[11px] font-semibold ${
                              rate >= 50
                                ? 'bg-rose-50 text-rose-700'
                                : rate > 0
                                  ? 'bg-amber-50 text-amber-700'
                                  : 'bg-emerald-50 text-emerald-700'
                            }`}
                          >
                            {rate}%
                          </span>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Top Active AI Agents */}
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
          <div className="mb-4">
            <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-900">
              <Bot className="h-4 w-4 text-indigo-600" aria-hidden="true" />
              Top Active AI Agents & Callers ({windowParam.toUpperCase()})
            </h2>
            <p className="mt-0.5 text-xs text-slate-500">
              User-Agents ranked by total traffic volume and blocked/rejected actions.
            </p>
          </div>

          {topAgents.length === 0 ? (
            <div className="flex h-40 items-center justify-center rounded-lg border border-dashed border-slate-200 bg-slate-50/50 text-xs text-slate-400">
              No agent traffic recorded in this window.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-200 text-slate-500">
                    <th className="pb-2 font-medium">User-Agent / Caller</th>
                    <th className="pb-2 text-right font-medium">Total</th>
                    <th className="pb-2 text-right font-medium">Allowed / Appr.</th>
                    <th className="pb-2 text-right font-medium">Blocked / Rej.</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {topAgents.map((ag) => (
                    <tr key={ag.agent} className="hover:bg-slate-50/80">
                      <td className="py-2.5 pr-3">
                        <span className="block max-w-[240px] truncate font-mono text-slate-800" title={ag.agent}>
                          {ag.agent}
                        </span>
                      </td>
                      <td className="py-2.5 text-right font-semibold text-slate-900">{ag.total}</td>
                      <td className="py-2.5 text-right text-emerald-600 font-medium">{ag.allowed}</td>
                      <td className="py-2.5 text-right text-rose-600 font-medium">{ag.intervened}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </>
  )
}