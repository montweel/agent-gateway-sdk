import { useEffect, useState } from 'react'
import { ArrowRight, Lock } from 'lucide-react'
import { api, errorMessage, proRequiredFrom, setWorkspace } from '../lib/api'
import type { ProRequiredResponse, WorkspaceOverview } from '../lib/types'
import { Badge, ErrorBanner, PageHeader, ProCallout, RefreshButton } from '../components/ui'
import type { Tone } from '../components/ui'
import { AgencyBadge } from '../components/LicenseCard'

const money = (n: number) => n.toLocaleString('en-US', { maximumFractionDigits: 2 })
const MODE_TONE: Record<string, Tone> = { normal: 'green', approval_only: 'amber', lockdown: 'red' }
const MODE_LABEL: Record<string, string> = { normal: 'Normal', approval_only: 'Approval-only', lockdown: 'Lockdown' }

/** Every workspace side by side for the last `hours`. Never throws. */
async function fetchOverview(
  hours: number
): Promise<{ overview: WorkspaceOverview } | { locked: ProRequiredResponse } | { error: string }> {
  try {
    return { overview: (await api.get<WorkspaceOverview>('/workspaces/overview', { params: { hours } })).data }
  } catch (err) {
    const locked = proRequiredFrom(err)
    return locked ? { locked } : { error: errorMessage(err) }
  }
}

/** Shown instead of the table when the license does not include the Agency overview. */
function LockedOverview({ notice }: { notice: ProRequiredResponse }) {
  return (
    <>
      <PageHeader title="All Clients Overview" subtitle="Every client workspace side by side, with a one-click jump into each." />
      <ProCallout agency message={notice.message} upgradeUrl={notice.upgradeUrl} />
      <div className="rounded-xl border border-dashed border-slate-300 bg-white p-8 text-center text-sm text-slate-500" aria-disabled="true">
        <div className="mb-2 flex items-center justify-center gap-2 font-semibold text-slate-400">
          <Lock className="h-4 w-4" aria-hidden="true" /> All-Clients Overview <AgencyBadge />
        </div>
        Pick a single client in the workspace switcher above to manage its rules, approvals and logs.
      </div>
    </>
  )
}

/** Agency view: every client workspace side by side, with a one-click jump into each. */
export function AllClientsOverview() {
  const [data, setData] = useState<WorkspaceOverview | null>(null)
  const [hours, setHours] = useState(24)
  const [error, setError] = useState<string | null>(null)
  const [locked, setLocked] = useState<ProRequiredResponse | null>(null)
  // The Refresh button bumps this, which re-runs the fetch effect for the same window.
  const [reloadToken, setReloadToken] = useState(0)
  const requestKey = `${hours}#${reloadToken}`
  // "Loading" = the data on screen is not the answer to the current request yet (derived, so the
  // effect only sets state once a request has settled). Background polls do not show the spinner.
  const [loadedKey, setLoadedKey] = useState<string | null>(null)
  const loading = loadedKey !== requestKey

  useEffect(() => {
    let live = true
    const refresh = () =>
      void fetchOverview(hours).then((r) => {
        if (!live) return
        if ('overview' in r) {
          setData(r.overview)
          setError(null)
          setLocked(null)
        } else if ('locked' in r) setLocked(r.locked)
        else setError(r.error)
        setLoadedKey(requestKey)
      })
    refresh()
    const id = window.setInterval(() => {
      if (!document.hidden) refresh()
    }, 15000)
    return () => {
      live = false
      window.clearInterval(id)
    }
  }, [hours, requestKey])

  const load = () => setReloadToken((t) => t + 1)

  if (locked) return <LockedOverview notice={locked} />

  const t = data?.totals
  return (
    <>
      <PageHeader
        title="All Clients Overview"
        subtitle="Every client workspace on this installation. Pick one to manage its rules, approvals and logs."
        action={
          <div className="flex items-center gap-2">
            <select
              value={hours}
              onChange={(e) => setHours(Number(e.target.value))}
              className="rounded-lg border border-slate-200 bg-white px-2 py-2 text-sm text-slate-700"
              aria-label="Time window"
            >
              <option value={24}>Last 24 hours</option>
              <option value={168}>Last 7 days</option>
              <option value={720}>Last 30 days</option>
            </select>
            <RefreshButton onClick={load} loading={loading} />
          </div>
        }
      />
      {error && <ErrorBanner message={error} onDismiss={() => setError(null)} />}

      {t && (
        <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-5">
          {[
            { label: 'Money protected', value: money(t.moneyProtected), tone: 'text-emerald-700' },
            { label: 'Money executed', value: money(t.moneyExecuted), tone: 'text-slate-900' },
            { label: 'Refused', value: t.blocked, tone: 'text-red-600' },
            { label: 'Allowed', value: t.allowed, tone: 'text-slate-900' },
            { label: 'Waiting for approval', value: t.pending, tone: t.pending ? 'text-amber-600' : 'text-slate-900' },
          ].map((s) => (
            <div key={s.label} className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
              <p className="text-sm text-slate-500">{s.label}</p>
              <p className={`mt-1 text-2xl font-semibold ${s.tone}`}>{s.value}</p>
            </div>
          ))}
        </div>
      )}

      {data && data.globalEmergency.mode !== 'normal' && (
        <div className="mb-4 rounded-lg border border-red-200 bg-red-50 px-4 py-2.5 text-sm text-red-800">
          The global switch is <strong>{MODE_LABEL[data.globalEmergency.mode]}</strong>: it applies to every client.
        </div>
      )}

      <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
        <table className="min-w-full divide-y divide-slate-200 text-sm">
          <thead className="bg-slate-50 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">
            <tr>
              <th className="px-5 py-3">Client</th>
              <th className="px-5 py-3">Mode</th>
              <th className="px-5 py-3 text-right">Protected</th>
              <th className="px-5 py-3 text-right">Refused</th>
              <th className="px-5 py-3 text-right">Allowed</th>
              <th className="px-5 py-3 text-right">Waiting</th>
              <th className="px-5 py-3 text-right">Shadow hits</th>
              <th className="px-5 py-3" />
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {(data?.workspaces ?? []).map((row) => {
              const w = row.workspace
              const c = row.counts
              return (
                <tr key={w.slug} className="transition hover:bg-slate-50">
                  <td className="px-5 py-3">
                    <p className="flex items-center gap-1.5 font-medium text-slate-900">
                      {w.name}
                      {!w.entitled && <Lock className="h-3.5 w-3.5 text-amber-600" aria-label="Beyond the license limit: its traffic is refused" />}
                    </p>
                    <p className="font-mono text-xs text-slate-400">{w.isDefault ? 'default' : w.slug}</p>
                  </td>
                  <td className="px-5 py-3">
                    <Badge tone={MODE_TONE[w.effectiveMode] ?? 'slate'}>{MODE_LABEL[w.effectiveMode] ?? w.effectiveMode}</Badge>
                  </td>
                  <td className="px-5 py-3 text-right font-semibold text-emerald-700">{money(row.moneyProtected)}</td>
                  <td className="px-5 py-3 text-right">{c.BLOCKED + c.RATE_LIMITED + (c.RESPONSE_BLOCKED ?? 0)}</td>
                  <td className="px-5 py-3 text-right">{c.ALLOWED + c.APPROVED}</td>
                  <td className={`px-5 py-3 text-right ${row.pending ? 'font-semibold text-amber-700' : ''}`}>{row.pending}</td>
                  <td className="px-5 py-3 text-right text-slate-600">{row.shadow.wouldBlock + row.shadow.wouldHold}</td>
                  <td className="px-5 py-3 text-right">
                    <button
                      type="button"
                      onClick={() => setWorkspace(w.slug)}
                      className="inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs font-semibold text-indigo-600 hover:bg-indigo-50"
                    >
                      Open <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
                    </button>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </>
  )
}
