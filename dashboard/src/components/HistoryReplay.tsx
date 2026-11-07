import { useState } from 'react'
import { History } from 'lucide-react'
import { api, errorMessage } from '../lib/api'
import type { Rules, SimOutcome, SimulationReport } from '../lib/types'
import { formatTime, INPUT_CLASS } from '../lib/utils'
import { Badge, ErrorBanner, MethodBadge, Spinner } from './ui'
import type { Tone } from './ui'

const OUTCOME_TONE: Record<SimOutcome, Tone> = {
  ALLOW: 'green',
  BLOCK: 'red',
  REQUIRE_APPROVAL: 'amber',
  RATE_LIMITED: 'violet',
}
const OUTCOME_LABEL: Record<SimOutcome, string> = {
  ALLOW: 'Allowed',
  BLOCK: 'Blocked',
  REQUIRE_APPROVAL: 'Held',
  RATE_LIMITED: 'Rate-limited',
}

const money = (n: number) => n.toLocaleString('en-US', { maximumFractionDigits: 2 })

/**
 * Policy Time-Machine: replays the last N recorded requests through the rules shown on this page
 * (saved rules of the selected workspace) and lists every request whose outcome would change.
 */
export function HistoryReplay({ rules }: { rules: Rules }) {
  const [open, setOpen] = useState(false)
  const [limit, setLimit] = useState('500')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [report, setReport] = useState<SimulationReport | null>(null)

  async function run() {
    const n = Number(limit)
    if (!Number.isInteger(n) || n < 1 || n > 5000) {
      setError('Replay between 1 and 5,000 requests.')
      return
    }
    setBusy(true)
    setError(null)
    try {
      // The rules on screen are what gets tested (identical to the saved ones for this workspace).
      const res = await api.post<SimulationReport>('/simulate/history', { limit: n, rules })
      setReport(res.data)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="mb-6 rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-900">
            <History className="h-4 w-4 text-indigo-600" aria-hidden="true" />
            Policy Time-Machine
          </h2>
          <p className="mt-0.5 text-xs text-slate-500">
            Replay recent real traffic through these rules and see exactly which requests would now be blocked, held or rate-limited.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <label className="flex items-center gap-2 text-xs text-slate-600">
            Last
            <input
              type="number"
              min={1}
              max={5000}
              value={limit}
              onChange={(e) => setLimit(e.target.value)}
              className={`${INPUT_CLASS} w-24`}
              aria-label="Number of recorded requests to replay"
            />
            requests
          </label>
          <button
            type="button"
            onClick={() => {
              setOpen(true)
              void run()
            }}
            disabled={busy}
            className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-500 disabled:opacity-60"
          >
            {busy ? <Spinner /> : <History className="h-4 w-4" aria-hidden="true" />}
            Test Rules Against History
          </button>
        </div>
      </div>

      {open && error && (
        <div className="mt-4">
          <ErrorBanner message={error} onDismiss={() => setError(null)} />
        </div>
      )}

      {open && report && (
        <div className="mt-4 space-y-4">
          <div className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-5">
            <Stat label="Replayed" value={report.evaluated} />
            <Stat label="Would change" value={report.changed} tone={report.changed ? 'text-indigo-700' : 'text-slate-900'} />
            <Stat label="Newly blocked" value={report.wouldBlock} tone="text-red-700" />
            <Stat label="Newly held" value={report.wouldHold} tone="text-amber-700" />
            <Stat label="Newly rate-limited" value={report.wouldRateLimit} tone="text-violet-700" />
          </div>
          <p className="text-xs text-slate-500">
            {report.from && report.to ? `${formatTime(report.from)} → ${formatTime(report.to)}. ` : ''}
            {report.moneyNewlyBlocked > 0 && <strong className="text-red-700">{money(report.moneyNewlyBlocked)} that went through would now be blocked. </strong>}
            {report.wouldAllow > 0 && `${report.wouldAllow} request(s) that were stopped would now run without a human. `}
            {report.shadow.wouldBlock + report.shadow.wouldHold > 0 &&
              `Shadow rules flag ${report.shadow.wouldBlock} block(s) and ${report.shadow.wouldHold} hold(s). `}
            {report.skippedNoSnapshot > 0 && `${report.skippedNoSnapshot} older request(s) have no recorded payload and were skipped. `}
            {report.unevaluable > 0 && `${report.unevaluable} request(s) were too large to replay against body policies.`}
          </p>
          {report.transitions.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {report.transitions.map((t) => (
                <span key={`${t.from}-${t.to}`} className="inline-flex items-center gap-1.5 rounded-full bg-slate-100 px-3 py-1 text-xs text-slate-700">
                  {OUTCOME_LABEL[t.from]} → <strong>{OUTCOME_LABEL[t.to]}</strong> × {t.count}
                </span>
              ))}
            </div>
          )}
          {report.rows.length === 0 ? (
            <p className="rounded-lg bg-emerald-50 px-4 py-3 text-sm text-emerald-800">
              No recorded request would be treated differently by these rules.
            </p>
          ) : (
            <div className="max-h-96 overflow-auto rounded-lg border border-slate-200">
              <table className="min-w-full text-left text-xs">
                <thead className="sticky top-0 bg-slate-50 text-slate-500">
                  <tr>
                    <th className="px-3 py-2 font-medium">When</th>
                    <th className="px-3 py-2 font-medium">Request</th>
                    <th className="px-3 py-2 font-medium">Then</th>
                    <th className="px-3 py-2 font-medium">Now</th>
                    <th className="px-3 py-2 font-medium">Why</th>
                    <th className="px-3 py-2 font-medium text-right">Amount</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {report.rows.map((r) => (
                    <tr key={r.logId}>
                      <td className="whitespace-nowrap px-3 py-2 text-slate-500">{formatTime(r.timestamp)}</td>
                      <td className="px-3 py-2">
                        <span className="inline-flex items-center gap-2">
                          <MethodBadge method={r.method} />
                          <span className="font-mono text-slate-800">{r.path}</span>
                        </span>
                      </td>
                      <td className="px-3 py-2">
                        <Badge tone={OUTCOME_TONE[r.historical]}>{OUTCOME_LABEL[r.historical]}</Badge>
                      </td>
                      <td className="px-3 py-2">
                        <Badge tone={OUTCOME_TONE[r.simulated]}>{OUTCOME_LABEL[r.simulated]}</Badge>
                      </td>
                      <td className="px-3 py-2 font-mono text-slate-600">{r.reason}</td>
                      <td className="px-3 py-2 text-right text-slate-700">{r.amount === null ? '' : money(r.amount)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function Stat({ label, value, tone = 'text-slate-900' }: { label: string; value: number; tone?: string }) {
  return (
    <div className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2">
      <p className="text-[11px] uppercase tracking-wide text-slate-500">{label}</p>
      <p className={`text-xl font-semibold ${tone}`}>{value}</p>
    </div>
  )
}
