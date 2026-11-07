import { useState } from 'react'
import { Fingerprint, ShieldAlert, ShieldCheck } from 'lucide-react'
import { api, errorMessage } from '../lib/api'
import type { LedgerVerifyReport } from '../lib/types'
import { formatTime } from '../lib/utils'
import { Spinner } from './ui'

/**
 * "Verify Ledger Integrity": walks the SHA-256 hash chain over every audit row and proves that
 * nothing was edited, deleted or inserted by hand. Pro / Agency (the chain itself is always kept).
 */
export function LedgerVerifyBadge() {
  const [busy, setBusy] = useState(false)
  const [report, setReport] = useState<LedgerVerifyReport | null>(null)
  const [error, setError] = useState<string | null>(null)

  async function verify() {
    setBusy(true)
    setError(null)
    try {
      const res = await api.get<LedgerVerifyReport>('/audit/verify')
      setReport(res.data)
    } catch (err) {
      setReport(null)
      setError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  const tone = report ? (report.ok ? 'border-emerald-300 bg-emerald-50 text-emerald-900' : 'border-red-300 bg-red-50 text-red-900') : 'border-slate-200 bg-white text-slate-700'

  return (
    <div className={`mb-5 flex flex-wrap items-center justify-between gap-3 rounded-xl border px-4 py-3 shadow-sm ${tone}`}>
      <div className="flex min-w-0 items-start gap-3">
        {report ? (
          report.ok ? (
            <ShieldCheck className="mt-0.5 h-5 w-5 shrink-0 text-emerald-600" aria-hidden="true" />
          ) : (
            <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0 text-red-600" aria-hidden="true" />
          )
        ) : (
          <Fingerprint className="mt-0.5 h-5 w-5 shrink-0 text-indigo-600" aria-hidden="true" />
        )}
        <div className="min-w-0 text-sm">
          {!report && !error && (
            <>
              <p className="font-semibold">Tamper-evident audit ledger</p>
              <p className="text-xs opacity-80">Every row is SHA-256 hash-chained to the one before it. Verify that none was edited or deleted.</p>
            </>
          )}
          {error && (
            <>
              <p className="font-semibold">Ledger verification unavailable</p>
              <p className="text-xs">{error}</p>
            </>
          )}
          {report?.ok && (
            <>
              <p className="font-semibold">Ledger verified: {report.checked.toLocaleString()} rows intact</p>
              <p className="break-all text-xs opacity-80">
                Head #{report.lastId ?? '—'} · <span className="font-mono">{report.headHash.slice(0, 24)}…</span>
                {report.checkpoint ? ` · retention checkpoint #${report.checkpoint.id}` : ''}
                {report.unsealed > 0 ? ` · ${report.unsealed} newest row(s) still sealing` : ''} · checked {formatTime(report.verifiedAt)}
              </p>
            </>
          )}
          {report && !report.ok && (
            <>
              <p className="font-semibold">Tampering detected{report.brokenAt ? ` at row #${report.brokenAt}` : ''}</p>
              <p className="text-xs">{report.reason}</p>
            </>
          )}
        </div>
      </div>
      <button
        type="button"
        onClick={() => void verify()}
        disabled={busy}
        className="inline-flex shrink-0 items-center gap-2 rounded-lg bg-slate-900 px-3.5 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-slate-700 disabled:opacity-60"
      >
        {busy ? <Spinner /> : <Fingerprint className="h-4 w-4" aria-hidden="true" />}
        Verify Ledger Integrity
      </button>
    </div>
  )
}
