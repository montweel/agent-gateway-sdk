import { useCallback, useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { Hand, OctagonX, ShieldCheck } from 'lucide-react'
import { api, errorMessage } from '../lib/api'
import type { EmergencyMode, ProtectionSummary } from '../lib/types'
import { formatTime, READ_ONLY_HINT } from '../lib/utils'
import { Spinner } from './ui'

const money = (n: number) => n.toLocaleString('en-US', { maximumFractionDigits: 2 })

const MODES: { mode: EmergencyMode; label: string; hint: string; active: string; icon: ReactNode }[] = [
  {
    mode: 'normal',
    label: 'Normal',
    hint: 'Your rules decide',
    active: 'bg-emerald-600 text-white',
    icon: <ShieldCheck className="h-4 w-4" aria-hidden="true" />,
  },
  {
    mode: 'approval_only',
    label: 'Approval-only',
    hint: 'Every write waits for a human; reads still work',
    active: 'bg-amber-500 text-white',
    icon: <Hand className="h-4 w-4" aria-hidden="true" />,
  },
  {
    mode: 'lockdown',
    label: 'Lockdown',
    hint: 'Refuse every agent request now; nothing queued can run',
    active: 'bg-red-600 text-white',
    icon: <OctagonX className="h-4 w-4" aria-hidden="true" />,
  },
]

/**
 * Always-visible strip: the emergency switch plus the last 24 hours at a glance
 * (money protected, blocked, waiting for approval, budgets).
 */
export function EmergencyBar({
  readOnly,
  workspace = 'default',
  multiWorkspace = false,
}: {
  readOnly: boolean
  /** Selected workspace slug, or 'all'. */
  workspace?: string
  multiWorkspace?: boolean
}) {
  // A client workspace has its own switch; the default workspace and 'All Clients' drive the global one.
  const scope = multiWorkspace && workspace !== 'all' && workspace !== 'default' ? 'client' : 'global'
  const [summary, setSummary] = useState<ProtectionSummary | null>(null)
  const [busy, setBusy] = useState<EmergencyMode | null>(null)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      const res = await api.get<ProtectionSummary>('/protection/summary', { params: { hours: 24 } })
      setSummary(res.data)
      setError(null)
    } catch (err) {
      setError(errorMessage(err))
    }
  }, [])

  useEffect(() => {
    void load()
    const id = window.setInterval(() => {
      if (!document.hidden) void load()
    }, 10000)
    return () => window.clearInterval(id)
  }, [load])

  async function switchTo(mode: EmergencyMode) {
    if (readOnly || !summary || summary.emergency.mode === mode) return
    let reason: string | null = null
    if (mode !== 'normal') {
      const who = scope === 'client' ? `this client's (${workspace})` : multiWorkspace ? "ALL clients'" : 'all'
      reason = window.prompt(
        mode === 'lockdown' ? `Lock down ${who} agent traffic. Reason (optional):` : `Require approval for every write (${scope === 'client' ? workspace : 'all clients'}). Reason (optional):`,
        ''
      )
      if (reason === null) return // cancelled
    }
    setBusy(mode)
    try {
      await api.post('/emergency', { mode, reason: reason || null })
      await load()
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(null)
    }
  }

  const current = summary?.emergency.mode ?? 'normal'
  const tone =
    current === 'lockdown' ? 'border-red-300 bg-red-50' : current === 'approval_only' ? 'border-amber-300 bg-amber-50' : 'border-slate-200 bg-white'

  return (
    <div className={`border-b ${tone}`}>
      <div className="mx-auto flex max-w-5xl flex-wrap items-center justify-between gap-3 px-10 py-3">
        <div className="flex items-center gap-2">
        {multiWorkspace && (
          <span className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">
            {scope === 'client' ? `Client switch · ${workspace}` : 'Global switch · all clients'}
          </span>
        )}
        <div role="radiogroup" aria-label="Emergency mode" className="inline-flex rounded-lg bg-slate-100 p-1">
          {MODES.map((m) => {
            const active = current === m.mode
            return (
              <button
                key={m.mode}
                type="button"
                role="radio"
                aria-checked={active}
                title={readOnly ? READ_ONLY_HINT : m.hint}
                disabled={readOnly || busy !== null}
                onClick={() => void switchTo(m.mode)}
                className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-semibold transition disabled:cursor-not-allowed ${
                  active ? m.active : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                {busy === m.mode ? <Spinner className="h-3.5 w-3.5" /> : m.icon}
                {m.label}
              </button>
            )
          })}
        </div>
        </div>

        {summary && (
          <div className="flex flex-wrap items-center gap-x-5 gap-y-1 text-xs text-slate-600">
            <span>
              <strong className="text-sm text-emerald-700">{money(summary.moneyProtected)}</strong> protected (24h)
            </span>
            <span>
              <strong className="text-slate-900">{summary.counts.BLOCKED + summary.counts.RATE_LIMITED}</strong> refused
            </span>
            <span>
              <strong className="text-slate-900">{summary.counts.ALLOWED + summary.counts.APPROVED}</strong> allowed
            </span>
            <span className={summary.pending > 0 ? 'font-semibold text-amber-700' : ''}>
              <strong>{summary.pending}</strong> waiting for you
            </span>
            {summary.shadow && summary.shadow.wouldBlock + summary.shadow.wouldHold > 0 && (
              <span title="SHADOW rules: requests let through that an enforced rule would have blocked / held">
                <strong className="text-slate-900">{summary.shadow.wouldBlock + summary.shadow.wouldHold}</strong> shadow hits
              </span>
            )}
            {summary.budgets.map((b) => (
              <span key={`${b.workspaceSlug ?? ''}:${b.ruleKey}`} title={`${b.ruleKey}: per ${b.windowMinutes} min${b.per === 'caller' ? ', per agent' : ''}`}>
                Budget {b.workspaceSlug && b.workspaceSlug !== 'default' && workspace === 'all' ? `[${b.workspaceSlug}] ` : ''}
                <span className="font-mono">{b.ruleKey.replace(/^[A-Z]+ /, '')}</span>:{' '}
                <strong className={b.remaining <= 0 ? 'text-red-700' : 'text-slate-900'}>
                  {money(b.spent)}/{money(b.max)}
                </strong>
              </span>
            ))}
          </div>
        )}
      </div>
      {summary && current !== 'normal' && (
        <div className="mx-auto max-w-5xl px-10 pb-2 text-xs font-medium text-slate-700">
          {scope === 'client' ? `[${workspace}] ` : ''}
          {current === 'lockdown' ? 'LOCKDOWN: every agent request is refused.' : 'APPROVAL-ONLY: every write waits for a human.'}
          {scope === 'client' && summary.globalEmergency && summary.globalEmergency.mode !== 'normal' && ' (set by the global switch)'}
          {summary.emergency.reason && <> Reason: “{summary.emergency.reason}”.</>}
          {summary.emergency.changedBy && (
            <>
              {' '}
              Set by {summary.emergency.changedBy}
              {summary.emergency.changedAt ? ` at ${formatTime(summary.emergency.changedAt)}` : ''}.
            </>
          )}
        </div>
      )}
      {error && <div className="mx-auto max-w-5xl px-10 pb-2 text-xs text-red-700">{error}</div>}
    </div>
  )
}
