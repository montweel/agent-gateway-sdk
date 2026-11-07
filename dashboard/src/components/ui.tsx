import type { ReactNode } from 'react'
import { AlertCircle, Check, Loader2, RefreshCw } from 'lucide-react'
import type { ApprovalStatus, LogStatus, Mode } from '../lib/types'
import { MODE_META, MODE_ORDER, READ_ONLY_HINT } from '../lib/utils'

export function Spinner({ className = 'h-4 w-4' }: { className?: string }) {
  return <Loader2 className={`animate-spin ${className}`} aria-hidden="true" />
}

export type Tone = 'green' | 'red' | 'amber' | 'violet' | 'slate'

const TONES: Record<Tone, { badge: string; dot: string }> = {
  green: { badge: 'bg-emerald-50 text-emerald-700 ring-emerald-600/20', dot: 'bg-emerald-500' },
  red: { badge: 'bg-red-50 text-red-700 ring-red-600/20', dot: 'bg-red-500' },
  amber: { badge: 'bg-amber-50 text-amber-800 ring-amber-600/20', dot: 'bg-amber-500' },
  violet: { badge: 'bg-violet-50 text-violet-700 ring-violet-600/20', dot: 'bg-violet-500' },
  slate: { badge: 'bg-slate-50 text-slate-700 ring-slate-600/20', dot: 'bg-slate-400' },
}

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

export function Badge({ tone, children }: { tone: Tone; children: ReactNode }) {
  const t = TONES[tone]
  return (
    <span
      className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-full px-2.5 py-1 text-xs font-semibold ring-1 ring-inset ${t.badge}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${t.dot}`} />
      {children}
    </span>
  )
}

const METHOD_STYLES: Record<string, string> = {
  GET: 'bg-sky-50 text-sky-700 ring-sky-600/20',
  POST: 'bg-violet-50 text-violet-700 ring-violet-600/20',
  PUT: 'bg-amber-50 text-amber-700 ring-amber-600/20',
  PATCH: 'bg-amber-50 text-amber-700 ring-amber-600/20',
  DELETE: 'bg-rose-50 text-rose-700 ring-rose-600/20',
}

/** Method badge for a rule row; "ANY" is shown for path-only rules. */
export function RuleMethodBadge({ method }: { method: string }) {
  if (method !== 'ANY') return <MethodBadge method={method} />
  return (
    <span
      title="Matches every method that has no method-specific rule"
      className="inline-flex rounded-md bg-slate-100 px-2 py-0.5 font-mono text-xs font-semibold text-slate-600 ring-1 ring-inset ring-slate-300"
    >
      ANY
    </span>
  )
}

export function MethodBadge({ method }: { method: string }) {
  const style = METHOD_STYLES[method] ?? 'bg-slate-50 text-slate-700 ring-slate-600/20'
  return (
    <span
      className={`inline-flex rounded-md px-2 py-0.5 font-mono text-xs font-semibold ring-1 ring-inset ${style}`}
    >
      {method}
    </span>
  )
}

export function ErrorBanner({ message, onDismiss }: { message: string; onDismiss?: () => void }) {
  return (
    <div
      role="alert"
      className="mb-4 flex items-start justify-between gap-3 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800"
    >
      <span className="flex items-start gap-2">
        <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
        <span>{message}</span>
      </span>
      {onDismiss && (
        <button onClick={onDismiss} className="shrink-0 font-medium text-red-700 hover:text-red-900">
          Dismiss
        </button>
      )}
    </div>
  )
}

/** Non-error callout shown when an API call answers `proRequired: true`. */
export function ProCallout({ message, upgradeUrl, onDismiss }: { message?: string; upgradeUrl?: string; onDismiss?: () => void }) {
  return (
    <div
      role="status"
      className="mb-4 flex items-start justify-between gap-3 rounded-lg border border-indigo-200 bg-indigo-50 px-4 py-3 text-sm text-indigo-900"
    >
      <span className="flex flex-wrap items-center gap-2">
        <span className="inline-flex items-center rounded-full bg-indigo-600 px-2 py-0.5 text-[10px] font-bold tracking-wide text-white">
          PRO FEATURE
        </span>
        <span>{message ?? 'Pro feature — claim your free 90-day trial key (no payment card required).'}</span>
        <a
          href={upgradeUrl ?? 'https://montweel.com/#license-renewal'}
          target="_blank"
          rel="noopener noreferrer"
          className="font-semibold underline hover:text-indigo-700"
        >
          Get your free 90-day trial key ↗
        </a>
      </span>
      {onDismiss && (
        <button onClick={onDismiss} className="shrink-0 font-medium text-indigo-700 hover:text-indigo-900">
          Dismiss
        </button>
      )}
    </div>
  )
}

export function WarningBanner({ children }: { children: ReactNode }) {
  return (
    <div
      role="alert"
      className="mb-4 flex items-start gap-2 rounded-lg border border-amber-300 bg-amber-50 px-4 py-3 text-sm text-amber-900"
    >
      <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
      <div>{children}</div>
    </div>
  )
}

export function SuccessBanner({ message, onDismiss }: { message: string; onDismiss: () => void }) {
  return (
    <div
      role="status"
      className="mb-4 flex items-start justify-between gap-3 rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800"
    >
      <span className="flex items-start gap-2">
        <Check className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
        <span>{message}</span>
      </span>
      <button onClick={onDismiss} className="shrink-0 font-medium text-emerald-700 hover:text-emerald-900">
        Dismiss
      </button>
    </div>
  )
}

export function PageHeader({
  title,
  subtitle,
  action,
}: {
  title: string
  subtitle: string
  action?: ReactNode
}) {
  return (
    <div className="mb-6 flex items-end justify-between gap-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-slate-900">{title}</h1>
        <p className="mt-1 text-sm text-slate-500">{subtitle}</p>
      </div>
      {action}
    </div>
  )
}

export function RefreshButton({ onClick, loading }: { onClick: () => void; loading: boolean }) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={loading}
      className="inline-flex shrink-0 items-center gap-2 rounded-lg border border-slate-200 bg-white px-3.5 py-2 text-sm font-medium text-slate-700 shadow-sm transition hover:bg-slate-50 disabled:opacity-60"
    >
      {loading ? <Spinner /> : <RefreshCw className="h-4 w-4" aria-hidden="true" />}
      Refresh
    </button>
  )
}

export function ModeSwitch({
  value,
  onChange,
  disabled,
}: {
  value: Mode
  onChange: (mode: Mode) => void
  disabled?: boolean
}) {
  return (
    <div role="radiogroup" aria-label="Access mode" className="inline-flex rounded-lg bg-slate-100 p-1">
      {MODE_ORDER.map((mode) => {
        const active = value === mode
        const meta = MODE_META[mode]
        return (
          <button
            key={mode}
            type="button"
            role="radio"
            aria-checked={active}
            title={disabled ? READ_ONLY_HINT : meta.title}
            disabled={disabled}
            onClick={() => {
              if (!active && !disabled) onChange(mode)
            }}
            className={`rounded-md px-3 py-1.5 text-xs font-semibold transition disabled:cursor-not-allowed disabled:opacity-60 ${
              active ? meta.active : 'text-slate-500 hover:text-slate-800'
            }`}
          >
            {meta.label}
          </button>
        )
      })}
    </div>
  )
}
