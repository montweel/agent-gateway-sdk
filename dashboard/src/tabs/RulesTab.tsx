import { useEffect, useMemo, useState } from 'react'
import type { FormEvent } from 'react'
import { AlertCircle, ArrowRight, Plus, SlidersHorizontal, Trash2 } from 'lucide-react'
import { api, errorMessage } from '../lib/api'
import type { RulesApi } from '../hooks/useRules'
import type { Mode, PolicyCondition, PolicyTier, Rule, Rules } from '../lib/types'
import { INPUT_CLASS, MODE_META, READ_ONLY_HINT, RULE_METHOD_OPTIONS, ruleKey, splitRuleKey } from '../lib/utils'
import type { RuleMethod } from '../lib/utils'
import { ErrorBanner, ModeSwitch, PageHeader, RefreshButton, RuleMethodBadge, Spinner } from '../components/ui'
import { HistoryReplay } from '../components/HistoryReplay'

const OP_SYMBOL: Record<string, string> = { '<=': '≤', '>=': '≥', '<': '<', '>': '>', '===': '=', '!==': '≠' }

function formatValue(v: unknown): string {
  return typeof v === 'string' ? `"${v}"` : String(v)
}

/** One-line summary of a payload condition, e.g. `body.amount ≤ 100`. */
function formatCondition(c: PolicyCondition): string {
  if (c.op === 'exists') return `${c.field} ${c.value === false ? 'is missing' : 'exists'}`
  if (c.op === 'in') return `${c.field} in [${(Array.isArray(c.value) ? c.value : [c.value]).map(formatValue).join(', ')}]`
  if (c.op === 'regex') return `${c.field} matches /${String(c.value)}/${c.flags ?? ''}`
  if (c.op === 'contains') return `${c.field} contains ${formatValue(c.value)}`
  return `${c.field} ${OP_SYMBOL[c.op] ?? c.op} ${formatValue(c.value)}`
}

const MODE_TEXT: Record<Mode, string> = {
  ALLOW: 'text-emerald-700',
  REQUIRE_APPROVAL: 'text-amber-700',
  BLOCK: 'text-red-700',
  SHADOW_BLOCK: 'text-slate-700',
  SHADOW_APPROVAL: 'text-slate-700',
}

const MAX_TIERS_SHOWN = 3

/** Compact read-only view of a rule's payload tiers, so the list does not show only the fallback. */
function TierSummary({ tiers }: { tiers: PolicyTier[] }) {
  const shown = tiers.slice(0, MAX_TIERS_SHOWN)
  return (
    <ol className="mt-3 space-y-1 rounded-lg border border-violet-200 bg-white px-3 py-2 text-xs">
      {shown.map((t, i) => (
        <li key={i} className="flex flex-wrap items-baseline gap-x-1.5">
          <span className="font-semibold text-slate-500">{i + 1}.</span>
          {t.name && <span className="font-medium text-slate-700">{t.name}:</span>}
          <span className="font-mono text-slate-600">if {t.when.map(formatCondition).join(' and ')}</span>
          <span className="text-slate-400">→</span>
          <span className={`font-semibold ${MODE_TEXT[t.mode]}`}>{MODE_META[t.mode].label}</span>
        </li>
      ))}
      {tiers.length > MAX_TIERS_SHOWN && (
        <li className="text-slate-500">+ {tiers.length - MAX_TIERS_SHOWN} more tier{tiers.length - MAX_TIERS_SHOWN === 1 ? '' : 's'}</li>
      )}
    </ol>
  )
}

function RuleRow({
  ruleId,
  path,
  method,
  rule,
  busy,
  readOnly,
  onMode,
  onDescription,
  onRateLimit,
  onDelete,
  onEditPayload,
}: {
  ruleId: string
  path: string
  method: string
  rule: Rule
  busy: boolean
  readOnly: boolean
  onMode: (mode: Mode) => void
  onDescription: (description: string) => void
  onRateLimit: (rateLimit: number | null) => void
  onDelete: () => void
  onEditPayload?: () => void
}) {
  const tiers = rule.policies ?? []
  const tiered = tiers.length > 0
  const [draft, setDraft] = useState(rule.description)
  const currentLimit = rule.rateLimit ?? null
  const [limitDraft, setLimitDraft] = useState(currentLimit === null ? '' : String(currentLimit))
  const [limitError, setLimitError] = useState(false)

  useEffect(() => {
    setDraft(rule.description)
  }, [rule.description])

  useEffect(() => {
    setLimitDraft(currentLimit === null ? '' : String(currentLimit))
    setLimitError(false)
  }, [currentLimit])

  function commitLimit() {
    if (readOnly) return
    const text = limitDraft.trim()
    if (text === '') {
      setLimitError(false)
      if (currentLimit !== null) onRateLimit(null)
      return
    }
    const n = Number(text)
    if (!Number.isInteger(n) || n < 1 || n > 1_000_000) {
      setLimitError(true)
      return
    }
    setLimitError(false)
    if (n !== currentLimit) onRateLimit(n)
  }

  function commit() {
    if (readOnly) return
    const value = draft.trim()
    if (value !== rule.description) onDescription(value)
    else setDraft(rule.description)
  }

  return (
    <li
      className={`px-6 py-4 transition ${
        tiered ? 'border-l-4 border-violet-400 bg-violet-50/40 pl-5 hover:bg-violet-50/70' : 'hover:bg-slate-50'
      }`}
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex min-w-0 flex-wrap items-center gap-2.5">
          <RuleMethodBadge method={method} />
          <p className="break-all font-mono text-sm font-medium text-slate-900">{path}</p>
          {tiered && (
            <span
              title="This endpoint decides per request based on its payload. The tiers below are checked first; the Otherwise mode applies only when none match."
              className="inline-flex items-center gap-1 rounded-md bg-violet-100 px-2 py-0.5 text-xs font-semibold text-violet-800 ring-1 ring-inset ring-violet-600/20"
            >
              <SlidersHorizontal className="h-3 w-3" aria-hidden="true" />
              Payload rules · {tiers.length} tier{tiers.length === 1 ? '' : 's'}
            </span>
          )}
          {rule.budget && (
            <span className="rounded-md bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-600" title={`Budget on ${rule.budget.field}`}>
              Budget
            </span>
          )}
          {rule.dedupe && (
            <span className="rounded-md bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-600" title={`Duplicate protection on ${rule.dedupe.fields.join(', ')}`}>
              Dedupe
            </span>
          )}
        </div>
        <div className="flex items-center gap-3">
          {busy && <Spinner className="h-4 w-4 text-slate-400" />}
          {tiered && <span className="text-xs font-medium text-slate-500">Otherwise</span>}
          <ModeSwitch value={rule.mode} onChange={onMode} disabled={busy || readOnly} />
          <button
            type="button"
            onClick={onDelete}
            disabled={busy || readOnly}
            title={readOnly ? READ_ONLY_HINT : 'Delete rule'}
            aria-label={`Delete rule for ${ruleId}`}
            className="rounded-lg p-2 text-slate-400 transition hover:bg-red-50 hover:text-red-600 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <Trash2 className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>
      </div>
      {tiered && (
        <>
          <TierSummary tiers={tiers} />
          {onEditPayload && (
            <button
              type="button"
              onClick={onEditPayload}
              className="mt-2 inline-flex items-center gap-1 text-xs font-semibold text-violet-700 hover:text-violet-900"
            >
              {readOnly ? 'View payload rules' : 'Edit payload rules'}
              <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
          )}
        </>
      )}
      <input
        type="text"
        value={draft}
        maxLength={500}
        disabled={busy || readOnly}
        onChange={(e) => setDraft(e.target.value)}
        onBlur={commit}
        onKeyDown={(e) => {
          if (e.key === 'Enter') e.currentTarget.blur()
          if (e.key === 'Escape') setDraft(rule.description)
        }}
        placeholder={readOnly ? 'No description' : 'Add a description so agents know what this endpoint does'}
        aria-label={`Description for ${ruleId}`}
        className={`${INPUT_CLASS} mt-3`}
      />
      {rule.mode !== 'BLOCK' && (
        <label className="mt-3 flex items-center gap-3">
          <span className="text-xs font-medium text-slate-600">Rate Limit (/min)</span>
          <input
            type="number"
            min={1}
            max={1000000}
            step={1}
            value={limitDraft}
            disabled={busy || readOnly}
            onChange={(e) => setLimitDraft(e.target.value)}
            onBlur={commitLimit}
            onKeyDown={(e) => {
              if (e.key === 'Enter') e.currentTarget.blur()
              if (e.key === 'Escape') {
                setLimitDraft(currentLimit === null ? '' : String(currentLimit))
                setLimitError(false)
              }
            }}
            placeholder="Default"
            aria-label={`Rate limit per minute for ${ruleId}`}
            aria-invalid={limitError}
            className={`${INPUT_CLASS} w-28 ${limitError ? 'border-red-400' : ''}`}
          />
          {limitError && <span className="text-xs text-red-600">Whole number, 1 to 1,000,000</span>}
        </label>
      )}
      {(rule.mode === 'SHADOW_BLOCK' || rule.mode === 'SHADOW_APPROVAL') && (
        <p className="mt-1.5 text-xs text-slate-500">
          Dry run: matching requests still go through. The audit log marks what this rule would have done, so you can watch it on
          live traffic before enforcing it.
        </p>
      )}
      {rule.mode === 'BLOCK' && (
        <p className="mt-1.5 text-xs text-slate-400">Blocked endpoints are not listed in agent discovery.</p>
      )}
    </li>
  )
}

export function RulesTab({
  rulesApi,
  readOnly,
  onEditPayload,
}: {
  rulesApi: RulesApi
  readOnly: boolean
  /** Open the payload rules editor on this rule key. */
  onEditPayload?: (key: string) => void
}) {
  const { rules, setRules, loading, error, setError, reload } = rulesApi
  const [busy, setBusy] = useState<Set<string>>(new Set())
  const [newPath, setNewPath] = useState('')
  const [newMethod, setNewMethod] = useState<RuleMethod>('ANY')
  const [newMode, setNewMode] = useState<Mode>('ALLOW')
  const [newDescription, setNewDescription] = useState('')
  const [newRateLimit, setNewRateLimit] = useState('')
  const [adding, setAdding] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)

  function setBusyFlag(path: string, on: boolean) {
    setBusy((prev) => {
      const next = new Set(prev)
      if (on) next.add(path)
      else next.delete(path)
      return next
    })
  }

  async function saveRule(path: string, payload: { mode: Mode; description?: string; rateLimit?: number | null }) {
    if (readOnly) return
    const previous = rules[path]
    setBusyFlag(path, true)
    setRules((r) => ({ ...r, [path]: { ...r[path], ...payload } }))
    try {
      const res = await api.post<{ success: boolean; rules: Rules }>('/rules', { [path]: payload })
      setRules(res.data.rules)
      setError(null)
    } catch (err) {
      setRules((r) => ({ ...r, [path]: previous }))
      setError(`Could not update ${path}: ${errorMessage(err)}`)
    } finally {
      setBusyFlag(path, false)
    }
  }

  async function deleteRule(path: string) {
    if (readOnly) return
    const ok = window.confirm(`Delete the rule for ${path}?\n\nRequests it covered fall back to a path-only rule if one exists, otherwise they are blocked (default deny).`)
    if (!ok) return
    setBusyFlag(path, true)
    try {
      const res = await api.delete<{ success: boolean; rules: Rules }>('/rules', { params: { path } })
      setRules(res.data.rules)
      setError(null)
    } catch (err) {
      setError(`Could not delete ${path}: ${errorMessage(err)}`)
    } finally {
      setBusyFlag(path, false)
    }
  }

  async function addRule(e: FormEvent) {
    e.preventDefault()
    if (readOnly) return
    setFormError(null)

    let path = newPath.trim()
    if (path && !path.startsWith('/')) path = `/${path}`
    path = path.length > 1 ? path.replace(/\/+$/, '') : path

    if (!path.startsWith('/api/')) {
      setFormError('Path must start with /api/, for example /api/get-flights.')
      return
    }
    if (path.includes('?') || path.includes('#')) {
      setFormError('Leave out the query string: rules match the path only.')
      return
    }
    if (path.startsWith('/api/agent-admin')) {
      setFormError('Admin routes bypass the gateway, so rules cannot apply to them.')
      return
    }

    let rateLimit: number | null = null
    if (newRateLimit.trim() !== '') {
      const n = Number(newRateLimit)
      if (!Number.isInteger(n) || n < 1 || n > 1_000_000) {
        setFormError('Rate limit must be a whole number from 1 to 1,000,000, or blank to use the global limit.')
        return
      }
      rateLimit = n
    }

    setAdding(true)
    try {
      const res = await api.post<{ success: boolean; rules: Rules }>('/rules', {
        [ruleKey(newMethod, path)]: { mode: newMode, description: newDescription.trim(), rateLimit },
      })
      setRules(res.data.rules)
      setNewPath('')
      setNewRateLimit('')
      setNewDescription('')
      setNewMode('ALLOW')
      setNewMethod('ANY')
      setError(null)
    } catch (err) {
      setFormError(errorMessage(err))
    } finally {
      setAdding(false)
    }
  }

  // Grouped by path; within a path the ANY rule comes first, then methods alphabetically.
  const entries = useMemo(
    () =>
      Object.entries(rules).sort(([a], [b]) => {
        const x = splitRuleKey(a)
        const y = splitRuleKey(b)
        if (x.path !== y.path) return x.path < y.path ? -1 : 1
        if (x.method === y.method) return 0
        if (x.method === 'ANY') return -1
        if (y.method === 'ANY') return 1
        return x.method < y.method ? -1 : 1
      }),
    [rules]
  )
  const counts = useMemo(() => {
    const c: Record<Mode, number> = { ALLOW: 0, REQUIRE_APPROVAL: 0, BLOCK: 0, SHADOW_BLOCK: 0, SHADOW_APPROVAL: 0 }
    for (const [, rule] of entries) c[rule.mode] += 1
    return c
  }, [entries])

  const stats = [
    { label: 'Total rules', value: entries.length, color: 'text-slate-900' },
    { label: 'Allowed', value: counts.ALLOW, color: 'text-emerald-600' },
    { label: 'Require approval', value: counts.REQUIRE_APPROVAL, color: 'text-amber-600' },
    { label: 'Blocked', value: counts.BLOCK, color: 'text-red-600' },
    { label: 'Shadow (dry run)', value: counts.SHADOW_BLOCK + counts.SHADOW_APPROVAL, color: 'text-slate-600' },
  ]

  return (
    <>
      <PageHeader
        title="Access Rules"
        subtitle="Control which endpoints agents can call. Anything not listed is blocked."
        action={<RefreshButton onClick={() => void reload()} loading={loading} />}
      />

      {error && <ErrorBanner message={error} onDismiss={() => setError(null)} />}

      <HistoryReplay rules={rules} />

      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-5">
        {stats.map((s) => (
          <div key={s.label} className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
            <p className="text-sm text-slate-500">{s.label}</p>
            <p className={`mt-1 text-3xl font-semibold ${s.color}`}>{loading ? '–' : s.value}</p>
          </div>
        ))}
      </div>

      <form
        onSubmit={addRule}
        className={`mb-6 rounded-xl border border-slate-200 bg-white p-5 shadow-sm ${readOnly ? 'opacity-70' : ''}`}
      >
        <h2 className="text-sm font-semibold text-slate-900">Add a rule</h2>
        <p className="mt-0.5 text-xs text-slate-500">
          {readOnly
            ? 'Read-only mode: adding or changing rules is disabled.'
            : 'Pick a method to apply the rule to that method only. ANY matches every method that has no method-specific rule. Adding a rule that already exists updates it.'}
        </p>

        <div className="mt-4 grid gap-4 md:grid-cols-2">
          <div className="flex gap-3">
            <label className="block w-28 shrink-0">
              <span className="mb-1.5 block text-xs font-medium text-slate-600">Method</span>
              <select
                value={newMethod}
                onChange={(e) => setNewMethod(e.target.value as RuleMethod)}
                disabled={readOnly}
                aria-label="HTTP method"
                title="ANY applies to every method that has no method-specific rule"
                className={`${INPUT_CLASS} font-mono`}
              >
                {RULE_METHOD_OPTIONS.map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
              </select>
            </label>
            <label className="block min-w-0 flex-1">
              <span className="mb-1.5 block text-xs font-medium text-slate-600">Endpoint path</span>
              <input
                type="text"
                value={newPath}
                onChange={(e) => setNewPath(e.target.value)}
                disabled={readOnly}
                placeholder="/api/cancel-flight"
                className={`${INPUT_CLASS} font-mono`}
              />
            </label>
          </div>
          <div>
            <span className="mb-1.5 block text-xs font-medium text-slate-600">Mode</span>
            <ModeSwitch value={newMode} onChange={setNewMode} disabled={readOnly} />
          </div>
          <label className="block">
            <span className="mb-1.5 block text-xs font-medium text-slate-600">Rate Limit (/min)</span>
            <input
              type="number"
              min={1}
              max={1000000}
              step={1}
              value={newRateLimit}
              onChange={(e) => setNewRateLimit(e.target.value)}
              disabled={readOnly}
              placeholder="Default"
              title="Max requests per minute per IP for this route. Leave blank to use the global rate limit."
              className={INPUT_CLASS}
            />
          </label>
          <label className="block md:col-span-2">
            <span className="mb-1.5 block text-xs font-medium text-slate-600">
              Description (shown to agents in discovery)
            </span>
            <input
              type="text"
              value={newDescription}
              maxLength={500}
              onChange={(e) => setNewDescription(e.target.value)}
              disabled={readOnly}
              placeholder="Cancels an existing booking by its booking id"
              className={INPUT_CLASS}
            />
          </label>
        </div>

        {formError && (
          <p role="alert" className="mt-3 flex items-start gap-2 text-sm text-red-600">
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
            {formError}
          </p>
        )}

        <div className="mt-4 flex justify-end">
          <button
            type="submit"
            disabled={adding || readOnly || newPath.trim() === ''}
            title={readOnly ? READ_ONLY_HINT : undefined}
            className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {adding ? <Spinner /> : <Plus className="h-4 w-4" aria-hidden="true" />}
            Add rule
          </button>
        </div>
      </form>

      <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
        {loading ? (
          <ul className="divide-y divide-slate-100">
            {[0, 1, 2].map((i) => (
              <li key={i} className="animate-pulse px-6 py-5">
                <div className="flex items-center justify-between">
                  <div className="h-4 w-48 rounded bg-slate-200" />
                  <div className="h-8 w-52 rounded-lg bg-slate-200" />
                </div>
                <div className="mt-3 h-9 rounded-lg bg-slate-100" />
              </li>
            ))}
          </ul>
        ) : entries.length === 0 ? (
          <div className="px-6 py-16 text-center text-sm text-slate-500">
            No rules defined yet. Every request is blocked by default.
          </div>
        ) : (
          <ul className="divide-y divide-slate-100">
            {entries.map(([key, rule]) => {
              const { method, path } = splitRuleKey(key)
              return (
                <RuleRow
                  key={key}
                  ruleId={key}
                  path={path}
                  method={method}
                  rule={rule}
                  busy={busy.has(key)}
                  onMode={(mode) => void saveRule(key, { mode })}
                  onDescription={(description) => void saveRule(key, { mode: rule.mode, description })}
                  onRateLimit={(rateLimit) => void saveRule(key, { mode: rule.mode, rateLimit })}
                  onDelete={() => void deleteRule(key)}
                  onEditPayload={onEditPayload ? () => onEditPayload(key) : undefined}
                  readOnly={readOnly}
                />
              )
            })}
          </ul>
        )}
      </div>
    </>
  )
}
