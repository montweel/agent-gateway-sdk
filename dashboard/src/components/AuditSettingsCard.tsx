import { useEffect, useState } from 'react'
import type { FormEvent, KeyboardEvent } from 'react'
import { Check, EyeOff, Landmark, Plane, ShoppingBag, SlidersHorizontal, X } from 'lucide-react'
import { api, errorMessage } from '../lib/api'
import type { ApplyTemplateResponse, AuditConfig, ComplianceTemplate, ComplianceTemplateId, ComplianceTemplatesResponse, GatewayConfig } from '../lib/types'
import { INPUT_CLASS, READ_ONLY_HINT } from '../lib/utils'
import { ErrorBanner, Spinner, SuccessBanner } from './ui'

const sameKeys = (a: string[], b: string[]) => a.length === b.length && a.every((k, i) => k === b[i])

/** Comma / newline separated input -> trimmed, de-duplicated keys. */
function splitKeys(text: string): string[] {
  return text
    .split(/[,\n]/)
    .map((k) => k.trim())
    .filter(Boolean)
}

const TEMPLATE_ICONS: Record<ComplianceTemplateId, typeof Landmark> = {
  fintech: Landmark,
  retail: ShoppingBag,
  travel: Plane,
  custom: SlidersHorizontal,
}

/** Framework chips always offered, plus any the install already declared. */
const DEFAULT_FRAMEWORKS = ['SOC2', 'PCI-DSS', 'GDPR', 'HIPAA', 'ISO 27001']

/**
 * "Audit & PII Redaction": response capture, custom redact keys, and industry compliance presets
 * (config.json "audit"). Saved on its own (POST /config { audit } or /compliance/apply-template),
 * so it never touches the other gateway settings.
 */
export function AuditSettingsCard({
  audit,
  readOnly,
  onSaved,
}: {
  audit: AuditConfig
  readOnly: boolean
  onSaved: (audit: AuditConfig) => void
}) {
  const [capture, setCapture] = useState(audit.capturePayloads)
  const [keys, setKeys] = useState<string[]>(audit.redactKeys)
  const [draft, setDraft] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [skipped, setSkipped] = useState<Array<{ key: string; reason: string }>>([])

  // A newer saved config (our own save, a template, or another admin) resets the form to it.
  const [syncedAudit, setSyncedAudit] = useState(audit)
  if (syncedAudit !== audit) {
    setSyncedAudit(audit)
    setCapture(audit.capturePayloads)
    setKeys(audit.redactKeys)
    setDraft('')
  }

  // ---- industry presets ----
  const [templates, setTemplates] = useState<ComplianceTemplate[]>([])
  const [knownFrameworks, setKnownFrameworks] = useState<string[]>(DEFAULT_FRAMEWORKS)
  const [templateId, setTemplateId] = useState<ComplianceTemplateId>(audit.activeTemplate ?? 'fintech')
  const [frameworks, setFrameworks] = useState<string[]>(audit.complianceFrameworks ?? [])
  const [includeRules, setIncludeRules] = useState(false)
  const [applying, setApplying] = useState(false)

  useEffect(() => {
    let live = true
    api.get<ComplianceTemplatesResponse>('/compliance/templates').then(
      (res) => {
        if (!live) return
        setTemplates(res.data.templates)
        setKnownFrameworks([...new Set([...DEFAULT_FRAMEWORKS, ...res.data.knownFrameworks])])
      },
      () => undefined // the presets are optional; the rest of the card still works
    )
    return () => {
      live = false
    }
  }, [])

  const template = templates.find((t) => t.id === templateId)
  const frameworkChoices = [...new Set([...knownFrameworks, ...frameworks])]

  const pending = splitKeys(draft).filter((k) => !keys.includes(k))
  const nextKeys = [...keys, ...pending]
  const dirty = capture !== audit.capturePayloads || !sameKeys(nextKeys, audit.redactKeys)

  function chooseTemplate(id: ComplianceTemplateId) {
    setTemplateId(id)
    const t = templates.find((x) => x.id === id)
    // A preset suggests its frameworks; Custom keeps whatever is selected.
    if (t && id !== 'custom') setFrameworks(t.frameworks)
    if (id === 'custom') setIncludeRules(false)
  }

  function toggleFramework(f: string) {
    setFrameworks((prev) => (prev.includes(f) ? prev.filter((x) => x !== f) : [...prev, f]))
  }

  function addDraft() {
    if (pending.length === 0) {
      setDraft('')
      return
    }
    setKeys(nextKeys)
    setDraft('')
  }

  function onKeyDown(e: KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault()
      addDraft()
    } else if (e.key === 'Backspace' && draft === '' && keys.length > 0) {
      setKeys(keys.slice(0, -1))
    }
  }

  async function save(e: FormEvent) {
    e.preventDefault()
    if (readOnly) return
    setSaving(true)
    setError(null)
    setNotice(null)
    setSkipped([])
    try {
      // Text still in the box counts: nobody expects a typed key to be silently dropped.
      const res = await api.post<{ success: boolean; config: GatewayConfig }>('/config', {
        audit: { capturePayloads: capture, redactKeys: nextKeys },
      })
      setNotice('Audit settings saved. They apply to the next request.')
      onSaved(res.data.config.audit ?? { ...audit, capturePayloads: capture, redactKeys: nextKeys })
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setSaving(false)
    }
  }

  async function applyTemplate() {
    if (readOnly || !template) return
    setApplying(true)
    setError(null)
    setNotice(null)
    setSkipped([])
    try {
      const res = await api.post<ApplyTemplateResponse>('/compliance/apply-template', {
        template: template.id,
        includeRules: includeRules && template.id !== 'custom',
        frameworks,
      })
      const r = res.data
      const parts = [
        `${template.name} applied.`,
        r.addedRedactKeys.length ? `Added ${r.addedRedactKeys.length} redacted key(s).` : 'All of its redacted keys were already in place.',
      ]
      if (r.rules) {
        parts.push(
          r.rules.added.length
            ? `Added ${r.rules.added.length} approval rule(s) to workspace "${r.rules.workspace}": ${r.rules.added.join(', ')}.`
            : `No approval rules added to workspace "${r.rules.workspace}".`
        )
        setSkipped(r.rules.skipped)
      }
      setNotice(parts.join(' '))
      onSaved(r.config.audit)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setApplying(false)
    }
  }

  return (
    <form onSubmit={save} className="mb-6 rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
      <div className="flex items-start gap-3">
        <EyeOff className="mt-0.5 h-4 w-4 shrink-0 text-indigo-600" aria-hidden="true" />
        <div>
          <h2 className="text-sm font-semibold text-slate-900">
            Audit &amp; PII Redaction
            {readOnly && <span className="ml-2 text-xs font-medium text-amber-700">(read-only)</span>}
          </h2>
          <p className="mt-0.5 text-xs text-slate-500">
            What the hash-chained audit ledger keeps about each request. Everything is redacted before it is written.
          </p>
        </div>
      </div>

      {error && (
        <div className="mt-4">
          <ErrorBanner message={error} onDismiss={() => setError(null)} />
        </div>
      )}
      {notice && (
        <div className="mt-4">
          <SuccessBanner message={notice} onDismiss={() => setNotice(null)} />
        </div>
      )}
      {skipped.length > 0 && (
        <div className="mt-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-600">
          <p className="mb-1 font-semibold text-slate-700">Rules left unchanged (your existing decisions win):</p>
          <ul className="list-inside list-disc space-y-0.5">
            {skipped.map((s) => (
              <li key={s.key}>
                <code className="font-mono">{s.key}</code>: {s.reason}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* ---- Industry compliance preset ---- */}
      <div className="mt-4 rounded-lg border border-indigo-100 bg-indigo-50/40 p-3.5">
        <p className="text-xs font-semibold text-slate-900">Industry compliance preset</p>
        <p className="mt-0.5 text-xs text-slate-500">
          Adds the industry&apos;s sensitive fields to your redacted keys (nothing is removed) and records the frameworks you report against in the
          auditor pack.
          {audit.activeTemplate && (
            <>
              {' '}
              Active: <strong className="font-semibold text-slate-700">{templates.find((t) => t.id === audit.activeTemplate)?.name ?? audit.activeTemplate}</strong>
              {audit.complianceFrameworks?.length ? ` (${audit.complianceFrameworks.join(', ')})` : ''}.
            </>
          )}
        </p>

        <div className="mt-3 grid gap-2 sm:grid-cols-4" role="radiogroup" aria-label="Industry compliance preset">
          {templates.map((t) => {
            const Icon = TEMPLATE_ICONS[t.id]
            const active = t.id === templateId
            return (
              <button
                key={t.id}
                type="button"
                role="radio"
                aria-checked={active}
                disabled={readOnly}
                onClick={() => chooseTemplate(t.id)}
                className={`flex items-center gap-2 rounded-lg border px-3 py-2 text-left text-xs font-semibold transition disabled:cursor-not-allowed disabled:opacity-60 ${
                  active ? 'border-indigo-400 bg-white text-indigo-800 ring-1 ring-indigo-200' : 'border-slate-200 bg-white text-slate-700 hover:bg-slate-50'
                }`}
              >
                <Icon className="h-4 w-4 shrink-0" aria-hidden="true" />
                {t.name.split(' & ')[0]}
              </button>
            )
          })}
          {templates.length === 0 && <p className="text-xs text-slate-500 sm:col-span-4">Loading presets…</p>}
        </div>

        {template && (
          <div className="mt-3 space-y-3 text-xs">
            <p className="text-slate-600">{template.summary}</p>
            {template.redactKeys.length > 0 && (
              <div className="flex flex-wrap gap-1">
                {template.redactKeys.map((k) => (
                  <span
                    key={k}
                    className={`rounded px-1.5 py-0.5 font-mono ${keys.some((x) => x.toLowerCase() === k.toLowerCase()) ? 'bg-slate-100 text-slate-500' : 'bg-indigo-100 text-indigo-800'}`}
                    title={keys.some((x) => x.toLowerCase() === k.toLowerCase()) ? 'Already redacted' : 'Will be added'}
                  >
                    {k}
                  </span>
                ))}
              </div>
            )}

            <div>
              <p className="mb-1 font-medium text-slate-600">Frameworks</p>
              <div className="flex flex-wrap gap-1.5">
                {frameworkChoices.map((f) => {
                  const on = frameworks.includes(f)
                  return (
                    <button
                      key={f}
                      type="button"
                      aria-pressed={on}
                      disabled={readOnly}
                      onClick={() => toggleFramework(f)}
                      className={`rounded-full px-2.5 py-0.5 font-medium ring-1 ring-inset transition disabled:opacity-60 ${
                        on ? 'bg-indigo-600 text-white ring-indigo-600' : 'bg-white text-slate-600 ring-slate-200 hover:bg-slate-50'
                      }`}
                    >
                      {f}
                    </button>
                  )
                })}
              </div>
            </div>

            {template.id !== 'custom' && (
              <label className="flex items-start gap-2">
                <input
                  type="checkbox"
                  checked={includeRules}
                  disabled={readOnly}
                  onChange={(e) => setIncludeRules(e.target.checked)}
                  className="mt-0.5 h-4 w-4 rounded border-slate-300 text-indigo-600 focus:ring-indigo-500"
                />
                <span>
                  <span className="font-medium text-slate-800">Also add recommended REQUIRE_APPROVAL route rules for this industry</span>
                  <span className="mt-0.5 block text-slate-500">
                    {Object.keys(template.rules).join(', ')}. Added to the selected workspace only where they don&apos;t override a rule you already
                    have; routes you explicitly block stay blocked.
                  </span>
                </span>
              </label>
            )}

            <div className="flex items-center justify-end gap-3">
              {dirty && <span className="text-amber-700">Save or discard your key changes first.</span>}
              <button
                type="button"
                onClick={() => void applyTemplate()}
                disabled={readOnly || applying || dirty}
                title={readOnly ? READ_ONLY_HINT : undefined}
                className="inline-flex items-center gap-2 rounded-lg border border-indigo-200 bg-white px-3.5 py-1.5 text-xs font-semibold text-indigo-700 shadow-sm transition hover:bg-indigo-50 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {applying ? <Spinner className="h-3.5 w-3.5" /> : <Check className="h-3.5 w-3.5" aria-hidden="true" />}
                Apply {template.name.split(' & ')[0]} preset
              </button>
            </div>
          </div>
        )}
      </div>

      <label className="mt-4 flex items-start gap-3 rounded-lg border border-slate-200 bg-slate-50/70 p-3.5">
        <input
          type="checkbox"
          checked={capture}
          disabled={readOnly}
          onChange={(e) => setCapture(e.target.checked)}
          className="mt-0.5 h-4 w-4 rounded border-slate-300 text-indigo-600 focus:ring-indigo-500 disabled:opacity-50"
        />
        <div className="text-xs">
          <span className="font-semibold text-slate-900">Capture outgoing response payloads</span>
          <p className="mt-0.5 text-slate-500">
            Stores the redacted upstream response (up to 64 KB) with each allowed or approved request and seals it into the
            ledger. Request bodies are always kept, redacted, for history replay. Event streams and binary or compressed
            bodies are noted but not stored.
          </p>
        </div>
      </label>

      <div className="mt-4">
        <span className="mb-1.5 block text-xs font-medium text-slate-600">Custom redacted keys</span>
        <div
          className={`${INPUT_CLASS} flex min-h-[2.5rem] flex-wrap items-center gap-1.5 ${readOnly ? 'opacity-60' : ''}`}
          onClick={(e) => (e.currentTarget.querySelector('input') as HTMLInputElement | null)?.focus()}
        >
          {keys.map((k) => (
            <span key={k} className="inline-flex items-center gap-1 rounded-md bg-indigo-50 py-0.5 pl-2 pr-1 font-mono text-xs text-indigo-800 ring-1 ring-inset ring-indigo-200">
              {k}
              {!readOnly && (
                <button
                  type="button"
                  onClick={() => setKeys(keys.filter((x) => x !== k))}
                  aria-label={`Remove ${k}`}
                  className="rounded p-0.5 hover:bg-indigo-100"
                >
                  <X className="h-3 w-3" aria-hidden="true" />
                </button>
              )}
            </span>
          ))}
          <input
            type="text"
            value={draft}
            disabled={readOnly}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={onKeyDown}
            onBlur={addDraft}
            placeholder={keys.length === 0 ? 'e.g. customer_ref, dob, iban' : 'Add a key…'}
            aria-label="Add a redacted key"
            className="min-w-[8rem] flex-1 border-0 bg-transparent p-0 font-mono text-sm outline-none focus:ring-0"
          />
        </div>
        <p className="mt-1.5 text-xs text-slate-500">
          Press Enter or comma to add. Whole-key match, ignoring case, <code className="font-mono">_</code>,{' '}
          <code className="font-mono">-</code> and <code className="font-mono">.</code> (<code className="font-mono">credit_card</code>{' '}
          also matches <code className="font-mono">creditCard</code>; <code className="font-mono">key</code> does not match{' '}
          <code className="font-mono">monkey</code>). Standard secrets are always redacted automatically: passwords, tokens,
          API keys, Authorization / Bearer values, JWTs, card numbers, CVV and SSN.
        </p>
      </div>

      <div className="mt-4 flex justify-end gap-2 border-t border-slate-100 pt-4">
        {dirty && !readOnly && (
          <button
            type="button"
            onClick={() => {
              setCapture(audit.capturePayloads)
              setKeys(audit.redactKeys)
              setDraft('')
            }}
            className="rounded-lg border border-slate-200 px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
          >
            Discard
          </button>
        )}
        <button
          type="submit"
          disabled={saving || !dirty || readOnly}
          title={readOnly ? READ_ONLY_HINT : undefined}
          className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {saving ? <Spinner /> : <Check className="h-4 w-4" aria-hidden="true" />}
          Save audit settings
        </button>
      </div>
    </form>
  )
}
