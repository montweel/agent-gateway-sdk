import { useState } from 'react'
import type { FormEvent, KeyboardEvent } from 'react'
import { Check, EyeOff, X } from 'lucide-react'
import { api, errorMessage } from '../lib/api'
import type { AuditConfig, GatewayConfig } from '../lib/types'
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

/**
 * "Audit & PII Redaction": response capture and custom redact keys (config.json "audit").
 * Saved on its own (POST /config { audit }), so it never touches the other gateway settings.
 */
export function AuditSettingsCard({
  audit,
  readOnly,
  onSaved,
}: {
  audit: AuditConfig
  readOnly: boolean
  onSaved: (config: GatewayConfig) => void
}) {
  const [capture, setCapture] = useState(audit.capturePayloads)
  const [keys, setKeys] = useState<string[]>(audit.redactKeys)
  const [draft, setDraft] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)

  const pending = splitKeys(draft).filter((k) => !keys.includes(k))
  const nextKeys = [...keys, ...pending]
  const dirty = capture !== audit.capturePayloads || !sameKeys(nextKeys, audit.redactKeys)

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
    setSaved(false)
    try {
      // Text still in the box counts: nobody expects a typed key to be silently dropped.
      const res = await api.post<{ success: boolean; config: GatewayConfig }>('/config', {
        audit: { capturePayloads: capture, redactKeys: nextKeys },
      })
      const stored = res.data.config.audit ?? { capturePayloads: capture, redactKeys: nextKeys }
      setCapture(stored.capturePayloads)
      setKeys(stored.redactKeys)
      setDraft('')
      setSaved(true)
      onSaved(res.data.config)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setSaving(false)
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
      {saved && (
        <div className="mt-4">
          <SuccessBanner message="Audit settings saved. They apply to the next request." onDismiss={() => setSaved(false)} />
        </div>
      )}

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

      <div className="mt-4 flex justify-end border-t border-slate-100 pt-4">
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
