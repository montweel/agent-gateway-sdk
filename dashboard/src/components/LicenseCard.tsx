import { useState } from 'react'
import type { FormEvent } from 'react'
import { Award, Check, Trash2 } from 'lucide-react'
import { api, errorMessage } from '../lib/api'
import type { LicenseStatus } from '../lib/types'
import { INPUT_CLASS, READ_ONLY_HINT } from '../lib/utils'
import type { LicenseApi } from '../hooks/useLicense'
import { Badge, ErrorBanner, Spinner, SuccessBanner } from './ui'
import type { Tone } from './ui'

/** Small "PRO" pill for features that need an active Pro trial or key. */
export function ProBadge() {
  return (
    <span className="inline-flex items-center rounded-full bg-indigo-600 px-2 py-0.5 text-[10px] font-bold tracking-wide text-white">
      PRO
    </span>
  )
}

/** "PRO · Renew free ↗" prompt that opens Settings & Discovery, where the license card lives. */
export function ProLockLink({ onOpen, label = 'Renew free ↗' }: { onOpen: () => void; label?: string }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <ProBadge />
      <button type="button" onClick={onOpen} className="text-xs font-medium text-indigo-600 hover:text-indigo-500">
        {label}
      </button>
    </span>
  )
}

function statusBadge(l: LicenseStatus): { tone: Tone; label: string } {
  if (l.tier === 'PRO' && l.isTrial) return { tone: 'green', label: '7-Day Free Pro Trial' }
  if (l.tier === 'PRO') return { tone: 'violet', label: 'Mont Pro Active' }
  return { tone: 'amber', label: l.isTrial ? 'Community Edition (Trial Expired)' : 'Community Edition (Key Expired)' }
}

function formatDate(iso?: string): string {
  return iso ? new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }) : '—'
}

export function LicenseCard({ licenseApi, readOnly }: { licenseApi: LicenseApi; readOnly: boolean }) {
  const { license, setLicense } = licenseApi
  const [keyInput, setKeyInput] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)

  async function activate(e: FormEvent) {
    e.preventDefault()
    if (readOnly || !keyInput.trim()) return
    setBusy(true)
    setError(null)
    setMessage(null)
    try {
      const res = await api.post<LicenseStatus>('/license', { licenseKey: keyInput.trim() })
      setLicense(res.data)
      setKeyInput('')
      setMessage(
        res.data.tier === 'PRO'
          ? `Mont Pro is active until ${formatDate(res.data.expiresAt)}.`
          : 'That key is valid but has already expired. Get a fresh free 90-day trial key at montweel.com/#license-renewal.'
      )
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  async function remove() {
    if (readOnly || !window.confirm('Remove the stored license key?')) return
    setBusy(true)
    setError(null)
    setMessage(null)
    try {
      const res = await api.delete<LicenseStatus>('/license')
      setLicense(res.data)
      setMessage('License key removed.')
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  const badge = license ? statusBadge(license) : null
  const hasStoredKey = license?.source === 'DB'

  return (
    <div id="mont-license" className="mb-6 rounded-xl border border-indigo-200 bg-white p-5 shadow-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-900">
            <Award className="h-4 w-4 text-indigo-600" aria-hidden="true" />
            Mont Pro License &amp; Free Renewal
          </h2>
          {license ? (
            <p className="mt-0.5 text-xs text-slate-500">
              {license.expired
                ? `Expired ${formatDate(license.expiresAt)}`
                : `Expires ${formatDate(license.expiresAt)} · ${license.daysRemaining ?? 0} day${
                    license.daysRemaining === 1 ? '' : 's'
                  } remaining`}
              {license.org && !license.isTrial && ` · ${license.org}`}
            </p>
          ) : (
            <p className="mt-0.5 text-xs text-slate-500">Loading license status…</p>
          )}
        </div>
        {badge && <Badge tone={badge.tone}>{badge.label}</Badge>}
      </div>

      <div className="mt-4 rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-3 text-xs text-emerald-900">
        <span className="font-semibold">🎁 Free 90-Day Team Pro Trial:</span> Activate your free 90-day Team Pro trial
        key at{' '}
        <a
          href={license?.renewalUrl ?? 'https://montweel.com/#license-renewal'}
          target="_blank"
          rel="noopener noreferrer"
          className="font-semibold text-emerald-700 underline hover:text-emerald-600"
        >
          montweel.com/#license-renewal ↗
        </a>{' '}
        — no credit card or payment required.
      </div>

      {license?.reason && license.expired && <p className="mt-3 text-xs text-amber-800">{license.reason}</p>}

      <div className="mt-4">
        {error && <ErrorBanner message={error} onDismiss={() => setError(null)} />}
        {message && <SuccessBanner message={message} onDismiss={() => setMessage(null)} />}
      </div>

      <form onSubmit={activate} className="flex flex-wrap items-end gap-3">
        <label className="block min-w-[16rem] flex-1">
          <span className="mb-1.5 block text-xs font-medium text-slate-600">License key</span>
          <input
            type="text"
            value={keyInput}
            onChange={(e) => setKeyInput(e.target.value)}
            disabled={readOnly}
            placeholder="MONT-..."
            spellCheck={false}
            autoComplete="off"
            className={`${INPUT_CLASS} font-mono`}
          />
        </label>
        <button
          type="submit"
          disabled={busy || readOnly || !keyInput.trim()}
          title={readOnly ? READ_ONLY_HINT : undefined}
          className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {busy ? <Spinner /> : <Check className="h-4 w-4" aria-hidden="true" />}
          Activate / Renew Key
        </button>
        {hasStoredKey && !readOnly && (
          <button
            type="button"
            onClick={() => void remove()}
            disabled={busy}
            className="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 shadow-sm transition hover:bg-slate-50 disabled:opacity-60"
          >
            <Trash2 className="h-4 w-4" aria-hidden="true" />
            Remove Key
          </button>
        )}
      </form>
      {license?.source === 'ENV' && (
        <p className="mt-2 text-xs text-slate-500">
          This license comes from the <code className="font-mono">MONT_LICENSE_KEY</code> environment variable.
        </p>
      )}
    </div>
  )
}
