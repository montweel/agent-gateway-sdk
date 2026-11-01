import { useCallback, useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import { Check, Copy, KeyRound, Plus, Trash2 } from 'lucide-react'
import { api, errorMessage } from '../lib/api'
import { isProRequired } from '../lib/types'
import type { AgentKey, ProRequiredResponse } from '../lib/types'
import { INPUT_CLASS, formatTime } from '../lib/utils'
import { ErrorBanner, ProCallout, RefreshButton, Spinner, WarningBanner } from './ui'
import { ProLockLink } from './LicenseCard'

const COMMUNITY_KEY_LIMIT = 2

/** Agent API keys (admin only). A new key is shown once; the server keeps only its hash. */
export function AgentKeysPanel({
  required,
  isPro,
  onOpenLicense,
}: {
  required: boolean
  isPro: boolean
  onOpenLicense: () => void
}) {
  const [keys, setKeys] = useState<AgentKey[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [proNotice, setProNotice] = useState<ProRequiredResponse | null>(null)
  const [name, setName] = useState('')
  const [creating, setCreating] = useState(false)
  const [revealed, setRevealed] = useState<{ name: string; key: string } | null>(null)
  const [copied, setCopied] = useState(false)
  const [deleting, setDeleting] = useState<number | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const res = await api.get<AgentKey[]>('/agent-keys')
      setKeys(res.data)
      setError(null)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  useEffect(() => {
    if (!copied) return
    const id = window.setTimeout(() => setCopied(false), 1500)
    return () => window.clearTimeout(id)
  }, [copied])

  const limitReached = !isPro && keys.length >= COMMUNITY_KEY_LIMIT

  async function create(e: FormEvent) {
    e.preventDefault()
    if (!name.trim() || limitReached) return
    setCreating(true)
    setError(null)
    try {
      const res = await api.post<{ name: string; key: string } | ProRequiredResponse>('/agent-keys', {
        name: name.trim(),
      })
      if (isProRequired(res.data)) {
        setProNotice(res.data)
        return
      }
      setProNotice(null)
      setRevealed({ name: res.data.name, key: res.data.key })
      setName('')
      await load()
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setCreating(false)
    }
  }

  async function remove(k: AgentKey) {
    if (!window.confirm(`Delete the key "${k.name}"? Agents using it will stop working immediately.`)) return
    setDeleting(k.id)
    setError(null)
    try {
      await api.delete(`/agent-keys/${k.id}`)
      await load()
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setDeleting(null)
    }
  }

  async function copyKey() {
    if (!revealed) return
    try {
      await navigator.clipboard.writeText(revealed.key)
      setCopied(true)
    } catch {
      // ignore
    }
  }

  return (
    <div className="mb-6 rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-900">
            <KeyRound className="h-4 w-4 text-slate-400" aria-hidden="true" />
            Agent API keys
          </h2>
          <p className="mt-0.5 text-xs text-slate-500">
            Agents send a key as <code className="font-mono">x-agent-key</code> or{' '}
            <code className="font-mono">Authorization: Bearer agk_…</code>. The key&apos;s name is recorded in the audit
            log and on approvals.
          </p>
        </div>
        <RefreshButton onClick={() => void load()} loading={loading} />
      </div>

      {required && keys.length === 0 && !loading && (
        <div className="mt-4">
          <WarningBanner>Keys are required but none exist, so every agent request is currently refused.</WarningBanner>
        </div>
      )}
      {proNotice && (
        <div className="mt-4">
          <ProCallout message={proNotice.message} upgradeUrl={proNotice.upgradeUrl} onDismiss={() => setProNotice(null)} />
        </div>
      )}
      {error && (
        <div className="mt-4">
          <ErrorBanner message={error} onDismiss={() => setError(null)} />
        </div>
      )}

      {revealed && (
        <div className="mt-4 rounded-lg border border-emerald-200 bg-emerald-50 p-4" role="status">
          <p className="text-sm font-medium text-emerald-900">
            Key for “{revealed.name}” created. Copy it now: it will not be shown again.
          </p>
          <div className="mt-2 flex items-center gap-2">
            <code className="min-w-0 flex-1 break-all rounded-md bg-white px-3 py-2 font-mono text-xs text-slate-900 ring-1 ring-inset ring-emerald-200">
              {revealed.key}
            </code>
            <button
              type="button"
              onClick={() => void copyKey()}
              className="inline-flex items-center gap-2 rounded-lg border border-emerald-200 bg-white px-3 py-2 text-sm font-medium text-emerald-800 shadow-sm hover:bg-emerald-100"
            >
              {copied ? <Check className="h-4 w-4" aria-hidden="true" /> : <Copy className="h-4 w-4" aria-hidden="true" />}
              {copied ? 'Copied' : 'Copy'}
            </button>
            <button
              type="button"
              onClick={() => setRevealed(null)}
              className="rounded-lg px-3 py-2 text-sm font-medium text-emerald-800 hover:bg-emerald-100"
            >
              Done
            </button>
          </div>
        </div>
      )}

      <form onSubmit={create} className="mt-4 flex flex-wrap items-end gap-3">
        <label className="block min-w-[14rem] flex-1">
          <span className="mb-1.5 block text-xs font-medium text-slate-600">New key name</span>
          <input
            type="text"
            value={name}
            maxLength={64}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. travel-booking-agent"
            className={INPUT_CLASS}
          />
        </label>
        <button
          type="submit"
          disabled={creating || !name.trim() || limitReached}
          className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {creating ? <Spinner /> : <Plus className="h-4 w-4" aria-hidden="true" />}
          Create key
        </button>
        {limitReached && (
          <div className="flex items-center gap-2 pb-2 text-xs text-slate-600">
            <ProLockLink onOpen={onOpenLicense} label="Renew free to add more ↗" />
            <span>Community Edition is limited to {COMMUNITY_KEY_LIMIT} keys.</span>
          </div>
        )}
      </form>

      <div className="mt-4 overflow-hidden rounded-lg border border-slate-200">
        {keys.length === 0 ? (
          <p className="px-4 py-6 text-center text-xs text-slate-500">{loading ? 'Loading…' : 'No agent keys yet.'}</p>
        ) : (
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50 text-slate-500">
              <tr>
                <th className="px-4 py-2 font-medium">Name</th>
                <th className="px-4 py-2 font-medium">Key</th>
                <th className="px-4 py-2 font-medium">Created</th>
                <th className="px-4 py-2 font-medium">Last used</th>
                <th className="px-4 py-2" />
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {keys.map((k) => (
                <tr key={k.id}>
                  <td className="px-4 py-2 font-medium text-slate-900">{k.name}</td>
                  <td className="px-4 py-2 font-mono text-slate-600">{k.keyPrefix}…</td>
                  <td className="px-4 py-2 text-slate-600">{formatTime(k.createdAt)}</td>
                  <td className="px-4 py-2 text-slate-600">{k.lastUsedAt ? formatTime(k.lastUsedAt) : 'Never'}</td>
                  <td className="px-4 py-2 text-right">
                    <button
                      type="button"
                      onClick={() => void remove(k)}
                      disabled={deleting === k.id}
                      aria-label={`Delete key ${k.name}`}
                      className="rounded-md p-1.5 text-slate-400 transition hover:bg-red-50 hover:text-red-600 disabled:opacity-60"
                    >
                      {deleting === k.id ? <Spinner /> : <Trash2 className="h-4 w-4" aria-hidden="true" />}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
