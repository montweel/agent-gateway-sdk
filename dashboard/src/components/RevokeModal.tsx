import { useEffect, useState } from 'react'
import { ShieldOff, X } from 'lucide-react'
import { api, errorMessage } from '../lib/api'
import type { RevokeResponse } from '../lib/types'
import { INPUT_CLASS } from '../lib/utils'
import { Spinner } from './ui'

export interface RevokeTarget {
  actionId: number
  method: string
  path: string
  agentKey?: string | null
  agentKeyPrefix?: string | null
  callerIp?: string | null
}

/**
 * "Revoke & Block Caller": blocks the agent key and/or IP, auto-rejects anything that
 * caller still has queued, and optionally fires the compensating rollback webhook.
 */
export function RevokeModal({
  target,
  onClose,
  onDone,
}: {
  target: RevokeTarget
  onClose: () => void
  onDone: (result: RevokeResponse) => void
}) {
  const hasKey = Boolean(target.agentKey)
  const hasIp = Boolean(target.callerIp)
  const [blockAgentKey, setBlockAgentKey] = useState(hasKey)
  const [blockIp, setBlockIp] = useState(hasIp)
  const [fireRollback, setFireRollback] = useState(true)
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !busy) onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [busy, onClose])

  async function submit() {
    setBusy(true)
    setError(null)
    try {
      const res = await api.post<RevokeResponse>(`/approvals/${target.actionId}/revoke`, {
        blockAgentKey,
        blockIp,
        fireRollback,
        reason: reason.trim() || null,
      })
      onDone(res.data)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  const nothingSelected = !(blockAgentKey && hasKey) && !(blockIp && hasIp)

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 p-4" role="dialog" aria-modal="true" aria-labelledby="revoke-title">
      <div className="w-full max-w-lg rounded-xl bg-white p-6 shadow-xl">
        <div className="mb-4 flex items-start justify-between gap-3">
          <div>
            <h2 id="revoke-title" className="flex items-center gap-2 text-lg font-semibold text-slate-900">
              <ShieldOff className="h-5 w-5 text-red-600" aria-hidden="true" />
              Revoke &amp; block caller
            </h2>
            <p className="mt-1 text-sm text-slate-500">
              Action #{target.actionId} · <span className="font-mono">{target.method} {target.path}</span>
            </p>
          </div>
          <button type="button" onClick={onClose} disabled={busy} className="text-slate-400 hover:text-slate-700" aria-label="Close">
            <X className="h-5 w-5" aria-hidden="true" />
          </button>
        </div>

        <div className="space-y-3 text-sm">
          <label className={`flex items-start gap-3 rounded-lg border p-3 ${hasKey ? 'border-slate-200' : 'border-slate-100 opacity-60'}`}>
            <input type="checkbox" className="mt-0.5" checked={blockAgentKey && hasKey} disabled={!hasKey || busy} onChange={(e) => setBlockAgentKey(e.target.checked)} />
            <span>
              <span className="font-medium text-slate-900">Block agent key</span>
              <span className="block text-xs text-slate-500">
                {hasKey ? `“${target.agentKey}”${target.agentKeyPrefix ? ` (${target.agentKeyPrefix}…)` : ''}` : 'This request did not use an agent key.'}
              </span>
            </span>
          </label>
          <label className={`flex items-start gap-3 rounded-lg border p-3 ${hasIp ? 'border-slate-200' : 'border-slate-100 opacity-60'}`}>
            <input type="checkbox" className="mt-0.5" checked={blockIp && hasIp} disabled={!hasIp || busy} onChange={(e) => setBlockIp(e.target.checked)} />
            <span>
              <span className="font-medium text-slate-900">Block IP address</span>
              <span className="block text-xs text-slate-500">{hasIp ? target.callerIp : 'No IP was recorded for this request.'}</span>
            </span>
          </label>
          <label className="flex items-start gap-3 rounded-lg border border-slate-200 p-3">
            <input type="checkbox" className="mt-0.5" checked={fireRollback} disabled={busy} onChange={(e) => setFireRollback(e.target.checked)} />
            <span>
              <span className="font-medium text-slate-900">Fire compensating rollback webhook</span>
              <span className="block text-xs text-slate-500">
                POSTs the original request id and payload to the rollback URL from Gateway Setup (skipped if none is set).
              </span>
            </span>
          </label>
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-slate-600">Reason (kept in the audit log)</span>
            <textarea value={reason} onChange={(e) => setReason(e.target.value)} maxLength={500} rows={2} className={INPUT_CLASS} placeholder="e.g. Prompt injection discovered in support ticket #4411" disabled={busy} />
          </label>
          <p className="rounded-lg bg-amber-50 px-3 py-2 text-xs text-amber-900">
            Anything this caller still has waiting for approval is rejected automatically.
          </p>
        </div>

        {error && <p role="alert" className="mt-3 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800">{error}</p>}

        <div className="mt-5 flex justify-end gap-3">
          <button type="button" onClick={onClose} disabled={busy} className="rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50">
            Cancel
          </button>
          <button
            type="button"
            onClick={() => void submit()}
            disabled={busy || nothingSelected}
            className="inline-flex items-center gap-2 rounded-lg bg-red-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-red-500 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {busy ? <Spinner /> : <ShieldOff className="h-4 w-4" aria-hidden="true" />}
            Revoke &amp; block
          </button>
        </div>
      </div>
    </div>
  )
}
