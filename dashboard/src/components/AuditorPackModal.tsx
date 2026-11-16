import { useState } from 'react'
import type { FormEvent, ReactNode } from 'react'
import axios from 'axios'
import { FileCheck2, FileJson, FileText, X } from 'lucide-react'
import { api, errorMessage } from '../lib/api'
import { INPUT_CLASS } from '../lib/utils'
import { Spinner } from './ui'

type PackFormat = 'report' | 'json'

/** Error bodies of a blob request arrive as a Blob: read the JSON message out of it. */
async function blobErrorMessage(err: unknown): Promise<{ message: string; proRequired: boolean }> {
  if (axios.isAxiosError(err) && err.response?.data instanceof Blob) {
    try {
      const data = JSON.parse(await err.response.data.text()) as { message?: string; proRequired?: boolean }
      if (data.message) return { message: data.message, proRequired: Boolean(data.proRequired) }
    } catch {
      // fall through
    }
  }
  return { message: errorMessage(err), proRequired: axios.isAxiosError(err) && err.response?.status === 402 }
}

function filenameFrom(disposition: string | undefined, fallback: string): string {
  const m = /filename="([^"]+)"/.exec(disposition ?? '')
  return m ? m[1] : fallback
}

/**
 * Auditor Evidence Pack download (GET /audit/export-pack, Pro): a Markdown attestation report or a
 * checksummed JSON evidence bundle, for a date range and optionally one agent / end user.
 */
export function AuditorPackModal({ agents, onClose, onOpenLicense }: { agents: string[]; onClose: () => void; onOpenLicense?: () => void }) {
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const [agentName, setAgentName] = useState('')
  const [endUser, setEndUser] = useState('')
  const [format, setFormat] = useState<PackFormat>('report')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<{ message: string; proRequired: boolean } | null>(null)

  async function download(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const params: Record<string, string> = { format }
      if (from) params.from = new Date(from).toISOString()
      if (to) params.to = new Date(to).toISOString()
      if (agentName.trim()) params.agentName = agentName.trim()
      if (endUser.trim()) params.endUser = endUser.trim()
      const res = await api.get<Blob>('/audit/export-pack', { params, responseType: 'blob' })
      const url = URL.createObjectURL(res.data)
      const a = document.createElement('a')
      a.href = url
      a.download = filenameFrom(res.headers['content-disposition'] as string | undefined, format === 'json' ? 'mont-auditor-evidence.json' : 'mont-auditor-report.md')
      document.body.appendChild(a)
      a.click()
      a.remove()
      URL.revokeObjectURL(url)
      onClose()
    } catch (err) {
      setError(await blobErrorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  const option = (value: PackFormat, icon: ReactNode, title: string, text: string) => (
    <label
      className={`flex cursor-pointer items-start gap-3 rounded-lg border p-3 text-xs transition ${format === value ? 'border-indigo-400 bg-indigo-50/60 ring-1 ring-indigo-200' : 'border-slate-200 hover:bg-slate-50'}`}
    >
      <input type="radio" name="pack-format" checked={format === value} onChange={() => setFormat(value)} className="mt-0.5 h-4 w-4 border-slate-300 text-indigo-600" />
      <span>
        <span className="flex items-center gap-1.5 font-semibold text-slate-900">
          {icon}
          {title}
        </span>
        <span className="mt-0.5 block text-slate-500">{text}</span>
      </span>
    </label>
  )

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 p-4" role="dialog" aria-modal="true" aria-labelledby="pack-title">
      <form onSubmit={download} className="w-full max-w-lg rounded-xl bg-white p-6 shadow-xl">
        <div className="mb-4 flex items-start justify-between gap-3">
          <div>
            <h2 id="pack-title" className="flex items-center gap-2 text-base font-semibold text-slate-900">
              <FileCheck2 className="h-5 w-5 text-indigo-600" aria-hidden="true" />
              Export Auditor Pack
            </h2>
            <p className="mt-0.5 text-xs text-slate-500">
              A live ledger-integrity certificate, your policy snapshot, summary metrics and the matching redacted transactions.
            </p>
          </div>
          <button type="button" onClick={onClose} aria-label="Close" className="rounded-md p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-700">
            <X className="h-5 w-5" aria-hidden="true" />
          </button>
        </div>

        <div className="grid gap-3 sm:grid-cols-2">
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-slate-600">From</span>
            <input type="datetime-local" value={from} onChange={(e) => setFrom(e.target.value)} className={INPUT_CLASS} />
          </label>
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-slate-600">To</span>
            <input type="datetime-local" value={to} onChange={(e) => setTo(e.target.value)} className={INPUT_CLASS} />
          </label>
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-slate-600">Agent (key name)</span>
            <input list="pack-agents" value={agentName} onChange={(e) => setAgentName(e.target.value)} placeholder="All agents" className={`${INPUT_CLASS} font-mono`} />
            <datalist id="pack-agents">
              {agents.map((a) => (
                <option key={a} value={a} />
              ))}
            </datalist>
          </label>
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-slate-600">End user</span>
            <input value={endUser} onChange={(e) => setEndUser(e.target.value)} placeholder="All end users" className={`${INPUT_CLASS} font-mono`} />
          </label>
        </div>
        <p className="mt-1.5 text-xs text-slate-500">Leave the dates empty to cover the whole retained ledger. The integrity check always covers the entire chain.</p>

        <div className="mt-4 space-y-2">
          {option('report', <FileText className="h-3.5 w-3.5" aria-hidden="true" />, 'Auditor Attestation Report (.md)', 'Readable report: scope, integrity certificate, policy, metrics and a transaction table.')}
          {option(
            'json',
            <FileJson className="h-3.5 w-3.5" aria-hidden="true" />,
            'JSON Evidence Bundle (.json)',
            'Machine-readable, every row in full with its hashes, plus a bundleSha256 checksum that shows whether the file was changed after download.'
          )}
        </div>

        {error && (
          <div className="mt-4 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-800">
            {error.message}
            {error.proRequired && onOpenLicense && (
              <button type="button" onClick={onOpenLicense} className="ml-1 font-semibold text-indigo-700 underline">
                Activate a key
              </button>
            )}
          </div>
        )}

        <div className="mt-5 flex justify-end gap-2">
          <button type="button" onClick={onClose} className="rounded-lg border border-slate-200 px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50">
            Cancel
          </button>
          <button
            type="submit"
            disabled={busy}
            className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-500 disabled:opacity-60"
          >
            {busy && <Spinner />}
            Download
          </button>
        </div>
      </form>
    </div>
  )
}
