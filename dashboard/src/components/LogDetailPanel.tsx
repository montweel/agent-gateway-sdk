import { useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { Copy, Link2, Lock, UserCheck, UserRound } from 'lucide-react'
import { api, errorMessage } from '../lib/api'
import type { LogDetail } from '../lib/types'
import { JsonInspector } from './JsonInspector'
import { EndUserBadge } from './EndUserBadge'
import { Spinner } from './ui'

/** JSON text for the inspector; a string body (non-JSON response) is shown as-is. */
function asText(value: unknown): string | null {
  if (value === null || value === undefined) return null
  return typeof value === 'string' ? value : JSON.stringify(value)
}

function Field({ icon, label, children, title }: { icon: ReactNode; label: string; children: ReactNode; title?: string }) {
  return (
    <div className="min-w-0" title={title}>
      <dt className="mb-0.5 flex items-center gap-1 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
        {icon}
        {label}
      </dt>
      <dd className="truncate text-sm text-slate-800">{children}</dd>
    </div>
  )
}

function HashLine({ label, value }: { label: string; value: string | null }) {
  const [copied, setCopied] = useState(false)
  if (!value) return null
  return (
    <div className="flex min-w-0 items-center gap-2 text-xs">
      <span className="w-20 shrink-0 font-medium text-slate-500">{label}</span>
      <code className="min-w-0 flex-1 break-all font-mono text-slate-700">{value}</code>
      <button
        type="button"
        onClick={() => {
          void navigator.clipboard?.writeText(value).then(() => {
            setCopied(true)
            setTimeout(() => setCopied(false), 1200)
          })
        }}
        aria-label={`Copy ${label}`}
        className="shrink-0 rounded p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-700"
      >
        {copied ? <span className="text-[10px] font-semibold text-emerald-600">Copied</span> : <Copy className="h-3.5 w-3.5" aria-hidden="true" />}
      </button>
    </div>
  )
}

/**
 * Expanded audit row: attribution, the redacted request / response payloads and the row's link in
 * the SHA-256 hash chain. Loaded on demand from GET /logs/:id (the list stays lean).
 */
export function LogDetailPanel({ id }: { id: number }) {
  const [detail, setDetail] = useState<LogDetail | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let live = true
    api
      .get<LogDetail>(`/logs/${id}`)
      .then((res) => live && setDetail(res.data))
      .catch((err: unknown) => live && setError(errorMessage(err)))
    return () => {
      live = false
    }
  }, [id])

  if (error) return <p className="text-sm text-red-700">Could not load row #{id}: {error}</p>
  if (!detail) {
    return (
      <p className="flex items-center gap-2 text-sm text-slate-500">
        <Spinner /> Loading audit row #{id}…
      </p>
    )
  }

  const req = detail.request
  const resp = typeof detail.response === 'string' ? { status: 0, contentType: null, bytes: 0, body: detail.response } : detail.response
  const isDecision = (detail.user_agent ?? '').startsWith('decided_by:')
  const hasQuery = typeof req?.query === 'object' && req.query !== null && Object.keys(req.query).length > 0

  return (
    <div className="space-y-4">
      <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Field icon={<UserRound className="h-3 w-3" aria-hidden="true" />} label="End user">
          {detail.end_user ? (
            <span className="flex min-w-0 items-center gap-1.5">
              <span className="truncate" title={detail.end_user}>
                {detail.end_user}
              </span>
              <EndUserBadge verified={Boolean(detail.end_user_verified)} />
            </span>
          ) : (
            <span className="text-slate-400">not provided</span>
          )}
        </Field>
        <Field icon={<Link2 className="h-3 w-3" aria-hidden="true" />} label="Agent">
          {detail.agent_key ?? (isDecision ? <span className="text-slate-400">—</span> : (detail.caller_ip ?? <span className="text-slate-400">unknown</span>))}
        </Field>
        <Field icon={<UserCheck className="h-3 w-3" aria-hidden="true" />} label="Approved by" title="The signed-in admin (or verified SSO identity) who released this held action">
          {detail.approved_by ?? <span className="text-slate-400">{detail.action_id ? 'see the APPROVED row for this request ID' : 'not held for approval'}</span>}
        </Field>
        <Field icon={<Lock className="h-3 w-3" aria-hidden="true" />} label="Ledger">
          {detail.sealed ? (
            <span className="font-medium text-emerald-700">Sealed</span>
          ) : detail.response_pending ? (
            <span className="text-amber-700">Waiting for the response…</span>
          ) : (
            <span className="text-amber-700">Sealing…</span>
          )}
        </Field>
      </dl>

      <div className="grid gap-4 lg:grid-cols-2">
        <section>
          <h4 className="mb-1.5 flex items-center justify-between text-xs font-semibold uppercase tracking-wider text-slate-500">
            Request payload (redacted)
            {req?.truncated && <span className="normal-case tracking-normal text-amber-700">body too large to keep</span>}
          </h4>
          <JsonInspector
            text={asText(req?.body)}
            emptyLabel={req?.bodyUnknown ? 'Body not read (refused before parsing)' : req ? 'No body' : 'No request snapshot recorded for this row'}
            defaultExpandDepth={2}
          />
          {hasQuery && (
            <div className="mt-2">
              <p className="mb-1 text-[11px] font-medium text-slate-500">Query</p>
              <JsonInspector text={asText(req.query)} defaultExpandDepth={1} maxHeight="max-h-32" />
            </div>
          )}
        </section>
        <section>
          <h4 className="mb-1.5 flex items-center justify-between text-xs font-semibold uppercase tracking-wider text-slate-500">
            Response payload (redacted)
            {resp && resp.status > 0 && (
              <span className="normal-case tracking-normal text-slate-600">
                HTTP {resp.status}
                {resp.contentType ? ` · ${resp.contentType.split(';')[0]}` : ''}
                {resp.truncated ? ' · truncated' : ''}
              </span>
            )}
          </h4>
          <JsonInspector
            text={asText(resp?.body)}
            emptyLabel={
              resp?.note
                ? `Not stored: ${resp.note}`
                : resp
                  ? 'Empty body'
                  : detail.response_pending
                    ? 'Response still in flight'
                    : detail.status === 'ALLOWED' || detail.status === 'APPROVED'
                      ? 'No response recorded (capture was off, or the row predates it)'
                      : 'Not forwarded, so there is no upstream response'
            }
            defaultExpandDepth={2}
          />
        </section>
      </div>

      {(detail.original_payload || detail.modified_payload) && (
        <section className="grid gap-4 lg:grid-cols-2">
          <div>
            <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-slate-500">As queued</h4>
            <JsonInspector text={detail.original_payload} defaultExpandDepth={2} maxHeight="max-h-48" />
          </div>
          <div>
            <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-slate-500">As edited by the approver</h4>
            <JsonInspector text={detail.modified_payload} defaultExpandDepth={2} maxHeight="max-h-48" />
          </div>
        </section>
      )}

      <section className="rounded-lg border border-slate-200 bg-white px-3 py-2">
        <h4 className="mb-1 text-xs font-semibold uppercase tracking-wider text-slate-500">Hash chain</h4>
        {detail.row_hash ? (
          <div className="space-y-1">
            <HashLine label="Ledger hash" value={detail.row_hash} />
            <HashLine label="Previous" value={detail.prev_hash} />
          </div>
        ) : (
          <p className="text-xs text-slate-500">Not sealed yet. Rows are sealed in order, usually within a second (or once their response arrives).</p>
        )}
      </section>
    </div>
  )
}
