import { useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { AlertTriangle, BadgeCheck, Link2, Lock, UserCheck, UserRound } from 'lucide-react'
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
      <dd className="break-words text-sm text-slate-800">{children}</dd>
    </div>
  )
}

function Pill({ tone, title, children }: { tone: 'emerald' | 'amber'; title: string; children: ReactNode }) {
  const cls = tone === 'emerald' ? 'bg-emerald-50 text-emerald-800 ring-emerald-200' : 'bg-amber-50 text-amber-800 ring-amber-200'
  return (
    <span title={title} className={`inline-flex shrink-0 items-center gap-0.5 rounded-full px-1.5 py-0.5 text-[10px] font-semibold ring-1 ring-inset ${cls}`}>
      {tone === 'emerald' ? <BadgeCheck className="h-3 w-3" aria-hidden="true" /> : <AlertTriangle className="h-3 w-3" aria-hidden="true" />}
      {children}
    </span>
  )
}

/** The approval column: who approved / rejected this row, or what happened to the held request. */
function approvalField(d: LogDetail): { label: string; value: ReactNode } {
  // Rows decided before attribution existed carry the decider only in user_agent ("decided_by:<actor>").
  const decider = d.approved_by ?? ((d.user_agent ?? '').startsWith('decided_by:') ? (d.user_agent ?? '').slice('decided_by:'.length) : null)
  if (d.status === 'APPROVED') return { label: 'Approved by', value: decider ?? 'Not recorded' }
  if (d.status === 'REJECTED') return { label: 'Rejected by', value: decider ?? 'Not recorded' }
  const a = d.approval
  if (!a) return { label: 'Approval status', value: <span className="text-slate-500">Not required</span> }
  const revoked = a.revokedBy ? ` · revoked by ${a.revokedBy}` : ''
  const value: Record<string, ReactNode> = {
    PENDING: <span className="font-medium text-amber-700">Pending</span>,
    EXECUTING: <span className="font-medium text-amber-700">Approved{a.by ? ` by ${a.by}` : ''}, executing</span>,
    APPROVED: <span className="font-medium text-emerald-700">Approved by {a.by ?? 'an admin'}{revoked}</span>,
    REJECTED: <span className="font-medium text-red-700">Rejected by {a.by ?? 'an admin'}</span>,
    FAILED: <span className="font-medium text-red-700">Approved by {a.by ?? 'an admin'}, then failed{revoked}</span>,
    EXPIRED: <span className="text-slate-600">Expired: nobody decided in time</span>,
    UNKNOWN: <span className="text-slate-600">Decided (no longer in the approval queue)</span>,
  }
  return { label: 'Approval status', value: value[a.status] ?? a.status }
}

/**
 * Expanded audit row: attribution (agent, end user, approver), seal status and the redacted
 * request / response payloads. Loaded on demand from GET /logs/:id (the list stays lean). Full
 * hashes live in the Auditor Evidence Pack; here only the first 8 characters, on hover.
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
  const hasQuery = typeof req?.query === 'object' && req.query !== null && Object.keys(req.query).length > 0
  const approval = approvalField(detail)

  return (
    // min-w-0 on every grid cell: a long value or a JSON box can never stretch its column (and the
    // row, and the page) wider than the table cell this panel lives in.
    <div className="min-w-0 max-w-full space-y-4">
      <dl className="grid min-w-0 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Field icon={<UserRound className="h-3 w-3" aria-hidden="true" />} label="End user">
          {detail.end_user ? (
            <span className="flex min-w-0 flex-wrap items-center gap-1.5">
              <span className="min-w-0 break-all">{detail.end_user}</span>
              <EndUserBadge verified={Boolean(detail.end_user_verified)} />
            </span>
          ) : (
            <span className="text-slate-500">Not provided</span>
          )}
        </Field>
        <Field icon={<Link2 className="h-3 w-3" aria-hidden="true" />} label="Agent">
          {/* agent_key is only ever recorded from a key the gateway verified (agk_ agent key or mws_ workspace key). */}
          {detail.agent_key ? (
            <span className="flex flex-wrap items-center gap-1.5">
              <span className="break-all">{detail.agent_key}</span>
              <Pill tone="emerald" title="Authenticated with a registered agent (or workspace) API key">
                Verified Key
              </Pill>
            </span>
          ) : (
            <span className="flex flex-wrap items-center gap-1.5" title={detail.caller_ip ? `Caller IP ${detail.caller_ip}` : undefined}>
              <span>Anonymous</span>
              <Pill tone="amber" title="No agent API key was sent: the caller is identified only by its IP address">
                Unverified (No Key)
              </Pill>
            </span>
          )}
        </Field>
        <Field icon={<UserCheck className="h-3 w-3" aria-hidden="true" />} label={approval.label}>
          {approval.value}
        </Field>
        <Field icon={<Lock className="h-3 w-3" aria-hidden="true" />} label="Ledger">
          {detail.sealed ? (
            <span
              className="cursor-help font-medium text-emerald-700 underline decoration-dotted underline-offset-2"
              title={detail.row_hash ? `Row hash ${detail.row_hash.slice(0, 8)}… (full hashes are in the Auditor Evidence Pack)` : undefined}
            >
              Sealed
            </span>
          ) : detail.response_pending ? (
            <span className="text-amber-700">Waiting for the response…</span>
          ) : (
            <span className="text-amber-700">Sealing…</span>
          )}
        </Field>
      </dl>

      <div className="grid min-w-0 gap-4 lg:grid-cols-2">
        <section className="min-w-0">
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
        <section className="min-w-0">
          <h4 className="mb-1.5 flex flex-wrap items-center justify-between gap-x-2 text-xs font-semibold uppercase tracking-wider text-slate-500">
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
        <section className="grid min-w-0 gap-4 lg:grid-cols-2">
          <div className="min-w-0">
            <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-slate-500">As queued</h4>
            <JsonInspector text={detail.original_payload} defaultExpandDepth={2} maxHeight="max-h-48" />
          </div>
          <div className="min-w-0">
            <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-slate-500">As edited by the approver</h4>
            <JsonInspector text={detail.modified_payload} defaultExpandDepth={2} maxHeight="max-h-48" />
          </div>
        </section>
      )}
    </div>
  )
}
