import { useMemo, useState } from 'react'
import axios from 'axios'
import { AlertCircle, Check, X } from 'lucide-react'
import { api, errorMessage } from '../lib/api'
import type { ApprovalsApi } from '../hooks/useApprovals'
import type { Decision, DecideResponse } from '../lib/types'
import { formatTime, prettyJson, READ_ONLY_HINT } from '../lib/utils'
import {
  APPROVAL_TONES,
  Badge,
  ErrorBanner,
  MethodBadge,
  PageHeader,
  RefreshButton,
  Spinner,
  SuccessBanner,
} from '../components/ui'

const DECIDED_VERB: Record<string, string> = {
  APPROVED: 'Approved',
  REJECTED: 'Rejected',
  EXECUTING: 'Executing, approved',
  FAILED: 'Approved (failed)',
}

export function ApprovalsTab({ approvalsApi, readOnly }: { approvalsApi: ApprovalsApi; readOnly: boolean }) {
  const { approvals, loading, error, reload } = approvalsApi
  const [filter, setFilter] = useState<'ALL' | 'PENDING'>('ALL')
  const [deciding, setDeciding] = useState<Record<number, Decision | undefined>>({})
  const [cardErrors, setCardErrors] = useState<Record<number, string | undefined>>({})
  const [notice, setNotice] = useState<string | null>(null)

  const pendingCount = useMemo(() => approvals.filter((a) => a.status === 'PENDING').length, [approvals])
  const visible = filter === 'PENDING' ? approvals.filter((a) => a.status === 'PENDING') : approvals

  async function decide(id: number, decision: Decision) {
    if (readOnly) return
    setCardErrors((prev) => ({ ...prev, [id]: undefined }))
    setNotice(null)
    setDeciding((prev) => ({ ...prev, [id]: decision }))
    try {
      const res = await api.post<DecideResponse>(`/approvals/${id}/decide`, { decision })
      if (decision === 'APPROVE' || decision === 'RETRY') {
        const code =
          res.data.replayStatus !== undefined ? ` The target replied with HTTP ${res.data.replayStatus}.` : ''
        const warn = res.data.warning ? ` ${res.data.warning}` : ''
        setNotice(`Request #${id} was ${decision === 'RETRY' ? 'retried' : 'approved'} and executed.${code}${warn}`)
      } else {
        setNotice(`Request #${id} was rejected.`)
      }
    } catch (err) {
      let message = errorMessage(err)
      const status = axios.isAxiosError(err) ? err.response?.status : undefined
      if (status === 409 || status === 410) {
        message = `${message} The list has been refreshed.`
      }
      setCardErrors((prev) => ({ ...prev, [id]: message }))
    } finally {
      setDeciding((prev) => ({ ...prev, [id]: undefined }))
      await reload(true)
    }
  }

  return (
    <>
      <PageHeader
        title="Pending Approvals"
        subtitle="Requests to REQUIRE_APPROVAL endpoints wait here until an admin decides."
        action={<RefreshButton onClick={() => void reload()} loading={loading} />}
      />

      {error && <ErrorBanner message={error} />}
      {notice && <SuccessBanner message={notice} onDismiss={() => setNotice(null)} />}

      <div className="mb-4 flex gap-2">
        {(
          [
            { id: 'ALL', label: `All (${approvals.length})` },
            { id: 'PENDING', label: `Pending (${pendingCount})` },
          ] as const
        ).map((chip) => (
          <button
            key={chip.id}
            onClick={() => setFilter(chip.id)}
            aria-pressed={filter === chip.id}
            className={`rounded-full px-3.5 py-1.5 text-sm font-medium transition ${
              filter === chip.id
                ? 'bg-slate-900 text-white'
                : 'bg-white text-slate-600 ring-1 ring-inset ring-slate-200 hover:bg-slate-50'
            }`}
          >
            {chip.label}
          </button>
        ))}
      </div>

      {loading ? (
        <div className="space-y-4">
          {[0, 1].map((i) => (
            <div key={i} className="animate-pulse rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
              <div className="h-4 w-64 rounded bg-slate-200" />
              <div className="mt-4 h-20 rounded-lg bg-slate-100" />
            </div>
          ))}
        </div>
      ) : visible.length === 0 ? (
        <div className="rounded-xl border border-slate-200 bg-white px-6 py-16 text-center text-sm text-slate-500 shadow-sm">
          {filter === 'PENDING' ? 'Nothing is waiting for approval.' : 'No requests have been queued yet.'}
        </div>
      ) : (
        <div className="space-y-4">
          {visible.map((a) => {
            const isPending = a.status === 'PENDING'
            const isFailed = a.status === 'FAILED'
            const body = prettyJson(a.body)
            const action = deciding[a.id]
            const cardError = cardErrors[a.id]
            return (
              <div
                key={a.id}
                className={`rounded-xl border bg-white p-5 shadow-sm ${
                  isPending ? 'border-amber-300 ring-1 ring-amber-200/60' : 'border-slate-200'
                }`}
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="rounded-md bg-slate-100 px-2 py-0.5 font-mono text-xs font-semibold text-slate-600">
                        #{a.id}
                      </span>
                      <MethodBadge method={a.method} />
                      <span className="break-all font-mono text-sm font-medium text-slate-900">{a.path}</span>
                    </div>
                    <p className="mt-1.5 text-xs text-slate-500">
                      Queued {formatTime(a.timestamp)}
                      {a.agent_key && (
                        <span className="ml-2 font-medium text-slate-700">· from agent “{a.agent_key}”</span>
                      )}
                      {a.decided_by && (
                        <span className="ml-2 font-medium text-slate-700">
                          · {DECIDED_VERB[a.status] ?? 'Handled'} by {a.decided_by}
                        </span>
                      )}
                      {isPending && a.expires_at ? (
                        <span className="ml-2 text-slate-500">· expires {formatTime(new Date(a.expires_at).toISOString())}</span>
                      ) : null}
                    </p>
                  </div>
                  <Badge tone={APPROVAL_TONES[a.status] ?? 'slate'}>{a.status}</Badge>
                </div>

                <div className="mt-4">
                  <p className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-slate-500">Request body</p>
                  {body ? (
                    <pre className="max-h-56 overflow-auto rounded-lg bg-slate-900 p-3 font-mono text-xs leading-relaxed text-slate-100">
                      {body}
                    </pre>
                  ) : (
                    <p className="rounded-lg bg-slate-50 px-3 py-2 text-xs text-slate-500">No body</p>
                  )}
                </div>

                {a.response_preview && (
                  <div className="mt-4">
                    <p className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-slate-500">
                      Response preview
                    </p>
                    <pre
                      className={`max-h-40 overflow-auto whitespace-pre-wrap break-all rounded-lg border p-3 font-mono text-xs ${
                        isFailed
                          ? 'border-red-200 bg-red-50 text-red-900'
                          : 'border-emerald-200 bg-emerald-50 text-emerald-900'
                      }`}
                    >
                      {a.response_preview}
                    </pre>
                  </div>
                )}

                {cardError && (
                  <div
                    role="alert"
                    className="mt-4 flex items-start justify-between gap-3 rounded-lg border border-red-200 bg-red-50 px-3 py-2.5 text-sm text-red-800"
                  >
                    <span className="flex items-start gap-2">
                      <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
                      <span>{cardError}</span>
                    </span>
                    <button
                      onClick={() => setCardErrors((prev) => ({ ...prev, [a.id]: undefined }))}
                      className="shrink-0 text-red-700 hover:text-red-900"
                      aria-label="Dismiss error"
                    >
                      <X className="h-4 w-4" aria-hidden="true" />
                    </button>
                  </div>
                )}

                {isFailed && (
                  <p className="mt-4 text-xs text-slate-600">
                    The replay did not complete. The target may still have received the request, so check it before
                    retrying.
                  </p>
                )}

                {(isPending || isFailed) && readOnly && (
                  <p className="mt-4 text-xs font-medium text-amber-700">
                    Read-only mode: only admins can approve or reject requests.
                  </p>
                )}

                {(isPending || isFailed) && (
                  <div className="mt-4 flex flex-wrap gap-3">
                    <button
                      onClick={() => void decide(a.id, isFailed ? 'RETRY' : 'APPROVE')}
                      disabled={action !== undefined || readOnly}
                      title={readOnly ? READ_ONLY_HINT : undefined}
                      className="inline-flex items-center gap-2 rounded-lg bg-emerald-600 px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-emerald-500 disabled:cursor-not-allowed disabled:opacity-60"
                    >
                      {action === 'APPROVE' || action === 'RETRY' ? (
                        <Spinner />
                      ) : (
                        <Check className="h-4 w-4" aria-hidden="true" />
                      )}
                      {isFailed ? 'Retry' : 'Approve & Execute'}
                    </button>
                    <button
                      onClick={() => void decide(a.id, 'REJECT')}
                      disabled={action !== undefined || readOnly}
                      title={readOnly ? READ_ONLY_HINT : undefined}
                      className="inline-flex items-center gap-2 rounded-lg border border-red-200 bg-white px-4 py-2 text-sm font-semibold text-red-600 shadow-sm transition hover:bg-red-50 disabled:cursor-not-allowed disabled:opacity-60"
                    >
                      {action === 'REJECT' ? <Spinner /> : <X className="h-4 w-4" aria-hidden="true" />}
                      Reject
                    </button>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </>
  )
}
