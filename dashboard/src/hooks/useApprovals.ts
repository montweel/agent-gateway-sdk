import { useCallback, useEffect, useRef, useState } from 'react'
import axios from 'axios'
import { api, errorMessage } from '../lib/api'
import type { Approval } from '../lib/types'

/** Server-side filters for the approvals list. The list is capped at `limit`; counts are not. */
export interface ApprovalsQuery {
  status: 'ALL' | 'PENDING'
  /** One action id (the #736 shown in Telegram / Slack), or null for all. */
  id: number | null
  limit: number
}

export interface ApprovalCounts {
  total: number
  pending: number
}

export const APPROVALS_PAGE = 100
const DEFAULT_QUERY: ApprovalsQuery = { status: 'ALL', id: null, limit: APPROVALS_PAGE }

export function useApprovals() {
  const [approvals, setApprovals] = useState<Approval[]>([])
  const [counts, setCounts] = useState<ApprovalCounts>({ total: 0, pending: 0 })
  const [query, setQueryState] = useState<ApprovalsQuery>(DEFAULT_QUERY)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [online, setOnline] = useState(true)
  const requestId = useRef(0)

  const reload = useCallback(
    async (silent = false) => {
      const thisRequest = ++requestId.current
      if (!silent) setLoading(true)
      try {
        const params: Record<string, string> = { limit: String(query.limit) }
        if (query.status === 'PENDING') params.status = 'PENDING'
        if (query.id !== null) params.id = String(query.id)
        const [list, totals] = await Promise.all([
          api.get<Approval[]>('/approvals', { params }),
          api.get<ApprovalCounts>('/approvals/counts'),
        ])
        if (thisRequest !== requestId.current) return // the query changed while this was in flight
        setApprovals(list.data)
        setCounts(totals.data)
        setError(null)
        setOnline(true)
      } catch (err) {
        if (thisRequest !== requestId.current) return
        setError(errorMessage(err))
        setOnline(!(axios.isAxiosError(err) && !err.response))
      } finally {
        if (!silent && thisRequest === requestId.current) setLoading(false)
      }
    },
    [query]
  )

  useEffect(() => {
    void reload()
    const id = window.setInterval(() => {
      if (!document.hidden) void reload(true)
    }, 5000)
    return () => window.clearInterval(id)
  }, [reload])

  /** Merges into the current query; changing the status or id starts again from the first page. */
  const setQuery = useCallback((patch: Partial<ApprovalsQuery>) => {
    setQueryState((prev) => {
      const next = { ...prev, ...patch }
      if ((patch.status !== undefined && patch.status !== prev.status) || (patch.id !== undefined && patch.id !== prev.id)) {
        next.limit = patch.limit ?? APPROVALS_PAGE
      }
      return next
    })
  }, [])

  return { approvals, counts, query, setQuery, loading, error, online, reload }
}
export type ApprovalsApi = ReturnType<typeof useApprovals>
