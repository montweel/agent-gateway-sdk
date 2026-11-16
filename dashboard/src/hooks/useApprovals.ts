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

type ApprovalsResult = { approvals: Approval[]; counts: ApprovalCounts } | { error: string; online: boolean }

/** The list for `query` plus the overall counts. Never throws. */
async function fetchApprovals(query: ApprovalsQuery): Promise<ApprovalsResult> {
  try {
    const params: Record<string, string> = { limit: String(query.limit) }
    if (query.status === 'PENDING') params.status = 'PENDING'
    if (query.id !== null) params.id = String(query.id)
    const [list, totals] = await Promise.all([api.get<Approval[]>('/approvals', { params }), api.get<ApprovalCounts>('/approvals/counts')])
    return { approvals: list.data, counts: totals.data }
  } catch (err) {
    return { error: errorMessage(err), online: !(axios.isAxiosError(err) && !err.response) }
  }
}

export function useApprovals() {
  const [approvals, setApprovals] = useState<Approval[]>([])
  const [counts, setCounts] = useState<ApprovalCounts>({ total: 0, pending: 0 })
  const [query, setQueryState] = useState<ApprovalsQuery>(DEFAULT_QUERY)
  const [error, setError] = useState<string | null>(null)
  const [online, setOnline] = useState(true)
  const requestId = useRef(0)

  // "Loading" = the list on screen is not for the current query yet, or a manual refresh runs.
  // Derived, so the fetch effect below only sets state once a request has settled.
  const queryKey = JSON.stringify(query)
  const [loadedKey, setLoadedKey] = useState<string | null>(null)
  const [refreshing, setRefreshing] = useState(false)
  const loading = loadedKey !== queryKey || refreshing

  /** Applies a response, unless a newer request has started since (the query changed). */
  const show = useCallback((thisRequest: number, key: string, r: ApprovalsResult) => {
    if (thisRequest !== requestId.current) return
    if ('approvals' in r) {
      setApprovals(r.approvals)
      setCounts(r.counts)
      setError(null)
      setOnline(true)
    } else {
      setError(r.error)
      setOnline(r.online)
    }
    setLoadedKey(key)
  }, [])

  /** Refresh after an action. `silent` keeps the list on screen instead of showing the spinner. */
  const reload = useCallback(
    async (silent = false) => {
      const thisRequest = ++requestId.current
      if (!silent) setRefreshing(true)
      try {
        show(thisRequest, queryKey, await fetchApprovals(query))
      } finally {
        if (!silent) setRefreshing(false)
      }
    },
    [query, queryKey, show]
  )

  useEffect(() => {
    let live = true // false once the query changed: drop anything still in flight for the old one
    const run = () => {
      const thisRequest = ++requestId.current
      void fetchApprovals(query).then((r) => {
        if (live) show(thisRequest, queryKey, r)
      })
    }
    run()
    const id = window.setInterval(() => {
      if (!document.hidden) run()
    }, 5000)
    return () => {
      live = false
      window.clearInterval(id)
    }
  }, [query, queryKey, show])

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
