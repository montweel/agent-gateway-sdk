import { useCallback, useEffect, useState } from 'react'
import axios from 'axios'
import { api, errorMessage } from '../lib/api'
import type { Approval } from '../lib/types'
 
export function useApprovals() {
  const [approvals, setApprovals] = useState<Approval[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [online, setOnline] = useState(true)
 
  const reload = useCallback(async (silent = false) => {
    if (!silent) setLoading(true)
    try {
      const res = await api.get<Approval[]>('/approvals')
      setApprovals(res.data)
      setError(null)
      setOnline(true)
    } catch (err) {
      setError(errorMessage(err))
      setOnline(!(axios.isAxiosError(err) && !err.response))
    } finally {
      if (!silent) setLoading(false)
    }
  }, [])
 
  useEffect(() => {
    void reload()
    const id = window.setInterval(() => {
      if (!document.hidden) void reload(true)
    }, 5000)
    return () => window.clearInterval(id)
  }, [reload])
 
  return { approvals, loading, error, online, reload }
}
export type ApprovalsApi = ReturnType<typeof useApprovals>
 