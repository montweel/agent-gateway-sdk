import { useCallback, useEffect, useState } from 'react'
import { api, errorMessage } from '../lib/api'
import type { Rules } from '../lib/types'
 
export function useRules() {
  const [rules, setRules] = useState<Rules>({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
 
  const reload = useCallback(async () => {
    setLoading(true)
    try {
      const res = await api.get<Rules>('/rules')
      setRules(res.data)
      setError(null)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setLoading(false)
    }
  }, [])
 
  useEffect(() => {
    void reload()
  }, [reload])
 
  return { rules, setRules, loading, error, setError, reload }
}
export type RulesApi = ReturnType<typeof useRules>
 