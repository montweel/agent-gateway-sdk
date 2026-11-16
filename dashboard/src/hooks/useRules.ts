import { useCallback, useEffect, useState } from 'react'
import { api, errorMessage } from '../lib/api'
import type { Rules } from '../lib/types'

type RulesResult = { rules: Rules } | { error: string }

/** GET /rules. Never throws. */
async function fetchRules(): Promise<RulesResult> {
  try {
    return { rules: (await api.get<Rules>('/rules')).data }
  } catch (err) {
    return { error: errorMessage(err) }
  }
}

export function useRules() {
  const [rules, setRules] = useState<Rules>({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const show = useCallback((r: RulesResult) => {
    if ('rules' in r) {
      setRules(r.rules)
      setError(null)
    } else setError(r.error)
    setLoading(false)
  }, [])

  /** Refresh (buttons, after saves): shows the spinner, then the answer. */
  const reload = useCallback(async () => {
    setLoading(true)
    show(await fetchRules())
  }, [show])

  // First load: "loading" already starts true, so only the answer is set.
  useEffect(() => {
    let live = true
    void fetchRules().then((r) => {
      if (live) show(r)
    })
    return () => {
      live = false
    }
  }, [show])

  return { rules, setRules, loading, error, setError, reload }
}
export type RulesApi = ReturnType<typeof useRules>
