import { useCallback, useEffect, useState } from 'react'
import { api, getWorkspace, setWorkspace, WORKSPACE_CHANGED_EVENT } from '../lib/api'
import type { WorkspacesResponse } from '../lib/types'

/** The installation-wide workspace list, or null when it cannot be read. Never throws. */
async function fetchWorkspaces(): Promise<WorkspacesResponse | null> {
  try {
    // The list is installation-wide: never scoped to the selected workspace.
    return (await api.get<WorkspacesResponse>('/workspaces', { headers: { 'x-mont-workspace': 'all' } })).data
  } catch {
    return null // keep the last list
  }
}

/** Keeps the list of workspaces fresh and the current selection valid. */
export function useWorkspaces() {
  const [data, setData] = useState<WorkspacesResponse | null>(null)
  const [selected, setSelected] = useState<string>(getWorkspace())

  const show = useCallback((list: WorkspacesResponse | null) => {
    if (!list) return
    setData(list)
    // The selected workspace was deleted (or renamed): fall back to the default one.
    const current = getWorkspace()
    if (current !== 'all' && !list.workspaces.some((w) => w.slug === current)) setWorkspace('default')
  }, [])

  /** After creating / editing / deleting a workspace. */
  const reload = useCallback(async () => {
    show(await fetchWorkspaces())
  }, [show])

  useEffect(() => {
    let live = true
    const refresh = () =>
      void fetchWorkspaces().then((list) => {
        if (live) show(list)
      })
    refresh()
    const onChange = () => setSelected(getWorkspace())
    window.addEventListener(WORKSPACE_CHANGED_EVENT, onChange)
    const id = window.setInterval(() => {
      if (!document.hidden) refresh()
    }, 15000)
    return () => {
      live = false
      window.removeEventListener(WORKSPACE_CHANGED_EVENT, onChange)
      window.clearInterval(id)
    }
  }, [show])

  return { data, selected, reload }
}
export type WorkspacesApi = ReturnType<typeof useWorkspaces>
