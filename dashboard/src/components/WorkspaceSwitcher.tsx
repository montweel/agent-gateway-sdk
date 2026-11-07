import { useCallback, useEffect, useRef, useState } from 'react'
import { Building2, Check, ChevronDown, LayoutGrid, Lock } from 'lucide-react'
import { api, getWorkspace, setWorkspace, WORKSPACE_CHANGED_EVENT } from '../lib/api'
import type { Workspace, WorkspacesResponse } from '../lib/types'

const MODE_DOT: Record<string, string> = { normal: 'bg-emerald-500', approval_only: 'bg-amber-500', lockdown: 'bg-red-500' }

/** Keeps the list of workspaces fresh and the current selection valid. */
export function useWorkspaces() {
  const [data, setData] = useState<WorkspacesResponse | null>(null)
  const [selected, setSelected] = useState<string>(getWorkspace())

  const reload = useCallback(async () => {
    try {
      // The list is installation-wide: never scoped to the selected workspace.
      const res = await api.get<WorkspacesResponse>('/workspaces', { headers: { 'x-mont-workspace': 'all' } })
      setData(res.data)
      const current = getWorkspace()
      if (current !== 'all' && !res.data.workspaces.some((w) => w.slug === current)) setWorkspace('default')
    } catch {
      // keep the last list
    }
  }, [])

  useEffect(() => {
    void reload()
    const onChange = () => setSelected(getWorkspace())
    window.addEventListener(WORKSPACE_CHANGED_EVENT, onChange)
    const id = window.setInterval(() => {
      if (!document.hidden) void reload()
    }, 15000)
    return () => {
      window.removeEventListener(WORKSPACE_CHANGED_EVENT, onChange)
      window.clearInterval(id)
    }
  }, [reload])

  return { data, selected, reload }
}
export type WorkspacesApi = ReturnType<typeof useWorkspaces>

/**
 * Top-bar dropdown: switch between client workspaces, or open the "All Clients Overview".
 * Everything below the top bar (rules, approvals, logs, analytics, the emergency switch) follows it.
 */
export function WorkspaceSwitcher({ workspacesApi }: { workspacesApi: WorkspacesApi }) {
  const { data, selected } = workspacesApi
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false)
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  const workspaces = data?.workspaces ?? []
  // Single-store installs never see the switcher: nothing changes for them.
  if (workspaces.length <= 1) return null
  const current: Workspace | undefined = workspaces.find((w) => w.slug === selected)
  const label = selected === 'all' ? 'All Clients Overview' : (current?.name ?? selected)

  function pick(slug: string) {
    setOpen(false)
    setWorkspace(slug)
  }

  return (
    <div className="relative" ref={ref}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="listbox"
        aria-expanded={open}
        className="inline-flex max-w-[18rem] items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm font-medium text-slate-800 shadow-sm transition hover:bg-slate-50"
      >
        {selected === 'all' ? <LayoutGrid className="h-4 w-4 text-indigo-600" aria-hidden="true" /> : <Building2 className="h-4 w-4 text-indigo-600" aria-hidden="true" />}
        <span className="truncate">{label}</span>
        {current && current.effectiveMode !== 'normal' && <span className={`h-2 w-2 shrink-0 rounded-full ${MODE_DOT[current.effectiveMode]}`} />}
        <ChevronDown className={`h-4 w-4 shrink-0 text-slate-400 transition-transform ${open ? 'rotate-180' : ''}`} aria-hidden="true" />
      </button>
      {open && (
        <div role="listbox" className="absolute left-0 top-full z-50 mt-2 max-h-96 w-72 overflow-auto rounded-xl border border-slate-200 bg-white p-1.5 shadow-lg">
          <button
            type="button"
            role="option"
            aria-selected={selected === 'all'}
            onClick={() => pick('all')}
            className="flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-left text-sm font-semibold text-slate-800 hover:bg-slate-50"
          >
            <LayoutGrid className="h-4 w-4 text-indigo-600" aria-hidden="true" />
            <span className="flex-1">All Clients Overview</span>
            {selected === 'all' && <Check className="h-4 w-4 text-indigo-600" aria-hidden="true" />}
          </button>
          <div className="my-1 border-t border-slate-100" />
          {workspaces.map((w) => (
            <button
              key={w.slug}
              type="button"
              role="option"
              aria-selected={selected === w.slug}
              onClick={() => pick(w.slug)}
              className="flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-left text-sm text-slate-700 hover:bg-slate-50"
            >
              <span className={`h-2 w-2 shrink-0 rounded-full ${MODE_DOT[w.effectiveMode] ?? 'bg-slate-300'}`} title={`Mode: ${w.effectiveMode}`} />
              <span className="min-w-0 flex-1">
                <span className="block truncate font-medium">{w.name}</span>
                <span className="block truncate font-mono text-[11px] text-slate-400">{w.isDefault ? 'default · rules.json' : w.slug}</span>
              </span>
              {!w.entitled && <Lock className="h-3.5 w-3.5 text-amber-600" aria-label="Beyond the license limit" />}
              {selected === w.slug && <Check className="h-4 w-4 text-indigo-600" aria-hidden="true" />}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
