import { useEffect, useRef, useState } from 'react'
import { ChevronDown, KeyRound, Lock, LogOut } from 'lucide-react'
import type { AuthUser } from '../lib/types'

export function TopBar({
  user,
  online,
  onSignOut,
  onOpenPasswordModal,
}: {
  user: AuthUser
  online: boolean
  onSignOut: () => void
  onOpenPasswordModal: () => void
}) {
  const [open, setOpen] = useState(false)
  const menuRef = useRef<HTMLDivElement>(null)
  const isAdmin = user.role === 'admin'
  const canChangeOwnPassword = user.id > 0 && !user.sso

  // Close on outside click or Escape while the menu is open.
  useEffect(() => {
    if (!open) return
    const onPointerDown = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) setOpen(false)
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', onPointerDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onPointerDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  const itemClass =
    'flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-left text-sm font-medium transition'

  return (
    <header className="sticky top-0 z-20 flex h-14 items-center justify-between border-b border-slate-200 bg-white/90 px-8 backdrop-blur-xs">
      <div className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-xs font-medium text-slate-600">
        <span className={`h-2 w-2 shrink-0 rounded-full ${online ? 'bg-emerald-500' : 'bg-red-500'}`} />
        <span className="font-mono">
          {window.location.host}
          {online ? '' : ' (offline)'}
        </span>
      </div>

      <div className="relative" ref={menuRef}>
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          aria-haspopup="menu"
          aria-expanded={open}
          className="flex items-center gap-2.5 rounded-lg px-2 py-1.5 transition hover:bg-slate-100"
        >
          <span className="flex h-8 w-8 items-center justify-center rounded-full bg-indigo-600 text-sm font-semibold text-white">
            {user.username.charAt(0).toUpperCase()}
          </span>
          <span className="max-w-[10rem] truncate text-sm font-medium text-slate-800" title={user.username}>
            {user.username}
          </span>
          <span
            className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-semibold ring-1 ring-inset ${
              isAdmin ? 'bg-indigo-50 text-indigo-700 ring-indigo-600/20' : 'bg-slate-50 text-slate-700 ring-slate-600/20'
            }`}
          >
            {!isAdmin && <Lock className="h-2.5 w-2.5" aria-hidden="true" />}
            {isAdmin ? 'Admin' : 'Viewer'}
          </span>
          <ChevronDown
            className={`h-4 w-4 text-slate-400 transition-transform ${open ? 'rotate-180' : ''}`}
            aria-hidden="true"
          />
        </button>

        {open && (
          <div
            role="menu"
            className="absolute right-0 top-full z-50 mt-2 w-56 rounded-xl border border-slate-200 bg-white p-1.5 shadow-lg"
          >
            <div className="px-3 py-2">
              <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Signed in as</p>
              <p className="mt-0.5 truncate text-sm font-semibold text-slate-900" title={user.username}>
                {user.username}
              </p>
              <p className="mt-0.5 text-xs text-slate-500">{user.sso ? 'Enterprise SSO' : 'Local Auth'}</p>
            </div>
            {(canChangeOwnPassword || !user.sso) && <div className="my-1 border-t border-slate-100" />}
            {canChangeOwnPassword && (
              <button
                type="button"
                role="menuitem"
                onClick={() => {
                  setOpen(false)
                  onOpenPasswordModal()
                }}
                className={`${itemClass} text-slate-700 hover:bg-slate-50`}
              >
                <KeyRound className="h-4 w-4 text-slate-400" aria-hidden="true" />
                Change password
              </button>
            )}
            {!user.sso && (
              <button
                type="button"
                role="menuitem"
                onClick={() => {
                  setOpen(false)
                  onSignOut()
                }}
                className={`${itemClass} text-rose-600 hover:bg-rose-50`}
              >
                <LogOut className="h-4 w-4" aria-hidden="true" />
                Sign out
              </button>
            )}
          </div>
        )}
      </div>
    </header>
  )
}
