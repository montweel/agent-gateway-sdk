import type { ReactNode } from 'react'
import { BarChart3, Inbox, ScrollText, Settings, ShieldCheck, Users, Wand2 } from 'lucide-react'
import type { AuthUser, LicenseStatus, Tab } from '../lib/types'
import { MontLogo } from './MontLogo'

/** Footer badge: trial countdown, active key, or an expired warning. Every state opens the license card. */
function LicenseBadge({ license, onOpen }: { license: LicenseStatus | null; onOpen: () => void }) {
  if (!license) return <span className="text-[11px] text-slate-500">Mont</span>

  let tone = 'border-slate-700 bg-slate-800/60 text-slate-300 hover:bg-slate-800'
  let title = 'Community Edition'
  let subtitle: string | null = 'Get free 90-day key ↗'

  if (license.expired) {
    tone = 'border-amber-500/40 bg-amber-500/10 text-amber-300 hover:bg-amber-500/20'
    title = 'Pro Expired · Free 90-day key ↗'
    subtitle = null
  } else if (license.tier === 'PRO' && license.isTrial) {
    tone = 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300 hover:bg-emerald-500/20'
    title = `Pro Trial · ${license.daysRemaining ?? 0}d left`
    subtitle = 'Get free 90-day key ↗'
  } else if (license.tier === 'PRO') {
    tone = 'border-indigo-500/40 bg-indigo-500/10 text-indigo-300 hover:bg-indigo-500/20'
    title = `Mont Pro · ${license.org ?? 'Licensed'} (${license.daysRemaining ?? 0}d left)`
    subtitle = null
  }

  return (
    <button
      type="button"
      onClick={onOpen}
      className={`w-full rounded-lg border px-3 py-2 text-left transition ${tone}`}
    >
      <span className="block text-xs font-semibold">{title}</span>
      {subtitle && <span className="mt-0.5 block text-[11px] opacity-80">{subtitle}</span>}
    </button>
  )
}

export function Sidebar({
  tab,
  onChange,
  pendingCount,
  user,
  license,
  onOpenLicense,
}: {
  tab: Tab
  onChange: (t: Tab) => void
  pendingCount: number
  user: AuthUser
  license: LicenseStatus | null
  onOpenLicense: () => void
}) {
  const isAdmin = user.role === 'admin'
 
  const items: { id: Tab; label: string; icon: ReactNode; adminOnly?: boolean }[] = [
    { id: 'rules', label: 'Access Rules', icon: <ShieldCheck className="h-5 w-5" aria-hidden="true" /> },
    { id: 'approvals', label: 'Pending Approvals', icon: <Inbox className="h-5 w-5" aria-hidden="true" /> },
    { id: 'logs', label: 'Audit Logs', icon: <ScrollText className="h-5 w-5" aria-hidden="true" /> },
    { id: 'analytics', label: 'Analytics', icon: <BarChart3 className="h-5 w-5" aria-hidden="true" /> },
    { id: 'team', label: 'Team & Users', icon: <Users className="h-5 w-5" aria-hidden="true" />, adminOnly: true },
    { id: 'setup', label: 'Gateway Setup (No-Code)', icon: <Wand2 className="h-5 w-5" aria-hidden="true" /> },
    { id: 'settings', label: 'Settings & Discovery', icon: <Settings className="h-5 w-5" aria-hidden="true" /> },
  ]
 
  return (
    <aside className="flex w-64 shrink-0 flex-col bg-slate-900 text-slate-300">
      <div className="flex items-center gap-3 px-6 py-6">
        <MontLogo size={36} className="shrink-0 shadow-lg shadow-indigo-900/40" />
        <div>
          <p className="text-sm font-semibold text-white">Mont Gateway</p>
          <p className="text-xs text-slate-500">{isAdmin ? 'Admin Console' : 'Viewer Console'}</p>
        </div>
      </div>
 
      <nav className="mt-2 flex-1 space-y-1 px-3">
        <p className="px-3 pb-2 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Manage</p>
        {items
          .filter((item) => !item.adminOnly || isAdmin)
          .map((item) => {
            const active = tab === item.id
            return (
              <button
                key={item.id}
                onClick={() => onChange(item.id)}
                aria-current={active ? 'page' : undefined}
                className={`flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition ${
                  active ? 'bg-slate-800 text-white' : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'
                }`}
              >
                <span className={active ? 'text-indigo-400' : ''}>{item.icon}</span>
                <span className="flex-1 text-left">{item.label}</span>
                {item.id === 'approvals' && pendingCount > 0 && (
                  <span
                    className="inline-flex min-w-[1.5rem] items-center justify-center rounded-full bg-amber-500 px-2 py-0.5 text-xs font-bold text-slate-900"
                    aria-label={`${pendingCount} pending approvals`}
                  >
                    {pendingCount}
                  </span>
                )}
              </button>
            )
          })}
      </nav>
 
      <div className="border-t border-slate-800 px-5 py-4 text-xs text-slate-400">
        <LicenseBadge license={license} onOpen={onOpenLicense} />
      </div>
    </aside>
  )
}
 