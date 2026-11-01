import { useCallback, useMemo, useState } from 'react'
import { useApprovals } from '../hooks/useApprovals'
import { useLicense } from '../hooks/useLicense'
import { useRules } from '../hooks/useRules'
import type { AuthUser, LicenseStatus, Tab } from '../lib/types'
import { Sidebar } from '../components/Sidebar'
import { TopBar } from '../components/TopBar'
import { ChangePasswordModal } from '../components/ChangePasswordModal'
import { RulesTab } from '../tabs/RulesTab'
import { ApprovalsTab } from '../tabs/ApprovalsTab'
import { LogsTab } from '../tabs/LogsTab'
import { AnalyticsTab } from '../tabs/AnalyticsTab'
import { TeamTab } from '../tabs/TeamTab'
import { SettingsTab } from '../tabs/SettingsTab'
 
function ViewerBanner() {
  return (
    <div
      role="status"
      className="sticky top-14 z-10 border-b border-amber-200 bg-amber-50/95 text-sm text-amber-900 backdrop-blur"
    >
      <div className="mx-auto max-w-5xl px-10 py-2.5">
        👁️ Viewer Mode (Read-Only): You can inspect audit logs and active rules, but modifications and approvals are
        disabled.
      </div>
    </div>
  )
}
 
function LicenseExpiredBanner({ license, onOpen }: { license: LicenseStatus; onOpen: () => void }) {
  return (
    <div role="status" className="border-b border-amber-200 bg-amber-50 text-sm text-amber-900">
      <div className="mx-auto max-w-5xl px-10 py-2.5">
        Activate your free 90-day Team Pro trial key at{' '}
        <a
          href={license.renewalUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="font-semibold underline hover:text-amber-700"
        >
          montweel.com/#license-renewal ↗
        </a>{' '}
        — no credit card or payment required. You can also{' '}
        <button type="button" onClick={onOpen} className="font-semibold underline hover:text-amber-700">
          paste your key in Settings
        </button>
        .
      </div>
    </div>
  )
}

export function Dashboard({ user, onSignOut }: { user: AuthUser; onSignOut: () => void }) {
  const readOnly = user.role !== 'admin'
  const [tab, setTab] = useState<Tab>('rules')
  const licenseApi = useLicense()
  const openLicense = useCallback(() => setTab('settings'), [])
  const [showPasswordModal, setShowPasswordModal] = useState(false)
  const rulesApi = useRules()
  const approvalsApi = useApprovals()
 
  const closePasswordModal = useCallback(() => setShowPasswordModal(false), [])
 
  const pendingCount = useMemo(
    () => approvalsApi.approvals.filter((a) => a.status === 'PENDING').length,
    [approvalsApi.approvals]
  )
 
  return (
    <div className="flex h-screen bg-slate-100 font-sans text-slate-900">
      <Sidebar
        tab={tab}
        onChange={setTab}
        pendingCount={pendingCount}
        user={user}
        license={licenseApi.license}
        onOpenLicense={openLicense}
      />
      <main className="flex-1 overflow-y-auto">
        <TopBar
          user={user}
          online={approvalsApi.online}
          onSignOut={onSignOut}
          onOpenPasswordModal={() => setShowPasswordModal(true)}
        />
        {licenseApi.license?.expired && <LicenseExpiredBanner license={licenseApi.license} onOpen={openLicense} />}
        {readOnly && <ViewerBanner />}
        <div className="mx-auto max-w-5xl px-10 py-8">
          {tab === 'rules' && <RulesTab rulesApi={rulesApi} readOnly={readOnly} />}
          {tab === 'approvals' && <ApprovalsTab approvalsApi={approvalsApi} readOnly={readOnly} />}
          {tab === 'logs' && <LogsTab rulesApi={rulesApi} readOnly={readOnly} />}
          {tab === 'analytics' && <AnalyticsTab isPro={licenseApi.isPro} onOpenLicense={openLicense} />}
          {tab === 'team' && !readOnly && <TeamTab currentUser={user} />}
          {tab === 'settings' && <SettingsTab readOnly={readOnly} licenseApi={licenseApi} />}
        </div>
      </main>
      {showPasswordModal && <ChangePasswordModal onClose={closePasswordModal} />}
    </div>
  )
}