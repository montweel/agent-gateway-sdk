import { useCallback, useEffect, useState } from 'react'
import { useApprovals } from '../hooks/useApprovals'
import { useLicense } from '../hooks/useLicense'
import { useRules } from '../hooks/useRules'
import type { AuthUser, LicenseStatus, Tab } from '../lib/types'
import { getWorkspace, WORKSPACE_CHANGED_EVENT } from '../lib/api'
import { ruleKey } from '../lib/utils'
import { Sidebar } from '../components/Sidebar'
import { TopBar } from '../components/TopBar'
import { ChangePasswordModal } from '../components/ChangePasswordModal'
import { RulesTab } from '../tabs/RulesTab'
import { ApprovalsTab } from '../tabs/ApprovalsTab'
import { LogsTab } from '../tabs/LogsTab'
import type { LogsFilter } from '../tabs/LogsTab'
import { AnalyticsTab } from '../tabs/AnalyticsTab'
import { TeamTab } from '../tabs/TeamTab'
import { SettingsTab } from '../tabs/SettingsTab'
import { SetupTab } from '../tabs/SetupTab'
import { EmergencyBar } from '../components/EmergencyBar'
import { useWorkspaces, WorkspaceSwitcher } from '../components/WorkspaceSwitcher'
import { AllClientsOverview } from './AllClientsOverview'

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

// Tabs whose content belongs to one workspace; "All Clients" shows the overview there instead.
const SCOPED_TABS: Tab[] = ['rules', 'approvals', 'logs', 'analytics']

export function Dashboard({ user, onSignOut }: { user: AuthUser; onSignOut: () => void }) {
  const readOnly = user.role !== 'admin'
  const [tab, setTabState] = useState<Tab>('rules')
  // Rule key to open in the payload rules editor when jumping there from the rules list or
  // the audit log. A key with no rule yet starts a new rule pre-filled with its method + path.
  const [policyFocus, setPolicyFocus] = useState<string | null>(null)
  // Filters to open the Audit Logs with (from Analytics). Cleared by ordinary tab navigation.
  const [logsFilter, setLogsFilter] = useState<LogsFilter | null>(null)
  const setTab = useCallback((next: Tab) => {
    setPolicyFocus(null)
    setLogsFilter(null)
    setTabState(next)
  }, [])
  const openLogs = useCallback((filter: LogsFilter, withinMs?: number) => {
    setPolicyFocus(null)
    // A relative window ("the last 24h") becomes a fixed start time at the moment of the click.
    setLogsFilter(withinMs ? { ...filter, from: new Date(Date.now() - withinMs).toISOString() } : filter)
    setTabState('logs')
  }, [])
  const openPayloadEditor = useCallback((key: string) => {
    setPolicyFocus(key)
    setTabState('setup')
  }, [])
  const licenseApi = useLicense()
  const openLicense = useCallback(() => setTab('settings'), [setTab])
  const [showPasswordModal, setShowPasswordModal] = useState(false)
  const rulesApi = useRules()
  const approvalsApi = useApprovals()
  const workspacesApi = useWorkspaces()
  const [workspace, setWorkspaceState] = useState(getWorkspace())

  // Switching client reloads everything that is scoped to a workspace.
  const { reload: reloadRules } = rulesApi
  const { reload: reloadApprovals } = approvalsApi
  useEffect(() => {
    const onChange = () => {
      setWorkspaceState(getWorkspace())
      void reloadRules()
      void reloadApprovals()
    }
    window.addEventListener(WORKSPACE_CHANGED_EVENT, onChange)
    return () => window.removeEventListener(WORKSPACE_CHANGED_EVENT, onChange)
  }, [reloadRules, reloadApprovals])

  const closePasswordModal = useCallback(() => setShowPasswordModal(false), [])

  // The real COUNT(*) from the server; the approvals list itself is capped.
  const pendingCount = approvalsApi.counts.pending

  // "Edit Rule" from Analytics: open the rule that actually governs this method + path when one is
  // keyed on it (method-specific first, then the any-method rule); otherwise start a new rule
  // pre-filled with it. Wildcard rules are not opened, so editing never widens or narrows a pattern
  // that covers other endpoints by surprise.
  const { rules } = rulesApi
  const openRuleFor = useCallback(
    (method: string, path: string) => {
      const exact = ruleKey(method, path)
      const own = (k: string) => Object.prototype.hasOwnProperty.call(rules, k)
      openPayloadEditor(own(exact) ? exact : method !== 'MCP' && own(path) ? path : exact)
    },
    [rules, openPayloadEditor]
  )

  const { setQuery: setApprovalsQuery } = approvalsApi
  const openApproval = useCallback(
    (id: number) => {
      setApprovalsQuery({ status: 'ALL', id })
      setTab('approvals')
    },
    [setApprovalsQuery, setTab]
  )

  const multiWorkspace = (workspacesApi.data?.workspaces.length ?? 0) > 1
  const showOverview = multiWorkspace && workspace === 'all' && SCOPED_TABS.includes(tab)

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
          workspaceSlot={<WorkspaceSwitcher workspacesApi={workspacesApi} />}
        />
        <EmergencyBar key={`emergency-${workspace}`} readOnly={readOnly} workspace={workspace} multiWorkspace={multiWorkspace} />
        {licenseApi.license?.expired && <LicenseExpiredBanner license={licenseApi.license} onOpen={openLicense} />}
        {readOnly && <ViewerBanner />}
        <div className="mx-auto max-w-5xl px-10 py-8" key={`content-${workspace}`}>
          {showOverview ? (
            <AllClientsOverview />
          ) : (
            <>
              {tab === 'rules' && <RulesTab rulesApi={rulesApi} readOnly={readOnly} onEditPayload={openPayloadEditor} />}
              {tab === 'approvals' && <ApprovalsTab approvalsApi={approvalsApi} readOnly={readOnly} />}
              {tab === 'logs' && (
                <LogsTab
                  key={JSON.stringify(logsFilter)}
                  rulesApi={rulesApi}
                  readOnly={readOnly}
                  initialFilter={logsFilter}
                  onCreateRule={(method, path) => openPayloadEditor(ruleKey(method, path))}
                  onOpenApproval={openApproval}
                />
              )}
              {tab === 'analytics' && (
                <AnalyticsTab isPro={licenseApi.isPro} onOpenLicense={openLicense} onViewLogs={openLogs} onEditRule={openRuleFor} readOnly={readOnly} />
              )}
              {tab === 'team' && !readOnly && <TeamTab currentUser={user} />}
              {tab === 'setup' && (
                <SetupTab
                  rulesApi={rulesApi}
                  readOnly={readOnly}
                  licenseApi={licenseApi}
                  workspacesApi={workspacesApi}
                  focusRuleKey={policyFocus}
                />
              )}
              {tab === 'settings' && <SettingsTab readOnly={readOnly} licenseApi={licenseApi} />}
            </>
          )}
        </div>
      </main>
      {showPasswordModal && <ChangePasswordModal onClose={closePasswordModal} />}
    </div>
  )
}
