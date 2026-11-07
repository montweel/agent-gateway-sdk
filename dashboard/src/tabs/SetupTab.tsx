import { useCallback, useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { BellRing, Clock, EyeOff, Package, Plus, Send, Server, ShieldOff, SlidersHorizontal, Trash2, Undo2, Wand2 } from 'lucide-react'
import { api, errorMessage } from '../lib/api'
import type { RulesApi } from '../hooks/useRules'
import type {
  ApplyPresetResponse,
  BlockedCaller,
  BudgetSpec,
  DedupeSpec,
  BridgeStatus,
  GatewaySettings,
  PolicyPreset,
  Mode,
  NotifyResult,
  PolicyCondition,
  PolicyOperator,
  PolicyTier,
  Rule,
  Rules,
  SetupResponse,
} from '../lib/types'
import { formatTime, INPUT_CLASS, MODE_META, MODE_ORDER, READ_ONLY_HINT, RULE_METHOD_OPTIONS, ruleKey, splitRuleKey } from '../lib/utils'
import { Badge, ErrorBanner, PageHeader, RefreshButton, Spinner, SuccessBanner, WarningBanner } from '../components/ui'

// =====================================================================
// Policy draft <-> server conversion
// =====================================================================
const OPERATORS: { op: PolicyOperator; label: string }[] = [
  { op: '<=', label: '≤ at most' },
  { op: '<', label: '< less than' },
  { op: '>=', label: '≥ at least' },
  { op: '>', label: '> more than' },
  { op: '===', label: '= equals' },
  { op: '!==', label: '≠ not equal' },
  { op: 'contains', label: 'contains' },
  { op: 'in', label: 'is one of' },
  { op: 'regex', label: 'matches regex' },
  { op: 'exists', label: 'exists' },
]
const NUMERIC_OPS: PolicyOperator[] = ['<', '<=', '>', '>=']

const COMMON_TIMEZONES = [
  'UTC',
  'America/New_York',
  'America/Chicago',
  'America/Denver',
  'America/Los_Angeles',
  'America/Toronto',
  'America/Sao_Paulo',
  'Europe/London',
  'Europe/Berlin',
  'Europe/Paris',
  'Europe/Madrid',
  'Africa/Lagos',
  'Asia/Dubai',
  'Asia/Kolkata',
  'Asia/Singapore',
  'Asia/Tokyo',
  'Australia/Sydney',
]

interface DraftCondition {
  field: string
  op: PolicyOperator
  value: string
  caseInsensitive: boolean
}
interface DraftTier {
  name: string
  mode: Mode
  when: DraftCondition[]
}

/** "250" -> 250, "true" -> true, "null" -> null, "\"250\"" -> "250", anything else -> the text. */
function parseScalar(text: string): string | number | boolean | null {
  const t = text.trim()
  if (/^".*"$/.test(t)) return t.slice(1, -1)
  if (t === 'true') return true
  if (t === 'false') return false
  if (t === 'null') return null
  if (/^-?\d+(\.\d+)?$/.test(t)) return Number(t)
  return t
}

function formatScalar(v: unknown): string {
  if (typeof v === 'string') return /^(-?\d+(\.\d+)?|true|false|null)$/.test(v) ? `"${v}"` : v
  return String(v)
}

function toDraft(t: PolicyTier): DraftTier {
  return {
    name: t.name ?? '',
    mode: t.mode,
    when: t.when.map((c) => ({
      field: c.field,
      op: c.op,
      value: c.op === 'in' && Array.isArray(c.value) ? c.value.map(formatScalar).join(', ') : c.value === undefined ? '' : formatScalar(c.value),
      caseInsensitive: c.flags === 'i',
    })),
  }
}

function fromDraft(d: DraftTier, index: number): { tier?: PolicyTier; error?: string } {
  const when: PolicyCondition[] = []
  for (const [j, c] of d.when.entries()) {
    const where = `Tier ${index + 1}, condition ${j + 1}`
    if (!/^(body|query|headers)\.[^.]/.test(c.field.trim())) return { error: `${where}: the field must start with body., query. or headers.` }
    const cond: PolicyCondition = { field: c.field.trim(), op: c.op }
    if (NUMERIC_OPS.includes(c.op)) {
      const n = Number(c.value)
      if (c.value.trim() === '' || !Number.isFinite(n)) return { error: `${where}: "${c.op}" needs a number.` }
      cond.value = n
    } else if (c.op === 'in') {
      const items = c.value.split(',').map((s) => s.trim()).filter(Boolean)
      if (items.length === 0) return { error: `${where}: list at least one value, separated by commas.` }
      cond.value = items.map(parseScalar)
    } else if (c.op === 'exists') {
      cond.value = c.value.trim() !== 'false'
    } else if (c.op === 'regex') {
      if (!c.value) return { error: `${where}: enter a regular expression.` }
      cond.value = c.value
      if (c.caseInsensitive) cond.flags = 'i'
    } else if (c.op === 'contains') {
      if (!c.value.trim()) return { error: `${where}: enter the text to look for.` }
      cond.value = parseScalar(c.value)
    } else {
      cond.value = parseScalar(c.value)
    }
    when.push(cond)
  }
  if (when.length === 0) return { error: `Tier ${index + 1} needs at least one condition.` }
  const tier: PolicyTier = { mode: d.mode, when }
  if (d.name.trim()) tier.name = d.name.trim()
  return { tier }
}

const REFUND_TEMPLATE: DraftTier[] = [
  { name: 'small refund', mode: 'ALLOW', when: [{ field: 'body.amount', op: '<=', value: '100', caseInsensitive: false }] },
  {
    name: 'needs a human',
    mode: 'REQUIRE_APPROVAL',
    when: [
      { field: 'body.amount', op: '>', value: '100', caseInsensitive: false },
      { field: 'body.amount', op: '<=', value: '1000', caseInsensitive: false },
    ],
  },
  { name: 'too large', mode: 'BLOCK', when: [{ field: 'body.amount', op: '>', value: '1000', caseInsensitive: false }] },
]

// =====================================================================
// Small building blocks
// =====================================================================
function Section({ icon, step, title, subtitle, children }: { icon: ReactNode; step: string; title: string; subtitle: string; children: ReactNode }) {
  return (
    <section className="mb-6 rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
      <div className="mb-4 flex items-start gap-3">
        <span className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-indigo-50 text-indigo-600">{icon}</span>
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-wider text-indigo-600">{step}</p>
          <h2 className="text-base font-semibold text-slate-900">{title}</h2>
          <p className="text-sm text-slate-500">{subtitle}</p>
        </div>
      </div>
      {children}
    </section>
  )
}

function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1 block text-xs font-medium text-slate-600">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-slate-500">{hint}</span>}
    </label>
  )
}

function Toggle({ checked, onChange, disabled, label }: { checked: boolean; onChange: (v: boolean) => void; disabled?: boolean; label: string }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition disabled:cursor-not-allowed disabled:opacity-60 ${checked ? 'bg-emerald-500' : 'bg-slate-300'}`}
    >
      <span className={`inline-block h-5 w-5 transform rounded-full bg-white shadow transition ${checked ? 'translate-x-5' : 'translate-x-0.5'}`} />
    </button>
  )
}

function ModeSelect({ value, onChange, disabled }: { value: Mode; onChange: (m: Mode) => void; disabled?: boolean }) {
  return (
    <select value={value} onChange={(e) => onChange(e.target.value as Mode)} disabled={disabled} className={INPUT_CLASS}>
      {MODE_ORDER.map((m) => (
        <option key={m} value={m}>
          {m === 'REQUIRE_APPROVAL' ? 'Require approval' : MODE_META[m].label}
        </option>
      ))}
    </select>
  )
}

const PRIMARY_BTN =
  'inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-60'
const SECONDARY_BTN =
  'inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-slate-700 shadow-sm transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-60'

// =====================================================================
// The tab
// =====================================================================
export function SetupTab({ rulesApi, readOnly }: { rulesApi: RulesApi; readOnly: boolean }) {
  const { rules, setRules, reload: reloadRules } = rulesApi
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [warnings, setWarnings] = useState<string[]>([])
  const [gatewayPort, setGatewayPort] = useState<number | null>(null)

  // Step 1
  const [targetUrl, setTargetUrl] = useState('')
  const [listenPort, setListenPort] = useState('')
  const [rateLimit, setRateLimit] = useState('60')
  const [savingGateway, setSavingGateway] = useState(false)

  // Step 3 + 4
  const [settings, setSettings] = useState<GatewaySettings | null>(null)
  const [savingNotify, setSavingNotify] = useState(false)
  const [testing, setTesting] = useState(false)
  const [testResults, setTestResults] = useState<NotifyResult[] | null>(null)
  const [savingRollback, setSavingRollback] = useState(false)

  // Blocked callers
  const [blocked, setBlocked] = useState<BlockedCaller[]>([])
  const [unblocking, setUnblocking] = useState<number | null>(null)

  // Bridges, privacy
  const [bridges, setBridges] = useState<SetupResponse['bridges']>(undefined)
  const [savingPrivacy, setSavingPrivacy] = useState(false)
  const [savingHours, setSavingHours] = useState(false)
  const [sendingDigest, setSendingDigest] = useState(false)
  const [withinHours, setWithinHours] = useState<boolean | undefined>(undefined)

  const apply = useCallback((data: SetupResponse) => {
    setTargetUrl(data.gateway.targetUrl)
    setRateLimit(String(data.gateway.rateLimitPerMinute))
    setListenPort(data.settings.listenPort === null ? '' : String(data.settings.listenPort))
    setGatewayPort(data.gateway.gatewayPort)
    setSettings(data.settings)
    setBridges(data.bridges)
    setWithinHours(data.withinBusinessHours)
  }, [])

  // Keep the Telegram / Slack connection badges live.
  useEffect(() => {
    const id = window.setInterval(() => {
      if (document.hidden) return
      api
        .get<SetupResponse>('/setup')
        .then((res) => setBridges(res.data.bridges))
        .catch(() => undefined)
    }, 5000)
    return () => window.clearInterval(id)
  }, [])

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [setup, blockedRes] = await Promise.all([api.get<SetupResponse>('/setup'), api.get<BlockedCaller[]>('/blocked-callers')])
      apply(setup.data)
      setBlocked(blockedRes.data)
      setError(null)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setLoading(false)
    }
  }, [apply])

  useEffect(() => {
    void load()
  }, [load])

  async function saveSetup(body: Record<string, unknown>, done: string, setBusy: (b: boolean) => void) {
    if (readOnly) return
    setBusy(true)
    setError(null)
    setNotice(null)
    setWarnings([])
    try {
      const res = await api.post<SetupResponse & { success: boolean }>('/setup', body)
      apply(res.data)
      setWarnings(res.data.warnings ?? [])
      setNotice(done)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  function saveGateway() {
    const n = Number(rateLimit)
    if (!Number.isInteger(n) || n < 1 || n > 1_000_000) {
      setError('The global rate limit must be a whole number from 1 to 1,000,000.')
      return
    }
    let port: number | null = null
    if (listenPort.trim() !== '') {
      port = Number(listenPort)
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        setError('The listening port must be a whole number from 1 to 65535, or empty for the default.')
        return
      }
    }
    void saveSetup({ targetUrl: targetUrl.trim(), rateLimitPerMinute: n, listenPort: port }, 'Gateway settings saved.', setSavingGateway)
  }

  function saveNotifications() {
    if (!settings) return
    void saveSetup(
      { publicBaseUrl: settings.publicBaseUrl, notifications: settings.notifications },
      'Phone approval settings saved.',
      setSavingNotify
    )
  }

  function saveRollback() {
    if (!settings) return
    void saveSetup({ rollback: settings.rollback }, 'Rollback webhook saved.', setSavingRollback)
  }

  function savePrivacy() {
    if (!settings) return
    void saveSetup({ privacy: settings.privacy }, 'Privacy settings saved.', setSavingPrivacy)
  }

  function saveHoursAndAlerts() {
    if (!settings) return
    void saveSetup(
      { timezone: settings.timezone, schedule: settings.schedule, alerts: settings.alerts },
      'Business hours and alerts saved.',
      setSavingHours
    )
  }

  async function sendDigestNow() {
    setSendingDigest(true)
    setError(null)
    try {
      const res = await api.post<{ success: boolean; results: NotifyResult[] }>('/alerts/digest')
      setNotice(res.data.success ? 'Digest sent.' : `Digest sent with errors: ${res.data.results.filter((r) => !r.ok).map((r) => r.channel).join(', ')}`)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setSendingDigest(false)
    }
  }

  async function sendTest() {
    setTesting(true)
    setTestResults(null)
    setError(null)
    try {
      const res = await api.post<{ success: boolean; results: NotifyResult[] }>('/setup/test-notification')
      setTestResults(res.data.results)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setTesting(false)
    }
  }

  async function unblock(id: number) {
    setUnblocking(id)
    try {
      await api.delete(`/blocked-callers/${id}`)
      setBlocked((prev) => prev.filter((b) => b.id !== id))
      setNotice('Caller unblocked.')
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setUnblocking(null)
    }
  }

  const patchNotify = <K extends keyof GatewaySettings['notifications']>(channel: K, patch: Partial<GatewaySettings['notifications'][K]>) =>
    setSettings((s) => (s ? { ...s, notifications: { ...s.notifications, [channel]: { ...s.notifications[channel], ...patch } } } : s))

  return (
    <>
      <PageHeader
        title="Gateway Setup"
        subtitle="Point Mont at your store or API, set spending limits, and get approvals on your phone. No code needed."
        action={<RefreshButton onClick={() => void Promise.all([load(), reloadRules()])} loading={loading} />}
      />

      {error && <ErrorBanner message={error} onDismiss={() => setError(null)} />}
      {notice && <SuccessBanner message={notice} onDismiss={() => setNotice(null)} />}
      {warnings.map((w) => (
        <WarningBanner key={w}>{w}</WarningBanner>
      ))}
      {readOnly && <WarningBanner>{READ_ONLY_HINT}</WarningBanner>}

      {/* ---------------- Step 1 ---------------- */}
      <Section icon={<Server className="h-5 w-5" aria-hidden="true" />} step="Step 1" title="Connect your API" subtitle="Where should allowed AI agent requests go?">
        <div className="grid gap-4 md:grid-cols-3">
          <div className="md:col-span-3">
            <Field label="Upstream target URL" hint="Agents call this gateway at /api/...; allowed requests are forwarded to <target>/api/... Leave empty in Express middleware mode.">
              <input value={targetUrl} onChange={(e) => setTargetUrl(e.target.value)} placeholder="https://api.mystore.com" disabled={readOnly || loading} className={`${INPUT_CLASS} font-mono`} />
            </Field>
          </div>
          <Field label="Proxy listening port" hint={`Used by "agent-gateway-sdk start" on its next start. Running now on ${gatewayPort ?? '…'}.`}>
            <input value={listenPort} onChange={(e) => setListenPort(e.target.value)} placeholder="8080" inputMode="numeric" disabled={readOnly || loading} className={INPUT_CLASS} />
          </Field>
          <Field label="Global rate limit (requests / minute / caller)" hint="Stops runaway agent loops. Individual rules can set their own limit below.">
            <input value={rateLimit} onChange={(e) => setRateLimit(e.target.value)} inputMode="numeric" disabled={readOnly || loading} className={INPUT_CLASS} />
          </Field>
          <div className="flex items-end">
            <button type="button" onClick={saveGateway} disabled={readOnly || loading || savingGateway} className={PRIMARY_BTN} title={readOnly ? READ_ONLY_HINT : undefined}>
              {savingGateway && <Spinner />}
              Save gateway settings
            </button>
          </div>
        </div>
      </Section>

      {/* ---------------- Step 2 ---------------- */}
      <Section
        icon={<SlidersHorizontal className="h-5 w-5" aria-hidden="true" />}
        step="Step 2"
        title="Payload rules"
        subtitle="Decide by what the agent is actually asking for, e.g. allow small refunds, hold medium ones for you, block huge ones."
      >
        <PresetPicker readOnly={readOnly} setRules={setRules} onError={setError} onNotice={setNotice} />
        <PolicyBuilder rules={rules} setRules={setRules} readOnly={readOnly} onError={setError} onNotice={setNotice} onWarnings={setWarnings} />
      </Section>

      {/* ---------------- Step 3 ---------------- */}
      <Section
        icon={<BellRing className="h-5 w-5" aria-hidden="true" />}
        step="Step 3"
        title="Approve from your phone"
        subtitle="Get a Telegram or Slack message with the payload and Approve / Reject buttons. Telegram polling and Slack Socket Mode need no public URL, tunnel or open port."
      >
        {settings && (
          <div className="space-y-5">
            <div className="grid gap-4 lg:grid-cols-3">
              {/* ---- Telegram ---- */}
              <div className="rounded-lg border border-slate-200 p-4">
                <div className="mb-3 flex items-center justify-between gap-2">
                  <span className="text-sm font-semibold text-slate-900">Telegram</span>
                  <div className="flex items-center gap-2">
                    {settings.notifications.telegram.mode === 'polling' && <BridgeBadge status={bridges?.telegram} />}
                    <Toggle label="Enable Telegram" checked={settings.notifications.telegram.enabled} onChange={(v) => patchNotify('telegram', { enabled: v })} disabled={readOnly} />
                  </div>
                </div>
                <div className="space-y-3">
                  <ModeChooser
                    value={settings.notifications.telegram.mode}
                    options={[
                      { value: 'polling', label: 'Buttons (no tunnel)', hint: 'Mont polls Telegram outbound; tap Approve / Reject in the chat.' },
                      { value: 'links', label: 'Links', hint: 'Buttons open a confirmation page; needs the Public URL below.' },
                    ]}
                    onChange={(m) => patchNotify('telegram', { mode: m as 'polling' | 'links' })}
                    disabled={readOnly}
                  />
                  <Field label="Bot token" hint="Create a bot with @BotFather and paste its token.">
                    <input
                      value={settings.notifications.telegram.botToken}
                      onChange={(e) => patchNotify('telegram', { botToken: e.target.value })}
                      placeholder="123456789:AA..."
                      disabled={readOnly}
                      className={`${INPUT_CLASS} font-mono text-xs`}
                    />
                  </Field>
                  <Field label="Chat id" hint="Your user id, a group id (-100…), or @channel. Buttons are only accepted from this chat.">
                    <input
                      value={settings.notifications.telegram.chatId}
                      onChange={(e) => patchNotify('telegram', { chatId: e.target.value })}
                      placeholder="-1001234567890"
                      disabled={readOnly}
                      className={`${INPUT_CLASS} font-mono text-xs`}
                    />
                  </Field>
                  <Field label="Approver user ids (optional)" hint="Only these Telegram users may tap Approve / Reject. Empty = anyone in the chat.">
                    <input
                      value={settings.notifications.telegram.approverIds}
                      onChange={(e) => patchNotify('telegram', { approverIds: e.target.value })}
                      placeholder="123456789, 987654321"
                      disabled={readOnly}
                      className={`${INPUT_CLASS} font-mono text-xs`}
                    />
                  </Field>
                </div>
              </div>

              {/* ---- Slack ---- */}
              <div className="rounded-lg border border-slate-200 p-4">
                <div className="mb-3 flex items-center justify-between gap-2">
                  <span className="text-sm font-semibold text-slate-900">Slack</span>
                  <div className="flex items-center gap-2">
                    {settings.notifications.slack.mode === 'socket' && <BridgeBadge status={bridges?.slack} />}
                    <Toggle label="Enable Slack" checked={settings.notifications.slack.enabled} onChange={(v) => patchNotify('slack', { enabled: v })} disabled={readOnly} />
                  </div>
                </div>
                <div className="space-y-3">
                  <ModeChooser
                    value={settings.notifications.slack.mode}
                    options={[
                      { value: 'socket', label: 'Socket Mode (no tunnel)', hint: 'A Slack app with Socket Mode on; buttons work over an outbound WebSocket.' },
                      { value: 'webhook', label: 'Incoming webhook', hint: 'Simplest setup; buttons open a confirmation page and need the Public URL.' },
                    ]}
                    onChange={(m) => patchNotify('slack', { mode: m as 'webhook' | 'socket' })}
                    disabled={readOnly}
                  />
                  {settings.notifications.slack.mode === 'webhook' ? (
                    <Field label="Incoming webhook URL" hint="Slack → Apps → Incoming Webhooks → Add to channel.">
                      <input
                        value={settings.notifications.slack.webhookUrl}
                        onChange={(e) => patchNotify('slack', { webhookUrl: e.target.value })}
                        placeholder="https://hooks.slack.com/services/..."
                        disabled={readOnly}
                        className={`${INPUT_CLASS} font-mono text-xs`}
                      />
                    </Field>
                  ) : (
                    <>
                      <Field label="Bot token" hint="OAuth & Permissions → Bot User OAuth Token (scope chat:write).">
                        <input
                          value={settings.notifications.slack.botToken}
                          onChange={(e) => patchNotify('slack', { botToken: e.target.value })}
                          placeholder="xoxb-..."
                          disabled={readOnly}
                          className={`${INPUT_CLASS} font-mono text-xs`}
                        />
                      </Field>
                      <Field label="App-level token" hint="Basic Information → App-Level Tokens (scope connections:write). Turn on Socket Mode and Interactivity.">
                        <input
                          value={settings.notifications.slack.appToken}
                          onChange={(e) => patchNotify('slack', { appToken: e.target.value })}
                          placeholder="xapp-..."
                          disabled={readOnly}
                          className={`${INPUT_CLASS} font-mono text-xs`}
                        />
                      </Field>
                      <Field label="Channel id" hint="Invite the bot to the channel, then copy the id from the channel details. Buttons are only accepted from it.">
                        <input
                          value={settings.notifications.slack.channelId}
                          onChange={(e) => patchNotify('slack', { channelId: e.target.value })}
                          placeholder="C0123ABCD"
                          disabled={readOnly}
                          className={`${INPUT_CLASS} font-mono text-xs`}
                        />
                      </Field>
                      <Field label="Approver user ids (optional)" hint="Only these Slack users may decide. Empty = anyone in the channel.">
                        <input
                          value={settings.notifications.slack.approverIds}
                          onChange={(e) => patchNotify('slack', { approverIds: e.target.value })}
                          placeholder="U0123ABCD"
                          disabled={readOnly}
                          className={`${INPUT_CLASS} font-mono text-xs`}
                        />
                      </Field>
                    </>
                  )}
                </div>
              </div>
              <div className="rounded-lg border border-slate-200 p-4">
                <div className="mb-3 flex items-center justify-between">
                  <span className="text-sm font-semibold text-slate-900">Custom webhook</span>
                  <Toggle label="Enable webhook" checked={settings.notifications.webhook.enabled} onChange={(v) => patchNotify('webhook', { enabled: v })} disabled={readOnly} />
                </div>
                <div className="space-y-3">
                  <Field label="URL">
                    <input
                      value={settings.notifications.webhook.url}
                      onChange={(e) => patchNotify('webhook', { url: e.target.value })}
                      placeholder="https://hooks.zapier.com/..."
                      disabled={readOnly}
                      className={`${INPUT_CLASS} font-mono text-xs`}
                    />
                  </Field>
                  <Field label="Signing secret" hint="Sent as x-mont-signature: sha256=HMAC(secret, timestamp + '.' + body). Generated if empty.">
                    <input
                      value={settings.notifications.webhook.secret}
                      onChange={(e) => patchNotify('webhook', { secret: e.target.value })}
                      disabled={readOnly}
                      className={`${INPUT_CLASS} font-mono text-xs`}
                    />
                  </Field>
                </div>
              </div>
            </div>

            <Field
              label="Public URL of this gateway (only for link-based channels)"
              hint="Needed only for Telegram “Links”, Slack “Incoming webhook” and the custom webhook's approveUrl / rejectUrl: an address your phone can reach (e.g. a Cloudflare Tunnel). Links are HMAC-SHA256 signed and expire with the request."
            >
              <input
                value={settings.publicBaseUrl}
                onChange={(e) => setSettings({ ...settings, publicBaseUrl: e.target.value })}
                placeholder="https://mont.mystore.com (optional)"
                disabled={readOnly}
                className={`${INPUT_CLASS} font-mono`}
              />
            </Field>

            <div className="flex flex-wrap items-center gap-3">
              <button type="button" onClick={saveNotifications} disabled={readOnly || savingNotify} className={PRIMARY_BTN}>
                {savingNotify && <Spinner />}
                Save phone approvals
              </button>
              <button type="button" onClick={() => void sendTest()} disabled={readOnly || testing} className={SECONDARY_BTN}>
                {testing ? <Spinner /> : <Send className="h-4 w-4" aria-hidden="true" />}
                Send test notification
              </button>
              {testResults && (
                <div className="flex flex-wrap gap-2">
                  {testResults.map((r) => (
                    <Badge key={r.channel} tone={r.ok ? 'green' : 'red'}>
                      {r.channel}: {r.ok ? 'sent' : `failed${r.status ? ` (${r.status})` : ''}`}
                    </Badge>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </Section>

      {/* ---------------- Step 4 ---------------- */}
      <Section
        icon={<Undo2 className="h-5 w-5" aria-hidden="true" />}
        step="Step 4"
        title="Undo button for approved actions"
        subtitle="When you Revoke an approved request, Mont blocks the caller and POSTs the original request to this URL so your system can roll it back."
      >
        {settings && (
          <div className="grid gap-4 md:grid-cols-[1fr_18rem_auto]">
            <Field label="Rollback webhook URL" hint='Receives {"event":"approval.revoked","originalRequestId":…,"method","path","body",…} with an Idempotency-Key header.'>
              <input
                value={settings.rollback.url}
                onChange={(e) => setSettings({ ...settings, rollback: { ...settings.rollback, url: e.target.value } })}
                placeholder="https://api.mystore.com/api/rollback"
                disabled={readOnly}
                className={`${INPUT_CLASS} font-mono`}
              />
            </Field>
            <Field label="Signing secret" hint="Generated if empty.">
              <input
                value={settings.rollback.secret}
                onChange={(e) => setSettings({ ...settings, rollback: { ...settings.rollback, secret: e.target.value } })}
                disabled={readOnly}
                className={`${INPUT_CLASS} font-mono text-xs`}
              />
            </Field>
            <div className="flex items-end">
              <button type="button" onClick={saveRollback} disabled={readOnly || savingRollback} className={PRIMARY_BTN}>
                {savingRollback && <Spinner />}
                Save
              </button>
            </div>
          </div>
        )}
      </Section>

      {/* ---------------- Business hours + alerts ---------------- */}
      <Section
        icon={<Clock className="h-5 w-5" aria-hidden="true" />}
        step="Step 5"
        title="Business hours, alerts & daily digest"
        subtitle="Outside opening hours nothing changes data without you. Get told about attacks as they happen, and a summary every morning."
      >
        {settings && (
          <div className="space-y-5">
            <div className="grid gap-4 md:grid-cols-3">
              <Field label="Time zone" hint='IANA name, e.g. "America/New_York", "Europe/London", "Asia/Kolkata".'>
                <input
                  value={settings.timezone}
                  onChange={(e) => setSettings({ ...settings, timezone: e.target.value })}
                  list="mont-timezones"
                  className={`${INPUT_CLASS} font-mono`}
                  disabled={readOnly}
                />
                <datalist id="mont-timezones">
                  {COMMON_TIMEZONES.map((tz) => (
                    <option key={tz} value={tz} />
                  ))}
                </datalist>
              </Field>
            </div>

            <div className="rounded-lg border border-slate-200 p-4">
              <div className="mb-3 flex items-center justify-between gap-3">
                <span>
                  <span className="block text-sm font-semibold text-slate-900">Business hours</span>
                  <span className="text-xs text-slate-500">
                    Outside these hours, writes your rules would allow wait for your approval (reads still work).
                    {withinHours !== undefined && settings.schedule.enabled && (
                      <strong className={withinHours ? ' text-emerald-700' : ' text-amber-700'}>{withinHours ? ' Open now.' : ' Closed now.'}</strong>
                    )}
                  </span>
                </span>
                <Toggle
                  label="Enable business hours"
                  checked={settings.schedule.enabled}
                  onChange={(v) => setSettings({ ...settings, schedule: { ...settings.schedule, enabled: v } })}
                  disabled={readOnly}
                />
              </div>
              <div className="flex flex-wrap items-end gap-3">
                <div className="flex gap-1" role="group" aria-label="Business days">
                  {['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].map((d, i) => {
                    const on = settings.schedule.days.includes(i)
                    return (
                      <button
                        key={d}
                        type="button"
                        aria-pressed={on}
                        disabled={readOnly}
                        onClick={() =>
                          setSettings({
                            ...settings,
                            schedule: { ...settings.schedule, days: on ? settings.schedule.days.filter((x) => x !== i) : [...settings.schedule.days, i].sort() },
                          })
                        }
                        className={`rounded-md px-2.5 py-1.5 text-xs font-semibold ${on ? 'bg-indigo-600 text-white' : 'bg-slate-100 text-slate-600 hover:bg-slate-200'}`}
                      >
                        {d}
                      </button>
                    )
                  })}
                </div>
                <Field label="Opens">
                  <input
                    type="time"
                    value={settings.schedule.start}
                    onChange={(e) => setSettings({ ...settings, schedule: { ...settings.schedule, start: e.target.value } })}
                    className={INPUT_CLASS}
                    disabled={readOnly}
                  />
                </Field>
                <Field label="Closes">
                  <input
                    type="time"
                    value={settings.schedule.end}
                    onChange={(e) => setSettings({ ...settings, schedule: { ...settings.schedule, end: e.target.value } })}
                    className={INPUT_CLASS}
                    disabled={readOnly}
                  />
                </Field>
              </div>
            </div>

            <div className="rounded-lg border border-slate-200 p-4">
              <div className="mb-3 flex items-center justify-between gap-3">
                <span>
                  <span className="block text-sm font-semibold text-slate-900">Security alerts</span>
                  <span className="text-xs text-slate-500">
                    Sent to the channels in Step 3: attack bursts, spending budgets reached, lockdown on / off.
                  </span>
                </span>
                <Toggle
                  label="Enable security alerts"
                  checked={settings.alerts.enabled}
                  onChange={(v) => setSettings({ ...settings, alerts: { ...settings.alerts, enabled: v } })}
                  disabled={readOnly}
                />
              </div>
              <div className="grid gap-3 md:grid-cols-3">
                <Field label="Alert when this many requests are refused…">
                  <input
                    value={String(settings.alerts.burstThreshold)}
                    onChange={(e) => setSettings({ ...settings, alerts: { ...settings.alerts, burstThreshold: Number(e.target.value) || 1 } })}
                    inputMode="numeric"
                    className={INPUT_CLASS}
                    disabled={readOnly}
                  />
                </Field>
                <Field label="…within minutes">
                  <input
                    value={String(settings.alerts.burstWindowMinutes)}
                    onChange={(e) => setSettings({ ...settings, alerts: { ...settings.alerts, burstWindowMinutes: Number(e.target.value) || 1 } })}
                    inputMode="numeric"
                    className={INPUT_CLASS}
                    disabled={readOnly}
                  />
                </Field>
                <Field label="Daily digest at (local time)">
                  <select
                    value={settings.alerts.digestHour === null ? '' : String(settings.alerts.digestHour)}
                    onChange={(e) => setSettings({ ...settings, alerts: { ...settings.alerts, digestHour: e.target.value === '' ? null : Number(e.target.value) } })}
                    className={INPUT_CLASS}
                    disabled={readOnly}
                  >
                    <option value="">Off</option>
                    {Array.from({ length: 24 }, (_, h) => (
                      <option key={h} value={String(h)}>
                        {String(h).padStart(2, '0')}:00
                      </option>
                    ))}
                  </select>
                </Field>
              </div>
            </div>

            <div className="flex flex-wrap gap-3">
              <button type="button" onClick={saveHoursAndAlerts} disabled={readOnly || savingHours} className={PRIMARY_BTN}>
                {savingHours && <Spinner />}
                Save hours & alerts
              </button>
              <button type="button" onClick={() => void sendDigestNow()} disabled={readOnly || sendingDigest} className={SECONDARY_BTN}>
                {sendingDigest ? <Spinner /> : <Send className="h-4 w-4" aria-hidden="true" />}
                Send digest now
              </button>
            </div>
          </div>
        )}
      </Section>

      {/* ---------------- Privacy ---------------- */}
      <Section
        icon={<EyeOff className="h-5 w-5" aria-hidden="true" />}
        step="Privacy"
        title="Scrub customer data from logs and notifications"
        subtitle="Auth headers, cookies, API keys, passwords, tokens and card numbers (Luhn-checked) are always redacted before anything is stored or sent to Slack / Telegram / webhooks."
      >
        {settings && (
          <div className="flex flex-wrap items-center gap-6">
            <label className="flex items-center gap-3 text-sm text-slate-700">
              <Toggle
                label="Mask email addresses"
                checked={settings.privacy.redactEmails}
                onChange={(v) => setSettings({ ...settings, privacy: { ...settings.privacy, redactEmails: v } })}
                disabled={readOnly}
              />
              Mask email addresses <span className="font-mono text-xs text-slate-500">j***@example.com</span>
            </label>
            <label className="flex items-center gap-3 text-sm text-slate-700">
              <Toggle
                label="Mask phone numbers"
                checked={settings.privacy.redactPhones}
                onChange={(v) => setSettings({ ...settings, privacy: { ...settings.privacy, redactPhones: v } })}
                disabled={readOnly}
              />
              Mask phone numbers <span className="font-mono text-xs text-slate-500">[REDACTED:phone ••42]</span>
            </label>
            <button type="button" onClick={savePrivacy} disabled={readOnly || savingPrivacy} className={PRIMARY_BTN}>
              {savingPrivacy && <Spinner />}
              Save privacy settings
            </button>
            <p className="w-full text-xs text-slate-500">
              Payload rules still see the real values (redaction happens only on what is stored or sent), and approved requests are replayed from an encrypted copy.
            </p>
          </div>
        )}
      </Section>

      {/* ---------------- Blocked callers ---------------- */}
      <Section icon={<ShieldOff className="h-5 w-5" aria-hidden="true" />} step="Kill-switch" title="Blocked callers" subtitle="Agent keys and IPs blocked with “Revoke & Block Caller”. Every request from them gets 403.">
        {blocked.length === 0 ? (
          <p className="text-sm text-slate-500">No callers are blocked.</p>
        ) : (
          <ul className="divide-y divide-slate-100">
            {blocked.map((b) => (
              <li key={b.id} className="flex flex-wrap items-center justify-between gap-3 py-2.5">
                <div className="min-w-0 text-sm">
                  <Badge tone="red">{b.kind === 'ip' ? 'IP' : 'Agent key'}</Badge>{' '}
                  <span className="font-mono text-slate-900">{b.label ?? b.value}</span>
                  <p className="mt-0.5 text-xs text-slate-500">
                    by {b.created_by} · {formatTime(b.created_at)}
                    {b.source_action_id ? ` · from action #${b.source_action_id}` : ''}
                    {b.reason ? ` · “${b.reason}”` : ''}
                  </p>
                </div>
                <button type="button" onClick={() => void unblock(b.id)} disabled={readOnly || unblocking === b.id} className={SECONDARY_BTN}>
                  {unblocking === b.id && <Spinner />}
                  Unblock
                </button>
              </li>
            ))}
          </ul>
        )}
      </Section>
    </>
  )
}

// =====================================================================
// Bridge status, mode chooser, starter packs
// =====================================================================
const BRIDGE_STYLE: Record<string, { label: string; cls: string }> = {
  connected: { label: 'Connected', cls: 'bg-emerald-50 text-emerald-700 ring-emerald-600/20' },
  connecting: { label: 'Connecting…', cls: 'bg-amber-50 text-amber-800 ring-amber-600/20' },
  standby: { label: 'Standby', cls: 'bg-slate-50 text-slate-600 ring-slate-500/20' },
  error: { label: 'Error', cls: 'bg-red-50 text-red-700 ring-red-600/20' },
  disabled: { label: 'Off', cls: 'bg-slate-50 text-slate-500 ring-slate-400/20' },
}

function BridgeBadge({ status }: { status: BridgeStatus | undefined }) {
  if (!status) return null
  const s = BRIDGE_STYLE[status.state] ?? BRIDGE_STYLE.disabled
  return (
    <span title={status.detail ?? undefined} className={`inline-flex rounded-full px-2 py-0.5 text-[11px] font-semibold ring-1 ring-inset ${s.cls}`}>
      {s.label}
    </span>
  )
}

function ModeChooser({
  value,
  options,
  onChange,
  disabled,
}: {
  value: string
  options: { value: string; label: string; hint: string }[]
  onChange: (v: string) => void
  disabled?: boolean
}) {
  return (
    <div role="radiogroup" className="space-y-1.5">
      {options.map((o) => (
        <label
          key={o.value}
          className={`flex cursor-pointer items-start gap-2 rounded-lg border px-3 py-2 text-xs ${value === o.value ? 'border-indigo-300 bg-indigo-50/60' : 'border-slate-200'}`}
        >
          <input type="radio" className="mt-0.5" checked={value === o.value} onChange={() => onChange(o.value)} disabled={disabled} />
          <span>
            <span className="block font-semibold text-slate-900">{o.label}</span>
            <span className="text-slate-500">{o.hint}</span>
          </span>
        </label>
      ))}
    </div>
  )
}

function PresetPicker({
  readOnly,
  setRules,
  onError,
  onNotice,
}: {
  readOnly: boolean
  setRules: (r: Rules) => void
  onError: (e: string | null) => void
  onNotice: (n: string | null) => void
}) {
  const [presets, setPresets] = useState<PolicyPreset[]>([])
  const [selected, setSelected] = useState('')
  const [busy, setBusy] = useState<'merge' | 'replace' | null>(null)

  useEffect(() => {
    api
      .get<PolicyPreset[]>('/setup/presets')
      .then((res) => {
        setPresets(res.data)
        if (res.data.length > 0) setSelected((s) => s || res.data[0].id)
      })
      .catch((err: unknown) => onError(errorMessage(err)))
  }, [onError])

  const preset = presets.find((p) => p.id === selected)

  async function install(mode: 'merge' | 'replace') {
    if (!preset || readOnly) return
    if (mode === 'replace' && !window.confirm(`Replace ALL current rules with "${preset.name}"? Rules not in the pack will be removed (default deny applies to them).`)) return
    setBusy(mode)
    onError(null)
    try {
      const res = await api.post<ApplyPresetResponse>(`/setup/presets/${preset.id}/apply`, { mode })
      setRules(res.data.rules)
      onNotice(
        `Installed “${preset.name}”: ${res.data.added.length} rule(s) added${res.data.replaced.length ? `, ${res.data.replaced.length} updated` : ''}${mode === 'replace' ? ', all other rules removed' : ''}.`
      )
    } catch (err) {
      onError(errorMessage(err))
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="mb-6 rounded-lg border border-indigo-200 bg-indigo-50/40 p-4">
      <div className="mb-3 flex items-center gap-2">
        <Package className="h-4 w-4 text-indigo-600" aria-hidden="true" />
        <span className="text-sm font-semibold text-slate-900">Load Starter Policy Pack</span>
        <span className="text-xs text-slate-500">1-click protection you can fine-tune below</span>
      </div>
      <div className="grid gap-3 md:grid-cols-3">
        {presets.map((p) => (
          <button
            key={p.id}
            type="button"
            onClick={() => setSelected(p.id)}
            aria-pressed={selected === p.id}
            className={`rounded-lg border p-3 text-left transition ${selected === p.id ? 'border-indigo-400 bg-white shadow-sm ring-1 ring-indigo-300' : 'border-slate-200 bg-white/70 hover:bg-white'}`}
          >
            <span className="block text-sm font-semibold text-slate-900">{p.name}</span>
            <span className="mt-1 block text-xs text-slate-600">{p.summary}</span>
          </button>
        ))}
      </div>
      {preset && (
        <div className="mt-3 rounded-lg border border-slate-200 bg-white p-3">
          <ul className="list-disc space-y-0.5 pl-5 text-xs text-slate-700">
            {preset.highlights.map((h) => (
              <li key={h}>{h}</li>
            ))}
          </ul>
          <details className="mt-2">
            <summary className="cursor-pointer text-xs font-semibold text-slate-500">Rules this pack installs ({Object.keys(preset.rules).length})</summary>
            <ul className="mt-1 space-y-0.5 font-mono text-[11px] text-slate-700">
              {Object.entries(preset.rules).map(([k, r]) => (
                <li key={k}>
                  {k} → {r.mode}
                  {r.rateLimit ? ` · ${r.rateLimit}/min` : ''}
                  {r.policies?.length ? ` · ${r.policies.length} tier(s)` : ''}
                </li>
              ))}
            </ul>
          </details>
          <div className="mt-3 flex flex-wrap gap-2">
            <button type="button" onClick={() => void install('merge')} disabled={readOnly || busy !== null} className={PRIMARY_BTN}>
              {busy === 'merge' && <Spinner />}
              Add to my rules
            </button>
            <button type="button" onClick={() => void install('replace')} disabled={readOnly || busy !== null} className={SECONDARY_BTN}>
              {busy === 'replace' && <Spinner />}
              Replace all rules
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

// =====================================================================
// Visual payload policy builder
// =====================================================================
function PolicyBuilder({
  rules,
  setRules,
  readOnly,
  onError,
  onNotice,
  onWarnings,
}: {
  rules: Rules
  setRules: (r: Rules) => void
  readOnly: boolean
  onError: (e: string | null) => void
  onNotice: (n: string | null) => void
  onWarnings: (w: string[]) => void
}) {
  const keys = useMemo(() => Object.keys(rules).sort(), [rules])
  const [selected, setSelected] = useState<string>('__new__')
  const [newMethod, setNewMethod] = useState<string>('POST')
  const [newPath, setNewPath] = useState('/api/refund')
  const [fallback, setFallback] = useState<Mode>('REQUIRE_APPROVAL')
  const [ruleLimit, setRuleLimit] = useState('')
  const [tiers, setTiers] = useState<DraftTier[]>([])
  const [saving, setSaving] = useState(false)
  // Spending budget
  const [budgetOn, setBudgetOn] = useState(false)
  const [budgetField, setBudgetField] = useState('body.amount')
  const [budgetMax, setBudgetMax] = useState('300')
  const [budgetWindow, setBudgetWindow] = useState('60')
  const [budgetPer, setBudgetPer] = useState<'global' | 'caller'>('global')
  const [budgetOnExceed, setBudgetOnExceed] = useState<'REQUIRE_APPROVAL' | 'BLOCK'>('REQUIRE_APPROVAL')
  // Duplicate protection
  const [dedupeOn, setDedupeOn] = useState(false)
  const [dedupeFields, setDedupeFields] = useState('body.orderId')
  const [dedupeWindow, setDedupeWindow] = useState('1440')
  const [dedupeOnDuplicate, setDedupeOnDuplicate] = useState<'BLOCK' | 'REQUIRE_APPROVAL'>('BLOCK')

  // Load the chosen rule into the editor.
  useEffect(() => {
    if (selected === '__new__') return
    const rule: Rule | undefined = rules[selected]
    if (!rule) return
    setFallback(rule.mode)
    setRuleLimit(rule.rateLimit ? String(rule.rateLimit) : '')
    setTiers((rule.policies ?? []).map(toDraft))
    setBudgetOn(Boolean(rule.budget))
    if (rule.budget) {
      setBudgetField(rule.budget.field)
      setBudgetMax(String(rule.budget.max))
      setBudgetWindow(String(rule.budget.windowMinutes))
      setBudgetPer(rule.budget.per)
      setBudgetOnExceed(rule.budget.onExceed)
    }
    setDedupeOn(Boolean(rule.dedupe))
    if (rule.dedupe) {
      setDedupeFields(rule.dedupe.fields.join(', '))
      setDedupeWindow(String(rule.dedupe.windowMinutes))
      setDedupeOnDuplicate(rule.dedupe.onDuplicate)
    }
  }, [selected, rules])

  useEffect(() => {
    if (selected === '__new__' && keys.length > 0 && tiers.length === 0) {
      const firstWithPolicies = keys.find((k) => (rules[k]?.policies?.length ?? 0) > 0)
      if (firstWithPolicies) setSelected(firstWithPolicies)
    }
    // Only on first load of rules.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [keys.length])

  const editKey = selected === '__new__' ? ruleKey(newMethod, newPath.trim()) : selected

  const updateTier = (i: number, patch: Partial<DraftTier>) => setTiers((t) => t.map((x, j) => (j === i ? { ...x, ...patch } : x)))
  const updateCond = (i: number, c: number, patch: Partial<DraftCondition>) =>
    setTiers((t) => t.map((x, j) => (j === i ? { ...x, when: x.when.map((y, k) => (k === c ? { ...y, ...patch } : y)) } : x)))

  async function save() {
    if (readOnly) return
    onError(null)
    onNotice(null)
    onWarnings([])
    const policies: PolicyTier[] = []
    for (const [i, d] of tiers.entries()) {
      const r = fromDraft(d, i)
      if (r.error) {
        onError(r.error)
        return
      }
      policies.push(r.tier as PolicyTier)
    }
    let rateLimit: number | null = null
    if (ruleLimit.trim() !== '') {
      rateLimit = Number(ruleLimit)
      if (!Number.isInteger(rateLimit) || rateLimit < 1) {
        onError('The rule rate limit must be a whole number of at least 1, or empty to use the global limit.')
        return
      }
    }
    if (!editKey.includes('/api/')) {
      onError('The endpoint path must start with /api/.')
      return
    }
    let budget: BudgetSpec | null = null
    if (budgetOn) {
      const max = Number(budgetMax)
      if (budgetMax.trim() === '' || !Number.isFinite(max) || max < 0) {
        onError('The spending budget must be a number of at least 0.')
        return
      }
      budget = { field: budgetField.trim(), max, windowMinutes: Number(budgetWindow), per: budgetPer, onExceed: budgetOnExceed }
    }
    let dedupe: DedupeSpec | null = null
    if (dedupeOn) {
      const fields = dedupeFields.split(',').map((s) => s.trim()).filter(Boolean)
      if (fields.length === 0) {
        onError('Duplicate protection needs at least one field, e.g. body.orderId.')
        return
      }
      dedupe = { fields, windowMinutes: Number(dedupeWindow), onDuplicate: dedupeOnDuplicate }
    }
    setSaving(true)
    try {
      const existing = rules[editKey]
      const res = await api.post<{ success: boolean; rules: Rules; warnings?: string[] }>('/rules', {
        [editKey]: { mode: fallback, description: existing?.description ?? '', rateLimit, policies, budget, dedupe },
      })
      setRules(res.data.rules)
      onWarnings(res.data.warnings ?? [])
      onNotice(`Payload rules for ${editKey} saved (${policies.length} tier${policies.length === 1 ? '' : 's'}).`)
      setSelected(editKey)
    } catch (err) {
      onError(errorMessage(err))
    } finally {
      setSaving(false)
    }
  }

  const { method: selMethod, path: selPath } = splitRuleKey(editKey)

  return (
    <div className="space-y-4">
      <div className="grid gap-3 md:grid-cols-[1fr_auto]">
        <Field label="Endpoint">
          <select value={selected} onChange={(e) => setSelected(e.target.value)} className={`${INPUT_CLASS} font-mono`}>
            <option value="__new__">+ New endpoint…</option>
            {keys.map((k) => (
              <option key={k} value={k}>
                {k}
                {rules[k]?.policies?.length ? `  (${rules[k].policies?.length} tiers)` : ''}
              </option>
            ))}
          </select>
        </Field>
        <div className="flex items-end">
          <button type="button" className={SECONDARY_BTN} disabled={readOnly} onClick={() => {
              setTiers(REFUND_TEMPLATE.map((t) => ({ ...t, when: t.when.map((c) => ({ ...c })) })))
              setFallback('REQUIRE_APPROVAL')
              setBudgetOn(true)
              setBudgetField('body.amount')
              setBudgetMax('300')
              setBudgetWindow('60')
              setDedupeOn(true)
              setDedupeFields('body.orderId')
              setDedupeWindow('1440')
            }}>
            <Wand2 className="h-4 w-4" aria-hidden="true" />
            Use refund template
          </button>
        </div>
      </div>

      {selected === '__new__' && (
        <div className="grid gap-3 md:grid-cols-[8rem_1fr]">
          <Field label="Method">
            <select value={newMethod} onChange={(e) => setNewMethod(e.target.value)} className={INPUT_CLASS}>
              {RULE_METHOD_OPTIONS.map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Path">
            <input value={newPath} onChange={(e) => setNewPath(e.target.value)} className={`${INPUT_CLASS} font-mono`} placeholder="/api/refund" />
          </Field>
        </div>
      )}

      <div className="space-y-3">
        {tiers.length === 0 && (
          <p className="rounded-lg border border-dashed border-slate-300 px-4 py-6 text-center text-sm text-slate-500">
            No payload tiers yet: every request to <span className="font-mono">{selMethod} {selPath}</span> gets the fallback decision below.
          </p>
        )}
        {tiers.map((t, i) => (
          <div key={i} className="rounded-lg border border-slate-200 bg-slate-50/60 p-4">
            <div className="mb-3 grid gap-3 md:grid-cols-[3rem_1fr_13rem_auto] md:items-end">
              <span className="text-xs font-semibold text-slate-500">Tier {i + 1}</span>
              <Field label="Name (optional)">
                <input value={t.name} onChange={(e) => updateTier(i, { name: e.target.value })} className={INPUT_CLASS} placeholder="small refund" disabled={readOnly} />
              </Field>
              <Field label="Then">
                <ModeSelect value={t.mode} onChange={(m) => updateTier(i, { mode: m })} disabled={readOnly} />
              </Field>
              <button type="button" aria-label={`Remove tier ${i + 1}`} disabled={readOnly} onClick={() => setTiers((x) => x.filter((_, j) => j !== i))} className="mb-1 text-slate-400 hover:text-red-600">
                <Trash2 className="h-4 w-4" aria-hidden="true" />
              </button>
            </div>
            <p className="mb-2 text-xs font-medium text-slate-600">When ALL of these are true:</p>
            <div className="space-y-2">
              {t.when.map((c, k) => (
                <div key={k} className="grid gap-2 md:grid-cols-[1fr_10rem_1fr_auto] md:items-center">
                  <input value={c.field} onChange={(e) => updateCond(i, k, { field: e.target.value })} className={`${INPUT_CLASS} font-mono`} placeholder="body.amount" disabled={readOnly} aria-label="Field" />
                  <select value={c.op} onChange={(e) => updateCond(i, k, { op: e.target.value as PolicyOperator })} className={INPUT_CLASS} disabled={readOnly} aria-label="Operator">
                    {OPERATORS.map((o) => (
                      <option key={o.op} value={o.op}>
                        {o.label}
                      </option>
                    ))}
                  </select>
                  {c.op === 'exists' ? (
                    <select value={c.value === 'false' ? 'false' : 'true'} onChange={(e) => updateCond(i, k, { value: e.target.value })} className={INPUT_CLASS} disabled={readOnly} aria-label="Value">
                      <option value="true">is present</option>
                      <option value="false">is missing</option>
                    </select>
                  ) : (
                    <div className="flex items-center gap-2">
                      <input
                        value={c.value}
                        onChange={(e) => updateCond(i, k, { value: e.target.value })}
                        className={`${INPUT_CLASS} font-mono`}
                        placeholder={NUMERIC_OPS.includes(c.op) ? '100' : c.op === 'in' ? 'USD, EUR' : c.op === 'regex' ? '^ord_[0-9]+$' : 'value'}
                        disabled={readOnly}
                        aria-label="Value"
                      />
                      {c.op === 'regex' && (
                        <label className="flex shrink-0 items-center gap-1 text-xs text-slate-600">
                          <input type="checkbox" checked={c.caseInsensitive} onChange={(e) => updateCond(i, k, { caseInsensitive: e.target.checked })} disabled={readOnly} />
                          ignore case
                        </label>
                      )}
                    </div>
                  )}
                  <button
                    type="button"
                    aria-label="Remove condition"
                    disabled={readOnly || t.when.length === 1}
                    onClick={() => updateTier(i, { when: t.when.filter((_, j) => j !== k) })}
                    className="text-slate-400 hover:text-red-600 disabled:opacity-30"
                  >
                    <Trash2 className="h-4 w-4" aria-hidden="true" />
                  </button>
                </div>
              ))}
            </div>
            <button
              type="button"
              disabled={readOnly}
              onClick={() => updateTier(i, { when: [...t.when, { field: 'body.', op: '===', value: '', caseInsensitive: false }] })}
              className="mt-2 inline-flex items-center gap-1 text-xs font-semibold text-indigo-600 hover:text-indigo-800"
            >
              <Plus className="h-3.5 w-3.5" aria-hidden="true" /> AND condition
            </button>
          </div>
        ))}
        <button
          type="button"
          disabled={readOnly}
          onClick={() => setTiers((t) => [...t, { name: '', mode: 'REQUIRE_APPROVAL', when: [{ field: 'body.amount', op: '>', value: '', caseInsensitive: false }] }])}
          className={SECONDARY_BTN}
        >
          <Plus className="h-4 w-4" aria-hidden="true" /> Add tier
        </button>
      </div>

      <div className="grid gap-4 border-t border-slate-100 pt-4 lg:grid-cols-2">
        {/* ---- Spending budget ---- */}
        <div className="rounded-lg border border-slate-200 p-4">
          <div className="mb-3 flex items-center justify-between">
            <span>
              <span className="block text-sm font-semibold text-slate-900">Spending budget</span>
              <span className="text-xs text-slate-500">Caps the TOTAL the agent can move on its own, e.g. $300 of refunds per hour.</span>
            </span>
            <Toggle label="Enable spending budget" checked={budgetOn} onChange={setBudgetOn} disabled={readOnly} />
          </div>
          {budgetOn && (
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Add up this field">
                <input value={budgetField} onChange={(e) => setBudgetField(e.target.value)} className={`${INPUT_CLASS} font-mono`} disabled={readOnly} />
              </Field>
              <Field label="Maximum total">
                <input value={budgetMax} onChange={(e) => setBudgetMax(e.target.value)} inputMode="decimal" className={INPUT_CLASS} placeholder="300" disabled={readOnly} />
              </Field>
              <Field label="Per">
                <select value={budgetWindow} onChange={(e) => setBudgetWindow(e.target.value)} className={INPUT_CLASS} disabled={readOnly}>
                  <option value="60">hour</option>
                  <option value="1440">day</option>
                  <option value="10080">week</option>
                  <option value="43200">30 days</option>
                </select>
              </Field>
              <Field label="Counted">
                <select value={budgetPer} onChange={(e) => setBudgetPer(e.target.value as 'global' | 'caller')} className={INPUT_CLASS} disabled={readOnly}>
                  <option value="global">for all agents together</option>
                  <option value="caller">separately per agent</option>
                </select>
              </Field>
              <div className="sm:col-span-2">
                <Field label="When the budget is used up">
                  <select value={budgetOnExceed} onChange={(e) => setBudgetOnExceed(e.target.value as 'REQUIRE_APPROVAL' | 'BLOCK')} className={INPUT_CLASS} disabled={readOnly}>
                    <option value="REQUIRE_APPROVAL">ask me to approve</option>
                    <option value="BLOCK">block</option>
                  </select>
                </Field>
              </div>
            </div>
          )}
        </div>

        {/* ---- Duplicate protection ---- */}
        <div className="rounded-lg border border-slate-200 p-4">
          <div className="mb-3 flex items-center justify-between">
            <span>
              <span className="block text-sm font-semibold text-slate-900">Duplicate protection</span>
              <span className="text-xs text-slate-500">Stops a looping agent from doing the same thing twice, e.g. refunding one order twice.</span>
            </span>
            <Toggle label="Enable duplicate protection" checked={dedupeOn} onChange={setDedupeOn} disabled={readOnly} />
          </div>
          {dedupeOn && (
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="sm:col-span-2">
                <Field label="Same action = same values in" hint="Comma-separated body fields, e.g. body.orderId or body.destination, body.amount">
                  <input value={dedupeFields} onChange={(e) => setDedupeFields(e.target.value)} className={`${INPUT_CLASS} font-mono`} disabled={readOnly} />
                </Field>
              </div>
              <Field label="Within">
                <select value={dedupeWindow} onChange={(e) => setDedupeWindow(e.target.value)} className={INPUT_CLASS} disabled={readOnly}>
                  <option value="10">10 minutes</option>
                  <option value="60">1 hour</option>
                  <option value="1440">24 hours</option>
                  <option value="10080">7 days</option>
                  <option value="43200">30 days</option>
                </select>
              </Field>
              <Field label="A duplicate is">
                <select value={dedupeOnDuplicate} onChange={(e) => setDedupeOnDuplicate(e.target.value as 'BLOCK' | 'REQUIRE_APPROVAL')} className={INPUT_CLASS} disabled={readOnly}>
                  <option value="BLOCK">blocked</option>
                  <option value="REQUIRE_APPROVAL">sent to me for approval</option>
                </select>
              </Field>
            </div>
          )}
        </div>
      </div>

      <div className="grid gap-3 border-t border-slate-100 pt-4 md:grid-cols-[1fr_1fr_auto]">
        <Field label="Otherwise (no tier matched, or a field is missing)" hint="Require approval or Block keeps this fail-closed.">
          <ModeSelect value={fallback} onChange={setFallback} disabled={readOnly} />
        </Field>
        <Field label="Rate limit for this endpoint (per minute)" hint="Empty = global limit.">
          <input value={ruleLimit} onChange={(e) => setRuleLimit(e.target.value)} inputMode="numeric" className={INPUT_CLASS} placeholder="e.g. 5" disabled={readOnly} />
        </Field>
        <div className="flex items-end">
          <button type="button" onClick={() => void save()} disabled={readOnly || saving} className={PRIMARY_BTN}>
            {saving && <Spinner />}
            Save payload rules
          </button>
        </div>
      </div>
      <p className="text-xs text-slate-500">
        Tiers are checked top to bottom; the first match wins. Body numbers must be real JSON numbers (<span className="font-mono">"250"</span> as text never
        counts as 250). Quote a value to compare it as text, e.g. <span className="font-mono">"123"</span>.
      </p>
    </div>
  )
}
