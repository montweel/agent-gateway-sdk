import { useCallback, useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import axios from 'axios'
import { Check, Copy, Eye, EyeOff, Globe } from 'lucide-react'
import { api, BASE_URL, DISPLAY_HOST, errorMessage } from '../lib/api'
import { isProRequired } from '../lib/types'
import type { GatewayConfig, ProRequiredResponse } from '../lib/types'
import { INPUT_CLASS, READ_ONLY_HINT } from '../lib/utils'
import { AgentKeysPanel } from '../components/AgentKeysPanel'
import { LicenseCard, ProLockLink } from '../components/LicenseCard'
import type { LicenseApi } from '../hooks/useLicense'
import { Badge, ErrorBanner, PageHeader, ProCallout, RefreshButton, Spinner, SuccessBanner, WarningBanner } from '../components/ui'

const scrollToLicense = () => document.getElementById('mont-license')?.scrollIntoView({ behavior: 'smooth' })

export function SettingsTab({ readOnly, licenseApi }: { readOnly: boolean; licenseApi: LicenseApi }) {
  const isPro = licenseApi.isPro
  const [config, setConfig] = useState<GatewayConfig | null>(null)
  const [targetUrl, setTargetUrl] = useState('')
  const [rateLimit, setRateLimit] = useState('60')
  const [requireAgentApiKey, setRequireAgentApiKey] = useState(false)
  const [ssoTrustProxyHeader, setSsoTrustProxyHeader] = useState(false)
  const [showSecret, setShowSecret] = useState(false)
  const [secretCopied, setSecretCopied] = useState(false)
  const [ssoUserHeader, setSsoUserHeader] = useState('x-forwarded-user')
  const [ssoRoleHeader, setSsoRoleHeader] = useState('x-forwarded-role')

  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [selfLoopHint, setSelfLoopHint] = useState(false)
  const [saved, setSaved] = useState<string | null>(null)
  const [proNotice, setProNotice] = useState<ProRequiredResponse | null>(null)
  const [warnings, setWarnings] = useState<string[]>([])

  const [manifest, setManifest] = useState<string | null>(null)
  const [manifestLoading, setManifestLoading] = useState(true)
  const [manifestError, setManifestError] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  const loadManifest = useCallback(async () => {
    setManifestLoading(true)
    try {
      const res = await axios.get<unknown>(`${BASE_URL}/.well-known/agent.json`)
      setManifest(JSON.stringify(res.data, null, 2))
      setManifestError(null)
    } catch (err) {
      setManifestError(errorMessage(err))
    } finally {
      setManifestLoading(false)
    }
  }, [])

  const applyConfig = useCallback((c: GatewayConfig) => {
    setConfig(c)
    setTargetUrl(c.targetUrl)
    setRateLimit(String(c.rateLimitPerMinute))
    setRequireAgentApiKey(Boolean(c.requireAgentApiKey))
    setSsoTrustProxyHeader(Boolean(c.ssoTrustProxyHeader))
    setSsoUserHeader(c.ssoUserHeader ?? 'x-forwarded-user')
    setSsoRoleHeader(c.ssoRoleHeader ?? 'x-forwarded-role')
  }, [])

  const loadConfig = useCallback(async () => {
    setLoading(true)
    try {
      const res = await api.get<GatewayConfig>('/config')
      applyConfig(res.data)
      setError(null)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setLoading(false)
    }
  }, [applyConfig])

  useEffect(() => {
    void loadConfig()
    void loadManifest()
  }, [loadConfig, loadManifest])

  useEffect(() => {
    if (!copied) return
    const id = window.setTimeout(() => setCopied(false), 1500)
    return () => window.clearTimeout(id)
  }, [copied])

  const normalizedUrl = targetUrl.trim().replace(/\/+$/, '')
  const dirty =
    config !== null &&
    (normalizedUrl !== config.targetUrl ||
      rateLimit.trim() !== String(config.rateLimitPerMinute) ||
      requireAgentApiKey !== Boolean(config.requireAgentApiKey) ||
      ssoTrustProxyHeader !== Boolean(config.ssoTrustProxyHeader) ||
      ssoUserHeader.trim().toLowerCase() !== (config.ssoUserHeader ?? 'x-forwarded-user') ||
      ssoRoleHeader.trim().toLowerCase() !== (config.ssoRoleHeader ?? 'x-forwarded-role'))

  async function save(e: FormEvent) {
    e.preventDefault()
    if (readOnly) return
    setError(null)
    setProNotice(null)
    setSelfLoopHint(false)
    setSaved(null)
    setWarnings([])

    const n = Number(rateLimit)
    if (rateLimit.trim() === '' || !Number.isInteger(n) || n < 1 || n > 1_000_000) {
      setError('Rate limit must be a whole number between 1 and 1,000,000.')
      return
    }

    setSaving(true)
    try {
      const res = await api.post<
        { success: boolean; config: GatewayConfig; warnings?: string[] } | ProRequiredResponse
      >('/config', {
        targetUrl: targetUrl.trim(),
        rateLimitPerMinute: n,
        requireAgentApiKey,
        ssoTrustProxyHeader,
        ssoUserHeader: ssoUserHeader.trim().toLowerCase(),
        ssoRoleHeader: ssoRoleHeader.trim().toLowerCase(),
      })
      if (isProRequired(res.data)) {
        // SSO is a Pro feature: nothing was saved, so revert the form and show the upgrade callout.
        setProNotice(res.data)
        if (config) applyConfig(config)
        return
      }
      applyConfig({ ...res.data.config, ssoSharedSecretConfigured: res.data.config.ssoSharedSecret !== '' })
      setWarnings(res.data.warnings ?? [])
      setSaved('Settings saved. They apply immediately to the next request.')
      void loadManifest()
    } catch (err) {
      const message = errorMessage(err)
      setError(message)
      setSelfLoopHint(/itself/i.test(message))
    } finally {
      setSaving(false)
    }
  }

  async function copyManifest() {
    if (!manifest) return
    try {
      await navigator.clipboard.writeText(manifest)
      setCopied(true)
    } catch {
      // ignore
    }
  }

  const ssoSecret = config?.ssoSharedSecret ?? ''

  async function copySecret() {
    if (!ssoSecret) return
    try {
      await navigator.clipboard.writeText(ssoSecret)
      setSecretCopied(true)
      window.setTimeout(() => setSecretCopied(false), 1500)
    } catch {
      // ignore
    }
  }

  return (
    <>
      <PageHeader
        title="Gateway Settings & Discovery"
        subtitle="Configure upstream proxy routing, rate limits, Enterprise SSO headers, and preview what agents discover."
      />

      <LicenseCard licenseApi={licenseApi} readOnly={readOnly} />

      {proNotice && (
        <ProCallout message={proNotice.message} upgradeUrl={proNotice.upgradeUrl} onDismiss={() => setProNotice(null)} />
      )}
      {error && <ErrorBanner message={error} onDismiss={() => setError(null)} />}
      {selfLoopHint && (
        <div className="-mt-2 mb-4 rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900">
          <p className="font-medium">The gateway cannot forward to itself.</p>
          <p className="mt-1">
            Set this to the address of your real API server (for example{' '}
            <code className="font-mono">http://localhost:4000</code>), not the gateway&apos;s own address. Leave the
            field empty to use the built-in test endpoints.
          </p>
        </div>
      )}
      {saved && <SuccessBanner message={saved} onDismiss={() => setSaved(null)} />}
      {warnings.map((w) => (
        <WarningBanner key={w}>{w}</WarningBanner>
      ))}

      <form onSubmit={save} className="mb-6 space-y-6 rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <div>
          <div className="flex items-center justify-between gap-3">
            <h2 className="text-sm font-semibold text-slate-900">
              Upstream proxy &amp; rate limit
              {readOnly && <span className="ml-2 text-xs font-medium text-amber-700">(read-only)</span>}
            </h2>
            {config && (
              <Badge tone={config.targetUrl ? 'green' : 'slate'}>
                {config.targetUrl ? 'Proxy mode' : 'Local test mode'}
              </Badge>
            )}
          </div>
          <p className="mt-0.5 text-xs text-slate-500">
            {config?.targetUrl
              ? `Allowed requests are forwarded to ${config.targetUrl}.`
              : 'Allowed requests are served by the built-in dummy endpoints.'}
          </p>

          {loading ? (
            <div className="mt-4 grid animate-pulse gap-4 md:grid-cols-3">
              <div className="h-16 rounded-lg bg-slate-100 md:col-span-2" />
              <div className="h-16 rounded-lg bg-slate-100" />
            </div>
          ) : (
            <div className="mt-4 grid gap-4 md:grid-cols-3">
              <label className="block md:col-span-2">
                <span className="mb-1.5 block text-xs font-medium text-slate-600">Target URL</span>
                <input
                  type="text"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  disabled={readOnly}
                  placeholder="https://api.example.com (empty = local test endpoints)"
                  className={`${INPUT_CLASS} font-mono`}
                />
              </label>
              <label className="block">
                <span className="mb-1.5 block text-xs font-medium text-slate-600">
                  Rate limit (requests / minute / IP)
                </span>
                <input
                  type="number"
                  min={1}
                  step={1}
                  value={rateLimit}
                  onChange={(e) => setRateLimit(e.target.value)}
                  disabled={readOnly}
                  className={INPUT_CLASS}
                />
              </label>
            </div>
          )}
        </div>

        <div className="border-t border-slate-200 pt-5">
          <div className="flex items-start justify-between gap-4">
            <div>
          <label className="flex items-start gap-3 rounded-lg border border-slate-200 bg-slate-50/70 p-3.5">
            <input
              type="checkbox"
              checked={requireAgentApiKey}
              disabled={readOnly}
              onChange={(e) => setRequireAgentApiKey(e.target.checked)}
              className="mt-0.5 h-4 w-4 rounded border-slate-300 text-indigo-600 focus:ring-indigo-500 disabled:opacity-50"
            />
            <div className="text-xs">
              <span className="font-semibold text-slate-900">Require an agent API key</span>
              <p className="mt-0.5 text-slate-500">
                When on, requests to <code className="font-mono">/api/*</code> without a valid key from the list below
                get <code className="font-mono">401 Unauthorized</code>. Create the keys first so your agents are not
                locked out.
              </p>
            </div>
          </label>
        </div>

        <div>
              <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-900">
                Enterprise SSO (Trusted Identity Proxy Headers)
                {!isPro && <ProLockLink onOpen={scrollToLicense} />}
              </h3>
              <p className="mt-0.5 text-xs text-slate-500">
                Integrate Active Directory, Okta, Azure AD (Entra ID), or Google Workspace by placing an identity
                reverse-proxy (Cloudflare Access, OAuth2-Proxy, Authelia, AWS ALB) in front of the gateway.
              </p>
            </div>
            <Badge tone={ssoTrustProxyHeader ? 'violet' : 'slate'}>
              {ssoTrustProxyHeader ? 'SSO Header Active' : 'Local Auth'}
            </Badge>
          </div>

          <label className="mt-4 flex items-start gap-3 rounded-lg border border-slate-200 bg-slate-50/70 p-3.5">
            <input
              type="checkbox"
              checked={ssoTrustProxyHeader}
              disabled={readOnly || (!isPro && !config?.ssoTrustProxyHeader)}
              onChange={(e) => setSsoTrustProxyHeader(e.target.checked)}
              className="mt-0.5 h-4 w-4 rounded border-slate-300 text-indigo-600 focus:ring-indigo-500 disabled:opacity-50"
            />
            <div className="text-xs">
              <span className="font-semibold text-slate-900">Trust identity headers from upstream reverse proxy</span>
              <p className="mt-0.5 text-slate-500">
                Only enable this when the gateway is behind a reverse proxy that strips external identity headers. If
                the role header value is <code className="font-mono">admin</code>, the user receives Admin access;
                otherwise they default to read-only <code className="font-mono">viewer</code> mode.
              </p>
            </div>
          </label>

          {ssoTrustProxyHeader && (
            <div className="mt-3 rounded-lg border border-slate-200 bg-white p-3.5 text-xs">
              <p className="font-semibold text-slate-900">Proxy shared secret</p>
              <p className="mt-0.5 text-slate-500">
                Your identity proxy must send this value as <code className="font-mono">x-gateway-sso-secret</code> on
                every request. Identity headers without it are ignored, so a caller that reaches the gateway directly
                cannot pretend to be an admin.
              </p>
              {ssoSecret ? (
                <div className="mt-2 flex items-center gap-2">
                  <code className="min-w-0 flex-1 break-all rounded-md bg-slate-50 px-3 py-2 font-mono text-slate-800 ring-1 ring-inset ring-slate-200">
                    {showSecret ? ssoSecret : '•'.repeat(32)}
                  </code>
                  <button
                    type="button"
                    onClick={() => setShowSecret((v) => !v)}
                    aria-label={showSecret ? 'Hide secret' : 'Show secret'}
                    className="rounded-lg border border-slate-200 p-2 text-slate-600 hover:bg-slate-50"
                  >
                    {showSecret ? <EyeOff className="h-4 w-4" aria-hidden="true" /> : <Eye className="h-4 w-4" aria-hidden="true" />}
                  </button>
                  <button
                    type="button"
                    onClick={() => void copySecret()}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 px-3 py-2 font-medium text-slate-700 hover:bg-slate-50"
                  >
                    {secretCopied ? <Check className="h-4 w-4" aria-hidden="true" /> : <Copy className="h-4 w-4" aria-hidden="true" />}
                    {secretCopied ? 'Copied' : 'Copy'}
                  </button>
                </div>
              ) : (
                <p className="mt-2 font-medium text-amber-700">
                  {readOnly
                    ? 'Only administrators can see the secret.'
                    : 'A random secret is generated when you save these settings.'}
                </p>
              )}
            </div>
          )}

          {ssoTrustProxyHeader && (
            <div className="mt-4 grid gap-4 md:grid-cols-2">
              <label className="block">
                <span className="mb-1.5 block text-xs font-medium text-slate-600">Authenticated user header name</span>
                <input
                  type="text"
                  value={ssoUserHeader}
                  disabled={readOnly}
                  onChange={(e) => setSsoUserHeader(e.target.value)}
                  placeholder="x-forwarded-user"
                  className={`${INPUT_CLASS} font-mono`}
                />
              </label>
              <label className="block">
                <span className="mb-1.5 block text-xs font-medium text-slate-600">Role header name (admin / viewer)</span>
                <input
                  type="text"
                  value={ssoRoleHeader}
                  disabled={readOnly}
                  onChange={(e) => setSsoRoleHeader(e.target.value)}
                  placeholder="x-forwarded-role"
                  className={`${INPUT_CLASS} font-mono`}
                />
              </label>
            </div>
          )}
        </div>

        <div className="flex justify-end border-t border-slate-100 pt-4">
          <button
            type="submit"
            disabled={saving || loading || !dirty || readOnly}
            title={readOnly ? READ_ONLY_HINT : undefined}
            className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {saving ? <Spinner /> : <Check className="h-4 w-4" aria-hidden="true" />}
            Save settings
          </button>
        </div>
      </form>

      {!readOnly && <AgentKeysPanel required={requireAgentApiKey} isPro={isPro} onOpenLicense={scrollToLicense} />}

      <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-900">
              <Globe className="h-4 w-4 text-slate-400" aria-hidden="true" />
              Agent discovery manifest
            </h2>
            <p className="mt-0.5 font-mono text-xs text-slate-500">
              GET {BASE_URL || `http://${DISPLAY_HOST}`}/.well-known/agent.json
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => void copyManifest()}
              disabled={!manifest}
              className="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3.5 py-2 text-sm font-medium text-slate-700 shadow-sm transition hover:bg-slate-50 disabled:opacity-60"
            >
              {copied ? <Check className="h-4 w-4" aria-hidden="true" /> : <Copy className="h-4 w-4" aria-hidden="true" />}
              {copied ? 'Copied' : 'Copy'}
            </button>
            <RefreshButton onClick={() => void loadManifest()} loading={manifestLoading} />
          </div>
        </div>

        {manifestError && (
          <div className="mt-4">
            <ErrorBanner message={manifestError} />
          </div>
        )}

        <pre className="mt-4 max-h-96 min-h-[8rem] overflow-auto rounded-lg bg-slate-900 p-4 font-mono text-xs leading-relaxed text-emerald-200">
          {manifestLoading && !manifest ? 'Loading…' : manifest ?? 'No data.'}
        </pre>
        <p className="mt-2 text-xs text-slate-500">
          Read-only. Only endpoints in ALLOW or REQUIRE_APPROVAL mode are listed. Edit them in Access Rules.
        </p>
      </div>
    </>
  )
}
