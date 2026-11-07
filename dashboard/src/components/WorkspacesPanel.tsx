import { useState } from 'react'
import type { FormEvent } from 'react'
import { Building2, Copy, KeyRound, Lock, Plus, Save, Trash2 } from 'lucide-react'
import { api, errorMessage, setWorkspace } from '../lib/api'
import type { Workspace } from '../lib/types'
import { INPUT_CLASS, READ_ONLY_HINT } from '../lib/utils'
import type { WorkspacesApi } from './WorkspaceSwitcher'
import { ErrorBanner, Spinner, SuccessBanner } from './ui'

interface Draft {
  name: string
  upstreamUrl: string
  telegramChatId: string
  slackChannel: string
  requireKey: boolean
}

const toDraft = (w: Workspace): Draft => ({
  name: w.name,
  upstreamUrl: w.upstreamUrl ?? '',
  telegramChatId: w.telegramChatId ?? '',
  slackChannel: w.slackChannel ?? '',
  requireKey: w.requireKey,
})

/**
 * Client workspaces (Mont Agency): one installation protecting many stores. Each workspace has its
 * own rules, budgets, upstream, emergency switch, approval chat and API key.
 */
export function WorkspacesPanel({ workspacesApi, readOnly }: { workspacesApi: WorkspacesApi; readOnly: boolean }) {
  const { data, reload } = workspacesApi
  const [form, setForm] = useState<Draft & { slug: string }>({ name: '', slug: '', upstreamUrl: '', telegramChatId: '', slackChannel: '', requireKey: true })
  const [drafts, setDrafts] = useState<Record<string, Draft | undefined>>({})
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [revealed, setRevealed] = useState<{ slug: string; key: string } | null>(null)

  const workspaces = data?.workspaces ?? []
  const license = data?.license
  const atLimit = license ? workspaces.length >= license.maxWorkspaces : false

  async function create(e: FormEvent) {
    e.preventDefault()
    if (readOnly || !form.name.trim()) return
    setBusy('create')
    setError(null)
    try {
      const body: Record<string, unknown> = { name: form.name.trim(), requireKey: form.requireKey }
      if (form.slug.trim()) body.slug = form.slug.trim()
      if (form.upstreamUrl.trim()) body.upstreamUrl = form.upstreamUrl.trim()
      if (form.telegramChatId.trim()) body.telegramChatId = form.telegramChatId.trim()
      if (form.slackChannel.trim()) body.slackChannel = form.slackChannel.trim()
      const res = await api.post<{ workspace: Workspace; apiKey: string }>('/workspaces', body)
      setRevealed({ slug: res.data.workspace.slug, key: res.data.apiKey })
      setNotice(`Workspace "${res.data.workspace.name}" created. Copy its API key now: it is shown only once.`)
      setForm({ name: '', slug: '', upstreamUrl: '', telegramChatId: '', slackChannel: '', requireKey: true })
      await reload()
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(null)
    }
  }

  async function save(w: Workspace) {
    const d = drafts[w.slug]
    if (!d || readOnly) return
    setBusy(w.slug)
    setError(null)
    try {
      const body: Record<string, unknown> = { name: d.name, telegramChatId: d.telegramChatId || null, slackChannel: d.slackChannel || null }
      if (!w.isDefault) {
        body.upstreamUrl = d.upstreamUrl || null
        body.requireKey = d.requireKey
      }
      await api.patch(`/workspaces/${w.slug}`, body)
      setDrafts((p) => ({ ...p, [w.slug]: undefined }))
      setNotice(`Saved "${d.name}".`)
      await reload()
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(null)
    }
  }

  async function rotate(w: Workspace) {
    if (readOnly || !window.confirm(`Create a new API key for "${w.name}"? The current key stops working immediately.`)) return
    setBusy(w.slug)
    setError(null)
    try {
      const res = await api.post<{ apiKey: string }>(`/workspaces/${w.slug}/rotate-key`)
      setRevealed({ slug: w.slug, key: res.data.apiKey })
      setNotice(`New key for "${w.name}". Update the client's agents now: the old key no longer works.`)
      await reload()
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(null)
    }
  }

  async function remove(w: Workspace) {
    if (readOnly || !window.confirm(`Delete workspace "${w.name}"? Its rules are deleted; its audit history is kept.`)) return
    setBusy(w.slug)
    setError(null)
    try {
      await api.delete(`/workspaces/${w.slug}`)
      setNotice(`Workspace "${w.name}" deleted.`)
      await reload()
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(null)
    }
  }

  const field = (slug: string, k: keyof Draft, w: Workspace) => drafts[slug]?.[k] ?? toDraft(w)[k]
  const edit = (w: Workspace, patch: Partial<Draft>) => setDrafts((p) => ({ ...p, [w.slug]: { ...(p[w.slug] ?? toDraft(w)), ...patch } }))

  return (
    <div>
      {error && <ErrorBanner message={error} onDismiss={() => setError(null)} />}
      {notice && <SuccessBanner message={notice} onDismiss={() => setNotice(null)} />}
      {revealed && (
        <div className="mb-4 rounded-lg border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900">
          <p className="font-semibold">API key for “{revealed.slug}” (shown once)</p>
          <div className="mt-2 flex items-center gap-2">
            <code className="min-w-0 flex-1 break-all rounded bg-white px-2 py-1 font-mono text-xs">{revealed.key}</code>
            <button
              type="button"
              onClick={() => void navigator.clipboard?.writeText(revealed.key)}
              className="inline-flex items-center gap-1 rounded-md border border-amber-300 bg-white px-2 py-1 text-xs font-medium"
            >
              <Copy className="h-3.5 w-3.5" aria-hidden="true" /> Copy
            </button>
            <button type="button" onClick={() => setRevealed(null)} className="text-xs underline">
              Done
            </button>
          </div>
          <p className="mt-2 text-xs">
            Agents send it as <code className="font-mono">Authorization: Bearer mws_…</code>, and call <code className="font-mono">/api/w/{revealed.slug}/…</code> or
            add <code className="font-mono">x-mont-workspace: {revealed.slug}</code>.
          </p>
        </div>
      )}

      <p className="mb-3 text-xs text-slate-500">
        {license ? (
          <>
            {workspaces.length} of {license.maxWorkspaces} workspace{license.maxWorkspaces === 1 ? '' : 's'} used on your {license.tier} plan.
            {!license.multiWorkspace && ' Multiple client workspaces need a Mont Pro or Agency key (License & Plan, above).'}
          </>
        ) : (
          'Loading workspaces…'
        )}
      </p>

      <ul className="mb-4 divide-y divide-slate-100 rounded-lg border border-slate-200">
        {workspaces.map((w) => {
          const dirty = drafts[w.slug] !== undefined
          return (
            <li key={w.slug} className="p-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <p className="flex items-center gap-2 text-sm font-semibold text-slate-900">
                  <Building2 className="h-4 w-4 text-indigo-600" aria-hidden="true" />
                  {w.name}
                  <span className="font-mono text-xs font-normal text-slate-400">{w.isDefault ? 'default (rules.json)' : w.slug}</span>
                  {!w.entitled && (
                    <span className="inline-flex items-center gap-1 rounded-full bg-amber-100 px-2 py-0.5 text-[11px] font-semibold text-amber-800">
                      <Lock className="h-3 w-3" aria-hidden="true" /> over plan limit: traffic refused
                    </span>
                  )}
                </p>
                <div className="flex items-center gap-2">
                  <button type="button" onClick={() => setWorkspace(w.slug)} className="text-xs font-semibold text-indigo-600 hover:text-indigo-500">
                    Manage →
                  </button>
                  {!w.isDefault && (
                    <>
                      <button
                        type="button"
                        onClick={() => void rotate(w)}
                        disabled={readOnly || busy !== null}
                        title={readOnly ? READ_ONLY_HINT : 'Issue a new API key'}
                        className="inline-flex items-center gap-1 rounded-md border border-slate-200 px-2 py-1 text-xs text-slate-700 hover:bg-slate-50 disabled:opacity-50"
                      >
                        <KeyRound className="h-3.5 w-3.5" aria-hidden="true" /> {w.hasApiKey ? `${w.apiKeyPrefix}… rotate` : 'Create key'}
                      </button>
                      <button
                        type="button"
                        onClick={() => void remove(w)}
                        disabled={readOnly || busy !== null}
                        title={readOnly ? READ_ONLY_HINT : 'Delete workspace'}
                        aria-label={`Delete ${w.name}`}
                        className="rounded-md p-1.5 text-slate-400 hover:bg-red-50 hover:text-red-600 disabled:opacity-50"
                      >
                        <Trash2 className="h-4 w-4" aria-hidden="true" />
                      </button>
                    </>
                  )}
                </div>
              </div>
              <div className="mt-3 grid gap-3 md:grid-cols-2">
                <label className="block">
                  <span className="mb-1 block text-xs font-medium text-slate-600">Name</span>
                  <input className={INPUT_CLASS} value={field(w.slug, 'name', w) as string} disabled={readOnly} onChange={(e) => edit(w, { name: e.target.value })} />
                </label>
                <label className="block">
                  <span className="mb-1 block text-xs font-medium text-slate-600">Upstream URL</span>
                  <input
                    className={`${INPUT_CLASS} font-mono`}
                    value={w.isDefault ? 'config.json targetUrl (Gateway Setup)' : (field(w.slug, 'upstreamUrl', w) as string)}
                    disabled={readOnly || w.isDefault}
                    placeholder="https://client-store.example.com (blank = global target)"
                    onChange={(e) => edit(w, { upstreamUrl: e.target.value })}
                  />
                </label>
                <label className="block">
                  <span className="mb-1 block text-xs font-medium text-slate-600">Telegram chat for approvals</span>
                  <input
                    className={`${INPUT_CLASS} font-mono`}
                    value={field(w.slug, 'telegramChatId', w) as string}
                    disabled={readOnly}
                    placeholder="blank = the global chat"
                    onChange={(e) => edit(w, { telegramChatId: e.target.value })}
                  />
                </label>
                <label className="block">
                  <span className="mb-1 block text-xs font-medium text-slate-600">Slack channel (Socket Mode)</span>
                  <input
                    className={`${INPUT_CLASS} font-mono`}
                    value={field(w.slug, 'slackChannel', w) as string}
                    disabled={readOnly}
                    placeholder="blank = the global channel"
                    onChange={(e) => edit(w, { slackChannel: e.target.value })}
                  />
                </label>
              </div>
              <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
                {!w.isDefault ? (
                  <label className="inline-flex items-center gap-2 text-xs text-slate-700">
                    <input
                      type="checkbox"
                      checked={field(w.slug, 'requireKey', w) as boolean}
                      disabled={readOnly}
                      onChange={(e) => edit(w, { requireKey: e.target.checked })}
                      className="h-4 w-4 rounded border-slate-300"
                    />
                    Require this workspace's API key (recommended: stops one client's agent acting on another's store)
                  </label>
                ) : (
                  <span className="text-xs text-slate-500">The default workspace uses rules.json and your global settings; agents need no workspace key.</span>
                )}
                {dirty && (
                  <button
                    type="button"
                    onClick={() => void save(w)}
                    disabled={readOnly || busy !== null}
                    className="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-indigo-500 disabled:opacity-60"
                  >
                    {busy === w.slug ? <Spinner className="h-3.5 w-3.5" /> : <Save className="h-3.5 w-3.5" aria-hidden="true" />}
                    Save
                  </button>
                )}
              </div>
            </li>
          )
        })}
      </ul>

      <form onSubmit={create} className="rounded-lg border border-dashed border-slate-300 p-4">
        <p className="text-sm font-semibold text-slate-900">Add a client workspace</p>
        <div className="mt-3 grid gap-3 md:grid-cols-3">
          <input className={INPUT_CLASS} placeholder="Client name, e.g. Acme Outfitters" value={form.name} disabled={readOnly} onChange={(e) => setForm({ ...form, name: e.target.value })} />
          <input className={`${INPUT_CLASS} font-mono`} placeholder="slug (optional)" value={form.slug} disabled={readOnly} onChange={(e) => setForm({ ...form, slug: e.target.value })} />
          <input
            className={`${INPUT_CLASS} font-mono`}
            placeholder="Upstream URL (optional)"
            value={form.upstreamUrl}
            disabled={readOnly}
            onChange={(e) => setForm({ ...form, upstreamUrl: e.target.value })}
          />
          <input
            className={`${INPUT_CLASS} font-mono`}
            placeholder="Telegram chat id (optional)"
            value={form.telegramChatId}
            disabled={readOnly}
            onChange={(e) => setForm({ ...form, telegramChatId: e.target.value })}
          />
          <input
            className={`${INPUT_CLASS} font-mono`}
            placeholder="Slack channel id (optional)"
            value={form.slackChannel}
            disabled={readOnly}
            onChange={(e) => setForm({ ...form, slackChannel: e.target.value })}
          />
          <button
            type="submit"
            disabled={readOnly || busy !== null || !form.name.trim() || atLimit}
            title={readOnly ? READ_ONLY_HINT : atLimit ? 'Your plan has no free workspace left' : undefined}
            className="inline-flex items-center justify-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {busy === 'create' ? <Spinner /> : <Plus className="h-4 w-4" aria-hidden="true" />}
            Create workspace
          </button>
        </div>
        {atLimit && <p className="mt-2 text-xs text-amber-700">Your plan's workspace limit is reached. Activate a Mont Agency key for more clients.</p>}
      </form>
    </div>
  )
}
