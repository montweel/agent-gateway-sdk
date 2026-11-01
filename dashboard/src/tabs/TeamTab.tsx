import { useCallback, useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import { Check, Copy, KeyRound, Plus, Sparkles, Trash2 } from 'lucide-react'
import { api, errorMessage } from '../lib/api'
import { isProRequired } from '../lib/types'
import type { AuthUser, ProRequiredResponse, TeamUser, UserRole } from '../lib/types'
import { formatTime, INPUT_CLASS } from '../lib/utils'
import { Badge, ErrorBanner, ProCallout, PageHeader, RefreshButton, Spinner } from '../components/ui'
 
interface IssuedCreds {
  username: string
  role?: UserRole
  temporaryPassword: string
  isReset: boolean
}
 
export function TeamTab({ currentUser }: { currentUser: AuthUser }) {
  const [users, setUsers] = useState<TeamUser[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [proNotice, setProNotice] = useState<ProRequiredResponse | null>(null)

  const [newUsername, setNewUsername] = useState('')
  const [newRole, setNewRole] = useState<UserRole>('viewer')
  const [creating, setCreating] = useState(false)
 
  const [issuedCreds, setIssuedCreds] = useState<IssuedCreds | null>(null)
  const [copiedCreds, setCopiedCreds] = useState(false)
  const [busyUserId, setBusyUserId] = useState<number | null>(null)
 
  const loadUsers = useCallback(async () => {
    setLoading(true)
    try {
      const res = await api.get<TeamUser[]>('/users')
      setUsers(res.data)
      setError(null)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setLoading(false)
    }
  }, [])
 
  useEffect(() => {
    void loadUsers()
  }, [loadUsers])
 
  useEffect(() => {
    if (!copiedCreds) return
    const id = window.setTimeout(() => setCopiedCreds(false), 1800)
    return () => window.clearTimeout(id)
  }, [copiedCreds])
 
  async function createUser(e: FormEvent) {
    e.preventDefault()
    if (!newUsername.trim()) return
    setCreating(true)
    setError(null)
    try {
      const res = await api.post<
        { success: boolean; user: TeamUser; temporaryPassword: string } | ProRequiredResponse
      >('/users', {
        username: newUsername.trim(),
        role: newRole,
      })
      const data = res.data
      if (isProRequired(data)) {
        setProNotice(data)
        return
      }
      setProNotice(null)
      setUsers((prev) => [...prev, data.user])
      setIssuedCreds({
        username: data.user.username,
        role: data.user.role,
        temporaryPassword: data.temporaryPassword,
        isReset: false,
      })
      setNewUsername('')
      setNewRole('viewer')
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setCreating(false)
    }
  }
 
  async function resetUserPassword(u: TeamUser) {
    const ok = window.confirm(
      `Generate a new one-time password for "${u.username}"?\n\nTheir current sessions will be signed out and they will be prompted to choose a new password on next sign-in.`
    )
    if (!ok) return
    setBusyUserId(u.id)
    setError(null)
    try {
      const res = await api.post<{ success: boolean; id: number; username: string; temporaryPassword: string }>(
        `/users/${u.id}/reset-password`
      )
      setUsers((prev) => prev.map((item) => (item.id === u.id ? { ...item, mustChangePassword: true } : item)))
      setIssuedCreds({
        username: u.username,
        role: u.role,
        temporaryPassword: res.data.temporaryPassword,
        isReset: true,
      })
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusyUserId(null)
    }
  }
 
  async function changeUserRole(u: TeamUser, role: UserRole) {
    setBusyUserId(u.id)
    setError(null)
    try {
      const res = await api.patch<{ success: boolean; user: TeamUser }>(`/users/${u.id}`, { role })
      setUsers((prev) => prev.map((item) => (item.id === u.id ? res.data.user : item)))
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusyUserId(null)
    }
  }
 
  async function deleteUser(u: TeamUser) {
    const ok = window.confirm(`Delete user "${u.username}"? This cannot be undone.`)
    if (!ok) return
    setBusyUserId(u.id)
    setError(null)
    try {
      await api.delete(`/users/${u.id}`)
      setUsers((prev) => prev.filter((item) => item.id !== u.id))
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusyUserId(null)
    }
  }
 
  async function copyInvite() {
    if (!issuedCreds) return
    const text = `Agent Gateway Console (${window.location.origin}/agent-admin/)\nUsername: ${issuedCreds.username}\nOne-Time Password: ${issuedCreds.temporaryPassword}\n(You will be asked to set your own permanent password when you sign in.)`
    try {
      await navigator.clipboard.writeText(text)
      setCopiedCreds(true)
    } catch {
      // ignore clipboard errors
    }
  }
 
  return (
    <>
      <PageHeader
        title="Team & Users"
        subtitle="Create Admin or read-only Viewer accounts. New users receive a one-time password and set their own password on first sign-in."
        action={<RefreshButton onClick={() => void loadUsers()} loading={loading} />}
      />
 
      {proNotice && (
        <ProCallout message={proNotice.message} upgradeUrl={proNotice.upgradeUrl} onDismiss={() => setProNotice(null)} />
      )}
      {error && <ErrorBanner message={error} onDismiss={() => setError(null)} />}
 
      {issuedCreds && (
        <div className="mb-6 rounded-xl border border-emerald-300 bg-emerald-50/90 p-5 shadow-sm">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h3 className="flex items-center gap-2 text-sm font-semibold text-emerald-950">
                <Sparkles className="h-4 w-4 text-emerald-600" aria-hidden="true" />
                {issuedCreds.isReset
                  ? `One-time password reset for "${issuedCreds.username}"`
                  : `Created account for "${issuedCreds.username}"`}
              </h3>
              <p className="mt-1 text-xs text-emerald-800">
                Share this one-time password with the user. It is only shown once, and they will be required to choose a
                permanent password as soon as they sign in.
              </p>
            </div>
            <button
              type="button"
              onClick={() => setIssuedCreds(null)}
              className="text-xs font-medium text-emerald-800 hover:text-emerald-950"
            >
              Dismiss
            </button>
          </div>
 
          <div className="mt-4 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-emerald-200 bg-white px-4 py-3">
            <div className="space-y-0.5 text-xs">
              <p className="text-slate-500">
                Username: <span className="font-mono font-semibold text-slate-900">{issuedCreds.username}</span>
              </p>
              <p className="text-slate-500">
                One-Time Password:{' '}
                <span className="rounded bg-amber-100 px-2 py-0.5 font-mono text-sm font-bold text-slate-900">
                  {issuedCreds.temporaryPassword}
                </span>
              </p>
            </div>
            <button
              type="button"
              onClick={() => void copyInvite()}
              className="inline-flex items-center gap-2 rounded-lg bg-emerald-600 px-3.5 py-2 text-xs font-semibold text-white shadow-sm transition hover:bg-emerald-500"
            >
              {copiedCreds ? <Check className="h-4 w-4" aria-hidden="true" /> : <Copy className="h-4 w-4" aria-hidden="true" />}
              {copiedCreds ? 'Copied invite!' : 'Copy invite credentials'}
            </button>
          </div>
        </div>
      )}
 
      <form onSubmit={createUser} className="mb-6 rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <h2 className="text-sm font-semibold text-slate-900">Create a team member</h2>
        <p className="mt-0.5 text-xs text-slate-500">
          Admins can edit rules, approve requests, and manage users. Viewers have read-only access to rules and logs.
        </p>
 
        <div className="mt-4 grid gap-4 md:grid-cols-3">
          <label className="block md:col-span-2">
            <span className="mb-1.5 block text-xs font-medium text-slate-600">Username</span>
            <input
              type="text"
              value={newUsername}
              maxLength={64}
              onChange={(e) => setNewUsername(e.target.value)}
              placeholder="e.g. neha, shop-manager, auditor@company.com"
              className={INPUT_CLASS}
            />
          </label>
          <label className="block">
            <span className="mb-1.5 block text-xs font-medium text-slate-600">Role</span>
            <select value={newRole} onChange={(e) => setNewRole(e.target.value as UserRole)} className={INPUT_CLASS}>
              <option value="viewer">Viewer (Read-Only)</option>
              <option value="admin">Admin (Full Access)</option>
            </select>
          </label>
        </div>
 
        <div className="mt-4 flex justify-end">
          <button
            type="submit"
            disabled={creating || newUsername.trim().length < 2}
            className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {creating ? <Spinner /> : <Plus className="h-4 w-4" aria-hidden="true" />}
            Create user &amp; generate password
          </button>
        </div>
      </form>
 
      <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
        <table className="min-w-full divide-y divide-slate-200">
          <thead className="bg-slate-50">
            <tr>
              {['User', 'Role', 'Password Status', 'Created', 'Actions'].map((h) => (
                <th
                  key={h}
                  scope="col"
                  className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500"
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {loading ? (
              [0, 1].map((i) => (
                <tr key={i} className="animate-pulse">
                  {[32, 24, 28, 24, 32].map((w, j) => (
                    <td key={j} className="px-6 py-4">
                      <div className="h-4 rounded bg-slate-200" style={{ width: `${w * 3}px` }} />
                    </td>
                  ))}
                </tr>
              ))
            ) : users.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-6 py-12 text-center text-sm text-slate-500">
                  No local users found.
                </td>
              </tr>
            ) : (
              users.map((u) => {
                const isSelf = u.id === currentUser.id
                const isBusy = busyUserId === u.id
                return (
                  <tr key={u.id} className="transition hover:bg-slate-50">
                    <td className="whitespace-nowrap px-6 py-4">
                      <div className="flex items-center gap-2">
                        <span className="font-medium text-slate-900">{u.username}</span>
                        {isSelf && (
                          <span className="rounded bg-indigo-50 px-2 py-0.5 text-[11px] font-semibold text-indigo-700">
                            You
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="whitespace-nowrap px-6 py-4">
                      <select
                        value={u.role}
                        disabled={isSelf || isBusy}
                        aria-label={`Role for ${u.username}`}
                        onChange={(e) => void changeUserRole(u, e.target.value as UserRole)}
                        title={isSelf ? 'You cannot demote your own account' : 'Change user role'}
                        className="rounded-lg border border-slate-200 bg-white px-2.5 py-1 text-xs font-semibold text-slate-800 shadow-2xs disabled:bg-slate-50 disabled:text-slate-400"
                      >
                        <option value="admin">Admin</option>
                        <option value="viewer">Viewer</option>
                      </select>
                    </td>
                    <td className="whitespace-nowrap px-6 py-4">
                      {u.mustChangePassword ? (
                        <Badge tone="amber">One-Time Password (Pending Reset)</Badge>
                      ) : (
                        <Badge tone="green">Permanent Password Set</Badge>
                      )}
                    </td>
                    <td className="whitespace-nowrap px-6 py-4 text-xs text-slate-500">{formatTime(u.createdAt)}</td>
                    <td className="whitespace-nowrap px-6 py-4">
                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          disabled={isBusy}
                          onClick={() => void resetUserPassword(u)}
                          className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-700 shadow-2xs transition hover:bg-slate-50 disabled:opacity-50"
                        >
                          <KeyRound className="h-3.5 w-3.5 text-slate-400" aria-hidden="true" />
                          Reset OTP
                        </button>
                        <button
                          type="button"
                          disabled={isSelf || isBusy}
                          onClick={() => void deleteUser(u)}
                          title={isSelf ? 'You cannot delete your own account' : `Delete ${u.username}`}
                          aria-label={`Delete ${u.username}`}
                          className="rounded-lg p-1.5 text-slate-400 transition hover:bg-red-50 hover:text-red-600 disabled:cursor-not-allowed disabled:opacity-30"
                        >
                          <Trash2 className="h-4 w-4" aria-hidden="true" />
                        </button>
                      </div>
                    </td>
                  </tr>
                )
              })
            )}
          </tbody>
        </table>
      </div>
    </>
  )
}
 