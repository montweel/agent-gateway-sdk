import { useState } from 'react'
import type { FormEvent, ReactNode } from 'react'
import { AlertCircle, KeyRound, Lock, Sparkles } from 'lucide-react'
import { api, errorMessage } from '../lib/api'
import type { AuthUser } from '../lib/types'
import { INPUT_CLASS } from '../lib/utils'
import { Spinner } from '../components/ui'

export function CenteredScreen({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-100 px-4 py-8 font-sans text-slate-900">
      {children}
    </div>
  )
}

function FormError({ message }: { message: string }) {
  return (
    <p role="alert" className="mt-3 flex items-start gap-2 text-sm text-red-600">
      <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
      {message}
    </p>
  )
}

export function FirstBootSetupScreen({
  setupTokenRequired,
  onComplete,
}: {
  setupTokenRequired: boolean
  onComplete: (token: string, user: AuthUser) => void
}) {
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [setupToken, setSetupToken] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    if (password.length < 8) {
      setError('Password must be at least 8 characters.')
      return
    }
    if (password !== confirm) {
      setError('Passwords do not match.')
      return
    }

    setBusy(true)
    try {
      const res = await api.post<{ success: boolean; token: string; user: AuthUser }>(
        '/auth/setup',
        { username: username.trim(), password, ...(setupTokenRequired ? { setupToken: setupToken.trim() } : {}) }
      )
      onComplete(res.data.token, res.data.user)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <CenteredScreen>
      <form onSubmit={submit} className="w-full max-w-md rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
        <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-gradient-to-br from-indigo-500 to-violet-600 text-white shadow-lg shadow-indigo-900/20">
          <Sparkles className="h-5 w-5" aria-hidden="true" />
        </div>
        <h1 className="mt-4 text-lg font-semibold text-slate-900">Welcome to Agent Gateway</h1>
        <p className="mt-1 text-sm text-slate-500">
          Create your Owner Admin account to get started. No terminal or config file edits needed—you can invite
          additional team members right from the dashboard.
        </p>
        {setupTokenRequired && (
          <p className="mt-2 rounded-lg bg-slate-50 px-3 py-2 text-xs text-slate-600">
            You are not on the server itself, so enter the setup key shown in the server console when the gateway
            started (or open this page from the server&apos;s own machine).
          </p>
        )}

        <div className="mt-5 space-y-4">
          {setupTokenRequired && (
            <label className="block">
              <span className="mb-1.5 block text-xs font-medium text-slate-600">Setup key</span>
              <input
                type="password"
                required
                value={setupToken}
                onChange={(e) => setSetupToken(e.target.value)}
                placeholder="setup_… (printed in the server console)"
                autoComplete="off"
                className={`${INPUT_CLASS} font-mono`}
              />
            </label>
          )}
          <label className="block">
            <span className="mb-1.5 block text-xs font-medium text-slate-600">Owner username</span>
            <input
              type="text"
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              className={INPUT_CLASS}
              autoFocus
            />
          </label>
          <label className="block">
            <span className="mb-1.5 block text-xs font-medium text-slate-600">Password (min 8 characters)</span>
            <input
              type="password"
              required
              minLength={8}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="new-password"
              placeholder="Choose a strong password"
              className={INPUT_CLASS}
            />
          </label>
          <label className="block">
            <span className="mb-1.5 block text-xs font-medium text-slate-600">Confirm password</span>
            <input
              type="password"
              required
              minLength={8}
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              autoComplete="new-password"
              placeholder="Re-enter your password"
              className={INPUT_CLASS}
            />
          </label>
        </div>

        {error && <FormError message={error} />}

        <button
          type="submit"
          disabled={busy || !username.trim() || !password || !confirm || (setupTokenRequired && !setupToken.trim())}
          className="mt-5 inline-flex w-full items-center justify-center gap-2 rounded-lg bg-indigo-600 px-4 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {busy && <Spinner />}
          Create owner account &amp; continue
        </button>
      </form>
    </CenteredScreen>
  )
}

export function SignInScreen({
  onPasswordSignIn,
  onTokenSignIn,
}: {
  onPasswordSignIn: (username: string, password: string) => Promise<string | null>
  onTokenSignIn: (token: string) => Promise<string | null>
}) {
  const [useTokenMode, setUseTokenMode] = useState(false)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [token, setToken] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    const err = useTokenMode ? await onTokenSignIn(token.trim()) : await onPasswordSignIn(username.trim(), password)
    setBusy(false)
    if (err) setError(err)
  }

  return (
    <CenteredScreen>
      <form onSubmit={submit} className="w-full max-w-sm rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
        <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-gradient-to-br from-indigo-500 to-violet-600 text-white shadow-lg shadow-indigo-900/20">
          <Lock className="h-5 w-5" aria-hidden="true" />
        </div>
        <h1 className="mt-4 text-lg font-semibold text-slate-900">Sign in to Agent Gateway</h1>
        <p className="mt-1 text-sm text-slate-500">
          {useTokenMode
            ? 'Enter a static ADMIN_TOKEN or VIEWER_TOKEN configured on the server.'
            : 'Sign in with your username and password (or a one-time password shared by your admin).'}
        </p>

        {useTokenMode ? (
          <label className="mt-5 block">
            <span className="mb-1.5 block text-xs font-medium text-slate-600">Access token</span>
            <input
              type="password"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              autoFocus
              autoComplete="off"
              placeholder="Paste your static token"
              className={`${INPUT_CLASS} font-mono`}
            />
          </label>
        ) : (
          <div className="mt-5 space-y-4">
            <label className="block">
              <span className="mb-1.5 block text-xs font-medium text-slate-600">Username</span>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoFocus
                autoComplete="username"
                placeholder="admin"
                className={INPUT_CLASS}
              />
            </label>
            <label className="block">
              <span className="mb-1.5 block text-xs font-medium text-slate-600">Password</span>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                placeholder="••••••••"
                className={INPUT_CLASS}
              />
            </label>
          </div>
        )}

        {error && <FormError message={error} />}

        <button
          type="submit"
          disabled={busy || (useTokenMode ? !token.trim() : !username.trim() || !password)}
          className="mt-5 inline-flex w-full items-center justify-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {busy && <Spinner />}
          Sign in
        </button>

        <div className="mt-4 text-center">
          <button
            type="button"
            onClick={() => {
              setUseTokenMode((v) => !v)
              setError(null)
            }}
            className="text-xs font-medium text-slate-500 hover:text-indigo-600"
          >
            {useTokenMode ? 'Use username & password instead' : 'Have an environment API token? Sign in with token'}
          </button>
        </div>
      </form>
    </CenteredScreen>
  )
}

export function ForcePasswordResetScreen({
  user,
  initialCurrentPassword,
  onResetComplete,
  onSignOut,
}: {
  user: AuthUser
  initialCurrentPassword: string
  onResetComplete: (updatedUser: AuthUser) => void
  onSignOut: () => void
}) {
  const [currentPassword, setCurrentPassword] = useState(initialCurrentPassword)
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    if (newPassword.length < 8) {
      setError('New password must be at least 8 characters.')
      return
    }
    if (newPassword !== confirmPassword) {
      setError('New passwords do not match.')
      return
    }

    setBusy(true)
    try {
      const res = await api.post<{ success: boolean; user: AuthUser }>('/auth/change-password', {
        currentPassword,
        newPassword,
      })
      onResetComplete(res.data.user)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <CenteredScreen>
      <form onSubmit={submit} className="w-full max-w-md rounded-xl border border-amber-300 bg-white p-6 shadow-sm">
        <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-amber-500 text-white shadow-sm">
          <KeyRound className="h-5 w-5" aria-hidden="true" />
        </div>
        <h1 className="mt-4 text-lg font-semibold text-slate-900">Set your permanent password</h1>
        <p className="mt-1 text-sm text-slate-500">
          Hi <span className="font-semibold text-slate-800">{user.username}</span>, you signed in with a one-time
          password. Please choose a new personal password to unlock the dashboard.
        </p>

        <div className="mt-5 space-y-4">
          {!initialCurrentPassword && (
            <label className="block">
              <span className="mb-1.5 block text-xs font-medium text-slate-600">One-time password</span>
              <input
                type="password"
                required
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                autoComplete="current-password"
                placeholder="Paste your tmp_... password"
                className={`${INPUT_CLASS} font-mono`}
              />
            </label>
          )}
          <label className="block">
            <span className="mb-1.5 block text-xs font-medium text-slate-600">New password (min 8 characters)</span>
            <input
              type="password"
              required
              minLength={8}
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              autoFocus
              autoComplete="new-password"
              placeholder="Choose a strong password"
              className={INPUT_CLASS}
            />
          </label>
          <label className="block">
            <span className="mb-1.5 block text-xs font-medium text-slate-600">Confirm new password</span>
            <input
              type="password"
              required
              minLength={8}
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              autoComplete="new-password"
              placeholder="Re-enter your new password"
              className={INPUT_CLASS}
            />
          </label>
        </div>

        {error && <FormError message={error} />}

        <button
          type="submit"
          disabled={busy || !currentPassword || !newPassword || !confirmPassword}
          className="mt-5 inline-flex w-full items-center justify-center gap-2 rounded-lg bg-indigo-600 px-4 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {busy && <Spinner />}
          Save password &amp; enter dashboard
        </button>

        <div className="mt-4 text-center">
          <button
            type="button"
            onClick={onSignOut}
            className="text-xs font-medium text-slate-400 hover:text-slate-600"
          >
            Sign out
          </button>
        </div>
      </form>
    </CenteredScreen>
  )
}
