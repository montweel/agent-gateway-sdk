/**
 * Dashboard root: session state machine only.
 *
 * Layout (paths relative to this file):
 *   lib/         api.ts (axios client, token, errors), types.ts, utils.ts
 *   components/  ui.tsx, Sidebar.tsx, ChangePasswordModal.tsx
 *   hooks/       useRules.ts, useApprovals.ts, useDebouncedValue.ts
 *   tabs/        Rules, Approvals, Logs, Analytics, Team, Settings
 *   screens/     AuthScreens.tsx (first-boot setup, sign-in, forced reset), Dashboard.tsx (signed-in shell)
 */
import { useCallback, useEffect, useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { api, AUTH_EXPIRED_EVENT, errorMessage, setAuthToken } from './lib/api'
import type { AuthStatusResponse, AuthUser } from './lib/types'
import { Spinner } from './components/ui'
import { Dashboard } from './screens/Dashboard'
import { CenteredScreen, FirstBootSetupScreen, ForcePasswordResetScreen, SignInScreen } from './screens/AuthScreens'

type AppState =
  | { status: 'loading' }
  | { status: 'offline'; message: string }
  | { status: 'setup'; setupTokenRequired: boolean }
  | { status: 'locked' }
  | { status: 'ready'; user: AuthUser; lastUsedPassword: string }

export default function App() {
  const [state, setState] = useState<AppState>({ status: 'loading' })

  const checkAuth = useCallback(async () => {
    setState({ status: 'loading' })
    try {
      const res = await api.get<AuthStatusResponse>('/auth/status')
      if (res.data.needsSetup) {
        setState({
          status: 'setup',
          setupTokenRequired: Boolean(res.data.requiresSetupToken ?? res.data.setupTokenRequired),
        })
      } else if (res.data.authenticated && res.data.user) {
        setState({ status: 'ready', user: res.data.user, lastUsedPassword: '' })
      } else {
        setState({ status: 'locked' })
      }
    } catch (err) {
      setState({ status: 'offline', message: errorMessage(err) })
    }
  }, [])

  useEffect(() => {
    void checkAuth()
  }, [checkAuth])

  // The server rejected our session while we were using the dashboard (expired, revoked,
  // password reset by an admin): go back to the sign-in screen instead of showing errors everywhere.
  useEffect(() => {
    const onExpired = () => void checkAuth()
    window.addEventListener(AUTH_EXPIRED_EVENT, onExpired)
    return () => window.removeEventListener(AUTH_EXPIRED_EVENT, onExpired)
  }, [checkAuth])

  const handlePasswordSignIn = useCallback(async (username: string, password: string): Promise<string | null> => {
    try {
      const res = await api.post<{ success: boolean; token: string; user: AuthUser }>('/auth/login', {
        username,
        password,
      })
      setAuthToken(res.data.token)
      setState({ status: 'ready', user: res.data.user, lastUsedPassword: password })
      return null
    } catch (err) {
      return errorMessage(err)
    }
  }, [])

  const handleTokenSignIn = useCallback(async (token: string): Promise<string | null> => {
    setAuthToken(token)
    try {
      const res = await api.get<AuthStatusResponse>('/auth/status')
      if (res.data.authenticated && res.data.user) {
        setState({ status: 'ready', user: res.data.user, lastUsedPassword: '' })
        return null
      }
      setAuthToken(null)
      return 'That token was not accepted. Check it and try again.'
    } catch (err) {
      setAuthToken(null)
      return errorMessage(err)
    }
  }, [])

  const handleSignOut = useCallback(async () => {
    try {
      await api.post('/auth/logout')
    } catch {
      // ignore network error during logout
    }
    setAuthToken(null)
    void checkAuth()
  }, [checkAuth])

  if (state.status === 'loading') {
    return (
      <CenteredScreen>
        <div className="flex items-center gap-3 text-sm text-slate-500" role="status">
          <Spinner className="h-5 w-5 text-indigo-500" />
          Checking access…
        </div>
      </CenteredScreen>
    )
  }

  if (state.status === 'offline') {
    return (
      <CenteredScreen>
        <div className="w-full max-w-md rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
          <h1 className="text-lg font-semibold text-slate-900">Could not load the dashboard</h1>
          <p className="mt-2 text-sm text-slate-600">{state.message}</p>
          <button
            type="button"
            onClick={() => void checkAuth()}
            className="mt-4 inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-500"
          >
            <RefreshCw className="h-4 w-4" aria-hidden="true" />
            Try again
          </button>
        </div>
      </CenteredScreen>
    )
  }

  if (state.status === 'setup') {
    return (
      <FirstBootSetupScreen
        setupTokenRequired={state.setupTokenRequired}
        onComplete={(token, user) => {
          setAuthToken(token)
          setState({ status: 'ready', user, lastUsedPassword: '' })
        }}
      />
    )
  }

  if (state.status === 'locked') {
    return <SignInScreen onPasswordSignIn={handlePasswordSignIn} onTokenSignIn={handleTokenSignIn} />
  }

  if (state.user.mustChangePassword) {
    return (
      <ForcePasswordResetScreen
        user={state.user}
        initialCurrentPassword={state.lastUsedPassword}
        onResetComplete={(updatedUser) => setState({ status: 'ready', user: updatedUser, lastUsedPassword: '' })}
        onSignOut={() => void handleSignOut()}
      />
    )
  }

  return <Dashboard user={state.user} onSignOut={() => void handleSignOut()} />
}
