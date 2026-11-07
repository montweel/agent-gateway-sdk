import axios from 'axios'
 
// =====================================================================
// API client: base URL, session token handling, error text
// =====================================================================
export const BASE_URL =
  typeof window !== 'undefined' && window.location.port === '5173' ? 'http://localhost:3000' : ''
export const DISPLAY_HOST =
  typeof window !== 'undefined' && window.location.port !== '5173'
    ? window.location.host
    : 'localhost:3000'
 
const TOKEN_KEY = 'agent-gateway-token'
 
/** Fired when the server rejects our session mid-use, so the app can return to the sign-in screen. */
export const AUTH_EXPIRED_EVENT = 'agent-gateway:auth-expired'
 
function loadStoredToken(): string | null {
  try {
    return window.sessionStorage.getItem(TOKEN_KEY)
  } catch {
    return null
  }
}
 
let currentToken: string | null = loadStoredToken()
 
export function setAuthToken(token: string | null): void {
  currentToken = token
  try {
    if (token) window.sessionStorage.setItem(TOKEN_KEY, token)
    else window.sessionStorage.removeItem(TOKEN_KEY)
  } catch {
    // ignore storage errors
  }
}
 
export const api = axios.create({
  baseURL: `${BASE_URL}/api/agent-admin`,
})
 
// =====================================================================
// Workspace (client) selection: sent as x-mont-workspace on every admin call.
// 'all' = the "All Clients Overview" (no header: every workspace).
// =====================================================================
const WORKSPACE_KEY = 'mont-workspace'
export const WORKSPACE_CHANGED_EVENT = 'mont:workspace-changed'

function loadWorkspace(): string {
  try {
    return window.localStorage.getItem(WORKSPACE_KEY) || 'default'
  } catch {
    return 'default'
  }
}

let currentWorkspace: string = loadWorkspace()

export function getWorkspace(): string {
  return currentWorkspace
}

export function setWorkspace(slug: string): void {
  if (slug === currentWorkspace) return
  currentWorkspace = slug
  try {
    window.localStorage.setItem(WORKSPACE_KEY, slug)
  } catch {
    // ignore storage errors
  }
  window.dispatchEvent(new Event(WORKSPACE_CHANGED_EVENT))
}

api.interceptors.request.use((config) => {
  if (currentToken) config.headers.set('x-admin-token', currentToken)
  // A request may pin its own scope (e.g. the overview asks for every workspace).
  if (currentWorkspace !== 'all' && !config.headers.has('x-mont-workspace')) {
    config.headers.set('x-mont-workspace', currentWorkspace)
  }
  return config
})
 
// A 401 whose body says role "none" means "no valid session" (as opposed to a wrong
// current password, which also returns 401). Drop the dead token and tell the app.
api.interceptors.response.use(
  (response) => response,
  (err: unknown) => {
    if (axios.isAxiosError(err) && err.response?.status === 401) {
      const data = err.response.data as { role?: unknown } | undefined
      if (data?.role === 'none' && currentToken) {
        setAuthToken(null)
        window.dispatchEvent(new Event(AUTH_EXPIRED_EVENT))
      }
    }
    return Promise.reject(err)
  }
)
 
export function errorMessage(err: unknown): string {
  if (axios.isAxiosError(err)) {
    if (err.response) {
      const data = err.response.data as { message?: unknown; error?: unknown } | undefined
      if (typeof data?.message === 'string') return data.message
      if (typeof data?.error === 'string') return data.error
      if (err.response.status === 401) {
        return 'Your session expired or was not accepted. Please sign in again.'
      }
      return `Request failed (${err.response.status})`
    }
    return `Cannot reach the backend at ${BASE_URL || DISPLAY_HOST}. Is the server running?`
  }
  return 'Something went wrong.'
}
 