import { useState } from 'react'
import { Eye, EyeOff } from 'lucide-react'
import { api, errorMessage } from '../lib/api'
import { Spinner } from './ui'

/** Must match src/core/secretMask.ts: the server never sends a stored credential, only this mask. */
const SECRET_MASK = '••••••••'

/**
 * Password-style input for a credential, with Show / Hide.
 *
 * A saved credential arrives masked ("••••••••abcd"). The box then shows empty with a "Saved … type
 * to replace" hint, so typing replaces it instead of appending to the bullets; the masked value is
 * what gets posted back if nothing is typed, and the server keeps the stored secret for it.
 * Show fetches the real value from GET /secrets/<revealField> (administrators only).
 */
export function SecretInput({
  value,
  onChange,
  revealField,
  placeholder,
  disabled,
  className = '',
  label,
}: {
  value: string
  onChange: (value: string) => void
  /** Server field name for GET /secrets/:field. Without it a saved value cannot be revealed. */
  revealField?: string
  placeholder?: string
  disabled?: boolean
  className?: string
  /** Accessible name, e.g. "Telegram bot token". */
  label: string
}) {
  const [shown, setShown] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const saved = value.startsWith(SECRET_MASK)
  const canReveal = !saved || (Boolean(revealField) && !disabled)

  async function toggle() {
    setError(null)
    if (shown) {
      setShown(false)
      return
    }
    if (saved && revealField) {
      setBusy(true)
      try {
        const res = await api.get<{ value: string }>(`/secrets/${revealField}`)
        onChange(res.data.value)
      } catch (err) {
        setError(errorMessage(err))
        return
      } finally {
        setBusy(false)
      }
    }
    setShown(true)
  }

  return (
    <div>
      <div className="relative">
        <input
          type={shown ? 'text' : 'password'}
          value={saved ? '' : value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={saved ? `Saved (${value}) · type to replace` : placeholder}
          disabled={disabled}
          aria-label={label}
          autoComplete="new-password"
          spellCheck={false}
          data-1p-ignore
          data-lpignore="true"
          className={`${className} pr-10`}
        />
        <button
          type="button"
          onClick={() => void toggle()}
          disabled={busy || !canReveal}
          aria-label={shown ? `Hide ${label}` : `Show ${label}`}
          title={!canReveal ? 'Only administrators can reveal a saved credential.' : shown ? 'Hide' : 'Show'}
          className="absolute inset-y-0 right-0 flex w-9 items-center justify-center text-slate-400 hover:text-slate-700 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {busy ? <Spinner className="h-3.5 w-3.5" /> : shown ? <EyeOff className="h-4 w-4" aria-hidden="true" /> : <Eye className="h-4 w-4" aria-hidden="true" />}
        </button>
      </div>
      {saved && !disabled && (
        <button type="button" onClick={() => onChange('')} className="mt-1 text-xs font-medium text-slate-500 hover:text-red-700">
          Remove saved value
        </button>
      )}
      {error && <p className="mt-1 text-xs text-red-700">{error}</p>}
    </div>
  )
}
