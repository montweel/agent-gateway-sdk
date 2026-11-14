import { AlertTriangle, BadgeCheck } from 'lucide-react'

/**
 * Whether an audit row's end user was vouched for by the trusted identity proxy (it sent the SSO
 * shared secret) or only claimed by the agent itself. Auditors should treat the two differently.
 */
export function EndUserBadge({ verified }: { verified: boolean }) {
  return verified ? (
    <span
      className="inline-flex shrink-0 items-center gap-0.5 rounded-full bg-emerald-50 px-1.5 py-0.5 text-[10px] font-semibold text-emerald-800 ring-1 ring-inset ring-emerald-200"
      title="Verified: the trusted identity proxy sent this user together with the SSO shared secret"
    >
      <BadgeCheck className="h-3 w-3" aria-hidden="true" />
      Verified
    </span>
  ) : (
    <span
      className="inline-flex shrink-0 items-center gap-0.5 rounded-full bg-amber-50 px-1.5 py-0.5 text-[10px] font-semibold text-amber-800 ring-1 ring-inset ring-amber-200"
      title="Unverified: the agent named this user itself, without the SSO shared secret. Treat it as a claim."
    >
      <AlertTriangle className="h-3 w-3" aria-hidden="true" />
      Unverified (agent-claimed)
    </span>
  )
}
