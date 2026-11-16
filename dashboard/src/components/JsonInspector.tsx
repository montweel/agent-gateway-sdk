import { useState } from 'react'
import { AlertTriangle, ChevronDown, ChevronRight } from 'lucide-react'

/** Keys that deserve a second look before approving (substring, case-insensitive). Mirrors the server list. */
const HIGH_RISK_FIELDS = ['amount', 'price', 'delete', 'email', 'destination']

function isHighRiskKey(key: string): boolean {
  const k = key.toLowerCase()
  return HIGH_RISK_FIELDS.some((r) => k.includes(r))
}

interface RiskHit {
  path: string
  value: unknown
}

/** Every primitive value under a high-risk key, as dot paths. */
function findHighRisk(value: unknown, prefix = 'body', depth = 0, out: RiskHit[] = []): RiskHit[] {
  if (depth > 12 || out.length >= 50) return out
  if (Array.isArray(value)) {
    value.forEach((v, i) => findHighRisk(v, `${prefix}.${i}`, depth + 1, out))
  } else if (typeof value === 'object' && value !== null) {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      const p = `${prefix}.${k}`
      if (isHighRiskKey(k) && (typeof v !== 'object' || v === null)) out.push({ path: p, value: v })
      findHighRisk(v, p, depth + 1, out)
    }
  }
  return out
}

function parseJsonSafe(text: string | null | undefined): { ok: true; value: unknown } | { ok: false; raw: string } | null {
  if (text === null || text === undefined || text === '') return null
  try {
    return { ok: true, value: JSON.parse(text) as unknown }
  } catch {
    return { ok: false, raw: text }
  }
}

function Primitive({ value }: { value: unknown }) {
  if (value === null) return <span className="text-slate-400">null</span>
  // Long values (justifications, tokens, URLs) wrap inside the box instead of widening the page.
  if (typeof value === 'string') return <span className="whitespace-pre-wrap text-emerald-300 [overflow-wrap:anywhere]">"{value}"</span>
  if (typeof value === 'number') return <span className="text-amber-300">{String(value)}</span>
  if (typeof value === 'boolean') return <span className="text-violet-300">{String(value)}</span>
  return <span className="text-slate-300">{String(value)}</span>
}

function Node({
  name,
  value,
  depth,
  defaultExpandDepth,
  risky,
  isLast,
}: {
  name: string | null
  value: unknown
  depth: number
  defaultExpandDepth: number
  risky: boolean
  isLast: boolean
}) {
  const [open, setOpen] = useState(depth < defaultExpandDepth)
  const isArray = Array.isArray(value)
  const isObject = typeof value === 'object' && value !== null
  const comma = isLast ? '' : ','
  const keyLabel =
    name === null ? null : (
      <span className={risky ? 'rounded bg-red-500/25 px-1 font-semibold text-red-200 ring-1 ring-red-400/60' : 'text-sky-300'}>
        {risky && <AlertTriangle className="mr-1 inline h-3 w-3 -translate-y-px text-red-300" aria-label="High-risk field" />}"{name}"
      </span>
    )

  if (!isObject) {
    return (
      <div className={`pl-4 ${risky ? 'bg-red-500/10' : ''}`}>
        {keyLabel}
        {keyLabel && <span className="text-slate-500">: </span>}
        <Primitive value={value} />
        <span className="text-slate-500">{comma}</span>
      </div>
    )
  }

  const entries: [string, unknown][] = isArray
    ? (value as unknown[]).map((v, i) => [String(i), v])
    : Object.entries(value as Record<string, unknown>)
  const [openBrace, closeBrace] = isArray ? ['[', ']'] : ['{', '}']

  return (
    <div className="pl-4">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="-ml-4 inline-flex items-center text-left hover:text-white"
        aria-expanded={open}
      >
        {open ? (
          <ChevronDown className="h-3.5 w-3.5 text-slate-500" aria-hidden="true" />
        ) : (
          <ChevronRight className="h-3.5 w-3.5 text-slate-500" aria-hidden="true" />
        )}
        {keyLabel}
        {keyLabel && <span className="text-slate-500">: </span>}
        <span className="text-slate-400">{openBrace}</span>
        {!open && (
          <span className="text-slate-500">
            {' '}
            {entries.length} {isArray ? 'items' : 'keys'} {closeBrace}
            {comma}
          </span>
        )}
      </button>
      {open && (
        <>
          {entries.map(([k, v], i) => (
            <Node
              key={k}
              name={isArray ? null : k}
              value={v}
              depth={depth + 1}
              defaultExpandDepth={defaultExpandDepth}
              risky={!isArray && isHighRiskKey(k)}
              isLast={i === entries.length - 1}
            />
          ))}
          <div>
            <span className="text-slate-400">{closeBrace}</span>
            <span className="text-slate-500">{comma}</span>
          </div>
        </>
      )}
    </div>
  )
}

/** The dark box: never wider than its parent, scrolls (both ways) inside itself, text wraps anywhere. */
const BOX = 'min-w-0 max-w-full overflow-auto rounded-lg bg-slate-900 p-3 font-mono text-xs leading-relaxed text-slate-100 [overflow-wrap:anywhere]'

/** Collapsible, syntax-highlighted JSON tree. High-risk keys are flagged in red. */
export function JsonInspector({
  text,
  emptyLabel = 'No body',
  defaultExpandDepth = 3,
  maxHeight = 'max-h-[300px]',
}: {
  text: string | null | undefined
  emptyLabel?: string
  defaultExpandDepth?: number
  maxHeight?: string
}) {
  const parsed = parseJsonSafe(text)
  if (parsed === null) {
    return <p className="rounded-lg bg-slate-50 px-3 py-2 text-xs text-slate-500">{emptyLabel}</p>
  }
  if (!parsed.ok) {
    return (
      <pre className={`${maxHeight} ${BOX} whitespace-pre-wrap`}>{parsed.raw}</pre>
    )
  }
  return (
    <div className={`${maxHeight} ${BOX}`}>
      <div className="-ml-4">
        <Node name={null} value={parsed.value} depth={0} defaultExpandDepth={defaultExpandDepth} risky={false} isLast />
      </div>
    </div>
  )
}

/** Chips summarising every high-risk value found in a JSON body. */
export function HighRiskSummary({ text }: { text: string | null | undefined }) {
  const parsed = parseJsonSafe(text)
  if (!parsed || !parsed.ok) return null
  const hits = findHighRisk(parsed.value)
  if (hits.length === 0) return null
  return (
    <div className="mb-2 rounded-lg border border-red-200 bg-red-50 px-3 py-2">
      <p className="mb-1.5 flex items-center gap-1.5 text-xs font-semibold text-red-800">
        <AlertTriangle className="h-3.5 w-3.5" aria-hidden="true" />
        High-risk fields: check these before approving
      </p>
      <div className="flex flex-wrap gap-1.5">
        {hits.map((h) => (
          <span key={h.path} className="rounded-md bg-white px-2 py-0.5 font-mono text-xs text-red-800 ring-1 ring-inset ring-red-200">
            {h.path} = <strong>{JSON.stringify(h.value)}</strong>
          </span>
        ))}
      </div>
    </div>
  )
}
