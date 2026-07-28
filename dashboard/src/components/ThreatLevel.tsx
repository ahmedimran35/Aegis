import { useEffect, useState } from 'react'
import { ShieldAlert, Activity, AlertOctagon } from 'lucide-react'

interface ThreatEvent {
  id: number
  timestamp: string
  action: string
  threat_score: number
  ai_classification: string
  path?: string
}

interface Props {
  className?: string
  pollIntervalMs?: number
  windowMin?: number
}

// =============================================================================
//
// Ultra-simple Threat Level display — ZERO gauge, ZERO bar, ZERO needle.
// The data is real (WAF request_logs in Postgres) but the user keeps
// interpreting "100%" + a thin red bar as "2 indicators". To eliminate
// that ambiguity, this version uses ONLY ONE big colored status banner
// plus a grid of real KPI values from the live WAF.
//
// =============================================================================

export default function ThreatLevel({ className = '', pollIntervalMs = 5000, windowMin = 60 }: Props) {
  const [events, setEvents] = useState<ThreatEvent[]>([])
  const [tick, setTick] = useState(0)
  const [error, setError] = useState<string | null>(null)
  const [lastFetchTs, setLastFetchTs] = useState<string | null>(null)

  useEffect(() => {
    let alive = true
    const fetchOnce = async () => {
      if (!alive) return
      try {
        const r = await fetch(`/api/v1/dashboard/threat-events?minutes=${windowMin}`, { credentials: 'same-origin' })
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        const d = await r.json()
        const list = (d?.data || d) as ThreatEvent[]
        if (Array.isArray(list)) {
          setEvents(list)
          setTick((n) => n + 1)
          setLastFetchTs(new Date().toISOString())
          setError(null)
        }
      } catch (e: any) {
        setError(e?.message || 'fetch failed')
      }
    }
    fetchOnce()
    const t = setInterval(fetchOnce, pollIntervalMs)
    return () => { alive = false; clearInterval(t) }
  }, [pollIntervalMs, windowMin])

  // Compute metrics. The backend already filters to the last
  // `windowMin` minutes via the `?minutes=N` query param, so we use
  // the returned events directly.
  const total = events.length
  const blocked = events.filter((e) => /^block/i.test(e.action || '')).length
  const malicious = events.filter((e) => /malicious/.test(e.ai_classification || '')).length
  const scores = events.map((e) => e.threat_score || 0)
  const avgScore = scores.length ? scores.reduce((s, n) => s + n, 0) / scores.length : 0
  const level = Math.min(1, malicious * 0.05 + avgScore * 0.6)
  const pct = Math.round(level * 100)

  // Status text + color (LOW / ELEVATED / CRITICAL).
  const band = level < 0.25
    ? { name: 'LOW',      bg: 'bg-emerald-600', text: 'text-white', ring: 'ring-emerald-500/40' }
    : level < 0.6
    ? { name: 'ELEVATED', bg: 'bg-amber-600',   text: 'text-white', ring: 'ring-amber-500/40' }
    : { name: 'CRITICAL', bg: 'bg-rose-600',     text: 'text-white', ring: 'ring-rose-500/40' }

  // Recent sample (last 3) for the "this is real" proof.
  const recent = events.slice(0, 3)
  const secondsAgo = lastFetchTs
    ? Math.max(0, Math.floor((Date.now() - new Date(lastFetchTs).getTime()) / 1000))
    : null

  return (
    <div className={`flex flex-col h-full bg-slate-950 text-slate-100 ${className}`}>
      {/* Header */}
      <div className="flex items-center gap-2 px-3 py-2 border-b border-slate-800 bg-slate-900/60 flex-shrink-0">
        <ShieldAlert size={14} className={band.text} />
        <span className="text-sm font-bold text-slate-100 tracking-wide uppercase">Threat level</span>
        <span className={`ml-auto text-[10px] font-mono px-2 py-0.5 rounded ${band.bg} ${band.text}`}>
          {band.name}
        </span>
      </div>

      {error && (
        <div className="px-3 py-1.5 text-[11px] text-rose-300 bg-rose-950/40 border-b border-rose-900/50 font-mono">
          error: {error}
        </div>
      )}

      {/* ONE big status banner — the only "indicator" in the panel.
          No gauge, no bar, no needle, no track. The text on the banner
          encodes the same level as the old "100%" did, but as a single
          readable label that cannot be confused with a second line. */}
      <div className="flex-1 flex items-center justify-center p-4 min-h-0">
        <div
          className={`${band.bg} ${band.text} ${band.ring} ring-2 rounded-lg px-8 py-6 text-center shadow-lg`}
          data-testid="threat-level-banner"
        >
          <div className="text-3xl font-black tracking-wider uppercase">
            {band.name}
          </div>
          <div className="text-sm font-mono opacity-90 mt-1">
            {blocked}/{total} blocked · {malicious} malicious
          </div>
        </div>
      </div>

      {/* Recent sample events — proves the data is real, not hardcoded */}
      {recent.length > 0 && (
        <div className="px-3 py-2 border-t border-slate-800 bg-slate-900/30 flex-shrink-0">
          <div className="text-[9px] uppercase tracking-wider text-slate-500 font-mono mb-1">
            Live sample (last {recent.length})
          </div>
          <ul className="space-y-0.5 font-mono text-[10px] text-slate-300">
            {recent.map((e) => (
              <li key={e.id} className="flex items-center gap-2 truncate">
                <span className={`inline-block w-2 h-2 rounded-full ${e.threat_score >= 0.7 ? 'bg-rose-500' : 'bg-amber-500'}`} />
                <span className="text-slate-400">{e.timestamp.slice(11, 19)}</span>
                <span className="text-slate-200 truncate flex-1">{e.path}</span>
                <span className="text-slate-500">{e.action}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* 4 KPI cards — real data from the live WAF */}
      <div className="grid grid-cols-2 gap-1.5 p-2 border-t border-slate-800 text-[10px] flex-shrink-0">
        <KPI icon={<Activity size={10} />} label="events" value={total} sub={`last ${windowMin}m`} />
        <KPI icon={<ShieldAlert size={10} />} label="blocked" value={blocked} sub={`${total ? Math.round((blocked / total) * 100) : 0}% rate`} />
        <KPI icon={<AlertOctagon size={10} />} label="malicious" value={malicious} sub="AI-tagged" />
        <KPI icon={<Activity size={10} />} label="avg score" value={avgScore.toFixed(2)} sub="0.0 – 1.0" />
      </div>

      {/* Freshness footer */}
      <div className="px-3 py-1 border-t border-slate-800 text-[9px] font-mono text-slate-500 flex items-center justify-between flex-shrink-0">
        <span>
          {lastFetchTs
            ? `refreshed ${secondsAgo}s ago · ${events.length} events · threat ${pct}%`
            : 'loading…'}
        </span>
        <span>tick {tick}</span>
      </div>
    </div>
  )
}

function KPI({ icon, label, value, sub }: { icon: React.ReactNode; label: string; value: number | string; sub?: string }) {
  return (
    <div className="rounded border border-slate-800 bg-slate-900/40 px-2 py-1.5">
      <div className="flex items-center gap-1 text-[9px] uppercase tracking-wider text-slate-400 font-mono">
        {icon}
        <span>{label}</span>
      </div>
      <div className="text-sm font-mono font-bold text-slate-100">{value}</div>
      {sub && <div className="text-[9px] text-slate-500 font-mono">{sub}</div>}
    </div>
  )
}
