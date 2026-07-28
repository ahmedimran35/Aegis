import React, { useEffect, useState } from 'react'
import { Shield, Wifi, Globe, Activity, Database, Lock, CheckCircle2, AlertTriangle, RefreshCw, Server, Cpu, type LucideIcon } from 'lucide-react'

// ActiveDefenses — P-FREE-1..5 in-cluster protection layers.
//
// IMPORTANT: this page uses RAW fetch() with absolute paths instead of
// apiGet/usePolling. This is deliberate: apiGet prepends BASE_URL='/api/v1'
// and any stale caller that also passes '/api/v1/...' would double-prefix
// the path. Bypassing the helper here removes that class of bug entirely.
// Each fetch sends credentials: 'same-origin' so the HttpOnly session
// cookie travels automatically.

interface WSGuardStats {
  upgrades_allowed: number
  upgrades_blocked: number
  messages_blocked: number
  origins_rejected: number
  config: string
  frame_limit: number
}
interface ThreatFeedStats {
  sources: number
  last_fetch: string
  last_error: string
  total_ips: number
  feeds: Record<string, number>
  checks: number
  hits: number
  blocks: number
}
interface CRSUpdateStats {
  last_fetch: string
  last_error: string
  imported: number
  skipped: number
  ref: string
  interval: string
}
interface AnomalyStatsStats {
  requests_scanned: number
  entropy_blocks: number
  zscore_blocks: number
  errors: number
}

type LoadState<T> = { data: T | null; err: string | null; loading: boolean; status: number }

async function rawGet<T>(path: string): Promise<LoadState<T>> {
  // path is ABSOLUTE (starts with /api/v1). No helper indirection.
  try {
    const res = await fetch(path, { credentials: 'same-origin' })
    const text = await res.text()
    let json: any = null
    try { json = JSON.parse(text) } catch { /* not JSON */ }
    if (!res.ok) {
      return { data: null, err: `HTTP ${res.status} ${res.statusText}`, loading: false, status: res.status }
    }
    if (json && json.success === false) {
      return { data: null, err: json.error?.message || 'API error', loading: false, status: res.status }
    }
    const payload = json && 'data' in json ? json.data : json
    return { data: payload as T, err: null, loading: false, status: res.status }
  } catch (e) {
    return { data: null, err: e instanceof Error ? e.message : String(e), loading: false, status: 0 }
  }
}

function useRawPolled<T>(path: string, ms: number): LoadState<T> {
  const [state, setState] = useState<LoadState<T>>({ data: null, err: null, loading: true, status: 0 })
  useEffect(() => {
    let cancelled = false
    const tick = async () => {
      const next = await rawGet<T>(path)
      if (!cancelled) setState(next)
    }
    tick()
    const id = setInterval(tick, ms)
    return () => { cancelled = true; clearInterval(id) }
  }, [path, ms])
  return state
}

function fmtNum(n: number | undefined | null): string {
  if (n == null) return '—'
  return n.toLocaleString()
}

function fmtTime(iso: string | undefined | null): string {
  if (!iso || iso.startsWith('0001-01-01')) return '—'
  return new Date(iso).toLocaleString()
}

// Visible build marker — bumped on every rebuild so the user can confirm
// they're looking at the latest bundle. Read from the same VITE_BUILD_HASH
// value the TopBar shows (set by vite.config.ts at config-time).
const BUILD_TAG = (import.meta.env.VITE_BUILD_HASH as string) || 'dev'

export default function ActiveDefenses() {
  const ws   = useRawPolled<WSGuardStats>('/api/v1/dashboard/wsguard/stats', 10000)
  const tf   = useRawPolled<ThreatFeedStats>('/api/v1/dashboard/threatfeed', 30000)
  const crs  = useRawPolled<CRSUpdateStats>('/api/v1/dashboard/crs-update', 60000)
  const anom = useRawPolled<AnomalyStatsStats>('/api/v1/dashboard/anomaly-stats', 10000)

  const anyLoading = ws.loading || tf.loading || crs.loading || anom.loading

  return (
    <div className="space-y-6 section-stagger p-6">
      <header className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold tracking-tight bg-gradient-to-r from-emerald-700 via-emerald-500 to-emerald-700 bg-clip-text text-transparent">
            Active Defenses
          </h1>
          <p className="text-sm text-slate-500 mt-1">
            Five in-cluster layers that protect your app without third-party / paid services.
            All counts below come directly from the running WAF binary.
          </p>
        </div>
        <div className="flex items-center gap-2 px-3 py-2 rounded-xl border border-emerald-200 bg-emerald-50/60">
          <Cpu size={14} className="text-emerald-600" />
          <span className="text-xs font-mono font-semibold text-emerald-700">build: {BUILD_TAG}</span>
          <span className="text-[10px] text-emerald-700/60">·</span>
          <span className="text-xs font-semibold text-emerald-700">
            {anyLoading ? 'Loading…' : 'Live · 100% in-cluster'}
          </span>
        </div>
      </header>

      {/* Layer 1: WebSocket Guard */}
      <section className="rounded-2xl border border-emerald-200 bg-emerald-50/40 p-5">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-emerald-900 flex items-center gap-2">
            <Shield size={18} /> WebSocket Guard
          </h2>
          <span className="text-[10px] uppercase tracking-wider font-bold text-emerald-700/70">Layer 1</span>
        </div>
        <p className="text-xs text-emerald-700/80 mt-1">
          Per-frame size cap · per-connection rate limit · origin allowlist
        </p>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-4">
          <StatCard label="Upgrades allowed" value={fmtNum(ws.data?.upgrades_allowed)} icon={CheckCircle2} color="forest" />
          <StatCard label="Upgrades blocked" value={fmtNum(ws.data?.upgrades_blocked)} icon={Lock} color="brick" />
          <StatCard label="Messages blocked" value={fmtNum(ws.data?.messages_blocked)} icon={AlertTriangle} color="brick" />
          <StatCard label="Origins rejected" value={fmtNum(ws.data?.origins_rejected)} icon={Globe} color="steel" />
        </div>
        {ws.err && <p className="text-xs text-red-600 mt-3">err: {ws.err}</p>}
        {ws.data?.config && (
          <p className="text-xs text-slate-500 mt-3 font-mono break-all">{ws.data.config}</p>
        )}
      </section>

      {/* Layer 2: Community Threat Feed */}
      <section className="rounded-2xl border border-sky-200 bg-sky-50/40 p-5">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-sky-900 flex items-center gap-2">
            <Globe size={18} /> Community Threat Feed
          </h2>
          <span className="text-[10px] uppercase tracking-wider font-bold text-sky-700/70">Layer 2</span>
        </div>
        <p className="text-xs text-sky-700/80 mt-1">
          Spamhaus DROP + Tor exit nodes + FireHOL Level 1 · refreshed every 1–24 h
        </p>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-4">
          <StatCard label="Sources" value={fmtNum(tf.data?.sources)} icon={Database} color="steel" />
          <StatCard label="Total IPs" value={fmtNum(tf.data?.total_ips)} icon={Shield} color="forest" />
          <StatCard label="Hits" value={fmtNum(tf.data?.hits)} icon={AlertTriangle} color="brick" />
          <StatCard label="Blocks" value={fmtNum(tf.data?.blocks)} icon={Lock} color="brick" />
        </div>
        <p className="text-xs text-slate-500 mt-3">last refresh: {fmtTime(tf.data?.last_fetch)}</p>
        {tf.err && <p className="text-xs text-red-600 mt-1">err: {tf.err}</p>}
        {tf.data?.last_error && <p className="text-xs text-amber-700 mt-1">last_error: {tf.data.last_error}</p>}
        {tf.data?.feeds && Object.keys(tf.data.feeds).length > 0 && (
          <ul className="text-xs text-slate-600 mt-3 space-y-1 border-t border-sky-200 pt-3">
            {Object.entries(tf.data.feeds).map(([name, count]) => (
              <li key={name} className="flex justify-between font-mono">
                <span>{name}</span>
                <span className="tabular-nums">{fmtNum(count)} IPs</span>
              </li>
            ))}
          </ul>
        )}
      </section>

      {/* Layer 3: OWASP CRS Auto-Update */}
      <section className="rounded-2xl border border-amber-200 bg-amber-50/40 p-5">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-amber-900 flex items-center gap-2">
            <Database size={18} /> OWASP CRS Auto-Update
          </h2>
          <span className="text-[10px] uppercase tracking-wider font-bold text-amber-700/70">Layer 3</span>
        </div>
        <p className="text-xs text-amber-700/80 mt-1">
          Nightly pull from github.com/coreruleset/coreruleset · MIT, no API key
        </p>
        <div className="grid grid-cols-2 md:grid-cols-3 gap-3 mt-4">
          <StatCard label="Imported" value={fmtNum(crs.data?.imported)} icon={CheckCircle2} color="forest" />
          <StatCard label="Skipped" value={fmtNum(crs.data?.skipped)} icon={AlertTriangle} color="steel" />
          <StatCard label="Ref" value={crs.data?.ref ?? '—'} icon={RefreshCw} color="steel" />
        </div>
        <p className="text-xs text-slate-500 mt-3">last refresh: {fmtTime(crs.data?.last_fetch)}</p>
        {crs.err && <p className="text-xs text-red-600 mt-1">err: {crs.err}</p>}
        {crs.data?.last_error && <p className="text-xs text-amber-700 mt-1">last_error: {crs.data.last_error}</p>}
      </section>

      {/* Layer 4: Statistical Anomaly */}
      <section className="rounded-2xl border border-violet-200 bg-violet-50/40 p-5">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-violet-900 flex items-center gap-2">
            <Activity size={18} /> Statistical Anomaly Scoring
          </h2>
          <span className="text-[10px] uppercase tracking-wider font-bold text-violet-700/70">Layer 4</span>
        </div>
        <p className="text-xs text-violet-700/80 mt-1">
          Path Shannon entropy + per-IP request-rate z-score · zero external API calls
        </p>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-4">
          <StatCard label="Requests scanned" value={fmtNum(anom.data?.requests_scanned)} icon={Activity} color="steel" />
          <StatCard label="Entropy blocks" value={fmtNum(anom.data?.entropy_blocks)} icon={AlertTriangle} color="brick" />
          <StatCard label="Z-score blocks" value={fmtNum(anom.data?.zscore_blocks)} icon={AlertTriangle} color="brick" />
          <StatCard label="Errors" value={fmtNum(anom.data?.errors)} icon={Wifi} color="steel" />
        </div>
        {anom.err && <p className="text-xs text-red-600 mt-3">err: {anom.err}</p>}
      </section>

      {/* Layer 5: k8s / Helm */}
      <section className="rounded-2xl border border-slate-200 bg-slate-50 p-5">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-slate-900 flex items-center gap-2">
            <Server size={18} /> k8s / Helm Deployment
          </h2>
          <span className="text-[10px] uppercase tracking-wider font-bold text-slate-500">Layer 5</span>
        </div>
        <p className="text-sm text-slate-600 mt-2">
          Run{' '}
          <code className="text-xs bg-slate-100 px-1.5 py-0.5 rounded">helm install aegis ./deploy/helm/aegis</code>
          {' '}or apply{' '}
          <code className="text-xs bg-slate-100 px-1.5 py-0.5 rounded">deploy/k8s/deployment.yaml</code>.
        </p>
        <p className="text-xs text-slate-500 mt-1">
          Ships with HPA, PDB, NetworkPolicy, ServiceMonitor — all stock k8s primitives, no commercial operator.
        </p>
      </section>
    </div>
  )
}

// Inline copy of StatCard to avoid an extra import in this file. The
// original component lives at ../components/StatCard and is used everywhere
// else; we duplicate the shell here so this page is fully self-contained
// for raw-fetch testing.

interface StatCardProps {
  label: string
  value: string | number
  icon: LucideIcon
  color?: 'forest' | 'brick' | 'steel'
  delay?: number
}

function StatCard({ label, value, icon: Icon, color = 'steel' }: StatCardProps) {
  const colorClass =
    color === 'forest' ? 'text-emerald-700 bg-emerald-50 border-emerald-200' :
    color === 'brick'   ? 'text-red-700    bg-red-50    border-red-200'    :
                          'text-slate-700  bg-slate-50  border-slate-200'
  return (
    <div className={`rounded-xl border p-4 ${colorClass}`}>
      <div className="flex items-center justify-between">
        <span className="text-xs uppercase tracking-wide font-semibold opacity-80">{label}</span>
        <Icon size={14} />
      </div>
      <div className="mt-1 text-2xl font-bold tabular-nums">{value}</div>
    </div>
  )
}