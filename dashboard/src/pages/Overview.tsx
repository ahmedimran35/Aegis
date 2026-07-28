import { lazy, Suspense, useEffect, useMemo, useState } from 'react'
import { Activity, ShieldBan, Zap, Globe, Crosshair, ArrowUpDown, Wifi, WifiOff, Gauge, Flag } from 'lucide-react'
import LiveFeed from '../components/LiveFeed'
import Pulse from '../components/Pulse'
// 2D world map — pure SVG, no WebGL, no three.js, no shader cost.
import WorldMap2D from '../components/WorldMap2D'
import TopAttackers from '../components/TopAttackers'
import TopCountriesTable from '../components/TopCountriesTable'
import RequestMethodsChart from '../components/RequestMethodsChart.lazy'
import StatusCodeChart from '../components/StatusCodeChart'
import TopAttackedUrls from '../components/TopAttackedUrls'
import AttackTypeChart from '../components/AttackTypeChart.lazy'
import BandwidthChart from '../components/BandwidthChart.lazy'
import TrafficLineChart from '../components/TrafficLineChart.lazy'
import ThreatPieChart from '../components/ThreatPieChart.lazy'
import StatCard from '../components/StatCard'
import { SkeletonStatCard, SkeletonChart } from '../components/Skeleton'
import { usePolling } from '../api/client'
import { useWebSocket } from '../hooks/useWebSocket'
import { useAppStore } from '../store'
import { useMinDisplay } from '../hooks/useMinDisplay'

type TimeRange = '1h' | '6h' | '24h' | '7d'

// Build marker — visible in the UI header so we can prove a fresh
// rebuild reached the user's tab. Bump this constant each time you ship
// changes; the value renders as `Build v3` etc. in the page header.
const BUILD_TAG = 'globe+v3'

interface OverviewData {
  total_requests: number
  blocked_count: number
  unique_ips: number
  requests_trend?: number
  blocked_trend?: number
  top_threat?: { type?: string; count?: number }
}

interface TrafficPoint {
  time: string
  get: number
  post: number
  put: number
  delete: number
}

interface ThreatBreakdown {
  benign: number
  suspicious: number
  malicious: number
}

interface TopIP {
  ip: string
  count: number
  blocked: number
  last_seen?: string
  country?: string
}

interface GeoAttack {
  ip: string
  country: string
  count: number
}

interface StatusCode { code: number; count: number }
interface AttackedUrl { path: string; count: number; blocked: number }
interface AttackType { type: string; count: number }
interface BandwidthPoint { time: string; bytes_out: number; bytes_in: number }

const TIME_RANGES: { value: TimeRange; label: string }[] = [
  { value: '1h',  label: '1h' },
  { value: '6h',  label: '6h' },
  { value: '24h', label: '24h' },
  { value: '7d',  label: '7d' },
]

function AnimatedTime() {
  const [time, setTime] = useState(new Date())
  useEffect(() => {
    const id = setInterval(() => setTime(new Date()), 1000)
    return () => clearInterval(id)
  }, [])
  return <span className="font-mono text-xs text-slate-400 tabular-nums">{time.toLocaleTimeString()}</span>
}

export default function Overview() {
  const [isMobile, setIsMobile] = useState(() => window.matchMedia('(max-width: 767px)').matches)
  useEffect(() => {
    const media = window.matchMedia('(max-width: 767px)')
    const update = () => setIsMobile(media.matches)
    media.addEventListener('change', update)
    return () => media.removeEventListener('change', update)
  }, [])

  // Global time-range picker (SafeLine-style). Local state is sufficient —
  // P-FREE-recovery: time-range selection is plain local state, no
  // URL-hash mirror. A previous version wrote to window.location.hash
  // and called history.replaceState, which (combined with the 401
  // redirect on stale sessions) caused the pills to flicker as the
  // route kept re-evaluating. Local state is simpler and the user's
  // selection survives within the SPA session.
  const [timeRange, setTimeRange] = useState<TimeRange>('24h')

  const [countryFilter, setCountryFilter] = useState<string | null>(null)

  // Range mapping: backend supports 1h/6h/24h for traffic + bandwidth.
  // For 7d we fall back to 24h on those endpoints (graceful — SafeLine
  // shows 7d by aggregating; we keep the picker at the same level for
  // consistency without changing backend semantics).
  const trafficRange = timeRange === '7d' ? '24h' : timeRange
  const bandwidthRange = timeRange === '7d' ? '24h' : timeRange

  // pull = usePolling(...) : the refetch callback is also used by an effect
  // below to force a reload when the user changes the time range. Without
  // this defensive effect some browsers leave the old interval running
  // and only pick up the new range on the *next* 5s tick.
  const pollTraffic = usePolling<TrafficPoint[]>('/dashboard/traffic', 5000, { range: trafficRange })
  const pollBandwidth = usePolling<BandwidthPoint[]>('/dashboard/bandwidth', 5000, { range: bandwidthRange })

  const { data: overview, loading: loadingOverview, error: overviewError } = usePolling<OverviewData>('/dashboard/overview', 5000)
  const { data: traffic, loading: loadingTraffic, refetch: refetchTraffic } = pollTraffic
  const { data: threats, loading: loadingThreats } = usePolling<ThreatBreakdown>('/dashboard/threats', 10000)
  const { data: topIPs } = usePolling<TopIP[]>('/dashboard/top-ips', 10000)
  const { data: statusCodes } = usePolling<StatusCode[]>('/dashboard/status-codes', 10000)
  const { data: attackedUrls } = usePolling<AttackedUrl[]>('/dashboard/top-attacked-urls', 10000)
  const { data: attackTypes } = usePolling<AttackType[]>('/dashboard/attack-types', 10000)
  const { data: bandwidth, loading: loadingBandwidth, refetch: refetchBandwidth } = pollBandwidth
  const { data: geoAttacks } = usePolling<GeoAttack[]>('/dashboard/geo-attacks', 10000)

  // Force-refetch traffic + bandwidth the instant the picker changes,
  // instead of waiting for the next 5 s polling tick. This is what makes
  // "click 1h → traffic chart immediately redraws" feel live.
  useEffect(() => {
    refetchTraffic()
    refetchBandwidth()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [timeRange])
  const { connected } = useWebSocket()

  const showOverviewSkeleton = useMinDisplay(loadingOverview)
  const showTrafficSkeleton = useMinDisplay(loadingTraffic)
  const showThreatsSkeleton = useMinDisplay(loadingThreats)
  const showBandwidthSkeleton = useMinDisplay(loadingBandwidth)
  const compact = useAppStore((s) => s.compactMode)

  const threatData = threats ? [
    { name: 'Benign', value: threats.benign || 0, color: '#059669' },
    { name: 'Suspicious', value: threats.suspicious || 0, color: '#D97706' },
    { name: 'Malicious', value: threats.malicious || 0, color: '#DC2626' },
  ] : []

  const totalThreats = threats ? (threats.suspicious || 0) + (threats.malicious || 0) : 0
  const totalAll = threats ? (threats.benign || 0) + totalThreats : 0
  const threatLevel = totalAll > 0 ? Math.min((totalThreats / totalAll) * 100, 100) : 0

  const blockRate = (overview?.total_requests ?? 0) > 0
    ? (((overview?.blocked_count ?? 0) / (overview?.total_requests ?? 1)) * 100).toFixed(1)
    : '0.0'

  // Traffic totals for the bandwidth caption (real sum from bandwidth series).
  const bandwidthTotals = useMemo(() => {
    if (!bandwidth || bandwidth.length === 0) return { ingress: '0 B', egress: '0 B' }
    const inB = bandwidth.reduce((s, p) => s + (p.bytes_in || 0), 0)
    const outB = bandwidth.reduce((s, p) => s + (p.bytes_out || 0), 0)
    return { ingress: humanBytes(inB), egress: humanBytes(outB) }
  }, [bandwidth])

  return (
    <div className={`${compact ? 'space-y-3' : 'space-y-5'} section-stagger`}>
      {overviewError && <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-sm text-red-700">{overviewError}</div>}

      {/* Header + global time-range picker */}
      <div className="flex flex-wrap items-center justify-between gap-3 animate-fade-in">
        <div>
          <h1 className="text-2xl font-bold tracking-tight bg-gradient-to-r from-slate-900 via-slate-700 to-slate-900 bg-clip-text text-transparent">
            Overview
          </h1>
          <p className="text-xs text-slate-400 mt-1 flex items-center gap-2">
            <Pulse variant={connected ? 'live' : 'alert'} size="sm" />
            Real-time threat intelligence dashboard
          </p>
        </div>
        <div className="flex items-center gap-3">
          {/* Global time-range picker (SafeLine-style). Persists in URL hash. */}
          <div className="flex items-center gap-1 p-1 rounded-xl border border-ivory-300 bg-white/70 backdrop-blur-sm">
            {TIME_RANGES.map((r) => (
              <button
                key={r.value}
                type="button"
                onClick={() => setTimeRange(r.value)}
                aria-pressed={timeRange === r.value}
                className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-all duration-200
                  ${timeRange === r.value
                    ? 'bg-slate-900 text-white shadow-sm'
                    : 'text-slate-500 hover:text-slate-800 hover:bg-ivory-100'}`}
              >
                {r.label}
              </button>
            ))}
          </div>
          <div className={`flex items-center gap-2 px-3.5 py-2 rounded-xl border backdrop-blur-sm transition-all duration-300 ${connected ? 'bg-emerald-50/80 border-emerald-200 shadow-emerald-500/5 shadow-lg' : 'bg-red-50/80 border-red-200 shadow-red-500/5 shadow-lg'}`}>
            <Pulse variant={connected ? 'live' : 'alert'} size="sm" ariaLabel={connected ? 'Connection live' : 'Connection offline'} />
            {connected ? <Wifi size={13} className="text-emerald-600" /> : <WifiOff size={13} className="text-red-500" />}
            <span className={`text-xs font-semibold ${connected ? 'text-emerald-700' : 'text-red-600'}`}>
              {connected ? 'Live' : 'Offline'}
            </span>
          </div>
          <div className="px-3 py-2 rounded-xl border border-ivory-300 bg-white/60 backdrop-blur-sm">
            <AnimatedTime />
          </div>
        </div>
      </div>

      {/* 1. KPI STRIP — five cards, all from real /dashboard endpoints */}
      <div className={`grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 ${compact ? 'gap-3' : 'gap-4'}`}>
        {showOverviewSkeleton ? (
          Array.from({ length: 5 }).map((_, i) => <SkeletonStatCard key={i} />)
        ) : (
          <>
            <StatCard label="Total Requests" value={overview?.total_requests?.toLocaleString() ?? '—'} icon={Activity} color="steel" delay={0}
              trend={overview?.requests_trend != null ? { value: Math.round(overview.requests_trend), label: 'vs yesterday' } : undefined}
              sparklineData={traffic?.slice(-12).map(t => (t.get ?? 0) + (t.post ?? 0) + (t.put ?? 0) + (t.delete ?? 0))} />
            <StatCard label="Blocked" value={overview?.blocked_count?.toLocaleString() ?? '—'} icon={ShieldBan} color="brick" delay={80}
              trend={overview?.blocked_trend != null ? { value: Math.round(overview.blocked_trend), label: 'vs yesterday' } : undefined}
              sparklineData={bandwidth?.slice(-12).map(b => b.bytes_out ?? 0)} />
            <StatCard label="Block Rate" value={`${blockRate}%`} icon={Zap} color="burnt" delay={160} />
            <StatCard label="Unique IPs" value={overview?.unique_ips?.toLocaleString() ?? '—'} icon={Globe} color="forest" delay={240}
              sparklineData={traffic?.slice(-12).map(t => (t.get ?? 0) + (t.post ?? 0))} />
            <StatCard
              label="Threat Score"
              value={`${threatLevel.toFixed(0)}%`}
              icon={Gauge}
              color={threatLevel > 60 ? 'brick' : threatLevel > 30 ? 'burnt' : 'forest'}
              delay={320}
            />
          </>
        )}
      </div>

      {/* 2. ATTACK SOURCE MAP — 2D SVG world map + side country leaderboard.
           Replaces the old three.js globe. No WebGL, no shader, no per-frame
           work — just a static <svg> that re-paints when /geo-attacks polls. */}
      <div className="overflow-hidden rounded-2xl border border-slate-800/60 shadow-xl shadow-slate-900/20 bg-slate-950" style={{ minHeight: 480 }}>
        <WorldMap2D
          pollIntervalMs={10000}
          selectedCountry={countryFilter ?? undefined}
          onSelect={(cc) => setCountryFilter(cc)}
        />
      </div>

      {/* 3. TRAFFIC FLOW + THREAT CLASSIFICATION */}
      <div className={`grid grid-cols-1 lg:grid-cols-3 ${compact ? 'gap-3' : 'gap-4'}`}>
        <div className={`lg:col-span-2 card-glow ${compact ? 'p-4' : 'p-5'} relative overflow-hidden`}>
          <div className="absolute top-0 left-0 w-24 h-24 bg-gradient-to-br from-blue-500/5 to-transparent rounded-br-full pointer-events-none" />
          <h2 className="text-sm font-semibold text-slate-700 mb-4 flex items-center gap-2 relative">
            <div className="w-1.5 h-4 rounded-full bg-gradient-to-b from-blue-500 to-blue-600" />
            Traffic Flow ({timeRange})
          </h2>
          {showTrafficSkeleton ? <SkeletonChart /> : <TrafficLineChart data={traffic || []} />}
        </div>
        <div className={`card-glow ${compact ? 'p-4' : 'p-5'} relative overflow-hidden`}>
          <div className="absolute top-0 right-0 w-20 h-20 bg-gradient-to-bl from-violet-500/5 to-transparent rounded-bl-full pointer-events-none" />
          <h2 className="text-sm font-semibold text-slate-700 mb-4 flex items-center gap-2 relative">
            <div className="w-1.5 h-4 rounded-full bg-gradient-to-b from-violet-500 to-purple-600" />
            Classification
          </h2>
          {showThreatsSkeleton ? <SkeletonChart height="h-[200px]" /> : (
            <>
              <div className="h-[200px]">
                <ThreatPieChart data={threatData} />
              </div>
              <div className="flex justify-center gap-4 mt-2">
                {threatData.map((d) => (
                  <div key={d.name} className="flex items-center gap-1.5">
                    <div className="w-2.5 h-2.5 rounded-full" style={{ background: d.color }} />
                    <span className="text-[10px] text-slate-500">{d.name}</span>
                    <span className="text-[10px] text-slate-400 font-mono">{d.value.toLocaleString()}</span>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      </div>

      {/* 4. ATTACK TYPES (h-bars) + TOP COUNTRIES (top 5) — same /geo-attacks data */}
      <div className={`grid grid-cols-1 lg:grid-cols-2 ${compact ? 'gap-3' : 'gap-4'}`}>
        <div className="card-glow p-5 relative overflow-hidden">
          <div className="absolute bottom-0 left-0 w-28 h-28 bg-gradient-to-tr from-red-500/5 to-transparent rounded-tr-full pointer-events-none" />
          <h2 className="text-sm font-semibold text-slate-700 mb-4 flex items-center gap-2 relative">
            <div className="w-6 h-6 rounded-lg bg-red-50 flex items-center justify-center">
              <Crosshair size={13} className="text-red-500" />
            </div>
            Attack Types
          </h2>
          <AttackTypeChart data={attackTypes || []} />
        </div>
        <div className="card-glow p-5 relative overflow-hidden">
          <div className="absolute top-0 left-0 w-full h-0.5 bg-gradient-to-r from-rose-500/30 via-orange-500/20 to-transparent" />
          <h2 className="text-sm font-semibold text-slate-700 mb-4 flex items-center gap-2 relative">
            <div className="w-6 h-6 rounded-lg bg-rose-50 flex items-center justify-center">
              <Flag size={13} className="text-rose-500" />
            </div>
            Top Attacking Countries
            <span className="text-[10px] text-slate-400 font-medium ml-auto">top 5</span>
          </h2>
          <TopCountriesTable
            attacks={geoAttacks || []}
            selectedCountry={countryFilter ?? undefined}
            onSelect={setCountryFilter}
            limit={5}
          />
        </div>
      </div>

      {/* 5. TOP ATTACKERS (filterable) + TOP TARGETED URLS */}
      <div className={`grid grid-cols-1 lg:grid-cols-2 ${compact ? 'gap-3' : 'gap-4'}`}>
        <div className="card-glow p-5 relative overflow-hidden">
          <div className="absolute top-0 left-0 w-full h-0.5 bg-gradient-to-r from-red-500/30 via-orange-500/20 to-transparent" />
          <h2 className="text-sm font-semibold text-slate-700 mb-4 flex items-center gap-2 relative">
            <div className="w-6 h-6 rounded-lg bg-red-50 flex items-center justify-center">
              <ShieldBan size={13} className="text-red-500" />
            </div>
            Top Attackers
            {countryFilter && (
              <span className="text-[10px] text-rose-600 font-medium ml-auto">filtered → {countryFilter}</span>
            )}
          </h2>
          <TopAttackers
            attackers={topIPs || []}
            countryFilter={countryFilter ?? undefined}
            onClearFilter={() => setCountryFilter(null)}
          />
        </div>
        <div className="card-glow p-5 relative overflow-hidden">
          <div className="absolute top-0 left-0 w-full h-0.5 bg-gradient-to-r from-amber-500/30 via-yellow-500/20 to-transparent" />
          <h2 className="text-sm font-semibold text-slate-700 mb-4 flex items-center gap-2 relative">
            <div className="w-6 h-6 rounded-lg bg-amber-50 flex items-center justify-center">
              <Crosshair size={13} className="text-amber-500" />
            </div>
            Top Targeted URLs
          </h2>
          <TopAttackedUrls data={attackedUrls || []} />
        </div>
      </div>

      {/* 6. STATUS CODES + REQUEST METHODS */}
      <div className={`grid grid-cols-1 lg:grid-cols-2 ${compact ? 'gap-3' : 'gap-4'}`}>
        <div className="card-glow p-5 relative overflow-hidden">
          <div className="absolute bottom-0 right-0 w-28 h-28 bg-gradient-to-tl from-blue-500/5 to-transparent rounded-tl-full pointer-events-none" />
          <h2 className="text-sm font-semibold text-slate-700 mb-4 flex items-center gap-2 relative">
            <div className="w-6 h-6 rounded-lg bg-blue-50 flex items-center justify-center">
              <ArrowUpDown size={13} className="text-blue-500" />
            </div>
            Status Codes
          </h2>
          <StatusCodeChart data={statusCodes || []} />
        </div>
        <div className="card-glow p-5 relative overflow-hidden">
          <div className="absolute bottom-0 right-0 w-24 h-24 bg-gradient-to-tl from-indigo-500/5 to-transparent rounded-tl-full pointer-events-none" />
          <h2 className="text-sm font-semibold text-slate-700 mb-4 flex items-center gap-2 relative">
            <div className="w-6 h-6 rounded-lg bg-blue-50 flex items-center justify-center">
              <Activity size={13} className="text-blue-500" />
            </div>
            Request Methods
          </h2>
          <RequestMethodsChart data={traffic || []} />
        </div>
      </div>

      {/* 7. BANDWIDTH — real sum totals at the bottom of the chart */}
      <div className={`card-glow ${compact ? 'p-4' : 'p-5'} relative overflow-hidden`}>
        <div className="absolute top-0 left-0 w-full h-0.5 bg-gradient-to-r from-emerald-500/30 via-cyan-500/20 to-transparent" />
        <div className="absolute top-0 right-0 w-32 h-32 bg-gradient-to-bl from-emerald-500/5 to-transparent rounded-bl-full pointer-events-none" />
        <h2 className="text-sm font-semibold text-slate-700 mb-4 flex items-center gap-2 relative">
          <div className="w-1.5 h-4 rounded-full bg-gradient-to-b from-emerald-500 to-cyan-600" />
          Bandwidth ({timeRange})
          <span className="text-[10px] text-slate-400 font-medium ml-auto font-mono">
            ingress {bandwidthTotals.ingress} · egress {bandwidthTotals.egress}
          </span>
        </h2>
        {showBandwidthSkeleton ? <SkeletonChart height="h-[200px]" /> : <BandwidthChart data={bandwidth || []} />}
      </div>

      {/* 8. LIVE EVENT FEED — moved to bottom, full-width per SafeLine */}
      <LiveFeed />
    </div>
  )
}

// Human-readable byte formatter (no external lib; ~150 B minified).
function humanBytes(n: number): string {
  if (!n || n < 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  let v = n
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++ }
  return `${v.toFixed(v < 10 && i > 0 ? 2 : v < 100 && i > 0 ? 1 : 0)} ${units[i]}`
}
