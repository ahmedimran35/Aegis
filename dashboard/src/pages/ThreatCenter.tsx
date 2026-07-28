import { ShieldAlert, ShieldX, AlertTriangle, ShieldCheck, Activity, Crosshair, Bug, UserX, Lock, Unlock, Database } from 'lucide-react'
import DataTable from '../components/DataTable'
import Pulse from '../components/Pulse'
import SeverityBarChart from '../components/SeverityBarChart.lazy'
import StatusBadge from '../components/StatusBadge'
import StatCard from '../components/StatCard'
import { SkeletonStatCard, SkeletonTable } from '../components/Skeleton'
import { usePolling, apiPost } from '../api/client'

interface ThreatEvent {
  id: number
  timestamp: string
  client_ip: string
  method: string
  path: string
  action: string
  threat_score: number
  ai_classification: string
  rule_name?: string
}

interface Anomaly {
  id: number
  type: string
  severity: string
  description: string
  resolved: boolean
  created_at: string
}

// /integrations/stats — the cockpit's data source.
// Real payload example (5 of 7 detectors; for brevity):
// {
//   "shadow_api":      { "enabled": true, "discovered": 240, "flagged": 24, ... },
//   "behavioral_bot":  { "enabled": true, "total_checked": 112, "blocked": 0, ... },
//   "credential_stuffing": { "enabled": true, "blocked": 0, "detected": 0, ... },
//   "bola":            { "enabled": true, "checks": 0, "flagged": 0, ... },
//   "csp_nonce":       { "enabled": true },
//   "policy_tuner":    { "enabled": false, ... },
//   "slow_dos":        { "enabled": true, "detected": 0, "blocked": 0, ... },
// }
// Each detector ships a different metric; the cockpit shows whatever
// fields that detector exposes.
interface IntegrationsStats {
  shadow_api?: { enabled?: boolean; discovered?: number; flagged?: number; top_endpoints?: Record<string, number>; flagged_endpoints?: Record<string, number>; mode?: string }
  behavioral_bot?: { enabled?: boolean; mode?: string; total_checked?: number; blocked?: number; suspicious?: number; allowed?: number; score_threshold?: number; top_bot_types?: Record<string, number> }
  credential_stuffing?: { enabled?: boolean; detected?: number; blocked?: number; top_compromised?: Record<string, number> }
  bola?: { enabled?: boolean; checks?: number; flagged?: number; top_violations?: Record<string, number> }
  csp_nonce?: { enabled?: boolean }
  policy_tuner?: { enabled?: boolean; min_threshold?: number; max_threshold?: number; min_samples?: number; fn_weight?: number; fp_weight?: number }
  slow_dos?: { enabled?: boolean; detected?: number; blocked?: number; concurrent?: number }
}

interface ATOStats {
  events_24h?: number
  locked_ips?: number
  active_ips_tracked?: number
  events_by_type?: Record<string, number>
  max_attempts_per_ip?: number
  max_usernames_per_ip?: number
  max_ips_per_username?: number
  lockout_duration?: string
}

interface ATOEvent {
  id: number
  ip: string
  username: string
  attack_type: string
  attempt_count: number
  unique_usernames: number
  unique_ips: number
  locked_until?: string
  created_at: string
}

export default function ThreatCenter() {
  const { data: threats, loading: loadingThreats, error: threatsError } = usePolling<ThreatEvent[]>('/dashboard/threat-events', 5000)
  const { data: anomalies, loading: loadingAnomalies } = usePolling<Anomaly[]>('/anomalies', 10000)
  const { data: atoStats, loading: loadingATOStats, refetch: refetchATOStats } = usePolling<ATOStats>('/ato/stats', 10000)
  const { data: atoEvents, loading: loadingATOEvents, refetch: refetchATOEvents } = usePolling<ATOEvent[]>('/ato/events', 10000)
  const { data: integrations, loading: loadingIntegrations } = usePolling<IntegrationsStats>('/integrations/stats', 15000)

  const threatList = Array.isArray(threats) ? threats : []
  const criticalCount = threatList.filter(t => (t.threat_score ?? 0) > 0.9).length
  const highCount = threatList.filter(t => (t.threat_score ?? 0) > 0.7 && (t.threat_score ?? 0) <= 0.9).length
  const blockedCount = threatList.filter(t => t.action === 'blocked').length
  const unresolvedAnomalies = Array.isArray(anomalies) ? anomalies.filter(a => !a.resolved).length : 0

  const atoEventList = Array.isArray(atoEvents) ? atoEvents : []
  const atoEventsCount = atoStats?.events_24h ?? 0
  const atoLockedIPs = atoStats?.locked_ips ?? 0
  const atoActiveIPs = atoStats?.active_ips_tracked ?? 0

  const handleUnlockIP = async (ip: string) => {
    try {
      await apiPost(`/ato/unlock/${encodeURIComponent(ip)}`, {})
      refetchATOStats()
      refetchATOEvents()
    } catch { /* silent */ }
  }

  const threatCols = [
    { key: 'timestamp', header: 'Time', render: (r: ThreatEvent) => (
      <span className="font-mono text-xs text-slate-500">{new Date(r.timestamp).toLocaleTimeString()}</span>
    )},
    { key: 'client_ip', header: 'IP', className: 'font-mono text-xs' },
    { key: 'method', header: 'Method', render: (r: ThreatEvent) => (
      <span className="font-mono text-xs font-semibold text-slate-600">{r.method}</span>
    )},
    { key: 'path', header: 'Path', className: 'font-mono text-xs max-w-[200px] truncate' },
    { key: 'threat_score', header: 'Score', render: (r: ThreatEvent) => {
      const score = r.threat_score ?? 0
      return (
      <span className={`font-mono text-xs font-semibold ${score > 0.7 ? 'text-red-600' : score > 0.3 ? 'text-amber-600' : 'text-emerald-600'}`}>
        {score.toFixed(2)}
      </span>
      )
    }},
    { key: 'ai_classification', header: 'Classification', render: (r: ThreatEvent) => (
      <StatusBadge status={r.ai_classification} />
    )},
    { key: 'action', header: 'Action', render: (r: ThreatEvent) => (
      <StatusBadge status={r.action} />
    )},
  ]

  const anomalyCols = [
    { key: 'created_at', header: 'Time', render: (r: Anomaly) => (
      <span className="font-mono text-xs text-slate-500">{new Date(r.created_at).toLocaleString()}</span>
    )},
    { key: 'type', header: 'Type', render: (r: Anomaly) => (
      <span className="badge bg-amber-50 text-amber-700">{r.type}</span>
    )},
    { key: 'severity', header: 'Severity', render: (r: Anomaly) => <StatusBadge status={r.severity} /> },
    { key: 'description', header: 'Description', className: 'max-w-[300px] truncate' },
    { key: 'resolved', header: 'Status', render: (r: Anomaly) => (
      <StatusBadge status={r.resolved ? 'approved' : 'pending'} />
    )},
  ]

  const atoCols = [
    { key: 'created_at', header: 'Time', render: (r: ATOEvent) => (
      <span className="font-mono text-xs text-slate-500">{new Date(r.created_at).toLocaleTimeString()}</span>
    )},
    { key: 'ip', header: 'IP', className: 'font-mono text-xs' },
    { key: 'username', header: 'Username', className: 'font-mono text-xs max-w-[120px] truncate' },
    { key: 'attack_type', header: 'Attack Type', render: (r: ATOEvent) => {
      const colors: Record<string, string> = {
        credential_stuffing: 'bg-red-50 text-red-700',
        brute_force: 'bg-orange-50 text-orange-700',
        distributed: 'bg-purple-50 text-purple-700',
        spray: 'bg-amber-50 text-amber-700',
      }
      const label: Record<string, string> = {
        credential_stuffing: 'Credential Stuffing',
        brute_force: 'Brute Force',
        distributed: 'Distributed',
        spray: 'Spray',
      }
      return <span className={`badge ${colors[r.attack_type] || 'bg-slate-50 text-slate-700'}`}>{label[r.attack_type] || r.attack_type}</span>
    }},
    { key: 'attempt_count', header: 'Attempts', render: (r: ATOEvent) => (
      <span className="font-mono text-xs font-semibold">{r.attempt_count}</span>
    )},
    { key: 'unique_usernames', header: 'Usernames', render: (r: ATOEvent) => (
      <span className="font-mono text-xs">{r.unique_usernames}</span>
    )},
    { key: 'actions', header: 'Action', render: (r: ATOEvent) => (
      <button onClick={() => handleUnlockIP(r.ip)} className="text-xs text-blue-600 hover:text-blue-800 flex items-center gap-1">
        <Unlock size={12} /> Unlock
      </button>
    )},
  ]

  const severityData = [
    { severity: 'Critical', count: criticalCount, fill: '#DC2626' },
    { severity: 'High', count: highCount, fill: '#D97706' },
    { severity: 'Medium', count: threatList.filter(t => (t.threat_score ?? 0) > 0.3 && (t.threat_score ?? 0) <= 0.7).length, fill: '#3B82F6' },
    { severity: 'Low', count: threatList.filter(t => (t.threat_score ?? 0) <= 0.3).length, fill: '#059669' },
  ]

  return (
    <div className="space-y-5 section-stagger">
      {threatsError && <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-sm text-red-700">{threatsError}</div>}
      {/* Header */}
      <div className="animate-fade-in">
        <div className="flex items-baseline justify-between">
          <h1 className="text-2xl font-bold tracking-tight bg-gradient-to-r from-slate-900 via-red-700 to-slate-900 bg-clip-text text-transparent">
            Threat Center
          </h1>
          <div className="hidden sm:flex items-center gap-3 text-[10px] font-mono uppercase tracking-[0.08em] text-slate-400">
            <span>{threatList.length} ACTIVE</span>
            <span className="text-slate-300">·</span>
            <span>{criticalCount} CRIT</span>
          </div>
        </div>
        <p className="text-xs text-slate-400 mt-1 flex items-center gap-2">
          <Pulse variant={criticalCount > 0 ? 'alert' : 'live'} size="sm" />
          Real-time threat detection and anomaly analysis
        </p>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {loadingThreats ? (
          Array.from({ length: 4 }).map((_, i) => <SkeletonStatCard key={i} />)
        ) : (
          <>
            <StatCard label="Critical" value={criticalCount.toString()} icon={ShieldX} color="brick" delay={0} />
            <StatCard label="High Severity" value={highCount.toString()} icon={AlertTriangle} color="burnt" delay={80} />
            <StatCard label="Blocked" value={blockedCount.toString()} icon={ShieldCheck} color="forest" delay={160} />
            <StatCard label="Open Anomalies" value={unresolvedAnomalies.toString()} icon={Bug} color="steel" delay={240} />
          </>
        )}
      </div>

      {/* Severity chart */}
      <div className="card-glow p-5 relative overflow-hidden">
        <div className="absolute top-0 left-0 w-full h-0.5 bg-gradient-to-r from-red-500/30 via-amber-500/20 to-transparent" />
        <div className="absolute top-0 right-0 w-32 h-32 bg-gradient-to-bl from-red-500/5 to-transparent rounded-bl-full pointer-events-none" />
        <h2 className="text-sm font-semibold text-slate-700 mb-4 flex items-center gap-2 relative">
          <div className="w-6 h-6 rounded-lg bg-red-50 flex items-center justify-center">
            <Crosshair size={13} className="text-red-500" />
          </div>
          Threat Severity Distribution
        </h2>
        <div className="h-[200px]">
          <SeverityBarChart data={severityData} />
        </div>
      </div>

      {/* Threat events */}
      <div className="card-glow p-5 relative overflow-hidden">
        <div className="absolute top-0 left-0 w-full h-0.5 bg-gradient-to-r from-amber-500/30 via-orange-500/20 to-transparent" />
        <h2 className="text-sm font-semibold text-slate-700 mb-4 flex items-center gap-2 relative">
          <div className="w-6 h-6 rounded-lg bg-amber-50 flex items-center justify-center">
            <AlertTriangle size={13} className="text-amber-500" />
          </div>
          Recent Threat Events
        </h2>
        {loadingThreats ? <SkeletonTable rows={5} cols={7} /> : (
          <DataTable columns={threatCols} data={threatList} searchable pageSize={25} emptyMessage="No threats detected — your Aegis is protecting you" />
        )}
      </div>

      {/* Behavioral Detector Cockpit — replaces the duplicated anomalies
          panel. Wires /integrations/stats which surfaces the 7 detectors
          (behavioural_bot, slow_dos, BOLA, credential-stuffing, shadow-API,
          policy-tuner, CSP-nonce). Also keeps the AI anomalies table
          (from /anomalies) accessible via the toggle below. */}
      <div className="card-glow p-5 relative overflow-hidden">
        <div className="absolute top-0 left-0 w-full h-0.5 bg-gradient-to-r from-violet-500/30 via-purple-500/20 to-transparent" />
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold text-slate-700 flex items-center gap-2 relative">
            <div className="w-6 h-6 rounded-lg bg-violet-50 flex items-center justify-center">
              <Database size={13} className="text-violet-500" />
            </div>
            Behavioral Detector Cockpit
          </h2>
          <span className="text-[10px] font-mono text-slate-400">/integrations/stats · 15s poll</span>
        </div>

        {loadingIntegrations ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {Array.from({ length: 7 }).map((_, i) => (
              <div key={i} className="h-[120px] rounded-lg bg-slate-50 animate-pulse" />
            ))}
          </div>
        ) : integrations ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {(() => {
              // Each detector renders its own tile. Whichever fields the
              // backend supplied, that's what we show; otherwise a
              // status pill. No fabricated metrics.
              const tiles: Array<{ key: string; title: string; tone: string; rows: Array<[string, string]> }> = []

              const sa = integrations.shadow_api
              if (sa) {
                tiles.push({
                  key: 'shadow_api', title: 'Shadow API Discovery', tone: 'amber',
                  rows: [
                    ['Status',  sa.enabled === false ? 'disabled' : 'active'],
                    ['Discovered endpoints', `${sa.discovered ?? 0}`],
                    ['Flagged as high-risk', `${sa.flagged ?? 0}`],
                  ],
                })
              }
              const bb = integrations.behavioral_bot
              if (bb) {
                tiles.push({
                  key: 'behavioral_bot', title: 'Behavioral Bot', tone: 'blue',
                  rows: [
                    ['Mode',  String(bb.mode ?? 'challenge')],
                    ['Scored requests', `${bb.total_checked ?? 0}`],
                    ['Blocked / Suspicious', `${bb.blocked ?? 0} / ${bb.suspicious ?? 0}`],
                    ['Score threshold', `${bb.score_threshold ?? 5}`],
                  ],
                })
              }
              const cs = integrations.credential_stuffing
              if (cs) {
                tiles.push({
                  key: 'credential_stuffing', title: 'Credential Stuffing', tone: 'rose',
                  rows: [
                    ['Detected', `${cs.detected ?? 0}`],
                    ['Blocked',  `${cs.blocked ?? 0}`],
                  ],
                })
              }
              const bola = integrations.bola
              if (bola) {
                tiles.push({
                  key: 'bola', title: 'BOLA (Broken Object-Level Auth)', tone: 'fuchsia',
                  rows: [
                    ['Endpoint checks',  `${bola.checks ?? 0}`],
                    ['BOLA violations',  `${bola.flagged ?? 0}`],
                  ],
                })
              }
              const csp = integrations.csp_nonce
              if (csp) tiles.push({
                key: 'csp_nonce', title: 'CSP Nonce Enforcement', tone: 'slate',
                rows: [['Enforcement', csp.enabled === false ? 'disabled' : 'active (nonce-strict)']]
              })
              const pt = integrations.policy_tuner
              if (pt) {
                tiles.push({
                  key: 'policy_tuner', title: 'Policy Tuner', tone: 'teal',
                  rows: [
                    ['Mode',          pt.enabled ? 'auto-adjusting' : 'paused'],
                    ['Threshold range', `${pt.min_threshold ?? '?'} – ${pt.max_threshold ?? '?'}`],
                    ['Min samples',   `${pt.min_samples ?? '?'}`],
                    ['FN / FP weights', `${pt.fn_weight ?? 1} / ${pt.fp_weight ?? 1}`],
                  ],
                })
              }
              const sd = integrations.slow_dos
              if (sd) {
                tiles.push({
                  key: 'slow_dos', title: 'Slow-loris / Slow-body DoS', tone: 'orange',
                  rows: [
                    ['Detected', `${sd.detected ?? 0}`],
                    ['Blocked',  `${sd.blocked ?? 0}`],
                    ['Concurrent conns', `${sd.concurrent ?? 0}`],
                  ],
                })
              }

              const tones: Record<string, string> = {
                amber:  'border-amber-200 bg-amber-50/40',
                blue:   'border-blue-200 bg-blue-50/40',
                rose:   'border-rose-200 bg-rose-50/40',
                fuchsia:'border-fuchsia-200 bg-fuchsia-50/40',
                slate:  'border-slate-200 bg-slate-50/40',
                teal:   'border-teal-200 bg-teal-50/40',
                orange: 'border-orange-200 bg-orange-50/40',
              }
              const dots: Record<string, string> = {
                amber: '#f59e0b', blue: '#3b82f6', rose: '#dc2626',
                fuchsia:'#c026d3', slate: '#64748b', teal: '#14b8a6', orange: '#f97316',
              }

              return tiles.map((t) => (
                <div key={t.key} className={`rounded-lg border p-3 ${tones[t.tone] || 'border-slate-200 bg-slate-50/40'}`}>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-[11px] font-semibold text-slate-700 uppercase tracking-wide">{t.title}</span>
                    <span className="w-2 h-2 rounded-full" style={{ background: dots[t.tone] || '#64748b' }} />
                  </div>
                  {t.rows.map(([k, v]) => (
                    <div key={k} className="flex items-center justify-between text-xs py-0.5">
                      <span className="text-slate-500">{k}</span>
                      <span className="font-mono font-semibold text-slate-800">{v}</span>
                    </div>
                  ))}
                </div>
              ))
            })()}
          </div>
        ) : null}

        {/* Anomalies table — kept under the cockpit so /threats is still the
            one-stop threat page. Visually de-emphasised because the
            cockpit tiles already tell you which detector tripped. */}
        <details className="mt-5 group">
          <summary className="text-xs font-semibold text-slate-500 cursor-pointer hover:text-slate-700 flex items-center gap-1.5">
            <span className="text-slate-400 group-open:rotate-90 transition-transform">▸</span>
            AI-detected anomalies ({anomalies?.length ?? 0})
          </summary>
          <div className="mt-3">
            {loadingAnomalies ? <SkeletonTable rows={4} cols={5} /> : (
              <DataTable columns={anomalyCols} data={anomalies || []} searchable pageSize={10} emptyMessage="No anomalies detected" />
            )}
          </div>
        </details>
      </div>

      {/* Brute Force & Response Inspection */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="card-glow p-5 relative overflow-hidden">
          <div className="absolute top-0 left-0 w-full h-0.5 bg-gradient-to-r from-orange-500/30 via-red-500/20 to-transparent" />
          <h2 className="text-sm font-semibold text-slate-700 mb-3 flex items-center gap-2">
            <div className="w-6 h-6 rounded-lg bg-orange-50 flex items-center justify-center">
              <ShieldAlert size={13} className="text-orange-500" />
            </div>
            Brute Force Protection
          </h2>
          <div className="space-y-2">
            <div className="flex items-center justify-between p-2 bg-emerald-50/50 rounded-lg">
              <span className="text-xs text-slate-600">Status</span>
              <span className="badge bg-emerald-100 text-emerald-700">Active</span>
            </div>
            <div className="flex items-center justify-between p-2 bg-ivory-50 rounded-lg">
              <span className="text-xs text-slate-600">Max Attempts</span>
              <span className="font-mono text-xs font-semibold">5</span>
            </div>
            <div className="flex items-center justify-between p-2 bg-ivory-50 rounded-lg">
              <span className="text-xs text-slate-600">Lock Duration</span>
              <span className="font-mono text-xs font-semibold">15 min</span>
            </div>
            <p className="text-[11px] text-slate-400 mt-2">Failed login attempts are tracked per IP and per username. Accounts are locked after 5 failures.</p>
          </div>
        </div>

        <div className="card-glow p-5 relative overflow-hidden">
          <div className="absolute top-0 left-0 w-full h-0.5 bg-gradient-to-r from-cyan-500/30 via-blue-500/20 to-transparent" />
          <h2 className="text-sm font-semibold text-slate-700 mb-3 flex items-center gap-2">
            <div className="w-6 h-6 rounded-lg bg-cyan-50 flex items-center justify-center">
              <Bug size={13} className="text-cyan-500" />
            </div>
            Response Inspection
          </h2>
          <div className="space-y-2">
            <div className="flex items-center justify-between p-2 bg-emerald-50/50 rounded-lg">
              <span className="text-xs text-slate-600">Status</span>
              <span className="badge bg-emerald-100 text-emerald-700">Monitoring</span>
            </div>
            <div className="flex items-center justify-between p-2 bg-ivory-50 rounded-lg">
              <span className="text-xs text-slate-600">Categories</span>
              <span className="font-mono text-xs font-semibold">7</span>
            </div>
            <div className="flex items-center justify-between p-2 bg-ivory-50 rounded-lg">
              <span className="text-xs text-slate-600">Patterns</span>
              <span className="font-mono text-xs font-semibold">32</span>
            </div>
            <p className="text-[11px] text-slate-400 mt-2">Scans responses for SQL errors, stack traces, PHP errors, internal IPs, web shells, server version leaks, and sensitive paths.</p>
          </div>
        </div>
      </div>

      {/* Account Takeover Detection */}
      <div className="card-glow p-5 relative overflow-hidden">
        <div className="absolute top-0 left-0 w-full h-0.5 bg-gradient-to-r from-rose-500/30 via-red-500/20 to-transparent" />
        <div className="absolute top-0 right-0 w-32 h-32 bg-gradient-to-bl from-rose-500/5 to-transparent rounded-bl-full pointer-events-none" />
        <h2 className="text-sm font-semibold text-slate-700 mb-4 flex items-center gap-2 relative">
          <div className="w-6 h-6 rounded-lg bg-rose-50 flex items-center justify-center">
            <UserX size={13} className="text-rose-500" />
          </div>
          Account Takeover Detection
        </h2>

        {/* ATO Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
          {loadingATOStats ? (
            Array.from({ length: 4 }).map((_, i) => <SkeletonStatCard key={i} />)
          ) : (
            <>
              <div className="p-3 bg-rose-50/50 rounded-lg border border-rose-100">
                <div className="text-[10px] font-semibold uppercase tracking-widest text-slate-400 mb-1">ATO Events (24h)</div>
                <div className="font-mono text-xl font-bold text-slate-900">{atoEventsCount}</div>
              </div>
              <div className="p-3 bg-red-50/50 rounded-lg border border-red-100">
                <div className="text-[10px] font-semibold uppercase tracking-widest text-slate-400 mb-1">IPs Locked</div>
                <div className="font-mono text-xl font-bold text-slate-900">{atoLockedIPs}</div>
              </div>
              <div className="p-3 bg-amber-50/50 rounded-lg border border-amber-100">
                <div className="text-[10px] font-semibold uppercase tracking-widest text-slate-400 mb-1">IPs Tracked</div>
                <div className="font-mono text-xl font-bold text-slate-900">{atoActiveIPs}</div>
              </div>
              <div className="p-3 bg-violet-50/50 rounded-lg border border-violet-100">
                <div className="text-[10px] font-semibold uppercase tracking-widest text-slate-400 mb-1">Lockout</div>
                <div className="font-mono text-xl font-bold text-slate-900">{atoStats?.lockout_duration || '15m'}</div>
              </div>
            </>
          )}
        </div>

        {/* Attack Type Breakdown */}
        {atoStats?.events_by_type && Object.keys(atoStats.events_by_type).length > 0 && (
          <div className="flex flex-wrap gap-2 mb-4">
            {Object.entries(atoStats.events_by_type).map(([type, count]) => {
              const colors: Record<string, string> = {
                credential_stuffing: 'bg-red-50 text-red-700 ring-red-600/20',
                brute_force: 'bg-orange-50 text-orange-700 ring-orange-600/20',
                distributed: 'bg-purple-50 text-purple-700 ring-purple-600/20',
                spray: 'bg-amber-50 text-amber-700 ring-amber-600/20',
              }
              const label: Record<string, string> = {
                credential_stuffing: 'Credential Stuffing',
                brute_force: 'Brute Force',
                distributed: 'Distributed',
                spray: 'Spray',
              }
              return (
                <span key={type} className={`inline-flex items-center gap-1.5 text-[11px] font-medium ring-1 ring-inset rounded-full px-2.5 py-1 ${colors[type] || 'bg-slate-50 text-slate-700 ring-slate-500/20'}`}>
                  <Lock size={11} />
                  {label[type] || type}: {count}
                </span>
              )
            })}
          </div>
        )}

        {/* Thresholds */}
        <div className="grid grid-cols-3 gap-2 mb-4">
          <div className="flex items-center justify-between p-2 bg-ivory-50 rounded-lg">
            <span className="text-[11px] text-slate-500">Max attempts/IP</span>
            <span className="font-mono text-xs font-semibold">{atoStats?.max_attempts_per_ip ?? 5}</span>
          </div>
          <div className="flex items-center justify-between p-2 bg-ivory-50 rounded-lg">
            <span className="text-[11px] text-slate-500">Max usernames/IP</span>
            <span className="font-mono text-xs font-semibold">{atoStats?.max_usernames_per_ip ?? 10}</span>
          </div>
          <div className="flex items-center justify-between p-2 bg-ivory-50 rounded-lg">
            <span className="text-[11px] text-slate-500">IPs per username</span>
            <span className="font-mono text-xs font-semibold">{atoStats?.max_ips_per_username ?? 5}</span>
          </div>
        </div>

        {/* ATO Events Table */}
        <h3 className="text-xs font-semibold text-slate-600 mb-2">Recent ATO Events</h3>
        {loadingATOEvents ? <SkeletonTable rows={4} cols={7} /> : (
          <DataTable columns={atoCols} data={atoEventList} searchable pageSize={10} emptyMessage="No account takeover events detected" />
        )}
        <p className="text-[11px] text-slate-400 mt-3">Detects credential stuffing, brute force, distributed attacks, and password spray patterns on login endpoints. Complements standard brute force protection with cross-dimensional analysis.</p>
      </div>
    </div>
  )
}
