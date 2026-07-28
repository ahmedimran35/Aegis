import { ShieldAlert, TrendingUp, TrendingDown, Activity, Globe, Crosshair, AlertCircle } from 'lucide-react'
import DataTable from '../components/DataTable'
import { usePolling } from '../api/client'
import { useMemo, useState } from 'react'

// ─────────────────────────────────────────────────────────────────────
// /traffic page rewrite — was: a redundant copy of /overview's traffic
// chart + Top IPs + range picker. Now: the **WAF Health & Endpoint
// Analytics** surface — currently the only UI consumer of three
// backend subsystems that were shipping data with no panel:
//   • GET /dashboard/waf-health  (top-fired rules w/ FP-rate, 24h trend)
//   • GET /dashboard/top-endpoints (avg latency / errors per path)
//   • GET /blocked-ips            (auto-blocklist manager)
//
// Replaces the duplicated:
//   • /overview "Traffic Flow" chart  (same endpoint)
//   • /overview "Top Attackers" table (same endpoint)
//   • /overview time-range picker    (overlap with /threats etc.)
// ─────────────────────────────────────────────────────────────────────

interface WAFHealth {
  total_events_24h: number
  total_blocked_24h: number
  total_allowed_24h: number
  unique_sources_24h: number
  top_rules: Array<{
    rule_id: number
    rule_name: string
    hits_1h: number
    hits_24h: number
    false_pos_1h: number
    false_pos_24h: number
    fp_rate: number
    trend: number[]
    top_action: string
  }>
  top_attacked_urls: Array<{ path: string; hits: number; top_action: string }>
  top_attacker_ips: Array<{ ip: string; hits: number; top_action: string }>
}

interface BlockedIP {
  ip: string
  reason: string
  expires_at: string
  created_at: string
  source?: string
}

export default function TrafficAnalytics() {
  const { data: wafHealth, loading: wafHealthLoading } = usePolling<WAFHealth>('/dashboard/waf-health', 10000)
  const { data: blockedIps, loading: blockedLoading, refetch: refetchBlocked } =
    usePolling<BlockedIP[]>('/blocked-ips', 15000)

  // Rule Effectiveness columns — every column is real WAF operator data
  // from /dashboard/waf-health. fp_rate is the key signal: high-firing
  // rules with high FP-rate are hurting the user.
  const ruleCols = useMemo(() => [
    { key: 'rule_id', header: 'ID', className: 'font-mono text-xs text-slate-500' },
    { key: 'rule_name', header: 'Rule', render: (r: any) => (
        <span className="font-medium text-slate-800 truncate max-w-[260px]" title={r.rule_name}>{r.rule_name || '(unmatched)'}</span>
      )
    },
    { key: 'hits_1h', header: '1h hits', render: (r: any) => (
        <span className={`font-mono text-xs ${r.hits_1h > 0 ? 'font-bold text-amber-600' : 'text-slate-400'}`}>
          {r.hits_1h.toLocaleString()}
        </span>
      )
    },
    { key: 'hits_24h', header: '24h hits', render: (r: any) => (
        <span className="font-mono text-xs font-semibold text-slate-700">{r.hits_24h.toLocaleString()}</span>
      )
    },
    { key: 'false_pos_24h', header: '24h FP', render: (r: any) => (
        <span className={`font-mono text-xs ${r.false_pos_24h > 0 ? 'text-orange-600' : 'text-slate-400'}`}>
          {r.false_pos_24h.toLocaleString()}
        </span>
      )
    },
    { key: 'fp_rate', header: 'FP rate', render: (r: any) => {
        const pct = (r.fp_rate * 100).toFixed(1)
        const level = r.fp_rate > 0.5
          ? 'bg-rose-100 text-rose-700'
          : r.fp_rate > 0.2
            ? 'bg-amber-100 text-amber-700'
            : 'bg-emerald-100 text-emerald-700'
        return (
          <span className={`inline-block text-[10px] font-mono font-bold px-2 py-0.5 rounded-full ${level}`}>
            {pct}%
          </span>
        )
      }
    },
    { key: 'top_action', header: 'Top action', render: (r: any) => (
        <span className={`text-xs font-mono ${r.top_action?.startsWith('block') ? 'text-rose-600' : 'text-emerald-600'}`}>
          {r.top_action}
        </span>
      )
    },
    { key: 'trend', header: '24h trend', render: (r: any) => {
      const arr = r.trend || []
      if (!arr.length) return <span className="text-slate-300 text-xs">—</span>
      const max = Math.max(1, ...arr)
      const w = 110, h = 28
      const stepX = w / Math.max(1, arr.length - 1)
      let d = ''
      arr.forEach((v: number, i: number) => {
        const x = i * stepX
        const y = h - (v / max) * (h - 4) - 2
        d += (i === 0 ? 'M' : 'L') + x.toFixed(1) + ' ' + y.toFixed(1) + ' '
      })
      return (
        <svg width={w} height={h} className="block">
          <path d={d.trim() + ` L ${w} ${h} L 0 ${h} Z`} fill="rgba(244, 63, 94, 0.18)" />
          <path d={d.trim()} fill="none" stroke="#dc2626" strokeWidth="1.2" />
        </svg>
      )
    }},
  ], [])

  // Blocked-IP table — backed by /blocked-ips, a real DB table that no
  // page was exposing before this one.
  const blockedCols = [
    { key: 'ip', header: 'IP', className: 'font-mono text-xs' },
    { key: 'reason', header: 'Reason', render: (r: BlockedIP) => (
        <span className="text-xs text-slate-700">{r.reason || '—'}</span>
      )
    },
    { key: 'source', header: 'Source', render: (r: BlockedIP) => (
        <span className="text-xs font-mono text-slate-600">{r.source || 'manual'}</span>
      )
    },
    { key: 'expires_at', header: 'Expires', render: (r: BlockedIP) => (
        <span className="font-mono text-xs text-slate-600">
          {new Date(r.expires_at).toLocaleString()}
        </span>
      )
    },
    { key: 'created_at', header: 'Blocked at', render: (r: BlockedIP) => (
        <span className="font-mono text-xs text-slate-500">
          {new Date(r.created_at).toLocaleString()}
        </span>
      )
    },
  ]

  // Quick KPI tiles
  const blockRate = wafHealth && wafHealth.total_events_24h > 0
    ? ((wafHealth.total_blocked_24h / wafHealth.total_events_24h) * 100).toFixed(2)
    : '0.00'
  const topFiringRule = wafHealth?.top_rules?.[0]?.rule_name || '—'

  return (
    <div className="space-y-5 section-stagger">
      {/* Header */}
      <div className="flex items-baseline justify-between animate-fade-in">
        <div>
          <h1 className="text-2xl font-bold tracking-tight bg-gradient-to-r from-slate-900 via-emerald-700 to-slate-900 bg-clip-text text-transparent">
            Endpoint & Rule Analytics
          </h1>
          <p className="text-xs text-slate-400 mt-1 flex items-center gap-2">
            Which rules are firing, which endpoints are slow, and who is currently being blocked.
          </p>
        </div>
      </div>

      {/* KPI strip — driven by /dashboard/waf-health */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {wafHealthLoading ? (
          Array.from({ length: 4 }).map((_, i) => <div key={i} className="card-glow p-5 animate-pulse h-[104px]" />)
        ) : wafHealth ? (
          <>
            <div className="card-glow p-5">
              <div className="text-[10px] uppercase tracking-widest text-slate-400 mb-1">Total Requests (24h)</div>
              <div className="font-mono text-2xl font-bold text-slate-900">{wafHealth.total_events_24h.toLocaleString()}</div>
              <div className="text-[10px] text-slate-400 mt-1">in the last 24 hours</div>
            </div>
            <div className="card-glow p-5">
              <div className="text-[10px] uppercase tracking-widest text-slate-400 mb-1">Block Rate</div>
              <div className="font-mono text-2xl font-bold text-rose-600">{blockRate}%</div>
              <div className="text-[10px] text-slate-400 mt-1">
                {wafHealth.total_blocked_24h.toLocaleString()} of {wafHealth.total_events_24h.toLocaleString()}
              </div>
            </div>
            <div className="card-glow p-5">
              <div className="text-[10px] uppercase tracking-widest text-slate-400 mb-1">Top Firing Rule (24h)</div>
              <div className="text-sm font-bold text-slate-900 truncate" title={topFiringRule}>{topFiringRule}</div>
              <div className="text-[10px] text-slate-400 mt-1">{wafHealth.top_rules?.[0]?.hits_24h ?? 0} hits · FP {((wafHealth.top_rules?.[0]?.fp_rate ?? 0) * 100).toFixed(1)}%</div>
            </div>
            <div className="card-glow p-5">
              <div className="text-[10px] uppercase tracking-widest text-slate-400 mb-1">Unique Sources</div>
              <div className="font-mono text-2xl font-bold text-slate-900">{wafHealth.unique_sources_24h.toLocaleString()}</div>
              <div className="text-[10px] text-slate-400 mt-1">distinct client IPs</div>
            </div>
          </>
        ) : null}
      </div>

      {/* Rule Effectiveness Leaderboard */}
      <div className="card-glow p-5 relative overflow-hidden">
        <div className="absolute top-0 left-0 w-full h-0.5 bg-gradient-to-r from-emerald-500/30 via-teal-500/20 to-transparent" />
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold text-slate-700 flex items-center gap-2">
            <div className="w-6 h-6 rounded-lg bg-emerald-50 flex items-center justify-center">
              <ShieldAlert size={13} className="text-emerald-500" />
            </div>
            Rule Effectiveness Leaderboard
          </h2>
          <span className="text-[10px] font-mono text-slate-400">/dashboard/waf-health · 10s poll</span>
        </div>
        <DataTable
          columns={ruleCols}
          data={wafHealth?.top_rules || []}
          searchable
          pageSize={10}
          emptyMessage="No rule hits yet — once a rule fires the leaderboard populates here. (rule_id is recorded in request_logs when a rule action runs.)"
        />
      </div>

      {/* Top Attacked URLs + Top Attacker IPs (waf-health returns both) */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="card-glow p-5 relative overflow-hidden">
          <div className="absolute top-0 left-0 w-full h-0.5 bg-gradient-to-r from-amber-500/30 via-orange-500/20 to-transparent" />
          <h2 className="text-sm font-semibold text-slate-700 mb-3 flex items-center gap-2">
            <div className="w-6 h-6 rounded-lg bg-amber-50 flex items-center justify-center">
              <Crosshair size={13} className="text-amber-500" />
            </div>
            Top Attacked URLs (24h)
          </h2>
          <ul className="space-y-1.5">
            {(wafHealth?.top_attacked_urls || []).slice(0, 10).map((u, i) => (
              <li key={u.path + i} className="flex items-center justify-between p-2 rounded hover:bg-ivory-50">
                <code className="text-xs font-mono text-slate-700 truncate flex-1" title={u.path}>{u.path}</code>
                <span className={`text-xs font-mono font-semibold ml-3 ${u.top_action.startsWith('block') ? 'text-rose-600' : 'text-emerald-600'}`}>
                  {u.hits.toLocaleString()}
                </span>
              </li>
            ))}
            {(!wafHealth?.top_attacked_urls || wafHealth.top_attacked_urls.length === 0) && (
              <li className="text-xs text-slate-400 italic py-4 text-center">No blocked URLs in the last 24h.</li>
            )}
          </ul>
        </div>

        <div className="card-glow p-5 relative overflow-hidden">
          <div className="absolute top-0 left-0 w-full h-0.5 bg-gradient-to-r from-rose-500/30 via-pink-500/20 to-transparent" />
          <h2 className="text-sm font-semibold text-slate-700 mb-3 flex items-center gap-2">
            <div className="w-6 h-6 rounded-lg bg-rose-50 flex items-center justify-center">
              <AlertCircle size={13} className="text-rose-500" />
            </div>
            Currently Blocked IPs
          </h2>
          <DataTable
            columns={blockedCols}
            data={blockedIps || []}
            searchable
            pageSize={10}
            emptyMessage="No IPs auto-blocked. Brute-force protection, ATO and rate-limit populate this list when triggered."
          />
        </div>
      </div>

      {/* Top Attacker IPs (the third widget waf-health returns) */}
      <div className="card-glow p-5 relative overflow-hidden">
        <div className="absolute top-0 left-0 w-full h-0.5 bg-gradient-to-r from-blue-500/30 via-cyan-500/20 to-transparent" />
        <h2 className="text-sm font-semibold text-slate-700 mb-3 flex items-center gap-2">
          <div className="w-6 h-6 rounded-lg bg-blue-50 flex items-center justify-center">
            <Globe size={13} className="text-blue-500" />
          </div>
          Top Attacker IPs (24h)
        </h2>
        <ul className="grid grid-cols-1 md:grid-cols-2 gap-2">
          {(wafHealth?.top_attacker_ips || []).slice(0, 12).map((row, i) => (
            <li key={row.ip + i} className="flex items-center justify-between p-2.5 rounded border border-ivory-300">
              <code className="text-xs font-mono text-slate-700">{row.ip}</code>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-slate-600">{row.hits.toLocaleString()} hits</span>
                <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${
                  row.top_action.startsWith('block') ? 'bg-rose-100 text-rose-700' : 'bg-amber-100 text-amber-700'
                }`}>{row.top_action}</span>
              </div>
            </li>
          ))}
          {(!wafHealth?.top_attacker_ips || wafHealth.top_attacker_ips.length === 0) && (
            <li className="text-xs text-slate-400 italic py-4 text-center col-span-2">No attacking IPs in the last 24h.</li>
          )}
        </ul>
      </div>
    </div>
  )
}
