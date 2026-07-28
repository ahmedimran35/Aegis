import { useState, useEffect, useCallback } from 'react'
import { ShieldAlert, Globe, Flower2, Fingerprint, Zap, Plus, Trash2, AlertTriangle, Crosshair, Database, Layers, Search } from 'lucide-react'
import DataTable from '../components/DataTable'
import StatusBadge from '../components/StatusBadge'
import StatCard from '../components/StatCard'
import { apiGet, apiPost, apiDelete, apiPut } from '../api/client'
import { useToast } from '../hooks/useToast'
import { SkeletonTable } from '../components/Skeleton'

interface GeoIPRule { id: number; country_code: string; action: string; reason: string; enabled: boolean }
interface AllowlistRule { id: number; rule_type: string; pattern: string; description: string; priority: number; enabled: boolean }
interface HoneypotHit { id: number; client_ip: string; method: string; path: string; user_agent: string; created_at: string }
interface TLSFingerprint { id: number; ja3_hash: string; client_ip: string; user_agent: string; request_count: number; reputation: string; last_seen: string }
interface FalsePositive { id: number; log_id: number; rule_id: number; reason: string; reviewed_by: number; username: string; created_at: string }
interface LibinjectStats { requests_scanned: number; sqli_blocked: number; xss_blocked: number; sqli_detected: number; xss_detected: number; recent_detections: Array<{ time: string; type: string; payload: string; ip: string }> }
interface ReputationStats { ips_checked: number; ips_blocked: number; cache_hits: number; cache_misses: number; api_errors: number; cache_hit_rate: number }
interface ReputationTopEntry { ip: string; abuse_confidence_score: number; country_code: string; isp: string; total_reports: number }
interface GraphQLStats { queries_blocked: number; introspection_blocked: number; depth_violations: number; complexity_violations: number; operation_violations: number; total_queries: number; avg_depth: number }
interface BodyInspectStats { enabled: boolean; parsed_json: number; parsed_form: number; parsed_multipart: number; parsed_xml: number; parsed_text: number; threats_found: number; top_attacks: Record<string, number> }

type Tab = 'geoip' | 'allowlist' | 'honeypot' | 'tls' | 'fp' | 'libinject' | 'reputation' | 'graphql' | 'bodyinspect'

export default function SecurityCenter() {
  const [tab, setTab] = useState<Tab>('geoip')
  const [geoRules, setGeoRules] = useState<GeoIPRule[]>([])
  const [allowRules, setAllowRules] = useState<AllowlistRule[]>([])
  const [honeypotHits, setHoneypotHits] = useState<HoneypotHit[]>([])
  const [honeypotStats, setHoneypotStats] = useState<Record<string, unknown>>({})
  const [fingerprints, setFingerprints] = useState<TLSFingerprint[]>([])
  const [fpList, setFpList] = useState<FalsePositive[]>([])
  const [libinjectStats, setLibinjectStats] = useState<LibinjectStats | null>(null)
  const [repStats, setRepStats] = useState<ReputationStats | null>(null)
  const [repTop, setRepTop] = useState<ReputationTopEntry[]>([])
  const [repCheckIP, setRepCheckIP] = useState('')
  const [repCheckResult, setRepCheckResult] = useState<Record<string, unknown> | null>(null)
  const [repCheckLoading, setRepCheckLoading] = useState(false)
  const [graphqlStats, setGraphqlStats] = useState<GraphQLStats | null>(null)
  const [bodyInspectStats, setBodyInspectStats] = useState<BodyInspectStats | null>(null)
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ country_code: '', action: 'block', reason: '', rule_type: 'ip', pattern: '', description: '', priority: 100 })
  const [loadError, setLoadError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [submitting, setSubmitting] = useState(false)
  const [formError, setFormError] = useState('')

  const loadGeo = useCallback(async () => { try { setGeoRules(await apiGet<GeoIPRule[]>('/geoip')); setLoadError(null) } catch (e) { useToast.getState().error(e instanceof Error ? e.message : 'Failed to load data'); setLoadError(e instanceof Error ? e.message : 'Failed to load data') } }, [])
  const loadAllow = useCallback(async () => { try { setAllowRules(await apiGet<AllowlistRule[]>('/allowlist')); setLoadError(null) } catch (e) { useToast.getState().error(e instanceof Error ? e.message : 'Failed to load data'); setLoadError(e instanceof Error ? e.message : 'Failed to load data') } }, [])
  const loadHoneypot = useCallback(async () => {
    try { setHoneypotHits(await apiGet<HoneypotHit[]>('/honeypot/hits')); setLoadError(null) } catch (e) { useToast.getState().error(e instanceof Error ? e.message : 'Failed to load data'); setLoadError(e instanceof Error ? e.message : 'Failed to load data') }
    try { setHoneypotStats(await apiGet<Record<string, unknown>>('/honeypot/stats')) } catch (e) { useToast.getState().error(e instanceof Error ? e.message : 'Failed to load honeypot stats') }
  }, [])
  const loadTLS = useCallback(async () => { try { setFingerprints(await apiGet<TLSFingerprint[]>('/tls-fingerprints')); setLoadError(null) } catch (e) { useToast.getState().error(e instanceof Error ? e.message : 'Failed to load data'); setLoadError(e instanceof Error ? e.message : 'Failed to load data') } }, [])
  const loadFP = useCallback(async () => { try { setFpList(await apiGet<FalsePositive[]>('/false-positives')); setLoadError(null) } catch (e) { useToast.getState().error(e instanceof Error ? e.message : 'Failed to load data'); setLoadError(e instanceof Error ? e.message : 'Failed to load data') } }, [])
  const loadLibinject = useCallback(async () => { try { setLibinjectStats(await apiGet<LibinjectStats>('/libinjection/stats')) } catch (e) { useToast.getState().error(e instanceof Error ? e.message : 'Failed to load libinject stats') } }, [])
  const loadReputation = useCallback(async () => {
    try { setRepStats(await apiGet<ReputationStats>('/reputation/stats')) } catch (e) { useToast.getState().error(e instanceof Error ? e.message : 'Failed to load reputation stats') }
    try { setRepTop(await apiGet<ReputationTopEntry[]>('/reputation/top')) } catch (e) { useToast.getState().error(e instanceof Error ? e.message : 'Failed to load reputation top') }
  }, [])
  const loadGraphQL = useCallback(async () => { try { setGraphqlStats(await apiGet<GraphQLStats>('/graphql/stats')) } catch (e) { useToast.getState().error(e instanceof Error ? e.message : 'Failed to load graphql stats') } }, [])
  const loadBodyInspect = useCallback(async () => { try { setBodyInspectStats(await apiGet<BodyInspectStats>('/body-inspect/stats')) } catch (e) { useToast.getState().error(e instanceof Error ? e.message : 'Failed to load body inspect') } }, [])

  useEffect(() => { Promise.all([loadGeo(), loadAllow(), loadHoneypot(), loadTLS(), loadFP(), loadLibinject(), loadReputation(), loadGraphQL(), loadBodyInspect()]).finally(() => setLoading(false)) }, [loadGeo, loadAllow, loadHoneypot, loadTLS, loadFP, loadLibinject, loadReputation, loadGraphQL, loadBodyInspect])

  useEffect(() => {
    if (!showForm) return
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setShowForm(false) }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [showForm])

  const handleAddGeo = async () => {
    setFormError('')
    if (!form.country_code || form.country_code.length !== 2) { setFormError('Country code must be 2 letters'); return }
    setSubmitting(true)
    try { await apiPost('/geoip', form); setShowForm(false); loadGeo() } catch (e) { useToast.getState().error(e instanceof Error ? e.message : 'Error') } finally { setSubmitting(false) }
  }
  const handleAddAllow = async () => {
    setFormError('')
    if (!form.pattern.trim()) { setFormError('Pattern is required'); return }
    setSubmitting(true)
    try { await apiPost('/allowlist', form); setShowForm(false); loadAllow() } catch (e) { useToast.getState().error(e instanceof Error ? e.message : 'Error') } finally { setSubmitting(false) }
  }
  const handleDeleteGeo = async (id: number) => { try { await apiDelete(`/geoip/${id}`); loadGeo() } catch (e) { useToast.getState().error(e instanceof Error ? e.message : 'Delete geo rule failed') } }
  const handleDeleteAllow = async (id: number) => { try { await apiDelete(`/allowlist/${id}`); loadAllow() } catch (e) { useToast.getState().error(e instanceof Error ? e.message : 'Delete allowlist failed') } }
  const handleToggleRep = async (hash: string, rep: string) => {
    try { await apiPut(`/tls-fingerprints/${hash}/reputation`, { reputation: rep }); loadTLS() } catch (e) { useToast.getState().error(e instanceof Error ? e.message : 'Toggle reputation failed') }
  }
  const handleDeleteFP = async (id: number) => { try { await apiDelete(`/false-positives/${id}`); loadFP() } catch (e) { useToast.getState().error(e instanceof Error ? e.message : 'Delete false positive failed') } }
  const handleRepCheck = async () => {
    if (!repCheckIP.trim()) return
    setRepCheckLoading(true)
    setRepCheckResult(null)
    try { setRepCheckResult(await apiPost<Record<string, unknown>>(`/reputation/check/${encodeURIComponent(repCheckIP.trim())}`, {})) } catch (e) { useToast.getState().error(e instanceof Error ? e.message : 'Check failed') } finally { setRepCheckLoading(false) }
  }

  const tabs = [
    { key: 'geoip', label: 'GeoIP', icon: Globe },
    { key: 'allowlist', label: 'Allowlist', icon: ShieldAlert },
    { key: 'honeypot', label: 'Honeypot', icon: Flower2 },
    { key: 'tls', label: 'TLS Fingerprints', icon: Fingerprint },
    { key: 'fp', label: 'False Positives', icon: AlertTriangle },
    { key: 'libinject', label: 'SQLi/XSS', icon: Crosshair },
    { key: 'reputation', label: 'IP Reputation', icon: Database },
    { key: 'graphql', label: 'GraphQL', icon: Layers },
    { key: 'bodyinspect', label: 'Body Inspect', icon: Search },
  ] as const

  const geoColumns = [
    { key: 'country_code', header: 'Country', render: (r: GeoIPRule) => <span className="font-mono font-medium">{r.country_code}</span> },
    { key: 'action', header: 'Action', render: (r: GeoIPRule) => <StatusBadge status={r.action === 'block' ? 'blocked' : 'allowed'} /> },
    { key: 'reason', header: 'Reason' },
    { key: 'enabled', header: 'Status', render: (r: GeoIPRule) => <StatusBadge status={r.enabled ? 'active' : 'inactive'} /> },
    { key: 'actions', header: '', render: (r: GeoIPRule) => <button onClick={() => handleDeleteGeo(r.id)} aria-label="Delete GeoIP rule" className="p-1.5 rounded-md hover:bg-red-50 text-slate-400 hover:text-red-500"><Trash2 size={14} /></button> },
  ]

  const allowColumns = [
    { key: 'rule_type', header: 'Type', render: (r: AllowlistRule) => <span className="badge bg-slate-50 text-slate-600">{r.rule_type}</span> },
    { key: 'pattern', header: 'Pattern', render: (r: AllowlistRule) => <span className="font-mono text-xs">{r.pattern}</span> },
    { key: 'description', header: 'Description' },
    { key: 'priority', header: 'Priority', render: (r: AllowlistRule) => <span className="font-mono text-xs">{r.priority}</span> },
    { key: 'actions', header: '', render: (r: AllowlistRule) => <button onClick={() => handleDeleteAllow(r.id)} aria-label="Delete allowlist rule" className="p-1.5 rounded-md hover:bg-red-50 text-slate-400 hover:text-red-500"><Trash2 size={14} /></button> },
  ]

  const honeypotColumns = [
    { key: 'client_ip', header: 'IP', render: (r: HoneypotHit) => <span className="font-mono text-xs">{r.client_ip}</span> },
    { key: 'method', header: 'Method', render: (r: HoneypotHit) => <span className="badge bg-slate-50 text-slate-600">{r.method}</span> },
    { key: 'path', header: 'Path', render: (r: HoneypotHit) => <span className="font-mono text-xs text-red-600">{r.path}</span> },
    { key: 'user_agent', header: 'User Agent', render: (r: HoneypotHit) => <span className="text-xs text-slate-500 max-w-[200px] truncate block">{r.user_agent}</span> },
    { key: 'created_at', header: 'Time', render: (r: HoneypotHit) => <span className="text-xs text-slate-400">{new Date(r.created_at).toLocaleString()}</span> },
  ]

  const tlsColumns = [
    { key: 'ja3_hash', header: 'JA3 Hash', render: (r: TLSFingerprint) => <span className="font-mono text-xs">{r.ja3_hash?.slice(0, 16)}...</span> },
    { key: 'client_ip', header: 'IP', render: (r: TLSFingerprint) => <span className="font-mono text-xs">{r.client_ip}</span> },
    { key: 'request_count', header: 'Requests', render: (r: TLSFingerprint) => <span className="font-mono text-xs">{r.request_count}</span> },
    { key: 'reputation', header: 'Reputation', render: (r: TLSFingerprint) => <StatusBadge status={r.reputation === 'blocked' ? 'blocked' : r.reputation === 'trusted' ? 'allowed' : 'pending'} /> },
    { key: 'last_seen', header: 'Last Seen', render: (r: TLSFingerprint) => <span className="text-xs text-slate-400">{r.last_seen ? new Date(r.last_seen).toLocaleString() : '-'}</span> },
    { key: 'actions', header: '', render: (r: TLSFingerprint) => (
      <div className="flex gap-1">
        <button onClick={() => handleToggleRep(r.ja3_hash, 'blocked')} aria-label="Block fingerprint" className="p-1 rounded hover:bg-red-50 text-red-400" title="Block">Block</button>
        <button onClick={() => handleToggleRep(r.ja3_hash, 'trusted')} aria-label="Trust fingerprint" className="p-1 rounded hover:bg-emerald-50 text-emerald-400" title="Trust">Trust</button>
      </div>
    )},
  ]

  const fpColumns = [
    { key: 'log_id', header: 'Log ID', render: (r: FalsePositive) => <span className="font-mono text-xs">#{r.log_id}</span> },
    { key: 'rule_id', header: 'Rule ID', render: (r: FalsePositive) => <span className="font-mono text-xs">{r.rule_id || '-'}</span> },
    { key: 'reason', header: 'Reason', render: (r: FalsePositive) => <span className="text-xs text-slate-600 max-w-[300px] truncate block">{r.reason || '-'}</span> },
    { key: 'username', header: 'Reviewed By', render: (r: FalsePositive) => <span className="text-xs">{r.username}</span> },
    { key: 'created_at', header: 'Date', render: (r: FalsePositive) => <span className="text-xs text-slate-400">{new Date(r.created_at).toLocaleString()}</span> },
    { key: 'actions', header: '', render: (r: FalsePositive) => <button onClick={() => handleDeleteFP(r.id)} aria-label="Remove false positive" className="p-1.5 rounded-md hover:bg-red-50 text-slate-400 hover:text-red-500"><Trash2 size={14} /></button> },
  ]

  const repTopColumns = [
    { key: 'ip', header: 'IP', render: (r: ReputationTopEntry) => <span className="font-mono text-xs">{r.ip}</span> },
    { key: 'abuse_confidence_score', header: 'Abuse Score', render: (r: ReputationTopEntry) => <span className={`font-mono text-xs font-bold ${r.abuse_confidence_score >= 80 ? 'text-red-600' : r.abuse_confidence_score >= 50 ? 'text-amber-600' : 'text-emerald-600'}`}>{r.abuse_confidence_score}%</span> },
    { key: 'country_code', header: 'Country', render: (r: ReputationTopEntry) => <span className="font-mono text-xs">{r.country_code || '-'}</span> },
    { key: 'isp', header: 'ISP', render: (r: ReputationTopEntry) => <span className="text-xs text-slate-600 max-w-[200px] truncate block">{r.isp || '-'}</span> },
    { key: 'total_reports', header: 'Reports', render: (r: ReputationTopEntry) => <span className="font-mono text-xs">{r.total_reports}</span> },
  ]

  const libinjectDetCols = [
    { key: 'time', header: 'Time', render: (r: Record<string, string>) => <span className="text-xs text-slate-400">{r.time ? new Date(r.time).toLocaleString() : '-'}</span> },
    { key: 'type', header: 'Type', render: (r: Record<string, string>) => <span className={`badge ${r.type === 'sqli' ? 'bg-red-50 text-red-700' : 'bg-amber-50 text-amber-700'}`}>{r.type?.toUpperCase()}</span> },
    { key: 'payload', header: 'Payload', render: (r: Record<string, string>) => <span className="font-mono text-xs text-red-600 max-w-[300px] truncate block">{r.payload}</span> },
    { key: 'ip', header: 'IP', render: (r: Record<string, string>) => <span className="font-mono text-xs">{r.ip}</span> },
  ]

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold tracking-tight text-slate-900 flex items-center gap-2">
        <ShieldAlert size={20} className="text-slate-600" />
        Security Center
      </h1>

      {loadError && <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-sm text-red-700">{loadError}</div>}

      {/* Tabs */}
      <div className="flex gap-1 p-1 bg-ivory-100 rounded-lg w-fit">
        {tabs.map(({ key, label, icon: Icon }) => (
          <button key={key} onClick={() => setTab(key)}
            className={`flex items-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition-colors ${tab === key ? 'bg-white shadow-sm text-slate-900' : 'text-slate-500 hover:text-slate-700'}`}>
            <Icon size={16} /> {label}
          </button>
        ))}
      </div>

      {loading && <SkeletonTable rows={5} cols={5} />}
      {/* GeoIP Tab */}
      {!loading && tab === 'geoip' && (
        <div className="space-y-4">
          <div className="flex justify-end">
            <button onClick={() => { setForm({ ...form, rule_type: 'country' }); setShowForm(true) }} className="btn-primary"><Plus size={16} /> Add Country Rule</button>
          </div>
          <DataTable columns={geoColumns} data={geoRules} searchable pageSize={25} emptyMessage="No GeoIP rules configured" />
        </div>
      )}

      {/* Allowlist Tab */}
      {!loading && tab === 'allowlist' && (
        <div className="space-y-4">
          <div className="p-4 bg-amber-50 border border-amber-200 rounded-lg text-sm text-amber-800">
            <strong>Default-Deny Mode:</strong> Only requests matching allowlist rules will pass through. All others are blocked.
          </div>
          <div className="flex justify-end">
            <button onClick={() => { setForm({ ...form, rule_type: 'ip' }); setShowForm(true) }} className="btn-primary"><Plus size={16} /> Add Allow Rule</button>
          </div>
          <DataTable columns={allowColumns} data={allowRules} searchable pageSize={25} emptyMessage="No allowlist rules defined" />
        </div>
      )}

      {/* Honeypot Tab */}
      {!loading && tab === 'honeypot' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <StatCard label="Total Hits" value={String(honeypotStats.total_hits || 0)} icon={Flower2} color="brick" />
            <StatCard label="Hits Today" value={String(honeypotStats.hits_today || 0)} icon={Zap} color="burnt" />
            <StatCard label="Attackers" value={String((honeypotStats.top_attackers as unknown[])?.length || 0)} icon={ShieldAlert} color="ink" />
          </div>
          <DataTable columns={honeypotColumns} data={honeypotHits} searchable pageSize={25} emptyMessage="No honeypot hits yet" />
        </div>
      )}

      {/* TLS Fingerprints Tab */}
      {!loading && tab === 'tls' && (
        <div className="space-y-4">
          <DataTable columns={tlsColumns} data={fingerprints} searchable pageSize={25} emptyMessage="No TLS fingerprints recorded" />
        </div>
      )}

      {/* False Positives Tab */}
      {!loading && tab === 'fp' && (
        <div className="space-y-4">
          <div className="p-4 bg-amber-50 border border-amber-200 rounded-lg text-sm text-amber-800">
            <strong>False Positive Tuning:</strong> Entries marked as false positives help improve rule accuracy. Review and remove incorrect markings to refine detection.
          </div>
          <DataTable columns={fpColumns} data={fpList} searchable pageSize={25} emptyMessage="No false positives recorded yet" />
        </div>
      )}

      {/* Libinjection (SQLi/XSS) Tab */}
      {!loading && tab === 'libinject' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
            <StatCard label="Scanned" value={String(libinjectStats?.requests_scanned ?? 0)} icon={Crosshair} color="steel" />
            <StatCard label="SQLi Blocked" value={String(libinjectStats?.sqli_blocked ?? 0)} icon={ShieldAlert} color="brick" />
            <StatCard label="XSS Blocked" value={String(libinjectStats?.xss_blocked ?? 0)} icon={ShieldAlert} color="burnt" />
            <StatCard label="SQLi Detected" value={String(libinjectStats?.sqli_detected ?? 0)} icon={Zap} color="brick" />
            <StatCard label="XSS Detected" value={String(libinjectStats?.xss_detected ?? 0)} icon={Zap} color="burnt" />
          </div>
          <div className="card p-4">
            <h3 className="text-sm font-semibold text-slate-900 mb-3">Recent Detections</h3>
            <DataTable columns={libinjectDetCols} data={libinjectStats?.recent_detections || []} searchable pageSize={10} emptyMessage="No recent SQLi/XSS detections" />
          </div>
        </div>
      )}

      {/* IP Reputation Tab */}
      {!loading && tab === 'reputation' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-3 lg:grid-cols-6 gap-4">
            <StatCard label="IPs Checked" value={String(repStats?.ips_checked ?? 0)} icon={Database} color="steel" />
            <StatCard label="IPs Blocked" value={String(repStats?.ips_blocked ?? 0)} icon={ShieldAlert} color="brick" />
            <StatCard label="Cache Hits" value={String(repStats?.cache_hits ?? 0)} icon={Zap} color="forest" />
            <StatCard label="Cache Misses" value={String(repStats?.cache_misses ?? 0)} icon={Database} color="ink" />
            <StatCard label="API Errors" value={String(repStats?.api_errors ?? 0)} icon={AlertTriangle} color="burnt" />
            <StatCard label="Hit Rate" value={`${(repStats?.cache_hit_rate ?? 0).toFixed(1)}%`} icon={Zap} color="steel" />
          </div>
          <div className="card p-4">
            <h3 className="text-sm font-semibold text-slate-900 mb-3">Check IP Reputation</h3>
            <div className="flex gap-2 mb-3">
              <input value={repCheckIP} onChange={(e) => setRepCheckIP(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && handleRepCheck()} className="input-field font-mono text-xs flex-1" placeholder="Enter IP address (e.g. 1.2.3.4)" />
              <button onClick={handleRepCheck} disabled={repCheckLoading || !repCheckIP.trim()} className="btn-primary disabled:opacity-50"><Search size={14} /> {repCheckLoading ? 'Checking...' : 'Check'}</button>
            </div>
            {repCheckResult && (
              <div className="p-3 bg-slate-50 rounded-lg text-sm space-y-1">
                {Object.entries(repCheckResult).map(([k, v]) => (
                  <div key={k} className="flex justify-between"><span className="text-slate-500">{k}</span><span className="font-mono text-xs">{String(v)}</span></div>
                ))}
              </div>
            )}
          </div>
          <div className="card p-4">
            <h3 className="text-sm font-semibold text-slate-900 mb-3">Top Lookups</h3>
            <DataTable columns={repTopColumns} data={repTop} searchable pageSize={10} emptyMessage="No reputation lookups yet" />
          </div>
        </div>
      )}

      {/* GraphQL Protection Tab */}
      {!loading && tab === 'graphql' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <StatCard label="Total Queries" value={String(graphqlStats?.total_queries ?? 0)} icon={Layers} color="steel" />
            <StatCard label="Queries Blocked" value={String(graphqlStats?.queries_blocked ?? 0)} icon={ShieldAlert} color="brick" />
            <StatCard label="Introspection Blocked" value={String(graphqlStats?.introspection_blocked ?? 0)} icon={ShieldAlert} color="burnt" />
            <StatCard label="Avg Depth" value={(graphqlStats?.avg_depth ?? 0).toFixed(1)} icon={Layers} color="ink" />
          </div>
          <div className="card p-4">
            <h3 className="text-sm font-semibold text-slate-900 mb-3">Violation Breakdown</h3>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="p-3 bg-red-50 rounded-lg text-center">
                <div className="font-mono text-2xl font-bold text-red-700">{graphqlStats?.depth_violations ?? 0}</div>
                <div className="text-xs text-red-600 mt-1">Depth Violations</div>
              </div>
              <div className="p-3 bg-amber-50 rounded-lg text-center">
                <div className="font-mono text-2xl font-bold text-amber-700">{graphqlStats?.complexity_violations ?? 0}</div>
                <div className="text-xs text-amber-600 mt-1">Complexity Violations</div>
              </div>
              <div className="p-3 bg-orange-50 rounded-lg text-center">
                <div className="font-mono text-2xl font-bold text-orange-700">{graphqlStats?.operation_violations ?? 0}</div>
                <div className="text-xs text-orange-600 mt-1">Operation Violations</div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Body Inspection Tab */}
      {!loading && tab === 'bodyinspect' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <StatCard label="Threats Found" value={String(bodyInspectStats?.threats_found ?? 0)} icon={ShieldAlert} color="brick" />
            <StatCard label="JSON Parsed" value={String(bodyInspectStats?.parsed_json ?? 0)} icon={Search} color="steel" />
            <StatCard label="Form Parsed" value={String(bodyInspectStats?.parsed_form ?? 0)} icon={Search} color="forest" />
            <StatCard label="XML Parsed" value={String(bodyInspectStats?.parsed_xml ?? 0)} icon={Search} color="burnt" />
          </div>
          <div className="card p-4">
            <h3 className="text-sm font-semibold text-slate-900 mb-3">Content Type Breakdown</h3>
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
              {[
                { label: 'JSON', value: bodyInspectStats?.parsed_json ?? 0, color: 'bg-blue-50 text-blue-700' },
                { label: 'Form', value: bodyInspectStats?.parsed_form ?? 0, color: 'bg-emerald-50 text-emerald-700' },
                { label: 'Multipart', value: bodyInspectStats?.parsed_multipart ?? 0, color: 'bg-purple-50 text-purple-700' },
                { label: 'XML', value: bodyInspectStats?.parsed_xml ?? 0, color: 'bg-amber-50 text-amber-700' },
                { label: 'Text', value: bodyInspectStats?.parsed_text ?? 0, color: 'bg-slate-50 text-slate-700' },
              ].map(({ label, value, color }) => (
                <div key={label} className={`p-3 rounded-lg text-center ${color}`}>
                  <div className="font-mono text-lg font-bold">{value}</div>
                  <div className="text-xs mt-0.5">{label}</div>
                </div>
              ))}
            </div>
          </div>
          {bodyInspectStats?.top_attacks && Object.keys(bodyInspectStats.top_attacks).length > 0 && (
            <div className="card p-4">
              <h3 className="text-sm font-semibold text-slate-900 mb-3">Top Attack Types</h3>
              <div className="space-y-2">
                {Object.entries(bodyInspectStats.top_attacks).sort(([, a], [, b]) => b - a).map(([type, count]) => (
                  <div key={type} className="flex items-center gap-3">
                    <span className="text-xs text-slate-600 w-32 truncate">{type}</span>
                    <div className="flex-1 bg-slate-100 rounded-full h-2 overflow-hidden">
                      <div className="bg-red-500 h-full rounded-full" style={{ width: `${Math.min(100, (count / Math.max(...Object.values(bodyInspectStats.top_attacks))) * 100)}%` }} />
                    </div>
                    <span className="font-mono text-xs text-slate-500 w-12 text-right">{count}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Add Rule Modal */}
      {showForm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/30 backdrop-blur-sm" onClick={() => setShowForm(false)}>
          <div role="dialog" aria-modal="true" aria-labelledby="add-rule-title" className="w-full max-w-md mx-4 bg-white rounded-2xl shadow-xl border border-ivory-300 p-6 animate-slide-up" onClick={(e) => e.stopPropagation()}>
            <h2 id="add-rule-title" className="text-lg font-semibold text-slate-900 mb-4">Add Rule</h2>
            {formError && <div className="p-3 bg-red-50 text-red-700 text-sm rounded-lg mb-3">{formError}</div>}
            <div className="space-y-3">
              {tab === 'geoip' ? (
                <>
                  <div>
                    <label className="block text-xs font-medium text-slate-600 mb-1">Country Code (2 letter)</label>
                    <input value={form.country_code} onChange={(e) => setForm({ ...form, country_code: e.target.value.toUpperCase() })} className="input-field" placeholder="US" maxLength={2} />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-600 mb-1">Action</label>
                    <select value={form.action} onChange={(e) => setForm({ ...form, action: e.target.value })} className="input-field">
                      <option value="block">Block</option>
                      <option value="allow">Allow</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-600 mb-1">Reason</label>
                    <input value={form.reason} onChange={(e) => setForm({ ...form, reason: e.target.value })} className="input-field" placeholder="Blocked region" />
                  </div>
                </>
              ) : (
                <>
                  <div>
                    <label className="block text-xs font-medium text-slate-600 mb-1">Rule Type</label>
                    <select value={form.rule_type} onChange={(e) => setForm({ ...form, rule_type: e.target.value })} className="input-field">
                      <option value="ip">IP / CIDR</option>
                      <option value="path">Path (exact)</option>
                      <option value="path_prefix">Path Prefix</option>
                      <option value="host">Host</option>
                      <option value="method_path">Method + Path</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-600 mb-1">Pattern</label>
                    <input value={form.pattern} onChange={(e) => setForm({ ...form, pattern: e.target.value })} className="input-field font-mono text-xs" placeholder="192.168.1.0/24" />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-600 mb-1">Description</label>
                    <input value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} className="input-field" placeholder="Office network" />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-600 mb-1">Priority</label>
                    <input type="number" value={form.priority} onChange={(e) => setForm({ ...form, priority: parseInt(e.target.value) || 100 })} className="input-field w-24" />
                  </div>
                </>
              )}
            </div>
            <div className="flex justify-end gap-3 mt-5">
              <button onClick={() => setShowForm(false)} className="btn-secondary">Cancel</button>
              <button onClick={tab === 'geoip' ? handleAddGeo : handleAddAllow} disabled={submitting} className="btn-primary disabled:opacity-50">{submitting ? 'Adding...' : 'Add Rule'}</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
