import { useState, useCallback, useEffect } from 'react'
import { Search, Download, X, ScrollText, AlertTriangle } from 'lucide-react'
import DataTable from '../components/DataTable'
import StatusBadge from '../components/StatusBadge'
import { apiGet, apiPost } from '../api/client'
import { useMinDisplay } from '../hooks/useMinDisplay'
import { useToast } from '../hooks/useToast'
import { SkeletonTable } from '../components/Skeleton'

interface LogEntry {
  id: number
  timestamp: string
  client_ip: string
  method: string
  host: string
  path: string
  query: string
  user_agent: string
  action: string
  threat_score: number
  ai_classification: string
  response_code: number
  response_time_ms: number
  country: string
}

interface Filters {
  ip: string
  path: string
  action: string
  threat_min: string
  threat_max: string
  page: string
}

export default function RequestLogs() {
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [filters, setFilters] = useState<Filters>({ ip: '', path: '', action: '', threat_min: '', threat_max: '', page: '1' })
  const [total, setTotal] = useState(0)
  const [selected, setSelected] = useState<LogEntry | null>(null)
  const [search, setSearch] = useState('')
  const [loading, setLoading] = useState(true)
  const [fpReason, setFpReason] = useState('')
  const [fpSubmitting, setFpSubmitting] = useState(false)
  const [showFpForm, setShowFpForm] = useState(false)
  const [loadError, setLoadError] = useState<string | null>(null)
  const showSkeleton = useMinDisplay(loading)

  const handleMarkFP = async () => {
    if (!selected) return
    setFpSubmitting(true)
    try {
      await apiPost(`/logs/${selected.id}/false-positive`, { reason: fpReason })
      useToast.getState().success('Marked as false positive')
      setShowFpForm(false)
      setFpReason('')
    } catch (e) {
      useToast.getState().error(e instanceof Error ? e.message : 'Failed to mark as FP')
    } finally {
      setFpSubmitting(false)
    }
  }

  const loadLogs = useCallback(async () => {
    try {
      const params: Record<string, string> = {}
      if (filters.ip) params.ip = filters.ip
      if (filters.path) params.path = filters.path
      if (filters.action) params.action = filters.action
      if (filters.threat_min) params.threat_min = filters.threat_min
      if (filters.threat_max) params.threat_max = filters.threat_max
      params.page = filters.page
      params.per_page = '50'
      const data = await apiGet<LogEntry[]>('/logs', params)
      setLogs(data || [])
      setTotal((data || []).length)
      setLoadError(null)
    } catch (e) {
      setLogs([])
      useToast.getState().error(e instanceof Error ? e.message : 'Failed to load request logs')
      setLoadError(e instanceof Error ? e.message : 'Failed to load request logs')
    } finally {
      setLoading(false)
    }
  }, [filters])

  useEffect(() => { loadLogs() }, [loadLogs])

  useEffect(() => {
    if (!selected) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { setSelected(null); setShowFpForm(false); setFpReason('') }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [selected])

  const handleExport = async (format: 'csv' | 'json') => {
    try {
      const params: Record<string, string> = { format }
      if (filters.ip) params.ip = filters.ip
      if (filters.action) params.action = filters.action
      const url = `/api/v1/logs/export?${new URLSearchParams(params)}`
      const res = await fetch(url, {
        credentials: 'same-origin'
      })
      const blob = await res.blob()
      const blobUrl = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = blobUrl
      a.download = `aegis-logs.${format}`
      a.click()
      URL.revokeObjectURL(blobUrl)
    } catch (e) {
      useToast.getState().error(e instanceof Error ? e.message : 'Export failed')
    }
  }

  const columns = [
    { key: 'timestamp', header: 'Time', render: (r: LogEntry) => (
      <span className="font-mono text-[11px] text-slate-500">{new Date(r.timestamp).toLocaleString()}</span>
    )},
    { key: 'client_ip', header: 'IP', render: (r: LogEntry) => <span className="font-mono text-xs">{r.client_ip}</span> },
    { key: 'country', header: 'Country', render: (r: LogEntry) => r.country ? (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-slate-100 text-[11px] font-medium text-slate-700">{r.country}</span>
    ) : <span className="text-slate-300">—</span> },
    { key: 'method', header: 'Method', render: (r: LogEntry) => (
      <span className={`font-mono text-[11px] font-bold ${
        r.method === 'GET' ? 'text-accent-600' :
        r.method === 'POST' ? 'text-emerald-600' :
        r.method === 'PUT' ? 'text-amber-600' :
        'text-red-600'
      }`}>{r.method}</span>
    )},
    { key: 'path', header: 'Path', render: (r: LogEntry) => (
      <span className="font-mono text-xs text-slate-600 max-w-[200px] truncate block">{r.path}</span>
    )},
    { key: 'action', header: 'Action', render: (r: LogEntry) => <StatusBadge status={r.action} /> },
    { key: 'threat_score', header: 'Threat', render: (r: LogEntry) => (
      <span className={`font-mono text-xs font-semibold ${
        r.threat_score > 0.7 ? 'text-red-600' :
        r.threat_score > 0.3 ? 'text-amber-600' :
        'text-emerald-600'
      }`}>{r.threat_score?.toFixed(2) ?? '—'}</span>
    )},
    { key: 'response_code', header: 'Code', render: (r: LogEntry) => (
      <span className={`font-mono text-xs ${
        r.response_code >= 500 ? 'text-red-600' :
        r.response_code >= 400 ? 'text-amber-600' :
        'text-emerald-600'
      }`}>{r.response_code}</span>
    )},
    { key: 'response_time_ms', header: 'Time', render: (r: LogEntry) => (
      <span className="font-mono text-xs text-slate-500">{r.response_time_ms}ms</span>
    )},
  ]

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold tracking-tight text-slate-900 flex items-center gap-2">
          <ScrollText size={20} className="text-slate-600" />
          Request Logs
        </h1>
        <div className="flex items-center gap-2">
          <button onClick={() => handleExport('csv')} className="btn-secondary text-xs py-1.5">
            <Download size={14} /> CSV
          </button>
          <button onClick={() => handleExport('json')} className="btn-secondary text-xs py-1.5">
            <Download size={14} /> JSON
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="card p-4">
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <div className="relative">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              value={filters.ip}
              onChange={(e) => setFilters({ ...filters, ip: e.target.value, page: '1' })}
              className="input-field pl-9"
              placeholder="Filter by IP..."
            />
          </div>
          <input
            value={filters.path}
            onChange={(e) => setFilters({ ...filters, path: e.target.value, page: '1' })}
            className="input-field"
            placeholder="Filter by path..."
          />
          <select
            value={filters.action}
            onChange={(e) => setFilters({ ...filters, action: e.target.value, page: '1' })}
            className="input-field"
          >
            <option value="">All Actions</option>
            <option value="allowed">Allowed</option>
            <option value="blocked">Blocked</option>
          </select>
          <input
            value={filters.threat_min}
            onChange={(e) => setFilters({ ...filters, threat_min: e.target.value, page: '1' })}
            className="input-field"
            placeholder="Min threat score"
            type="number"
            step="0.1"
            min="0"
            max="1"
          />
          <input
            value={filters.threat_max}
            onChange={(e) => setFilters({ ...filters, threat_max: e.target.value, page: '1' })}
            className="input-field"
            placeholder="Max threat score"
            type="number"
            step="0.1"
            min="0"
            max="1"
          />
        </div>
      </div>

      {loadError && <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-sm text-red-700">{loadError}</div>}

      {/* Table */}
      {showSkeleton ? <SkeletonTable rows={5} cols={8} /> : (
        <DataTable
          columns={columns}
          data={logs}
          searchable
          pageSize={50}
          emptyMessage="No requests logged yet"
          onRowClick={setSelected}
        />
      )}

      {/* Detail Modal */}
      {selected && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/30 backdrop-blur-sm" role="dialog" aria-modal="true" onClick={() => { setSelected(null); setShowFpForm(false); setFpReason('') }}>
          <div className="w-full max-w-2xl mx-4 bg-white rounded-2xl shadow-xl border border-ivory-300 p-4 md:p-6 animate-slide-up max-h-[90vh] overflow-y-auto" onClick={(e) => e.stopPropagation()} onKeyDown={(e) => e.key === 'Escape' && setSelected(null)}>
            <div className="flex items-center justify-between mb-5">
              <h2 className="text-lg font-semibold text-slate-900">Request Details</h2>
              <button onClick={() => { setSelected(null); setShowFpForm(false); setFpReason('') }} className="p-1.5 rounded-lg hover:bg-ivory-100 text-slate-400 transition-colors">
                <X size={18} />
              </button>
            </div>
            <div className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div><span className="stat-label">Timestamp</span><p className="font-mono text-sm mt-1">{new Date(selected.timestamp).toLocaleString()}</p></div>
                <div><span className="stat-label">Client IP</span><p className="font-mono text-sm mt-1">{selected.client_ip}</p></div>
                <div><span className="stat-label">Method</span><p className="font-mono text-sm font-bold mt-1">{selected.method}</p></div>
                <div><span className="stat-label">Response Code</span><p className="font-mono text-sm mt-1">{selected.response_code}</p></div>
                <div><span className="stat-label">Action</span><div className="mt-1"><StatusBadge status={selected.action} /></div></div>
                <div><span className="stat-label">AI Classification</span><div className="mt-1"><StatusBadge status={selected.ai_classification || 'benign'} /></div></div>
                <div><span className="stat-label">Threat Score</span><p className="font-mono text-sm mt-1">{selected.threat_score?.toFixed(4) ?? '—'}</p></div>
                <div><span className="stat-label">Response Time</span><p className="font-mono text-sm mt-1">{selected.response_time_ms}ms</p></div>
              </div>
              <div>
                <span className="stat-label">Full Path</span>
                <p className="font-mono text-sm mt-1 text-slate-700 break-all">{selected.path}</p>
              </div>
              {selected.query && (
                <div>
                  <span className="stat-label">Query String</span>
                  <p className="font-mono text-sm mt-1 text-slate-700 break-all">{selected.query}</p>
                </div>
              )}
              <div>
                <span className="stat-label">User Agent</span>
                <p className="font-mono text-xs mt-1 text-slate-500 break-all">{selected.user_agent}</p>
              </div>

              {/* False Positive Feedback */}
              <div className="pt-3 border-t border-ivory-200">
                {!showFpForm ? (
                  <button
                    onClick={() => setShowFpForm(true)}
                    className="btn-secondary text-xs py-1.5 text-amber-600 border-amber-200 hover:bg-amber-50"
                  >
                    <AlertTriangle size={14} /> Mark as False Positive
                  </button>
                ) : (
                  <div className="space-y-3">
                    <label className="block text-xs font-medium text-slate-600">Reason for marking as false positive</label>
                    <textarea
                      value={fpReason}
                      onChange={(e) => setFpReason(e.target.value)}
                      className="input-field min-h-[60px]"
                      placeholder="Why is this a false positive? (e.g., legitimate admin request误 flagged)"
                    />
                    <div className="flex gap-2">
                      <button onClick={handleMarkFP} disabled={fpSubmitting} className="btn-primary text-xs py-1.5 disabled:opacity-50">
                        {fpSubmitting ? 'Submitting...' : 'Confirm'}
                      </button>
                      <button onClick={() => { setShowFpForm(false); setFpReason('') }} className="btn-secondary text-xs py-1.5">Cancel</button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
