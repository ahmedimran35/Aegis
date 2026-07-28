import { useState, useEffect, useCallback } from 'react'
import { ScrollText, Filter } from 'lucide-react'
import DataTable from '../components/DataTable'
import StatusBadge from '../components/StatusBadge'
import { apiGet } from '../api/client'
import { SkeletonTable } from '../components/Skeleton'

interface AuditEntry {
  id: number
  user_id: number
  username: string
  action: string
  resource_type: string
  resource_id: string
  details: Record<string, unknown>
  ip_address: string
  created_at: string
}

export default function AuditLog() {
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [filter, setFilter] = useState({ resource_type: '' })
  const [loadError, setLoadError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const perPage = 50

  const loadEntries = useCallback(async () => {
    try {
      const params: Record<string, string> = { page: String(page), per_page: String(perPage) }
      if (filter.resource_type) params.resource_type = filter.resource_type
      const qs = Object.entries(params).filter(([, v]) => v).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&')
      const json = await apiGet<{ data: AuditEntry[]; meta?: { total: number } }>(`/audit${qs ? '?' + qs : ''}`)
      setEntries(Array.isArray(json.data) ? json.data : [])
      setTotal(json.meta?.total ?? 0)
      setLoadError(null)
    } catch (e) { setLoadError(e instanceof Error ? e.message : 'Failed to load audit log') } finally { setLoading(false) }
  }, [page, filter])

  useEffect(() => { loadEntries() }, [loadEntries])

  const actionColor = (action: string) => {
    if (action.includes('create')) return 'active'
    if (action.includes('delete')) return 'blocked'
    if (action.includes('update') || action.includes('toggle')) return 'pending'
    return 'inactive'
  }

  const columns = [
    { key: 'created_at', header: 'Time', render: (e: AuditEntry) => <span className="text-xs text-slate-400 whitespace-nowrap">{new Date(e.created_at).toLocaleString()}</span> },
    { key: 'username', header: 'User', render: (e: AuditEntry) => <span className="font-medium text-sm">{e.username}</span> },
    { key: 'action', header: 'Action', render: (e: AuditEntry) => <StatusBadge status={actionColor(e.action)} /> },
    { key: 'resource_type', header: 'Resource', render: (e: AuditEntry) => <span className="badge bg-slate-50 text-slate-600">{e.resource_type}</span> },
    { key: 'resource_id', header: 'ID', render: (e: AuditEntry) => <span className="font-mono text-xs">{e.resource_id}</span> },
    { key: 'details', header: 'Details', render: (e: AuditEntry) => (
      <span className="text-xs text-slate-500 max-w-[200px] truncate block">
        {e.details ? JSON.stringify(e.details).slice(0, 80) : '-'}
      </span>
    )},
    { key: 'ip_address', header: 'IP', render: (e: AuditEntry) => <span className="font-mono text-xs">{e.ip_address || '-'}</span> },
  ]

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold tracking-tight text-slate-900 flex items-center gap-2">
          <ScrollText size={20} className="text-slate-600" />
          Audit Log
        </h1>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        <Filter size={16} className="text-slate-400" />
        <select value={filter.resource_type} onChange={(e) => { setFilter({ ...filter, resource_type: e.target.value }); setPage(1) }} className="input-field sm:w-48">
          <option value="">All Resources</option>
          <option value="rule">Rules</option>
          <option value="user">Users</option>
          <option value="settings">Settings</option>
          <option value="virtual_patch">Virtual Patches</option>
        </select>
      </div>

      {loadError && <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-sm text-red-700">{loadError}</div>}

      {loading ? <SkeletonTable rows={5} cols={7} /> : <DataTable columns={columns} data={entries} searchable pageSize={25} emptyMessage="No audit events recorded" />}

      {/* Pagination */}
      <div className="flex items-center justify-between text-sm text-slate-500">
        <span>Showing {entries.length} of {total} entries</span>
        <div className="flex gap-2">
          <button onClick={() => setPage(Math.max(1, page - 1))} disabled={page === 1} className="btn-secondary text-xs disabled:opacity-50">Previous</button>
          <span className="px-3 py-1.5 text-xs">Page {page}</span>
          <button onClick={() => setPage(page + 1)} disabled={entries.length < perPage} className="btn-secondary text-xs disabled:opacity-50">Next</button>
        </div>
      </div>
    </div>
  )
}
