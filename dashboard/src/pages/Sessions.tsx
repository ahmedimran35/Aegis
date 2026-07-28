import { useState, useEffect, useCallback } from 'react'
import { Radio, Fingerprint } from 'lucide-react'
import DataTable from '../components/DataTable'
import StatusBadge from '../components/StatusBadge'
import StatCard from '../components/StatCard'
import { SkeletonStatCard, SkeletonTable } from '../components/Skeleton'
import { apiGet } from '../api/client'

interface Session {
  id: string
  client_ip: string
  user_agent: string
  fingerprint: string
  first_seen: string
  last_seen: string
  request_count: number
  blocked_count: number
  country: string
}

export default function Sessions() {
  const [sessions, setSessions] = useState<Session[]>([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState<string | null>(null)

  const loadSessions = useCallback(async () => {
    try { setSessions(await apiGet<Session[]>('/sessions')); setLoadError(null) } catch (e) { /* sanitized message via client.ts */ setLoadError(e instanceof Error ? e.message : 'Failed to load sessions') } finally { setLoading(false) }
  }, [])

  useEffect(() => { loadSessions() }, [loadSessions])

  const list = sessions || []
  const totalReqs = list.reduce((s, r) => s + r.request_count, 0)
  const totalBlocked = list.reduce((s, r) => s + r.blocked_count, 0)
  const uniqueIPs = new Set(list.map(s => s.client_ip)).size
  const uniqueFPs = new Set(list.map(s => s.fingerprint).filter(Boolean)).size

  const columns = [
    { key: 'id', header: 'Session', render: (s: Session) => <span className="font-mono text-xs">{s.id.slice(0, 12)}...</span> },
    { key: 'client_ip', header: 'IP', render: (s: Session) => <span className="font-mono text-xs">{s.client_ip}</span> },
    { key: 'fingerprint', header: 'Fingerprint', render: (s: Session) => s.fingerprint ? <span className="font-mono text-xs text-slate-400">{s.fingerprint.slice(0, 8)}...</span> : <span className="text-xs text-slate-300">-</span> },
    { key: 'user_agent', header: 'User Agent', render: (s: Session) => <span className="text-xs text-slate-500 max-w-[180px] truncate block">{s.user_agent}</span> },
    { key: 'request_count', header: 'Requests', render: (s: Session) => <span className="font-mono text-xs">{s.request_count}</span> },
    { key: 'blocked_count', header: 'Blocked', render: (s: Session) => s.blocked_count > 0 ? <StatusBadge status="blocked" /> : <span className="text-xs text-slate-300">0</span> },
    { key: 'last_seen', header: 'Last Seen', render: (s: Session) => <span className="text-xs text-slate-400">{new Date(s.last_seen).toLocaleString()}</span> },
  ]

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold tracking-tight text-slate-900 flex items-center gap-2">
        <Radio size={20} className="text-slate-600" />
        Sessions
      </h1>

      {loadError && <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-sm text-red-700">{loadError}</div>}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {loading ? (
          Array.from({ length: 4 }).map((_, i) => <SkeletonStatCard key={i} />)
        ) : (
          <>
            <StatCard label="Active Sessions" value={list.length} icon={Radio} color="blue" />
            <StatCard label="Unique IPs" value={uniqueIPs} icon={Radio} color="slate" />
            <StatCard label="Unique Fingerprints" value={uniqueFPs} icon={Fingerprint} color="amber" />
            <StatCard label="Total Blocked" value={totalBlocked} icon={Radio} color="red" />
          </>
        )}
      </div>

      {loading ? <SkeletonTable rows={5} cols={7} /> : (
        <DataTable columns={columns} data={sessions} searchable pageSize={25} emptyMessage="No active sessions" />
      )}
    </div>
  )
}
