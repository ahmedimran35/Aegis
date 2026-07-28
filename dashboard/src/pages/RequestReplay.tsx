import { ShieldOff, Plus, Trash2, Clock, AlertTriangle, ListChecks } from 'lucide-react'
import DataTable from '../components/DataTable'
import { usePolling, apiPost, apiDelete } from '../api/client'
import { useState } from 'react'

// ─────────────────────────────────────────────────────────────────────
// /replay page rewrite — was a duplicate of /logs (just the blocked-row
// subset). Now: the **Auto-Blocklist Manager**. Wires three endpoints
// that previously had no UI consumer in this codebase:
//
//   • GET    /blocked-ips         — list auto/manually-blocked IPs
//   • POST   /blocked-ips         — manually block a new IP (with TTL)
//   • DELETE /blocked-ips/{id}    — release a previously-blocked IP
//
// This is one of the most-used operator screens in any production WAF:
// "who is currently being blocked, by what, when does it expire, and
// let me add/remove one quickly."
// ─────────────────────────────────────────────────────────────────────

interface BlockedIP {
  id: number
  ip_cidr: string
  reason: string
  source: string
  expires_at?: string | null
  created_at: string
}

function isExpired(row: BlockedIP): boolean {
  if (!row.expires_at) return false
  return new Date(row.expires_at).getTime() < Date.now()
}

function timeUntil(iso?: string | null): string {
  if (!iso) return 'permanent'
  const diff = new Date(iso).getTime() - Date.now()
  if (diff <= 0) return 'expired'
  const s = Math.floor(diff / 1000)
  if (s < 60) return `${s}s`
  if (s < 3600) return `${Math.floor(s / 60)}m`
  if (s < 86400) return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`
  return `${Math.floor(s / 86400)}d ${Math.floor((s % 86400) / 3600)}h`
}

export default function RequestReplay() {
  const { data: blockedIps, loading, error, refetch } = usePolling<BlockedIP[]>('/blocked-ips', 10000)
  const [showForm, setShowForm] = useState(false)
  const [formIp, setFormIp] = useState('')
  const [formReason, setFormReason] = useState('')
  const [formTtl, setFormTtl] = useState('24h')
  const [formError, setFormError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [unblocking, setUnblocking] = useState<number | null>(null)

  const rows = (blockedIps || []).map((r) => ({ ...r, _expired: isExpired(r) }))
  const live = rows.filter((r) => !r._expired)
  const expired = rows.filter((r) => r._expired)

  async function handleBlock(e: React.FormEvent) {
    e.preventDefault()
    setFormError(null)
    setBusy(true)
    try {
      await apiPost('/blocked-ips', {
        ip_cidr: formIp.trim(),
        reason: formReason.trim() || 'manual block',
        source: 'manual',
        expires_in: formTtl,
      })
      setFormIp(''); setFormReason(''); setFormTtl('24h')
      setShowForm(false)
      refetch()
    } catch (e: any) {
      setFormError(e?.message || 'block failed')
    } finally {
      setBusy(false)
    }
  }

  async function handleUnblock(id: number) {
    setUnblocking(id)
    try {
      await apiDelete(`/blocked-ips/${id}`)
      refetch()
    } finally {
      setUnblocking(null)
    }
  }

  const cols = [
    { key: 'ip_cidr', header: 'IP / CIDR', className: 'font-mono text-xs font-semibold' },
    { key: 'reason', header: 'Reason', render: (r: any) => (
        <span className="text-xs text-slate-700">{r.reason || '—'}</span>
      )
    },
    { key: 'source', header: 'Source', render: (r: any) => (
        <span className={`text-xs font-mono ${
          r.source === 'manual' ? 'text-blue-600' :
          r.source === 'brute-force' ? 'text-rose-600' :
          'text-amber-600'
        }`}>{r.source}</span>
      )
    },
    { key: 'expires_at', header: 'Expires in', render: (r: any) => (
        <span className={`font-mono text-xs flex items-center gap-1 ${r._expired ? 'text-rose-500 line-through' : 'text-slate-600'}`}>
          <Clock size={10} />
          {timeUntil(r.expires_at)}
        </span>
      )
    },
    { key: 'created_at', header: 'Blocked at', render: (r: any) => (
        <span className="font-mono text-xs text-slate-500">{new Date(r.created_at).toLocaleString()}</span>
      )
    },
    { key: '_actions', header: 'Action', render: (r: any) => (
        <button
          onClick={() => handleUnblock(r.id)}
          disabled={unblocking === r.id}
          className="inline-flex items-center gap-1 text-xs text-rose-600 hover:text-rose-800 disabled:opacity-50"
        >
          <Trash2 size={12} /> {unblocking === r.id ? '…' : 'Unblock'}
        </button>
      )
    },
  ]

  return (
    <div className="space-y-5 section-stagger">
      {/* Header */}
      <div className="flex items-baseline justify-between animate-fade-in">
        <div>
          <h1 className="text-2xl font-bold tracking-tight bg-gradient-to-r from-slate-900 via-rose-700 to-slate-900 bg-clip-text text-transparent">
            Auto-Blocklist Manager
          </h1>
          <p className="text-xs text-slate-400 mt-1 flex items-center gap-2">
            Every IP currently being denied by brute-force protection, ATO, rate-limit, or manual block.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="px-3 py-1.5 rounded-lg bg-slate-100 text-slate-700 text-xs font-mono">
            {live.length} active
            {expired.length > 0 ? ` · ${expired.length} expired pending GC` : ''}
          </div>
          <button
            onClick={() => setShowForm((v) => !v)}
            className="px-3 py-1.5 rounded-lg bg-rose-600 text-white text-xs font-semibold hover:bg-rose-700 flex items-center gap-1"
          >
            <Plus size={14} /> Block IP
          </button>
        </div>
      </div>

      {/* KPI strip */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="card-glow p-4">
          <div className="text-[10px] uppercase tracking-widest text-slate-400 mb-1">Active blocks</div>
          <div className="font-mono text-2xl font-bold text-rose-600">{live.length}</div>
        </div>
        <div className="card-glow p-4">
          <div className="text-[10px] uppercase tracking-widest text-slate-400 mb-1">Manual blocks</div>
          <div className="font-mono text-2xl font-bold text-blue-600">
            {rows.filter((r) => r.source === 'manual').length}
          </div>
        </div>
        <div className="card-glow p-4">
          <div className="text-[10px] uppercase tracking-widest text-slate-400 mb-1">Auto (brute-force / ATO / RL)</div>
          <div className="font-mono text-2xl font-bold text-amber-600">
            {rows.filter((r) => r.source !== 'manual').length}
          </div>
        </div>
        <div className="card-glow p-4">
          <div className="text-[10px] uppercase tracking-widest text-slate-400 mb-1">Distinct /24s</div>
          <div className="font-mono text-2xl font-bold text-slate-700">
            {new Set(rows.map((r) => r.ip_cidr.split('/')[0].split('.').slice(0, 3).join('.') + '.0/24')).size}
          </div>
        </div>
      </div>

      {/* Manual block form */}
      {showForm && (
        <div className="card-glow p-5 relative overflow-hidden">
          <div className="absolute top-0 left-0 w-full h-0.5 bg-gradient-to-r from-rose-500/30 via-pink-500/20 to-transparent" />
          <h2 className="text-sm font-semibold text-slate-700 mb-3 flex items-center gap-2">
            <ShieldOff size={13} className="text-rose-500" />
            Manually block an IP / CIDR
          </h2>
          <form onSubmit={handleBlock} className="grid grid-cols-1 md:grid-cols-4 gap-3 items-end">
            <div>
              <label className="text-[10px] uppercase tracking-widest text-slate-500">IP or CIDR</label>
              <input
                type="text"
                value={formIp}
                onChange={(e) => setFormIp(e.target.value)}
                placeholder="192.0.2.45 or 192.0.2.0/24"
                required
                className="input-field w-full mt-1 font-mono"
              />
            </div>
            <div>
              <label className="text-[10px] uppercase tracking-widest text-slate-500">Reason</label>
              <input
                type="text"
                value={formReason}
                onChange={(e) => setFormReason(e.target.value)}
                placeholder="manual block — e.g. repeated 4xx probes"
                className="input-field w-full mt-1"
              />
            </div>
            <div>
              <label className="text-[10px] uppercase tracking-widest text-slate-500">Expires in</label>
              <select value={formTtl} onChange={(e) => setFormTtl(e.target.value)} className="input-field w-full mt-1">
                <option value="1h">1 hour</option>
                <option value="24h">24 hours</option>
                <option value="7d">7 days</option>
                <option value="30d">30 days</option>
                <option value="">permanent (no expiry)</option>
              </select>
            </div>
            <button
              type="submit"
              disabled={busy}
              className="px-3 py-2 rounded-lg bg-rose-600 text-white text-xs font-semibold hover:bg-rose-700 disabled:opacity-50 flex items-center gap-1 self-end h-[34px]"
            >
              <ShieldOff size={14} /> {busy ? 'Blocking…' : 'Block IP'}
            </button>
          </form>
          {formError && (
            <div className="mt-3 px-3 py-2 rounded bg-rose-50 border border-rose-200 text-xs text-rose-700 flex items-center gap-2">
              <AlertTriangle size={12} /> {formError}
            </div>
          )}
        </div>
      )}

      {/* Block list table */}
      <div className="card-glow p-5 relative overflow-hidden">
        <div className="absolute top-0 left-0 w-full h-0.5 bg-gradient-to-r from-slate-500/30 via-slate-400/20 to-transparent" />
        <h2 className="text-sm font-semibold text-slate-700 mb-4 flex items-center gap-2">
          <ListChecks size={13} className="text-slate-500" />
          Active blocks
        </h2>
        {error && (
          <div className="mb-3 px-3 py-2 rounded bg-amber-50 border border-amber-200 text-xs text-amber-700">
            {error} — note: this endpoint is <code>editor+</code> only.
          </div>
        )}
        <DataTable
          columns={cols}
          data={rows}
          searchable
          pageSize={20}
          emptyMessage="No IPs currently blocked. Brute-force, ATO, and rate-limit subsystems populate this list when triggered; you can also block manually above."
        />
      </div>
    </div>
  )
}
