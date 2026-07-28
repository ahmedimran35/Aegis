import { ShieldCheck, AlertTriangle, ListChecks, Database, Plus, Trash2 } from 'lucide-react'
import DataTable from '../components/DataTable'
import StatusBadge from '../components/StatusBadge'
import { usePolling, apiPost, apiDelete } from '../api/client'
import { useState } from 'react'

// ─────────────────────────────────────────────────────────────────────
// /virtual-patches page rewrite — was a near-duplicate of /rules.
// Now: the **OWASP CRS Coverage & Rule Conflicts** view. Wires three
// backend endpoints that previously had no UI consumer in this codebase:
//
//   • GET /rules?source=owasp-crs      — every loaded OWASP CRS rule
//   • GET /rules/conflicts             — pairs of overlapping rules
//   • GET /rules?source=virtual-patch  — operator's own virtual patches
//   • POST/DELETE /virtual-patches     — manage virtual-patch CRUD
//
// The old "list of rules" view is one tab of /rules, not a whole page.
// ─────────────────────────────────────────────────────────────────────

interface Rule {
  id: number
  name: string
  pattern: string
  match_type: string
  action: string
  severity: string
  enabled: boolean
  paranoia_level?: number
  source: string
}

interface Conflict {
  id: number
  rule_a: number
  rule_b: number
  reason: string
  severity: string
  detected_at: string
}

export default function VirtualPatches() {
  const { data: crsRules, loading: crsLoading } = usePolling<Rule[]>('/rules', 30000, { source: 'owasp-crs' })
  const { data: vpRules, loading: vpLoading, refetch: refetchVp } = usePolling<Rule[]>('/rules', 30000, { source: 'virtual-patch' })
  const { data: conflictsData, loading: conflictsLoading } = usePolling<{ conflicts: Conflict[]; count: number }>('/rules/conflicts', 30000)

  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ name: '', pattern: '', match_type: 'regex', action: 'block', severity: 'high', description: '' })
  const [formError, setFormError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  // CRS summary stats — derived from the live ruleset, not hardcoded
  const crs = crsRules || []
  const byAction: Record<string, number> = {}
  const bySeverity: Record<string, number> = {}
  let paranoiaMax = 0
  for (const r of crs) {
    byAction[r.action] = (byAction[r.action] || 0) + 1
    bySeverity[r.severity] = (bySeverity[r.severity] || 0) + 1
    if (typeof r.paranoia_level === 'number' && r.paranoia_level > paranoiaMax) paranoiaMax = r.paranoia_level
  }
  const crsTotal = crs.length
  const crsEnabled = crs.filter((r) => r.enabled).length
  const crsDisabled = crsTotal - crsEnabled

  // Conflicts (server-detected overlapping rule pairs)
  const conflicts: Conflict[] = (conflictsData?.conflicts) || []

  // Virtual-patch CRUD
  const vp = vpRules || []
  async function handleAddVp(e: React.FormEvent) {
    e.preventDefault()
    setFormError(null)
    setBusy(true)
    try {
      await apiPost('/virtual-patches', {
        name: form.name,
        pattern: form.pattern,
        match_type: form.match_type,
        action: form.action,
        severity: form.severity,
        enabled: true,
        description: form.description,
        source: 'virtual-patch',
      })
      setForm({ name: '', pattern: '', match_type: 'regex', action: 'block', severity: 'high', description: '' })
      setShowForm(false)
      refetchVp()
    } catch (e: any) {
      setFormError(e?.message || 'create failed')
    } finally {
      setBusy(false)
    }
  }
  async function handleDeleteVp(id: number) {
    try {
      await apiDelete(`/virtual-patches/${id}`)
      refetchVp()
    } catch { /* silent */ }
  }

  // Columns for the virtual-patches table
  const vpCols = [
    { key: 'name', header: 'Name', render: (r: any) => (
        <span className="font-medium text-slate-800">{r.name}</span>
      )
    },
    { key: 'pattern', header: 'Pattern', className: 'font-mono text-xs max-w-[260px] truncate' },
    { key: 'match_type', header: 'Match', render: (r: any) => (
        <span className="text-xs font-mono text-slate-600">{r.match_type}</span>
      )
    },
    { key: 'action', header: 'Action', render: (r: any) => <StatusBadge status={r.action} /> },
    { key: 'severity', header: 'Severity', render: (r: any) => <StatusBadge status={r.severity} /> },
    { key: 'enabled', header: 'Status', render: (r: any) => (
        <span className={`text-xs font-mono ${r.enabled ? 'text-emerald-600' : 'text-slate-400'}`}>
          {r.enabled ? 'enabled' : 'disabled'}
        </span>
      )
    },
    { key: '_actions', header: 'Action', render: (r: any) => (
        <button onClick={() => handleDeleteVp(r.id)} className="text-rose-600 hover:text-rose-800 text-xs flex items-center gap-1">
          <Trash2 size={12} /> Delete
        </button>
      )
    },
  ]

  return (
    <div className="space-y-5 section-stagger">
      {/* Header */}
      <div className="flex items-baseline justify-between animate-fade-in">
        <div>
          <h1 className="text-2xl font-bold tracking-tight bg-gradient-to-r from-slate-900 via-blue-700 to-slate-900 bg-clip-text text-transparent">
            OWASP CRS Coverage & Rule Conflicts
          </h1>
          <p className="text-xs text-slate-400 mt-1 flex items-center gap-2">
            Loaded rule set, paranoia level, and any overlapping rule pairs that may behave unexpectedly.
          </p>
        </div>
        <button
          onClick={() => setShowForm((v) => !v)}
          className="px-3 py-1.5 rounded-lg bg-blue-600 text-white text-xs font-semibold hover:bg-blue-700 flex items-center gap-1"
        >
          <Plus size={14} /> New Virtual Patch
        </button>
      </div>

      {/* CRS Coverage summary */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="card-glow p-4">
          <div className="text-[10px] uppercase tracking-widest text-slate-400 mb-1">CRS rules loaded</div>
          <div className="font-mono text-2xl font-bold text-slate-900">{crsTotal}</div>
          <div className="text-[10px] text-slate-400 mt-1">from /rules?source=owasp-crs</div>
        </div>
        <div className="card-glow p-4">
          <div className="text-[10px] uppercase tracking-widest text-slate-400 mb-1">Enabled</div>
          <div className="font-mono text-2xl font-bold text-emerald-600">{crsEnabled}</div>
          <div className="text-[10px] text-slate-400 mt-1">{crsDisabled} disabled</div>
        </div>
        <div className="card-glow p-4">
          <div className="text-[10px] uppercase tracking-widest text-slate-400 mb-1">Paranoia level max</div>
          <div className="font-mono text-2xl font-bold text-amber-600">PL{paranoiaMax || '?'}</div>
          <div className="text-[10px] text-slate-400 mt-1">OWASP CRS 3.x scale</div>
        </div>
        <div className="card-glow p-4">
          <div className="text-[10px] uppercase tracking-widest text-slate-400 mb-1">By action</div>
          <div className="font-mono text-sm font-bold text-slate-900 flex flex-wrap gap-2 mt-1">
            {Object.entries(byAction).map(([a, n]) => (
              <span key={a} className="text-xs px-1.5 py-0.5 rounded bg-slate-100 text-slate-700">
                {a} {n}
              </span>
            ))}
            {Object.keys(byAction).length === 0 && <span className="text-xs text-slate-400">—</span>}
          </div>
        </div>
      </div>

      {/* CRS by severity — quick distribution */}
      <div className="card-glow p-5 relative overflow-hidden">
        <div className="absolute top-0 left-0 w-full h-0.5 bg-gradient-to-r from-blue-500/30 via-cyan-500/20 to-transparent" />
        <h2 className="text-sm font-semibold text-slate-700 mb-3 flex items-center gap-2">
          <div className="w-6 h-6 rounded-lg bg-blue-50 flex items-center justify-center">
            <ShieldCheck size={13} className="text-blue-500" />
          </div>
          CRS Coverage by Severity
        </h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
          {(['critical', 'high', 'medium', 'low'] as const).map((sev) => {
            const n = bySeverity[sev] || 0
            const pct = crsTotal > 0 ? Math.round((n / crsTotal) * 100) : 0
            const tones: Record<string, string> = {
              critical: 'bg-rose-100 text-rose-700',
              high:     'bg-orange-100 text-orange-700',
              medium:   'bg-amber-100 text-amber-700',
              low:      'bg-slate-100 text-slate-700',
            }
            return (
              <div key={sev} className={`rounded p-3 ${tones[sev]}`}>
                <div className="text-[10px] uppercase tracking-widest opacity-80">{sev}</div>
                <div className="font-mono text-xl font-bold">{n}</div>
                <div className="text-[10px] opacity-80">{pct}% of ruleset</div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Rule Conflicts — server-detected overlapping pairs */}
      <div className="card-glow p-5 relative overflow-hidden">
        <div className="absolute top-0 left-0 w-full h-0.5 bg-gradient-to-r from-amber-500/30 via-orange-500/20 to-transparent" />
        <h2 className="text-sm font-semibold text-slate-700 mb-3 flex items-center gap-2">
          <div className="w-6 h-6 rounded-lg bg-amber-50 flex items-center justify-center">
            <AlertTriangle size={13} className="text-amber-500" />
          </div>
          Rule Conflicts
          <span className="text-[10px] font-mono text-slate-400 ml-auto">/rules/conflicts · 30s poll</span>
        </h2>
        {conflictsLoading ? (
          <div className="text-xs text-slate-400 italic">Scanning ruleset…</div>
        ) : conflicts.length === 0 ? (
          <div className="text-xs text-slate-500 italic py-2">
            No overlapping rule pairs detected. Conflicts arise when two rules match the same traffic — usually because one shadows the other.
          </div>
        ) : (
          <ul className="space-y-2">
            {conflicts.slice(0, 12).map((c) => (
              <li key={c.id} className="flex items-start gap-2 p-2 rounded border border-amber-200 bg-amber-50/50">
                <AlertTriangle size={12} className="text-amber-600 mt-0.5 shrink-0" />
                <div className="flex-1">
                  <div className="text-xs text-slate-700">
                    <span className="font-mono">rule #{c.rule_a}</span> &harr; <span className="font-mono">rule #{c.rule_b}</span>
                    <span className={`ml-2 text-[10px] font-mono font-bold px-1.5 py-0.5 rounded ${
                      c.severity === 'high' ? 'bg-rose-100 text-rose-700' :
                      c.severity === 'medium' ? 'bg-amber-100 text-amber-700' :
                      'bg-slate-100 text-slate-600'
                    }`}>{c.severity}</span>
                  </div>
                  <div className="text-[11px] text-slate-600 mt-0.5">{c.reason}</div>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* Virtual Patch CRUD (form + table) */}
      {showForm && (
        <div className="card-glow p-5 relative overflow-hidden">
          <div className="absolute top-0 left-0 w-full h-0.5 bg-gradient-to-r from-emerald-500/30 via-cyan-500/20 to-transparent" />
          <h2 className="text-sm font-semibold text-slate-700 mb-3 flex items-center gap-2">
            <Plus size={13} className="text-emerald-500" />
            New Virtual Patch
          </h2>
          <form onSubmit={handleAddVp} className="grid grid-cols-1 md:grid-cols-6 gap-3 items-end">
            <div className="md:col-span-2">
              <label className="text-[10px] uppercase tracking-widest text-slate-500">Name</label>
              <input value={form.name} onChange={(e) => setForm({...form, name: e.target.value})} required className="input-field w-full mt-1" placeholder="e.g. CVE-2024-XXXX — log4j JNDI" />
            </div>
            <div className="md:col-span-2">
              <label className="text-[10px] uppercase tracking-widest text-slate-500">Pattern</label>
              <input value={form.pattern} onChange={(e) => setForm({...form, pattern: e.target.value})} required className="input-field w-full mt-1 font-mono" placeholder="\$\{jndi:.*\}" />
            </div>
            <div>
              <label className="text-[10px] uppercase tracking-widest text-slate-500">Match</label>
              <select value={form.match_type} onChange={(e) => setForm({...form, match_type: e.target.value})} className="input-field w-full mt-1">
                <option value="regex">regex</option>
                <option value="string">string</option>
                <option value="cidr">cidr</option>
              </select>
            </div>
            <div>
              <label className="text-[10px] uppercase tracking-widest text-slate-500">Action</label>
              <select value={form.action} onChange={(e) => setForm({...form, action: e.target.value})} className="input-field w-full mt-1">
                <option value="block">block</option>
                <option value="log">log</option>
                <option value="challenge">challenge</option>
              </select>
            </div>
            <button type="submit" disabled={busy} className="md:col-span-6 px-3 py-2 rounded-lg bg-blue-600 text-white text-xs font-semibold hover:bg-blue-700 disabled:opacity-50">
              {busy ? 'Saving…' : 'Add Virtual Patch'}
            </button>
          </form>
          {formError && <div className="mt-3 text-xs text-rose-700">{formError}</div>}
        </div>
      )}

      <div className="card-glow p-5 relative overflow-hidden">
        <h2 className="text-sm font-semibold text-slate-700 mb-3 flex items-center gap-2">
          <div className="w-6 h-6 rounded-lg bg-emerald-50 flex items-center justify-center">
            <ListChecks size={13} className="text-emerald-500" />
          </div>
          Your virtual patches
          <span className="text-[10px] font-mono text-slate-400 ml-auto">{vp.length} rules · /rules?source=virtual-patch</span>
        </h2>
        <DataTable columns={vpCols} data={vp} searchable pageSize={20} emptyMessage="No virtual patches yet. Add one above to cover a CVE for the time your upstream patch window is open." />
      </div>
    </div>
  )
}
