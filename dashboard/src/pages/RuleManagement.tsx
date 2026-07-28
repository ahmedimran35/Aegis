import { useState, useEffect, useCallback } from 'react'
import { Plus, ToggleLeft, ToggleRight, Trash2, Pencil, Lightbulb, CheckCircle, XCircle, FileText, Beaker, Play, X, ShieldCheck, ShieldAlert, AlertTriangle } from 'lucide-react'
import DataTable from '../components/DataTable'
import StatusBadge from '../components/StatusBadge'
import { apiGet, apiPost, apiPut, apiDelete } from '../api/client'
import { useToast } from '../hooks/useToast'
import { useMinDisplay } from '../hooks/useMinDisplay'
import { confirmAction } from '../components/ConfirmDialog'
import { SkeletonTable } from '../components/Skeleton'
import { checkRegexPattern } from '../utils/regexSafety'

interface Rule {
  id: number
  name: string
  pattern: string
  match_type: string
  action: string
  severity: string
  priority: number
  enabled: boolean
  hit_count: number
  source: string
  description: string
  paranoia_level: number
  transforms: string
  created_at: string
  updated_at: string
}

interface RuleSuggestion {
  id: number
  pattern: string
  match_type: string
  suggested_action: string
  confidence: number
  status: string
}

interface RuleTrigger {
  rule_id: number
  name: string
  pattern: string
  pattern_match: string
  score_added: number
  severity: string
  match_type: string
  action: string
  paranoia_level: number
}

interface ScoreBreakdown {
  rule_id: number
  name: string
  running_score: number
  severity: string
  score_added: number
}

interface SandboxResult {
  matched: boolean
  rules_triggered: RuleTrigger[]
  total_score: number
  would_block: boolean
  anomaly_threshold: number
  paranoia_level: number
  classification: string
  breakdown: ScoreBreakdown[]
}

const emptyRule = { name: '', pattern: '', match_type: 'regex', action: 'block', severity: 'medium', priority: 100, description: '', paranoia_level: 1, transforms: '' }

export default function RuleManagement() {
  const [rules, setRules] = useState<Rule[]>([])
  const [suggestions, setSuggestions] = useState<RuleSuggestion[]>([])
  const [editing, setEditing] = useState<Rule | null>(null)
  const [form, setForm] = useState(emptyRule)
  const [showForm, setShowForm] = useState(false)
  const [filter, setFilter] = useState({ status: '', severity: '', source: '' })
  const [loadError, setLoadError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [submitting, setSubmitting] = useState(false)
  const [formError, setFormError] = useState('')

  // Sandbox state
  const [showSandbox, setShowSandbox] = useState(false)
  const [sandboxForm, setSandboxForm] = useState({ method: 'GET', path: '/api/v1', query: '', body: '', client_ip: '', paranoia_level: 0 })
  const [sandboxHeaders, setSandboxHeaders] = useState<{ key: string; value: string }[]>([
    { key: 'User-Agent', value: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
  ])
  const [sandboxResult, setSandboxResult] = useState<SandboxResult | null>(null)
  const [sandboxLoading, setSandboxLoading] = useState(false)
  const [sandboxError, setSandboxError] = useState('')

  const loadRules = useCallback(async () => {
    try {
      const params: Record<string, string> = {}
      if (filter.status) params.status = filter.status
      if (filter.severity) params.severity = filter.severity
      if (filter.source) params.source = filter.source
      const data = await apiGet<Rule[]>('/rules', params)
      setRules(data)
      setLoadError(null)
    } catch (e) { useToast.getState().error(e instanceof Error ? e.message : 'Failed to load rules'); setLoadError(e instanceof Error ? e.message : 'Failed to load rules') } finally { setLoading(false) }
  }, [filter])

  const loadSuggestions = useCallback(async () => {
    try {
      const data = await apiGet<RuleSuggestion[]>('/rules/suggestions')
      setSuggestions(data)
    } catch (e) { useToast.getState().error(e instanceof Error ? e.message : 'Failed to load suggestions') }
  }, [])

  useEffect(() => { loadRules(); loadSuggestions() }, [loadRules, loadSuggestions])
  useEffect(() => {
    if (!showForm) return
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setShowForm(false) }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [showForm])

  const showSkeleton = useMinDisplay(loading)

  const handleSave = async () => {
    setFormError('')
    if (!form.name.trim()) { setFormError('Name is required'); return }
    if (!form.pattern.trim()) { setFormError('Pattern is required'); return }
    // P-FIX (M-6): same regex-safety check used by VirtualPatches. For
    // new rules, block invalid; warn-then-confirm for risky patterns.
    if (form.match_type === 'regex') {
      const check = checkRegexPattern(form.pattern)
      if (check.level === 'invalid') {
        setFormError(check.reason || 'Invalid regex pattern')
        return
      }
      if (check.level === 'warning') {
        if (!await confirmAction(
          `Warning: ${check.reason || 'Pattern looks risky.'}\n\nSave this rule anyway?`
        )) return
      }
    }
    setSubmitting(true)
    try {
      if (editing) {
        await apiPut(`/rules/${editing.id}`, form)
      } else {
        await apiPost('/rules', form)
      }
      setShowForm(false)
      setEditing(null)
      setForm(emptyRule)
      loadRules()
    } catch (e) { useToast.getState().error(e instanceof Error ? e.message : 'Error') } finally { setSubmitting(false) }
  }

  const handleDelete = async (id: number) => {
    if (!await confirmAction('Delete this rule?')) return
    try {
      await apiDelete(`/rules/${id}`)
      loadRules()
    } catch (e) { useToast.getState().error(e instanceof Error ? e.message : 'Error') }
  }

  const handleToggle = async (id: number) => {
    try {
      await apiPut(`/rules/${id}/toggle`, {})
      loadRules()
    } catch (e) { useToast.getState().error(e instanceof Error ? e.message : 'Error') }
  }

  const handleSuggestion = async (id: number, action: 'approve' | 'reject') => {
    try {
      await apiPost(`/rules/suggestions/${id}/${action}`, {})
      loadSuggestions()
      loadRules()
    } catch (e) { useToast.getState().error(e instanceof Error ? e.message : 'Error') }
  }

  const handleSandboxTest = async () => {
    setSandboxLoading(true)
    setSandboxError('')
    setSandboxResult(null)
    try {
      const headers: Record<string, string> = {}
      sandboxHeaders.forEach(h => { if (h.key.trim()) headers[h.key.trim()] = h.value })
      const result = await apiPost<SandboxResult>('/rules/sandbox', {
        method: sandboxForm.method,
        path: sandboxForm.path,
        query: sandboxForm.query,
        headers,
        body: sandboxForm.body,
        client_ip: sandboxForm.client_ip || undefined,
        paranoia_level: sandboxForm.paranoia_level || undefined,
      })
      setSandboxResult(result)
    } catch (e) {
      setSandboxError(e instanceof Error ? e.message : 'Test failed')
    } finally {
      setSandboxLoading(false)
    }
  }

  const handleCreateFromMatch = (trigger: RuleTrigger) => {
    setShowSandbox(false)
    setEditing(null)
    setForm({
      ...emptyRule,
      name: `From: ${trigger.name}`,
      pattern: trigger.pattern,
      match_type: trigger.match_type,
      severity: trigger.severity,
      action: trigger.action,
      paranoia_level: trigger.paranoia_level,
    })
    setShowForm(true)
  }

  const columns = [
    { key: 'name', header: 'Name', render: (r: Rule) => <span className="font-medium">{r.name}</span> },
    { key: 'pattern', header: 'Pattern', render: (r: Rule) => <span className="font-mono text-xs text-slate-500 max-w-[200px] truncate block">{r.pattern}</span> },
    { key: 'match_type', header: 'Type', render: (r: Rule) => <span className="badge bg-slate-50 text-slate-600">{r.match_type}</span> },
    { key: 'action', header: 'Action', render: (r: Rule) => <StatusBadge status={r.action === 'block' ? 'blocked' : r.action === 'allow' ? 'allowed' : 'pending'} /> },
    { key: 'severity', header: 'Severity', render: (r: Rule) => <StatusBadge status={r.severity} /> },
    { key: 'priority', header: 'Priority', render: (r: Rule) => <span className="font-mono text-xs">{r.priority}</span> },
    { key: 'paranoia_level', header: 'PL', render: (r: Rule) => {
      const colors = ['bg-emerald-100 text-emerald-700', 'bg-amber-100 text-amber-700', 'bg-orange-100 text-orange-700', 'bg-red-100 text-red-700']
      return <span className={`badge ${colors[(r.paranoia_level ?? 1) - 1]}`}>PL{r.paranoia_level ?? 1}</span>
    }},
    { key: 'hit_count', header: 'Hits', render: (r: Rule) => <span className="font-mono text-xs">{(r.hit_count ?? 0).toLocaleString()}</span> },
    { key: 'enabled', header: 'Status', render: (r: Rule) => (
      <button onClick={() => handleToggle(r.id)} aria-label="Toggle rule" className="text-slate-400 hover:text-accent-600 transition-colors">
        {r.enabled ? <ToggleRight size={20} className="text-emerald-500" /> : <ToggleLeft size={20} />}
      </button>
    )},
    { key: 'actions', header: '', render: (r: Rule) => (
      <div className="flex items-center gap-1">
        <button onClick={() => { setEditing(r); setForm(r); setShowForm(true) }} aria-label="Edit rule" className="p-1.5 rounded-md hover:bg-ivory-100 text-slate-400 hover:text-accent-600 transition-colors"><Pencil size={14} /></button>
        <button onClick={() => handleDelete(r.id)} aria-label="Delete rule" className="p-1.5 rounded-md hover:bg-red-50 text-slate-400 hover:text-red-500 transition-colors"><Trash2 size={14} /></button>
      </div>
    )},
  ]

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold tracking-tight text-slate-900 flex items-center gap-2">
          <FileText size={20} className="text-slate-600" />
          Rule Management
        </h1>
        <div className="flex items-center gap-2">
          <button onClick={() => { setShowSandbox(true); setSandboxResult(null); setSandboxError('') }} className="btn-secondary">
            <Beaker size={16} /> Sandbox
          </button>
          <button onClick={() => { setEditing(null); setForm(emptyRule); setShowForm(true) }} className="btn-primary">
            <Plus size={16} /> New Rule
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-3">
        <select value={filter.status} onChange={(e) => setFilter({ ...filter, status: e.target.value })} className="input-field sm:w-40">
          <option value="">All Status</option>
          <option value="enabled">Enabled</option>
          <option value="disabled">Disabled</option>
        </select>
        <select value={filter.severity} onChange={(e) => setFilter({ ...filter, severity: e.target.value })} className="input-field sm:w-40">
          <option value="">All Severity</option>
          <option value="low">Low</option>
          <option value="medium">Medium</option>
          <option value="high">High</option>
          <option value="critical">Critical</option>
        </select>
      </div>

      {loadError && <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-sm text-red-700">{loadError}</div>}

      {showSkeleton ? <SkeletonTable rows={5} cols={9} /> : <DataTable columns={columns} data={rules} searchable pageSize={25} emptyMessage="No rules configured" />}

      {/* AI Suggestions */}
      {suggestions && suggestions.length > 0 && (
        <div className="card p-5">
          <h2 className="text-sm font-semibold text-slate-700 mb-4 flex items-center gap-2">
            <Lightbulb size={14} className="text-amber-500" />
            AI Rule Suggestions
          </h2>
          <div className="space-y-3">
            {suggestions.filter(s => s.status === 'pending').map((s) => (
              <div key={s.id} className="flex items-center justify-between p-3 bg-ivory-50 rounded-lg border border-ivory-200">
                <div>
                  <span className="font-mono text-xs text-slate-600">{s.pattern}</span>
                  <span className="ml-3 badge bg-accent-50 text-accent-700">{s.match_type}</span>
                  <span className="ml-2 text-xs text-slate-400">confidence: {((s.confidence ?? 0) * 100).toFixed(0)}%</span>
                </div>
                <div className="flex gap-2">
                  <button onClick={() => handleSuggestion(s.id, 'approve')} className="p-1.5 rounded-md hover:bg-emerald-50 text-emerald-500 transition-colors"><CheckCircle size={18} /></button>
                  <button onClick={() => handleSuggestion(s.id, 'reject')} className="p-1.5 rounded-md hover:bg-red-50 text-red-400 transition-colors"><XCircle size={18} /></button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Rule Form Modal */}
      {showForm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/30 backdrop-blur-sm" onClick={() => setShowForm(false)} onKeyDown={(e) => e.key === 'Escape' && setShowForm(false)} tabIndex={-1}>
          <div className="w-full max-w-lg mx-4 bg-white rounded-2xl shadow-xl border border-ivory-300 p-6 animate-slide-up max-h-[90vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <h2 className="text-lg font-semibold text-slate-900 mb-4">{editing ? 'Edit Rule' : 'Create Rule'}</h2>
            {formError && <div className="p-3 bg-red-50 text-red-700 text-sm rounded-lg mb-3">{formError}</div>}
            <div className="space-y-3">
              <div>
                <label className="block text-xs font-medium text-slate-600 mb-1">Name</label>
                <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} className="input-field" placeholder="SQL injection block" />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-600 mb-1">Pattern</label>
                <input value={form.pattern} onChange={(e) => setForm({ ...form, pattern: e.target.value })} className="input-field font-mono text-xs" placeholder="(?i)union\s+select" />
                {form.match_type === 'regex' && form.pattern && (() => {
                  const c = checkRegexPattern(form.pattern)
                  if (c.level === 'warning') {
                    return (
                      <p className="mt-1 text-[11px] text-amber-700 flex items-start gap-1">
                        <AlertTriangle size={12} className="mt-[1px] shrink-0" />
                        <span>{c.reason}</span>
                      </p>
                    )
                  }
                  if (c.level === 'invalid') {
                    return (
                      <p className="mt-1 text-[11px] text-red-700">{c.reason}</p>
                    )
                  }
                  return null
                })()}
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-600 mb-1">Match Type</label>
                  <select value={form.match_type} onChange={(e) => setForm({ ...form, match_type: e.target.value })} className="input-field">
                    <option value="regex">Regex</option>
                    <option value="string">String</option>
                    <option value="cidr">CIDR</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-600 mb-1">Action</label>
                  <select value={form.action} onChange={(e) => setForm({ ...form, action: e.target.value })} className="input-field">
                    <option value="block">Block</option>
                    <option value="allow">Allow</option>
                    <option value="log">Log Only</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-600 mb-1">Severity</label>
                  <select value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })} className="input-field">
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                    <option value="critical">Critical</option>
                  </select>
                </div>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-600 mb-1">Priority</label>
                  <input type="number" value={form.priority} onChange={(e) => setForm({ ...form, priority: parseInt(e.target.value) || 100 })} className="input-field w-24" />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-600 mb-1">Paranoia Level</label>
                  <select value={form.paranoia_level} onChange={(e) => setForm({ ...form, paranoia_level: parseInt(e.target.value) })} className="input-field">
                    <option value={1}>PL1 — Safe (default)</option>
                    <option value={2}>PL2 — Moderate</option>
                    <option value={3}>PL3 — Aggressive</option>
                    <option value={4}>PL4 — Maximum</option>
                  </select>
                </div>
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-600 mb-1">Input Transforms <span className="text-slate-400">(comma-separated)</span></label>
                <input value={form.transforms} onChange={(e) => setForm({ ...form, transforms: e.target.value })} className="input-field font-mono text-xs" placeholder="urldecode, base64decode, lowercase" />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-600 mb-1">Description</label>
                <textarea value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} className="input-field h-20 resize-none" />
              </div>
            </div>
            <div className="flex justify-end gap-3 mt-5">
              <button onClick={() => setShowForm(false)} className="btn-secondary">Cancel</button>
              <button onClick={handleSave} disabled={submitting} className="btn-primary disabled:opacity-50">{submitting ? (editing ? 'Updating...' : 'Creating...') : (editing ? 'Update' : 'Create')}</button>
            </div>
          </div>
        </div>
      )}

      {/* Sandbox Modal */}
      {showSandbox && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/30 backdrop-blur-sm" onClick={() => setShowSandbox(false)}>
          <div className="w-full max-w-3xl mx-4 bg-white rounded-2xl shadow-xl border border-ivory-300 animate-slide-up max-h-[90vh] flex flex-col" onClick={(e) => e.stopPropagation()}>
            {/* Header */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-ivory-200">
              <h2 className="text-lg font-semibold text-slate-900 flex items-center gap-2">
                <Beaker size={18} className="text-accent-600" />
                Rule Testing Sandbox
              </h2>
              <button onClick={() => setShowSandbox(false)} className="p-1.5 rounded-md hover:bg-ivory-100 text-slate-400 hover:text-slate-600 transition-colors">
                <X size={18} />
              </button>
            </div>

            {/* Body */}
            <div className="overflow-y-auto px-6 py-4 space-y-4">
              {/* Request Builder */}
              <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-600 mb-1">Method</label>
                  <select value={sandboxForm.method} onChange={(e) => setSandboxForm({ ...sandboxForm, method: e.target.value })} className="input-field">
                    <option>GET</option><option>POST</option><option>PUT</option><option>DELETE</option><option>PATCH</option><option>OPTIONS</option>
                  </select>
                </div>
                <div className="sm:col-span-2">
                  <label className="block text-xs font-medium text-slate-600 mb-1">Path</label>
                  <input value={sandboxForm.path} onChange={(e) => setSandboxForm({ ...sandboxForm, path: e.target.value })} className="input-field font-mono text-xs" placeholder="/api/v1/users" />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-600 mb-1">Paranoia Level</label>
                  <select value={sandboxForm.paranoia_level} onChange={(e) => setSandboxForm({ ...sandboxForm, paranoia_level: parseInt(e.target.value) })} className="input-field">
                    <option value={0}>Default</option><option value={1}>PL1</option><option value={2}>PL2</option><option value={3}>PL3</option><option value={4}>PL4</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-600 mb-1">Query String</label>
                  <input value={sandboxForm.query} onChange={(e) => setSandboxForm({ ...sandboxForm, query: e.target.value })} className="input-field font-mono text-xs" placeholder="id=1&name=test" />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-600 mb-1">Client IP <span className="text-slate-400">(for CIDR rules)</span></label>
                  <input value={sandboxForm.client_ip} onChange={(e) => setSandboxForm({ ...sandboxForm, client_ip: e.target.value })} className="input-field font-mono text-xs" placeholder="192.168.1.1" />
                </div>
              </div>

              {/* Headers */}
              <div>
                <label className="block text-xs font-medium text-slate-600 mb-1">Headers</label>
                <div className="space-y-2">
                  {sandboxHeaders.map((h, i) => (
                    <div key={i} className="flex items-center gap-2">
                      <input value={h.key} onChange={(e) => { const updated = [...sandboxHeaders]; updated[i] = { ...updated[i], key: e.target.value }; setSandboxHeaders(updated) }} className="input-field font-mono text-xs w-40" placeholder="Header-Name" />
                      <input value={h.value} onChange={(e) => { const updated = [...sandboxHeaders]; updated[i] = { ...updated[i], value: e.target.value }; setSandboxHeaders(updated) }} className="input-field font-mono text-xs flex-1" placeholder="value" />
                      <button onClick={() => setSandboxHeaders(sandboxHeaders.filter((_, j) => j !== i))} className="p-1.5 rounded-md hover:bg-red-50 text-slate-400 hover:text-red-500 transition-colors"><Trash2 size={14} /></button>
                    </div>
                  ))}
                  <button onClick={() => setSandboxHeaders([...sandboxHeaders, { key: '', value: '' }])} className="text-xs text-accent-600 hover:text-accent-700 font-medium flex items-center gap-1">
                    <Plus size={12} /> Add Header
                  </button>
                </div>
              </div>

              {/* Body */}
              <div>
                <label className="block text-xs font-medium text-slate-600 mb-1">Request Body</label>
                <textarea value={sandboxForm.body} onChange={(e) => setSandboxForm({ ...sandboxForm, body: e.target.value })} className="input-field h-20 resize-none font-mono text-xs" placeholder='{"query": "SELECT * FROM users"}' />
              </div>

              {sandboxError && <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-sm text-red-700">{sandboxError}</div>}

              <button onClick={handleSandboxTest} disabled={sandboxLoading} className="btn-primary disabled:opacity-50">
                <Play size={14} /> {sandboxLoading ? 'Testing...' : 'Test Request'}
              </button>

              {/* Results */}
              {sandboxResult && (
                <div className="space-y-4 pt-2 border-t border-ivory-200">
                  {/* Decision row */}
                  <div className="flex items-center gap-3 flex-wrap">
                    {sandboxResult.would_block ? (
                      <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm font-semibold bg-red-50 text-red-700 ring-1 ring-inset ring-red-600/20">
                        <ShieldAlert size={14} /> Would Block
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm font-semibold bg-emerald-50 text-emerald-700 ring-1 ring-inset ring-emerald-600/20">
                        <ShieldCheck size={14} /> Would Allow
                      </span>
                    )}
                    <span className={`badge ${sandboxResult.classification === 'block' ? 'bg-red-50 text-red-700' : sandboxResult.classification === 'log' ? 'bg-amber-50 text-amber-700' : 'bg-emerald-50 text-emerald-700'}`}>
                      {sandboxResult.classification}
                    </span>
                    <span className="text-sm text-slate-500">
                      PL{sandboxResult.paranoia_level} | Threshold: {sandboxResult.anomaly_threshold}
                    </span>
                  </div>

                  {/* Score gauge */}
                  <div>
                    <div className="flex items-center justify-between text-xs text-slate-500 mb-1">
                      <span>Anomaly Score</span>
                      <span className="font-semibold text-slate-700">{sandboxResult.total_score} / {sandboxResult.anomaly_threshold}</span>
                    </div>
                    <div className="relative h-4 bg-slate-100 rounded-full overflow-hidden">
                      <div
                        className={`absolute inset-y-0 left-0 rounded-full transition-all duration-500 ${sandboxResult.would_block ? 'bg-red-500' : sandboxResult.total_score > 0 ? 'bg-amber-400' : 'bg-emerald-400'}`}
                        style={{ width: `${Math.min(100, (sandboxResult.total_score / sandboxResult.anomaly_threshold) * 100)}%` }}
                      />
                      {/* Threshold marker */}
                      <div className="absolute inset-y-0 w-0.5 bg-red-400" style={{ left: '100%', transform: 'translateX(-1px)' }} />
                    </div>
                  </div>

                  {/* Triggered rules table */}
                  {sandboxResult.rules_triggered.length > 0 && (
                    <div>
                      <h3 className="text-sm font-semibold text-slate-700 mb-2">Triggered Rules ({sandboxResult.rules_triggered.length})</h3>
                      <div className="border border-ivory-200 rounded-lg overflow-hidden">
                        <table className="w-full text-sm">
                          <thead className="bg-ivory-50 text-xs text-slate-500 uppercase tracking-wider">
                            <tr>
                              <th className="text-left px-3 py-2">Rule</th>
                              <th className="text-left px-3 py-2">Matched On</th>
                              <th className="text-left px-3 py-2">Severity</th>
                              <th className="text-right px-3 py-2">Score</th>
                              <th className="text-right px-3 py-2">Running</th>
                              <th className="text-right px-3 py-2"></th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-ivory-100">
                            {sandboxResult.rules_triggered.map((trigger, i) => {
                              const bd = sandboxResult.breakdown[i]
                              return (
                                <tr key={trigger.rule_id} className="hover:bg-ivory-50/50">
                                  <td className="px-3 py-2">
                                    <div className="font-medium text-slate-800">{trigger.name}</div>
                                    <div className="font-mono text-[10px] text-slate-400 max-w-[180px] truncate">{trigger.pattern}</div>
                                  </td>
                                  <td className="px-3 py-2"><span className="badge bg-slate-50 text-slate-600">{trigger.pattern_match}</span></td>
                                  <td className="px-3 py-2"><span className={`badge ${trigger.severity === 'critical' ? 'bg-red-50 text-red-700' : trigger.severity === 'high' ? 'bg-orange-50 text-orange-700' : trigger.severity === 'medium' ? 'bg-amber-50 text-amber-700' : 'bg-blue-50 text-blue-700'}`}>{trigger.severity}</span></td>
                                  <td className="px-3 py-2 text-right font-mono text-xs font-semibold text-slate-700">+{trigger.score_added}</td>
                                  <td className="px-3 py-2 text-right font-mono text-xs text-slate-500">{bd?.running_score ?? '-'}</td>
                                  <td className="px-3 py-2 text-right">
                                    <button onClick={() => handleCreateFromMatch(trigger)} className="text-xs text-accent-600 hover:text-accent-700 font-medium">Create Rule</button>
                                  </td>
                                </tr>
                              )
                            })}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}

                  {/* No matches */}
                  {sandboxResult.rules_triggered.length === 0 && (
                    <div className="text-center py-6 text-slate-400 text-sm">
                      No rules matched this request.
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
