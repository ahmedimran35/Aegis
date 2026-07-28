import { useState, useEffect, useCallback } from 'react'
import { FileJson, Plus, Trash2, ToggleLeft, ToggleRight } from 'lucide-react'
import DataTable from '../components/DataTable'
import StatusBadge from '../components/StatusBadge'
import { apiGet, apiPost, apiDelete } from '../api/client'
import { SkeletonTable } from '../components/Skeleton'

interface APISchema {
  id: number
  name: string
  base_path: string
  enabled: boolean
  created_at: string
}

export default function APISchemas() {
  const [schemas, setSchemas] = useState<APISchema[]>([])
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ name: '', base_path: '', spec: '' })
  const [error, setError] = useState('')
  const [loadError, setLoadError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  const loadSchemas = useCallback(async () => { try { setSchemas(await apiGet<APISchema[]>('/api-schemas')); setLoadError(null) } catch (e) { /* sanitized message via client.ts */ setLoadError(e instanceof Error ? e.message : 'Failed to load schemas') } finally { setLoading(false) } }, [])
  useEffect(() => { loadSchemas() }, [loadSchemas])

  const handleCreate = async () => {
    setError('')
    try {
      let spec: unknown
      try { spec = JSON.parse(form.spec) } catch { setError('Invalid JSON in spec'); return }
      await apiPost('/api-schemas', { name: form.name, base_path: form.base_path, spec })
      setShowForm(false)
      setForm({ name: '', base_path: '', spec: '' })
      loadSchemas()
    } catch (e) { setError(e instanceof Error ? e.message : 'Error') }
  }

  const handleDelete = async (id: number) => { if (!confirm('Delete?')) return; try { await apiDelete(`/api-schemas/${id}`); loadSchemas() } catch { /* sanitized */ } }

  const columns = [
    { key: 'name', header: 'Name', render: (s: APISchema) => <span className="font-medium">{s.name}</span> },
    { key: 'base_path', header: 'Base Path', render: (s: APISchema) => <span className="font-mono text-xs">{s.base_path}</span> },
    { key: 'enabled', header: 'Status', render: (s: APISchema) => <StatusBadge status={s.enabled ? 'active' : 'inactive'} /> },
    { key: 'created_at', header: 'Created', render: (s: APISchema) => <span className="text-xs text-slate-400">{new Date(s.created_at).toLocaleDateString()}</span> },
    { key: 'actions', header: '', render: (s: APISchema) => <button onClick={() => handleDelete(s.id)} aria-label="Delete schema" className="p-1.5 rounded-md hover:bg-red-50 text-slate-400 hover:text-red-500"><Trash2 size={14} /></button> },
  ]

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold tracking-tight text-slate-900 flex items-center gap-2">
          <FileJson size={20} className="text-slate-600" />
          API Schema Validation
        </h1>
        <button onClick={() => setShowForm(true)} className="btn-primary"><Plus size={16} /> Add Schema</button>
      </div>

      <div className="p-4 bg-blue-50 border border-blue-200 rounded-lg text-sm text-blue-800">
        Upload OpenAPI schemas to validate incoming requests against your API specification. Invalid requests will be blocked.
      </div>

      {loadError && <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-sm text-red-700">{loadError}</div>}

      {loading ? <SkeletonTable rows={5} cols={5} /> : <DataTable columns={columns} data={schemas} searchable pageSize={25} emptyMessage="No API schemas configured" />}

      {/* Create Modal */}
      {showForm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/30 backdrop-blur-sm" onClick={() => setShowForm(false)}>
          <div className="w-full max-w-lg mx-4 bg-white rounded-2xl shadow-xl border border-ivory-300 p-6 animate-slide-up max-h-[90vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <h2 className="text-lg font-semibold text-slate-900 mb-4">Add API Schema</h2>
            {error && <div className="p-3 bg-red-50 text-red-700 text-sm rounded-lg mb-3">{error}</div>}
            <div className="space-y-3">
              <div>
                <label className="block text-xs font-medium text-slate-600 mb-1">Name</label>
                <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} className="input-field" placeholder="My API" />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-600 mb-1">Base Path</label>
                <input value={form.base_path} onChange={(e) => setForm({ ...form, base_path: e.target.value })} className="input-field font-mono text-xs" placeholder="/api/v1" />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-600 mb-1">OpenAPI Spec (JSON)</label>
                <textarea value={form.spec} onChange={(e) => setForm({ ...form, spec: e.target.value })} className="input-field h-48 font-mono text-xs resize-none" placeholder='{"openapi":"3.0.0",...}' />
              </div>
            </div>
            <div className="flex justify-end gap-3 mt-5">
              <button onClick={() => setShowForm(false)} className="btn-secondary">Cancel</button>
              <button onClick={handleCreate} className="btn-primary">Add Schema</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
