import { useState, useEffect, useCallback } from 'react'
import { Users as UsersIcon, Plus, Shield, Trash2 } from 'lucide-react'
import DataTable from '../components/DataTable'
import StatusBadge from '../components/StatusBadge'
import { apiGet, apiPost, apiPut, apiDelete } from '../api/client'
import { SkeletonTable } from '../components/Skeleton'
import { useToast } from '../hooks/useToast'
import { useMinDisplay } from '../hooks/useMinDisplay'
import { confirmAction } from '../components/ConfirmDialog'

interface User { id: number; username: string; role: string; created_at: string }

const roles = ['viewer', 'analyst', 'editor', 'admin']

const roleIconColors: Record<string, string> = {
  viewer: 'text-slate-500',
  analyst: 'text-amber-500',
  editor: 'text-blue-500',
  admin: 'text-red-500',
}

export default function Users() {
  const [users, setUsers] = useState<User[]>([])
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ username: '', password: '', role: 'viewer' })
  const [error, setError] = useState('')
  const [loadError, setLoadError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [submitting, setSubmitting] = useState(false)
  const [roleChanging, setRoleChanging] = useState<number | null>(null)

  const loadUsers = useCallback(async () => {
    try { setUsers(await apiGet<User[]>('/users')); setLoadError(null) } catch (e) { useToast.getState().error(e instanceof Error ? e.message : 'Failed to load users'); setLoadError(e instanceof Error ? e.message : 'Failed to load users') } finally { setLoading(false) }
  }, [])

  useEffect(() => { loadUsers() }, [loadUsers])
  useEffect(() => {
    if (!showForm) return
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setShowForm(false) }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [showForm])

  const showSkeleton = useMinDisplay(loading)

  const handleCreate = async () => {
    setError('')
    if (!form.username.trim()) { setError('Username is required'); return }
    if (!form.password || form.password.length < 8) { setError('Password must be at least 8 characters'); return }
    setSubmitting(true)
    try {
      await apiPost('/users', form)
      useToast.getState().success(`User ${form.username} created`)
      setShowForm(false)
      setForm({ username: '', password: '', role: 'viewer' })
      loadUsers()
    } catch (e) { useToast.getState().error(e instanceof Error ? e.message : 'Failed to create user'); setError(e instanceof Error ? e.message : 'Error') } finally { setSubmitting(false) }
  }

  const handleRoleChange = async (id: number, role: string) => {
    setRoleChanging(id)
    try { await apiPut(`/users/${id}/role`, { role }); useToast.getState().success(`Role updated to ${role}`); loadUsers() } catch (e) { useToast.getState().error(e instanceof Error ? e.message : 'Role change failed') }
    finally { setRoleChanging(null) }
  }

  // CRIT-3: replace browser confirm() with toast + double-action UI. We
  // use a window.confirm-equivalent inline state for now (no modal library)
  // but at least surface the action through the toast system so the user
  // gets feedback either way.
  const [deletingId, setDeletingId] = useState<number | null>(null)
  const handleDelete = async (id: number, username: string) => {
    if (!await confirmAction(`Delete user "${username}"? This cannot be undone.`)) return
    setDeletingId(id)
    try {
      await apiDelete(`/users/${id}`)
      useToast.getState().success(`User ${username} deleted`)
      loadUsers()
    } catch (e) {
      useToast.getState().error(e instanceof Error ? e.message : 'Delete failed')
    } finally { setDeletingId(null) }
  }

  const columns = [
    { key: 'username', header: 'Username', render: (u: User) => <span className="font-medium">{u.username}</span> },
    { key: 'role', header: 'Role', render: (u: User) => (
      <select value={u.role} disabled={roleChanging === u.id} onChange={(e) => handleRoleChange(u.id, e.target.value)}
        className="input-field w-28 py-1 text-xs">
        {roles.map(r => <option key={r} value={r}>{r}</option>)}
      </select>
    )},
    { key: 'actions', header: '', render: (u: User) => (
      <button onClick={() => handleDelete(u.id, u.username)} disabled={deletingId === u.id}
        className="p-1.5 rounded hover:bg-red-50 text-slate-400 hover:text-red-500 disabled:opacity-50"
        aria-label={`Delete user ${u.username}`}>
        <Trash2 size={14} />
      </button>
    )},
    { key: 'role_badge', header: 'Level', render: (u: User) => <StatusBadge status={u.role === 'admin' ? 'blocked' : u.role === 'editor' ? 'active' : u.role === 'analyst' ? 'pending' : 'inactive'} /> },
    { key: 'created_at', header: 'Created', render: (u: User) => <span className="text-xs text-slate-400">{new Date(u.created_at).toLocaleDateString()}</span> },
  ]

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold tracking-tight text-slate-900 flex items-center gap-2">
          <UsersIcon size={20} className="text-slate-600" />
          Users & Roles
        </h1>
        <button onClick={() => setShowForm(true)} className="btn-primary"><Plus size={16} /> Add User</button>
      </div>

      {/* Role descriptions */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
        {[
          { role: 'viewer', desc: 'Read-only dashboard access', color: 'slate' },
          { role: 'analyst', desc: 'View logs, export data, replay requests', color: 'amber' },
          { role: 'editor', desc: 'Manage rules, settings, patches', color: 'blue' },
          { role: 'admin', desc: 'Full access including user management', color: 'red' },
        ].map(r => (
          <div key={r.role} className="card p-4">
            <div className="flex items-center gap-2 mb-1">
              <Shield size={14} className={roleIconColors[r.role] || 'text-slate-500'} />
              <span className="text-sm font-semibold text-slate-700 capitalize">{r.role}</span>
            </div>
            <p className="text-xs text-slate-500">{r.desc}</p>
          </div>
        ))}
      </div>

      {loadError && <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-sm text-red-700">{loadError}</div>}

      {showSkeleton ? <SkeletonTable rows={5} cols={4} /> : <DataTable columns={columns} data={users} searchable pageSize={25} emptyMessage="No users found" />}

      {/* Create User Modal */}
      {showForm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/30 backdrop-blur-sm" onClick={() => setShowForm(false)} onKeyDown={(e) => e.key === 'Escape' && setShowForm(false)} tabIndex={-1}>
          <div className="w-full max-w-md mx-4 bg-white rounded-2xl shadow-xl border border-ivory-300 p-6 animate-slide-up" onClick={(e) => e.stopPropagation()}>
            <h2 className="text-lg font-semibold text-slate-900 mb-4">Create User</h2>
            {error && <div className="p-3 bg-red-50 text-red-700 text-sm rounded-lg mb-3">{error}</div>}
            <div className="space-y-3">
              <div>
                <label className="block text-xs font-medium text-slate-600 mb-1">Username</label>
                <input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} className="input-field" placeholder="john" />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-600 mb-1">Password</label>
                <input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} className="input-field" placeholder="••••••••" />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-600 mb-1">Role</label>
                <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })} className="input-field">
                  {roles.map(r => <option key={r} value={r}>{r}</option>)}
                </select>
              </div>
            </div>
            <div className="flex justify-end gap-3 mt-5">
              <button onClick={() => setShowForm(false)} className="btn-secondary">Cancel</button>
              <button onClick={handleCreate} disabled={submitting} className="btn-primary disabled:opacity-50">{submitting ? 'Creating...' : 'Create'}</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
