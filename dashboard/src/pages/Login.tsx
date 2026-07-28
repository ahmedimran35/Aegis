import { useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { Shield, Loader2, Lock } from 'lucide-react'
import { apiPost } from '../api/client'
import { useAppStore, type AuthUser } from '../store'
import Pulse from '../components/Pulse'

interface LoginResponse {
  user: AuthUser
  expires_in: number
}

export default function Login() {
  const navigate = useNavigate()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [searchParams] = useSearchParams()
  const setStoreUser = useAppStore((s) => s.setUser)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    // Validate ?next= param: must be a local path (starts with single "/", not "//" or "/\" or protocol).
    // React Router's navigate() will interpret "//evil.com" as protocol-relative URL on some browsers.
    const rawNext = searchParams.get('next') || ''
    const safeNext = /^\/[A-Za-z0-9_\-/]*$/.test(rawNext) ? rawNext : '/overview'

    try {
      const res = await apiPost<LoginResponse>('/auth/login', { username, password })
      // P-FIX (CWE-922): user goes into zustand memory only, never localStorage.
      // Auth token itself is set by server as HttpOnly cookie.
      setStoreUser(res.user)
      navigate(safeNext)
    } catch (err) {
      // P-FIX (L-2): api/client now sanitizes server error messages into
      // a generic "Operation failed (ref: XXXX)" — but auth has a small
      // allow-list that surfaces "Invalid username or password" so the
      // user knows what to fix. We render that string verbatim.
      setError(err instanceof Error ? err.message : 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center px-4 bg-ivory-100">
      {/* Subtle grid */}
      <div
        className="absolute inset-0 opacity-[0.5] pointer-events-none"
        style={{
          backgroundImage:
            'linear-gradient(rgba(212,205,184,0.25) 1px, transparent 1px), linear-gradient(90deg, rgba(212,205,184,0.25) 1px, transparent 1px)',
          backgroundSize: '32px 32px',
          maskImage: 'radial-gradient(ellipse at center, black 30%, transparent 80%)',
          WebkitMaskImage: 'radial-gradient(ellipse at center, black 30%, transparent 80%)',
        }}
      />

      <div className="w-full max-w-[360px] relative">
        {/* Brand */}
        <div className="text-center mb-6">
          <div className="relative inline-flex items-center justify-center w-14 h-14 rounded-md bg-forest-500 mb-3 shadow-[0_1px_0_rgba(28,31,38,0.04)]">
            <Shield className="w-7 h-7 text-ivory-50" strokeWidth={1.75} />
            <span className="absolute -top-1 -right-1 inline-flex h-3 w-3 rounded-full bg-forest-50 border-2 border-forest-500">
              <Pulse variant="live" size="sm" />
            </span>
          </div>
          <h1 className="text-xl font-semibold tracking-tight text-ink-700">Aegis</h1>
          <p className="text-[12px] text-ink-400 mt-1 font-mono uppercase tracking-[0.08em]">Security Operations</p>
        </div>

        {/* Trust badge */}
        <div className="flex items-center justify-center gap-2 mb-4 text-[10px] font-mono uppercase tracking-[0.08em] text-ink-400">
          <Lock size={10} strokeWidth={2} />
          <span>Session cookies are HttpOnly + Secure</span>
        </div>

        {/* Card */}
        <form onSubmit={handleSubmit} className="card-elevated p-5 space-y-4">
          {error && (
            <div className="px-3 py-2 text-[12px] text-brick-500 bg-brick-50 border border-brick-100 rounded">
              {error}
            </div>
          )}

          <div className="space-y-1">
            <label htmlFor="login-username" className="block stat-label">Username</label>
            <input
              id="login-username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="input-field"
              placeholder="admin"
              required
              autoFocus
            />
          </div>

          <div className="space-y-1">
            <label htmlFor="login-password" className="block stat-label">Password</label>
            <input
              id="login-password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="input-field font-mono"
              placeholder="••••••••••••"
              required
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="btn-primary w-full justify-center mt-2 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? (
              <Loader2 size={14} className="animate-spin" />
            ) : (
              'Sign In'
            )}
          </button>
        </form>

        <p className="text-center text-[10px] font-mono text-ink-500 mt-4 uppercase tracking-[0.08em]">
          Aegis WAF · v0.1.0
        </p>
      </div>
    </div>
  )
}