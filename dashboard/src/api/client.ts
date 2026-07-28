const BASE_URL = '/api/v1'

export interface ApiResponse<T> {
  success: boolean
  data: T
  meta?: { page: number; per_page: number; total: number }
  error?: { code: string; message: string }
}

// CSRF token handling.
//
// The server (internal/api/security.go) issues a non-HttpOnly cookie
// named `__Host-aegis_csrf` (HTTPS) or `aegis_csrf` (plain HTTP, dev
// only). The browser includes that cookie on every request, and we
// must echo its value in the `X-CSRF-Token` header on state-changing
// requests. This is the classic double-submit pattern: the cookie is
// sent automatically by the browser, and the JS-readable value is
// explicitly added as a header by fetch().
function readCookie(name: string): string | null {
  if (typeof document === 'undefined') return null
  for (const part of document.cookie ? document.cookie.split('; ') : []) {
    const eq = part.indexOf('=')
    if (eq < 0) continue
    if (part.slice(0, eq) === name) {
      return decodeURIComponent(part.slice(eq + 1))
    }
  }
  return null
}

// csrfHeaders returns the X-CSRF-Token header for double-submit
// validation on state-changing requests. The function inspects both
// the production cookie name and the dev fallback so it works in
// both modes.
export function csrfHeaders(): Record<string, string> {
  const v = readCookie('__Host-aegis_csrf') || readCookie('aegis_csrf')
  return v ? { 'X-CSRF-Token': v } : {}
}

// Auth state is tracked server-side via /auth/me (HttpOnly cookie).
// The previous version stored an `aegis_authed` localStorage flag that
// could be set by any script on the page; the client now relies on
// the server response alone. The functions below are kept as no-ops
// so legacy callers compile; they no longer touch localStorage.
export function getToken(): string | null { return null }
export function setToken(): void { /* no-op: cookie is HttpOnly */ }
export function clearToken(): void { /* no-op: cookie is cleared by server */ }

function authHeaders(): Record<string, string> {
  return {} // auth is via HttpOnly cookie, no JS-accessible header needed
}

// P-FIX (L-2): show the user a generic "Operation failed" message
// with a short correlation ID, instead of the server's raw error
// text. The detailed server message can leak internal state (table
// names, validation rules, stack traces). We log the full error to
// the browser console for support, but the visible toast / state
// shows only the correlation id.
function genErrorId(): string {
  return Math.random().toString(36).slice(2, 10).toUpperCase()
}

export class ApiError extends Error {
  id: string
  code: string
  status: number
  constructor(message: string, code: string, status: number, id: string) {
    super(message)
    this.id = id
    this.code = code
    this.status = status
  }
}

function sanitizeError(status: number, raw: { code?: string; message?: string } | null): ApiError {
  const id = genErrorId()
  // Generic copy keyed on broad status buckets. The server's raw
  // message is intentionally not exposed to the user — they can
  // reference the correlation id when contacting support.
  let safe = 'Operation failed'
  if (status === 401) safe = 'Authentication required'
  else if (status === 403) safe = 'Permission denied'
  else if (status === 404) safe = 'Not found'
  else if (status === 409) safe = 'Conflict'
  else if (status === 429) safe = 'Rate limited'
  else if (status >= 500) safe = 'Server error'
  // Allow-list a few harmless codes so the UI can branch sensibly
  // (e.g. WEAK_PASSWORD shows password rules; nothing else).
  const safeCodes = new Set(['WEAK_PASSWORD', 'INVALID_CREDENTIALS', 'ACCOUNT_LOCKED', 'MISSING_FIELDS', 'CSRF_CHECK_FAILED'])
  const code = raw?.code || 'UNKNOWN'
  const message = safeCodes.has(code) && raw?.message ? raw.message : safe
  // Log the full detail for support / debugging.
  if (raw) {
    // eslint-disable-next-line no-console
    console.error(`[api ${id}] ${status} ${code}: ${raw.message ?? '(no message)'}`)
  }
  return new ApiError(`${message} (ref: ${id})`, code, status, id)
}

async function checkRes(res: Response): Promise<Response> {
  if (res.status === 401) {
    // Session expired. Don't try to read the body for a friendly
    // message — the server's body might leak whether the account
    // exists. Just redirect to /login and surface a generic toast.
    clearToken()
    if (!window.location.pathname.startsWith('/login')) {
      window.location.href = '/login'
    }
    throw sanitizeError(401, { code: 'UNAUTHORIZED', message: 'authentication required' })
  }
  if (!res.ok) {
    let raw: { code?: string; message?: string } | null = null
    try {
      const body = await res.json()
      if (body && typeof body === 'object' && body.error) {
        raw = { code: body.error.code, message: body.error.message }
      }
    } catch { /* fall through with null */ }
    throw sanitizeError(res.status, raw)
  }
  return res
}

export async function apiGet<T>(path: string, params?: Record<string, string>): Promise<T> {
  const url = new URL(BASE_URL + path, window.location.origin)
  if (params) {
    Object.entries(params).forEach(([k, v]) => {
      if (v) url.searchParams.set(k, v)
    })
  }
  const res = await checkRes(await fetch(url.toString(), {
    headers: { ...authHeaders(), ...csrfHeaders() },
    credentials: 'same-origin',
  }))
  const json: ApiResponse<T> = await res.json()
  if (!json.success) throw sanitizeError(res.status, json.error || null)
  return json.data
}

export async function apiPost<T>(path: string, body: unknown): Promise<T> {
  const res = await checkRes(await fetch(BASE_URL + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders(), ...csrfHeaders() },
    body: JSON.stringify(body),
    credentials: 'same-origin',
  }))
  const json: ApiResponse<T> = await res.json()
  if (!json.success) throw sanitizeError(res.status, json.error || null)
  return json.data
}

export async function apiPut<T>(path: string, body: unknown): Promise<T> {
  const res = await checkRes(await fetch(BASE_URL + path, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', ...authHeaders(), ...csrfHeaders() },
    body: JSON.stringify(body),
    credentials: 'same-origin',
  }))
  const json: ApiResponse<T> = await res.json()
  if (!json.success) throw sanitizeError(res.status, json.error || null)
  return json.data
}

export async function apiDelete<T>(path: string): Promise<T> {
  const res = await checkRes(await fetch(BASE_URL + path, {
    method: 'DELETE',
    headers: { ...authHeaders(), ...csrfHeaders() },
    credentials: 'same-origin',
  }))
  const json: ApiResponse<T> = await res.json()
  if (!json.success) throw sanitizeError(res.status, json.error || null)
  return json.data
}

// Polling hook
import { useState, useEffect, useCallback } from 'react'

export function usePolling<T>(path: string, intervalMs = 5000, params?: Record<string, string>) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  const fetch_ = useCallback(async () => {
    try {
      const result = await apiGet<T>(path, params)
      setData(result)
      setError(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unknown error')
    } finally {
      setLoading(false)
    }
  }, [path, JSON.stringify(params)])

  useEffect(() => {
    fetch_()
    const id = setInterval(fetch_, intervalMs)
    return () => clearInterval(id)
  }, [fetch_, intervalMs])

  return { data, error, loading, refetch: fetch_ }
}

// ---------------------------------------------------------------------------
// P-FREE 1-4: client wrappers for the free improvements endpoints.
// All return live counters from the running WAF; no external service.
// ---------------------------------------------------------------------------

export interface WSGuardStats {
  upgrades_allowed: number
  upgrades_blocked: number
  messages_blocked: number
  origins_rejected: number
  config: string
  frame_limit: number
}

export const fetchWSGuardStats = () =>
  apiGet<WSGuardStats>('/dashboard/wsguard/stats')

export interface ThreatFeedStats {
  sources: number
  last_fetch: string
  last_error: string
  total_ips: number
  feeds: Record<string, number>
  checks: number
  hits: number
  blocks: number
}

export const fetchThreatFeedStats = () =>
  apiGet<ThreatFeedStats>('/dashboard/threatfeed')

export interface CRSUpdateStats {
  last_fetch: string
  last_error: string
  imported: number
  skipped: number
  ref: string
  interval: string
}

export const fetchCRSUpdateStats = () =>
  apiGet<CRSUpdateStats>('/dashboard/crs-update')

export interface AnomalyStatsStats {
  requests_scanned: number
  entropy_blocks: number
  zscore_blocks: number
  errors: number
}

export const fetchAnomalyStatsStats = () =>
  apiGet<AnomalyStatsStats>('/dashboard/anomaly-stats')
