import { useState, useEffect, useCallback, useRef } from 'react'
import { Settings as SettingsIcon, Save, RefreshCw, Globe, Shield, Zap, Radio, Bot, Bell, Brain, AlertTriangle, Download, Upload, KeyRound } from 'lucide-react'
import { useLocation } from 'react-router-dom'
import { apiGet, apiPut, apiPost } from '../api/client'
import { useToast } from '../hooks/useToast'
import { confirmAction } from '../components/ConfirmDialog'
import { SkeletonCard } from '../components/Skeleton'
import LocaleSwitcher from '../components/LocaleSwitcher'

interface AppSettings {
  // Upstream
  upstream_url: string
  // Rate limit
  rate_limit: string
  // AI
  ai_provider: string
  ai_nim_api_key: string
  ai_nim_api_key_configured: boolean
  ai_nim_model: string
  ai_nim_base_url: string
  ai_ollama_url: string
  ai_ollama_model: string
  ai_openrouter_api_key: string
  ai_openrouter_api_key_configured: boolean
  ai_openrouter_model: string
  ai_openrouter_base_url: string
  ai_failover_threshold: number
  // Auth
  auth_jwt_secret: string
  auth_jwt_secret_configured: boolean
  // Bot detection
  bot_detection_mode: string
  // Alerts
  alerts_webhook_url: string
  alerts_min_severity: string
  // TLS
  tls_enabled: boolean
  tls_domains: string
  tls_email: string
  // GeoIP
  geoip_enabled: boolean
  geoip_db_path: string
  geoip_blocked: string
  // DDoS
  ddos_max_concurrent_conns: number
  ddos_max_conns_per_ip: number
  ddos_max_new_conns_per_second: number
  ddos_max_tracked_ips: number
  ddos_max_tracked_conns: number
  // Honeypot
  honeypot_enabled: boolean
  honeypot_paths: string
  // Allowlist
  allowlist_enabled: boolean
  // Session
  session_enabled: boolean
  session_cookie_name: string
  session_ttl: string
  // SIEM
  siem_enabled: boolean
  siem_type: string
  siem_syslog_addr: string
  siem_file_path: string
  siem_format: string
  // Logging
  logging_batch_size: number
  logging_flush_interval: string
  // Log retention
  log_retention_days: number
  // Response Inspection
  response_inspect_enabled: boolean
  response_inspect_block_on_leak: boolean
  // AI Classification
  ai_classify_fail_closed: boolean
  ai_classify_fail_closed_paths: string
  ai_classify_timeout: string
  // Reputation / AbuseIPDB
  reputation_enabled: boolean
  abuseipdb_api_key: string
  abuseipdb_api_key_configured: boolean
  reputation_threshold: number
}

const defaults: AppSettings = {
  upstream_url: 'http://localhost:3000',
  rate_limit: '100/min',
  ai_provider: 'auto',
  ai_nim_api_key: '',
  ai_nim_api_key_configured: false,
  ai_nim_model: 'meta/llama-3.1-8b-instruct',
  ai_nim_base_url: 'https://integrate.api.nvidia.com/v1',
  ai_ollama_url: 'http://ollama:11434',
  ai_ollama_model: 'llama3:8b',
  ai_openrouter_api_key: '',
  ai_openrouter_api_key_configured: false,
  ai_openrouter_model: 'openrouter/auto',
  ai_openrouter_base_url: 'https://openrouter.ai/api/v1',
  ai_failover_threshold: 0.9,
  auth_jwt_secret: '',
  auth_jwt_secret_configured: false,
  bot_detection_mode: 'log',
  alerts_webhook_url: '',
  alerts_min_severity: 'medium',
  tls_enabled: false,
  tls_domains: '',
  tls_email: '',
  geoip_enabled: false,
  geoip_db_path: '/var/lib/aegis/GeoLite2-Country.mmdb',
  geoip_blocked: '',
  ddos_max_concurrent_conns: 1000,
  ddos_max_conns_per_ip: 50,
  ddos_max_new_conns_per_second: 100,
  ddos_max_tracked_ips: 10000,
  ddos_max_tracked_conns: 50000,
  honeypot_enabled: true,
  honeypot_paths: '/admin, /wp-login.php, /.env, /phpmyadmin, /xmlrpc.php',
  allowlist_enabled: false,
  session_enabled: true,
  session_cookie_name: 'aegis_session',
  session_ttl: '24h',
  siem_enabled: false,
  siem_type: 'syslog',
  siem_syslog_addr: 'localhost:514',
  siem_file_path: '/var/log/aegis/siem.json',
  siem_format: 'json',
  logging_batch_size: 100,
  logging_flush_interval: '1s',
  log_retention_days: 30,
  response_inspect_enabled: false,
  response_inspect_block_on_leak: false,
  ai_classify_fail_closed: false,
  ai_classify_fail_closed_paths: '/api/v1/auth/, /admin, /wp-admin, /phpmyadmin',
  ai_classify_timeout: '10s',
  reputation_enabled: false,
  abuseipdb_api_key: '',
  abuseipdb_api_key_configured: false,
  reputation_threshold: 50,
}

// P-FIX: keys whose values the server returns as masked (••••••••) plus
// a `_configured` boolean flag. The dashboard form must show the mask
// only — never the actual value — once a value has been saved.
const SECRET_KEYS = ['auth_jwt_secret', 'ai_nim_api_key', 'ai_openrouter_api_key', 'abuseipdb_api_key'] as const
type SecretKey = typeof SECRET_KEYS[number]

const SECRET_PLACEHOLDER = '••••••••'

type Tab = 'general' | 'security' | 'advanced'

function deepEqual(a: AppSettings, b: AppSettings): boolean {
  const ka = Object.keys(a) as (keyof AppSettings)[]
  const kb = Object.keys(b) as (keyof AppSettings)[]
  if (ka.length !== kb.length) return false
  for (const k of ka) {
    if (a[k] !== b[k]) return false
  }
  return true
}

export default function Settings() {
  const [settings, setSettings] = useState<AppSettings>(defaults)
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)
  const [loading, setLoading] = useState(true)
  const [tab, setTab] = useState<Tab>('general')
  const [nimModels, setNimModels] = useState<string[]>([])
  const [ollamaModels, setOllamaModels] = useState<string[]>([])
  const [openrouterModels, setOpenrouterModels] = useState<string[]>([])
  const [fetchingModels, setFetchingModels] = useState<string | null>(null)
  const toast = useToast()

  // --- Config export/import ---
  const [importing, setImporting] = useState(false)
  const [importPreview, setImportPreview] = useState<{dry_run: boolean; settings_count: number; rules_count: number; allowlist_count: number; patches_count: number; geoip_count: number; validation: string} | null>(null)
  const [importData, setImportData] = useState<Record<string, unknown> | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  // P-FIX (M-7/L-6): export without secrets by default. If the user
  // explicitly toggles "include secrets" they see a warning modal and
  // must type CONFIRM before the export proceeds. The export endpoint
  // also requires the same query param on the server, with admin role.
  const [includeSecrets, setIncludeSecrets] = useState(false)
  const [exportSecretsStep, setExportSecretsStep] = useState<0 | 1 | 2>(0) // 0=closed, 1=warning, 2=confirm-typed
  const [exportConfirmText, setExportConfirmText] = useState('')

  const doExport = async (withSecrets: boolean) => {
    try {
      const qs = withSecrets ? '?include_secrets=true' : ''
      const res = await fetch('/api/v1/config/export' + qs, { credentials: 'same-origin' })
      if (!res.ok) {
        const body = await res.json().catch(() => null)
        toast.error(body?.error?.message || 'Export failed')
        return
      }
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = withSecrets ? 'aegis-config-with-secrets.json' : 'aegis-config-export.json'
      a.click()
      URL.revokeObjectURL(url)
      toast.success(withSecrets ? 'Config exported WITH secrets' : 'Config exported')
    } catch (e) {
      toast.error('Export failed')
    }
  }

  const handleExport = () => {
    if (includeSecrets) {
      setExportSecretsStep(1)
      setExportConfirmText('')
    } else {
      doExport(false)
    }
  }

  const confirmSecretsExport = () => {
    if (exportConfirmText !== 'CONFIRM') {
      toast.error('Type CONFIRM to proceed')
      return
    }
    setExportSecretsStep(0)
    doExport(true)
  }

  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    if (file.size > 10 * 1024 * 1024) {
      toast.error('File too large (max 10MB)')
      if (fileInputRef.current) fileInputRef.current.value = ''
      return
    }
    // P-FIX (M-5): require explicit user confirmation before parsing
    // and importing any config file. The action overwrites all rules,
    // allowlist entries, virtual patches, and GeoIP rules on success.
    if (!await confirmAction(
      'Importing a config file will REPLACE your current rules, allowlist, virtual patches, and GeoIP rules. Continue?'
    )) {
      if (fileInputRef.current) fileInputRef.current.value = ''
      return
    }
    try {
      const text = await file.text()
      const data = JSON.parse(text)
      setImportData(data)
      // Dry-run validation
      const res = await fetch('/api/v1/config/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ ...data, dry_run: true }),
      })
      const result = await res.json()
      if (result.success) {
        setImportPreview(result.data)
      } else {
        toast.error(result.error?.message || 'Validation failed')
        setImportData(null)
      }
    } catch (e) {
      toast.error('Invalid JSON file')
      setImportData(null)
    }
    // Reset file input so the same file can be re-selected
    if (fileInputRef.current) fileInputRef.current.value = ''
  }

  const handleImportConfirm = async () => {
    if (!importData) return
    // P-FIX (M-5): second step-up confirmation. The first confirm was
    // on file select; this second guard catches "I clicked Import
    // accidentally and then clicked Cancel halfway through".
    if (!await confirmAction(
      'FINAL CONFIRMATION: Apply this import now? This will overwrite existing rules.'
    )) {
      return
    }
    setImporting(true)
    try {
      const res = await fetch('/api/v1/config/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(importData),
      })
      const result = await res.json()
      if (result.success) {
        const d = result.data
        toast.success(`Imported: ${d.settings_count} settings, ${d.rules_count} rules, ${d.allowlist_count} allowlist, ${d.patches_count} patches, ${d.geoip_count} geoip`)
        setImportPreview(null)
        setImportData(null)
        loadSettings()
      } else {
        toast.error(result.error?.message || 'Import failed')
      }
    } catch (e) {
      toast.error('Import failed')
    } finally {
      setImporting(false)
    }
  }

  const handleImportCancel = () => {
    setImportPreview(null)
    setImportData(null)
  }

  // --- Unsaved changes tracking ---
  const initialRef = useRef<AppSettings>(defaults)
  const [isDirty, setIsDirty] = useState(false)
  const [showNavModal, setShowNavModal] = useState(false)
  const pendingPathRef = useRef<string | null>(null)
  const location = useLocation()
  const prevPathRef = useRef(location.pathname)

  const checkDirty = useCallback((current: AppSettings) => {
    setIsDirty(!deepEqual(current, initialRef.current))
  }, [])

  const fetchModels = async (provider: 'nim' | 'ollama' | 'openrouter') => {
    setFetchingModels(provider)
    try {
      const models = await apiGet<string[]>('/ai/models', { provider })
      if (provider === 'nim') setNimModels(models)
      else if (provider === 'openrouter') setOpenrouterModels(models)
      else setOllamaModels(models)
    } catch (e) {
      useToast.getState().error(e instanceof Error ? e.message : 'Failed to fetch models')
    } finally {
      setFetchingModels(null)
    }
  }

  const loadSettings = useCallback(async () => {
    try {
      const data = await apiGet<Record<string, unknown>>('/settings')
      const merged = { ...defaults }
      if (data) {
        for (const [k, v] of Object.entries(data)) {
          if (Object.prototype.hasOwnProperty.call(data, k) && k !== '__proto__' && k !== 'constructor' && k !== 'prototype' && k in merged) {
            // P-FIX (M-4): never store the actual secret value in the
            // settings form. The server returns only a mask and a
            // `_configured` boolean. We keep the form field at empty
            // so the user sees "•••••••• Set" rendering rather than
            // a real value sitting in component state.
            if ((SECRET_KEYS as readonly string[]).includes(k)) {
              if (typeof v === 'string' && v !== '') {
                ;(merged as Record<string, unknown>)[k] = SECRET_PLACEHOLDER
              } else {
                ;(merged as Record<string, unknown>)[k] = ''
              }
            } else {
              ;(merged as Record<string, unknown>)[k] = v
            }
          }
        }
      }
      setSettings(merged)
      initialRef.current = merged
      setIsDirty(false)
    } catch {
      setSettings(defaults)
      initialRef.current = defaults
      setIsDirty(false)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { loadSettings() }, [loadSettings])

  useEffect(() => {
    if (!showNavModal && !importPreview) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        if (importPreview) setImportPreview(null)
        else if (showNavModal) setShowNavModal(false)
      }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [showNavModal, importPreview])

  // --- beforeunload guard for tab/window close ---
  useEffect(() => {
    const handler = (e: BeforeUnloadEvent) => {
      if (isDirty) {
        e.preventDefault()
      }
    }
    window.addEventListener('beforeunload', handler)
    return () => window.removeEventListener('beforeunload', handler)
  }, [isDirty])

  // --- In-app navigation guard ---
  useEffect(() => {
    if (location.pathname !== prevPathRef.current) {
      prevPathRef.current = location.pathname
      if (isDirty) {
        pendingPathRef.current = location.pathname
        setShowNavModal(true)
        // Navigate back to settings to prevent leaving
        window.history.pushState(null, '', '/settings')
      }
    }
  }, [location.pathname, isDirty])

  if (loading) return (
    <div className="space-y-6 max-w-4xl">
      <h1 className="text-xl font-semibold tracking-tight text-slate-900 flex items-center gap-2">
        <SettingsIcon size={20} className="text-slate-600" />
        Settings
      </h1>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {Array.from({ length: 6 }).map((_, i) => <SkeletonCard key={i} />)}
      </div>
    </div>
  )

  // Keys that are read-only or not allowed via settings API
  const readOnlyKeys = new Set<string>([])

  const handleSave = async () => {
    setSaving(true)
    try {
      const payload: Record<string, unknown> = {}
      for (const [k, v] of Object.entries(settings)) {
        if (readOnlyKeys.has(k)) continue
        // P-FIX (M-4): never send the masked placeholder back to the
        // server. If the user did not retype a secret, omit the key
        // entirely so the stored value is preserved.
        if ((SECRET_KEYS as readonly string[]).includes(k)) {
          if (typeof v === 'string' && v !== '' && v !== SECRET_PLACEHOLDER) {
            payload[k] = v
          }
          continue
        }
        // Drop the *_configured sentinels — they are read-only.
        if (k.endsWith('_configured')) continue
        payload[k] = v
      }
      // Update baseline BEFORE apiPut to avoid race where useEffect/auto-save can fire
      initialRef.current = { ...settings }
      setIsDirty(false)
      await apiPut('/settings', payload)
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    } catch (e) {
      useToast.getState().error(e instanceof Error ? e.message : 'Save failed')
    } finally {
      setSaving(false)
    }
  }

  const handleDiscard = () => {
    setSettings({ ...initialRef.current })
    setIsDirty(false)
    setShowNavModal(false)
    pendingPathRef.current = null
  }

  const handleNavConfirm = () => {
    setShowNavModal(false)
    const target = pendingPathRef.current
    pendingPathRef.current = null
    if (target) {
      // Remove our pushed state and navigate to the target
      window.history.replaceState(null, '', target)
      // Force React Router to see the new location
      window.dispatchEvent(new PopStateEvent('popstate'))
    }
  }

  const handleNavCancel = () => {
    setShowNavModal(false)
    pendingPathRef.current = null
  }

  const tabs = [
    { key: 'general', label: 'General', icon: SettingsIcon },
    { key: 'security', label: 'Security', icon: Shield },
    { key: 'advanced', label: 'Advanced', icon: Zap },
  ] as const

  const update = <K extends keyof AppSettings>(key: K, value: AppSettings[K]) => {
    const next = { ...settings, [key]: value }
    setSettings(next)
    checkDirty(next)
  }

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Navigation guard confirmation modal */}
      {showNavModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm" role="dialog" aria-modal="true" onKeyDown={(e) => e.key === 'Escape' && setShowNavModal(false)} tabIndex={-1}>
          <div className="bg-white rounded-2xl shadow-xl border border-ivory-300 max-w-md w-full mx-4 p-6 animate-slide-up space-y-4">
            <div className="flex items-start gap-3">
              <div className="p-2 rounded-full bg-amber-100 text-amber-600 shrink-0">
                <AlertTriangle size={20} />
              </div>
              <div>
                <h3 className="text-base font-semibold text-slate-900">Unsaved changes</h3>
                <p className="text-sm text-slate-500 mt-1">
                  You have unsaved settings changes. Would you like to save before leaving?
                </p>
              </div>
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <button onClick={handleNavCancel} className="btn-secondary">Cancel</button>
              <button onClick={handleDiscard} className="btn-secondary text-red-600 hover:bg-red-50">
                Discard &amp; Leave
              </button>
              <button onClick={async () => { await handleSave(); handleNavConfirm() }} className="btn-primary">
                Save &amp; Leave
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Import preview modal */}
      {importPreview && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm" role="dialog" aria-modal="true" onKeyDown={(e) => e.key === 'Escape' && setImportPreview(null)} tabIndex={-1}>
          <div className="bg-white rounded-2xl shadow-xl border border-ivory-300 max-w-lg w-full mx-4 p-6 animate-slide-up space-y-4">
            <div className="flex items-start gap-3">
              <div className="p-2 rounded-full bg-amber-100 text-amber-600 shrink-0">
                <AlertTriangle size={20} />
              </div>
              <div>
                <h3 className="text-base font-semibold text-slate-900">Import Configuration</h3>
                <p className="text-sm text-slate-500 mt-1">
                  This will <span className="font-semibold text-amber-700">REPLACE</span> your current configuration. Review what will be imported:
                </p>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3">
              {[
                { label: 'Settings', count: importPreview.settings_count },
                { label: 'Rules', count: importPreview.rules_count },
                { label: 'Allowlist', count: importPreview.allowlist_count },
                { label: 'Virtual Patches', count: importPreview.patches_count },
                { label: 'GeoIP Rules', count: importPreview.geoip_count },
              ].map(item => (
                <div key={item.label} className="flex items-center justify-between p-3 rounded-lg bg-ivory-50 border border-ivory-200">
                  <span className="text-sm text-slate-600">{item.label}</span>
                  <span className="text-sm font-semibold text-slate-900">{item.count}</span>
                </div>
              ))}
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <button onClick={handleImportCancel} className="btn-secondary">Cancel</button>
              <button onClick={handleImportConfirm} disabled={importing} className="btn-primary">
                <Upload size={14} /> {importing ? 'Importing...' : 'Confirm Import'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* P-FIX (L-6/M-7): secrets export warning modal. The user must type
          CONFIRM to download a JSON file that contains API keys and
          other secrets in cleartext. */}
      {exportSecretsStep === 1 && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm" role="dialog" aria-modal="true" onKeyDown={(e) => e.key === 'Escape' && setExportSecretsStep(0)} tabIndex={-1}>
          <div className="bg-white rounded-2xl shadow-xl border border-red-300 max-w-md w-full mx-4 p-6 animate-slide-up space-y-4">
            <div className="flex items-start gap-3">
              <div className="p-2 rounded-full bg-red-100 text-red-600 shrink-0">
                <KeyRound size={20} />
              </div>
              <div>
                <h3 className="text-base font-semibold text-slate-900">Exporting secrets — dangerous</h3>
                <p className="text-sm text-slate-600 mt-1">
                  This export will include API keys, the JWT secret, and webhook URLs in <span className="font-semibold text-red-700">cleartext</span>. Anyone with access to the downloaded file can authenticate against your Aegis deployment.
                </p>
                <ul className="mt-2 text-xs text-slate-600 list-disc pl-5 space-y-1">
                  <li>Store the file offline only</li>
                  <li>Never commit it to source control</li>
                  <li>Delete it after migration is complete</li>
                </ul>
              </div>
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-600 mb-1">Type <span className="font-mono">CONFIRM</span> to proceed</label>
              <input
                value={exportConfirmText}
                onChange={(e) => setExportConfirmText(e.target.value)}
                className="input-field font-mono"
                placeholder="CONFIRM"
                autoFocus
              />
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <button onClick={() => setExportSecretsStep(0)} className="btn-secondary">Cancel</button>
              <button onClick={confirmSecretsExport} disabled={exportConfirmText !== 'CONFIRM'} className="btn-primary bg-red-600 hover:bg-red-700 disabled:opacity-40">
                Download with secrets
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold tracking-tight text-slate-900 flex items-center gap-2">
          <SettingsIcon size={20} className="text-slate-600" />
          Settings
        </h1>
        <div className="flex items-center gap-3">
          <LocaleSwitcher />
          <div className="flex gap-2 items-center">
          <label className="flex items-center gap-1.5 text-[11px] text-slate-500 select-none cursor-pointer" title="When enabled, the exported JSON will include API keys, JWT secret, and webhook URLs in cleartext.">
            <input
              type="checkbox"
              checked={includeSecrets}
              onChange={(e) => setIncludeSecrets(e.target.checked)}
              className="w-3.5 h-3.5 rounded border-slate-300 text-red-600 focus:ring-red-500"
            />
            Include secrets
          </label>
          <button onClick={handleExport} className="btn-secondary"><Download size={14} /> Export</button>
          <button onClick={() => fileInputRef.current?.click()} className="btn-secondary"><Upload size={14} /> Import</button>
          <input ref={fileInputRef} type="file" accept=".json" onChange={handleFileSelect} className="hidden" />
          <button onClick={loadSettings} className="btn-secondary"><RefreshCw size={14} /> Reset</button>
          <button onClick={handleSave} disabled={saving} className="btn-primary">
            <Save size={16} /> {saving ? 'Saving...' : saved ? 'Saved!' : isDirty ? 'Save *' : 'Save All'}
          </button>
          </div>
        </div>
      </div>

      {/* Sticky unsaved changes banner */}
      {isDirty && (
        <div className="sticky top-0 z-30 flex items-center justify-between px-4 py-3 rounded-lg bg-amber-50 border border-amber-200 shadow-sm">
          <div className="flex items-center gap-2 text-sm text-amber-800">
            <AlertTriangle size={16} className="text-amber-500 shrink-0" />
            <span className="font-medium">You have unsaved changes</span>
          </div>
          <div className="flex gap-2">
            <button onClick={handleDiscard} className="btn-secondary text-sm">
              Discard
            </button>
            <button onClick={handleSave} disabled={saving} className="btn-primary text-sm disabled:opacity-50">
              {saving ? 'Saving...' : 'Save'}
            </button>
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-1 p-1 bg-ivory-100 rounded-lg w-fit">
        {tabs.map(({ key, label, icon: Icon }) => (
          <button key={key} onClick={() => setTab(key)}
            className={`flex items-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition-colors ${tab === key ? 'bg-white shadow-sm text-slate-900' : 'text-slate-500 hover:text-slate-700'}`}>
            <Icon size={16} /> {label}
          </button>
        ))}
      </div>

      {/* General Tab */}
      {tab === 'general' && (
        <div className="space-y-5">
          {/* Upstream */}
          <section className="card p-5">
            <h2 className="text-sm font-semibold text-slate-700 mb-4 pb-2 border-b border-ivory-200 flex items-center gap-2">
              <Globe size={14} /> Website / Upstream
            </h2>
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-600 mb-1.5">Upstream URL</label>
                <input value={settings.upstream_url} onChange={(e) => update('upstream_url', e.target.value)} className="input-field" placeholder="http://your-website:3000" />
                <p className="text-[11px] text-slate-400 mt-1">Your website/backend that Aegis protects and proxies traffic to</p>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-slate-600 mb-1.5">Rate Limit</label>
                  <input value={settings.rate_limit} onChange={(e) => update('rate_limit', e.target.value)} className="input-field" placeholder="100/min" />
                  <p className="text-[11px] text-slate-400 mt-1">Requests per window (e.g. 100/min, 1000/hour)</p>
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-600 mb-1.5">Log Retention (days)</label>
                  <input type="number" value={settings.log_retention_days} onChange={(e) => update('log_retention_days', parseInt(e.target.value) || 30)} className="input-field" />
                </div>
              </div>
            </div>
          </section>

          {/* Bot Detection */}
          <section className="card p-5">
            <h2 className="text-sm font-semibold text-slate-700 mb-4 pb-2 border-b border-ivory-200">Bot Detection</h2>
            <div>
              <label className="block text-xs font-medium text-slate-600 mb-1.5">Mode</label>
              <select value={settings.bot_detection_mode} onChange={(e) => update('bot_detection_mode', e.target.value)} className="input-field w-48">
                <option value="off">Off</option>
                <option value="log">Log Only</option>
                <option value="block">Block Bad Bots</option>
              </select>
              <p className="text-[11px] text-slate-400 mt-1">Block mode blocks nikto, sqlmap, nmap, burp, etc.</p>
            </div>
          </section>

          {/* Alerts */}
          <section className="card p-5">
            <h2 className="text-sm font-semibold text-slate-700 mb-4 pb-2 border-b border-ivory-200 flex items-center gap-2">
              <Bell size={14} /> Alerts
            </h2>
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-600 mb-1.5">Webhook URL</label>
                <input value={settings.alerts_webhook_url} onChange={(e) => update('alerts_webhook_url', e.target.value)} className="input-field" placeholder="https://hooks.slack.com/..." />
                <p className="text-[11px] text-slate-400 mt-1">Slack, Discord, or any webhook endpoint for alerts</p>
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-600 mb-1.5">Minimum Severity</label>
                <select value={settings.alerts_min_severity} onChange={(e) => update('alerts_min_severity', e.target.value)} className="input-field w-48">
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
              </div>
            </div>
          </section>
        </div>
      )}

      {/* Security Tab */}
      {tab === 'security' && (
        <div className="space-y-5">
          {/* TLS */}
          <section className="card p-5">
            <h2 className="text-sm font-semibold text-slate-700 mb-4 pb-2 border-b border-ivory-200 flex items-center gap-2">
              <Shield size={14} /> HTTPS / TLS (Let's Encrypt)
            </h2>
            <div className="space-y-4">
              <label className="flex items-center gap-3 cursor-pointer">
                <input type="checkbox" checked={settings.tls_enabled} onChange={(e) => update('tls_enabled', e.target.checked)} className="w-4 h-4 rounded border-slate-300 text-accent-600" />
                <span className="text-sm font-medium text-slate-700">Enable HTTPS with Let's Encrypt</span>
              </label>
              {settings.tls_enabled && (
                <>
                  <div>
                    <label className="block text-xs font-medium text-slate-600 mb-1.5">Domains (comma separated)</label>
                    <input value={settings.tls_domains} onChange={(e) => update('tls_domains', e.target.value)} className="input-field" placeholder="yourdomain.com, www.yourdomain.com" />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-600 mb-1.5">Email (for Let's Encrypt notifications)</label>
                    <input value={settings.tls_email} onChange={(e) => update('tls_email', e.target.value)} className="input-field" placeholder="you@email.com" />
                  </div>
                </>
              )}
            </div>
          </section>

          {/* GeoIP */}
          <section className="card p-5">
            <h2 className="text-sm font-semibold text-slate-700 mb-4 pb-2 border-b border-ivory-200 flex items-center gap-2">
              <Globe size={14} /> GeoIP Blocking
            </h2>
            <div className="space-y-4">
              <label className="flex items-center gap-3 cursor-pointer">
                <input type="checkbox" checked={settings.geoip_enabled} onChange={(e) => update('geoip_enabled', e.target.checked)} className="w-4 h-4 rounded border-slate-300 text-accent-600" />
                <span className="text-sm font-medium text-slate-700">Enable country-based blocking</span>
              </label>
              {settings.geoip_enabled && (
                <>
                  <div>
                    <label className="block text-xs font-medium text-slate-600 mb-1.5">MaxMind DB Path</label>
                    <input value={settings.geoip_db_path} onChange={(e) => update('geoip_db_path', e.target.value)} className="input-field font-mono text-xs" />
                    <p className="text-[11px] text-slate-400 mt-1">Download GeoLite2-Country.mmdb from maxmind.com (free)</p>
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-600 mb-1.5">Blocked Countries (comma separated 2-letter codes)</label>
                    <input value={settings.geoip_blocked} onChange={(e) => update('geoip_blocked', e.target.value)} className="input-field font-mono" placeholder="CN, RU, KP" />
                  </div>
                </>
              )}
            </div>
          </section>

          {/* DDoS */}
          <section className="card p-5">
            <h2 className="text-sm font-semibold text-slate-700 mb-4 pb-2 border-b border-ivory-200 flex items-center gap-2">
              <Zap size={14} /> DDoS Protection
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label className="block text-xs font-medium text-slate-600 mb-1.5">Max Concurrent Connections</label>
                <input type="number" value={settings.ddos_max_concurrent_conns} onChange={(e) => update('ddos_max_concurrent_conns', parseInt(e.target.value) || 1000)} className="input-field" />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-600 mb-1.5">Max Connections per IP</label>
                <input type="number" value={settings.ddos_max_conns_per_ip} onChange={(e) => update('ddos_max_conns_per_ip', parseInt(e.target.value) || 50)} className="input-field" />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-600 mb-1.5">Max New Connections/sec</label>
                <input type="number" value={settings.ddos_max_new_conns_per_second} onChange={(e) => update('ddos_max_new_conns_per_second', parseInt(e.target.value) || 100)} className="input-field" />
              </div>
            </div>
          </section>

          {/* Allowlist */}
          <section className="card p-5">
            <h2 className="text-sm font-semibold text-slate-700 mb-4 pb-2 border-b border-ivory-200 flex items-center gap-2">
              <Shield size={14} /> Allowlist Mode
            </h2>
            <label className="flex items-center gap-3 cursor-pointer">
              <input type="checkbox" checked={settings.allowlist_enabled} onChange={(e) => update('allowlist_enabled', e.target.checked)} className="w-4 h-4 rounded border-slate-300 text-accent-600" />
              <div>
                <span className="text-sm font-medium text-slate-700">Enable default-deny mode</span>
                <p className="text-[11px] text-slate-400 mt-0.5">Only explicitly allowed requests pass through. Manage allow rules in Security Center.</p>
              </div>
            </label>
          </section>

          {/* Honeypot */}
          <section className="card p-5">
            <h2 className="text-sm font-semibold text-slate-700 mb-4 pb-2 border-b border-ivory-200">Honeypot</h2>
            <div className="space-y-4">
              <label className="flex items-center gap-3 cursor-pointer">
                <input type="checkbox" checked={settings.honeypot_enabled} onChange={(e) => update('honeypot_enabled', e.target.checked)} className="w-4 h-4 rounded border-slate-300 text-accent-600" />
                <span className="text-sm font-medium text-slate-700">Enable honeypot decoy endpoints</span>
              </label>
              <div>
                <label className="block text-xs font-medium text-slate-600 mb-1.5">Trap Paths (comma separated)</label>
                <input value={settings.honeypot_paths} onChange={(e) => update('honeypot_paths', e.target.value)} className="input-field font-mono text-xs" />
              </div>
            </div>
          </section>

          {/* Protection Templates */}
          <ProtectionTemplatesCard />
        </div>
      )}

      {/* AI Tab */}
      {tab === 'advanced' && (
        <div className="space-y-5">
          {/* Session */}
          <section className="card p-5">
            <h2 className="text-sm font-semibold text-slate-700 mb-4 pb-2 border-b border-ivory-200 flex items-center gap-2">
              <Radio size={14} /> Session Tracking
            </h2>
            <div className="space-y-4">
              <label className="flex items-center gap-3 cursor-pointer">
                <input type="checkbox" checked={settings.session_enabled} onChange={(e) => update('session_enabled', e.target.checked)} className="w-4 h-4 rounded border-slate-300 text-accent-600" />
                <span className="text-sm font-medium text-slate-700">Enable session tracking</span>
              </label>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-slate-600 mb-1.5">Cookie Name</label>
                  <input value={settings.session_cookie_name} onChange={(e) => update('session_cookie_name', e.target.value)} className="input-field" />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-600 mb-1.5">TTL</label>
                  <input value={settings.session_ttl} onChange={(e) => update('session_ttl', e.target.value)} className="input-field" placeholder="24h" />
                </div>
              </div>
            </div>
          </section>

          {/* SIEM */}
          <section className="card p-5">
            <h2 className="text-sm font-semibold text-slate-700 mb-4 pb-2 border-b border-ivory-200">SIEM Integration</h2>
            <div className="space-y-4">
              <label className="flex items-center gap-3 cursor-pointer">
                <input type="checkbox" checked={settings.siem_enabled} onChange={(e) => update('siem_enabled', e.target.checked)} className="w-4 h-4 rounded border-slate-300 text-accent-600" />
                <span className="text-sm font-medium text-slate-700">Enable SIEM export</span>
              </label>
              {settings.siem_enabled && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs font-medium text-slate-600 mb-1.5">Type</label>
                    <select value={settings.siem_type} onChange={(e) => update('siem_type', e.target.value)} className="input-field">
                      <option value="syslog">Syslog</option>
                      <option value="file">File</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-600 mb-1.5">Format</label>
                    <select value={settings.siem_format} onChange={(e) => update('siem_format', e.target.value)} className="input-field">
                      <option value="json">JSON</option>
                      <option value="cef">CEF</option>
                    </select>
                  </div>
                  {settings.siem_type === 'syslog' ? (
                    <div>
                      <label className="block text-xs font-medium text-slate-600 mb-1.5">Syslog Address</label>
                      <input value={settings.siem_syslog_addr} onChange={(e) => update('siem_syslog_addr', e.target.value)} className="input-field" placeholder="localhost:514" />
                    </div>
                  ) : (
                    <div>
                      <label className="block text-xs font-medium text-slate-600 mb-1.5">File Path</label>
                      <input value={settings.siem_file_path} onChange={(e) => update('siem_file_path', e.target.value)} className="input-field font-mono text-xs" />
                    </div>
                  )}
                </div>
              )}
            </div>
          </section>

          {/* Logging */}
          <section className="card p-5">
            <h2 className="text-sm font-semibold text-slate-700 mb-4 pb-2 border-b border-ivory-200">Logging</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-medium text-slate-600 mb-1.5">Batch Size</label>
                <input type="number" value={settings.logging_batch_size} onChange={(e) => update('logging_batch_size', parseInt(e.target.value) || 100)} className="input-field" />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-600 mb-1.5">Flush Interval</label>
                <input value={settings.logging_flush_interval} onChange={(e) => update('logging_flush_interval', e.target.value)} className="input-field" placeholder="1s" />
              </div>
            </div>
          </section>

          {/* Auth */}
          <section className="card p-5 border-amber-200">
            <h2 className="text-sm font-semibold text-amber-700 mb-4 pb-2 border-b border-amber-100">Authentication</h2>
            <div>
              <label className="block text-xs font-medium text-slate-600 mb-1.5">JWT Secret</label>
              <SecretField
                fieldKey="auth_jwt_secret"
                value={settings.auth_jwt_secret}
                configured={settings.auth_jwt_secret_configured}
                onChange={(v) => update('auth_jwt_secret', v)}
                placeholder="change-me-in-production"
              />
              <p className="text-[11px] text-amber-600 mt-1">Changing this will invalidate all existing sessions</p>
            </div>
          </section>
        </div>
      )}
    </div>
  )
}

// SecretField renders a settings input that holds a sensitive value.
// P-FIX (M-4): once a secret is configured on the server, the field
// shows a static mask (••••••••) and a "Change" button. Clicking
// Change flips to a plain input; clicking "Cancel" or saving empties
// the field restores the mask. The component never holds the actual
// plaintext value in component state when initially mounted.
interface SecretFieldProps {
  fieldKey: SecretKey
  value: string
  configured: boolean
  onChange: (v: string) => void
  placeholder?: string
}

function SecretField({ value, configured, onChange, placeholder }: SecretFieldProps) {
  const [editing, setEditing] = useState(false)
  const showMask = configured && !editing
  return (
    <div className="flex items-center gap-2">
      {showMask ? (
        <>
          <input
            type="password"
            value={SECRET_PLACEHOLDER}
            readOnly
            aria-label="Secret (hidden)"
            className="input-field flex-1 font-mono text-slate-500 tracking-widest cursor-not-allowed"
          />
          <button
            type="button"
            onClick={() => { onChange(''); setEditing(true) }}
            className="btn-secondary text-xs shrink-0"
          >
            {value === '' ? 'Set' : 'Change'}
          </button>
        </>
      ) : (
        <>
          <input
            type="password"
            value={value}
            onChange={(e) => onChange(e.target.value)}
            className="input-field flex-1 font-mono"
            placeholder={placeholder || ''}
            autoFocus={editing}
          />
          {configured && (
            <button
              type="button"
              onClick={() => { onChange(SECRET_PLACEHOLDER); setEditing(false) }}
              className="btn-secondary text-xs shrink-0"
            >
              Cancel
            </button>
          )}
        </>
      )}
    </div>
  )
}

function ProtectionTemplatesCard() {
  const [templates, setTemplates] = useState<Array<{id: string; name: string; description: string; paranoia_level: number; rule_count: number}>>([])
  const [applying, setApplying] = useState<string | null>(null)

  useEffect(() => {
    apiGet<Array<{id: string; name: string; description: string; paranoia_level: number; rule_count: number}>>('/templates')
      .then(setTemplates)
      .catch(() => {})
  }, [])

  const handleApply = async (id: string) => {
    if (!await confirmAction(`Apply this template? It will add rules to your rule set.`)) return
    setApplying(id)
    try {
      const res = await apiPost<{rules_added: number}>(`/templates/${id}/apply`, {})
      useToast.getState().success(`Applied template — ${res.rules_added} rules added`)
    } catch (e) {
      useToast.getState().error(e instanceof Error ? e.message : 'Failed to apply template')
    } finally {
      setApplying(null)
    }
  }

  const icons: Record<string, string> = {
    'api-protection': '🔌',
    'web-app': '🌐',
    'high-security': '🛡️',
    'low-false-positives': '🎯',
  }

  return (
    <section className="card p-5">
      <h2 className="text-sm font-semibold text-slate-700 mb-4 pb-2 border-b border-ivory-200 flex items-center gap-2">
        <Shield size={14} /> Protection Templates
      </h2>
      <p className="text-xs text-slate-500 mb-4">Apply pre-built security profiles with one click. Each template adds a set of rules optimized for a specific use case.</p>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {templates.map(t => (
          <div key={t.id} className="p-4 rounded-xl border border-ivory-200 bg-ivory-50/50 hover:border-accent-300 transition-colors">
            <div className="flex items-start justify-between mb-2">
              <div>
                <span className="text-lg mr-2">{icons[t.id] || '📋'}</span>
                <span className="text-sm font-semibold text-slate-800">{t.name}</span>
              </div>
              <span className="badge bg-slate-100 text-slate-600">PL{t.paranoia_level}</span>
            </div>
            <p className="text-xs text-slate-500 mb-3">{t.description}</p>
            <div className="flex items-center justify-between">
              <span className="text-[11px] text-slate-400">{t.rule_count} rules</span>
              <button
                onClick={() => handleApply(t.id)}
                disabled={applying === t.id}
                className="btn-primary text-xs py-1.5 px-3 disabled:opacity-50"
              >
                {applying === t.id ? 'Applying...' : 'Apply'}
              </button>
            </div>
          </div>
        ))}
      </div>
    </section>
  )
}
