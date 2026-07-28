import { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Search,
  LayoutDashboard,
  BarChart3,
  ShieldAlert,
  FileText,
  Bot,
  ScrollText,
  Settings,
  Users,
  Radio,
  ShieldPlus,
  RotateCcw,
  FileJson,
  Shield,
  Zap,
  ArrowRight,
} from 'lucide-react'
import { useAppStore } from '../store'
import type { LucideIcon } from 'lucide-react'

interface CommandItem {
  id: string
  label: string
  description: string
  icon: LucideIcon
  action: () => void
  keywords: string[]
  type: 'navigation' | 'action'
}

export default function CommandPalette() {
  const open = useAppStore((s) => s.commandPaletteOpen)
  const close = useAppStore((s) => s.closeCommandPalette)
  const navigate = useNavigate()
  const [query, setQuery] = useState('')
  const [selectedIndex, setSelectedIndex] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)
  const listRef = useRef<HTMLDivElement>(null)

  const items: CommandItem[] = useMemo(() => [
    // Navigation
    { id: 'overview', label: 'Overview', description: 'Security dashboard', icon: LayoutDashboard, action: () => navigate('/overview'), keywords: ['home', 'dashboard', 'main'], type: 'navigation' },
    { id: 'traffic', label: 'Traffic Analytics', description: 'Request traffic data', icon: BarChart3, action: () => navigate('/traffic'), keywords: ['requests', 'analytics'], type: 'navigation' },
    { id: 'threats', label: 'Threat Center', description: 'View active threats', icon: ShieldAlert, action: () => navigate('/threats'), keywords: ['attacks', 'security'], type: 'navigation' },
    { id: 'rules', label: 'Rule Management', description: 'WAF rules', icon: FileText, action: () => navigate('/rules'), keywords: ['waf', 'filter'], type: 'navigation' },
    { id: 'ai', label: 'AI Panel', description: 'AI security assistant', icon: Bot, action: () => navigate('/ai'), keywords: ['chat', 'assistant', 'ml'], type: 'navigation' },
    { id: 'logs', label: 'Request Logs', description: 'Browse request logs', icon: ScrollText, action: () => navigate('/logs'), keywords: ['requests', 'history'], type: 'navigation' },
    { id: 'security', label: 'Security Center', description: 'Protection layers', icon: Shield, action: () => navigate('/security'), keywords: ['protection', 'layers'], type: 'navigation' },
    { id: 'users', label: 'Users & Roles', description: 'Manage users', icon: Users, action: () => navigate('/users'), keywords: ['accounts', 'admin'], type: 'navigation' },
    { id: 'audit', label: 'Audit Log', description: 'System audit trail', icon: ScrollText, action: () => navigate('/audit'), keywords: ['history', 'changes'], type: 'navigation' },
    { id: 'sessions', label: 'Sessions', description: 'Active sessions', icon: Radio, action: () => navigate('/sessions'), keywords: ['active', 'login'], type: 'navigation' },
    { id: 'patches', label: 'Virtual Patches', description: 'CVE patches', icon: ShieldPlus, action: () => navigate('/virtual-patches'), keywords: ['cve', 'vulnerability'], type: 'navigation' },
    { id: 'replay', label: 'Request Replay', description: 'Replay blocked requests', icon: RotateCcw, action: () => navigate('/replay'), keywords: ['test', 'blocked'], type: 'navigation' },
    { id: 'schemas', label: 'API Schemas', description: 'OpenAPI validation', icon: FileJson, action: () => navigate('/api-schemas'), keywords: ['openapi', 'validation'], type: 'navigation' },
    { id: 'settings', label: 'Settings', description: 'System configuration', icon: Settings, action: () => navigate('/settings'), keywords: ['config', 'preferences'], type: 'navigation' },
    // Quick actions
    { id: 'go-threats', label: 'View blocked threats', description: 'Jump to threat center', icon: Zap, action: () => navigate('/threats'), keywords: ['block', 'attack'], type: 'action' },
  ], [navigate])

  const filtered = useMemo(() => {
    if (!query.trim()) return items
    const q = query.toLowerCase()
    return items.filter((item) =>
      item.label.toLowerCase().includes(q) ||
      item.description.toLowerCase().includes(q) ||
      item.keywords.some((k) => k.includes(q))
    )
  }, [items, query])

  const executeItem = useCallback((item: CommandItem) => {
    item.action()
    close()
    setQuery('')
    setSelectedIndex(0)
  }, [close])

  // Reset selection when filtered changes
  useEffect(() => {
    setSelectedIndex(0)
  }, [filtered.length])

  // Focus input on open
  useEffect(() => {
    if (open) {
      setQuery('')
      setSelectedIndex(0)
      setTimeout(() => inputRef.current?.focus(), 50)
    }
  }, [open])

  // Global keyboard shortcut
  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault()
        useAppStore.getState().toggleCommandPalette()
      }
    }
    document.addEventListener('keydown', handleKey)
    return () => document.removeEventListener('keydown', handleKey)
  }, [])

  // Keyboard navigation within palette
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setSelectedIndex((i) => Math.min(i + 1, filtered.length - 1))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setSelectedIndex((i) => Math.max(i - 1, 0))
    } else if (e.key === 'Enter' && filtered[selectedIndex]) {
      e.preventDefault()
      executeItem(filtered[selectedIndex])
    } else if (e.key === 'Escape') {
      close()
    }
  }

  // Scroll selected item into view
  useEffect(() => {
    const list = listRef.current
    if (!list) return
    const selected = list.children[selectedIndex] as HTMLElement
    if (selected) {
      selected.scrollIntoView({ block: 'nearest' })
    }
  }, [selectedIndex])

  if (!open) return null

  return (
    <div
      className="fixed inset-0 z-[200] flex items-start justify-center pt-[15vh] px-4"
      onClick={close}
    >
      {/* Backdrop */}
      <div className="absolute inset-0 bg-slate-900/40 backdrop-blur-sm" />

      {/* Palette */}
      <div
        className="relative w-full max-w-xl bg-white rounded-2xl shadow-2xl shadow-slate-900/20 border border-ivory-200 overflow-hidden animate-slide-up"
        onClick={(e) => e.stopPropagation()}
        onKeyDown={handleKeyDown}
      >
        {/* Search input */}
        <div className="flex items-center gap-3 px-4 py-3.5 border-b border-ivory-200">
          <Search size={18} className="text-slate-400 shrink-0" />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Type a command or search..."
            className="flex-1 text-sm text-slate-800 placeholder:text-slate-400 focus:outline-none bg-transparent"
          />
          <kbd className="px-1.5 py-0.5 text-[10px] font-mono text-slate-400 bg-ivory-50 border border-ivory-200 rounded">
            Esc
          </kbd>
        </div>

        {/* Results */}
        <div ref={listRef} className="max-h-80 overflow-y-auto py-2">
          {filtered.length === 0 ? (
            <div className="px-4 py-8 text-center text-sm text-slate-400">
              No results for &ldquo;{query}&rdquo;
            </div>
          ) : (
            filtered.map((item, i) => {
              const Icon = item.icon
              const isSelected = i === selectedIndex
              return (
                <button
                  key={item.id}
                  onClick={() => executeItem(item)}
                  onMouseEnter={() => setSelectedIndex(i)}
                  className={`w-full flex items-center gap-3 px-4 py-2.5 text-left transition-colors ${
                    isSelected ? 'bg-accent-50 text-accent-700' : 'text-slate-700 hover:bg-ivory-50'
                  }`}
                >
                  <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${
                    isSelected ? 'bg-accent-100' : 'bg-ivory-100'
                  }`}>
                    <Icon size={15} className={isSelected ? 'text-accent-600' : 'text-slate-500'} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium truncate">{item.label}</div>
                    <div className="text-xs text-slate-400 truncate">{item.description}</div>
                  </div>
                  {isSelected && (
                    <ArrowRight size={14} className="text-accent-400 shrink-0" />
                  )}
                </button>
              )
            })
          )}
        </div>

        {/* Footer */}
        <div className="px-4 py-2 border-t border-ivory-100 flex items-center gap-4 text-[10px] text-slate-400">
          <span className="flex items-center gap-1">
            <kbd className="px-1 py-0.5 bg-ivory-50 border border-ivory-200 rounded font-mono">Up</kbd>
            <kbd className="px-1 py-0.5 bg-ivory-50 border border-ivory-200 rounded font-mono">Down</kbd>
            navigate
          </span>
          <span className="flex items-center gap-1">
            <kbd className="px-1 py-0.5 bg-ivory-50 border border-ivory-200 rounded font-mono">Enter</kbd>
            select
          </span>
          <span className="flex items-center gap-1">
            <kbd className="px-1 py-0.5 bg-ivory-50 border border-ivory-200 rounded font-mono">Esc</kbd>
            close
          </span>
        </div>
      </div>
    </div>
  )
}
