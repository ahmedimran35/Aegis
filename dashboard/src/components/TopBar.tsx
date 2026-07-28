import { useLocation, Link } from 'react-router-dom'
import { Wifi, WifiOff, Menu, LogOut, Keyboard, Columns, Search, Bell, Activity } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { usePolling } from '../api/client'
import { useAppStore } from '../store'
import { clearToken } from '../api/client'
import NotificationPanel from './NotificationPanel'

interface HealthData {
  status: string
  version: string
}

const routeTitles: Record<string, string> = {
  '/overview': 'Overview',
  '/traffic': 'Traffic Analytics',
  '/threats': 'Threat Center',
  '/logs': 'Request Logs',
  '/rules': 'Rule Management',
  '/security': 'Security Center',
  '/virtual-patches': 'Virtual Patches',
  '/api-schemas': 'API Schemas',
  '/ai': 'AI Panel',
  '/replay': 'Request Replay',
  '/users': 'Users & Roles',
  '/audit': 'Audit Log',
  '/sessions': 'Sessions',
  '/settings': 'Settings',
}

function useBreadcrumbs() {
  const location = useLocation()
  const segments = location.pathname.split('/').filter(Boolean)
  if (segments.length === 0) return [{ label: 'Aegis', to: '/' }]
  const crumbs = [{ label: 'Aegis', to: '/overview' }]
  let acc = ''
  for (const seg of segments) {
    acc += '/' + seg
    crumbs.push({ label: routeTitles[acc] || seg, to: acc })
  }
  return crumbs
}

export default function TopBar({ onShowShortcuts }: { onShowShortcuts?: () => void }) {
  const { data: health, error } = usePolling<HealthData>('/health', 10000)
  const toggleMobile = useAppStore((s) => s.toggleMobileMenu)
  const compactMode = useAppStore((s) => s.compactMode)
  const toggleCompact = useAppStore((s) => s.toggleCompactMode)
  const openCommandPalette = useAppStore((s) => s.openCommandPalette)
  const notifications = useAppStore((s) => s.notifications)
  const notificationPanelOpen = useAppStore((s) => s.notificationPanelOpen)
  const toggleNotificationPanel = useAppStore((s) => s.toggleNotificationPanel)
  const navigate = useNavigate()
  const crumbs = useBreadcrumbs()

  const unreadCount = notifications.filter((n) => !n.read).length

  const handleLogout = async () => {
    try {
      await fetch('/api/v1/auth/logout', { method: 'POST', credentials: 'same-origin' })
    } catch { /* best effort */ }
    clearToken()
    navigate('/login')
  }

  return (
    <header className="sticky top-0 z-30 h-14 bg-ivory-50/90 backdrop-blur border-b border-ivory-300">
      <div className="flex items-center justify-between h-full pl-3 pr-4 md:px-5">
        {/* Left: mobile menu + breadcrumb */}
        <div className="flex items-center gap-3 min-w-0">
          <button
            onClick={toggleMobile}
            aria-label="Toggle menu"
            className="md:hidden p-1.5 -ml-1 rounded text-ink-400 hover:bg-ivory-200"
          >
            <Menu size={18} />
          </button>

          {/* Breadcrumb path */}
          <nav className="hidden sm:flex items-center gap-1.5 text-[12px] font-mono tabular-nums min-w-0">
            {crumbs.map((c, i) => {
              const isLast = i === crumbs.length - 1
              return (
                <span key={c.to} className="flex items-center gap-1.5 min-w-0">
                  {i > 0 && <span className="text-ink-500">/</span>}
                  {isLast ? (
                    <span className="path-segment-active truncate">{c.label}</span>
                  ) : (
                    <Link to={c.to} className="path-segment">{c.label}</Link>
                  )}
                </span>
              )
            })}
          </nav>
        </div>

        {/* Center: Search trigger */}
        <button
          onClick={openCommandPalette}
          className="hidden md:flex items-center gap-2 px-3 py-1.5 text-[12px] text-ink-400 bg-white border border-ivory-300 rounded-md hover:border-ivory-400 hover:text-ink-500 transition-colors w-72"
        >
          <Search size={13} strokeWidth={1.75} />
          <span className="flex-1 text-left">Jump to...</span>
          <kbd className="inline-flex items-center px-1.5 py-0.5 text-[10px] font-mono bg-ivory-100 border border-ivory-300 rounded text-ink-400 tabular-nums">Ctrl K</kbd>
        </button>

        {/* Right: status + actions */}
        <div className="flex items-center gap-1">
          {/* Version + status — chunk hash so user can confirm they are on
              the latest build (after a hard refresh, this hash matches
              the one in `dist/assets/ThreatLevel-*.js`). */}
          <div className="hidden md:flex items-center gap-1.5 mr-2 text-[10px] font-mono text-ink-400 tabular-nums">
            {health && (
              <>
                <Activity size={11} className="text-forest-500" strokeWidth={1.75} />
                <span>v{health.version}</span>
                <span className="opacity-50">·</span>
                <span className="text-forest-600">{import.meta.env.VITE_BUILD_HASH || 'live'}</span>
              </>
            )}
          </div>

          {/* WS status */}
          <div className="flex items-center gap-1.5 px-2 h-7 rounded-md hover:bg-ivory-200/60">
            {error ? (
              <>
                <WifiOff size={12} className="text-brick-500" />
                <span className="text-[11px] font-medium text-brick-500">Offline</span>
              </>
            ) : (
              <>
                <Wifi size={12} className="text-forest-500" />
                <span className="ws-dot bg-forest-500 animate-pulse-dot" />
                <span className="text-[11px] font-medium text-forest-600">Connected</span>
              </>
            )}
          </div>

          {/* Notification bell */}
          <div className="relative">
            <button
              onClick={toggleNotificationPanel}
              aria-label={notificationPanelOpen ? 'Close notifications' : `Open notifications${unreadCount > 0 ? `, ${unreadCount} unread` : ''}`}
              aria-expanded={notificationPanelOpen}
              aria-haspopup="true"
              className={`relative p-1.5 rounded-md transition-colors ${
                notificationPanelOpen
                  ? 'text-ink-700 bg-ivory-200'
                  : 'text-ink-400 hover:text-ink-600 hover:bg-ivory-200'
              }`}
              title="Notifications"
            >
              <Bell size={14} />
              {unreadCount > 0 && (
                <span className="absolute -top-0.5 -right-0.5 min-w-[14px] h-3.5 flex items-center justify-center px-1 text-[9px] font-bold text-white bg-brick-400 rounded-full">
                  {unreadCount > 99 ? '99+' : unreadCount}
                </span>
              )}
            </button>
            <NotificationPanel />
          </div>

          <button
            onClick={toggleCompact}
            className={`p-1.5 rounded-md transition-colors ${compactMode ? 'text-ink-700 bg-ivory-200' : 'text-ink-400 hover:text-ink-600 hover:bg-ivory-200'}`}
            title={compactMode ? 'Normal mode' : 'Compact mode'}
          >
            <Columns size={14} />
          </button>

          {onShowShortcuts && (
            <button
              onClick={onShowShortcuts}
              className="p-1.5 rounded-md text-ink-400 hover:text-ink-600 hover:bg-ivory-200 transition-colors"
              title="Keyboard shortcuts"
            >
              <Keyboard size={14} />
            </button>
          )}

          <button
            onClick={handleLogout}
            aria-label="Logout"
            className="p-1.5 rounded-md text-ink-400 hover:text-brick-500 hover:bg-brick-50 transition-colors"
            title="Logout"
          >
            <LogOut size={14} />
          </button>
        </div>
      </div>
    </header>
  )
}