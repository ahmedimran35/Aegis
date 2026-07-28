import { useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { ShieldAlert, ShieldBan, CheckCheck, Bell, ExternalLink } from 'lucide-react'
import { useAppStore } from '../store'
import type { Notification } from '../store'

function timeAgo(ts: string): string {
  const diff = Date.now() - new Date(ts).getTime()
  const secs = Math.floor(diff / 1000)
  if (secs < 60) return 'just now'
  const mins = Math.floor(secs / 60)
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

function NotificationItem({ n, onClick }: { n: Notification; onClick: () => void }) {
  const isThreat = n.type === 'threat'
  return (
    <button
      onClick={onClick}
      className={`w-full flex items-start gap-3 px-4 py-3 text-left transition-colors hover:bg-ivory-50 ${
        !n.read ? 'bg-accent-50/40' : ''
      }`}
    >
      <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 mt-0.5 ${
        isThreat ? 'bg-red-100' : 'bg-orange-100'
      }`}>
        {isThreat
          ? <ShieldAlert size={14} className="text-red-600" />
          : <ShieldBan size={14} className="text-orange-600" />
        }
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className={`text-[10px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded ${
            isThreat ? 'bg-red-100 text-red-700' : 'bg-orange-100 text-orange-700'
          }`}>
            {n.type}
          </span>
          {!n.read && <span className="w-1.5 h-1.5 rounded-full bg-accent-500 shrink-0" />}
          <span className="text-[10px] text-slate-400 ml-auto shrink-0">{timeAgo(n.timestamp)}</span>
        </div>
        <p className="text-xs text-slate-700 mt-1 truncate font-medium">{n.message}</p>
        {(n.path || n.client_ip) && (
          <p className="text-[11px] text-slate-500 mt-0.5 font-mono truncate">
            {n.path && <span>{n.path}</span>}
            {n.client_ip && <span className="text-slate-400"> from {n.client_ip}</span>}
          </p>
        )}
      </div>
    </button>
  )
}

export default function NotificationPanel() {
  const open = useAppStore((s) => s.notificationPanelOpen)
  const notifications = useAppStore((s) => s.notifications)
  const markAllRead = useAppStore((s) => s.markAllRead)
  const close = useAppStore((s) => s.closeNotificationPanel)
  const clearNotifications = useAppStore((s) => s.clearNotifications)
  const navigate = useNavigate()
  const panelRef = useRef<HTMLDivElement>(null)

  const unreadCount = notifications.filter((n) => !n.read).length

  // Close on outside click
  useEffect(() => {
    if (!open) return
    const handler = (e: MouseEvent) => {
      if (panelRef.current && !panelRef.current.contains(e.target as Node)) {
        close()
      }
    }
    // Delay to avoid closing from the bell button click
    setTimeout(() => document.addEventListener('mousedown', handler), 0)
    return () => document.removeEventListener('mousedown', handler)
  }, [open, close])

  // Close on Escape
  useEffect(() => {
    if (!open) return
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') close()
    }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [open, close])

  if (!open) return null

  const handleClick = (n: Notification) => {
    // Mark this notification as read
    useAppStore.setState((s) => ({
      notifications: s.notifications.map((item) =>
        item.id === n.id ? { ...item, read: true } : item
      ),
    }))
    close()
    navigate('/threats')
  }

  return (
    <div
      ref={panelRef}
      className="absolute top-full right-0 mt-2 w-[400px] bg-white rounded-xl shadow-2xl shadow-slate-900/15 border border-ivory-200 overflow-hidden z-[60]"
      style={{ animation: 'slide-up 0.15s ease-out' }}
    >
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-ivory-200 bg-ivory-50/50">
        <div className="flex items-center gap-2">
          <Bell size={15} className="text-slate-600" />
          <span className="text-sm font-semibold text-slate-800">Notifications</span>
          {unreadCount > 0 && (
            <span className="px-1.5 py-0.5 text-[10px] font-bold text-white bg-accent-600 rounded-full min-w-[18px] text-center">
              {unreadCount}
            </span>
          )}
        </div>
        <div className="flex items-center gap-1">
          {unreadCount > 0 && (
            <button
              onClick={markAllRead}
              className="flex items-center gap-1 px-2 py-1 text-[11px] text-slate-500 hover:text-accent-600 hover:bg-accent-50 rounded-md transition-colors"
              title="Mark all as read"
            >
              <CheckCheck size={12} />
              Read all
            </button>
          )}
          {notifications.length > 0 && (
            <button
              onClick={clearNotifications}
              className="px-2 py-1 text-[11px] text-slate-400 hover:text-red-500 hover:bg-red-50 rounded-md transition-colors"
              title="Clear all"
            >
              Clear
            </button>
          )}
        </div>
      </div>

      {/* Notification list */}
      <div className="max-h-[420px] overflow-y-auto">
        {notifications.length === 0 ? (
          <div className="px-4 py-10 text-center">
            <div className="w-10 h-10 rounded-full bg-ivory-100 flex items-center justify-center mx-auto mb-3">
              <Bell size={18} className="text-slate-300" />
            </div>
            <p className="text-sm text-slate-400 font-medium">No notifications yet</p>
            <p className="text-xs text-slate-300 mt-1">Threats and blocked requests appear here in real-time</p>
          </div>
        ) : (
          <div className="divide-y divide-ivory-100">
            {notifications.map((n) => (
              <NotificationItem key={n.id} n={n} onClick={() => handleClick(n)} />
            ))}
          </div>
        )}
      </div>

      {/* Footer */}
      {notifications.length > 0 && (
        <div className="px-4 py-2.5 border-t border-ivory-200 bg-ivory-50/50">
          <button
            onClick={() => { close(); navigate('/threats') }}
            className="w-full flex items-center justify-center gap-1.5 text-xs font-medium text-accent-600 hover:text-accent-700 transition-colors"
          >
            View all threats
            <ExternalLink size={11} />
          </button>
        </div>
      )}
    </div>
  )
}
