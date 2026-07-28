import { useWebSocket } from '../hooks/useWebSocket'
import { Activity, AlertTriangle, Shield, Wifi, WifiOff, Zap } from 'lucide-react'

interface FeedEvent {
  event: string
  data: Record<string, unknown>
  timestamp: string
}

function getEventIcon(type: string) {
  switch (type) {
    case 'threat': return <AlertTriangle size={12} className="text-red-500" />
    case 'blocked': return <Shield size={12} className="text-orange-500" />
    case 'request': return <Activity size={12} className="text-blue-500" />
    default: return <Activity size={12} className="text-slate-400" />
  }
}

function getEventStyles(type: string) {
  switch (type) {
    case 'threat': return {
      border: 'border-l-red-500',
      bg: 'bg-red-50/60',
      badge: 'bg-red-100 text-red-700',
      dot: 'bg-red-500',
    }
    case 'blocked': return {
      border: 'border-l-orange-500',
      bg: 'bg-orange-50/60',
      badge: 'bg-orange-100 text-orange-700',
      dot: 'bg-orange-500',
    }
    case 'request': return {
      border: 'border-l-blue-500',
      bg: 'bg-blue-50/40',
      badge: 'bg-blue-100 text-blue-700',
      dot: 'bg-blue-500',
    }
    default: return {
      border: 'border-l-slate-300',
      bg: 'bg-slate-50/60',
      badge: 'bg-slate-100 text-slate-600',
      dot: 'bg-slate-400',
    }
  }
}

export default function LiveFeed() {
  const { connected, events } = useWebSocket()

  return (
    <div className="card-glow p-5 relative overflow-hidden">
      {/* Top gradient accent */}
      <div className="absolute top-0 left-0 w-full h-0.5 bg-gradient-to-r from-accent-500/40 via-emerald-500/30 to-transparent" />

      {/* Corner glow */}
      <div className="absolute top-0 right-0 w-20 h-20 bg-gradient-to-bl from-accent-500/5 to-transparent rounded-bl-full pointer-events-none" />

      <div className="flex items-center justify-between mb-4 relative">
        <h2 className="text-sm font-semibold text-slate-700 flex items-center gap-2">
          <div className="w-6 h-6 rounded-lg bg-accent-50 flex items-center justify-center">
            <Zap size={13} className="text-accent-500" />
          </div>
          Live Feed
        </h2>
        <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border transition-all duration-300 ${connected ? 'bg-emerald-50/80 border-emerald-200 shadow-sm shadow-emerald-500/5' : 'bg-red-50/80 border-red-200'}`}>
          <div className={`w-1.5 h-1.5 rounded-full ${connected ? 'bg-emerald-500 animate-pulse' : 'bg-red-500'}`} />
          {connected ? <Wifi size={11} className="text-emerald-600" /> : <WifiOff size={11} className="text-red-500" />}
          <span className={`text-[10px] font-semibold ${connected ? 'text-emerald-700' : 'text-red-600'}`}>
            {connected ? 'Connected' : 'Disconnected'}
          </span>
        </div>
      </div>

      <div className="space-y-1.5 max-h-72 overflow-y-auto relative scrollbar-thin">
        {events.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-10 text-center">
            <div className={`w-10 h-10 rounded-full flex items-center justify-center mb-3 ${connected ? 'bg-accent-50' : 'bg-slate-100'}`}>
              <Activity size={18} className={connected ? 'text-accent-400 animate-pulse' : 'text-slate-300'} />
            </div>
            <p className="text-xs text-slate-400 font-medium">
              {connected ? 'Waiting for events...' : 'Connecting...'}
            </p>
            <p className="text-[10px] text-slate-300 mt-1">
              {connected ? 'Events will appear here in real-time' : 'Establishing WebSocket connection'}
            </p>
          </div>
        ) : (
          events.map((e: FeedEvent, i: number) => {
            const styles = getEventStyles(e.event)
            return (
              <div
                key={`${e.timestamp}-${e.event}-${i}`}
                className={`border-l-2 ${styles.border} ${styles.bg} pl-3 py-2 rounded-r-lg transition-all duration-200 hover:translate-x-0.5 group/event`}
              >
                <div className="flex items-center gap-2">
                  <div className={`w-1.5 h-1.5 rounded-full ${styles.dot} shrink-0`} />
                  {getEventIcon(e.event)}
                  <span className={`text-[10px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded ${styles.badge}`}>
                    {e.event}
                  </span>
                  <span className="text-[10px] text-slate-400 ml-auto font-mono tabular-nums">
                    {new Date(e.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                  </span>
                </div>
                {e.data?.path != null && (
                  <p className="text-[11px] text-slate-600 mt-1.5 font-mono truncate" title={`${String(e.data.method ?? '')} ${String(e.data.path ?? '')}`}>
                    <span className="text-slate-400">{String(e.data.method ?? '')}</span>{' '}
                    <span className="font-medium">{String(e.data.path ?? '')}</span>
                    {e.data.client_ip != null && (
                      <span className="text-slate-400 ml-1">from {String(e.data.client_ip)}</span>
                    )}
                  </p>
                )}
              </div>
            )
          })
        )}
      </div>

      {/* Event count */}
      {events.length > 0 && (
        <div className="mt-3 pt-3 border-t border-ivory-200 flex items-center justify-between">
          <span className="text-[10px] text-slate-400 font-medium">{events.length} events captured</span>
          <div className="flex items-center gap-1">
            <div className="w-1 h-1 rounded-full bg-emerald-500 animate-pulse" />
            <span className="text-[10px] text-slate-400">streaming</span>
          </div>
        </div>
      )}
    </div>
  )
}
