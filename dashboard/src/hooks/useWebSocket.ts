import { useState, useEffect, useRef, useCallback } from 'react'

// P-FIX (L-1): the auth check no longer depends on a client-side
// localStorage flag (which any script on the page could set). The
// server enforces auth via the HttpOnly cookie on the WS upgrade
// request; if the session is invalid the connection simply never
// upgrades. We no longer gate connect() on a getToken() call.

interface WSEvent {
  event: string
  data: Record<string, unknown>
  timestamp: string
}

export function useWebSocket(path: string = '/api/v1/ws') {
  const [connected, setConnected] = useState(false)
  const [events, setEvents] = useState<WSEvent[]>([])
  const [lastEvent, setLastEvent] = useState<WSEvent | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimeout = useRef<ReturnType<typeof setTimeout>>()
  const mountedRef = useRef(true)

  const connect = useCallback(() => {
    if (!mountedRef.current) return

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const url = `${protocol}//${window.location.host}${path}`

    const ws = new WebSocket(url)
    wsRef.current = ws

    ws.onopen = () => {
      if (!mountedRef.current) { ws.close(); return }
      setConnected(true)
    }

    ws.onmessage = (event) => {
      try {
        const data: WSEvent = JSON.parse(event.data)
        setLastEvent(data)
        setEvents(prev => [data, ...prev].slice(0, 100))
      } catch { /* ignore non-JSON */ }
    }

    ws.onclose = () => {
      setConnected(false)
      if (mountedRef.current) {
        reconnectTimeout.current = setTimeout(connect, 3000)
      }
    }

    ws.onerror = () => ws.close()
  }, [path])

  useEffect(() => {
    mountedRef.current = true
    connect()
    return () => {
      mountedRef.current = false
      if (reconnectTimeout.current) clearTimeout(reconnectTimeout.current)
      wsRef.current?.close()
    }
  }, [connect])

  return { connected, events, lastEvent }
}
