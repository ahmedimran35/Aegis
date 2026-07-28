import { useEffect, useRef } from 'react'
import { useAppStore } from '../store'
import { useWebSocket } from './useWebSocket'

export function useNotifications() {
  const { lastEvent } = useWebSocket()
  const addNotification = useAppStore((s) => s.addNotification)
  const lastTsRef = useRef<string>('')

  useEffect(() => {
    if (!lastEvent) return
    // Only process threat and blocked events
    if (lastEvent.event !== 'threat' && lastEvent.event !== 'blocked') return
    // Deduplicate by timestamp
    if (lastEvent.timestamp === lastTsRef.current) return
    lastTsRef.current = lastEvent.timestamp

    const data = lastEvent.data || {}
    const path = typeof data.path === 'string' ? data.path : undefined
    const clientIp = typeof data.client_ip === 'string' ? data.client_ip : undefined
    const method = typeof data.method === 'string' ? data.method : undefined
    const classification = typeof data.ai_classification === 'string' ? data.ai_classification : undefined
    const threatScore = typeof data.threat_score === 'number' ? data.threat_score : undefined

    const message = lastEvent.event === 'threat'
      ? `Threat detected${path ? ` on ${path}` : ''}`
      : `Request blocked${path ? ` — ${method || ''} ${path}` : ''}`

    addNotification({
      id: `${lastEvent.timestamp}-${lastEvent.event}-${Math.random().toString(36).slice(2, 6)}`,
      type: lastEvent.event as 'threat' | 'blocked',
      message,
      timestamp: lastEvent.timestamp,
      read: false,
      path,
      client_ip: clientIp,
      threat_score: threatScore,
      classification,
    })
  }, [lastEvent, addNotification])
}
