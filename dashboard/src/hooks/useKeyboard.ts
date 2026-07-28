import { useEffect, useCallback, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'

export function useKeyboard() {
  const navigate = useNavigate()
  const [showHelp, setShowHelp] = useState(false)
  const pendingG = useRef(false)
  const pendingTimeout = useRef<ReturnType<typeof setTimeout>>()

  const handleKey = useCallback((e: KeyboardEvent) => {
    const target = e.target as HTMLElement
    const tag = target.tagName
    const isInput = tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || target.isContentEditable

    // Escape — always works
    if (e.key === 'Escape') {
      setShowHelp(false)
      return
    }

    // Don't capture when typing in inputs
    if (isInput) return

    // ? — toggle help
    if (e.key === '?' || (e.shiftKey && e.key === '/')) {
      e.preventDefault()
      setShowHelp((v) => !v)
      return
    }

    // / — focus search
    if (e.key === '/') {
      e.preventDefault()
      const searchInput = document.querySelector<HTMLInputElement>('input[type="text"][placeholder*="earch"], input[type="text"][placeholder*="ilter"]')
      if (searchInput) searchInput.focus()
      return
    }

    // g + key — go-to navigation
    if (pendingG.current) {
      pendingG.current = false
      if (pendingTimeout.current) clearTimeout(pendingTimeout.current)
      const routes: Record<string, string> = {
        o: '/overview',
        t: '/traffic',
        h: '/threats',
        r: '/rules',
        l: '/logs',
        s: '/settings',
      }
      const route = routes[e.key]
      if (route) navigate(route)
      return
    }

    if (e.key === 'g') {
      pendingG.current = true
      pendingTimeout.current = setTimeout(() => { pendingG.current = false }, 800)
    }
  }, [navigate])

  useEffect(() => {
    document.addEventListener('keydown', handleKey)
    return () => document.removeEventListener('keydown', handleKey)
  }, [handleKey])

  return { showHelp, setShowHelp }
}
