import { useEffect, useRef } from 'react'

interface Props {
  open: boolean
  onClose: () => void
  children: React.ReactNode
  labelledBy?: string
  className?: string
  initialFocus?: 'first' | 'cancel' | 'none'
}

export default function EscModal({ open, onClose, children, labelledBy, className = '', initialFocus = 'first' }: Props) {
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { e.stopPropagation(); onClose() }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [open, onClose])

  useEffect(() => {
    if (!open || initialFocus === 'none') return
    const el = ref.current
    if (!el) return
    let target: HTMLElement | null = null
    if (initialFocus === 'cancel') {
      target = el.querySelector<HTMLElement>('[data-autofocus]') || null
    } else {
      const focusables = el.querySelectorAll<HTMLElement>(
        'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
      )
      target = focusables[0] || null
    }
    target?.focus()
  }, [open, initialFocus])

  if (!open) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/30 backdrop-blur-sm" onClick={onClose}>
      <div ref={ref} role="dialog" aria-modal="true" aria-labelledby={labelledBy} className={className} onClick={(e) => e.stopPropagation()}>
        {children}
      </div>
    </div>
  )
}
