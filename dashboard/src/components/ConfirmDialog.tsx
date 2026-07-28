import { useEffect, useRef } from 'react'
import { AlertTriangle } from 'lucide-react'
import { useAppStore } from '../store'

interface PendingConfirm {
  message: string
  resolve: (ok: boolean) => void
}

let pending: PendingConfirm | null = null

export function confirmAction(message: string): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    if (pending) pending.resolve(false)
    pending = { message, resolve }
    useAppStore.setState({ confirmOpen: true })
  })
}

export default function ConfirmDialog() {
  const open = useAppStore((s) => s.confirmOpen)
  const setConfirmOpen = useAppStore((s) => s.setConfirmOpen)
  const message = pending?.message ?? ''
  const cancelRef = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    if (!open) pending = null
  }, [open])

  // Esc closes the dialog (resolves false). Cancel button is focused on
  // mount to keep keyboard focus inside the dialog (focus trap light).
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault()
        const p = pending
        pending = null
        setConfirmOpen(false)
        if (p) p.resolve(false)
      }
    }
    document.addEventListener('keydown', onKey)
    cancelRef.current?.focus()
    return () => document.removeEventListener('keydown', onKey)
  }, [open, setConfirmOpen])

  if (!open || !pending) return null

  const handleOk = () => { const p = pending!; pending = null; setConfirmOpen(false); p.resolve(true) }
  const handleCancel = () => { const p = pending!; pending = null; setConfirmOpen(false); p.resolve(false) }

  return (
    <div className="fixed inset-0 z-[70] flex items-center justify-center bg-black/30 backdrop-blur-sm" role="dialog" aria-modal="true" aria-labelledby="confirm-dialog-title" onClick={handleCancel}>
      <div className="w-full max-w-md mx-4 bg-white rounded-2xl shadow-xl border border-ivory-300 p-6 animate-slide-up" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-start gap-3 mb-3">
          <div className="w-9 h-9 rounded-full bg-amber-50 flex items-center justify-center flex-shrink-0">
            <AlertTriangle size={18} className="text-amber-500" />
          </div>
          <div className="flex-1">
            <h2 id="confirm-dialog-title" className="text-base font-semibold text-slate-900 mb-1">Confirm action</h2>
            <p className="text-sm text-slate-600">{message}</p>
          </div>
        </div>
        <div className="flex justify-end gap-3 mt-5">
          <button ref={cancelRef} onClick={handleCancel} className="btn-secondary">Cancel</button>
          <button onClick={handleOk} className="btn-primary bg-red-600 hover:bg-red-700">Confirm</button>
        </div>
      </div>
    </div>
  )
}