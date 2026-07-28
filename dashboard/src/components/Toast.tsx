import { useToast } from '../hooks/useToast'
import { CheckCircle, XCircle, AlertTriangle, Info, X } from 'lucide-react'

const icons = {
  success: CheckCircle,
  error: XCircle,
  warning: AlertTriangle,
  info: Info,
}

const colors = {
  success: 'bg-emerald-50 border-emerald-200 text-emerald-800',
  error: 'bg-red-50 border-red-200 text-red-800',
  warning: 'bg-amber-50 border-amber-200 text-amber-800',
  info: 'bg-blue-50 border-blue-200 text-blue-800',
}

const iconColors = {
  success: 'text-emerald-500',
  error: 'text-red-500',
  warning: 'text-amber-500',
  info: 'text-blue-500',
}

export default function ToastContainer() {
  const toasts = useToast((s) => s.toasts)
  const removeToast = useToast((s) => s.removeToast)

  if (toasts.length === 0) return null

  return (
    <div className="fixed top-4 right-4 z-[100] flex flex-col gap-2 w-80">
      {toasts.map((t) => {
        const Icon = icons[t.type]
        return (
          <div
            key={t.id}
            role="alert"
            className={`flex items-start gap-3 px-4 py-3 rounded-lg border shadow-lg animate-slide-up ${colors[t.type]}`}
          >
            <Icon size={16} className={`mt-0.5 shrink-0 ${iconColors[t.type]}`} />
            <span className="text-sm flex-1">{t.message}</span>
            <button onClick={() => removeToast(t.id)} aria-label="Close notification" className="shrink-0 opacity-60 hover:opacity-100">
              <X size={14} />
            </button>
          </div>
        )
      })}
    </div>
  )
}
