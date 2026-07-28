import { X } from 'lucide-react'

const shortcuts = [
  { keys: '/', desc: 'Focus search input' },
  { keys: 'Esc', desc: 'Close modal / cancel' },
  { keys: '?', desc: 'Show keyboard shortcuts' },
  { keys: 'g o', desc: 'Go to Overview' },
  { keys: 'g t', desc: 'Go to Traffic' },
  { keys: 'g h', desc: 'Go to Threats' },
  { keys: 'g r', desc: 'Go to Rules' },
  { keys: 'g l', desc: 'Go to Logs' },
  { keys: 'g s', desc: 'Go to Settings' },
]

interface Props {
  open: boolean
  onClose: () => void
}

export default function KeyboardHelp({ open, onClose }: Props) {
  if (!open) return null

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/30 backdrop-blur-sm" onClick={onClose}>
      <div role="dialog" aria-modal="true" aria-label="Keyboard shortcuts" className="w-full max-w-sm mx-4 bg-white rounded-2xl shadow-xl border border-ivory-300 p-6 animate-scale-in" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-slate-900">Keyboard Shortcuts</h2>
          <button onClick={onClose} aria-label="Close" className="p-1 rounded text-slate-400 hover:text-slate-600">
            <X size={18} />
          </button>
        </div>
        <div className="space-y-2">
          {shortcuts.map((s) => (
            <div key={s.keys} className="flex items-center justify-between py-1.5">
              <span className="text-sm text-slate-600">{s.desc}</span>
              <kbd className="px-2 py-0.5 text-xs font-mono font-medium text-slate-500 bg-ivory-100 border border-ivory-300 rounded">
                {s.keys}
              </kbd>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
