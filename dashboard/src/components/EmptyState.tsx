/**
 * EmptyState — uniform empty-state UI for tables, lists, and chart panels.
 *
 * Use:
 *   <EmptyState icon={Shield} title="No threats yet" hint="All clear. Aegis will surface any new attacks here." />
 *   <EmptyState icon={Activity} title="No traffic in window" hint="Adjust the time range or wait for new requests." cta="Refresh" onCta={refetch} />
 */
import { type LucideIcon, Inbox } from 'lucide-react'
import type { ReactNode } from 'react'

interface EmptyStateProps {
  icon?: LucideIcon
  title: string
  hint?: string
  cta?: string
  onCta?: () => void
  children?: ReactNode
}

export default function EmptyState({
  icon: Icon = Inbox,
  title,
  hint,
  cta,
  onCta,
  children,
}: EmptyStateProps) {
  return (
    <div
      className="flex flex-col items-center justify-center text-center px-6 py-10 rounded-lg border border-dashed border-ivory-300 bg-ivory-50/40"
      role="status"
      aria-live="polite"
    >
      <span className="inline-flex items-center justify-center w-10 h-10 rounded-md bg-ivory-100 text-ink-400 mb-3">
        <Icon size={18} strokeWidth={1.5} aria-hidden="true" />
      </span>
      <p className="text-sm font-semibold text-ink-700">{title}</p>
      {hint && (
        <p className="text-xs text-ink-400 mt-1 max-w-sm leading-relaxed">{hint}</p>
      )}
      {cta && onCta && (
        <button
          type="button"
          onClick={onCta}
          className="mt-4 px-3 py-1.5 rounded-md bg-forest-500 text-ivory-50 text-xs font-semibold hover:bg-forest-600 transition-colors duration-150"
        >
          {cta}
        </button>
      )}
      {children}
    </div>
  )
}