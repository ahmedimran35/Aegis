/**
 * Pulse — small live indicator that animates to convey activity.
 * Used in StatCard headers, hero metric strips, and status badges.
 *
 * Variants:
 *   - live: green pulse, indicates healthy streaming data
 *   - alert: brick-red pulse, indicates degraded or under-attack state
 *   - idle: ink-grey pulse (faded), indicates data is paused
 *   - warn: burnt-amber pulse, indicates elevated risk
 *
 * Sizes map to Tailwind text sizes so the dot scales with surrounding type.
 */
type PulseVariant = 'live' | 'alert' | 'idle' | 'warn'
type PulseSize = 'sm' | 'md' | 'lg'

const variantClass: Record<PulseVariant, string> = {
  live: 'bg-forest-500',
  alert: 'bg-brick-500',
  idle: 'bg-ink-300',
  warn: 'bg-burnt-500',
}

const ringClass: Record<PulseVariant, string> = {
  live: 'bg-forest-500/30',
  alert: 'bg-brick-500/30',
  idle: 'bg-ink-300/30',
  warn: 'bg-burnt-500/30',
}

const sizeMap: Record<PulseSize, { dot: string; ring: string; ringSize: string }> = {
  sm: { dot: 'w-1.5 h-1.5', ring: 'w-3 h-3', ringSize: 'h-3 w-3' },
  md: { dot: 'w-2 h-2', ring: 'w-4 h-4', ringSize: 'h-4 w-4' },
  lg: { dot: 'w-2.5 h-2.5', ring: 'w-5 h-5', ringSize: 'h-5 w-5' },
}

interface PulseProps {
  variant?: PulseVariant
  size?: PulseSize
  label?: string
  ariaLabel?: string
}

export default function Pulse({ variant = 'live', size = 'sm', label, ariaLabel }: PulseProps) {
  const s = sizeMap[size]
  const dot = variantClass[variant]
  const ring = ringClass[variant]
  return (
    <span
      className="inline-flex items-center gap-1.5"
      role={ariaLabel ? 'status' : undefined}
      aria-label={ariaLabel}
    >
      <span className="relative inline-flex items-center justify-center" aria-hidden="true">
        <span
          className={`absolute ${s.ringSize} rounded-full ${ring} animate-ping opacity-75`}
          style={{ animationDuration: variant === 'idle' ? '3s' : '1.6s' }}
        />
        <span className={`relative ${s.dot} rounded-full ${dot}`} />
      </span>
      {label && (
        <span className="text-[10px] font-semibold uppercase tracking-[0.08em] text-ink-500">
          {label}
        </span>
      )}
    </span>
  )
}