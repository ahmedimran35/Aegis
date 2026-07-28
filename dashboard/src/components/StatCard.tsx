import { type LucideIcon } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'

interface StatCardProps {
  label: string
  value: string | number
  icon: LucideIcon
  trend?: { value: number; label: string }
  color?: 'blue' | 'red' | 'amber' | 'emerald' | 'slate' | 'steel' | 'brick' | 'burnt' | 'forest' | 'ink'
  delay?: number
  sparklineData?: number[]
}

const colorMap: Record<NonNullable<StatCardProps['color']>, { bg: string; text: string; icon: string; glow: string; hoverGlow: string; ring: string; gradient: string }> = {
  blue: {
    bg: 'bg-accent-50',
    text: 'text-accent-600',
    icon: 'text-accent-500',
    glow: 'shadow-accent-500/10',
    hoverGlow: 'hover:shadow-accent-500/20',
    ring: 'ring-accent-500/10',
    gradient: 'from-accent-500 to-blue-400',
  },
  red: {
    bg: 'bg-red-50',
    text: 'text-red-600',
    icon: 'text-red-500',
    glow: 'shadow-red-500/10',
    hoverGlow: 'hover:shadow-red-500/20',
    ring: 'ring-red-500/10',
    gradient: 'from-red-500 to-rose-400',
  },
  amber: {
    bg: 'bg-amber-50',
    text: 'text-amber-600',
    icon: 'text-amber-500',
    glow: 'shadow-amber-500/10',
    hoverGlow: 'hover:shadow-amber-500/20',
    ring: 'ring-amber-500/10',
    gradient: 'from-amber-500 to-yellow-400',
  },
  emerald: {
    bg: 'bg-emerald-50',
    text: 'text-emerald-600',
    icon: 'text-emerald-500',
    glow: 'shadow-emerald-500/10',
    hoverGlow: 'hover:shadow-emerald-500/20',
    ring: 'ring-emerald-500/10',
    gradient: 'from-emerald-500 to-green-400',
  },
  slate: {
    bg: 'bg-slate-50',
    text: 'text-slate-600',
    icon: 'text-slate-500',
    glow: 'shadow-slate-500/10',
    hoverGlow: 'hover:shadow-slate-500/20',
    ring: 'ring-slate-500/10',
    gradient: 'from-slate-500 to-slate-400',
  },
  steel: {
    bg: 'bg-steel-50',
    text: 'text-steel-600',
    icon: 'text-steel-500',
    glow: 'shadow-steel-500/10',
    hoverGlow: 'hover:shadow-steel-500/20',
    ring: 'ring-steel-500/10',
    gradient: 'from-steel-500 to-steel-400',
  },
  brick: {
    bg: 'bg-brick-50',
    text: 'text-brick-600',
    icon: 'text-brick-500',
    glow: 'shadow-brick-500/10',
    hoverGlow: 'hover:shadow-brick-500/20',
    ring: 'ring-brick-500/10',
    gradient: 'from-brick-500 to-brick-400',
  },
  burnt: {
    bg: 'bg-burnt-50',
    text: 'text-burnt-600',
    icon: 'text-burnt-500',
    glow: 'shadow-burnt-500/10',
    hoverGlow: 'hover:shadow-burnt-500/20',
    ring: 'ring-burnt-500/10',
    gradient: 'from-burnt-500 to-burnt-400',
  },
  forest: {
    bg: 'bg-forest-50',
    text: 'text-forest-600',
    icon: 'text-forest-500',
    glow: 'shadow-forest-500/10',
    hoverGlow: 'hover:shadow-forest-500/20',
    ring: 'ring-forest-500/10',
    gradient: 'from-forest-500 to-forest-400',
  },
  ink: {
    bg: 'bg-ink-50',
    text: 'text-ink-600',
    icon: 'text-ink-500',
    glow: 'shadow-ink-500/10',
    hoverGlow: 'hover:shadow-ink-500/20',
    ring: 'ring-ink-500/10',
    gradient: 'from-ink-500 to-ink-400',
  },
}

function MiniSparkline({ data, color }: { data: number[]; color: string }) {
  if (!data || data.length < 2) return null
  const max = Math.max(...data)
  const min = Math.min(...data)
  const range = max - min || 1
  const w = 48
  const h = 20
  const points = data.map((v, i) => {
    const x = (i / (data.length - 1)) * w
    const y = h - ((v - min) / range) * h
    return `${x},${y}`
  }).join(' ')
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} className="opacity-60">
      <polyline
        points={points}
        fill="none"
        stroke={color}
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}

const sparklineColors: Record<NonNullable<StatCardProps['color']>, string> = {
  blue: '#3B82F6',
  red: '#EF4444',
  amber: '#F59E0B',
  emerald: '#10B981',
  slate: '#64748B',
  steel: '#475569',
  brick: '#B91C1C',
  burnt: '#C2410C',
  forest: '#166534',
  ink: '#1E293B',
}

export default function StatCard({ label, value, icon: Icon, trend, color = 'blue', delay = 0, sparklineData }: StatCardProps) {
  const c = colorMap[color]
  const [isVisible, setIsVisible] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const timer = setTimeout(() => setIsVisible(true), delay)
    return () => clearTimeout(timer)
  }, [delay])

  return (
    <div
      ref={ref}
      className={`
        relative overflow-hidden rounded-xl border border-ivory-300/80 bg-white p-5
        transition-all duration-300 ease-out
        hover:shadow-xl ${c.hoverGlow} hover:-translate-y-1 hover:border-ivory-300
        group cursor-default backdrop-blur-sm
        ${isVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'}
      `}
      style={{ transitionDelay: `${delay}ms` }}
    >
      {/* Background gradient orb */}
      <div className={`absolute -top-8 -right-8 w-24 h-24 rounded-full bg-gradient-to-br ${c.gradient} opacity-[0.06] blur-xl group-hover:opacity-[0.12] group-hover:scale-150 transition-all duration-500`} />

      {/* Subtle gradient overlay on hover */}
      <div className={`absolute inset-0 bg-gradient-to-br ${c.gradient} opacity-0 group-hover:opacity-[0.02] transition-opacity duration-300`} />

      {/* Shimmer on hover */}
      <div className="absolute inset-0 -translate-x-full group-hover:translate-x-full transition-transform duration-1000 ease-out bg-gradient-to-r from-transparent via-white/30 to-transparent pointer-events-none" />

      <div className="relative flex items-start justify-between mb-3">
        <span className="text-[10px] font-semibold uppercase tracking-widest text-slate-400">{label}</span>
        <div className={`flex items-center justify-center w-10 h-10 rounded-xl ${c.bg} transition-all duration-300 group-hover:scale-110 group-hover:shadow-md ${c.glow}`}>
          <Icon size={18} className={`${c.icon} transition-transform duration-300 group-hover:rotate-6`} strokeWidth={1.8} />
        </div>
      </div>

      <div className="relative flex items-end justify-between">
        <div className="font-mono text-2xl font-bold tracking-tight text-slate-900 number-reveal">
          {value}
        </div>
        {sparklineData && sparklineData.length > 1 && (
          <MiniSparkline data={sparklineData} color={sparklineColors[color]} />
        )}
      </div>

      {trend && (
        <div className="mt-2.5 flex items-center gap-1.5">
          <span className={`
            inline-flex items-center gap-0.5 text-[10px] font-bold px-2 py-0.5 rounded-full
            ${trend.value >= 0 ? 'bg-emerald-50 text-emerald-600 ring-1 ring-emerald-500/10' : 'bg-red-50 text-red-500 ring-1 ring-red-500/10'}
          `}>
            {trend.value >= 0 ? (
              <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 10l7-7m0 0l7 7m-7-7v18" /></svg>
            ) : (
              <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M19 14l-7 7m0 0l-7-7m7 7V3" /></svg>
            )}
            {Math.abs(trend.value)}%
          </span>
          <span className="text-[10px] text-slate-400 font-medium">{trend.label}</span>
        </div>
      )}

      {/* Bottom accent line */}
      <div className={`absolute bottom-0 left-0 right-0 h-0.5 bg-gradient-to-r ${c.gradient} opacity-0 group-hover:opacity-100 transition-opacity duration-300`} />
    </div>
  )
}
