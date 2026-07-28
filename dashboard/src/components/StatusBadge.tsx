interface StatusBadgeProps {
  status: 'allowed' | 'blocked' | 'malicious' | 'suspicious' | 'benign' | 'active' | 'inactive' | 'pending' | 'approved' | 'rejected' | 'low' | 'medium' | 'high' | 'critical' | string
  size?: 'sm' | 'md'
}

const styleMap: Record<string, string> = {
  allowed: 'bg-emerald-50 text-emerald-700 ring-emerald-600/20',
  blocked: 'bg-red-50 text-red-700 ring-red-600/20',
  malicious: 'bg-red-50 text-red-700 ring-red-600/20',
  suspicious: 'bg-amber-50 text-amber-700 ring-amber-600/20',
  benign: 'bg-emerald-50 text-emerald-700 ring-emerald-600/20',
  active: 'bg-emerald-50 text-emerald-700 ring-emerald-600/20',
  inactive: 'bg-slate-50 text-slate-600 ring-slate-500/20',
  pending: 'bg-amber-50 text-amber-700 ring-amber-600/20',
  approved: 'bg-emerald-50 text-emerald-700 ring-emerald-600/20',
  rejected: 'bg-red-50 text-red-700 ring-red-600/20',
  low: 'bg-blue-50 text-blue-700 ring-blue-600/20',
  medium: 'bg-amber-50 text-amber-700 ring-amber-600/20',
  high: 'bg-orange-50 text-orange-700 ring-orange-600/20',
  critical: 'bg-red-50 text-red-700 ring-red-600/20',
}

export default function StatusBadge({ status, size = 'sm' }: StatusBadgeProps) {
  const style = styleMap[status] || 'bg-slate-50 text-slate-600 ring-slate-500/20'
  const dotColor = {
    allowed: 'bg-emerald-500',
    blocked: 'bg-red-500',
    malicious: 'bg-red-500',
    suspicious: 'bg-amber-500',
    benign: 'bg-emerald-500',
    active: 'bg-emerald-500',
    inactive: 'bg-slate-400',
    pending: 'bg-amber-500',
    approved: 'bg-emerald-500',
    rejected: 'bg-red-500',
    low: 'bg-blue-500',
    medium: 'bg-amber-500',
    high: 'bg-orange-500',
    critical: 'bg-red-500',
  }[status] || 'bg-slate-400'

  return (
    <span className={`inline-flex items-center gap-1.5 font-medium ring-1 ring-inset rounded-full
      ${size === 'sm' ? 'px-2 py-0.5 text-[11px]' : 'px-2.5 py-1 text-xs'} ${style}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${dotColor}`} />
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  )
}
