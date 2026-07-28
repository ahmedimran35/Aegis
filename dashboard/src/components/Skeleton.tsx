export function SkeletonLine({ width = 'w-full', className = '' }: { width?: string; className?: string }) {
  return <div className={`h-4 bg-ivory-200 rounded animate-pulse ${width} ${className}`} />
}

export function SkeletonCard({ className = '' }: { className?: string }) {
  return (
    <div className={`card p-5 space-y-3 ${className}`}>
      <div className="flex items-start justify-between">
        <SkeletonLine width="w-20" className="h-3" />
        <div className="w-10 h-10 bg-ivory-200 rounded-xl animate-pulse" />
      </div>
      <SkeletonLine width="w-24" className="h-7" />
      <SkeletonLine width="w-16" className="h-3" />
    </div>
  )
}

export function SkeletonStatCard() {
  return (
    <div className="card p-5 space-y-3">
      <div className="flex items-start justify-between">
        <SkeletonLine width="w-16" className="h-2.5" />
        <div className="w-10 h-10 bg-ivory-200 rounded-xl animate-pulse" />
      </div>
      <SkeletonLine width="w-20" className="h-8" />
      <SkeletonLine width="w-24" className="h-3" />
    </div>
  )
}

export function SkeletonTable({ rows = 5, cols = 5 }: { rows?: number; cols?: number }) {
  return (
    <div className="overflow-x-auto rounded-xl border border-ivory-300 bg-white">
      <table className="w-full">
        <thead>
          <tr>
            {Array.from({ length: cols }).map((_, i) => (
              <th key={i} className="table-header">
                <SkeletonLine width="w-16" className="h-3" />
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {Array.from({ length: rows }).map((_, r) => (
            <tr key={r}>
              {Array.from({ length: cols }).map((_, c) => (
                <td key={c} className="table-cell">
                  <SkeletonLine width={c === 0 ? 'w-24' : 'w-16'} className="h-3" />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function SkeletonChart({ height = 'h-[260px]', className = '' }: { height?: string; className?: string }) {
  return (
    <div className={`${height} bg-ivory-100 rounded-lg animate-pulse flex items-end gap-1 p-4 ${className}`}>
      {Array.from({ length: 12 }).map((_, i) => (
        <div
          key={i}
          className="flex-1 bg-ivory-200 rounded-t animate-pulse"
          style={{ height: `${20 + ((i * 17 + 7) % 60)}%` }}
        />
      ))}
    </div>
  )
}
