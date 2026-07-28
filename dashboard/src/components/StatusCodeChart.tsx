interface StatusCode {
  code: number
  count: number
}

interface Props {
  data: StatusCode[]
}

function getStatusColor(code: number): string {
  if (code >= 200 && code < 300) return '#10B981'
  if (code >= 300 && code < 400) return '#3B82F6'
  if (code >= 400 && code < 500) return '#F59E0B'
  if (code >= 500) return '#EF4444'
  return '#94A3B8'
}

function getStatusLabel(code: number): string {
  if (code === 200) return '200 OK'
  if (code === 301) return '301 Redirect'
  if (code === 304) return '304 Not Modified'
  if (code === 400) return '400 Bad Request'
  if (code === 401) return '401 Unauthorized'
  if (code === 403) return '403 Forbidden'
  if (code === 404) return '404 Not Found'
  if (code === 500) return '500 Server Error'
  if (code === 502) return '502 Bad Gateway'
  if (code === 503) return '503 Unavailable'
  return `${code}`
}

export default function StatusCodeChart({ data }: Props) {
  const total = data.reduce((s, d) => s + d.count, 0)
  const maxCount = Math.max(...data.map(d => d.count), 1)

  return (
    <div className="space-y-2.5">
      {data.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-8 text-center">
          <div className="w-10 h-10 rounded-full bg-slate-100 flex items-center justify-center mb-3">
            <span className="text-lg font-bold text-slate-300">--</span>
          </div>
          <p className="text-xs text-slate-400 font-medium">No data yet</p>
          <p className="text-[10px] text-slate-300 mt-1">Status codes will appear here</p>
        </div>
      ) : (
        data.slice(0, 8).map((d) => {
          const pct = total > 0 ? ((d.count / total) * 100).toFixed(1) : '0.0'
          const barPct = (d.count / maxCount) * 100
          const color = getStatusColor(d.code)
          return (
            <div key={d.code} className="group p-2 rounded-lg hover:bg-ivory-50/60 transition-colors duration-200">
              <div className="flex items-center justify-between mb-1">
                <div className="flex items-center gap-2">
                  <span
                    className="text-xs font-mono font-bold px-2 py-0.5 rounded-md"
                    style={{ color, backgroundColor: color + '15', boxShadow: `0 0 0 1px ${color}10` }}
                  >
                    {d.code}
                  </span>
                  <span className="text-[11px] text-slate-500 font-medium">{getStatusLabel(d.code)}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] text-slate-400 font-mono tabular-nums">{pct}%</span>
                  <span className="text-xs font-bold text-slate-700 tabular-nums">{d.count.toLocaleString()}</span>
                </div>
              </div>
              <div className="h-2 bg-ivory-100 rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-500 relative overflow-hidden"
                  style={{ width: `${barPct}%`, backgroundColor: color }}
                >
                  <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent animate-shimmer" />
                </div>
              </div>
            </div>
          )
        })
      )}
      {data.length > 8 && (
        <p className="text-xs text-slate-400 mt-2 text-center">+{data.length - 8} more</p>
      )}
    </div>
  )
}
