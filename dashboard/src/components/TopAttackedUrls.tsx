import { ExternalLink } from 'lucide-react'

interface AttackedUrl {
  path: string
  count: number
  blocked: number
}

interface Props {
  data: AttackedUrl[]
}

export default function TopAttackedUrls({ data }: Props) {
  const maxCount = Math.max(...data.map(d => d.count), 1)

  return (
    <div className="space-y-2.5">
      {data.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-8 text-center">
          <div className="w-10 h-10 rounded-full bg-emerald-50 flex items-center justify-center mb-3">
            <ExternalLink size={18} className="text-emerald-400" />
          </div>
          <p className="text-xs text-slate-400 font-medium">No attacks recorded today</p>
          <p className="text-[10px] text-slate-300 mt-1">All endpoints are secure</p>
        </div>
      ) : (
        data.slice(0, 8).map((d, i) => {
          const pct = (d.count / maxCount) * 100
          const blockRate = d.count > 0 ? (d.blocked / d.count) * 100 : 0
          const displayPath = d.path.length > 40 ? d.path.slice(0, 37) + '...' : d.path

          return (
            <div key={d.path + i} className="group p-2 rounded-lg hover:bg-ivory-50/60 transition-colors duration-200">
              <div className="flex items-center justify-between mb-1">
                <div className="flex items-center gap-2 min-w-0">
                  <span className={`text-[10px] font-bold w-5 h-5 rounded-md flex items-center justify-center shrink-0 ${i === 0 ? 'bg-red-100 text-red-600' : i === 1 ? 'bg-orange-100 text-orange-600' : i === 2 ? 'bg-amber-100 text-amber-600' : 'bg-slate-100 text-slate-400'}`}>
                    {i + 1}
                  </span>
                  <code className="text-xs font-mono text-slate-700 truncate font-medium" title={d.path}>
                    {displayPath}
                  </code>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <span className="text-[10px] text-slate-500 font-medium">{d.count.toLocaleString()} hits</span>
                  {d.blocked > 0 && (
                    <span className="text-[10px] font-bold text-red-500 bg-red-50 px-1.5 py-0.5 rounded-md ring-1 ring-red-500/10">
                      {d.blocked.toLocaleString()} blocked
                    </span>
                  )}
                </div>
              </div>
              <div className="h-2 bg-ivory-100 rounded-full overflow-hidden ml-7">
                <div
                  className="h-full rounded-full transition-all duration-500 relative overflow-hidden"
                  style={{
                    width: `${pct}%`,
                    background: blockRate > 50
                      ? 'linear-gradient(90deg, #EF4444, #DC2626)'
                      : blockRate > 0
                        ? 'linear-gradient(90deg, #F59E0B, #D97706)'
                        : 'linear-gradient(90deg, #3B82F6, #2563EB)',
                  }}
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
