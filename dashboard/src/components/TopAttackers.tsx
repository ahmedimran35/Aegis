import { ShieldBan, Globe } from 'lucide-react'

interface Attacker {
  ip: string
  count: number
  blocked: number
  last_seen?: string
  country?: string
}

interface Props {
  attackers: Attacker[]
  // Optional country filter applied to the visible rows. Rows whose
  // country doesn't match are hidden. When set, a "clear filter"
  // affordance is shown so the user can return to the unfiltered view.
  countryFilter?: string
  onClearFilter?: () => void
}

export default function TopAttackers({ attackers, countryFilter, onClearFilter }: Props) {
  // Apply the country filter (case-insensitive) before computing the bar
  // widths so the chart stays proportional to whatever the user sees.
  const filtered = countryFilter
    ? attackers.filter((a) => (a.country || '').toUpperCase() === countryFilter.toUpperCase())
    : attackers
  const maxCount = Math.max(...filtered.map(a => a.count), 1)

  return (
    <div className="space-y-3">
      {countryFilter && (
        <div className="flex items-center justify-between px-2 py-1 rounded-md bg-rose-50 ring-1 ring-rose-200">
          <span className="text-[10px] font-medium text-rose-700">
            Filtered by country: <span className="font-mono font-bold">{countryFilter}</span>
          </span>
          {onClearFilter && (
            <button
              type="button"
              onClick={onClearFilter}
              className="text-[10px] font-semibold text-rose-600 hover:text-rose-800"
            >
              Clear ✕
            </button>
          )}
        </div>
      )}
      {filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-8 text-center">
          <div className="w-10 h-10 rounded-full bg-emerald-50 flex items-center justify-center mb-3">
            <ShieldBan size={18} className="text-emerald-400" />
          </div>
          <p className="text-xs text-slate-400 font-medium">
            {countryFilter ? `No attackers from ${countryFilter}` : 'No attacks recorded today'}
          </p>
          <p className="text-[10px] text-slate-300 mt-1">
            {countryFilter ? 'Try clearing the filter' : 'Your Aegis is protecting well'}
          </p>
        </div>
      ) : (
        filtered.slice(0, 6).map((a, i) => {
          const pct = (a.count / maxCount) * 100
          const blockRate = a.count > 0 ? (a.blocked / a.count) * 100 : 0
          return (
            <div key={a.ip} className="group p-2.5 rounded-lg hover:bg-ivory-50/60 transition-colors duration-200">
              <div className="flex items-center justify-between mb-1.5">
                <div className="flex items-center gap-2">
                  <span className={`text-[10px] font-bold w-5 h-5 rounded-md flex items-center justify-center ${i === 0 ? 'bg-red-100 text-red-600' : i === 1 ? 'bg-orange-100 text-orange-600' : i === 2 ? 'bg-amber-100 text-amber-600' : 'bg-slate-100 text-slate-400'}`}>
                    {i + 1}
                  </span>
                  <code className="text-xs font-mono font-semibold text-slate-800">{a.ip}</code>
                  {a.country && (
                    <span className="text-[10px] px-1.5 py-0.5 bg-slate-100/80 text-slate-500 rounded-md font-medium border border-slate-200/50">
                      {a.country}
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-2 text-[10px]">
                  <span className="text-slate-500 font-medium">{a.count.toLocaleString()} reqs</span>
                  <span className="flex items-center gap-0.5 text-red-500 font-bold bg-red-50 px-1.5 py-0.5 rounded-md">
                    <ShieldBan size={10} /> {a.blocked.toLocaleString()}
                  </span>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <div className="flex-1 h-2 bg-ivory-100 rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-700 ease-out relative overflow-hidden"
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
                <span className="text-[10px] text-slate-400 w-10 text-right font-mono font-medium">
                  {blockRate.toFixed(0)}%
                </span>
              </div>
            </div>
          )
        })
      )}
      {filtered.length > 6 && (
        <p className="text-xs text-slate-400 mt-2 text-center">+{filtered.length - 6} more</p>
      )}
    </div>
  )
}
