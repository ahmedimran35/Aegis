import { useMemo } from 'react'
import { Globe2, Flag } from 'lucide-react'

interface GeoAttack { ip: string; country: string; count: number }

interface Props {
  attacks: GeoAttack[]
  selectedCountry?: string
  onSelect?: (cc: string | null) => void
  limit?: number
}

// Minimal mapping from ISO-2 country code to display name + flag.
// Covers the top countries the WAF typically sees. Unknown codes fall
// back to the code itself with a neutral globe icon.
const COUNTRY_NAMES: Record<string, { name: string; flag: string }> = {
  US: { name: 'United States', flag: '🇺🇸' },
  CN: { name: 'China',         flag: '🇨🇳' },
  RU: { name: 'Russia',        flag: '🇷🇺' },
  DE: { name: 'Germany',       flag: '🇩🇪' },
  BR: { name: 'Brazil',        flag: '🇧🇷' },
  IN: { name: 'India',         flag: '🇮🇳' },
  GB: { name: 'United Kingdom',flag: '🇬🇧' },
  FR: { name: 'France',        flag: '🇫🇷' },
  JP: { name: 'Japan',         flag: '🇯🇵' },
  KR: { name: 'South Korea',   flag: '🇰🇷' },
  AU: { name: 'Australia',     flag: '🇦🇺' },
  NL: { name: 'Netherlands',   flag: '🇳🇱' },
  UA: { name: 'Ukraine',       flag: '🇺🇦' },
  SG: { name: 'Singapore',     flag: '🇸🇬' },
  ID: { name: 'Indonesia',     flag: '🇮🇩' },
  VN: { name: 'Vietnam',       flag: '🇻🇳' },
  TH: { name: 'Thailand',      flag: '🇹🇭' },
  TR: { name: 'Turkey',        flag: '🇹🇷' },
  SA: { name: 'Saudi Arabia',  flag: '🇸🇦' },
  MX: { name: 'Mexico',        flag: '🇲🇽' },
  AR: { name: 'Argentina',     flag: '🇦🇷' },
  ZA: { name: 'South Africa',  flag: '🇿🇦' },
  NG: { name: 'Nigeria',       flag: '🇳🇬' },
  EG: { name: 'Egypt',         flag: '🇪🇬' },
  IL: { name: 'Israel',        flag: '🇮🇱' },
  PL: { name: 'Poland',        flag: '🇵🇱' },
  IT: { name: 'Italy',         flag: '🇮🇹' },
  ES: { name: 'Spain',         flag: '🇪🇸' },
  CA: { name: 'Canada',        flag: '🇨🇦' },
  SE: { name: 'Sweden',        flag: '🇸🇪' },
  IR: { name: 'Iran',          flag: '🇮🇷' },
  PK: { name: 'Pakistan',      flag: '🇵🇰' },
  BD: { name: 'Bangladesh',    flag: '🇧🇩' },
  KE: { name: 'Kenya',         flag: '🇰🇪' },
  UNKNOWN: { name: 'Unknown',   flag: '🌐' },
}

export default function TopCountriesTable({ attacks, selectedCountry, onSelect, limit = 5 }: Props) {
  const rows = useMemo(() => {
    const acc = new Map<string, { count: number; cc: string }>()
    for (const a of attacks) {
      const cc = (a.country || 'UNKNOWN').toUpperCase()
      const cur = acc.get(cc)
      if (cur) cur.count += a.count
      else acc.set(cc, { count: a.count, cc })
    }
    return Array.from(acc.values())
      .sort((a, b) => b.count - a.count)
      .slice(0, limit)
  }, [attacks, limit])

  const total = rows.reduce((s, r) => s + r.count, 0)

  if (rows.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-8 text-center">
        <div className="w-10 h-10 rounded-full bg-emerald-50 flex items-center justify-center mb-3">
          <Globe2 size={18} className="text-emerald-400" />
        </div>
        <p className="text-xs text-slate-400 font-medium">No attacks recorded today</p>
      </div>
    )
  }

  return (
    <div className="space-y-2">
      {rows.map((r, i) => {
        const meta = COUNTRY_NAMES[r.cc] || { name: r.cc, flag: '🌐' }
        const pct = total > 0 ? Math.round((r.count / total) * 100) : 0
        const isSelected = selectedCountry === r.cc
        return (
          <button
            type="button"
            key={r.cc}
            onClick={() => onSelect?.(isSelected ? null : r.cc)}
            className={`w-full text-left p-2.5 rounded-lg transition-colors duration-200
              ${isSelected ? 'bg-rose-50 ring-1 ring-rose-300' : 'hover:bg-ivory-50/60'}`}
            aria-pressed={isSelected}
          >
            <div className="flex items-center justify-between mb-1.5">
              <div className="flex items-center gap-2">
                <span className={`text-[10px] font-bold w-5 h-5 rounded-md flex items-center justify-center ${i === 0 ? 'bg-red-100 text-red-600' : i === 1 ? 'bg-orange-100 text-orange-600' : 'bg-slate-100 text-slate-400'}`}>
                  {i + 1}
                </span>
                <span className="text-base" aria-hidden="true">{meta.flag}</span>
                <span className="text-xs font-medium text-slate-800">{meta.name}</span>
              </div>
              <div className="flex items-center gap-2 text-[10px]">
                <span className="text-slate-500 font-medium">{r.count.toLocaleString()}</span>
                <span className="text-rose-500 font-bold bg-rose-50 px-1.5 py-0.5 rounded-md">{pct}%</span>
              </div>
            </div>
            <div className="h-1.5 bg-ivory-100 rounded-full overflow-hidden">
              <div
                className="h-full rounded-full bg-gradient-to-r from-rose-500 to-orange-400"
                style={{ width: `${pct}%` }}
              />
            </div>
          </button>
        )
      })}
    </div>
  )
}
