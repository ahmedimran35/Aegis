import { useEffect, useMemo, useState } from 'react'
import { Globe2, Activity } from 'lucide-react'

interface GeoAttack { ip: string; country: string; count: number }

interface Props {
  className?: string
  pollIntervalMs?: number
  // Optional click handler for country dots. Lets the Overview page
  // wire a country-click to filtering the Top Attackers table.
  onCountryClick?: (cc: string) => void
}

// ============================================================================
// Equirectangular projection (lat/lon → x/y on 1000×500 canvas)
// ============================================================================
const W = 1000
const H = 500
const project = (lat: number, lon: number): [number, number] => {
  const x = ((lon + 180) / 360) * W
  const y = ((90 - lat) / 180) * H
  return [x, y]
}

// ============================================================================
// Country code → centroid (lat, lon)
// ============================================================================
const COUNTRY_CENTERS: Record<string, [number, number]> = {
  US: [39.8, -98.5], CN: [35.8, 104.1], RU: [61.5, 105.3], DE: [51.1, 10.4],
  BR: [-14.2, -51.9], IN: [20.5, 78.9], GB: [55.3, -3.4], FR: [46.2, 2.2],
  JP: [36.2, 138.2], KR: [35.9, 127.7], AU: [-25.2, 133.7], NL: [52.1, 5.2],
  UA: [48.3, 31.1], SG: [1.3, 103.8], ID: [-0.7, 113.9], VN: [14.0, 108.2],
  TH: [15.8, 100.9], TR: [38.9, 35.2], SA: [23.8, 45.0], MX: [23.6, -102.5],
  AR: [-38.4, -63.6], ZA: [-30.5, 22.9], NG: [9.0, 8.6], EG: [26.8, 30.8],
  IL: [31.0, 34.8], PL: [51.9, 19.1], IT: [41.8, 12.5], ES: [40.4, -3.7],
  CA: [56.1, -106.3], SE: [60.1, 18.6], IR: [32.4, 53.7], IQ: [33.2, 43.7],
  SY: [34.8, 38.9], AF: [33.9, 67.7], PK: [30.4, 69.3], BD: [23.7, 90.4],
  ET: [9.1, 40.5], KE: [-0.0, 37.9], DZ: [28.0, 1.7], MA: [31.8, -7.1],
  LY: [26.3, 17.2], SD: [12.9, 30.2], YE: [15.6, 48.5],
  LO: [40.0, -100.0],  // loopback (use USA coordinates as fallback)
  PR: [50.0, 10.0],    // private network (use central EU as fallback)
  unknown: [20, 0],
}

// ============================================================================
// Inline continent paths (simplified equirectangular polygons)
// Hand-tuned for visual recognizability. ~10x cheaper than a real topojson.
// ============================================================================
const CONTINENT_PATHS = [
  // North America
  'M 180 110 L 250 95 L 300 130 L 290 200 L 240 240 L 200 230 L 170 200 Z',
  // South America
  'M 280 280 L 310 270 L 330 320 L 320 400 L 290 430 L 270 410 L 260 340 Z',
  // Europe
  'M 470 110 L 530 100 L 560 130 L 540 170 L 490 175 L 465 150 Z',
  // Africa
  'M 480 200 L 540 195 L 570 240 L 575 310 L 540 360 L 500 350 L 485 280 Z',
  // Asia
  'M 560 110 L 720 100 L 800 140 L 820 200 L 770 240 L 700 230 L 620 200 L 580 160 Z',
  // India subcontinent
  'M 680 200 L 730 210 L 740 250 L 710 270 L 680 250 Z',
  // Southeast Asia
  'M 780 230 L 840 240 L 850 290 L 815 310 L 790 285 Z',
  // Australia
  'M 830 320 L 890 315 L 905 360 L 875 390 L 830 380 Z',
]

// Server origin (where the WAF runs)
const SERVER: [number, number] = [37.7749, -122.4194] // San Francisco

// ============================================================================
// Arc path generator (curved line from start to end via control point)
// ============================================================================
function arcPath(start: [number, number], end: [number, number], curvature = 0.25): string {
  const [sx, sy] = start
  const [ex, ey] = end
  const mx = (sx + ex) / 2
  const my = (sy + ey) / 2
  const dx = ex - sx
  const dy = ey - sy
  const len = Math.sqrt(dx * dx + dy * dy) || 1
  const nx = -dy / len
  const ny = dx / len
  const cpx = mx + nx * len * curvature
  const cpy = my + ny * len * curvature - len * curvature * 0.15
  return `M ${sx} ${sy} Q ${cpx} ${cpy} ${ex} ${ey}`
}

export default function AttackMap2D({ className = '', pollIntervalMs = 5000, onCountryClick }: Props) {
  const [attacks, setAttacks] = useState<GeoAttack[]>([])
  const [tick, setTick] = useState(0)
  const [error, setError] = useState<string | null>(null)
  const [isPaused, setIsPaused] = useState(false)

  // Poll /api/v1/dashboard/geo-attacks for the current country/IP breakdown.
  useEffect(() => {
    let alive = true
    const fetchOnce = async () => {
      if (!alive || isPaused) return
      try {
        const r = await fetch('/api/v1/dashboard/geo-attacks', { credentials: 'same-origin' })
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        const d = await r.json()
        const list = (d?.data || d) as GeoAttack[]
        if (Array.isArray(list)) {
          setAttacks(list)
          setTick((n) => n + 1)
          setError(null)
        }
      } catch (e: any) {
        setError(e?.message || 'fetch failed')
      }
    }
    fetchOnce()
    const t = setInterval(fetchOnce, pollIntervalMs)
    return () => { alive = false; clearInterval(t) }
  }, [pollIntervalMs, isPaused])

  // ============================================================================
  // Aggregate by country (dedupe to 1 dot per country, sized by count).
  // ============================================================================
  const { markers, arcs, total, countryCount, topCountries } = useMemo(() => {
    const m = new Map<string, { lat: number; lon: number; count: number; cc: string }>()
    for (const a of attacks) {
      const cc = (a.country || 'unknown').toUpperCase()
      const center = COUNTRY_CENTERS[cc] || COUNTRY_CENTERS.unknown
      const key = `${center[0].toFixed(1)},${center[1].toFixed(1)}`
      const cur = m.get(key)
      if (cur) cur.count += a.count
      else m.set(key, { lat: center[0], lon: center[1], count: a.count, cc })
    }
    const max = Math.max(1, ...Array.from(m.values()).map((b) => b.count))
    const tot = Array.from(m.values()).reduce((s, b) => s + b.count, 0)
    const sxy = project(SERVER[0], SERVER[1])
    const dots: { x: number; y: number; r: number; opacity: number; key: string; cc: string; count: number; lat: number; lon: number }[] = []
    const arx: { d: string; key: string; opacity: number }[] = []
    for (const [k, b] of m.entries()) {
      const [x, y] = project(b.lat, b.lon)
      const intensity = Math.min(1, b.count / max)
      const r = 3 + 9 * intensity
      dots.push({ x, y, r, opacity: 0.6 + 0.4 * intensity, key: k, cc: b.cc, count: b.count, lat: b.lat, lon: b.lon })
      if (b.lat !== SERVER[0] || b.lon !== SERVER[1]) {
        arx.push({
          d: arcPath(sxy, [x, y], 0.25),
          key: k,
          opacity: 0.3 + 0.5 * intensity,
        })
      }
    }
    // Top 5 countries by count for the side legend.
    const top = Array.from(m.entries())
      .map(([k, v]) => ({ key: k, cc: v.cc, count: v.count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5)
    return { markers: dots, arcs: arx, total: tot, countryCount: m.size, topCountries: top }
  }, [attacks])

  return (
    <div className={`flex flex-col h-full bg-slate-950 text-slate-100 ${className}`}>
      <div className="flex items-center gap-2 px-3 py-2 border-b border-slate-800 bg-slate-900/60 flex-shrink-0">
        <Globe2 size={14} className={isPaused ? 'text-slate-500' : 'text-emerald-400'} />
        <span className="text-sm font-bold text-slate-100 tracking-wide uppercase">Real-time attack map</span>
        {!isPaused && <span className="text-emerald-300 text-[10px] font-mono">● LIVE</span>}
        {isPaused && <span className="text-amber-300 text-[10px] font-mono">⏸ PAUSED</span>}
        <span className="ml-auto text-[10px] text-slate-400 font-mono">
          {countryCount} countries · {total} events · tick {tick}
        </span>
        <button
          onClick={() => setIsPaused((p) => !p)}
          className="ml-1 px-2 py-0.5 rounded border border-slate-700 hover:border-emerald-500 text-slate-200 text-[10px] font-mono"
        >
          {isPaused ? '▶' : '⏸'}
        </button>
      </div>

      {error && (
        <div className="px-3 py-1.5 text-[11px] text-rose-300 bg-rose-950/40 border-b border-rose-900/50 font-mono">
          error: {error}
        </div>
      )}

      <div className="flex-1 relative overflow-hidden bg-slate-950">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          preserveAspectRatio="xMidYMid meet"
          className="w-full h-full max-h-[420px]"
        >
          <defs>
            <radialGradient id="hot" cx="50%" cy="50%">
              <stop offset="0%" stopColor="#f43f5e" stopOpacity="0.95" />
              <stop offset="50%" stopColor="#f59e0b" stopOpacity="0.6" />
              <stop offset="100%" stopColor="#f59e0b" stopOpacity="0" />
            </radialGradient>
            <linearGradient id="arc" x1="0" y1="0" x2="1" y2="0">
              <stop offset="0%" stopColor="#f87171" stopOpacity="0.95" />
              <stop offset="100%" stopColor="#fbbf24" stopOpacity="0.5" />
            </linearGradient>
          </defs>
          {/* Graticule */}
          {Array.from({ length: 11 }, (_, i) => {
            const lon = -180 + i * 36
            const [x1, y1] = project(90, lon)
            const [x2, y2] = project(-90, lon)
            return <line key={`lon-${i}`} x1={x1} y1={y1} x2={x2} y2={y2} stroke="#1e293b" strokeWidth="0.5" />
          })}
          {Array.from({ length: 5 }, (_, i) => {
            const lat = 60 - i * 30
            const [x1, y1] = project(lat, -180)
            const [x2, y2] = project(lat, 180)
            return <line key={`lat-${i}`} x1={x1} y1={y1} x2={x2} y2={y2} stroke="#1e293b" strokeWidth="0.5" />
          })}
          {/* Continents */}
          {CONTINENT_PATHS.map((d, i) => (
            <path key={`c-${i}`} d={d} fill="#1e293b" stroke="#334155" strokeWidth="1" />
          ))}
          {/* Server marker */}
          {(() => {
            const [x, y] = project(SERVER[0], SERVER[1])
            return (
              <g>
                <circle cx={x} cy={y} r="8" fill="rgba(56, 189, 248, 0.25)" />
                <circle cx={x} cy={y} r="4" fill="#38bdf8" />
                <circle cx={x} cy={y} r="2" fill="#fff" />
                <text x={x + 10} y={y - 6} fontSize="9" fill="#94a3b8" fontFamily="ui-monospace, monospace">WAF</text>
              </g>
            )
          })()}
          {/* Arcs */}
          {arcs.map((a) => (
            <path
              key={`arc-${a.key}`}
              d={a.d}
              fill="none"
              stroke="url(#arc)"
              strokeWidth="1.5"
              strokeOpacity={a.opacity}
              strokeDasharray="4 3"
              style={{ animation: 'dash-flow 2s linear infinite' }}
            />
          ))}
          {/* Country dots */}
          {markers.map((m) => (
            <g
              key={`d-${m.key}`}
              onClick={onCountryClick ? () => onCountryClick(m.cc) : undefined}
              style={onCountryClick ? { cursor: 'pointer' } : undefined}
            >
              <circle cx={m.x} cy={m.y} r={m.r * 1.4} fill="url(#hot)" />
              <circle cx={m.x} cy={m.y} r={Math.max(2, m.r * 0.4)} fill="#fafafa" opacity={m.opacity} />
              {onCountryClick && (
                <circle
                  cx={m.x}
                  cy={m.y}
                  r={m.r * 1.4 + 4}
                  fill="transparent"
                  stroke="transparent"
                  style={{ pointerEvents: 'all' }}
                >
                  <title>Filter by {m.cc}</title>
                </circle>
              )}
              {/* Country code label, offset right of the dot */}
              <text
                x={m.x + m.r + 4}
                y={m.y + 4}
                fontSize="11"
                fontFamily="ui-monospace, monospace"
                fontWeight="700"
                fill="#fef2f2"
                stroke="#7f1d1d"
                strokeWidth="0.5"
                paintOrder="stroke fill"
              >
                {m.cc}
              </text>
              <text
                x={m.x + m.r + 4}
                y={m.y + 16}
                fontSize="9"
                fontFamily="ui-monospace, monospace"
                fill="#fecaca"
                opacity="0.85"
              >
                {m.count}
              </text>
            </g>
          ))}
        </svg>

        <div className="absolute top-2 left-2 text-[9px] text-slate-500 font-mono pointer-events-none">
          2D equirectangular · SVG · no WebGL · ~6KB
        </div>

        {/* Top countries legend (bottom-right) */}
        {topCountries.length > 0 && (
          <div className="absolute bottom-12 right-2 bg-slate-950/85 border border-slate-800 rounded p-2 text-[10px] font-mono pointer-events-none min-w-[140px]">
            <div className="text-[9px] uppercase tracking-wider text-slate-500 mb-1">Top sources</div>
            {topCountries.map((t) => (
              <div key={t.key} className="flex items-center justify-between gap-3 py-0.5">
                <span className="text-slate-200 font-bold">{t.cc}</span>
                <span className="text-rose-300">{t.count}</span>
              </div>
            ))}
          </div>
        )}

        {total === 0 && !error && (
          <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
            <div className="text-center bg-slate-950/70 px-4 py-3 rounded">
              <Activity size={24} className="mx-auto mb-1 text-slate-600" />
              <div className="text-slate-500 text-xs italic">No recent attacks</div>
              <div className="text-slate-600 text-[9px] font-mono mt-1">
                Try: curl 'http://127.0.0.1:8080/?id=1&apos; OR 1=1--'
              </div>
            </div>
          </div>
        )}
      </div>

      <style>{`
        @keyframes dash-flow {
          to { stroke-dashoffset: -14; }
        }
        @media (prefers-reduced-motion: reduce) {
          [style*="dash-flow"] { animation: none !important; }
        }
      `}</style>
    </div>
  )
}
