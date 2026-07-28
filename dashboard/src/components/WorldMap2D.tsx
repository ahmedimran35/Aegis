import { useEffect, useMemo, useRef, useState } from 'react'
import { feature } from 'topojson-client'
import { Shield, Wifi, WifiOff } from 'lucide-react'
// Vite handles JSON imports; world-atlas 110m keeps the bundle lean
// (~100 KB) and ships the same TopoJSON topology I previously used for the
// 3D globe. Pure SVG rendering — no WebGL, no three.js, no shader cost.
import countries110mRaw from 'world-atlas/countries-110m.json'
import { COORD_NAMES } from './countryNames'

interface GeoAttack { ip: string; country: string; count: number }

interface Props {
  className?: string
  pollIntervalMs?: number
  // ISO-2 code → bubble filter is reflected on the right-hand country
  // list; click a marker / row and the table highlights that row.
  selectedCountry?: string
  onSelect?: (cc: string | null) => void
}

// Country code (ISO-2) → geographic centroid. Used to place attack
// bubbles + draw arc endpoints. Reuses the same lookup that the old
// 3D globe used so attacker geographies stay in lock-step.
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
  LO: [40.0, -100.0],  // loopback fallback (USA coordinates)
  PR: [50.0, 10.0],    // private network fallback
  UNKNOWN: [20, 0],
}

// WAF origin — all attack arcs terminate here, drawn as quadratic Bézier
// curves that sweep upward (curvature auto-scales with distance).
const SERVER: [number, number] = [37.7749, -122.4194]

// Pre-build country polygons at module load so the component renders are
// cheap (no TopoJSON walk per render).
const countriesGeo = feature(
  countries110mRaw as any,
  (countries110mRaw as any).objects.countries,
) as unknown as { features: Array<{ properties: any; geometry: any }> }

// Equirectangular projection — same maths the old 3D globe texture baked
// in. Computes (x, y) on the SVG canvas from (lon, lat).
const W = 960
const H = 480
const project = (lon: number, lat: number): [number, number] => [
  ((lon + 180) / 360) * W,
  ((90 - lat) / 180) * H,
]

// `d` attribute builder for a polygon (or multi-polygon) ring.
const ringToPath = (ring: number[][]): string => {
  if (!ring || ring.length < 3) return ''
  let d = ''
  for (let i = 0; i < ring.length; i++) {
    const [lon, lat] = ring
    const [x, y] = project(ring[i][0], ring[i][1])
    d += (i === 0 ? 'M' : 'L') + x.toFixed(1) + ',' + y.toFixed(1) + ' '
  }
  return d + 'Z'
}

const featureToPath = (feature: { geometry: any }): string => {
  const g = feature.geometry
  if (!g) return ''
  let d = ''
  if (g.type === 'Polygon') {
    for (const ring of g.coordinates) d += ringToPath(ring)
  } else if (g.type === 'MultiPolygon') {
    for (const poly of g.coordinates) {
      for (const ring of poly) d += ringToPath(ring)
    }
  }
  return d
}

// Curved-arc `d` from src → dst via a control point that bulges upward
// proportional to the great-circle distance. Quadratic Bézier, no per-
// frame work, computed once per (src, dst) pair.
const arcD = (src: [number, number], dst: [number, number]): string => {
  const [sx, sy] = project(src[0], src[1])
  const [dx, dy] = project(dst[0], dst[1])
  const mx = (sx + dx) / 2
  const my = (sy + dy) / 2
  const len = Math.hypot(dx - sx, dy - sy) || 1
  // Larger distance → larger upward bulge.
  const bulge = Math.min(len * 0.35, 180)
  return `M ${sx.toFixed(1)} ${sy.toFixed(1)} Q ${mx.toFixed(1)} ${(my - bulge).toFixed(1)} ${dx.toFixed(1)} ${dy.toFixed(1)}`
}

export default function WorldMap2D({ className = '', pollIntervalMs = 5000, selectedCountry, onSelect }: Props) {
  const [attacks, setAttacks] = useState<GeoAttack[]>([])
  const [tick, setTick] = useState(0)
  const [error, setError] = useState<string | null>(null)
  const [hovered, setHovered] = useState<string | null>(null)
  const containerRef = useRef<HTMLDivElement | null>(null)
  const [viewSize, setViewSize] = useState<{ w: number; h: number }>({ w: W, h: H })

  // Track container width so the SVG scales without distortion.
  useEffect(() => {
    if (!containerRef.current) return
    const ro = new ResizeObserver((entries) => {
      const rect = entries[0]?.contentRect
      if (!rect) return
      setViewSize({ w: rect.width, h: rect.width * (H / W) })
    })
    ro.observe(containerRef.current)
    return () => ro.disconnect()
  }, [])

  // Poll /api/v1/dashboard/geo-attacks for the latest country/IP split.
  useEffect(() => {
    let alive = true
    const fetchOnce = async () => {
      if (!alive) return
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
  }, [pollIntervalMs])

  // Aggregate by country → one bubble / arc per country for the visual.
  // Built from the polled `attacks` array; memoized so re-renders that
  // don't change `attacks` produce the same output reference.
  const { countryData, totalEvents, topCountries } = useMemo(() => {
    const m = new Map<string, { cc: string; count: number; lat: number; lon: number }>()
    for (const a of attacks) {
      const cc = (a.country || 'UNKNOWN').toUpperCase()
      if (cc === 'UNKNOWN') continue
      const c = COUNTRY_CENTERS[cc]
      if (!c) continue
      const cur = m.get(cc)
      if (cur) cur.count += a.count
      else m.set(cc, { cc, count: a.count, lat: c[0], lon: c[1] })
    }
    const list = Array.from(m.values()).sort((a, b) => b.count - a.count)
    return {
      countryData: list,
      topCountries: list.slice(0, 10),
      totalEvents: list.reduce((s, c) => s + c.count, 0),
    }
  }, [attacks])

  // Pre-compute all arc `d` strings + per-country size/intensity once per
  // `countryData` change. The SVG just renders them as <path> tags.
  const arcs = useMemo(
    () => countryData.map((c) => ({ key: c.cc, d: arcD([c.lat, c.lon], SERVER), count: c.count })),
    [countryData],
  )

  // Country paths keyed by ISO-a2 (if available on the topojson feature).
  // Memoized once — never re-computed on render.
  const countryPaths = useMemo(() => {
    const map: Record<string, string> = {}
    for (const f of countriesGeo.features as Array<{ id: any; properties: any; geometry: any }>) {
      const path = featureToPath(f)
      if (!path) continue
      // First try `properties.iso_a2`; world-atlas 110m usually has the
      // numeric ISO-3166-1 id in `id` (e.g. "840" = USA).
      const iso = (f.properties && (f.properties.iso_a2 || f.properties.ISO_A2)) || null
      const key = iso || (f.id != null ? String(f.id) : null)
      if (key) map[key] = path
    }
    return map
  }, [])

  // Build the leaderboard right-side data
  return (
    <div
      ref={containerRef}
      className={`flex flex-col bg-slate-950 text-slate-100 ${className}`}
    >
      {/* Toolbar */}
      <div className="flex items-center gap-2 px-3 py-2 border-b border-slate-800 bg-slate-900/60 flex-shrink-0">
        <Shield size={14} className="text-emerald-400" />
        <span className="text-sm font-bold text-slate-100 tracking-wide uppercase">Attack source map</span>
        {error ? <span className="text-rose-300 text-[10px] font-mono">· {error}</span>
                : <span className="text-emerald-300 text-[10px] font-mono">● LIVE</span>}
        <span className="ml-auto text-[10px] text-slate-400 font-mono">
          {countryData.length} countries · {totalEvents.toLocaleString()} events · tick {tick}
        </span>
      </div>

      {/* Map + side panel */}
      <div className="flex-1 grid grid-cols-1 lg:grid-cols-[1fr_280px] min-h-0">
        {/* MAP COLUMN */}
        <div className="relative overflow-hidden bg-slate-950">
          {countryData.length === 0 ? (
            <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
              <div className="text-center bg-slate-950/70 px-4 py-3 rounded border border-slate-800">
                <WifiOff size={20} className="mx-auto mb-1 text-slate-500" />
                <div className="text-slate-400 text-xs">No recent attacks to plot</div>
              </div>
            </div>
          ) : null}

          {/* Real DOM element that paints the world as plain SVG. No
              <canvas>, no WebGL, no shader work — a single <path>
              repaint on every data poll, every 5 s. */}
          <svg
            viewBox={`0 0 ${W} ${H}`}
            preserveAspectRatio="xMidYMid meet"
            className="w-full h-full block"
            style={{ maxHeight: '100%' }}
          >
            {/* Ocean — base plate */}
            <rect x={0} y={0} width={W} height={H} fill="#0b1a2a" />

            {/* Subtle graticule (every 30°) */}
            <g stroke="#1e293b" strokeWidth={0.6} fill="none">
              {Array.from({ length: 7 }, (_, i) => (
                <line key={`lat-${i}`} x1={0} y1={(i + 1) * (H / 8)} x2={W} y2={(i + 1) * (H / 8)} />
              ))}
              {Array.from({ length: 12 }, (_, i) => (
                <line key={`lon-${i}`} x1={(i + 1) * (W / 13)} y1={0} x2={(i + 1) * (W / 13)} y2={H} />
              ))}
            </g>

            {/* Country polygons — light fill that you can hover. */}
            <g>
              {Object.entries(countryPaths).map(([key, d]) => (
                <path
                  key={key}
                  d={d}
                  fill={hovered === key ? '#1f3a2e' : '#3a5a48'}
                  stroke="#0f1f17"
                  strokeWidth={0.4}
                  className="cursor-default transition-colors duration-150"
                />
              ))}
            </g>

            {/* Animated attack arcs from each country centroid → WAF */}
            <g fill="none" strokeLinecap="round" strokeWidth={1.4}>
              {arcs.map(({ key, d, count }) => {
                const max = Math.max(1, ...countryData.map((c) => c.count))
                const alpha = 0.35 + 0.45 * Math.min(1, count / max)
                return (
                  <path
                    key={key}
                    d={d}
                    stroke={selectedCountry === key ? '#f43f5e' : '#fbbf24'}
                    strokeOpacity={alpha}
                    strokeDasharray="4 3"
                    opacity={selectedCountry && selectedCountry !== key ? 0.18 : 1}
                  />
                )
              })}
            </g>

            {/* Glowing source bubbles */}
            <g>
              {countryData.map((c) => {
                const [x, y] = project(c.lon, c.lat)
                const max = Math.max(1, ...countryData.map((p) => p.count))
                const r = 4 + 12 * Math.min(1, c.count / max)
                return (
                  <g
                    key={c.cc}
                    onMouseEnter={() => setHovered(c.cc)}
                    onMouseLeave={() => setHovered((h) => (h === c.cc ? null : h))}
                    onClick={() => onSelect?.(selectedCountry === c.cc ? null : c.cc)}
                    style={{ cursor: 'pointer' }}
                  >
                    <circle cx={x} cy={y} r={r + 3} fill={selectedCountry === c.cc ? 'rgba(244,63,94,0.3)' : 'rgba(251,191,36,0.15)'} />
                    <circle cx={x} cy={y} r={r} fill={selectedCountry === c.cc ? '#f43f5e' : '#fbbf24'} stroke="#0b1a2a" strokeWidth={0.8} />
                    <text x={x} y={y - r - 4} textAnchor="middle"
                          fill="#fef2f2" fontSize={10} fontFamily="ui-monospace, monospace"
                          style={{ pointerEvents: 'none' }}>
                      {c.cc} · {c.count.toLocaleString()}
                    </text>
                  </g>
                )
              })}
            </g>

            {/* WAF server pin (SF) */}
            {(() => {
              const [sx, sy] = project(SERVER[0], SERVER[1])
              return (
                <g>
                  <circle cx={sx} cy={sy} r={9} fill="rgba(56,189,248,0.2)" />
                  <circle cx={sx} cy={sy} r={5} fill="#38bdf8" stroke="#0b1a2a" strokeWidth={1} />
                  <text x={sx + 9} y={sy + 4} fontSize={11} fontFamily="ui-monospace, monospace"
                        fontWeight={700} fill="#38bdf8">⬢ WAF</text>
                </g>
              )
            })()}
          </svg>

          {/* Hover tooltip */}
          {hovered && (() => {
            const c = countryData.find((p) => p.cc === hovered)
            if (!c) return null
            const name = COORD_NAMES[c.cc]?.name || c.cc
            return (
              <div className="absolute top-2 left-2 px-2 py-1 rounded bg-slate-950/90 border border-slate-700 text-[10px] font-mono pointer-events-none">
                <span className="text-slate-200 font-bold">{name}</span>
                <span className="text-slate-400 ml-2">{c.count.toLocaleString()} attacks</span>
              </div>
            )
          })()}

          <div className="absolute bottom-1 left-2 text-[9px] text-slate-600 font-mono pointer-events-none">
            2D equirectangular · SVG · no WebGL
          </div>
        </div>

        {/* SIDE PANEL — country leaderboard */}
        <aside className="border-l border-slate-800 bg-slate-950/60 p-3 overflow-y-auto">
          <div className="text-[10px] uppercase tracking-wider text-slate-500 mb-2 font-mono">
            Top sources · {topCountries.length}
          </div>
          {topCountries.length === 0 ? (
            <div className="text-xs text-slate-500 italic">No traffic.</div>
          ) : (
            <ul className="space-y-1.5">
              {topCountries.map((c, i) => {
                const name = COORD_NAMES[c.cc]?.name || c.cc
                const flag = COORD_NAMES[c.cc]?.flag || ''
                const isSel = selectedCountry === c.cc
                const pct = totalEvents > 0 ? Math.round((c.count / totalEvents) * 100) : 0
                return (
                  <li key={c.cc}>
                    <button
                      type="button"
                      onClick={() => onSelect?.(isSel ? null : c.cc)}
                      className={`w-full text-left px-2 py-1.5 rounded-md transition-colors duration-150 flex items-center gap-2
                        ${isSel
                          ? 'bg-rose-500/20 ring-1 ring-rose-400'
                          : 'hover:bg-slate-800/60'}`}
                    >
                      <span className={`text-[10px] font-mono font-bold w-5 h-5 rounded flex items-center justify-center shrink-0
                        ${i === 0 ? 'bg-red-500/90 text-white'
                          : i === 1 ? 'bg-orange-500/90 text-white'
                          : i === 2 ? 'bg-amber-500/90 text-white'
                          : 'bg-slate-700 text-slate-200'}`}>
                        {i + 1}
                      </span>
                      <span className="text-base shrink-0" aria-hidden="true">{flag}</span>
                      <span className="text-xs text-slate-200 font-medium truncate flex-1">{name}</span>
                      <span className="text-xs font-mono font-bold text-rose-300 tabular-nums">{c.count.toLocaleString()}</span>
                      <span className="text-[10px] font-mono text-slate-500 w-8 text-right tabular-nums">{pct}%</span>
                    </button>
                  </li>
                )
              })}
            </ul>
          )}

          <div className="mt-4 pt-3 border-t border-slate-800 text-[10px] font-mono text-slate-500 leading-relaxed">
            <p>Click a country bubble or row to filter the rest of the dashboard.</p>
            <p className="mt-1">Bubbles sized by 24-hour attack count.</p>
          </div>
        </aside>
      </div>
    </div>
  )
}
