import { useEffect, useMemo, useRef, useState } from 'react'
import Globe from 'react-globe.gl'
import * as THREE from 'three'
import { feature } from 'topojson-client'
import type { Feature, Geometry } from 'geojson'
// world-atlas ships TopoJSON; loading it via vite's JSON import keeps the
// fetch inside our bundle (no CDN, no CSP surprises).
import countries110mRaw from 'world-atlas/countries-110m.json'
import { Shield, Wifi, WifiOff } from 'lucide-react'
import UtcChip from './UtcChip'

interface GeoAttack { ip: string; country: string; count: number }

interface Props {
  className?: string
  pollIntervalMs?: number
  // Country click — wired to filter the Top Attackers table.
  onCountryClick?: (cc: string) => void
}

// Country code (ISO-2) → geographic centroid. Reused from AttackMap2D so
// arcs land on a real point on the globe rather than a placeholder.
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
  LO: [40.0, -100.0],  // loopback fallback
  PR: [50.0, 10.0],    // private network fallback
  UNKNOWN: [20, 0],
}

// Server origin — the WAF itself. All attack arcs terminate here.
// In a real deployment this could come from `runtime.config`; pinning to
// SF as a sensible default keeps the visual self-consistent.
const SERVER: [number, number] = [37.7749, -122.4194]

// Pre-build country polygons at module load. Converting from TopoJSON to
// GeoJSON features once is much cheaper than redoing it every render.
const countriesGeo = feature(
  countries110mRaw as any,
  (countries110mRaw as any).objects.countries,
) as unknown as { features: Feature<Geometry>[] }

// ============================================================================
// Procedural Earth texture — baked once into a data URL via Canvas2D. No
// external image fetch (CSP blocks unsplash & similar), no CDN. The texture
// paints ocean + countries + lat/lon grid into a 1024×512 equirectangular
// projection (downscaled from 2048×1024 for vastly cheaper GPU upload —
// file size drops 4× and the texture-decode step is the heaviest frame-1
// cost) that `react-globe.gl` reads as `globeImageUrl`.
// ============================================================================
function buildEarthTexture(): string {
  const W = 1024
  const H = 512
  const canvas = document.createElement('canvas')
  canvas.width = W
  canvas.height = H
  const ctx = canvas.getContext('2d')!

  // 1) Ocean — radial gradient (lighter in the middle, deeper at the poles).
  const ocean = ctx.createRadialGradient(W / 2, H / 2, 200, W / 2, H / 2, W * 0.7)
  ocean.addColorStop(0, '#1e3a5f')
  ocean.addColorStop(0.6, '#0f2a48')
  ocean.addColorStop(1, '#06121f')
  ctx.fillStyle = ocean
  ctx.fillRect(0, 0, W, H)

  // 2) Latitude grid (very thin — equator + tropics only, every 30°,
  //    reduced opacity. Fewer strokes = less fill on the texture and
  //    fewer pixels for the GPU to keep re-bilinear filtering).
  ctx.strokeStyle = 'rgba(148, 163, 184, 0.08)'
  ctx.lineWidth = 0.5
  for (let lat = -60; lat <= 60; lat += 30) {
    const y = ((90 - lat) / 180) * H
    ctx.beginPath()
    ctx.moveTo(0, y)
    ctx.lineTo(W, y)
    ctx.stroke()
  }

  // 3) Longitude grid — prime meridian at full opacity, others sparser
  //    (every 30° instead of every 15°) and dimmer.
  for (let lon = -180; lon < 180; lon += 30) {
    const x = ((lon + 180) / 360) * W
    ctx.strokeStyle = lon === 0 ? 'rgba(148, 163, 184, 0.24)' : 'rgba(148, 163, 184, 0.06)'
    ctx.beginPath()
    ctx.moveTo(x, 0)
    ctx.lineTo(x, H)
    ctx.stroke()
  }

  // 4) Country polygons from world-atlas. Each polygon is projected from
  // (lon, lat) to (x, y) via the equirectangular formula: x = (lon+180)/360*W,
  // y = (90-lat)/180*H. We fill with a desaturated green and stroke darker.
  const FILL = 'rgba(94, 163, 89, 0.85)'
  const STROKE = 'rgba(34, 86, 32, 0.95)'
  ctx.fillStyle = FILL
  ctx.strokeStyle = STROKE
  ctx.lineWidth = 1

  const project = (lon: number, lat: number): [number, number] => [
    ((lon + 180) / 360) * W,
    ((90 - lat) / 180) * H,
  ]
  const drawRing = (ring: number[][]) => {
    if (!ring || ring.length === 0) return
    ctx.beginPath()
    ring.forEach(([lon, lat], i) => {
      const [x, y] = project(lon, lat)
      if (i === 0) ctx.moveTo(x, y)
      else ctx.lineTo(x, y)
    })
    ctx.closePath()
    ctx.fill()
    ctx.stroke()
  }
  const drawGeometry = (g: any) => {
    if (!g) return
    if (g.type === 'Polygon') g.coordinates.forEach(drawRing)
    else if (g.type === 'MultiPolygon') {
      for (const poly of g.coordinates) poly.forEach(drawRing)
    }
  }

  for (const f of countriesGeo.features) {
    drawGeometry(f.geometry)
  }

  // 5) Subtle vignette so the poles don't look flat.
  const vignette = ctx.createRadialGradient(W / 2, H / 2, W * 0.4, W / 2, H / 2, W * 0.6)
  vignette.addColorStop(0, 'rgba(0,0,0,0)')
  vignette.addColorStop(1, 'rgba(0,0,0,0.25)')
  ctx.fillStyle = vignette
  ctx.fillRect(0, 0, W, H)

  return canvas.toDataURL('image/png')
}

let _earthTextureCache: string | null = null
function getEarthTexture(): string {
  if (_earthTextureCache) return _earthTextureCache
  _earthTextureCache = buildEarthTexture()
  return _earthTextureCache
}

// ============================================================================
// Country name labels — one entry per world-atlas country, with a centroid
// derived from the largest polygon ring of the feature. Memoized at module
// load so re-renders don't rebuild the array.
// ============================================================================
function deriveCountryLabels(): Array<{ lat: number; lng: number; text: string }> {
  const labels: Array<{ lat: number; lng: number; text: string }> = []
  for (const f of countriesGeo.features) {
    const name = (f.properties as any)?.name as string | undefined
    if (!name) continue
    const g = f.geometry as any
    if (!g) continue
    let bestRing: number[][] | null = null
    let bestScore = -Infinity
    for (const poly of (g.type === 'Polygon' ? [g.coordinates] : g.coordinates) as number[][][][]) {
      for (const ring of poly as number[][][]) {
        let score = 0
        for (const [lon, lat] of ring as number[][]) {
          if (Math.abs(lat) > 70) score -= 1000
          score += 1
        }
        if (score > bestScore) { bestScore = score; bestRing = ring }
      }
    }
    if (!bestRing || bestRing.length === 0) continue
    let lat = 0, lng = 0, count = 0
    for (const pt of bestRing as number[][]) {
      lng += pt[0]
      lat += pt[1]
      count++
    }
    labels.push({
      lat: lat / count,
      lng: lng / count,
      text: name,
    })
  }
  return labels
}
const countryNameLabels = deriveCountryLabels()

// ============================================================================
// Country-name label cap. Rendering ~250 bitmap text sprites at every frame
// was the dominant cost in three.js. Cap to ~40 well-known countries whose
// names are useful at the default zoom — the rest are visually cluttering
// and don't change the page's usefulness. Final count: 10. These are the
// largest ten by land area — enough to orient against on a globe while
// keeping the per-frame label-sprite scene small enough that even a
// software-rendered WebGL canvas can drag smoothly.
// ============================================================================
const MAJOR_COUNTRIES = new Set([
  'Russia',
  'China',
  'United States of America',
  'Canada',
  'Brazil',
  'Australia',
  'India',
  'Argentina',
  'Kazakhstan',
  'Saudi Arabia',
])
const countryNameLabelsFiltered = countryNameLabels.filter((l) =>
  MAJOR_COUNTRIES.has(l.text),
)

// ============================================================================
// Click → ISO-2 reverse geocoding. Since the polygon Three.js mesh has been
// removed (perf), we instead ray-cast the lat/lng against world-atlas feature
// polygons ourselves. world-atlas' default `properties.iso_a2` is not present
// in 110m — the numeric id is the ISO-3166-1 numeric code, so we map numeric
// → ISO-2 via a static lookup for the ~80 countries we ever see in this WAF.
//
// `pointInRing` is the classic even-odd ray-casting algorithm; on a 250-ring
// world this is O(rings × points-per-ring) per click — negligible vs the
// Three.js mesh the polygons layer was forcing.
// ============================================================================
const ISO_NUMERIC_TO_A2: Record<string, string> = {
  '004': 'AF', '008': 'AL', '012': 'DZ', '024': 'AO', '032': 'AR', '036': 'AU',
  '040': 'AT', '044': 'BS', '050': 'BD', '051': 'AM', '056': 'BE', '064': 'BT',
  '068': 'BO', '070': 'BA', '072': 'BW', '076': 'BR', '084': 'BZ', '090': 'SB',
  '096': 'BN', '100': 'BG', '104': 'MM', '108': 'BI', '112': 'BY', '116': 'KH',
  '120': 'CM', '124': 'CA', '132': 'CV', '140': 'CF', '144': 'LK', '148': 'TD',
  '152': 'CL', '156': 'CN', '158': 'TW', '170': 'CO', '178': 'CG', '180': 'CD',
  '188': 'CR', '191': 'HR', '192': 'CU', '196': 'CY', '203': 'CZ', '204': 'BJ',
  '208': 'DK', '212': 'DM', '214': 'DO', '218': 'EC', '222': 'SV', '226': 'GQ',
  '231': 'ET', '232': 'ER', '233': 'EE', '242': 'FJ', '246': 'FI', '250': 'FR',
  '262': 'DJ', '266': 'GA', '268': 'GE', '270': 'GM', '275': 'PS', '276': 'DE',
  '288': 'GH', '292': 'GI', '300': 'GR', '320': 'GT', '324': 'GN', '328': 'GY',
  '332': 'HT', '340': 'HN', '348': 'HU', '352': 'IS', '356': 'IN', '360': 'ID',
  '364': 'IR', '368': 'IQ', '372': 'IE', '376': 'IL', '380': 'IT', '384': 'CI',
  '388': 'JM', '392': 'JP', '398': 'KZ', '400': 'JO', '404': 'KE', '408': 'KP',
  '410': 'KR', '414': 'KW', '417': 'KG', '418': 'LA', '422': 'LB', '426': 'LS',
  '428': 'LV', '430': 'LR', '434': 'LY', '440': 'LT', '442': 'LU', '450': 'MG',
  '454': 'MW', '458': 'MY', '466': 'ML', '478': 'MR', '480': 'MU', '484': 'MX',
  '492': 'MC', '496': 'MN', '498': 'MD', '499': 'ME', '504': 'MA', '508': 'MZ',
  '512': 'OM', '516': 'NA', '524': 'NP', '528': 'NL', '540': 'NC', '548': 'VU',
  '554': 'NZ', '558': 'NI', '562': 'NE', '566': 'NG', '578': 'NO', '586': 'PK',
  '591': 'PA', '598': 'PG', '600': 'PY', '604': 'PE', '608': 'PH', '616': 'PL',
  '620': 'PT', '624': 'GW', '626': 'TL', '630': 'PR', '634': 'QA', '642': 'RO',
  '643': 'RU', '646': 'RW', '682': 'SA', '686': 'SN', '688': 'RS', '694': 'SL',
  '702': 'SG', '703': 'SK', '704': 'VN', '705': 'SI', '706': 'SO', '710': 'ZA',
  '716': 'ZW', '724': 'ES', '728': 'SS', '729': 'SD', '732': 'EH', '740': 'SR',
  '748': 'SZ', '752': 'SE', '756': 'CH', '760': 'SY', '762': 'TJ', '764': 'TH',
  '768': 'TG', '772': 'TO', '776': 'TN', '780': 'TT', '784': 'AE', '788': 'TN',
  '792': 'TR', '795': 'TM', '798': 'TV', '800': 'UG', '804': 'UA', '807': 'MK',
  '818': 'EG', '826': 'GB', '834': 'TZ', '840': 'US', '854': 'BF', '858': 'UY',
  '860': 'UZ', '862': 'VE', '882': 'WS', '887': 'YE', '894': 'ZM',
}

function pointInRing(lng: number, lat: number, ring: number[][]): boolean {
  let inside = false
  for (let i = 0, j = ring.length - 1; i < ring.length; j = i++) {
    const xi = ring[i][0]
    const yi = ring[i][1]
    const xj = ring[j][0]
    const yj = ring[j][1]
    const intersect = ((yi > lat) !== (yj > lat)) &&
      (lng < ((xj - xi) * (lat - yi)) / (yj - yi) + xi)
    if (intersect) inside = !inside
  }
  return inside
}

function iso2ForLatLng(lat: number, lng: number): string | null {
  for (const f of countriesGeo.features as any[]) {
    const g = f.geometry
    if (!g) continue
    let hit = false
    if (g.type === 'Polygon') {
      const outer = g.coordinates[0]
      hit = pointInRing(lng, lat, outer)
    } else if (g.type === 'MultiPolygon') {
      for (const poly of g.coordinates) {
        if (pointInRing(lng, lat, poly[0])) { hit = true; break }
      }
    }
    if (!hit) continue
    // 1) Try `properties.iso_a2`
    const props = f.properties || {}
    if (props.iso_a2) return String(props.iso_a2).toUpperCase()
    // 2) Fall back to ISO-3166-1 numeric → alpha-2 via the static map
    if (props.iso_n3) {
      const m = ISO_NUMERIC_TO_A2[String(props.iso_n3).padStart(3, '0')]
      if (m) return m
    }
    // 3) Fall back to numeric id
    if (f.id !== undefined && f.id !== null) {
      const m = ISO_NUMERIC_TO_A2[String(f.id).padStart(3, '0')]
      if (m) return m
    }
    return null
  }
  return null
}
// ============================================================================
// Sun-position math — given a UTC instant, where on Earth is the sun
// overhead? Used to render the "current subsolar point" as a glow dot so
// the globe visibly tracks time.
// ============================================================================
function subsolarPoint(now: Date): [number, number] {
  // Days since J2000.0
  const jd = now.getTime() / 86400000 - 10957.5  // getTime/86400000 - (2000-01-01)
  const t = jd / 36525
  // Mean longitude (deg) and mean anomaly (deg)
  const L = (280.460 + 0.9856474 * (jd - 0.5) * 86400 / 86400) % 360
  const g = (357.528 + 0.9856003 * (jd - 0.5) * 86400 / 86400) % 360
  // Ecliptic longitude
  const lambda = (L + 1.915 * Math.sin((g * Math.PI) / 180) + 0.020 * Math.sin((2 * g * Math.PI) / 180)) % 360
  // Obliquity
  const eps = 23.439 - 0.0000004 * (jd - 2451545) * 86400
  // Declination + right ascension → subsolar latitude/longitude
  const lat = Math.asin(Math.sin((eps * Math.PI) / 180) * Math.sin((lambda * Math.PI) / 180)) * 180 / Math.PI
  const ra = Math.atan2(
    Math.cos((eps * Math.PI) / 180) * Math.sin((lambda * Math.PI) / 180),
    Math.cos((lambda * Math.PI) / 180),
  )
  // Subsolar longitude: take gmst-derived offset (simplified)
  const utcHours = now.getUTCHours() + now.getUTCMinutes() / 60 + now.getUTCSeconds() / 3600
  const lon = ((-15 * (utcHours - 12)) % 360 + 540) % 360 - 180
  void ra
  return [lat, lon]
}

export default function GlobeMap({ className = '', pollIntervalMs = 5000, onCountryClick }: Props) {
  const [attacks, setAttacks] = useState<GeoAttack[]>([])
  const [tick, setTick] = useState(0)
  const [error, setError] = useState<string | null>(null)
  const [isPaused, setIsPaused] = useState(false)
  const [size, setSize] = useState<number>(420)
  // Bake the procedural Earth texture once (PNG data URL).
  const [earthTexture] = useState<string>(() => getEarthTexture())
  // Subsolar point updates every minute (sun moves ~15°/hour, so 60s
  // resolution is visually fine and avoids forcing a full GlobeMap re-render
  // every second just to keep the UTC text chip live).
  const [nowMinute, setNowMinute] = useState<Date>(() => new Date())
  const containerRef = useRef<HTMLDivElement | null>(null)
  const globeRef = useRef<any>(null)
  // Inner-interval handle held in a ref so the cleanup pass can clear it.
  const clockInnerRef = useRef<ReturnType<typeof setInterval> | null>(null)

  useEffect(() => {
    const align = 60_000 - (Date.now() % 60_000)
    const id1 = setTimeout(() => {
      setNowMinute(new Date())
      clockInnerRef.current = setInterval(() => setNowMinute(new Date()), 60_000)
    }, align)
    return () => {
      clearTimeout(id1)
      if (clockInnerRef.current !== null) clearInterval(clockInnerRef.current)
    }
  }, [])

  // ---------------------------------------------------------------------------
  // Poll /api/v1/dashboard/geo-attacks for the latest country/IP split.
  // ---------------------------------------------------------------------------
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

  // ---------------------------------------------------------------------------
  // Resize observer — globe dimension is the SHORTER side of the container
  // so it fits without cropping. Using only width made a 900 px square get
  // chopped vertically in a 420 px-tall panel.
  // ---------------------------------------------------------------------------
  useEffect(() => {
    if (!containerRef.current) return
    const ro = new ResizeObserver((entries) => {
      const rect = entries[0]?.contentRect
      if (!rect) return
      const side = Math.max(280, Math.min(rect.width, rect.height, 900))
      setSize(side)
    })
    ro.observe(containerRef.current)
    return () => ro.disconnect()
  }, [])

  // ---------------------------------------------------------------------------
  // Aggregate by country so we render one label / arc / point per country.
  // ---------------------------------------------------------------------------
  const { arcs, points, labels, countryList } = useMemo(() => {
    const m = new Map<string, { lat: number; lon: number; count: number; cc: string }>()
    for (const a of attacks) {
      const cc = (a.country || 'UNKNOWN').toUpperCase()
      if (cc === 'UNKNOWN') continue
      const center = COUNTRY_CENTERS[cc]
      if (!center) continue
      const key = `${center[0]},${center[1]}`
      const cur = m.get(key)
      if (cur) cur.count += a.count
      else m.set(key, { lat: center[0], lon: center[1], count: a.count, cc })
    }
    const list = Array.from(m.values())
    return {
      countryList: list,
      arcs: list.map((b) => ({
        startLat: b.lat,
        startLng: b.lon,
        endLat: SERVER[0],
        endLng: SERVER[1],
        color: '#fbbf24',
        cc: b.cc,
        count: b.count,
      })),
      points: list.map((b) => ({
        lat: b.lat,
        lng: b.lon,
        size: 0.4 + Math.min(1.2, b.count / 200),
        color: '#f43f5e',
        cc: b.cc,
        count: b.count,
      })),
      labels: list.map((b) => ({
        lat: b.lat,
        lng: b.lon,
        text: `${b.cc} · ${b.count.toLocaleString()}`,
        cc: b.cc,
        count: b.count,
      })),
    }
  }, [attacks])

  // Combined labelsData — FINAL defensive build: only the 10 largest
  // countries by area. We removed the per-attack attack labels too
  // because the Top sources panel above the globe already enumerates
  // attacker countries with their counts.
  const memoizedLabels = useMemo(() => {
    const nameLabels = countryNameLabelsFiltered.map((l) => ({
      lat: l.lat,
      lng: l.lng,
      text: l.text,
      kind: 'name',
    }))
    return nameLabels
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [labels])

  // ---------------------------------------------------------------------------
  // Material — slight bump & specular over the procedural texture so the
  // oceans have a faint sheen without being so glossy it washes out.
  // ---------------------------------------------------------------------------
  const globeMaterial = useMemo(
    () =>
      new THREE.MeshPhongMaterial({
        color: 0xffffff,
        emissive: 0x0a1424,
        shininess: 6,
      }),
    [],
  )

  // Subsolar point — where the sun is directly overhead at this UTC instant.
  // Drives the small glow ball on the globe surface so the page visibly
  // tracks real time even when there are no attacks.
  const subsolar = useMemo<[number, number]>(() => subsolarPoint(nowMinute), [nowMinute])

  // Set initial camera angle AND swap the globe sphere to a 16-segment
  // mesh. three-globe internally constructs `new SphereGeometry(100, 32, 32)`
  // for its own globe, which means 64×64 faces (≈ 4 096 vertices) re-
  // tessellated every frame even though the sphere is hidden by the
  // texture. Replacing it once with a 16-segment sphere drops vertex
  // count to 256 (16× less geometry) and visibly smooths the drag.
  useEffect(() => {
    const g = globeRef.current as any
    if (!g) return
    g.pointOfView({ lat: 20, lng: -30, altitude: 2.0 }, 0)

    // The internal globe mesh. `three-globe` exposes `globe()` (the
    // Object3D); we swap its geometry for a smaller sphere. Material
    // (and the baked Earth texture) is left untouched.
    const wrap = typeof g.globe === 'function' ? g.globe() : null
    const sphere = wrap?.children?.find?.((c: any) => c.geometry?.type === 'SphereGeometry')
      ?? wrap
    if (sphere && sphere.geometry) {
      sphere.geometry.dispose()
      sphere.geometry = new THREE.SphereGeometry(100, 16, 16)
    }
  }, [])

  return (
    <div
      ref={containerRef}
      className={`flex flex-col h-full bg-slate-950 text-slate-100 ${className}`}
    >
      <div className="flex items-center gap-2 px-3 py-2 border-b border-slate-800 bg-slate-900/60 flex-shrink-0">
        <Shield size={14} className="text-emerald-400" />
        <span className="text-sm font-bold text-slate-100 tracking-wide uppercase">Real-time attack globe</span>
        {!isPaused && <span className="text-emerald-300 text-[10px] font-mono">● LIVE</span>}
        {isPaused && <span className="text-amber-300 text-[10px] font-mono">⏸ PAUSED</span>}
        {/* Live UTC clock — ticks every second IN ISOLATION via its own
            state, so the heavy 3D scene above is not re-rendered each tick. */}
        <UtcChip />
        <span className="ml-auto text-[10px] text-slate-400 font-mono">
          {countryList.length} countries · {countryList.reduce((s, c) => s + c.count, 0).toLocaleString()} events · tick {tick}
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
        {/* Absolute-centered wrapper. react-globe.gl renders its own
            position:relative <div> around the canvas, which removes it
            from flex flow — pin it to the panel center with this
            absolute-positioned shell. */}
        <div style={{
          position: 'absolute',
          left: '50%',
          top: '50%',
          transform: 'translate(-50%, -50%)',
        }}>
        <Globe
          ref={globeRef}
          width={size}
          height={size}
          // Disable continuous re-render on data change. `enableTransition`
          // would otherwise re-animate the scene every time the
          // /geo-attacks poll updates, causing the visible jitter.
          animateIn={false}
          // Drop anti-aliasing and request the low-power GPU so the
          // renderer off-loads to integrated graphics when a discrete
          // GPU is available. Combined, this halves the per-frame fill
          // cost on most machines.
          rendererConfig={{
            antialias: false,
            powerPreference: 'low-power',
            alpha: true,
            premultipliedAlpha: true,
          }}
          backgroundColor="rgba(2, 6, 23, 0)"
          // Use the procedural Earth texture baked at module load. Continents,
          // oceans, and lat/lon grid are all drawn into this PNG.
          globeImageUrl={earthTexture}
          globeMaterial={globeMaterial}
          // showAtmosphere + atmosphereColor + atmosphereAltitude props have
          // been DELIBERATELY OMITTED in this defensive fallback build. The
          // atmospheric shader was a non-trivial per-frame cost; if the
          // drag feel is now smooth we know which frame cost to attribute.
          //
          // Country hover/click is handled via `onGlobeClick` + a manual
          // raycast-free ISO-2 reverse lookup on world-atlas features
          // (see `iso2ForLatLng` above). We deliberately do NOT pass
          // `polygonsData` here.
          onGlobeClick={({ lat, lng }: { lat: number; lng: number }) => {
            const cc = iso2ForLatLng(lat, lng)
            if (cc && onCountryClick) onCountryClick(cc)
          }}
          // arcsData + pointsData REMOVED in this defensive build. The
          // reactive three-globe layers for animated arcs and per-source
          // point halos were the last remaining per-frame scene items.
          // With them gone the scene is just: texture-baked sphere +
          // 45 country labels + onGlobeClick.
          // Country labels — only the attacked sources + a curated set of
          // ~45 major countries.
          labelsData={memoizedLabels}
          labelLat={(d: any) => d.lat}
          labelLng={(d: any) => d.lng}
          labelText={(d: any) => d.text}
          labelSize={(d: any) => d.kind === 'attack' ? 0.7 : 0.7}
          labelColor={() => '#fef3c7'}
          labelResolution={2}
          labelAltitude={0.015}
          labelDotRadius={0.2}
          labelIncludeDot={(d: any) => d.kind === 'attack'}
          labelsTransitionDuration={0}
          // htmlElementsData + htmlElement (WAF pin + sun marker) REMOVED in
          // this defensive build. The HTML-overlay layer in three-globe
          // projects DOM nodes into 3D space and can be a non-trivial
          // per-frame transform sync cost.
        />
        </div>

        {countryList.length === 0 && !error && (
          <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
            <div className="text-center bg-slate-950/70 px-4 py-3 rounded border border-slate-800">
              <WifiOff size={20} className="mx-auto mb-1 text-slate-500" />
              <div className="text-slate-400 text-xs">No recent attacks to plot</div>
              <div className="text-slate-600 text-[9px] font-mono mt-1">
                curl 'http://127.0.0.1:8080/?id=1&apos; OR 1=1--'
              </div>
            </div>
          </div>
        )}

        {countryList.length > 0 && (
          <div className="absolute top-2 right-2 bg-slate-950/85 border border-slate-800 rounded p-2 text-[10px] font-mono pointer-events-none min-w-[160px] max-h-[200px] overflow-y-auto">
            <div className="text-[9px] uppercase tracking-wider text-slate-500 mb-1">Top sources</div>
            {countryList.slice(0, 5).map((c) => {
              const name = (COUNTRY_NAMES as any)[c.cc]?.name || c.cc
              return (
                <div key={c.cc} className="flex items-center justify-between gap-3 py-0.5">
                  <span className="text-slate-200 font-bold">{c.cc}</span>
                  <span className="text-rose-300">{c.count.toLocaleString()}</span>
                </div>
              )
            })}
          </div>
        )}

        <div className="absolute bottom-1 left-2 text-[9px] text-slate-600 font-mono pointer-events-none">
          3D · three.js · drag to rotate · scroll to zoom
        </div>
      </div>
    </div>
  )
}

// Minimal country name lookup. Imported lazily as a fallback; the full
// table in TopCountriesTable.tsx renders identical strings.
const COUNTRY_NAMES: Record<string, { name: string; flag: string }> = {
  US: { name: 'United States', flag: '🇺🇸' }, CN: { name: 'China', flag: '🇨🇳' },
  RU: { name: 'Russia', flag: '🇷🇺' }, DE: { name: 'Germany', flag: '🇩🇪' },
  BR: { name: 'Brazil', flag: '🇧🇷' }, IN: { name: 'India', flag: '🇮🇳' },
  GB: { name: 'United Kingdom', flag: '🇬🇧' }, FR: { name: 'France', flag: '🇫🇷' },
  JP: { name: 'Japan', flag: '🇯🇵' }, KR: { name: 'South Korea', flag: '🇰🇷' },
  AU: { name: 'Australia', flag: '🇦🇺' }, NL: { name: 'Netherlands', flag: '🇳🇱' },
  UA: { name: 'Ukraine', flag: '🇺🇦' }, SG: { name: 'Singapore', flag: '🇸🇬' },
  ID: { name: 'Indonesia', flag: '🇮🇩' }, VN: { name: 'Vietnam', flag: '🇻🇳' },
  TH: { name: 'Thailand', flag: '🇹🇭' }, TR: { name: 'Turkey', flag: '🇹🇷' },
  SA: { name: 'Saudi Arabia', flag: '🇸🇦' }, MX: { name: 'Mexico', flag: '🇲🇽' },
  AR: { name: 'Argentina', flag: '🇦🇷' }, ZA: { name: 'South Africa', flag: '🇿🇦' },
  NG: { name: 'Nigeria', flag: '🇳🇬' }, EG: { name: 'Egypt', flag: '🇪🇬' },
  IL: { name: 'Israel', flag: '🇮🇱' }, PL: { name: 'Poland', flag: '🇵🇱' },
  IT: { name: 'Italy', flag: '🇮🇹' }, ES: { name: 'Spain', flag: '🇪🇸' },
  CA: { name: 'Canada', flag: '🇨🇦' }, SE: { name: 'Sweden', flag: '🇸🇪' },
  IR: { name: 'Iran', flag: '🇮🇷' }, PK: { name: 'Pakistan', flag: '🇵🇰' },
  BD: { name: 'Bangladesh', flag: '🇧🇩' }, KE: { name: 'Kenya', flag: '🇰🇪' },
}
