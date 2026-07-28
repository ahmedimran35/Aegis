import { useEffect, useRef, useState } from 'react'

interface Props {
  score: number // 0-100
  label?: string
}

export default function ThreatGauge({ score, label }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const animRef = useRef(0)
  const [dimensions, setDimensions] = useState({ w: 300, h: 200 })

  useEffect(() => {
    const container = containerRef.current
    if (!container) return
    const observer = new ResizeObserver((entries) => {
      const entry = entries[0]
      if (!entry) return
      const w = Math.min(Math.floor(entry.contentRect.width), 400)
      const h = Math.floor(w * (2 / 3))
      setDimensions({ w, h })
    })
    observer.observe(container)
    return () => observer.disconnect()
  }, [])

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const dpr = window.devicePixelRatio || 1
    const w = dimensions.w
    const h = dimensions.h
    canvas.width = w * dpr
    canvas.height = h * dpr
    canvas.style.width = w + 'px'
    canvas.style.height = h + 'px'
    ctx.scale(dpr, dpr)

    const cx = w / 2
    const cy = h * 0.58
    const r = 85
    let currentAngle = 0
    const targetAngle = (Math.min(Math.max(score, 0), 100) / 100) * Math.PI

    function getColor(val: number): string {
      if (val < 30) return '#10B981'
      if (val < 60) return '#F59E0B'
      return '#EF4444'
    }

    function getLabel(val: number): string {
      if (val < 15) return 'Secure'
      if (val < 30) return 'Low'
      if (val < 60) return 'Elevated'
      if (val < 80) return 'High'
      return 'Critical'
    }

    function draw() {
      if (!ctx) return
      ctx.clearRect(0, 0, w, h)

      currentAngle += (targetAngle - currentAngle) * 0.035
      const currentScore = (currentAngle / Math.PI) * 100
      const color = getColor(currentScore)

      // --- Background track ---
      const bgGrad = ctx.createLinearGradient(cx - r, cy, cx + r, cy)
      bgGrad.addColorStop(0, 'rgba(16, 185, 129, 0.08)')
      bgGrad.addColorStop(0.5, 'rgba(245, 158, 11, 0.08)')
      bgGrad.addColorStop(1, 'rgba(239, 68, 68, 0.08)')

      ctx.beginPath()
      ctx.arc(cx, cy, r, Math.PI, 0)
      ctx.strokeStyle = bgGrad
      ctx.lineWidth = 18
      ctx.lineCap = 'round'
      ctx.stroke()

      // Thin inner track
      ctx.beginPath()
      ctx.arc(cx, cy, r - 14, Math.PI, 0)
      ctx.strokeStyle = 'rgba(148, 163, 184, 0.06)'
      ctx.lineWidth = 1
      ctx.stroke()

      // --- Glow layer ---
      if (currentAngle > 0.01) {
        ctx.save()
        ctx.shadowColor = color
        ctx.shadowBlur = 20
        ctx.beginPath()
        ctx.arc(cx, cy, r, Math.PI, Math.PI + currentAngle)
        ctx.strokeStyle = color + '30'
        ctx.lineWidth = 28
        ctx.lineCap = 'round'
        ctx.stroke()
        ctx.restore()
      }

      // --- Value arc with gradient ---
      if (currentAngle > 0.01) {
        const arcGrad = ctx.createLinearGradient(
          cx - r, cy, cx - r + (2 * r * (currentAngle / Math.PI)), cy
        )
        arcGrad.addColorStop(0, '#10B981')
        if (currentScore > 30) arcGrad.addColorStop(0.3, '#F59E0B')
        if (currentScore > 60) arcGrad.addColorStop(0.6, '#EF4444')
        arcGrad.addColorStop(1, color)

        ctx.beginPath()
        ctx.arc(cx, cy, r, Math.PI, Math.PI + currentAngle)
        ctx.strokeStyle = arcGrad
        ctx.lineWidth = 18
        ctx.lineCap = 'round'
        ctx.stroke()
      }

      // --- Tick marks ---
      for (let i = 0; i <= 20; i++) {
        const angle = Math.PI + (i / 20) * Math.PI
        const isMajor = i % 5 === 0
        const inner = r + (isMajor ? 14 : 12)
        const outer = r + (isMajor ? 22 : 17)
        const x1 = cx + inner * Math.cos(angle)
        const y1 = cy + inner * Math.sin(angle)
        const x2 = cx + outer * Math.cos(angle)
        const y2 = cy + outer * Math.sin(angle)

        ctx.beginPath()
        ctx.moveTo(x1, y1)
        ctx.lineTo(x2, y2)
        ctx.strokeStyle = isMajor ? 'rgba(100, 116, 139, 0.35)' : 'rgba(148, 163, 184, 0.15)'
        ctx.lineWidth = isMajor ? 1.5 : 1
        ctx.lineCap = 'round'
        ctx.stroke()
      }

      // --- Zone labels on the arc ---
      const zones = [
        { pos: 0, label: '0', align: 'left' as CanvasTextAlign },
        { pos: 0.25, label: '25', align: 'center' as CanvasTextAlign },
        { pos: 0.5, label: '50', align: 'center' as CanvasTextAlign },
        { pos: 0.75, label: '75', align: 'center' as CanvasTextAlign },
        { pos: 1, label: '100', align: 'right' as CanvasTextAlign },
      ]
      zones.forEach(z => {
        const angle = Math.PI + z.pos * Math.PI
        const lx = cx + (r + 32) * Math.cos(angle)
        const ly = cy + (r + 32) * Math.sin(angle)
        ctx.font = '500 9px system-ui, sans-serif'
        ctx.fillStyle = 'rgba(148, 163, 184, 0.6)'
        ctx.textAlign = z.align
        ctx.textBaseline = 'middle'
        ctx.fillText(z.label, lx, ly)
      })

      // --- Needle ---
      if (currentAngle > 0.01) {
        const needleAngle = Math.PI + currentAngle
        const needleLen = r - 24

        // Needle shadow
        ctx.save()
        ctx.shadowColor = color + '40'
        ctx.shadowBlur = 8

        ctx.beginPath()
        ctx.moveTo(cx, cy)
        ctx.lineTo(cx + needleLen * Math.cos(needleAngle), cy + needleLen * Math.sin(needleAngle))
        ctx.strokeStyle = color
        ctx.lineWidth = 2.5
        ctx.lineCap = 'round'
        ctx.stroke()
        ctx.restore()
      }

      // --- Center hub ---
      const hubGrad = ctx.createRadialGradient(cx, cy, 0, cx, cy, 8)
      hubGrad.addColorStop(0, '#fff')
      hubGrad.addColorStop(1, color)

      ctx.beginPath()
      ctx.arc(cx, cy, 8, 0, Math.PI * 2)
      ctx.fillStyle = hubGrad
      ctx.fill()

      ctx.beginPath()
      ctx.arc(cx, cy, 4, 0, Math.PI * 2)
      ctx.fillStyle = '#fff'
      ctx.fill()

      // --- Score number ---
      ctx.font = 'bold 42px "DM Sans", system-ui, sans-serif'
      ctx.fillStyle = color
      ctx.textAlign = 'center'
      ctx.textBaseline = 'middle'
      ctx.fillText(Math.round(currentScore).toString(), cx, cy + 42)

      // --- Status label ---
      const statusText = getLabel(currentScore)
      ctx.font = '600 11px "DM Sans", system-ui, sans-serif'
      ctx.fillStyle = color + 'CC'
      ctx.fillText(statusText.toUpperCase(), cx, cy + 60)

      // --- Bottom label ---
      ctx.font = '400 10px "DM Sans", system-ui, sans-serif'
      ctx.fillStyle = '#94A3B8'
      ctx.fillText(label || 'Threat Level', cx, cy + 76)

      if (Math.abs(currentAngle - targetAngle) > 0.001) {
        animRef.current = requestAnimationFrame(draw)
      }
    }

    animRef.current = requestAnimationFrame(draw)
    return () => cancelAnimationFrame(animRef.current)
  }, [score, label, dimensions])

  return (
    <div ref={containerRef} className="w-full">
      <canvas
        ref={canvasRef}
        className="w-full h-auto"
        role="meter"
        aria-valuenow={score}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label="Threat level gauge"
      />
    </div>
  )
}
