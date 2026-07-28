import { useEffect, useState } from 'react'

// Standalone component so a once-per-second tick does NOT re-render the
// heavy GlobeMap scene. Lives in its own mini-tree of one <span>.
export default function UtcChip() {
  const [now, setNow] = useState(() => new Date())
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(id)
  }, [])
  return (
    <span className="text-[10px] text-sky-300 font-mono tabular-nums" suppressHydrationWarning>
      ☀ UTC {now.toISOString().slice(11, 19)}
    </span>
  )
}
