import { useEffect, useState } from 'react'

/**
 * useMinDisplay accepts either a number (intervalMs) or a boolean
 * (active flag). When a number, returns a tick that fires at most every
 * `intervalMs` milliseconds. When a boolean, returns the same value back
 * — useful for boolean skeleton-while-loading gates that don't need a
 * periodic update but want the same call shape.
 */
export function useMinDisplay(intervalMsOrActive: number | boolean = 60_000): number | boolean {
  if (typeof intervalMsOrActive === 'boolean') {
    return intervalMsOrActive
  }
  const [tick, setTick] = useState(0)
  useEffect(() => {
    const id = setInterval(() => setTick((t) => t + 1), intervalMsOrActive)
    return () => clearInterval(id)
  }, [intervalMsOrActive])
  return tick
}
