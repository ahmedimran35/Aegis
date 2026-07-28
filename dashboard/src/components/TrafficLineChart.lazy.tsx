import { lazy, Suspense } from 'react'
import { Loader2 } from 'lucide-react'
const Chart = lazy(() => import('./TrafficLineChart'))
const Sk = () => <div className="h-[220px] flex items-center justify-center bg-ivory-50/30 rounded-md"><Loader2 size={16} className="animate-spin text-ink-400" /></div>
export default function TrafficLineChartLazy(props: any) { return <Suspense fallback={<Sk />}><Chart {...props} /></Suspense> }
