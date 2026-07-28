import { lazy, Suspense } from 'react'
import { Loader2 } from 'lucide-react'
const Chart = lazy(() => import('./TrafficAreaChart'))
const Sk = () => <div className="h-[300px] flex items-center justify-center bg-ivory-50/30 rounded-md"><Loader2 size={16} className="animate-spin text-ink-400" /></div>
export default function TrafficAreaChartLazy(props: any) { return <Suspense fallback={<Sk />}><Chart {...props} /></Suspense> }
