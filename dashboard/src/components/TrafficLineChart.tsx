import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts'

interface Props { data: any[] }

export default function TrafficLineChart({ data }: Props) {
  if (!data || data.length === 0) {
    return <div className="h-[260px] flex items-center justify-center"><p className="text-xs text-ink-400 font-mono">No traffic data yet</p></div>
  }
  return (
    <div className="h-[260px]">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data}>
          <CartesianGrid strokeDasharray="3 3" stroke="#E8E6DF" />
          <XAxis dataKey="time" tick={{ fontSize: 10, fill: '#94A3B8' }}
            tickFormatter={(v) => { try { return new Date(v).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) } catch { return '' } }} stroke="#D4D1C6" />
          <YAxis tick={{ fontSize: 10, fill: '#94A3B8' }} stroke="#D4D1C6" />
          <Tooltip contentStyle={{ background: '#fff', border: '1px solid #E8E6DF', borderRadius: 8, fontSize: 11, boxShadow: '0 4px 12px rgba(0,0,0,0.08)' }}
            labelFormatter={(v) => { try { return new Date(v as string).toLocaleTimeString() } catch { return String(v) } }} />
          <Legend wrapperStyle={{ fontSize: 10, fontFamily: 'JetBrains Mono, monospace' }} />
          <Line type="monotone" dataKey="get" stroke="#3B82F6" strokeWidth={2} dot={false} name="GET" />
          <Line type="monotone" dataKey="post" stroke="#10B981" strokeWidth={2} dot={false} name="POST" />
          <Line type="monotone" dataKey="put" stroke="#F59E0B" strokeWidth={1.5} dot={false} name="PUT" />
          <Line type="monotone" dataKey="delete" stroke="#EF4444" strokeWidth={1.5} dot={false} name="DELETE" />
        </LineChart>
      </ResponsiveContainer>
    </div>
  )
}
