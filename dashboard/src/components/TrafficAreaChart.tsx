import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts'

export default function TrafficAreaChart({ data }: { data: any[] }) {
  if (!data || data.length === 0) {
    return <div className="h-[300px] flex items-center justify-center"><p className="text-xs text-ink-400 font-mono">No traffic data yet</p></div>
  }
  return (
    <div className="h-[300px]">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data}>
          <defs>
            <linearGradient id="tac-colorGet" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.3} />
              <stop offset="95%" stopColor="#3B82F6" stopOpacity={0} />
            </linearGradient>
            <linearGradient id="tac-colorPost" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#10B981" stopOpacity={0.3} />
              <stop offset="95%" stopColor="#10B981" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#E8E6DF" />
          <XAxis dataKey="timestamp" tick={{ fontSize: 10, fill: '#94A3B8' }}
            tickFormatter={(v) => { try { return new Date(v).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) } catch { return '' } }} stroke="#D4D1C6" />
          <YAxis tick={{ fontSize: 10, fill: '#94A3B8' }} stroke="#D4D1C6" />
          <Tooltip contentStyle={{ background: '#fff', border: '1px solid #E8E6DF', borderRadius: 8, fontSize: 11, boxShadow: '0 4px 12px rgba(0,0,0,0.08)' }}
            labelFormatter={(v) => { try { return new Date(v as string).toLocaleTimeString() } catch { return String(v) } }} />
          <Legend wrapperStyle={{ fontSize: 10, fontFamily: 'JetBrains Mono, monospace' }} />
          <Area type="monotone" dataKey="get" stackId="1" stroke="#3B82F6" fill="url(#tac-colorGet)" strokeWidth={2} name="GET" />
          <Area type="monotone" dataKey="post" stackId="1" stroke="#10B981" fill="url(#tac-colorPost)" strokeWidth={2} name="POST" />
          <Area type="monotone" dataKey="put" stackId="1" stroke="#F59E0B" fill="#F59E0B22" strokeWidth={1.5} name="PUT" />
          <Area type="monotone" dataKey="delete" stackId="1" stroke="#EF4444" fill="#EF444422" strokeWidth={1.5} name="DELETE" />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}
