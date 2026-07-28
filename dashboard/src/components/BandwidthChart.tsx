import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts'

interface BandwidthPoint {
  time: string
  bytes_out: number
  bytes_in: number
}

interface Props {
  data: BandwidthPoint[]
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  if (bytes < 1024) return bytes + ' B'
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB'
  return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB'
}

export default function BandwidthChart({ data }: Props) {
  if (!data || data.length === 0) {
    return (
      <div className="h-[240px] flex items-center justify-center">
        <p className="text-xs text-slate-400">No bandwidth data yet</p>
      </div>
    )
  }

  return (
    <div className="h-[240px]">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data}>
          <defs>
            <linearGradient id="gradOut" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.3} />
              <stop offset="95%" stopColor="#3B82F6" stopOpacity={0} />
            </linearGradient>
            <linearGradient id="gradIn" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#10B981" stopOpacity={0.3} />
              <stop offset="95%" stopColor="#10B981" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#E8E6DF" />
          <XAxis
            dataKey="time"
            tick={{ fontSize: 10, fill: '#94A3B8' }}
            tickFormatter={(v) => {
              try { return new Date(v).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) }
              catch { return '' }
            }}
            stroke="#D4D1C6"
          />
          <YAxis
            tick={{ fontSize: 10, fill: '#94A3B8' }}
            stroke="#D4D1C6"
            tickFormatter={(v) => formatBytes(v)}
          />
          <Tooltip
            contentStyle={{
              background: '#fff',
              border: '1px solid #E8E6DF',
              borderRadius: '8px',
              fontSize: '11px',
              boxShadow: '0 4px 12px rgba(0,0,0,0.08)',
            }}
            formatter={(value: number, name: string) => [formatBytes(value), name === 'bytes_out' ? 'Outbound' : 'Inbound']}
            labelFormatter={(v) => {
              try { return new Date(v).toLocaleTimeString() }
              catch { return String(v) }
            }}
          />
          <Legend
            formatter={(value: string) => value === 'bytes_out' ? 'Outbound' : 'Inbound'}
            iconType="circle"
            iconSize={8}
            wrapperStyle={{ fontSize: '11px', color: '#64748B' }}
          />
          <Area
            type="monotone"
            dataKey="bytes_out"
            stroke="#3B82F6"
            strokeWidth={2}
            fill="url(#gradOut)"
            name="bytes_out"
          />
          <Area
            type="monotone"
            dataKey="bytes_in"
            stroke="#10B981"
            strokeWidth={2}
            fill="url(#gradIn)"
            name="bytes_in"
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}
