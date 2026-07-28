import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'

interface TrafficPoint {
  time: string
  get: number
  post: number
  put: number
  delete: number
}

interface Props {
  data: TrafficPoint[]
}

const METHOD_COLORS = {
  get: '#3B82F6',
  post: '#10B981',
  put: '#F59E0B',
  delete: '#EF4444',
}

export default function RequestMethodsChart({ data }: Props) {
  if (!data || data.length === 0) {
    return (
      <div className="h-[200px] flex items-center justify-center">
        <p className="text-xs text-slate-400">No request data yet</p>
      </div>
    )
  }

  // Aggregate totals for summary
  const totals = data.reduce(
    (acc, d) => ({
      get: acc.get + (d.get || 0),
      post: acc.post + (d.post || 0),
      put: acc.put + (d.put || 0),
      delete: acc.delete + (d.delete || 0),
    }),
    { get: 0, post: 0, put: 0, delete: 0 }
  )

  const summaryData = [
    { method: 'GET', count: totals.get, color: METHOD_COLORS.get },
    { method: 'POST', count: totals.post, color: METHOD_COLORS.post },
    { method: 'PUT', count: totals.put, color: METHOD_COLORS.put },
    { method: 'DELETE', count: totals.delete, color: METHOD_COLORS.delete },
  ]

  return (
    <div>
      <div className="h-[200px]">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={summaryData} barSize={36}>
            <XAxis
              dataKey="method"
              tick={{ fontSize: 11, fill: '#94A3B8' }}
              stroke="#D4D1C6"
              axisLine={false}
              tickLine={false}
            />
            <YAxis
              tick={{ fontSize: 10, fill: '#94A3B8' }}
              stroke="#D4D1C6"
              axisLine={false}
              tickLine={false}
            />
            <Tooltip
              contentStyle={{
                background: '#fff',
                border: '1px solid #E8E6DF',
                borderRadius: '8px',
                fontSize: '12px',
                boxShadow: '0 4px 12px rgba(0,0,0,0.08)',
              }}
              formatter={(value: number) => [value.toLocaleString(), 'Requests']}
            />
            <Bar dataKey="count" radius={[6, 6, 0, 0]}>
              {summaryData.map((entry, i) => (
                <Cell key={i} fill={entry.color} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Legend */}
      <div className="flex justify-center gap-4 mt-3">
        {summaryData.map((d) => (
          <div key={d.method} className="flex items-center gap-1.5">
            <div className="w-2.5 h-2.5 rounded-sm" style={{ background: d.color }} />
            <span className="text-[10px] text-slate-500 font-medium">{d.method}</span>
            <span className="text-[10px] text-slate-400">{d.count.toLocaleString()}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
