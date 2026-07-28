import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts'

interface SevPoint { severity: string; count: number; fill: string }

export default function SeverityBarChart({ data }: { data: SevPoint[] }) {
  if (!data || data.length === 0) {
    return <div className="h-[240px] flex items-center justify-center"><p className="text-xs text-ink-400 font-mono">No severity data</p></div>
  }
  return (
    <div className="h-[240px]">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout="vertical">
          <CartesianGrid strokeDasharray="3 3" stroke="#E8E6DF" />
          <XAxis type="number" tick={{ fontSize: 10, fill: '#94A3B8' }} stroke="#D4D1C6" />
          <YAxis type="category" dataKey="severity" tick={{ fontSize: 11, fill: '#64748B', fontWeight: 500 }} width={70} stroke="#D4D1C6" />
          <Tooltip contentStyle={{ background: '#fff', border: '1px solid #E8E6DF', borderRadius: 8, fontSize: 11, boxShadow: '0 4px 12px rgba(0,0,0,0.08)' }} />
          <Bar dataKey="count" radius={[0, 6, 6, 0]} barSize={28}>
            {data.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
