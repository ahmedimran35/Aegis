import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts'

interface Slice { name: string; value: number; color: string }

export default function ThreatPieChart({ data }: { data: Slice[] }) {
  if (data.length === 0 || data.every(d => d.value === 0)) {
    return <div className="h-[220px] flex items-center justify-center"><p className="text-xs text-ink-400 font-mono">No threats yet</p></div>
  }
  return (
    <div className="h-[220px]">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie data={data} cx="50%" cy="50%" innerRadius={60} outerRadius={90} paddingAngle={3} dataKey="value">
            {data.map((entry, i) => <Cell key={i} fill={entry.color} />)}
          </Pie>
          <Tooltip contentStyle={{ background: '#fff', border: '1px solid #E8E6DF', borderRadius: 8, fontSize: 11 }} />
        </PieChart>
      </ResponsiveContainer>
    </div>
  )
}
