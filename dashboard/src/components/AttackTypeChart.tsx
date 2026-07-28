import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'

interface AttackType {
  type: string
  count: number
}

interface Props {
  data: AttackType[]
}

const ATTACK_COLORS: Record<string, string> = {
  'SQL Injection': '#EF4444',
  'XSS': '#F59E0B',
  'RCE': '#DC2626',
  'Path Traversal': '#8B5CF6',
  'SSRF': '#EC4899',
  'CRLF Injection': '#F97316',
  'XXE': '#6366F1',
  'Command Injection': '#BE185D',
  'bot': '#64748B',
  'malicious': '#EF4444',
  'suspicious': '#F59E0B',
  'unknown': '#94A3B8',
}

function getColor(type: string): string {
  for (const [key, color] of Object.entries(ATTACK_COLORS)) {
    if (type.toLowerCase().includes(key.toLowerCase())) return color
  }
  // Hash string to color
  let hash = 0
  for (let i = 0; i < type.length; i++) {
    hash = type.charCodeAt(i) + ((hash << 5) - hash)
  }
  const colors = ['#3B82F6', '#10B981', '#8B5CF6', '#EC4899', '#F59E0B', '#06B6D4']
  return colors[Math.abs(hash) % colors.length]
}

function truncateLabel(label: string, maxLen: number): string {
  if (label.length <= maxLen) return label
  return label.slice(0, maxLen - 1) + '...'
}

export default function AttackTypeChart({ data }: Props) {
  if (data.length === 0) {
    return (
      <div className="h-[260px] flex items-center justify-center">
        <p className="text-xs text-slate-400">No attack data yet</p>
      </div>
    )
  }

  const chartData = data.slice(0, 8).map(d => ({
    ...d,
    shortType: truncateLabel(d.type, 14),
    color: getColor(d.type),
  }))

  return (
    <div>
      <div className="h-[220px]">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={chartData} layout="vertical" barSize={18}>
            <XAxis
              type="number"
              tick={{ fontSize: 10, fill: '#94A3B8' }}
              axisLine={false}
              tickLine={false}
            />
            <YAxis
              type="category"
              dataKey="shortType"
              tick={{ fontSize: 11, fill: '#64748B' }}
              width={100}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip
              contentStyle={{
                background: '#fff',
                border: '1px solid #E8E6DF',
                borderRadius: '8px',
                fontSize: '11px',
                boxShadow: '0 4px 12px rgba(0,0,0,0.08)',
              }}
              formatter={(value: number, _name: string, props: { payload?: { type?: string } }) => [
                value.toLocaleString() + ' blocked',
                props.payload?.type || 'Attack',
              ]}
            />
            <Bar dataKey="count" radius={[0, 6, 6, 0]}>
              {chartData.map((entry, i) => (
                <Cell key={i} fill={entry.color} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
      {data.length > 8 && (
        <p className="text-xs text-slate-400 mt-2 text-center">+{data.length - 8} more</p>
      )}
    </div>
  )
}
