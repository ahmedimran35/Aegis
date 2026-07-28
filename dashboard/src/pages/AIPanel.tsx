import { useState } from 'react'
import { Brain, Zap, AlertTriangle, Wand2, Search, CheckCircle, Globe, Sparkles, Shield } from 'lucide-react'
import StatusBadge from '../components/StatusBadge'
import { usePolling, apiPost, apiPut } from '../api/client'
import { useToast } from '../hooks/useToast'
import { SkeletonCard } from '../components/Skeleton'

interface AIStatus {
  nim: { available: boolean; success_rate: number; model: string; base_url: string }
  ollama: { available: boolean; success_rate: number; model: string; url: string }
  openrouter: { available: boolean; success_rate: number; model: string; url: string }
  active: string
}

interface Anomaly {
  id: number
  type: string
  severity: string
  description: string
  resolved: boolean
  created_at: string
}

interface AnalysisResult {
  summary: string
  findings: string[]
  suggestions: string[]
}

interface GeneratedRule {
  pattern: string
  match_type: string
  suggested_action: string
  confidence: number
  description: string
}

const providers = [
  { key: 'nim', label: 'NVIDIA NIM', sub: 'Cloud', icon: Brain, accent: 'blue', ringActive: 'ring-accent-500/30', badgeBg: 'bg-accent-50 text-accent-700 ring-accent-200', badgeLabel: 'Primary' },
  { key: 'openrouter', label: 'OpenRouter', sub: 'Cloud', icon: Globe, accent: 'violet', ringActive: 'ring-violet-500/30', badgeBg: 'bg-violet-50 text-violet-700 ring-violet-200', badgeLabel: 'Active' },
  { key: 'ollama', label: 'Ollama', sub: 'Local', icon: Zap, accent: 'emerald', ringActive: 'ring-emerald-500/30', badgeBg: 'bg-emerald-50 text-emerald-700 ring-emerald-200', badgeLabel: 'Fallback' },
] as const

const accentStyles = {
  blue: { bg: 'bg-accent-50', icon: 'text-accent-600', gradient: 'from-accent-500 to-blue-400', orb: 'from-accent-500/8', bar: 'from-blue-500/30 via-cyan-500/20' },
  violet: { bg: 'bg-violet-50', icon: 'text-violet-600', gradient: 'from-violet-500 to-purple-400', orb: 'from-violet-500/8', bar: 'from-violet-500/30 via-purple-500/20' },
  emerald: { bg: 'bg-emerald-50', icon: 'text-emerald-600', gradient: 'from-emerald-500 to-green-400', orb: 'from-emerald-500/8', bar: 'from-emerald-500/30 via-teal-500/20' },
} as const

export default function AIPanel() {
  const { data: aiStatus, error: aiError } = usePolling<AIStatus>('/ai/status', 5000)
  const { data: anomalies, refetch: refetchAnomalies } = usePolling<Anomaly[]>('/anomalies', 10000)

  const [analyzeQuery, setAnalyzeQuery] = useState('')
  const [analyzeResult, setAnalyzeResult] = useState<AnalysisResult | null>(null)
  const [analyzeLoading, setAnalyzeLoading] = useState(false)

  const [rulePrompt, setRulePrompt] = useState('')
  const [ruleResult, setRuleResult] = useState<GeneratedRule | null>(null)
  const [ruleLoading, setRuleLoading] = useState(false)

  const handleAnalyze = async () => {
    if (!analyzeQuery.trim()) return
    setAnalyzeLoading(true)
    try {
      const result = await apiPost<AnalysisResult>('/ai/analyze', { query: analyzeQuery })
      setAnalyzeResult(result)
    } catch (e) {
      useToast.getState().error(e instanceof Error ? e.message : 'Error')
    } finally {
      setAnalyzeLoading(false)
    }
  }

  const handleGenerateRule = async () => {
    if (!rulePrompt.trim()) return
    setRuleLoading(true)
    try {
      const result = await apiPost<GeneratedRule>('/ai/generate-rule', {
        examples: [rulePrompt],
        category: 'custom',
        count: 1,
      })
      setRuleResult(result)
    } catch (e) {
      useToast.getState().error(e instanceof Error ? e.message : 'Error')
    } finally {
      setRuleLoading(false)
    }
  }

  const handleResolveAnomaly = async (id: number) => {
    try {
      await apiPut(`/anomalies/${id}/resolve`, {})
      refetchAnomalies()
    } catch (e) {
      useToast.getState().error(e instanceof Error ? e.message : 'Error')
    }
  }

  const ratePercent = (rate: number | undefined | null) => `${((rate ?? 0) * 100).toFixed(1)}%`

  return (
    <div className="space-y-5 section-stagger">
      {aiError && <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-sm text-red-700">{aiError}</div>}
      {/* Header */}
      <div className="animate-fade-in">
        <h1 className="text-2xl font-bold tracking-tight bg-gradient-to-r from-slate-900 via-accent-700 to-slate-900 bg-clip-text text-transparent">
          AI Panel
        </h1>
        <p className="text-xs text-slate-400 mt-1 flex items-center gap-2">
          <span className="inline-block w-1 h-1 rounded-full bg-accent-500 animate-pulse-dot" />
          AI-powered threat analysis and rule generation
        </p>
      </div>

      {/* Provider health cards */}
      {!aiStatus ? (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {Array.from({ length: 3 }).map((_, i) => <SkeletonCard key={i} />)}
        </div>
      ) : (
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {providers.map((p) => {
          const provider = aiStatus?.[p.key as keyof AIStatus] as { available: boolean; success_rate: number; model: string } | undefined
          const isActive = aiStatus?.active === p.key
          const s = accentStyles[p.accent]
          const Icon = p.icon
          return (
            <div key={p.key} className={`card-glow p-5 relative overflow-hidden transition-all duration-300 ${isActive ? `ring-2 ${p.ringActive}` : ''}`}>
              <div className={`absolute top-0 left-0 w-full h-0.5 bg-gradient-to-r ${s.bar} to-transparent`} />
              <div className={`absolute -top-6 -right-6 w-20 h-20 rounded-full bg-gradient-to-br ${s.orb} to-transparent blur-xl pointer-events-none`} />
              <div className="flex items-center justify-between mb-4 relative">
                <div className="flex items-center gap-3">
                  <div className={`flex items-center justify-center w-10 h-10 rounded-xl ${s.bg} transition-all duration-300`}>
                    <Icon size={18} className={s.icon} strokeWidth={1.8} />
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-slate-900">{p.label}</h3>
                    <p className="text-[11px] text-slate-400">{p.sub} · {provider?.model || 'Not configured'}</p>
                  </div>
                </div>
                {isActive && (
                  <span className={`badge ${p.badgeBg} ring-1 text-[10px] font-semibold`}>{p.badgeLabel}</span>
                )}
              </div>
              <div className="grid grid-cols-2 gap-4 relative">
                <div>
                  <span className="text-[10px] font-semibold uppercase tracking-widest text-slate-400">Status</span>
                  <div className="flex items-center gap-1.5 mt-1.5">
                    <div className={`w-2 h-2 rounded-full ${provider?.available ? 'bg-emerald-500 animate-pulse' : 'bg-red-500'}`} />
                    <span className="text-sm font-medium text-slate-700">
                      {provider?.available ? 'Online' : 'Offline'}
                    </span>
                  </div>
                </div>
                <div>
                  <span className="text-[10px] font-semibold uppercase tracking-widest text-slate-400">Success Rate</span>
                  <div className="font-mono text-lg font-bold text-slate-900 mt-0.5 number-reveal">
                    {provider ? ratePercent(provider.success_rate) : '—'}
                  </div>
                </div>
              </div>
            </div>
          )
        })}
      </div>
      )}

      {/* Log Analyzer */}
      <div className="card-glow p-5 relative overflow-hidden">
        <div className="absolute top-0 left-0 w-full h-0.5 bg-gradient-to-r from-blue-500/30 via-cyan-500/20 to-transparent" />
        <div className="absolute top-0 right-0 w-24 h-24 bg-gradient-to-bl from-blue-500/5 to-transparent rounded-bl-full pointer-events-none" />
        <h2 className="text-sm font-semibold text-slate-700 mb-4 flex items-center gap-2 relative">
          <div className="w-6 h-6 rounded-lg bg-blue-50 flex items-center justify-center">
            <Search size={13} className="text-blue-500" />
          </div>
          Log Analyzer
        </h2>
        <div className="flex flex-col sm:flex-row gap-3 mb-4 relative">
          <input
            value={analyzeQuery}
            onChange={(e) => setAnalyzeQuery(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleAnalyze()}
            className="input-field flex-1"
            placeholder="Ask about your traffic: 'What IPs are attacking most frequently?'"
          />
          <button onClick={handleAnalyze} disabled={analyzeLoading} className="btn-primary">
            <Sparkles size={14} />
            {analyzeLoading ? 'Analyzing...' : 'Analyze'}
          </button>
        </div>
        {analyzeResult && (
          <div className="bg-ivory-50/80 rounded-xl border border-ivory-200 p-4 animate-fade-in relative">
            <p className="text-sm text-slate-800 mb-3 leading-relaxed">{analyzeResult.summary}</p>
            {analyzeResult.findings.length > 0 && (
              <div className="mb-3">
                <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-widest">Findings</span>
                <ul className="mt-2 space-y-1.5">
                  {analyzeResult.findings.map((f, i) => (
                    <li key={i} className="text-sm text-slate-600 flex items-start gap-2">
                      <span className="w-1.5 h-1.5 rounded-full bg-amber-400 mt-1.5 shrink-0" /> {f}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {analyzeResult.suggestions.length > 0 && (
              <div>
                <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-widest">Suggestions</span>
                <ul className="mt-2 space-y-1.5">
                  {analyzeResult.suggestions.map((s, i) => (
                    <li key={i} className="text-sm text-slate-600 flex items-start gap-2">
                      <span className="w-1.5 h-1.5 rounded-full bg-accent-500 mt-1.5 shrink-0" /> {s}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Rule Generator */}
      <div className="card-glow p-5 relative overflow-hidden">
        <div className="absolute top-0 left-0 w-full h-0.5 bg-gradient-to-r from-violet-500/30 via-purple-500/20 to-transparent" />
        <div className="absolute bottom-0 left-0 w-28 h-28 bg-gradient-to-tr from-violet-500/5 to-transparent rounded-tr-full pointer-events-none" />
        <h2 className="text-sm font-semibold text-slate-700 mb-4 flex items-center gap-2 relative">
          <div className="w-6 h-6 rounded-lg bg-violet-50 flex items-center justify-center">
            <Wand2 size={13} className="text-violet-500" />
          </div>
          AI Rule Generator
        </h2>
        <div className="flex flex-col sm:flex-row gap-3 mb-4 relative">
          <input
            value={rulePrompt}
            onChange={(e) => setRulePrompt(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleGenerateRule()}
            className="input-field flex-1"
            placeholder="Describe the attack pattern: 'SQL injection via UNION SELECT in query params'"
          />
          <button onClick={handleGenerateRule} disabled={ruleLoading} className="btn-primary">
            <Sparkles size={14} />
            {ruleLoading ? 'Generating...' : 'Generate'}
          </button>
        </div>
        {ruleResult && (
          <div className="bg-ivory-50/80 rounded-xl border border-ivory-200 p-4 animate-fade-in relative">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-3">
              <div>
                <span className="text-[10px] font-semibold uppercase tracking-widest text-slate-400">Pattern</span>
                <p className="font-mono text-sm text-slate-800 mt-1.5 break-all leading-relaxed">{ruleResult.pattern}</p>
              </div>
              <div>
                <span className="text-[10px] font-semibold uppercase tracking-widest text-slate-400">Match Type</span>
                <p className="text-sm text-slate-800 mt-1.5">{ruleResult.match_type}</p>
              </div>
              <div>
                <span className="text-[10px] font-semibold uppercase tracking-widest text-slate-400">Action</span>
                <div className="mt-1.5">
                  <StatusBadge status={ruleResult.suggested_action === 'block' ? 'blocked' : ruleResult.suggested_action === 'allow' ? 'allowed' : 'pending'} />
                </div>
              </div>
              <div>
                <span className="text-[10px] font-semibold uppercase tracking-widest text-slate-400">Confidence</span>
                <p className="font-mono text-sm font-bold text-slate-800 mt-1.5">{((ruleResult.confidence ?? 0) * 100).toFixed(0)}%</p>
              </div>
            </div>
            <p className="text-sm text-slate-600 leading-relaxed">{ruleResult.description}</p>
          </div>
        )}
      </div>

      {/* Anomalies */}
      <div className="card-glow p-5 relative overflow-hidden">
        <div className="absolute top-0 left-0 w-full h-0.5 bg-gradient-to-r from-amber-500/30 via-orange-500/20 to-transparent" />
        <h2 className="text-sm font-semibold text-slate-700 mb-4 flex items-center gap-2 relative">
          <div className="w-6 h-6 rounded-lg bg-amber-50 flex items-center justify-center">
            <AlertTriangle size={13} className="text-amber-500" />
          </div>
          Anomalies
        </h2>
        {!anomalies ? (
          <div className="space-y-2.5">
            {Array.from({ length: 3 }).map((_, i) => (
              <div key={i} className="h-16 bg-ivory-100 rounded-xl animate-pulse" />
            ))}
          </div>
        ) : anomalies.length === 0 ? (
          <div className="text-center py-8 relative">
            <div className="w-12 h-12 rounded-full bg-emerald-50 flex items-center justify-center mx-auto mb-3">
              <Shield size={20} className="text-emerald-400" />
            </div>
            <p className="text-sm text-slate-400">No anomalies detected</p>
          </div>
        ) : (
          <div className="space-y-2.5 relative">
            {anomalies.map((a) => (
              <div key={a.id} className={`flex items-center justify-between p-3.5 rounded-xl border transition-all duration-200 ${a.resolved ? 'bg-ivory-50/60 border-ivory-200 opacity-60' : 'bg-white border-amber-200/60 hover:border-amber-300 hover:shadow-sm'}`}>
                <div className="flex items-center gap-3">
                  <StatusBadge status={a.severity} />
                  <div>
                    <p className="text-sm font-medium text-slate-800">{a.description}</p>
                    <p className="text-[11px] text-slate-400 mt-0.5">{a.type} · {new Date(a.created_at).toLocaleString()}</p>
                  </div>
                </div>
                {!a.resolved && (
                  <button onClick={() => handleResolveAnomaly(a.id)} className="btn-secondary text-xs py-1.5 px-3">
                    <CheckCircle size={14} /> Resolve
                  </button>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
