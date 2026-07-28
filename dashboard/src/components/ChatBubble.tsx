import { useState, useRef, useEffect } from 'react'
import { MessageCircle, X, Send, Loader2, Bot, Maximize2, Minimize2, Sparkles } from 'lucide-react'
import { apiPost } from '../api/client'

interface ChatMessage {
  role: 'user' | 'assistant'
  content: string
}

// XSS-safe markdown rendering. We never unescape HTML entities before
// applying markdown replacements — the previous version reversed the
// escape then ran regex substitutions, which allowed attacker-controlled
// content (e.g. assistant responses, or prompt-injected user input that
// became assistant output) to inject markup. Instead, every block element
// is rendered as a React element, never via dangerouslySetInnerHTML, and
// inline formatting is also element-based.
import { Fragment, ReactNode } from 'react'

function renderInline(text: string, keyPrefix: string): ReactNode[] {
  // Tokenize inline markdown: `code`, **bold**, *italic*. Order matters:
  // bold before italic so ** doesn't get half-consumed.
  const out: ReactNode[] = []
  let rest = text
  let i = 0
  const re = /(`[^`\n]+`|\*\*[^*\n]+\*\*|\*[^*\n]+\*)/g
  let m: RegExpExecArray | null
  let lastIdx = 0
  while ((m = re.exec(rest)) !== null) {
    if (m.index > lastIdx) {
      out.push(<Fragment key={`${keyPrefix}-t${i++}`}>{rest.slice(lastIdx, m.index)}</Fragment>)
    }
    const tok = m[0]
    if (tok.startsWith('`')) {
      out.push(
        <code key={`${keyPrefix}-c${i++}`} className="bg-accent-50/80 px-1.5 py-0.5 rounded text-xs font-mono text-accent-700">
          {tok.slice(1, -1)}
        </code>,
      )
    } else if (tok.startsWith('**')) {
      out.push(
        <strong key={`${keyPrefix}-b${i++}`} className="font-semibold text-slate-900">
          {tok.slice(2, -2)}
        </strong>,
      )
    } else if (tok.startsWith('*')) {
      out.push(
        <em key={`${keyPrefix}-i${i++}`}>{tok.slice(1, -1)}</em>,
      )
    }
    lastIdx = re.lastIndex
  }
  if (lastIdx < rest.length) {
    out.push(<Fragment key={`${keyPrefix}-t${i++}`}>{rest.slice(lastIdx)}</Fragment>)
  }
  return out
}

function renderContent(text: string): ReactNode {
  const lines = text.split('\n')
  const blocks: ReactNode[] = []
  let i = 0
  let blockKey = 0

  while (i < lines.length) {
    const line = lines[i]

    // Fenced code block (```lang ... ```)
    if (line.startsWith('```')) {
      const codeLines: string[] = []
      i++
      while (i < lines.length && !lines[i].startsWith('```')) {
        codeLines.push(lines[i])
        i++
      }
      i++ // skip closing ```
      blocks.push(
        <pre key={`b${blockKey++}`} className="bg-slate-900 text-slate-100 rounded-lg p-3 my-2 text-xs overflow-x-auto font-mono">
          <code>{codeLines.join('\n')}</code>
        </pre>,
      )
      continue
    }

    // Heading
    if (line.startsWith('### ')) {
      blocks.push(<h3 key={`b${blockKey++}`} className="text-sm font-semibold text-slate-800 mt-3 mb-1">{renderInline(line.slice(4), `b${blockKey}`)}</h3>)
      i++; continue
    }
    if (line.startsWith('## ')) {
      blocks.push(<h2 key={`b${blockKey++}`} className="text-sm font-bold text-slate-900 mt-3 mb-1.5 border-b border-ivory-200 pb-1">{renderInline(line.slice(3), `b${blockKey}`)}</h2>)
      i++; continue
    }
    if (line.startsWith('# ')) {
      blocks.push(<h1 key={`b${blockKey++}`} className="text-base font-bold text-slate-900 mt-3 mb-1.5">{renderInline(line.slice(2), `b${blockKey}`)}</h1>)
      i++; continue
    }

    // Horizontal rule
    if (/^---+$/.test(line.trim())) {
      blocks.push(<hr key={`b${blockKey++}`} className="border-ivory-200 my-3" />)
      i++; continue
    }

    // Blockquote
    if (line.startsWith('&gt; ') || line.startsWith('> ')) {
      const content = line.startsWith('&gt; ') ? line.slice(5) : line.slice(2)
      blocks.push(
        <div key={`b${blockKey++}`} className="border-l-[3px] border-amber-400 bg-amber-50/60 pl-3 py-1.5 my-2 text-sm text-amber-900 rounded-r-lg">
          {renderInline(content, `b${blockKey}`)}
        </div>,
      )
      i++; continue
    }

    // Unordered list
    if (/^\s*-\s+/.test(line)) {
      const items: string[] = []
      while (i < lines.length && /^\s*-\s+/.test(lines[i])) {
        items.push(lines[i].replace(/^\s*-\s+/, ''))
        i++
      }
      blocks.push(
        <ul key={`b${blockKey++}`} className="ml-3 list-disc text-slate-700 leading-relaxed">
          {items.map((it, k) => <li key={k}>{renderInline(it, `b${blockKey}-li${k}`)}</li>)}
        </ul>,
      )
      continue
    }

    // Ordered list
    if (/^\s*\d+\.\s+/.test(line)) {
      const items: string[] = []
      while (i < lines.length && /^\s*\d+\.\s+/.test(lines[i])) {
        items.push(lines[i].replace(/^\s*\d+\.\s+/, ''))
        i++
      }
      blocks.push(
        <ol key={`b${blockKey++}`} className="ml-3 list-decimal text-slate-700 leading-relaxed">
          {items.map((it, k) => <li key={k}>{renderInline(it, `b${blockKey}-li${k}`)}</li>)}
        </ol>,
      )
      continue
    }

    // Empty line — paragraph break
    if (line.trim() === '') {
      i++; continue
    }

    // Default: paragraph (consecutive non-blank, non-block lines)
    const para: string[] = [line]
    i++
    while (i < lines.length && lines[i].trim() !== '' && !/^[#>\-\d`]|```/.test(lines[i])) {
      para.push(lines[i])
      i++
    }
    blocks.push(
      <p key={`b${blockKey++}`} className="mt-2">
        {renderInline(para.join('\n'), `b${blockKey}`)}
      </p>,
    )
  }

  return <>{blocks}</>
}

const QUICK_ACTIONS = [
  { label: 'Top threats now', icon: '!!' },
  { label: 'Block an IP', icon: 'IP' },
  { label: 'Add a security rule', icon: '+' },
  { label: 'Security report', icon: 'R' },
  { label: 'Check anomalies', icon: '?' },
  { label: 'Traffic overview', icon: '#' },
]

export default function ChatBubble() {
  const [open, setOpen] = useState(false)
  const [expanded, setExpanded] = useState(false)
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      role: 'assistant',
      content: `**Welcome — I'm your Aegis Security Assistant.**

I have **real-time access** to your Aegis traffic, threats, rules, anomalies, and all security layers. I can help you:

- **Analyze threats** — see what attacks are happening right now
- **Block IPs** — identify and block malicious actors
- **Manage rules** — create, explain, and optimize Aegis rules
- **Investigate incidents** — step-by-step forensic analysis
- **Security posture** — assess your protection gaps
- **Explain anything** — any Aegis feature, attack type, or security concept

Ask me anything — I have full visibility into your security data.`,
    },
  ])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const messagesEndRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, loading])

  useEffect(() => {
    if (open) inputRef.current?.focus()
  }, [open])

  const handleSend = async (text?: string) => {
    const msg = text || input.trim()
    if (!msg || loading) return
    if (!text) setInput('')

    const userMsg: ChatMessage = { role: 'user', content: msg }
    const newMessages = [...messages, userMsg]
    setMessages(newMessages)
    setLoading(true)

    try {
      const history = newMessages.slice(-11, -1).map(m => ({
        role: m.role,
        content: m.content,
      }))

      const res = await apiPost<{ answer: string }>('/ai/chat', {
        message: msg,
        history,
      })
      setMessages(prev => [...prev, { role: 'assistant', content: res.answer }])
    } catch (e) {
      setMessages(prev => [
        ...prev,
        { role: 'assistant', content: e instanceof Error ? e.message : 'Failed to get response. Check AI provider status in Settings.' },
      ])
    } finally {
      setLoading(false)
    }
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }

  const size = expanded ? 'w-[640px] h-[750px]' : 'w-[420px] h-[580px]'

  return (
    <>
      {/* Floating button */}
      {!open && (
        <button
          onClick={() => setOpen(true)}
          className="fixed bottom-6 right-6 z-30 w-14 h-14 rounded-full bg-gradient-to-br from-accent-500 to-accent-700 text-white shadow-xl shadow-accent-500/25 hover:shadow-2xl hover:shadow-accent-500/30 transition-all duration-300 hover:scale-105 flex items-center justify-center group"
          title="Aegis Security Assistant"
        >
          <div className="absolute inset-0 rounded-full bg-gradient-to-br from-accent-400 to-accent-600 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
          <MessageCircle size={22} className="relative z-10 group-hover:scale-110 transition-transform duration-200" />
          <span className="absolute -top-0.5 -right-0.5 w-4 h-4 bg-emerald-500 rounded-full border-[2.5px] border-white shadow-sm">
            <span className="absolute inset-0 rounded-full bg-emerald-400 animate-ping opacity-40" />
          </span>
        </button>
      )}

      {/* Chat window */}
      {open && (
        <div className={`fixed bottom-6 right-6 z-30 ${size} flex flex-col overflow-hidden transition-all duration-300 rounded-2xl shadow-2xl shadow-slate-900/15 border border-ivory-300/80 bg-white`}
          style={{ animation: 'slide-up 0.25s cubic-bezier(0.16, 1, 0.3, 1)' }}>
          {/* Header */}
          <div className="relative shrink-0">
            <div className="absolute inset-0 bg-gradient-to-r from-accent-600 via-accent-600 to-accent-700" />
            <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top_right,rgba(255,255,255,0.12),transparent_60%)]" />
            <div className="relative flex items-center justify-between px-4 py-3">
              <div className="flex items-center gap-2.5">
                <div className="w-9 h-9 rounded-xl bg-white/15 backdrop-blur-sm flex items-center justify-center ring-1 ring-white/10">
                  <Bot size={17} className="text-white" />
                </div>
                <div>
                  <span className="text-sm font-semibold text-white">Aegis Security Assistant</span>
                  <p className="text-[10px] text-white/60 flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                    Live data + full Aegis control
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-0.5">
                <button
                  onClick={() => setExpanded(!expanded)}
                  className="p-1.5 rounded-lg hover:bg-white/15 transition-colors text-white/70 hover:text-white"
                  title={expanded ? 'Minimize' : 'Maximize'}
                >
                  {expanded ? <Minimize2 size={14} /> : <Maximize2 size={14} />}
                </button>
                <button
                  onClick={() => setOpen(false)}
                  className="p-1.5 rounded-lg hover:bg-white/15 transition-colors text-white/70 hover:text-white"
                  title="Close"
                >
                  <X size={14} />
                </button>
              </div>
            </div>
          </div>

          {/* Messages */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4 scrollbar-thin">
            {messages.map((msg, i) => (
              <div key={i} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'} animate-fade-in`}
                style={{ animationDuration: '0.2s' }}>
                {msg.role === 'assistant' && (
                  <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-accent-50 to-accent-100 flex items-center justify-center mr-2 mt-0.5 shrink-0 ring-1 ring-accent-200/40">
                    <Bot size={13} className="text-accent-600" />
                  </div>
                )}
                <div
                  className={`max-w-[85%] rounded-2xl px-4 py-3 text-[13px] leading-relaxed ${
                    msg.role === 'user'
                      ? 'bg-gradient-to-br from-accent-600 to-accent-700 text-white rounded-br-md shadow-sm shadow-accent-500/10'
                      : 'bg-ivory-50/80 text-slate-800 rounded-bl-md border border-ivory-200/80'
                  }`}
                >
                  {/* P-FIX: render the assistant content as React elements,
                      not via dangerouslySetInnerHTML. The renderContent()
                      function returns a ReactNode tree of safe components
                      (no unescaped HTML). This prevents prompt-injected or
                      XSS-laden assistant responses from injecting markup. */}
                  {renderContent(msg.content)}
                </div>
              </div>
            ))}
            {loading && (
              <div className="flex justify-start animate-fade-in" style={{ animationDuration: '0.2s' }}>
                <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-accent-50 to-accent-100 flex items-center justify-center mr-2 shrink-0 ring-1 ring-accent-200/40">
                  <Bot size={13} className="text-accent-600" />
                </div>
                <div className="bg-ivory-50/80 rounded-2xl rounded-bl-md px-4 py-3 border border-ivory-200/80">
                  <div className="flex items-center gap-2">
                    <Loader2 size={14} className="animate-spin text-accent-500" />
                    <span className="text-xs text-slate-500">Analyzing your Aegis data...</span>
                  </div>
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Quick actions */}
          <div className="px-3 py-2 border-t border-ivory-100 flex gap-1.5 overflow-x-auto shrink-0 scrollbar-thin">
            {QUICK_ACTIONS.map(q => (
              <button
                key={q.label}
                onClick={() => handleSend(q.label)}
                disabled={loading}
                className="px-3 py-1.5 text-[11px] font-medium bg-ivory-50 text-slate-500 rounded-full border border-ivory-200/60 hover:bg-accent-50 hover:text-accent-700 hover:border-accent-200/60 transition-all duration-200 whitespace-nowrap disabled:opacity-50"
              >
                {q.label}
              </button>
            ))}
          </div>

          {/* Input */}
          <div className="p-3 border-t border-ivory-200/80 shrink-0 bg-white">
            <div className="flex gap-2">
              <input
                ref={inputRef}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                className="flex-1 px-4 py-2.5 bg-ivory-50/80 border border-ivory-200 rounded-xl text-sm text-slate-800 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-accent-500/20 focus:border-accent-400 transition-all duration-200"
                placeholder="Ask about threats, rules, IPs, incidents..."
                disabled={loading}
              />
              <button
                onClick={() => handleSend()}
                disabled={loading || !input.trim()}
                className="p-2.5 rounded-xl bg-gradient-to-br from-accent-500 to-accent-700 text-white hover:from-accent-600 hover:to-accent-700 disabled:opacity-40 disabled:cursor-not-allowed transition-all duration-200 shadow-sm shadow-accent-500/15 hover:shadow-md hover:shadow-accent-500/20"
              >
                <Send size={16} />
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
