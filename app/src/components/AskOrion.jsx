import { useState, useRef, useEffect } from 'react'
import { Sparkles, X, Send } from 'lucide-react'
import { CHAT_SEED, askOrion } from '../data/mock.js'

export default function AskOrion() {
  const [open, setOpen] = useState(false)
  const [messages, setMessages] = useState(CHAT_SEED)
  const [input, setInput] = useState('')
  const [thinking, setThinking] = useState(false)
  const endRef = useRef(null)

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, open, thinking])

  const send = () => {
    const text = input.trim()
    if (!text) return
    setMessages((m) => [...m, { role: 'user', text }])
    setInput('')
    setThinking(true)
    setTimeout(() => {
      setMessages((m) => [...m, { role: 'assistant', text: askOrion(text) }])
      setThinking(false)
    }, 700)
  }

  return (
    <>
      {open && (
        <div
          className="fixed bottom-24 right-6 z-50 flex h-[480px] w-[360px] flex-col overflow-hidden rounded-2xl shadow-2xl"
          style={{ background: 'var(--color-panel)', border: '1px solid var(--color-line)' }}
        >
          <div className="flex items-center justify-between px-4 py-3" style={{ borderBottom: '1px solid var(--color-line)' }}>
            <div className="flex items-center gap-2">
              <div className="flex h-7 w-7 items-center justify-center rounded-lg" style={{ background: 'var(--color-accent-soft)' }}>
                <Sparkles size={15} className="text-[color:var(--color-accent-bright)]" />
              </div>
              <div>
                <p className="text-sm font-semibold font-display">Ask Orion</p>
                <p className="text-[11px] text-[color:var(--color-muted)]">AI assistant</p>
              </div>
            </div>
            <button onClick={() => setOpen(false)} className="text-[color:var(--color-dim)] hover:text-[color:var(--color-text)]">
              <X size={18} />
            </button>
          </div>
          <div className="flex-1 space-y-3 overflow-y-auto px-4 py-4">
            {messages.map((m, i) => (
              <div key={i} className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                <div
                  className="max-w-[85%] rounded-2xl px-3.5 py-2.5 text-[13px] leading-relaxed"
                  style={
                    m.role === 'user'
                      ? { background: 'var(--color-accent)', color: '#04101f' }
                      : { background: 'var(--color-panel-2)', color: 'var(--color-text)', border: '1px solid var(--color-line)' }
                  }
                >
                  {m.text}
                </div>
              </div>
            ))}
            {thinking && (
              <div className="flex justify-start">
                <div className="rounded-2xl px-3.5 py-2.5 text-[13px]" style={{ background: 'var(--color-panel-2)', border: '1px solid var(--color-line)' }}>
                  <span className="inline-flex gap-1">
                    <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-[color:var(--color-accent-bright)]" style={{ animationDelay: '0ms' }} />
                    <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-[color:var(--color-accent-bright)]" style={{ animationDelay: '120ms' }} />
                    <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-[color:var(--color-accent-bright)]" style={{ animationDelay: '240ms' }} />
                  </span>
                </div>
              </div>
            )}
            <div ref={endRef} />
          </div>
          <div className="flex items-center gap-2 px-3 py-3" style={{ borderTop: '1px solid var(--color-line)' }}>
            <input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && send()}
              placeholder="Ask about findings, scans, reports…"
              className="input-field flex-1 rounded-xl px-3 py-2 text-sm"
            />
            <button onClick={send} className="btn-primary flex h-9 w-9 items-center justify-center rounded-xl">
              <Send size={15} />
            </button>
          </div>
        </div>
      )}

      <button
        onClick={() => setOpen((o) => !o)}
        className="fixed bottom-6 right-6 z-50 flex h-14 w-14 items-center justify-center rounded-full shadow-2xl btn-primary"
        title="Ask Orion"
      >
        <Sparkles size={22} />
      </button>
    </>
  )
}
