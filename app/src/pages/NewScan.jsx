import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Network, Globe, Radar, Check, ChevronRight, ChevronLeft, Loader2, PartyPopper } from 'lucide-react'
import { ASSETS } from '../data/mock.js'
import PageHeader from '../components/PageHeader.jsx'

const TYPES = [
  { key: 'network', label: 'Network Scan', icon: Network, desc: 'Discover hosts, open ports, services, and known CVEs across a CIDR range.' },
  { key: 'web', label: 'Web App Scan', icon: Globe, desc: 'Crawl and test a web application for OWASP Top 10 issues and misconfigurations.' },
  { key: 'advanced', label: 'Advanced / AI-Guided', icon: Radar, desc: 'Orion\'s AI agent chains recon, exploitation checks, and business-logic tests.' },
]

const STEPS = ['Scan type', 'Target & scope', 'Review & launch']

export default function NewScan() {
  const [step, setStep] = useState(0)
  const [type, setType] = useState('network')
  const [assetId, setAssetId] = useState(ASSETS[0].id)
  const [customTarget, setCustomTarget] = useState('')
  const [intensity, setIntensity] = useState('balanced')
  const [launching, setLaunching] = useState(false)
  const [done, setDone] = useState(false)
  const navigate = useNavigate()

  const asset = ASSETS.find((a) => a.id === assetId)
  const target = customTarget || asset?.value

  const launch = () => {
    setLaunching(true)
    setTimeout(() => {
      setLaunching(false)
      setDone(true)
    }, 1800)
  }

  if (done) {
    return (
      <div className="flex h-full flex-col items-center justify-center px-8 text-center">
        <div className="flex h-16 w-16 items-center justify-center rounded-full" style={{ background: 'var(--color-ok-soft, rgba(62,207,142,0.12))' }}>
          <PartyPopper size={26} className="text-[color:var(--color-ok)]" />
        </div>
        <h2 className="mt-5 font-display text-xl font-semibold">Scan queued</h2>
        <p className="mt-1.5 max-w-sm text-sm text-[color:var(--color-muted)]">
          Your {TYPES.find((t) => t.key === type).label.toLowerCase()} against <span className="font-mono">{target}</span> has been added to the queue. You'll see live progress on the Scans page.
        </p>
        <div className="mt-6 flex gap-3">
          <button onClick={() => navigate('/scans')} className="btn-primary rounded-xl px-5 py-2.5 text-sm">
            View scans
          </button>
          <button onClick={() => navigate('/dashboard')} className="btn-ghost rounded-xl px-5 py-2.5 text-sm">
            Back to dashboard
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="pb-10">
      <PageHeader title="New scan" subtitle="Scope a scan in three quick steps." />

      <div className="mx-8 mt-6 flex items-center gap-2">
        {STEPS.map((label, i) => (
          <div key={label} className="flex flex-1 items-center gap-2">
            <div className="flex items-center gap-2">
              <div
                className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full text-xs font-semibold"
                style={{
                  background: i <= step ? 'var(--color-accent)' : 'var(--color-panel-2)',
                  color: i <= step ? '#04101f' : 'var(--color-dim)',
                }}
              >
                {i < step ? <Check size={13} /> : i + 1}
              </div>
              <span className={`text-xs font-medium ${i === step ? 'text-[color:var(--color-text)]' : 'text-[color:var(--color-dim)]'}`}>{label}</span>
            </div>
            {i < STEPS.length - 1 && <div className="h-px flex-1" style={{ background: 'var(--color-line)' }} />}
          </div>
        ))}
      </div>

      <div className="card mx-8 mt-6 rounded-2xl p-6">
        {step === 0 && (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            {TYPES.map((t) => {
              const active = type === t.key
              return (
                <button
                  key={t.key}
                  onClick={() => setType(t.key)}
                  className="flex flex-col items-start gap-3 rounded-2xl p-5 text-left transition-colors"
                  style={{
                    background: active ? 'var(--color-accent-soft)' : 'var(--color-panel-2)',
                    border: `1px solid ${active ? 'var(--color-accent-bright)' : 'var(--color-line)'}`,
                  }}
                >
                  <div className="flex h-10 w-10 items-center justify-center rounded-xl" style={{ background: active ? 'var(--color-accent-bright)' : 'var(--color-panel)' }}>
                    <t.icon size={18} className={active ? 'text-[#04101f]' : 'text-[color:var(--color-muted)]'} />
                  </div>
                  <div>
                    <p className="text-sm font-semibold">{t.label}</p>
                    <p className="mt-1 text-xs leading-snug text-[color:var(--color-muted)]">{t.desc}</p>
                  </div>
                </button>
              )
            })}
          </div>
        )}

        {step === 1 && (
          <div className="max-w-lg space-y-5">
            <div>
              <label className="mb-1.5 block text-xs font-medium text-[color:var(--color-muted)]">Choose a monitored asset</label>
              <select
                value={assetId}
                onChange={(e) => { setAssetId(e.target.value); setCustomTarget('') }}
                className="input-field w-full rounded-xl px-3.5 py-2.5 text-sm"
              >
                {ASSETS.map((a) => (
                  <option key={a.id} value={a.id}>{a.name} — {a.value}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="mb-1.5 block text-xs font-medium text-[color:var(--color-muted)]">Or enter a custom target</label>
              <input
                value={customTarget}
                onChange={(e) => setCustomTarget(e.target.value)}
                placeholder="e.g. 10.0.4.0/24 or https://app.example.com"
                className="input-field w-full rounded-xl px-3.5 py-2.5 text-sm"
              />
            </div>
            <div>
              <label className="mb-1.5 block text-xs font-medium text-[color:var(--color-muted)]">Scan intensity</label>
              <div className="grid grid-cols-3 gap-2">
                {['light', 'balanced', 'aggressive'].map((level) => (
                  <button
                    key={level}
                    onClick={() => setIntensity(level)}
                    className="rounded-xl py-2.5 text-xs font-medium capitalize"
                    style={{
                      background: intensity === level ? 'var(--color-accent-soft)' : 'var(--color-panel-2)',
                      border: `1px solid ${intensity === level ? 'var(--color-accent-bright)' : 'var(--color-line)'}`,
                      color: intensity === level ? 'var(--color-accent-bright)' : 'var(--color-muted)',
                    }}
                  >
                    {level}
                  </button>
                ))}
              </div>
            </div>
          </div>
        )}

        {step === 2 && (
          <div className="max-w-lg space-y-4">
            <SummaryRow label="Scan type" value={TYPES.find((t) => t.key === type).label} />
            <SummaryRow label="Target" value={target} mono />
            <SummaryRow label="Intensity" value={intensity} capitalize />
            <SummaryRow label="Estimated duration" value={intensity === 'light' ? '~5 min' : intensity === 'aggressive' ? '~25 min' : '~12 min'} />
            <div className="rounded-xl px-4 py-3 text-xs leading-relaxed text-[color:var(--color-muted)]" style={{ background: 'var(--color-panel-2)', border: '1px solid var(--color-line)' }}>
              This is a simulated scan for demo purposes — no real traffic will be sent to the target.
            </div>
          </div>
        )}

        <div className="mt-8 flex items-center justify-between">
          <button
            onClick={() => setStep((s) => Math.max(0, s - 1))}
            disabled={step === 0}
            className="btn-ghost flex items-center gap-1.5 rounded-xl px-4 py-2.5 text-sm disabled:opacity-0"
          >
            <ChevronLeft size={15} /> Back
          </button>
          {step < 2 ? (
            <button
              onClick={() => setStep((s) => Math.min(2, s + 1))}
              className="btn-primary flex items-center gap-1.5 rounded-xl px-5 py-2.5 text-sm"
            >
              Continue <ChevronRight size={15} />
            </button>
          ) : (
            <button
              onClick={launch}
              disabled={launching}
              className="btn-primary flex items-center gap-2 rounded-xl px-5 py-2.5 text-sm disabled:opacity-70"
            >
              {launching ? <><Loader2 size={15} className="animate-spin" /> Launching…</> : 'Launch scan'}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

function SummaryRow({ label, value, mono, capitalize }) {
  return (
    <div className="flex items-center justify-between border-b pb-3" style={{ borderColor: 'var(--color-line)' }}>
      <span className="text-xs font-medium text-[color:var(--color-muted)]">{label}</span>
      <span className={`text-sm font-medium ${mono ? 'font-mono' : ''} ${capitalize ? 'capitalize' : ''}`}>{value}</span>
    </div>
  )
}
