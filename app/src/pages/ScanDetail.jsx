import { useParams, useNavigate, Link } from 'react-router-dom'
import { ArrowLeft, FileText } from 'lucide-react'
import { SCANS, FINDINGS } from '../data/mock.js'
import { SeverityBadge, StatusPill } from '../components/Badges.jsx'
import PageHeader from '../components/PageHeader.jsx'

const LOG_STEPS = [
  'Resolving target and validating scope',
  'Enumerating hosts / endpoints',
  'Fingerprinting services and software versions',
  'Matching against known CVE database',
  'Running active checks',
  'Scoring and de-duplicating findings',
  'Compiling report',
]

export default function ScanDetail() {
  const { id } = useParams()
  const navigate = useNavigate()
  const scan = SCANS.find((s) => s.id === id)

  if (!scan) {
    return (
      <div className="px-8 pt-8">
        <p className="text-sm text-[color:var(--color-muted)]">Scan not found.</p>
        <button onClick={() => navigate('/scans')} className="mt-3 flex items-center gap-1.5 text-sm text-[color:var(--color-accent-bright)]">
          <ArrowLeft size={14} /> Back to scans
        </button>
      </div>
    )
  }

  const relatedFindings = FINDINGS.filter((f) => f.asset === scan.target)
  const completedSteps = scan.status === 'completed' ? LOG_STEPS.length
    : scan.status === 'running' ? Math.round((scan.progress / 100) * LOG_STEPS.length)
    : scan.status === 'failed' ? 2
    : 0

  return (
    <div className="pb-10">
      <div className="px-8 pt-8">
        <button onClick={() => navigate('/scans')} className="mb-3 flex items-center gap-1.5 text-xs font-medium text-[color:var(--color-muted)] hover:text-[color:var(--color-text)]">
          <ArrowLeft size={13} /> Back to scans
        </button>
      </div>
      <PageHeader
        title={scan.target}
        subtitle={`${scan.agent} · started ${scan.started}`}
        action={<StatusPill status={scan.status} />}
      />

      <div className="grid grid-cols-1 gap-4 px-8 pt-6 lg:grid-cols-3">
        <div className="card rounded-2xl p-5 lg:col-span-2">
          <h3 className="mb-4 text-sm font-semibold">Scan progress</h3>
          <div className="space-y-0">
            {LOG_STEPS.map((label, i) => {
              const state = i < completedSteps ? 'done' : i === completedSteps && scan.status === 'running' ? 'active' : 'pending'
              return (
                <div key={label} className="flex items-start gap-3 pb-5 last:pb-0">
                  <div className="flex flex-col items-center">
                    <span
                      className={`flex h-5 w-5 items-center justify-center rounded-full text-[10px] font-bold ${state === 'active' ? 'pulse-ring' : ''}`}
                      style={{
                        background: state === 'done' ? 'var(--color-ok)' : state === 'active' ? 'var(--color-accent)' : 'var(--color-panel-2)',
                        color: state === 'pending' ? 'var(--color-dim)' : '#04101f',
                      }}
                    >
                      {state === 'done' ? '✓' : i + 1}
                    </span>
                    {i < LOG_STEPS.length - 1 && (
                      <span className="mt-1 h-full w-px flex-1" style={{ background: 'var(--color-line)', minHeight: 20 }} />
                    )}
                  </div>
                  <p className={`text-sm ${state === 'pending' ? 'text-[color:var(--color-dim)]' : 'text-[color:var(--color-text)]'}`}>
                    {label}
                    {state === 'active' && <span className="ml-1 text-[color:var(--color-accent-bright)]">…</span>}
                  </p>
                </div>
              )
            })}
          </div>
        </div>

        <div className="space-y-4">
          <div className="card rounded-2xl p-5">
            <h3 className="mb-3 text-sm font-semibold">Summary</h3>
            <dl className="space-y-2.5 text-sm">
              <Row k="Scan type" v={scan.type} capitalize />
              <Row k="Duration" v={scan.duration} mono />
              <Row k="Findings" v={scan.findings} />
              <Row k="Agent" v={scan.agent} />
            </dl>
          </div>
          {scan.status === 'completed' && (
            <Link to="/reports" className="card flex items-center justify-between rounded-2xl p-5 transition-colors hover:bg-[color:var(--color-panel-2)]">
              <span className="flex items-center gap-2 text-sm font-medium">
                <FileText size={16} className="text-[color:var(--color-accent-bright)]" /> View generated report
              </span>
              <ArrowLeft size={14} className="rotate-180 text-[color:var(--color-dim)]" />
            </Link>
          )}
        </div>
      </div>

      {relatedFindings.length > 0 && (
        <div className="card mx-8 mt-4 overflow-hidden rounded-2xl">
          <div className="border-b px-5 py-3.5" style={{ borderColor: 'var(--color-line)' }}>
            <h3 className="text-sm font-semibold">Findings from this scan</h3>
          </div>
          <div className="divide-y" style={{ borderColor: 'var(--color-line)' }}>
            {relatedFindings.map((f) => (
              <div key={f.id} className="flex items-center justify-between gap-3 px-5 py-3.5" style={{ borderColor: 'var(--color-line)' }}>
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium">{f.title}</p>
                  <p className="text-xs text-[color:var(--color-dim)]">{f.cve || 'No CVE mapped'}</p>
                </div>
                <SeverityBadge level={f.severity} />
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function Row({ k, v, mono, capitalize }) {
  return (
    <div className="flex items-center justify-between">
      <dt className="text-[color:var(--color-muted)]">{k}</dt>
      <dd className={`font-medium ${mono ? 'font-mono' : ''} ${capitalize ? 'capitalize' : ''}`}>{v}</dd>
    </div>
  )
}
