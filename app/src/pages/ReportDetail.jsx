import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft, Download, ShieldCheck } from 'lucide-react'
import { REPORTS, FINDINGS } from '../data/mock.js'
import { SeverityBadge } from '../components/Badges.jsx'
import PageHeader from '../components/PageHeader.jsx'
import { useAuth } from '../state/AuthContext.jsx'

export default function ReportDetail() {
  const { id } = useParams()
  const navigate = useNavigate()
  const { can } = useAuth()
  const report = REPORTS.find((r) => r.id === id)

  if (!report) {
    return (
      <div className="px-8 pt-8">
        <p className="text-sm text-[color:var(--color-muted)]">Report not found.</p>
        <button onClick={() => navigate('/reports')} className="mt-3 flex items-center gap-1.5 text-sm text-[color:var(--color-accent-bright)]">
          <ArrowLeft size={14} /> Back to reports
        </button>
      </div>
    )
  }

  const assetName = report.scan.split(' — ')[0]
  const relatedFindings = FINDINGS.filter((f) => f.asset === assetName)

  return (
    <div className="pb-10">
      <div className="px-8 pt-8">
        <button onClick={() => navigate('/reports')} className="mb-3 flex items-center gap-1.5 text-xs font-medium text-[color:var(--color-muted)] hover:text-[color:var(--color-text)]">
          <ArrowLeft size={13} /> Back to reports
        </button>
      </div>
      <PageHeader
        title={report.scan}
        subtitle={`Generated ${report.date} · ${report.format} format`}
        action={
          can('exportReports') && (
            <button className="btn-primary flex items-center gap-2 rounded-xl px-4 py-2.5 text-sm">
              <Download size={15} /> Export {report.format}
            </button>
          )
        }
      />

      <div className="card mx-8 mt-6 rounded-2xl p-7">
        <div className="flex items-center gap-3 border-b pb-5" style={{ borderColor: 'var(--color-line)' }}>
          <div className="flex h-11 w-11 items-center justify-center rounded-xl" style={{ background: 'var(--color-accent-soft)' }}>
            <ShieldCheck size={20} className="text-[color:var(--color-accent-bright)]" />
          </div>
          <div>
            <p className="font-display text-base font-semibold">Executive Summary</p>
            <p className="text-xs text-[color:var(--color-muted)]">Orion Security Assessment Report</p>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4 py-6 sm:grid-cols-4">
          <SummaryStat label="Total findings" value={report.findings} />
          <SummaryStat label="Critical" value={report.critical} tint="var(--color-crit)" />
          <SummaryStat label="High" value={report.high} tint="var(--color-high)" />
          <SummaryStat label="Scan date" value={report.date} small />
        </div>

        <div className="border-t pt-6" style={{ borderColor: 'var(--color-line)' }}>
          <h3 className="mb-4 text-sm font-semibold">Detailed findings</h3>
          {relatedFindings.length > 0 ? (
            <div className="space-y-2.5">
              {relatedFindings.map((f) => (
                <div key={f.id} className="flex items-center justify-between gap-3 rounded-xl px-4 py-3" style={{ background: 'var(--color-panel-2)' }}>
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium">{f.title}</p>
                    <p className="text-xs text-[color:var(--color-dim)]">{f.cve || 'No CVE mapped'} · confidence {Math.round(f.confidence * 100)}%</p>
                  </div>
                  <SeverityBadge level={f.severity} />
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-[color:var(--color-muted)]">No findings recorded — this scan completed clean or did not run to completion.</p>
          )}
        </div>
      </div>
    </div>
  )
}

function SummaryStat({ label, value, tint, small }) {
  return (
    <div>
      <p className={small ? 'font-mono text-sm font-semibold' : 'font-display text-2xl font-semibold'} style={tint ? { color: tint } : undefined}>
        {value}
      </p>
      <p className="mt-0.5 text-xs text-[color:var(--color-muted)]">{label}</p>
    </div>
  )
}
