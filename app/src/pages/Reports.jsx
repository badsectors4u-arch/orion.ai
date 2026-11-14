import { Link } from 'react-router-dom'
import { FileText, Download } from 'lucide-react'
import { REPORTS } from '../data/mock.js'
import PageHeader from '../components/PageHeader.jsx'
import { useAuth } from '../state/AuthContext.jsx'

export default function Reports() {
  const { can } = useAuth()

  return (
    <div className="pb-10">
      <PageHeader title="Reports" subtitle="Fixed-template reports generated automatically after every completed scan." />

      <div className="grid grid-cols-1 gap-4 px-8 pt-6 sm:grid-cols-2 xl:grid-cols-3">
        {REPORTS.map((r) => (
          <div key={r.id} className="card flex flex-col rounded-2xl p-5">
            <div className="flex items-start justify-between">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl" style={{ background: 'var(--color-accent-soft)' }}>
                <FileText size={18} className="text-[color:var(--color-accent-bright)]" />
              </div>
              <span className="rounded-md px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-[color:var(--color-muted)]" style={{ background: 'var(--color-panel-2)' }}>
                {r.format}
              </span>
            </div>
            <h3 className="mt-4 text-sm font-semibold leading-snug">{r.scan}</h3>
            <p className="mt-0.5 text-xs text-[color:var(--color-dim)]">{r.date}</p>
            <div className="mt-4 flex items-center gap-4 text-xs text-[color:var(--color-muted)]">
              <span>{r.findings} findings</span>
              {r.critical > 0 && <span className="text-[color:var(--color-crit)]">{r.critical} critical</span>}
              {r.high > 0 && <span className="text-[color:var(--color-high)]">{r.high} high</span>}
            </div>
            <div className="mt-5 flex gap-2">
              <Link to={`/reports/${r.id}`} className="btn-ghost flex-1 rounded-xl py-2 text-center text-xs font-medium">
                View
              </Link>
              {can('exportReports') && (
                <button className="btn-primary flex items-center justify-center gap-1.5 rounded-xl px-3 py-2 text-xs font-medium">
                  <Download size={13} /> Export
                </button>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
