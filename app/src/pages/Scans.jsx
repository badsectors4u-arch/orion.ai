import { useState } from 'react'
import { Link } from 'react-router-dom'
import { PlusCircle, Search, Network, Globe, Radar } from 'lucide-react'
import { SCANS } from '../data/mock.js'
import { StatusPill } from '../components/Badges.jsx'
import PageHeader from '../components/PageHeader.jsx'
import { useAuth } from '../state/AuthContext.jsx'

const TYPE_META = {
  network: { label: 'Network', icon: Network },
  web: { label: 'Web App', icon: Globe },
  advanced: { label: 'Advanced', icon: Radar },
}

export default function Scans() {
  const { can } = useAuth()
  const [q, setQ] = useState('')
  const [statusFilter, setStatusFilter] = useState('all')

  const filtered = SCANS.filter((s) => {
    const matchesQ = s.target.toLowerCase().includes(q.toLowerCase())
    const matchesStatus = statusFilter === 'all' || s.status === statusFilter
    return matchesQ && matchesStatus
  })

  return (
    <div className="pb-10">
      <PageHeader
        title="Scans"
        subtitle="Launch and track network, web, and advanced security scans."
        action={
          can('runScan') && (
            <Link to="/scans/new" className="btn-primary flex items-center gap-2 rounded-xl px-4 py-2.5 text-sm">
              <PlusCircle size={16} /> New Scan
            </Link>
          )
        }
      />

      <div className="mt-5 flex flex-wrap items-center gap-3 px-8">
        <div className="relative">
          <Search size={15} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[color:var(--color-dim)]" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search target…"
            className="input-field w-64 rounded-xl py-2 pl-9 pr-3 text-sm"
          />
        </div>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="input-field rounded-xl px-3 py-2 text-sm"
        >
          <option value="all">All statuses</option>
          <option value="running">Running</option>
          <option value="queued">Queued</option>
          <option value="completed">Completed</option>
          <option value="failed">Failed</option>
        </select>
      </div>

      <div className="card mx-8 mt-4 overflow-hidden rounded-2xl">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b text-left text-xs uppercase tracking-wide text-[color:var(--color-dim)]" style={{ borderColor: 'var(--color-line)' }}>
              <th className="px-5 py-3 font-medium">Target</th>
              <th className="px-5 py-3 font-medium">Type</th>
              <th className="px-5 py-3 font-medium">Started</th>
              <th className="px-5 py-3 font-medium">Duration</th>
              <th className="px-5 py-3 font-medium">Findings</th>
              <th className="px-5 py-3 font-medium">Status</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((s) => {
              const Meta = TYPE_META[s.type]
              return (
                <tr
                  key={s.id}
                  className="border-b transition-colors last:border-0 hover:bg-[color:var(--color-panel-2)]"
                  style={{ borderColor: 'var(--color-line)' }}
                >
                  <td className="px-5 py-3.5">
                    <Link to={`/scans/${s.id}`} className="font-medium hover:text-[color:var(--color-accent-bright)]">
                      {s.target}
                    </Link>
                  </td>
                  <td className="px-5 py-3.5">
                    <span className="flex items-center gap-1.5 text-[color:var(--color-muted)]">
                      <Meta.icon size={14} /> {Meta.label}
                    </span>
                  </td>
                  <td className="px-5 py-3.5 font-mono text-xs text-[color:var(--color-muted)]">{s.started}</td>
                  <td className="px-5 py-3.5 font-mono text-xs text-[color:var(--color-muted)]">{s.duration}</td>
                  <td className="px-5 py-3.5">
                    {s.status === 'running' ? (
                      <div className="flex items-center gap-2">
                        <div className="h-1.5 w-20 overflow-hidden rounded-full" style={{ background: 'var(--color-panel-2)' }}>
                          <div className="h-full rounded-full" style={{ width: `${s.progress}%`, background: 'var(--color-accent)' }} />
                        </div>
                        <span className="font-mono text-xs text-[color:var(--color-muted)]">{s.progress}%</span>
                      </div>
                    ) : (
                      s.findings
                    )}
                  </td>
                  <td className="px-5 py-3.5"><StatusPill status={s.status} /></td>
                </tr>
              )
            })}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={6} className="px-5 py-10 text-center text-sm text-[color:var(--color-dim)]">
                  No scans match your filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
