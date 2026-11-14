import { useMemo, useState } from 'react'
import { Search, X } from 'lucide-react'
import { FINDINGS } from '../data/mock.js'
import { SeverityBadge } from '../components/Badges.jsx'
import PageHeader from '../components/PageHeader.jsx'
import { useAuth } from '../state/AuthContext.jsx'

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']
const STATUS_LABEL = {
  open: 'Open', confirmed: 'Confirmed', false_positive: 'False positive', resolved: 'Resolved',
}

export default function Findings() {
  const { can } = useAuth()
  const [q, setQ] = useState('')
  const [severity, setSeverity] = useState('all')
  const [selected, setSelected] = useState(null)

  const filtered = useMemo(() => {
    return FINDINGS.filter((f) => {
      const matchesQ = f.title.toLowerCase().includes(q.toLowerCase()) || f.asset.toLowerCase().includes(q.toLowerCase())
      const matchesSeverity = severity === 'all' || f.severity === severity
      return matchesQ && matchesSeverity
    }).sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity))
  }, [q, severity])

  return (
    <div className="pb-10">
      <PageHeader title="Findings" subtitle="Every issue Orion has detected across your assets, ranked by severity." />

      <div className="mt-5 flex flex-wrap items-center gap-2 px-8">
        <div className="relative">
          <Search size={15} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[color:var(--color-dim)]" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search findings or assets…"
            className="input-field w-72 rounded-xl py-2 pl-9 pr-3 text-sm"
          />
        </div>
        <button
          onClick={() => setSeverity('all')}
          className="rounded-full px-3 py-1.5 text-xs font-medium"
          style={{ background: severity === 'all' ? 'var(--color-accent-soft)' : 'var(--color-panel-2)', color: severity === 'all' ? 'var(--color-accent-bright)' : 'var(--color-muted)' }}
        >
          All
        </button>
        {SEVERITIES.map((s) => (
          <button
            key={s}
            onClick={() => setSeverity(s)}
            className="rounded-full px-3 py-1.5 text-xs font-medium capitalize"
            style={{ background: severity === s ? 'var(--color-accent-soft)' : 'var(--color-panel-2)', color: severity === s ? 'var(--color-accent-bright)' : 'var(--color-muted)' }}
          >
            {s}
          </button>
        ))}
      </div>

      <div className="card mx-8 mt-4 overflow-hidden rounded-2xl">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b text-left text-xs uppercase tracking-wide text-[color:var(--color-dim)]" style={{ borderColor: 'var(--color-line)' }}>
              <th className="px-5 py-3 font-medium">Finding</th>
              <th className="px-5 py-3 font-medium">Asset</th>
              <th className="px-5 py-3 font-medium">Severity</th>
              <th className="px-5 py-3 font-medium">Confidence</th>
              <th className="px-5 py-3 font-medium">Status</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((f) => (
              <tr
                key={f.id}
                onClick={() => setSelected(f)}
                className="cursor-pointer border-b transition-colors last:border-0 hover:bg-[color:var(--color-panel-2)]"
                style={{ borderColor: 'var(--color-line)' }}
              >
                <td className="max-w-sm px-5 py-3.5">
                  <p className="truncate font-medium">{f.title}</p>
                  <p className="text-xs text-[color:var(--color-dim)]">{f.cve || 'No CVE mapped'}</p>
                </td>
                <td className="px-5 py-3.5 text-[color:var(--color-muted)]">{f.asset}</td>
                <td className="px-5 py-3.5"><SeverityBadge level={f.severity} /></td>
                <td className="px-5 py-3.5 font-mono text-xs text-[color:var(--color-muted)]">{Math.round(f.confidence * 100)}%</td>
                <td className="px-5 py-3.5 capitalize text-[color:var(--color-muted)]">{STATUS_LABEL[f.status] || f.status}</td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr><td colSpan={5} className="px-5 py-10 text-center text-sm text-[color:var(--color-dim)]">No findings match your filters.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      {selected && (
        <div className="fixed inset-0 z-50 flex items-center justify-end" style={{ background: 'rgba(5,8,16,0.6)' }} onClick={() => setSelected(null)}>
          <div
            className="h-full w-full max-w-md overflow-y-auto p-6"
            style={{ background: 'var(--color-panel)', borderLeft: '1px solid var(--color-line)' }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-start justify-between gap-3">
              <SeverityBadge level={selected.severity} />
              <button onClick={() => setSelected(null)} className="text-[color:var(--color-dim)] hover:text-[color:var(--color-text)]">
                <X size={18} />
              </button>
            </div>
            <h2 className="mt-4 text-lg font-semibold leading-snug">{selected.title}</h2>
            <dl className="mt-5 space-y-3 text-sm">
              <DetailRow k="Asset" v={selected.asset} />
              <DetailRow k="Detected by" v={selected.agent} />
              <DetailRow k="Discovered" v={selected.discovered} mono />
              <DetailRow k="Confidence" v={`${Math.round(selected.confidence * 100)}%`} mono />
              <DetailRow k="CVE" v={selected.cve || '—'} mono />
              <DetailRow k="Status" v={STATUS_LABEL[selected.status] || selected.status} capitalize />
            </dl>
            <div className="mt-5 rounded-xl p-4 text-xs leading-relaxed text-[color:var(--color-muted)]" style={{ background: 'var(--color-panel-2)', border: '1px solid var(--color-line)' }}>
              Remediation guidance, affected request/response samples, and a retest button would appear here in the full product.
            </div>
            {can('editAssets') && (
              <div className="mt-5 flex gap-2">
                <button className="btn-primary flex-1 rounded-xl py-2.5 text-sm">Mark as resolved</button>
                <button className="btn-ghost flex-1 rounded-xl py-2.5 text-sm">Flag false positive</button>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

function DetailRow({ k, v, mono, capitalize }) {
  return (
    <div className="flex items-center justify-between border-b pb-3" style={{ borderColor: 'var(--color-line)' }}>
      <dt className="text-[color:var(--color-muted)]">{k}</dt>
      <dd className={`font-medium ${mono ? 'font-mono' : ''} ${capitalize ? 'capitalize' : ''}`}>{v}</dd>
    </div>
  )
}
