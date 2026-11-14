import { useMemo } from 'react'
import { Link } from 'react-router-dom'
import { PlusCircle, ShieldAlert, Server, ScanLine, ListChecks, ArrowUpRight } from 'lucide-react'
import {
  ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid,
} from 'recharts'
import { ASSETS, SCANS, FINDINGS, SEVERITY_META } from '../data/mock.js'
import { SeverityBadge, StatusPill } from '../components/Badges.jsx'
import PageHeader from '../components/PageHeader.jsx'
import { useAuth } from '../state/AuthContext.jsx'

export default function Dashboard() {
  const { can, roleMeta, user } = useAuth()

  const openFindings = FINDINGS.filter((f) => f.status === 'open' || f.status === 'confirmed')
  const critical = FINDINGS.filter((f) => f.severity === 'critical' && f.status !== 'resolved' && f.status !== 'false_positive')

  const severityData = useMemo(() => {
    const order = ['critical', 'high', 'medium', 'low', 'info']
    return order.map((level) => ({
      level,
      count: FINDINGS.filter((f) => f.severity === level).length,
      fill: SEVERITY_META[level].color,
    }))
  }, [])

  const trendData = [
    { day: 'Mon', findings: 4 }, { day: 'Tue', findings: 7 }, { day: 'Wed', findings: 5 },
    { day: 'Thu', findings: 9 }, { day: 'Fri', findings: 6 }, { day: 'Sat', findings: 3 }, { day: 'Sun', findings: 2 },
  ]

  return (
    <div className="pb-10">
      <PageHeader
        title={`Welcome back, ${user?.orgName || 'there'}`}
        subtitle={`Signed in as ${roleMeta?.label} · here's your security posture at a glance`}
        action={
          can('runScan') && (
            <Link to="/scans/new" className="btn-primary flex items-center gap-2 rounded-xl px-4 py-2.5 text-sm">
              <PlusCircle size={16} /> New Scan
            </Link>
          )
        }
      />

      <div className="grid grid-cols-1 gap-4 px-8 pt-6 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard icon={Server} label="Monitored Assets" value={ASSETS.length} tint="var(--color-accent-bright)" />
        <StatCard icon={ScanLine} label="Scans This Month" value={SCANS.length} tint="var(--color-ok)" />
        <StatCard icon={ListChecks} label="Open Findings" value={openFindings.length} tint="var(--color-high)" />
        <StatCard icon={ShieldAlert} label="Critical, Unresolved" value={critical.length} tint="var(--color-crit)" alert />
      </div>

      <div className="grid grid-cols-1 gap-4 px-8 pt-4 xl:grid-cols-3">
        <div className="card rounded-2xl p-5 xl:col-span-2">
          <div className="mb-4 flex items-center justify-between">
            <h3 className="text-sm font-semibold">Findings discovered, last 7 days</h3>
            <Link to="/findings" className="flex items-center gap-1 text-xs font-medium text-[color:var(--color-accent-bright)] hover:underline">
              View all <ArrowUpRight size={12} />
            </Link>
          </div>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={trendData} margin={{ left: -20 }}>
              <CartesianGrid vertical={false} stroke="var(--color-line)" />
              <XAxis dataKey="day" tick={{ fill: 'var(--color-muted)', fontSize: 12 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: 'var(--color-muted)', fontSize: 12 }} axisLine={false} tickLine={false} allowDecimals={false} />
              <Tooltip
                contentStyle={{ background: 'var(--color-panel-2)', border: '1px solid var(--color-line)', borderRadius: 10, fontSize: 12 }}
                labelStyle={{ color: 'var(--color-text)' }}
              />
              <Bar dataKey="findings" radius={[6, 6, 0, 0]} fill="var(--color-accent)" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="card rounded-2xl p-5">
          <h3 className="mb-4 text-sm font-semibold">Findings by severity</h3>
          <ResponsiveContainer width="100%" height={180}>
            <PieChart>
              <Pie data={severityData} dataKey="count" nameKey="level" innerRadius={45} outerRadius={70} paddingAngle={3}>
                {severityData.map((d) => (
                  <Cell key={d.level} fill={d.fill} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ background: 'var(--color-panel-2)', border: '1px solid var(--color-line)', borderRadius: 10, fontSize: 12 }} />
            </PieChart>
          </ResponsiveContainer>
          <div className="mt-2 grid grid-cols-2 gap-x-3 gap-y-1.5">
            {severityData.map((d) => (
              <div key={d.level} className="flex items-center justify-between text-xs">
                <span className="flex items-center gap-1.5 capitalize text-[color:var(--color-muted)]">
                  <span className="h-1.5 w-1.5 rounded-full" style={{ background: d.fill }} /> {d.level}
                </span>
                <span className="font-mono font-medium">{d.count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 px-8 pt-4 xl:grid-cols-2">
        <div className="card rounded-2xl p-5">
          <div className="mb-3 flex items-center justify-between">
            <h3 className="text-sm font-semibold">Recent scans</h3>
            <Link to="/scans" className="text-xs font-medium text-[color:var(--color-accent-bright)] hover:underline">View all</Link>
          </div>
          <div className="space-y-2.5">
            {SCANS.slice(0, 4).map((s) => (
              <Link
                key={s.id}
                to={`/scans/${s.id}`}
                className="flex items-center justify-between rounded-xl px-3 py-2.5 transition-colors hover:bg-[color:var(--color-panel-2)]"
              >
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium">{s.target}</p>
                  <p className="text-xs text-[color:var(--color-dim)]">{s.agent} · {s.started}</p>
                </div>
                <StatusPill status={s.status} />
              </Link>
            ))}
          </div>
        </div>

        <div className="card rounded-2xl p-5">
          <div className="mb-3 flex items-center justify-between">
            <h3 className="text-sm font-semibold">Top findings</h3>
            <Link to="/findings" className="text-xs font-medium text-[color:var(--color-accent-bright)] hover:underline">View all</Link>
          </div>
          <div className="space-y-2.5">
            {FINDINGS.filter((f) => f.status !== 'resolved' && f.status !== 'false_positive')
              .sort((a, b) => ['critical', 'high', 'medium', 'low', 'info'].indexOf(a.severity) - ['critical', 'high', 'medium', 'low', 'info'].indexOf(b.severity))
              .slice(0, 4)
              .map((f) => (
                <div key={f.id} className="flex items-center justify-between gap-3 rounded-xl px-3 py-2.5 hover:bg-[color:var(--color-panel-2)]">
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium">{f.title}</p>
                    <p className="text-xs text-[color:var(--color-dim)]">{f.asset}</p>
                  </div>
                  <SeverityBadge level={f.severity} />
                </div>
              ))}
          </div>
        </div>
      </div>
    </div>
  )
}

function StatCard({ icon: Icon, label, value, tint, alert }) {
  return (
    <div className="card rounded-2xl p-5">
      <div className="flex items-center justify-between">
        <div
          className="flex h-10 w-10 items-center justify-center rounded-xl"
          style={{ background: `color-mix(in srgb, ${tint} 16%, transparent)` }}
        >
          <Icon size={18} style={{ color: tint }} />
        </div>
        {alert && value > 0 && (
          <span className="h-2 w-2 rounded-full pulse-ring" style={{ background: 'var(--color-crit)' }} />
        )}
      </div>
      <p className="mt-4 font-display text-2xl font-semibold">{value}</p>
      <p className="mt-0.5 text-xs text-[color:var(--color-muted)]">{label}</p>
    </div>
  )
}
