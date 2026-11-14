import { SEVERITY_META } from '../data/mock.js'

export function SeverityBadge({ level }) {
  const meta = SEVERITY_META[level] || SEVERITY_META.info
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-semibold font-mono uppercase tracking-wide"
      style={{ color: meta.color, background: meta.soft }}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: meta.color }} />
      {meta.label}
    </span>
  )
}

const STATUS_META = {
  open: { label: 'Open', color: '#f0883e', soft: 'rgba(240,136,62,0.12)' },
  confirmed: { label: 'Confirmed', color: '#ef4857', soft: 'rgba(239,72,87,0.12)' },
  false_positive: { label: 'False positive', color: '#8993ad', soft: 'rgba(137,147,173,0.12)' },
  resolved: { label: 'Resolved', color: '#3ecf8e', soft: 'rgba(62,207,142,0.12)' },
  completed: { label: 'Completed', color: '#3ecf8e', soft: 'rgba(62,207,142,0.12)' },
  running: { label: 'Running', color: '#5fa8ff', soft: 'rgba(95,168,255,0.12)' },
  queued: { label: 'Queued', color: '#e8c547', soft: 'rgba(232,197,71,0.12)' },
  failed: { label: 'Failed', color: '#ef4857', soft: 'rgba(239,72,87,0.12)' },
}

export function StatusPill({ status }) {
  const meta = STATUS_META[status] || STATUS_META.queued
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium" style={{ color: meta.color, background: meta.soft }}>
      {status === 'running' && <span className="h-1.5 w-1.5 rounded-full bg-current pulse-ring" />}
      {meta.label}
    </span>
  )
}

export function RoleBadge({ role }) {
  const map = {
    admin: { label: 'Admin', color: '#5fa8ff', soft: 'rgba(95,168,255,0.12)' },
    analyst: { label: 'Analyst', color: '#3ecf8e', soft: 'rgba(62,207,142,0.12)' },
    viewer: { label: 'Viewer', color: '#8993ad', soft: 'rgba(137,147,173,0.12)' },
  }
  const meta = map[role] || map.viewer
  return (
    <span className="inline-flex items-center rounded-md px-2 py-0.5 text-[11px] font-semibold font-mono uppercase tracking-wide" style={{ color: meta.color, background: meta.soft }}>
      {meta.label}
    </span>
  )
}
