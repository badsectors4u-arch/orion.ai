import { useState } from 'react'
import { Router, ShieldHalf, Network as SwitchIcon, Server, Laptop2 } from 'lucide-react'
import { NETWORK_NODES, NETWORK_EDGES } from '../data/mock.js'
import PageHeader from '../components/PageHeader.jsx'

const RISK_COLOR = {
  critical: 'var(--color-crit)', high: 'var(--color-high)', medium: 'var(--color-med)', low: 'var(--color-low)',
}
const KIND_ICON = {
  gateway: Router, firewall: ShieldHalf, switch: SwitchIcon, server: Server, cluster: Laptop2,
}

export default function NetworkMap() {
  const [hovered, setHovered] = useState(null)
  const nodeById = Object.fromEntries(NETWORK_NODES.map((n) => [n.id, n]))

  return (
    <div className="pb-10">
      <PageHeader title="Network Map" subtitle="A live-updating topology of discovered hosts, color-coded by risk." />

      <div className="grid grid-cols-1 gap-4 px-8 pt-6 lg:grid-cols-4">
        <div className="card relative overflow-hidden rounded-2xl p-4 lg:col-span-3" style={{ minHeight: 480 }}>
          <svg viewBox="0 0 100 100" className="h-[460px] w-full">
            {NETWORK_EDGES.map(([a, b], i) => {
              const na = nodeById[a]
              const nb = nodeById[b]
              return (
                <line
                  key={i}
                  x1={na.x} y1={na.y} x2={nb.x} y2={nb.y}
                  stroke="var(--color-line)"
                  strokeWidth="0.4"
                />
              )
            })}
            {NETWORK_NODES.map((n) => {
              const color = RISK_COLOR[n.risk] || 'var(--color-ok)'
              const active = hovered === n.id
              return (
                <g
                  key={n.id}
                  onMouseEnter={() => setHovered(n.id)}
                  onMouseLeave={() => setHovered(null)}
                  style={{ cursor: 'pointer' }}
                >
                  {(n.risk === 'critical' || n.risk === 'high') && (
                    <circle cx={n.x} cy={n.y} r={active ? 7 : 6} fill={color} opacity="0.18">
                      <animate attributeName="r" values="5;8;5" dur="2.4s" repeatCount="indefinite" />
                      <animate attributeName="opacity" values="0.25;0.05;0.25" dur="2.4s" repeatCount="indefinite" />
                    </circle>
                  )}
                  <circle cx={n.x} cy={n.y} r={active ? 4.2 : 3.6} fill="var(--color-panel-2)" stroke={color} strokeWidth="0.6" />
                  <text x={n.x} y={n.y + 8.5} textAnchor="middle" fontSize="2.6" fill="var(--color-muted)" style={{ fontFamily: 'var(--font-sans)' }}>
                    {n.label}
                  </text>
                </g>
              )
            })}
          </svg>

          {hovered && (
            <div className="pointer-events-none absolute left-4 top-4 rounded-xl px-3.5 py-2.5 text-xs shadow-xl" style={{ background: 'var(--color-panel-2)', border: '1px solid var(--color-line)' }}>
              <p className="font-semibold">{nodeById[hovered].label}</p>
              <p className="mt-0.5 capitalize text-[color:var(--color-muted)]">{nodeById[hovered].kind} · risk: <span style={{ color: RISK_COLOR[nodeById[hovered].risk] || 'var(--color-ok)' }}>{nodeById[hovered].risk}</span></p>
            </div>
          )}
        </div>

        <div className="space-y-4">
          <div className="card rounded-2xl p-5">
            <h3 className="mb-3 text-sm font-semibold">Legend</h3>
            <div className="space-y-2 text-xs">
              {Object.entries(RISK_COLOR).map(([level, color]) => (
                <div key={level} className="flex items-center gap-2">
                  <span className="h-2.5 w-2.5 rounded-full" style={{ background: color }} />
                  <span className="capitalize text-[color:var(--color-muted)]">{level} risk</span>
                </div>
              ))}
              <div className="flex items-center gap-2">
                <span className="h-2.5 w-2.5 rounded-full" style={{ background: 'var(--color-ok)' }} />
                <span className="text-[color:var(--color-muted)]">Low / clean</span>
              </div>
            </div>
          </div>
          <div className="card rounded-2xl p-5">
            <h3 className="mb-3 text-sm font-semibold">Nodes</h3>
            <div className="space-y-2.5">
              {NETWORK_NODES.map((n) => {
                const Icon = KIND_ICON[n.kind] || Server
                return (
                  <div key={n.id} className="flex items-center justify-between text-xs">
                    <span className="flex items-center gap-2 text-[color:var(--color-muted)]">
                      <Icon size={13} /> {n.label}
                    </span>
                    <span className="h-1.5 w-1.5 rounded-full" style={{ background: RISK_COLOR[n.risk] || 'var(--color-ok)' }} />
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
