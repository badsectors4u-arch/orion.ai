import { useState } from 'react'
import { UserPlus, Trash2, ShieldCheck, Users, Eye } from 'lucide-react'
import { ROLES } from '../data/mock.js'
import PageHeader from '../components/PageHeader.jsx'
const ROLE_ICONS = { admin: ShieldCheck, analyst: Users, viewer: Eye }

const SEED_MEMBERS = [
  { id: 'u1', username: 'teammember1', role: 'admin', status: 'active' },
  { id: 'u2', username: 'teammember2', role: 'analyst', status: 'active' },
  { id: 'u3', username: 'teammember3', role: 'analyst', status: 'active' },
  { id: 'u4', username: 'teammember4', role: 'viewer', status: 'invited' },
]

export default function UsersRoles() {
  const [members, setMembers] = useState(SEED_MEMBERS)
  const [showInvite, setShowInvite] = useState(false)
  const [newUsername, setNewUsername] = useState('')
  const [newRole, setNewRole] = useState('viewer')

  const invite = (e) => {
    e.preventDefault()
    if (!newUsername.trim()) return
    setMembers((m) => [...m, { id: `u${m.length + 1}`, username: newUsername.trim(), role: newRole, status: 'invited' }])
    setNewUsername('')
    setNewRole('viewer')
    setShowInvite(false)
  }

  const changeRole = (id, role) => setMembers((m) => m.map((u) => (u.id === id ? { ...u, role } : u)))
  const remove = (id) => setMembers((m) => m.filter((u) => u.id !== id))

  return (
    <div className="pb-10">
      <PageHeader
        title="Users & Roles"
        subtitle="Manage who has access to Orion and what each person can do."
        action={
          <button onClick={() => setShowInvite(true)} className="btn-primary flex items-center gap-2 rounded-xl px-4 py-2.5 text-sm">
            <UserPlus size={16} /> Invite member
          </button>
        }
      />

      <div className="grid grid-cols-1 gap-3 px-8 pt-6 sm:grid-cols-3">
        {Object.values(ROLES).map((r) => {
          const Icon = ROLE_ICONS[r.key]
          return (
            <div key={r.key} className="card rounded-2xl p-4">
              <div className="flex items-center gap-2.5">
                <div className="flex h-8 w-8 items-center justify-center rounded-lg" style={{ background: 'var(--color-panel-2)' }}>
                  <Icon size={15} className="text-[color:var(--color-muted)]" />
                </div>
                <p className="text-sm font-semibold">{r.label}</p>
              </div>
              <p className="mt-2 text-xs leading-snug text-[color:var(--color-muted)]">{r.blurb}</p>
            </div>
          )
        })}
      </div>

      <div className="card mx-8 mt-4 overflow-hidden rounded-2xl">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b text-left text-xs uppercase tracking-wide text-[color:var(--color-dim)]" style={{ borderColor: 'var(--color-line)' }}>
              <th className="px-5 py-3 font-medium">User</th>
              <th className="px-5 py-3 font-medium">Role</th>
              <th className="px-5 py-3 font-medium">Status</th>
              <th className="px-5 py-3 font-medium" />
            </tr>
          </thead>
          <tbody>
            {members.map((m) => (
              <tr key={m.id} className="border-b last:border-0" style={{ borderColor: 'var(--color-line)' }}>
                <td className="px-5 py-3.5 font-medium">{m.username}</td>
                <td className="px-5 py-3.5">
                  <select
                    value={m.role}
                    onChange={(e) => changeRole(m.id, e.target.value)}
                    className="input-field rounded-lg px-2.5 py-1.5 text-xs"
                  >
                    {Object.values(ROLES).map((r) => (
                      <option key={r.key} value={r.key}>{r.label}</option>
                    ))}
                  </select>
                </td>
                <td className="px-5 py-3.5">
                  <span
                    className="rounded-full px-2.5 py-1 text-xs font-medium capitalize"
                    style={{
                      color: m.status === 'active' ? 'var(--color-ok)' : 'var(--color-med)',
                      background: m.status === 'active' ? 'rgba(62,207,142,0.12)' : 'rgba(232,197,71,0.12)',
                    }}
                  >
                    {m.status}
                  </span>
                </td>
                <td className="px-5 py-3.5 text-right">
                  <button onClick={() => remove(m.id)} className="rounded-lg p-2 text-[color:var(--color-dim)] hover:bg-[color:var(--color-crit-soft)] hover:text-[color:var(--color-crit)]">
                    <Trash2 size={14} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {showInvite && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ background: 'rgba(5,8,16,0.6)' }} onClick={() => setShowInvite(false)}>
          <form
            onSubmit={invite}
            onClick={(e) => e.stopPropagation()}
            className="card w-full max-w-sm rounded-2xl p-6"
          >
            <h3 className="text-base font-semibold">Invite a team member</h3>
            <p className="mt-1 text-xs text-[color:var(--color-muted)]">They'll receive a sign-in link for this organization's Orion workspace.</p>
            <div className="mt-5 space-y-3">
              <input
                value={newUsername}
                onChange={(e) => setNewUsername(e.target.value)}
                placeholder="Username"
                className="input-field w-full rounded-xl px-3.5 py-2.5 text-sm"
                autoFocus
              />
              <select value={newRole} onChange={(e) => setNewRole(e.target.value)} className="input-field w-full rounded-xl px-3.5 py-2.5 text-sm">
                {Object.values(ROLES).map((r) => (
                  <option key={r.key} value={r.key}>{r.label}</option>
                ))}
              </select>
            </div>
            <div className="mt-5 flex gap-2">
              <button type="button" onClick={() => setShowInvite(false)} className="btn-ghost flex-1 rounded-xl py-2.5 text-sm">
                Cancel
              </button>
              <button type="submit" className="btn-primary flex-1 rounded-xl py-2.5 text-sm">
                Send invite
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  )
}
