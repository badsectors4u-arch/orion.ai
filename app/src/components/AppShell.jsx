import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import {
  LayoutDashboard, ScanLine, ListChecks, Share2, FileText, Users, Settings as SettingsIcon, LogOut,
} from 'lucide-react'
import Logo from './Logo.jsx'
import { RoleBadge } from './Badges.jsx'
import { useAuth } from '../state/AuthContext.jsx'
import AskOrion from './AskOrion.jsx'

const NAV = [
  { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard, always: true },
  { to: '/scans', label: 'Scans', icon: ScanLine, always: true },
  { to: '/findings', label: 'Findings', icon: ListChecks, always: true },
  { to: '/network', label: 'Network Map', icon: Share2, always: true },
  { to: '/reports', label: 'Reports', icon: FileText, always: true },
  { to: '/users', label: 'Users & Roles', icon: Users, perm: 'manageUsers' },
  { to: '/settings', label: 'Settings', icon: SettingsIcon, always: true },
]

export default function AppShell() {
  const { user, role, can, logout } = useAuth()
  const navigate = useNavigate()

  return (
    <div className="flex h-screen" style={{ background: 'var(--color-ink)' }}>
      <aside className="flex w-64 shrink-0 flex-col border-r" style={{ borderColor: 'var(--color-line)' }}>
        <div className="flex items-center gap-2.5 px-5 py-5">
          <Logo size={26} />
        </div>
        <nav className="flex-1 space-y-1 px-3">
          {NAV.filter((item) => item.always || can(item.perm)).map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition-colors ${
                  isActive ? 'text-[color:var(--color-text)]' : 'text-[color:var(--color-muted)] hover:text-[color:var(--color-text)]'
                }`
              }
              style={({ isActive }) => ({
                background: isActive ? 'var(--color-accent-soft)' : 'transparent',
              })}
            >
              <item.icon size={18} strokeWidth={2} />
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="mx-3 mb-3 rounded-xl p-3" style={{ background: 'var(--color-panel-2)', border: '1px solid var(--color-line)' }}>
          <div className="flex items-center justify-between">
            <div className="min-w-0">
              <p className="truncate text-sm font-medium">{user?.orgName || 'Organization'}</p>
              <div className="mt-1"><RoleBadge role={role} /></div>
            </div>
            <button
              onClick={() => { logout(); navigate('/login') }}
              className="rounded-lg p-2 text-[color:var(--color-dim)] hover:text-[color:var(--color-crit)] hover:bg-[color:var(--color-crit-soft)]"
              title="Log out"
            >
              <LogOut size={16} />
            </button>
          </div>
        </div>
      </aside>

      <main className="relative flex-1 overflow-y-auto">
        <Outlet />
        <AskOrion />
      </main>
    </div>
  )
}
