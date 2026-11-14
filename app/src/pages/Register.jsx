import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { ShieldCheck, Users, Eye, Fingerprint, UsbIcon, Check } from 'lucide-react'
import { ROLES } from '../data/mock.js'
import { useAuth } from '../state/AuthContext.jsx'
import AuthShell from '../components/AuthShell.jsx'

const ROLE_ICONS = { admin: ShieldCheck, analyst: Users, viewer: Eye }

export default function Register() {
  const [org, setOrg] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState('admin')
  const [stepUp, setStepUp] = useState(null) // null | 'biometric' | 'key'
  const { login } = useAuth()
  const navigate = useNavigate()

  const submit = (e) => {
    e.preventDefault()
    login(org || 'Demo Organization', role)
    navigate('/dashboard')
  }

  return (
    <AuthShell
      title="Create your organization"
      subtitle="Set up Orion for your security team in a few steps."
    >
      <form onSubmit={submit} className="space-y-4">
        <Field label="Organization name">
          <input
            className="input-field w-full rounded-xl px-3.5 py-2.5 text-sm"
            placeholder="e.g. Acme Corp"
            value={org}
            onChange={(e) => setOrg(e.target.value)}
            required
          />
        </Field>

        <div className="grid grid-cols-2 gap-3">
          <Field label="Username">
            <input
              className="input-field w-full rounded-xl px-3.5 py-2.5 text-sm"
              placeholder="Username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              required
            />
          </Field>
          <Field label="Password">
            <input
              type="password"
              className="input-field w-full rounded-xl px-3.5 py-2.5 text-sm"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="new-password"
              required
            />
          </Field>
        </div>

        <div>
          <span className="mb-2 block text-xs font-medium text-[color:var(--color-muted)]">
            Choose your role
          </span>
          <div className="grid grid-cols-1 gap-2">
            {Object.values(ROLES).map((r) => {
              const Icon = ROLE_ICONS[r.key]
              const active = role === r.key
              return (
                <button
                  type="button"
                  key={r.key}
                  onClick={() => setRole(r.key)}
                  className="flex items-start gap-3 rounded-xl px-3.5 py-3 text-left transition-colors"
                  style={{
                    background: active ? 'var(--color-accent-soft)' : 'var(--color-panel-2)',
                    border: `1px solid ${active ? 'var(--color-accent-bright)' : 'var(--color-line)'}`,
                  }}
                >
                  <div
                    className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg"
                    style={{ background: active ? 'var(--color-accent-bright)' : 'var(--color-panel)' }}
                  >
                    <Icon size={15} className={active ? 'text-[#04101f]' : 'text-[color:var(--color-muted)]'} />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center justify-between gap-2">
                      <p className="text-sm font-semibold">{r.label}</p>
                      {active && <Check size={15} className="text-[color:var(--color-accent-bright)]" />}
                    </div>
                    <p className="mt-0.5 text-xs leading-snug text-[color:var(--color-muted)]">{r.blurb}</p>
                  </div>
                </button>
              )
            })}
          </div>
        </div>

        {role === 'admin' && (
          <div>
            <span className="mb-2 block text-xs font-medium text-[color:var(--color-muted)]">
              Add a second factor for Admin (recommended)
            </span>
            <div className="grid grid-cols-2 gap-2">
              <StepUpOption
                active={stepUp === 'biometric'}
                icon={Fingerprint}
                label="Biometric"
                onClick={() => setStepUp(stepUp === 'biometric' ? null : 'biometric')}
              />
              <StepUpOption
                active={stepUp === 'key'}
                icon={UsbIcon}
                label="Security Key"
                onClick={() => setStepUp(stepUp === 'key' ? null : 'key')}
              />
            </div>
          </div>
        )}

        <button type="submit" className="btn-primary mt-2 w-full rounded-xl py-2.5 text-sm">
          Create account
        </button>
      </form>

      <p className="mt-6 text-center text-sm text-[color:var(--color-muted)]">
        Already have an organization?{' '}
        <Link to="/login" className="font-medium text-[color:var(--color-accent-bright)] hover:underline">
          Sign in
        </Link>
      </p>
    </AuthShell>
  )
}

function Field({ label, children }) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-xs font-medium text-[color:var(--color-muted)]">{label}</span>
      {children}
    </label>
  )
}

function StepUpOption({ active, icon: Icon, label, onClick }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="flex flex-col items-center gap-1.5 rounded-xl py-3 text-xs font-medium"
      style={{
        background: active ? 'var(--color-accent-soft)' : 'var(--color-panel-2)',
        border: `1px solid ${active ? 'var(--color-accent-bright)' : 'var(--color-line)'}`,
        color: active ? 'var(--color-accent-bright)' : 'var(--color-muted)',
      }}
    >
      <Icon size={18} />
      {label}
    </button>
  )
}
