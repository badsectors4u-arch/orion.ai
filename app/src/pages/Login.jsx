import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { KeyRound, Fingerprint, UsbIcon, ShieldCheck, Loader2 } from 'lucide-react'
import { ROLES } from '../data/mock.js'
import { useAuth } from '../state/AuthContext.jsx'
import AuthShell from '../components/AuthShell.jsx'

const METHODS = [
  { key: 'password', label: 'Password', icon: KeyRound },
  { key: 'biometric', label: 'Biometric', icon: Fingerprint },
  { key: 'key', label: 'Security Key', icon: UsbIcon },
]

export default function Login() {
  const [method, setMethod] = useState('password')
  const [org, setOrg] = useState('')
  const [role, setRole] = useState('analyst')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [stage, setStage] = useState('idle') // idle | working | done
  const { login } = useAuth()
  const navigate = useNavigate()

  const complete = () => {
    login(org || 'Demo Organization', role)
    navigate('/dashboard')
  }

  const submitPassword = (e) => {
    e.preventDefault()
    complete()
  }

  const runDeviceAuth = () => {
    setStage('working')
    setTimeout(() => setStage('done'), 1400)
    setTimeout(() => complete(), 2000)
  }

  return (
    <AuthShell
      title="Welcome back"
      subtitle="Sign in to your organization's Orion dashboard."
    >
      <div className="mb-6 grid grid-cols-3 gap-2 rounded-xl p-1" style={{ background: 'var(--color-panel-2)' }}>
        {METHODS.map((m) => (
          <button
            key={m.key}
            onClick={() => { setMethod(m.key); setStage('idle') }}
            className="flex items-center justify-center gap-1.5 rounded-lg py-2 text-xs font-medium transition-colors"
            style={{
              background: method === m.key ? 'var(--color-accent-soft)' : 'transparent',
              color: method === m.key ? 'var(--color-accent-bright)' : 'var(--color-muted)',
            }}
          >
            <m.icon size={14} /> {m.label}
          </button>
        ))}
      </div>

      <div className="mb-5 grid grid-cols-1 gap-3">
        <Field label="Organization">
          <input
            className="input-field w-full rounded-xl px-3.5 py-2.5 text-sm"
            placeholder="e.g. Acme Corp"
            value={org}
            onChange={(e) => setOrg(e.target.value)}
          />
        </Field>
        <Field label="Sign in as">
          <select
            className="input-field w-full rounded-xl px-3.5 py-2.5 text-sm"
            value={role}
            onChange={(e) => setRole(e.target.value)}
          >
            {Object.values(ROLES).map((r) => (
              <option key={r.key} value={r.key}>{r.label}</option>
            ))}
          </select>
        </Field>
      </div>

      {method === 'password' && (
        <form onSubmit={submitPassword} className="space-y-3">
          <Field label="Username">
            <input
              className="input-field w-full rounded-xl px-3.5 py-2.5 text-sm"
              placeholder="Username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
            />
          </Field>
          <Field label="Password">
            <input
              type="password"
              className="input-field w-full rounded-xl px-3.5 py-2.5 text-sm"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
            />
          </Field>
          <button type="submit" className="btn-primary mt-2 w-full rounded-xl py-2.5 text-sm">
            Sign in
          </button>
        </form>
      )}

      {method === 'biometric' && (
        <DeviceAuth
          stage={stage}
          onRun={runDeviceAuth}
          icon={Fingerprint}
          idleText="Touch the sensor or use Face ID to continue"
          workingText="Scanning…"
          doneText="Identity verified"
        />
      )}

      {method === 'key' && (
        <DeviceAuth
          stage={stage}
          onRun={runDeviceAuth}
          icon={UsbIcon}
          idleText="Insert and tap your security key"
          workingText="Waiting for key…"
          doneText="Key verified"
        />
      )}

      <p className="mt-6 text-center text-sm text-[color:var(--color-muted)]">
        New organization?{' '}
        <Link to="/register" className="font-medium text-[color:var(--color-accent-bright)] hover:underline">
          Create an account
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

function DeviceAuth({ stage, onRun, icon: Icon, idleText, workingText, doneText }) {
  return (
    <div className="flex flex-col items-center rounded-2xl px-6 py-8" style={{ background: 'var(--color-panel-2)', border: '1px dashed var(--color-line)' }}>
      <button
        onClick={stage === 'idle' ? onRun : undefined}
        className="relative flex h-20 w-20 items-center justify-center rounded-full"
        style={{ background: 'var(--color-accent-soft)' }}
      >
        {stage === 'working' && <span className="absolute inset-0 rounded-full pulse-ring" style={{ border: '2px solid var(--color-accent-bright)' }} />}
        {stage === 'done' ? (
          <ShieldCheck size={30} className="text-[color:var(--color-ok)]" />
        ) : stage === 'working' ? (
          <Loader2 size={30} className="animate-spin text-[color:var(--color-accent-bright)]" />
        ) : (
          <Icon size={30} className="text-[color:var(--color-accent-bright)]" />
        )}
      </button>
      <p className="mt-4 text-sm font-medium">
        {stage === 'done' ? doneText : stage === 'working' ? workingText : idleText}
      </p>
      {stage === 'idle' && <p className="mt-1 text-xs text-[color:var(--color-dim)]">Tap the icon to simulate for this demo</p>}
    </div>
  )
}
