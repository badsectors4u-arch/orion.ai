import { useState } from 'react'
import { Fingerprint, UsbIcon, Bell, Building2, Check } from 'lucide-react'
import PageHeader from '../components/PageHeader.jsx'
import { RoleBadge } from '../components/Badges.jsx'
import { useAuth } from '../state/AuthContext.jsx'

export default function Settings() {
  const { user, role, can } = useAuth()
  const [biometricOn, setBiometricOn] = useState(true)
  const [keyOn, setKeyOn] = useState(false)
  const [notifyCritical, setNotifyCritical] = useState(true)
  const [notifyWeekly, setNotifyWeekly] = useState(true)
  const [saved, setSaved] = useState(false)

  const save = () => {
    setSaved(true)
    setTimeout(() => setSaved(false), 1800)
  }

  return (
    <div className="pb-10">
      <PageHeader title="Settings" subtitle="Organization, security, and notification preferences." />

      <div className="mx-8 mt-6 max-w-2xl space-y-4">
        <section className="card rounded-2xl p-6">
          <div className="flex items-center gap-2.5">
            <Building2 size={17} className="text-[color:var(--color-muted)]" />
            <h3 className="text-sm font-semibold">Organization</h3>
          </div>
          <div className="mt-4 flex items-center justify-between rounded-xl px-4 py-3" style={{ background: 'var(--color-panel-2)' }}>
            <div>
              <p className="text-sm font-medium">{user?.orgName || 'Demo Organization'}</p>
              <p className="mt-0.5 text-xs text-[color:var(--color-dim)]">Signed in as this organization's {role}</p>
            </div>
            <RoleBadge role={role} />
          </div>
        </section>

        <section className="card rounded-2xl p-6">
          <div className="flex items-center gap-2.5">
            <Fingerprint size={17} className="text-[color:var(--color-muted)]" />
            <h3 className="text-sm font-semibold">Authentication methods</h3>
          </div>
          <p className="mt-1.5 text-xs text-[color:var(--color-muted)]">
            Orion supports password, biometric, and hardware security key sign-in. Enable the ones your organization will use.
          </p>
          <div className="mt-4 space-y-2.5">
            <ToggleRow
              icon={Fingerprint}
              label="Biometric (Face ID / fingerprint)"
              desc="Lets this device's biometric sensor stand in for a password."
              checked={biometricOn}
              onChange={() => setBiometricOn((v) => !v)}
              disabled={!can('manageSettings')}
            />
            <ToggleRow
              icon={UsbIcon}
              label="Hardware security key"
              desc="Require a physical FIDO2/WebAuthn key to sign in."
              checked={keyOn}
              onChange={() => setKeyOn((v) => !v)}
              disabled={!can('manageSettings')}
            />
          </div>
          {!can('manageSettings') && (
            <p className="mt-3 text-xs text-[color:var(--color-dim)]">Only Admins can change authentication settings.</p>
          )}
        </section>

        <section className="card rounded-2xl p-6">
          <div className="flex items-center gap-2.5">
            <Bell size={17} className="text-[color:var(--color-muted)]" />
            <h3 className="text-sm font-semibold">Notifications</h3>
          </div>
          <div className="mt-4 space-y-2.5">
            <ToggleRow
              label="Critical findings"
              desc="Get notified immediately when a critical-severity finding is detected."
              checked={notifyCritical}
              onChange={() => setNotifyCritical((v) => !v)}
            />
            <ToggleRow
              label="Weekly summary"
              desc="A digest of scans, findings, and trends every Monday."
              checked={notifyWeekly}
              onChange={() => setNotifyWeekly((v) => !v)}
            />
          </div>
        </section>

        <div className="flex items-center gap-3">
          <button onClick={save} className="btn-primary rounded-xl px-5 py-2.5 text-sm">
            Save changes
          </button>
          {saved && (
            <span className="flex items-center gap-1.5 text-sm text-[color:var(--color-ok)]">
              <Check size={15} /> Saved
            </span>
          )}
        </div>
      </div>
    </div>
  )
}

function ToggleRow({ icon: Icon, label, desc, checked, onChange, disabled }) {
  return (
    <div className="flex items-center justify-between gap-4 rounded-xl px-4 py-3" style={{ background: 'var(--color-panel-2)' }}>
      <div className="flex items-start gap-3">
        {Icon && <Icon size={16} className="mt-0.5 text-[color:var(--color-muted)]" />}
        <div>
          <p className="text-sm font-medium">{label}</p>
          <p className="mt-0.5 text-xs leading-snug text-[color:var(--color-dim)]">{desc}</p>
        </div>
      </div>
      <button
        onClick={onChange}
        disabled={disabled}
        className="relative h-6 w-11 shrink-0 rounded-full transition-colors disabled:opacity-50"
        style={{ background: checked ? 'var(--color-accent)' : 'var(--color-line)' }}
      >
        <span
          className="absolute top-0.5 h-5 w-5 rounded-full bg-white transition-all"
          style={{ left: checked ? '22px' : '2px' }}
        />
      </button>
    </div>
  )
}
