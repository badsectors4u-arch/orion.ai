import Logo from './Logo.jsx'

export default function AuthShell({ title, subtitle, children, footnote }) {
  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden px-4 py-10" style={{ background: 'var(--color-ink)' }}>
      {/* ambient grid + glow backdrop */}
      <div
        className="pointer-events-none absolute inset-0 opacity-40"
        style={{
          backgroundImage:
            'linear-gradient(var(--color-line) 1px, transparent 1px), linear-gradient(90deg, var(--color-line) 1px, transparent 1px)',
          backgroundSize: '44px 44px',
          maskImage: 'radial-gradient(ellipse at 50% 0%, black 0%, transparent 70%)',
        }}
      />
      <div
        className="pointer-events-none absolute -top-40 left-1/2 h-96 w-[48rem] -translate-x-1/2 rounded-full opacity-30 blur-3xl"
        style={{ background: 'var(--color-accent)' }}
      />

      <div className="relative z-10 w-full max-w-md">
        <div className="mb-8 flex flex-col items-center text-center">
          <Logo size={34} />
          <h1 className="mt-6 font-display text-2xl font-semibold">{title}</h1>
          <p className="mt-1.5 text-sm text-[color:var(--color-muted)]">{subtitle}</p>
        </div>

        <div className="card rounded-2xl p-7">{children}</div>

        <p className="mt-6 text-center text-xs text-[color:var(--color-dim)]">
          {footnote || 'Demo environment — all data shown is simulated. No real credentials are stored.'}
        </p>
      </div>
    </div>
  )
}
