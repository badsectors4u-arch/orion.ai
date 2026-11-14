export default function PageHeader({ title, subtitle, action }) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-4 px-8 pt-8">
      <div>
        <h1 className="font-display text-xl font-semibold">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-[color:var(--color-muted)]">{subtitle}</p>}
      </div>
      {action}
    </div>
  )
}
