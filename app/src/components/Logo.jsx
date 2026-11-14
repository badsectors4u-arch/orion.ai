export default function Logo({ size = 28, withWordmark = true }) {
  return (
    <div className="flex items-center gap-2.5">
      <svg width={size} height={size} viewBox="0 0 64 64" fill="none">
        <path d="M32 8 L50 17 V35 C50 48 41 57 32 59 C23 57 14 48 14 35 V17 Z" stroke="#5FA8FF" strokeWidth="2.5" />
        <path d="M32 23 L35.5 29.5 L42 32 L35.5 34.5 L32 41 L28.5 34.5 L22 32 L28.5 29.5 Z" fill="url(#g)" />
        <circle cx="46" cy="20" r="2.2" fill="#5FA8FF" />
        <path d="M18 24 C28 14 40 14 48 20" stroke="#2F6FED" strokeWidth="1.4" fill="none" opacity="0.7" />
        <defs>
          <linearGradient id="g" x1="22" y1="23" x2="42" y2="41" gradientUnits="userSpaceOnUse">
            <stop stopColor="#CFE3FF" />
            <stop offset="1" stopColor="#5FA8FF" />
          </linearGradient>
        </defs>
      </svg>
      {withWordmark && (
        <span className="font-display font-semibold tracking-wide text-[color:var(--color-text)]" style={{ fontSize: size * 0.6 }}>
          ORION
        </span>
      )}
    </div>
  )
}
