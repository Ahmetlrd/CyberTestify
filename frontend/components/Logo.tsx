// onDark: koyu/yesil zeminler (Footer bg-brand-deep gibi) icin — kalkan BEYAZ olur ki
// marka-teal (#123F3A) zeminde kaybolmasin. Acik zeminde (Nav) varsayilan teal kalkan.
export function Logo({ className, onDark = false }: { className?: string; onDark?: boolean }) {
  return (
    <svg viewBox="0 0 32 32" fill="none" className={className} aria-hidden="true">
      <path
        d="M16 2.5l11 4v8.2c0 6.9-4.6 12.2-11 14.8C9.6 26.9 5 21.6 5 14.7V6.5l11-4z"
        fill={onDark ? '#FFFFFF' : '#123F3A'}
      />
      <path
        d="M10.5 16.2l3.7 3.7 7.3-7.6"
        stroke="#F5A623"
        strokeWidth="2.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
