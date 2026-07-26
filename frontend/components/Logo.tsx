export function Logo({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" fill="none" className={className} aria-hidden="true">
      <path
        d="M16 2.5l11 4v8.2c0 6.9-4.6 12.2-11 14.8C9.6 26.9 5 21.6 5 14.7V6.5l11-4z"
        fill="#123F3A"
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
