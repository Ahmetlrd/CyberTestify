// (WINDOWS BAYRAK FIX) Bölge bayrakları emoji ile gösteriliyordu; Windows'ta flag-emoji fontu YOK →
// "TR/DE/GB" harfleri çıkıyordu. Çözüm: OS-bağımsız satır-içi SVG bayraklar. Kap `overflow-hidden`
// olduğundan iç clipPath'e gerek yok (birden çok örnekte id çakışması da olmaz).
export function Flag({ code, className = '' }: { code: string; className?: string }) {
  const c = `inline-block h-3.5 w-5 shrink-0 overflow-hidden rounded-[2px] align-[-2px] ring-1 ring-black/10 ${className}`;
  switch (code) {
    case 'de':
      return (
        <svg viewBox="0 0 5 3" className={c} aria-hidden>
          <rect width="5" height="3" fill="#000" /><rect y="1" width="5" height="1" fill="#DD0000" /><rect y="2" width="5" height="1" fill="#FFCE00" />
        </svg>
      );
    case 'tr':
      return (
        <svg viewBox="0 0 30 20" className={c} aria-hidden>
          <rect width="30" height="20" fill="#E30A17" />
          <circle cx="12" cy="10" r="5" fill="#fff" /><circle cx="13.6" cy="10" r="4" fill="#E30A17" />
          <path fill="#fff" d="M19.5 7.4 20.1 9.2 22 9.2 20.4 10.3 21 12.1 19.5 11 18 12.1 18.6 10.3 17 9.2 18.9 9.2Z" />
        </svg>
      );
    case 'en':
      return (
        <svg viewBox="0 0 60 30" className={c} aria-hidden>
          <rect width="60" height="30" fill="#012169" />
          <path d="M0,0 60,30 M60,0 0,30" stroke="#fff" strokeWidth="6" />
          <path d="M0,0 60,30 M60,0 0,30" stroke="#C8102E" strokeWidth="3" />
          <path d="M30,0 V30 M0,15 H60" stroke="#fff" strokeWidth="10" />
          <path d="M30,0 V30 M0,15 H60" stroke="#C8102E" strokeWidth="6" />
        </svg>
      );
    case 'us':
      return (
        <svg viewBox="0 0 13 8" className={c} aria-hidden>
          <rect width="13" height="8" fill="#B22234" />
          <g fill="#fff"><rect y="1" width="13" height="1" /><rect y="3" width="13" height="1" /><rect y="5" width="13" height="1" /><rect y="7" width="13" height="1" /></g>
          <rect width="6" height="4" fill="#3C3B6E" />
        </svg>
      );
    case 'ae':
      return (
        <svg viewBox="0 0 6 3" className={c} aria-hidden>
          <rect width="6" height="1" fill="#00732F" /><rect y="1" width="6" height="1" fill="#fff" /><rect y="2" width="6" height="1" fill="#000" />
          <rect width="1.5" height="3" fill="#FF0000" />
        </svg>
      );
    default:
      return <span className={className}>{code.toUpperCase()}</span>;
  }
}
