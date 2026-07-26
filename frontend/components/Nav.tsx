import Link from 'next/link';
import { Logo } from './Logo';

const LINKS: Array<[string, string]> = [
  ['Nasıl Çalışır', '/#nasil-calisir'],
  ['Neden Biz', '/#neden-biz'],
  ['Paketler', '/#paketler'],
];

export function Nav() {
  return (
    <header className="sticky top-0 z-40 border-b border-line/70 bg-canvas/80 backdrop-blur">
      <nav className="container-page flex h-16 items-center justify-between gap-4">
        <Link href="/" className="flex items-center gap-2.5" aria-label="CyberTestify ana sayfa">
          <Logo className="h-8 w-8" />
          <span className="text-lg font-extrabold tracking-tight text-brand">
            Cyber<span className="text-accent-600">Testify</span>
          </span>
        </Link>

        <div className="hidden items-center gap-7 md:flex">
          {LINKS.map(([label, href]) => (
            <Link key={href} href={href} className="text-sm font-medium text-ink-soft transition hover:text-brand">
              {label}
            </Link>
          ))}
        </div>

        <div className="flex items-center gap-2 sm:gap-3">
          {/* Bölge seçici — Faz 5'te (çok-bölgeli) işlevsel hale gelecek placeholder */}
          <span className="hidden items-center gap-1 rounded-pill border border-line bg-white px-2.5 py-1.5 text-xs font-medium text-ink-muted sm:inline-flex">
            🇹🇷 TR
          </span>
          <Link href="/login" className="btn-ghost hidden sm:inline-flex">
            Giriş
          </Link>
          <Link href="/register" className="btn-primary">
            Ücretsiz Doğrula
          </Link>
        </div>
      </nav>
    </header>
  );
}
