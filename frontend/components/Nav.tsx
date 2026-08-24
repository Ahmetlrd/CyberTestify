import Link from 'next/link';
import { Logo } from './Logo';
import { RegionSelector } from './RegionSelector';
import { AuthNav } from './AuthNav';
import { MobileMenu } from './MobileMenu';
import type { RegionConfig } from '../config/regions';
import { getDict } from '../config/i18n';

export function Nav({ region }: { region: RegionConfig }) {
  const d = getDict(region).nav;
  const base = `/${region.code}`;

  const links: Array<[string, string]> = [
    [d.how, `${base}#nasil-calisir`],
    [d.why, `${base}#neden-biz`],
    [d.packages, `${base}/packages`],
    [d.otonom, `${base}/otonom-red-team`], // (Otonom AI Red Team — deneysel, ayrı katman)
    ['Blog', '/blog'], // SEO: her sayfada blog'a internal link (Google kesfi icin)
  ];

  return (
    <header className="sticky top-0 z-40 border-b border-line/70 bg-canvas/80 backdrop-blur">
      <nav className="container-page flex h-16 items-center justify-between gap-4">
        <Link href={base} className="flex items-center gap-2.5" aria-label="CyberTestify">
          <Logo className="h-8 w-8" />
          <span className="text-lg font-extrabold tracking-tight text-brand">
            Cyber<span className="text-accent-600">Testify</span>
          </span>
        </Link>

        <div className="hidden items-center gap-7 md:flex">
          {links.map(([label, href]) => (
            <Link key={href} href={href} className="text-sm font-medium text-ink-soft transition hover:text-brand">
              {label}
            </Link>
          ))}
        </div>

        <div className="flex items-center gap-2 sm:gap-3">
          <RegionSelector current={region.code} />
          {/* Auth butonlari desktop'ta; mobilde hamburger menu icine tasinir (tasma olmasin). */}
          <div className="hidden items-center gap-2 sm:gap-3 md:flex">
            <AuthNav labels={{ login: d.login, cta: d.cta, panel: d.panel, logout: d.logout, profile: d.profile }} />
          </div>
          <MobileMenu links={links} authLabels={{ login: d.login, cta: d.cta, panel: d.panel, profile: d.profile }} regionCode={region.code} />
        </div>
      </nav>
    </header>
  );
}
