'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Logo } from './Logo';
import { RegionSelector } from './RegionSelector';
import { AuthNav } from './AuthNav';
import { MobileMenu } from './MobileMenu';
import { getRegion, REGION_CODES, type RegionConfig } from '../config/regions';
import { getDict } from '../config/i18n';

export function Nav({ region }: { region: RegionConfig }) {
  // (BUG DÜZELTME) Nav kök layout'ta cookie-region ile render edilir; kök layout client-navigasyonda
  // YENİDEN RENDER EDİLMEZ → bölge değişince appbar (link etiketleri/dil, RegionSelector) ESKİ kalıyordu.
  // Çözüm: aktif bölgeyi URL'den TÜRET (Footer/RegionSelector ile aynı desen); yoksa prop'a düş.
  const pathname = usePathname();
  const seg = (pathname ?? '/').split('/')[1] ?? '';
  const activeRegion = (REGION_CODES as readonly string[]).includes(seg) ? getRegion(seg) : region;
  const d = getDict(activeRegion).nav;
  const base = `/${activeRegion.code}`;

  const links: Array<[string, string]> = [
    [d.how, `${base}#nasil-calisir`],
    [d.why, `${base}#neden-biz`],
    [d.packages, `${base}/packages`],
    // (P3) S1 Otonom AI Red Team /de + /en'de gizli → nav'da da gösterme.
    ...(activeRegion.code === 'de' || activeRegion.code === 'en' ? [] : [[d.otonom, `${base}/otonom-red-team`] as [string, string]]),
    ['Blog', `${base}/blog`], // SEO: her sayfada blog'a internal link; bölge-önekli (/tr/blog, /de/blog)
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
          <RegionSelector current={activeRegion.code} />
          {/* Auth butonlari desktop'ta; mobilde hamburger menu icine tasinir (tasma olmasin). */}
          <div className="hidden items-center gap-2 sm:gap-3 md:flex">
            <AuthNav labels={{ login: d.login, cta: d.cta, panel: d.panel, logout: d.logout, profile: d.profile }} />
          </div>
          <MobileMenu links={links} authLabels={{ login: d.login, cta: d.cta, panel: d.panel, profile: d.profile }} regionCode={activeRegion.code} />
        </div>
      </nav>
    </header>
  );
}
