'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { readRegionCookie } from '../lib/region';
import { getRegion, REGION_CODES, type RegionCode } from '../config/regions';

// (404) Next'in varsayılan siyah/İngilizce sayfası yerine MARKALI + bölgeye göre lokalize sayfa.
// Kök layout'un içinde render edildiği için Nav (logo) ve Footer otomatik gelir → site ile tutarlı.
// HTTP durum kodu Next tarafından 404 döner (soft-200 değil) — burada dokunulmaz.
const T = {
  tr: {
    title: 'Aradığınız sayfa bulunamadı',
    sub: 'Bu adres taşınmış, adı değişmiş ya da hiç var olmamış olabilir. Aşağıdan devam edebilirsiniz.',
    home: 'Ana sayfaya dön',
    helpful: 'Şunlar işinize yarayabilir:',
    packages: 'Paketler',
    blog: 'Blog',
    contact: 'İletişim',
  },
  de: {
    title: 'Seite nicht gefunden',
    sub: 'Diese Adresse wurde möglicherweise verschoben, umbenannt oder hat nie existiert. Unten können Sie weitermachen.',
    home: 'Zur Startseite',
    helpful: 'Das könnte Ihnen weiterhelfen:',
    packages: 'Pakete',
    blog: 'Blog',
    contact: 'Kontakt',
  },
  en: {
    title: 'Page not found',
    sub: 'This address may have moved, been renamed, or never existed. You can continue from the links below.',
    home: 'Back to home',
    helpful: 'These might help:',
    packages: 'Packages',
    blog: 'Blog',
    contact: 'Contact',
  },
} as const;

export default function NotFound() {
  // Bölgeyi URL'den türet (/de/... → Almanca); bölge-öneksiz adreste cookie'ye düş.
  const pathname = usePathname();
  const seg = (pathname ?? '/').split('/')[1] ?? '';
  const region = (REGION_CODES as readonly string[]).includes(seg)
    ? getRegion(seg)
    : getRegion(readRegionCookie());
  const code = region.code as RegionCode;
  const lang = region.lang === 'de' ? 'de' : region.lang === 'en' ? 'en' : 'tr';
  const t = T[lang];

  return (
    <main className="container-page max-w-2xl py-20 text-center">
      {/* Marka rozeti — koyu yeşil kalkan + turuncu onay (site logosuyla aynı dil) */}
      <span className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl bg-brand-50">
        <svg width="34" height="34" viewBox="0 0 24 24" fill="none" aria-hidden>
          <path d="M12 2l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V5l7-3z" fill="#123F3A" />
          <path d="M9 12l2 2 4-4" stroke="#F5A623" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" fill="none" />
        </svg>
      </span>

      <p className="mt-6 text-5xl font-extrabold tracking-tight text-accent sm:text-6xl">404</p>
      <h1 className="mt-3 text-2xl font-extrabold text-brand sm:text-3xl">{t.title}</h1>
      <p className="mx-auto mt-3 max-w-md text-sm leading-relaxed text-ink-soft">{t.sub}</p>

      <div className="mt-8 flex justify-center">
        <Link href={`/${code}`} className="btn-primary px-6">{t.home}</Link>
      </div>

      <div className="mt-10 border-t border-line pt-6">
        <p className="text-xs font-semibold uppercase tracking-wide text-ink-muted">{t.helpful}</p>
        <div className="mt-3 flex flex-wrap justify-center gap-x-6 gap-y-2 text-sm font-semibold">
          <Link href={`/${code}/packages`} className="text-accent-600 hover:underline">{t.packages}</Link>
          <Link href={`/${code}/blog`} className="text-accent-600 hover:underline">{t.blog}</Link>
          <Link href={lang === 'de' ? '/de/legal/impressum' : lang === 'en' ? '/en/legal/business-info' : `/${code}/iletisim`} className="text-accent-600 hover:underline">{t.contact}</Link>
        </div>
      </div>
    </main>
  );
}
