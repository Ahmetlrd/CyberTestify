'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { COMPANY } from '../lib/company';
import { Logo } from './Logo';
import { CookiePrefsButton } from './CookiePrefsButton';
import { getRegion, REGION_CODES, type RegionConfig } from '../config/regions';
import { getDict } from '../config/i18n';

const LEGAL_LINKS_TR: Array<[string, string]> = [
  ['Kullanım Koşulları', '/legal/kullanim-kosullari'],
  ['KVKK Aydınlatma Metni', '/legal/kvkk-aydinlatma'],
  ['Gizlilik Politikası ve Sözleşmesi', '/legal/gizlilik'],
  ['Çerez Politikası', '/legal/cerez'],
  ['Mesafeli Satış Sözleşmesi', '/legal/mesafeli-satis'],
  ['Ön Bilgilendirme Formu', '/legal/on-bilgilendirme'],
  ['Teslimat, İptal / İade & Cayma', '/legal/iptal-iade'],
  ['Sorumluluk Reddi', '/legal/sorumluluk-reddi'],
];
// (Almanya) /de'de Alman hukuki sayfa seti (TR slug'larından AYRI).
const LEGAL_LINKS_DE: Array<[string, string]> = [
  ['Impressum', '/legal/impressum'],
  ['Datenschutzerklärung', '/legal/datenschutz'],
  ['AGB', '/legal/agb'],
  ['Widerrufsbelehrung', '/legal/widerruf'],
];

// (İngiltere) /en'de UK hukuki sayfa seti (TR/DE slug'larından AYRI).
const LEGAL_LINKS_EN: Array<[string, string]> = [
  ['Terms & Conditions', '/legal/terms'],
  ['Privacy Policy', '/legal/privacy'],
  ['Cancellation Rights', '/legal/cancellation'],
  ['Business Information', '/legal/business-info'],
];

// (Almanya) Footer üst-link etiketleri de dile göre — /de'de Almanca + Künye → Impressum.
const NAV_LINKS_DE = { about: 'Über uns', blog: 'Blog', openSource: 'Open Source', contact: 'Kontakt & Impressum →' };
const NAV_LINKS_TR = { about: 'Hakkımızda', blog: 'Blog', openSource: 'Açık Kaynak', contact: 'İletişim & Künye →' };
const NAV_LINKS_EN = { about: 'About', blog: 'Blog', openSource: 'Open Source', contact: 'Contact & Business Info →' };

export function Footer({ region }: { region: RegionConfig }) {
  // (BUG DÜZELTME) Footer kök layout'ta cookie-region ile render edilir; kök layout client-navigasyonda
  // YENİDEN RENDER EDİLMEZ → bölge değişince yasal başlıklar/linkler ESKİ dil/bölgede kalıyordu. Çözüm:
  // bölge-önekli sayfada aktif bölgeyi URL'den TÜRET (RegionSelector ile aynı desen); yoksa prop'a düş.
  const pathname = usePathname();
  const seg = (pathname ?? '/').split('/')[1] ?? '';
  const activeRegion = (REGION_CODES as readonly string[]).includes(seg) ? getRegion(seg) : region;

  const d = getDict(activeRegion).footer;
  const isDe = activeRegion.lang === 'de';
  const isEn = activeRegion.lang === 'en';
  const legalLinks = isDe ? LEGAL_LINKS_DE : isEn ? LEGAL_LINKS_EN : LEGAL_LINKS_TR;
  const nav = isDe ? NAV_LINKS_DE : isEn ? NAV_LINKS_EN : NAV_LINKS_TR;
  // Künye/Impressum → /de'de Alman Impressum sayfası; TR'de mevcut /iletisim korunur.
  // (URL TUTARLILIGI) Tum footer linkleri artik /{bolge}/... deseninde.
  const contactHref = isDe ? '/de/legal/impressum' : isEn ? '/en/legal/business-info' : `/${activeRegion.code}/iletisim`;

  return (
    <footer className="mt-24 bg-brand-deep text-white/80">
      <div className="container-page py-14">
        <div className="grid gap-10 md:grid-cols-[1.3fr_1fr]">
          <div>
            {/* Yesil zemin: logo (yesil kalkan) + yazi BEYAZ oval pill icinde -> net gorunur. */}
            <div className="inline-flex items-center gap-2.5 rounded-pill bg-white px-4 py-2 shadow-sm">
              <Logo className="h-7 w-7" />
              <span className="text-lg font-extrabold tracking-tight text-brand">CyberTestify</span>
            </div>
            <p className="mt-4 max-w-sm text-sm leading-relaxed text-white/70">{d.tagline}</p>
            <p className="mt-4 text-sm">
              {d.questions}{' '}
              <a href={`mailto:${activeRegion.supportEmail}`} className="font-medium text-accent hover:underline">
                {activeRegion.supportEmail}
              </a>
            </p>
            <p className="mt-2 flex flex-wrap gap-x-4 text-sm">
              <Link href={`/${activeRegion.code}/hakkimizda`} className="font-medium text-white/80 hover:text-white hover:underline">
                {nav.about}
              </Link>
              <Link href={`/${activeRegion.code}/blog`} className="font-medium text-white/80 hover:text-white hover:underline">
                {nav.blog}
              </Link>
              <Link href={`/${activeRegion.code}/acik-kaynak`} className="font-medium text-white/80 hover:text-white hover:underline">
                {nav.openSource}
              </Link>
              <Link href={contactHref} className="font-medium text-white/80 hover:text-white hover:underline">
                {nav.contact}
              </Link>
            </p>
          </div>

          <div>
            <h3 className="text-xs font-semibold uppercase tracking-widest text-white/50">{d.legal}</h3>
            {activeRegion.legalReady ? (
              <ul className="mt-4 grid grid-cols-1 gap-2.5 sm:grid-cols-2">
                {legalLinks.map(([label, href]) => (
                  <li key={href}>
                    <Link href={`/${activeRegion.code}${href}`} className="text-sm text-white/70 transition hover:text-white">
                      {label}
                    </Link>
                  </li>
                ))}
                <li>
                  <CookiePrefsButton className="text-sm text-white/70 transition hover:text-white" />
                </li>
              </ul>
            ) : (
              <p className="mt-4 text-sm text-white/50">
                Legal documents for this region are being prepared.
              </p>
            )}
          </div>
        </div>

        <div className="mt-12 border-t border-white/10 pt-6 text-xs leading-relaxed text-white/55">
          <div className="font-semibold text-white/75">{COMPANY.brand}</div>
          <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1">
            <span>
              <a href={`mailto:${COMPANY.email}`} className="hover:text-white">
                {COMPANY.email}
              </a>
            </span>
          </div>
          {/* iyzico resmi "iyzico ile ode" bandi (Visa/Mastercard/Troy dahil) — koyu zemin icin White */}
          <img
            src="/iyzico/logo_band_white.svg"
            alt={`${isDe ? 'Mit iyzico bezahlen' : isEn ? 'Pay with iyzico' : 'iyzico ile Öde'} — Visa, Mastercard, Troy`}
            className="mt-4 h-auto w-auto max-w-full"
            width={456}
            height={32}
          />
          <div className="mt-3 text-white/40">
            © {COMPANY.brand} — {d.disclaimer} v{COMPANY.legalVersion}
          </div>
        </div>
      </div>
    </footer>
  );
}
