import Link from 'next/link';
import { COMPANY } from '../lib/company';
import { Logo } from './Logo';
import type { RegionConfig } from '../config/regions';
import { getDict } from '../config/i18n';

const LEGAL_LINKS: Array<[string, string]> = [
  ['Kullanım Koşulları', '/legal/kullanim-kosullari'],
  ['KVKK Aydınlatma Metni', '/legal/kvkk-aydinlatma'],
  ['Gizlilik Politikası ve Sözleşmesi', '/legal/gizlilik'],
  ['Çerez Politikası', '/legal/cerez'],
  ['Mesafeli Satış Sözleşmesi', '/legal/mesafeli-satis'],
  ['Ön Bilgilendirme Formu', '/legal/on-bilgilendirme'],
  ['Teslimat, İptal / İade & Cayma', '/legal/iptal-iade'],
  ['Sorumluluk Reddi', '/legal/sorumluluk-reddi'],
];

export function Footer({ region }: { region: RegionConfig }) {
  const d = getDict(region).footer;
  // TR fatura yöntemi = e-Arşiv → tam imprint (MERSİS/vergi). Diğer bölgeler için
  // kendi tüzel kişilik/vergi bilgileri ayrıca hazırlanacak (config-driven).
  const showTrImprint = region.invoicingMethod === 'earsiv';

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
              <a href={`mailto:${region.supportEmail}`} className="font-medium text-accent hover:underline">
                {region.supportEmail}
              </a>
            </p>
            <p className="mt-2 flex flex-wrap gap-x-4 text-sm">
              <Link href="/hakkimizda" className="font-medium text-white/80 hover:text-white hover:underline">
                Hakkımızda
              </Link>
              <Link href="/iletisim" className="font-medium text-white/80 hover:text-white hover:underline">
                İletişim &amp; Künye →
              </Link>
            </p>
          </div>

          <div>
            <h3 className="text-xs font-semibold uppercase tracking-widest text-white/50">{d.legal}</h3>
            {region.legalReady ? (
              <ul className="mt-4 grid grid-cols-1 gap-2.5 sm:grid-cols-2">
                {LEGAL_LINKS.map(([label, href]) => (
                  <li key={href}>
                    <Link href={href} className="text-sm text-white/70 transition hover:text-white">
                      {label}
                    </Link>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="mt-4 text-sm text-white/50">
                Legal documents for this region are being prepared.
              </p>
            )}
          </div>
        </div>

        <div className="mt-12 border-t border-white/10 pt-6 text-xs leading-relaxed text-white/55">
          <div className="font-semibold text-white/75">{region.companyLegalName}</div>
          {showTrImprint && (
            <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1">
              <span>{COMPANY.address}</span>
              <span>
                {COMPANY.taxOffice} V.D. — Vergi No: {COMPANY.taxNo}
              </span>
              <span>Ticaret Sicil No: {COMPANY.ticaretSicilNo}</span>
              <span>MERSİS: {COMPANY.mersisNo}</span>
              <span>Tel: {COMPANY.phone}</span>
              <span>
                <a href={`mailto:${COMPANY.email}`} className="hover:text-white">
                  {COMPANY.email}
                </a>
              </span>
              {COMPANY.kep && <span>KEP: {COMPANY.kep}</span>}
            </div>
          )}
          {/* iyzico resmi "iyzico ile ode" bandi (Visa/Mastercard/Troy dahil) — koyu zemin icin White */}
          <img
            src="/iyzico/logo_band_white.svg"
            alt="iyzico ile Öde — Visa, Mastercard, Troy"
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
