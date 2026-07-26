import Link from 'next/link';
import { COMPANY } from '../lib/company';
import { Logo } from './Logo';
import type { RegionConfig } from '../config/regions';
import { getDict } from '../config/i18n';

const LEGAL_LINKS: Array<[string, string]> = [
  ['Kullanım Koşulları', '/legal/kullanim-kosullari'],
  ['KVKK Aydınlatma Metni', '/legal/kvkk-aydinlatma'],
  ['Gizlilik Politikası', '/legal/gizlilik'],
  ['Çerez Politikası', '/legal/cerez'],
  ['Mesafeli Satış Sözleşmesi', '/legal/mesafeli-satis'],
  ['Ön Bilgilendirme Formu', '/legal/on-bilgilendirme'],
  ['İptal / İade & Cayma', '/legal/iptal-iade'],
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
            <div className="flex items-center gap-2.5">
              <Logo className="h-8 w-8" />
              <span className="text-lg font-extrabold tracking-tight text-white">CyberTestify</span>
            </div>
            <p className="mt-4 max-w-sm text-sm leading-relaxed text-white/70">{d.tagline}</p>
            <p className="mt-4 text-sm">
              {d.questions}{' '}
              <a href={`mailto:${region.supportEmail}`} className="font-medium text-accent hover:underline">
                {region.supportEmail}
              </a>
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
              <span>MERSİS: {COMPANY.mersisNo}</span>
              <span>
                Vergi D./No: {COMPANY.taxOffice} / {COMPANY.taxNo}
              </span>
              <span>{COMPANY.address}</span>
              <span>Tel: {COMPANY.phone}</span>
              <span>KEP: {COMPANY.kep}</span>
            </div>
          )}
          {showTrImprint && (
            <div className="mt-3 text-accent/80">
              [ETBİS kaydı sonrası doğrulama karekodu buraya eklenecek — yayına almadan önce zorunlu.]
            </div>
          )}
          <div className="mt-3 text-white/40">
            © {COMPANY.brand} — {d.disclaimer} v{COMPANY.legalVersion}
          </div>
        </div>
      </div>
    </footer>
  );
}
