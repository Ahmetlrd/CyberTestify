import Link from 'next/link';
import { COMPANY } from '../lib/company';
import { Logo } from './Logo';

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

export function Footer() {
  return (
    <footer className="mt-24 bg-brand-deep text-white/80">
      <div className="container-page py-14">
        <div className="grid gap-10 md:grid-cols-[1.3fr_1fr]">
          <div>
            <div className="flex items-center gap-2.5">
              <Logo className="h-8 w-8" />
              <span className="text-lg font-extrabold tracking-tight text-white">CyberTestify</span>
            </div>
            <p className="mt-4 max-w-sm text-sm leading-relaxed text-white/70">
              Yalnızca sahipliğini doğruladığınız alan adına karşı, tamamen otonom yapay zeka ile
              güvenlik ön-değerlendirmesi. Resmi denetim/sertifikasyon yerine geçmez.
            </p>
            <p className="mt-4 text-sm">
              Sorularınız mı var?{' '}
              <a href={`mailto:${COMPANY.email}`} className="font-medium text-accent hover:underline">
                {COMPANY.email}
              </a>
            </p>
          </div>

          <div>
            <h3 className="text-xs font-semibold uppercase tracking-widest text-white/50">Yasal</h3>
            <ul className="mt-4 grid grid-cols-1 gap-2.5 sm:grid-cols-2">
              {LEGAL_LINKS.map(([label, href]) => (
                <li key={href}>
                  <Link href={href} className="text-sm text-white/70 transition hover:text-white">
                    {label}
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* İşletme kimliği (imprint) — 6563 s. Kanun / TKHK gereği zorunlu */}
        <div className="mt-12 border-t border-white/10 pt-6 text-xs leading-relaxed text-white/55">
          <div className="font-semibold text-white/75">{COMPANY.legalName}</div>
          <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1">
            <span>MERSİS: {COMPANY.mersisNo}</span>
            <span>
              Vergi D./No: {COMPANY.taxOffice} / {COMPANY.taxNo}
            </span>
            <span>{COMPANY.address}</span>
            <span>Tel: {COMPANY.phone}</span>
            <span>KEP: {COMPANY.kep}</span>
          </div>
          <div className="mt-3">
            {COMPANY.etbisRegistered ? (
              <span>ETBİS kayıtlıdır. (Doğrulama karekodu burada gösterilir.)</span>
            ) : (
              <span className="text-accent/80">
                [ETBİS kaydı sonrası doğrulama karekodu buraya eklenecek — yayına almadan önce zorunlu.]
              </span>
            )}
          </div>
          <div className="mt-3 text-white/40">
            © {COMPANY.brand} — Güvenlik ön-değerlendirme hizmeti. Sürüm {COMPANY.legalVersion}.
          </div>
        </div>
      </div>
    </footer>
  );
}
