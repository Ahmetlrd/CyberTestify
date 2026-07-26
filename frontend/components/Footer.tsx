import Link from 'next/link';
import { COMPANY } from '../lib/company';

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
    <footer style={{ marginTop: 48, borderTop: '1px solid #e1e4e8', paddingTop: 20, fontSize: 13, color: '#57606a' }}>
      <nav style={{ display: 'flex', flexWrap: 'wrap', gap: '8px 16px', marginBottom: 16 }}>
        {LEGAL_LINKS.map(([label, href]) => (
          <Link key={href} href={href} style={{ color: '#57606a' }}>
            {label}
          </Link>
        ))}
      </nav>

      {/* İşletme kimliği (imprint) — 6563 s. Kanun / TKHK gereği zorunlu. */}
      <div style={{ lineHeight: 1.7 }}>
        <div>
          <strong>{COMPANY.legalName}</strong> ({COMPANY.brand})
        </div>
        <div>MERSİS No: {COMPANY.mersisNo}</div>
        <div>
          Vergi Dairesi / No: {COMPANY.taxOffice} / {COMPANY.taxNo}
        </div>
        <div>Adres: {COMPANY.address}</div>
        <div>
          Tel: {COMPANY.phone} · E-posta: {COMPANY.email} · KEP: {COMPANY.kep}
        </div>
        <div style={{ marginTop: 8 }}>
          {COMPANY.etbisRegistered ? (
            <span>ETBİS kayıtlıdır. (Doğrulama karekodu burada gösterilir.)</span>
          ) : (
            <span style={{ color: '#9a6700' }}>
              [ETBİS kaydı sonrası doğrulama karekodu buraya eklenecek — yayına almadan önce zorunlu.]
            </span>
          )}
        </div>
        <div style={{ marginTop: 8, color: '#8b949e' }}>
          © {COMPANY.brand} — Bu bir güvenlik ön-değerlendirme hizmetidir; resmi denetim/sertifikasyon
          yerine geçmez. Sürüm {COMPANY.legalVersion}.
        </div>
      </div>
    </footer>
  );
}
