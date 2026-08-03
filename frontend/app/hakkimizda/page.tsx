import Link from 'next/link';
import { COMPANY } from '../../lib/company';

export const metadata = {
  title: 'Hakkımızda — CyberTestify',
  description: 'CyberTestify, sahipliği doğrulanmış alan adlarına yönelik yapay zeka tabanlı pasif güvenlik ön-değerlendirme hizmeti sunar.',
};

export default function Page() {
  return (
    <main className="container-page max-w-2xl py-14">
      <h1 className="text-3xl font-extrabold text-brand">Hakkımızda</h1>

      <p className="mt-4 text-ink-soft">
        <strong>CyberTestify</strong>, işletmelerin web varlıklarındaki güvenlik risklerini erkenden görebilmeleri
        için tasarlanmış, yapay zeka tabanlı bir <strong>güvenlik ön-değerlendirme</strong> hizmetidir. Yalnızca
        <strong> sahipliğini doğruladığınız</strong> alan adına karşı, saldırgan olmayan ve büyük ölçüde pasif
        yöntemlerle çalışırız; bulguları anlaşılır bir rapora ve somut iyileştirme önerilerine dönüştürürüz.
      </p>

      <h2 className="mt-8 text-lg font-bold text-brand">Ne yapıyoruz?</h2>
      <ul className="mt-3 list-disc space-y-2 pl-5 text-ink-soft">
        <li>SSL/TLS yapılandırması, güvenlik başlıkları, DNS/e-posta güvenliği gibi dışarıdan gözlemlenebilir kontroller.</li>
        <li>Bilinen zafiyet ve yanlış yapılandırma tespiti — istismar denemeden, yalnızca tespit ve raporlama.</li>
        <li>Her tarama sonunda şifreli, tek kullanımlık erişim koduyla açılan profesyonel bir PDF rapor.</li>
      </ul>

      <h2 className="mt-8 text-lg font-bold text-brand">Sınırlarımız</h2>
      <p className="mt-3 text-ink-soft">
        Hizmetimiz resmi bir denetim veya sertifikasyon (ör. ASV/QSA) yerine geçmez; farkındalık ve erken tespit
        amaçlıdır. Raporlar yapay zeka tarafından üretilir ve olgusal ifadeler bağımsız doğrulanmadan
        kullanılmamalıdır.
      </p>

      <h2 className="mt-8 text-lg font-bold text-brand">İşletme Bilgileri</h2>
      <div className="mt-3 rounded-card border border-line bg-brand-50/40 p-5 text-sm leading-relaxed text-ink-soft">
        <div className="font-semibold text-brand">{COMPANY.legalName}</div>
        <div className="mt-1">{COMPANY.address}</div>
        <div className="mt-1">
          {COMPANY.taxOffice} V.D. — Vergi No: {COMPANY.taxNo} · Ticaret Sicil No: {COMPANY.ticaretSicilNo} · MERSİS:{' '}
          {COMPANY.mersisNo}
        </div>
        <div className="mt-1">
          <a href={`mailto:${COMPANY.email}`} className="text-accent-600 underline">
            {COMPANY.email}
          </a>{' '}
          · {COMPANY.phone}
        </div>
      </div>

      <p className="mt-6 text-sm text-ink-muted">
        Daha fazla bilgi için{' '}
        <Link href="/iletisim" className="text-accent-600 underline">
          İletişim
        </Link>{' '}
        sayfamıza göz atabilirsiniz.
      </p>
    </main>
  );
}
