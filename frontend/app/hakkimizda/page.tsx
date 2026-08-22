import Link from 'next/link';
import { COMPANY } from '../../lib/company';

export const metadata = {
  title: 'Hakkımızda — CyberTestify',
  description: 'CyberTestify, sahipliği doğrulanmış alan adlarına yönelik yapay zekâ destekli, otomatik güvenlik ön-değerlendirme hizmeti sunar.',
  alternates: { canonical: '/hakkimizda' },
  openGraph: { type: 'website', siteName: 'CyberTestify', url: 'https://cybertestify.com/hakkimizda', title: 'Hakkımızda — CyberTestify', description: 'CyberTestify, yapay zekâ destekli otomatik güvenlik ön-değerlendirme hizmeti.' },
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

      <h2 className="mt-8 text-lg font-bold text-brand">Metodolojimiz — Üç Katmanlı Doğrulama</h2>
      <p className="mt-3 text-ink-soft">
        CyberTestify, <strong>Otonom AI Red-Team + Deterministik Güvenlik Doğrulama</strong> yaklaşımını birleştirir.
        Kişiye değil <strong>sürece ve kanıta</strong> güvenilir: her bulgu, motorun sözüne değil, saklanan
        <strong> ham istek/yanıt kanıtına</strong> bağlanır. Bulgular üç katmanda şeffaf sınıflanır:
      </p>
      <div className="mt-3 grid gap-3 sm:grid-cols-3">
        <div className="rounded-card border border-emerald-300/50 bg-emerald-50/40 p-4 text-sm text-ink-soft">
          <div className="font-semibold text-emerald-700">Kanıtlı</div>
          <p className="mt-1.5">Ham istek/yanıtta deterministik imzayla teyit edilmiş bulgu. Genel risk yalnız bunlardan türetilir.</p>
        </div>
        <div className="rounded-card border border-amber-300/50 bg-amber-50/40 p-4 text-sm text-ink-soft">
          <div className="font-semibold text-amber-700">Belirsiz</div>
          <p className="mt-1.5">Kanıt var ama kesin imza yok — gizlenmez; açıkça insan doğrulamasına bırakılır.</p>
        </div>
        <div className="rounded-card border border-line bg-brand-50/40 p-4 text-sm text-ink-soft">
          <div className="font-semibold text-ink">Hayalet</div>
          <p className="mt-1.5">Hiçbir ham izi olmayan (ya da hedef-dışı) iddialar elenir — yanlış-pozitif ve gürültü rapora girmez.</p>
        </div>
      </div>
      <p className="mt-3 text-ink-soft">
        <strong>Deterministik istek/yanıt kanıt kaydı:</strong> yalnızca teyit edilen bulgular raporlanır; teyit
        edilemeyen iddialar dürüstçe elenir. Böylece rapor gürültüden arınır, güvenilir kalır.
      </p>

      <h2 className="mt-8 text-lg font-bold text-brand">İzolasyon &amp; Güvenlik</h2>
      <ul className="mt-3 list-disc space-y-2 pl-5 text-ink-soft">
        <li><strong>İzole sandbox / efemer altyapı:</strong> etkin testler, dışarı-çıkışı (egress) varsayılan-red olan, her koşuda tek-kullanımlık izole bir ortamda yürütülür.</li>
        <li><strong>256-bit şifreli raporlar:</strong> her rapor uçtan uca şifrelidir ve size özel tek-kullanımlık erişim koduyla açılır.</li>
        <li><strong>KVKK/GDPR odaklı işleme:</strong> yapısal PII maskeleme ve alan adı sahipliği doğrulaması ön koşuldur.</li>
      </ul>

      <h2 className="mt-8 text-lg font-bold text-brand">Sınırlarımız</h2>
      <p className="mt-3 text-ink-soft">
        Hizmetimiz resmi bir denetim veya sertifikasyon (ör. ASV/QSA) yerine geçmez; farkındalık ve erken tespit
        amaçlıdır. Raporlar yapay zeka tarafından üretilir ve olgusal ifadeler bağımsız doğrulanmadan
        kullanılmamalıdır.
      </p>

      <h2 className="mt-8 text-lg font-bold text-brand">Biz buyuz / Biz bu değiliz</h2>
      <div className="mt-3 grid gap-4 sm:grid-cols-2">
        <div className="rounded-card border border-emerald-300/50 bg-emerald-50/40 p-4 text-sm text-ink-soft">
          <div className="font-semibold text-emerald-700">Biziz</div>
          <ul className="mt-2 list-disc space-y-1.5 pl-5">
            <li>Hızlı, uygun fiyatlı güvenlik <strong>ön değerlendirmesi</strong>.</li>
            <li>Yapay zeka ile <strong>otomatik</strong> tarama ve raporlama.</li>
            <li>KOBİ, ajans ve yazılım ekipleri için pratik bir ilk katman.</li>
          </ul>
        </div>
        <div className="rounded-card border border-line bg-brand-50/40 p-4 text-sm text-ink-soft">
          <div className="font-semibold text-ink">Biz bu değiliz</div>
          <ul className="mt-2 list-disc space-y-1.5 pl-5">
            <li>Resmi / mahkemede geçerli <strong>pentest veya denetim</strong> değiliz.</li>
            <li>Banka/holding <strong>red-team</strong> alternatifi değiliz.</li>
            <li>Kurumsal yıllık sözleşmeli bir ürün değiliz.</li>
          </ul>
        </div>
      </div>

      <h2 className="mt-8 text-lg font-bold text-brand">Neden CyberTestify?</h2>
      <ul className="mt-3 list-disc space-y-2 pl-5 text-ink-soft">
        <li><strong>Tek seferlik, sürpriz maliyeti olmayan sabit fiyat.</strong></li>
        <li><strong>Türkçe rapor + KVKK odaklı kontroller.</strong></li>
        <li><strong>Alan adı sahipliği doğrulanmadan tarama yapılmıyor</strong> (güvenlik öncelikli).</li>
      </ul>

      <h2 className="mt-8 text-lg font-bold text-brand">İletişim</h2>
      <div className="mt-3 rounded-card border border-line bg-brand-50/40 p-5 text-sm leading-relaxed text-ink-soft">
        <a href={`mailto:${COMPANY.email}`} className="text-accent-600 underline">
          {COMPANY.email}
        </a>
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
