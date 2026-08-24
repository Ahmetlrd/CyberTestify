import Link from 'next/link';
import { cookies } from 'next/headers';
import { COMPANY } from '../../lib/company';
import { getRegion } from '../../config/regions';

// (Çok-bölge) Bölge-bağımsız kök sayfa; dili region cookie'sinden alır (tr | de). /de'de KVKK yerine
// DSGVO, "Türkçe rapor" yerine "Deutscher Bericht" — düz çeviri değil, bağlam uyarlaması.
const T = {
  tr: {
    metaTitle: 'Hakkımızda — CyberTestify',
    metaDesc: 'CyberTestify, sahipliği doğrulanmış alan adlarına yönelik yapay zekâ destekli, otomatik güvenlik ön-değerlendirme hizmeti sunar.',
    title: 'Hakkımızda',
    introHtml: '<strong>CyberTestify</strong>, işletmelerin web varlıklarındaki güvenlik risklerini erkenden görebilmeleri için tasarlanmış, yapay zeka tabanlı bir <strong>güvenlik ön-değerlendirme</strong> hizmetidir. Yalnızca <strong>sahipliğini doğruladığınız</strong> alan adına karşı, saldırgan olmayan ve büyük ölçüde pasif yöntemlerle çalışırız; bulguları anlaşılır bir rapora ve somut iyileştirme önerilerine dönüştürürüz.',
    whatTitle: 'Ne yapıyoruz?',
    what: [
      'SSL/TLS yapılandırması, güvenlik başlıkları, DNS/e-posta güvenliği gibi dışarıdan gözlemlenebilir kontroller.',
      'Bilinen zafiyet ve yanlış yapılandırma tespiti — istismar denemeden, yalnızca tespit ve raporlama.',
      'Her tarama sonunda şifreli, tek kullanımlık erişim koduyla açılan profesyonel bir PDF rapor.',
    ],
    methodTitle: 'Metodolojimiz — Üç Katmanlı Doğrulama',
    methodHtml: 'CyberTestify, <strong>Otonom AI Red-Team + Deterministik Güvenlik Doğrulama</strong> yaklaşımını birleştirir. Kişiye değil <strong>sürece ve kanıta</strong> güvenilir: her bulgu, motorun sözüne değil, saklanan <strong>ham istek/yanıt kanıtına</strong> bağlanır. Bulgular üç katmanda şeffaf sınıflanır:',
    tiers: [
      { t: 'Kanıtlı', d: 'Ham istek/yanıtta deterministik imzayla teyit edilmiş bulgu. Genel risk yalnız bunlardan türetilir.' },
      { t: 'Belirsiz', d: 'Kanıt var ama kesin imza yok — gizlenmez; açıkça insan doğrulamasına bırakılır.' },
      { t: 'Hayalet', d: 'Hiçbir ham izi olmayan (ya da hedef-dışı) iddialar elenir — yanlış-pozitif ve gürültü rapora girmez.' },
    ],
    methodFootHtml: '<strong>Deterministik istek/yanıt kanıt kaydı:</strong> yalnızca teyit edilen bulgular raporlanır; teyit edilemeyen iddialar dürüstçe elenir. Böylece rapor gürültüden arınır, güvenilir kalır.',
    isoTitle: 'İzolasyon & Güvenlik',
    iso: [
      '<strong>İzole sandbox / efemer altyapı:</strong> etkin testler, dışarı-çıkışı (egress) varsayılan-red olan, her koşuda tek-kullanımlık izole bir ortamda yürütülür.',
      '<strong>256-bit şifreli raporlar:</strong> her rapor uçtan uca şifrelidir ve size özel tek-kullanımlık erişim koduyla açılır.',
      '<strong>KVKK/GDPR odaklı işleme:</strong> yapısal PII maskeleme ve alan adı sahipliği doğrulaması ön koşuldur.',
    ],
    limitsTitle: 'Sınırlarımız',
    limitsHtml: 'Hizmetimiz resmi bir denetim veya sertifikasyon (ör. ASV/QSA) yerine geçmez; farkındalık ve erken tespit amaçlıdır. Raporlar yapay zeka tarafından üretilir ve olgusal ifadeler bağımsız doğrulanmadan kullanılmamalıdır.',
    weTitle: 'Biz buyuz / Biz bu değiliz',
    weAre: 'Biziz',
    weAreList: [
      'Hızlı, uygun fiyatlı güvenlik <strong>ön değerlendirmesi</strong>.',
      'Yapay zeka ile <strong>otomatik</strong> tarama ve raporlama.',
      'KOBİ, ajans ve yazılım ekipleri için pratik bir ilk katman.',
    ],
    weNot: 'Biz bu değiliz',
    weNotList: [
      'Resmi / mahkemede geçerli <strong>pentest veya denetim</strong> değiliz.',
      'Banka/holding <strong>red-team</strong> alternatifi değiliz.',
      'Kurumsal yıllık sözleşmeli bir ürün değiliz.',
    ],
    whyTitle: 'Neden CyberTestify?',
    why: [
      '<strong>Tek seferlik, sürpriz maliyeti olmayan sabit fiyat.</strong>',
      '<strong>Türkçe rapor + KVKK odaklı kontroller.</strong>',
      '<strong>Alan adı sahipliği doğrulanmadan tarama yapılmıyor</strong> (güvenlik öncelikli).',
    ],
    contactTitle: 'İletişim',
    moreHtml: 'Daha fazla bilgi için',
    moreLink: 'İletişim',
    moreTail: 'sayfamıza göz atabilirsiniz.',
  },
  de: {
    metaTitle: 'Über uns — CyberTestify',
    metaDesc: 'CyberTestify bietet eine KI-gestützte, automatisierte Sicherheits-Vorabbewertung für verifizierte Domains.',
    title: 'Über uns',
    introHtml: '<strong>CyberTestify</strong> ist ein KI-basierter Dienst zur <strong>Sicherheits-Vorabbewertung</strong>, der Unternehmen hilft, Sicherheitsrisiken ihrer Web-Ressourcen frühzeitig zu erkennen. Wir arbeiten ausschließlich gegen die von Ihnen <strong>verifizierte</strong> Domain, mit nicht-angreifenden und weitgehend passiven Methoden, und überführen die Befunde in einen verständlichen Bericht mit konkreten Handlungsempfehlungen.',
    whatTitle: 'Was wir tun',
    what: [
      'Von außen beobachtbare Prüfungen wie SSL/TLS-Konfiguration, Sicherheitsheader, DNS-/E-Mail-Sicherheit.',
      'Erkennung bekannter Schwachstellen und Fehlkonfigurationen — ohne Ausnutzung, nur Feststellung und Bericht.',
      'Nach jedem Scan ein professioneller PDF-Bericht, der mit einem verschlüsselten Einmal-Zugangscode geöffnet wird.',
    ],
    methodTitle: 'Unsere Methodik — dreistufige Verifizierung',
    methodHtml: 'CyberTestify verbindet den Ansatz <strong>Autonomes AI Red-Team + deterministische Sicherheitsverifizierung</strong>. Vertraut wird nicht einer Person, sondern <strong>dem Prozess und dem Nachweis</strong>: Jeder Befund wird nicht an das Wort der Engine, sondern an gespeicherte <strong>rohe Request/Response-Nachweise</strong> gebunden. Befunde werden transparent in drei Stufen klassifiziert:',
    tiers: [
      { t: 'Nachgewiesen', d: 'Durch eine deterministische Signatur im rohen Request/Response bestätigter Befund. Das Gesamtrisiko wird nur hieraus abgeleitet.' },
      { t: 'Unklar', d: 'Nachweis vorhanden, aber keine eindeutige Signatur — wird nicht verborgen, sondern offen der menschlichen Prüfung überlassen.' },
      { t: 'Phantom', d: 'Behauptungen ohne jede Spur im Rohmaterial (oder außerhalb des Ziels) werden aussortiert — False Positives und Rauschen gelangen nicht in den Bericht.' },
    ],
    methodFootHtml: '<strong>Deterministische Request/Response-Nachweisführung:</strong> Es werden nur bestätigte Befunde berichtet; nicht bestätigte Behauptungen werden ehrlich aussortiert. So bleibt der Bericht rauschfrei und verlässlich.',
    isoTitle: 'Isolierung & Sicherheit',
    iso: [
      '<strong>Isolierte Sandbox / ephemere Infrastruktur:</strong> Aktive Tests laufen in einer bei jedem Durchlauf einmaligen, isolierten Umgebung mit standardmäßig verweigertem Egress.',
      '<strong>256-Bit-verschlüsselte Berichte:</strong> Jeder Bericht ist Ende-zu-Ende-verschlüsselt und wird mit einem für Sie einmaligen Zugangscode geöffnet.',
      '<strong>DSGVO-orientierte Verarbeitung:</strong> strukturelle Maskierung personenbezogener Daten und Verifizierung der Domain-Inhaberschaft sind Voraussetzung.',
    ],
    limitsTitle: 'Unsere Grenzen',
    limitsHtml: 'Unser Dienst ersetzt kein formelles Audit und keine Zertifizierung (z. B. ASV/QSA); er dient der Sensibilisierung und Früherkennung. Berichte werden von KI erstellt; sachliche Aussagen sollten nicht ohne unabhängige Überprüfung verwendet werden.',
    weTitle: 'Das sind wir / das sind wir nicht',
    weAre: 'Das sind wir',
    weAreList: [
      'Eine schnelle, günstige Sicherheits-<strong>Vorabbewertung</strong>.',
      '<strong>Automatisiertes</strong> Scannen und Berichten mit KI.',
      'Eine praktische erste Schicht für KMU, Agenturen und Software-Teams.',
    ],
    weNot: 'Das sind wir nicht',
    weNotList: [
      'Kein formeller / gerichtsfester <strong>Pentest oder Audit</strong>.',
      'Kein Ersatz für ein <strong>Red-Team</strong> einer Bank/eines Konzerns.',
      'Kein Produkt mit jährlichem Unternehmensvertrag.',
    ],
    whyTitle: 'Warum CyberTestify?',
    why: [
      '<strong>Einmaliger Festpreis ohne Überraschungskosten.</strong>',
      '<strong>Deutscher Bericht + DSGVO-orientierte Prüfungen.</strong>',
      '<strong>Kein Scan ohne Verifizierung der Domain-Inhaberschaft</strong> (Sicherheit zuerst).',
    ],
    contactTitle: 'Kontakt',
    moreHtml: 'Weitere Informationen finden Sie auf unserer',
    moreLink: 'Kontakt',
    moreTail: 'Seite.',
  },
} as const;

function pick() {
  const region = getRegion(cookies().get('region')?.value);
  return { t: T[region.lang === 'de' ? 'de' : 'tr'], home: `/${region.code}` };
}

export function generateMetadata() {
  const { t } = pick();
  return {
    title: t.metaTitle,
    description: t.metaDesc,
    alternates: { canonical: '/hakkimizda' },
    openGraph: { type: 'website' as const, siteName: 'CyberTestify', url: 'https://cybertestify.com/hakkimizda', title: t.metaTitle, description: t.metaDesc },
  };
}

const H = ({ html }: { html: string }) => <span dangerouslySetInnerHTML={{ __html: html }} />;

export default function Page() {
  const { t } = pick();
  return (
    <main className="container-page max-w-2xl py-14">
      <h1 className="text-3xl font-extrabold text-brand">{t.title}</h1>

      <p className="mt-4 text-ink-soft"><H html={t.introHtml} /></p>

      <h2 className="mt-8 text-lg font-bold text-brand">{t.whatTitle}</h2>
      <ul className="mt-3 list-disc space-y-2 pl-5 text-ink-soft">
        {t.what.map((x, i) => <li key={i}>{x}</li>)}
      </ul>

      <h2 className="mt-8 text-lg font-bold text-brand">{t.methodTitle}</h2>
      <p className="mt-3 text-ink-soft"><H html={t.methodHtml} /></p>
      <div className="mt-3 grid gap-3 sm:grid-cols-3">
        <div className="rounded-card border border-emerald-300/50 bg-emerald-50/40 p-4 text-sm text-ink-soft">
          <div className="font-semibold text-emerald-700">{t.tiers[0].t}</div>
          <p className="mt-1.5">{t.tiers[0].d}</p>
        </div>
        <div className="rounded-card border border-amber-300/50 bg-amber-50/40 p-4 text-sm text-ink-soft">
          <div className="font-semibold text-amber-700">{t.tiers[1].t}</div>
          <p className="mt-1.5">{t.tiers[1].d}</p>
        </div>
        <div className="rounded-card border border-line bg-brand-50/40 p-4 text-sm text-ink-soft">
          <div className="font-semibold text-ink">{t.tiers[2].t}</div>
          <p className="mt-1.5">{t.tiers[2].d}</p>
        </div>
      </div>
      <p className="mt-3 text-ink-soft"><H html={t.methodFootHtml} /></p>

      <h2 className="mt-8 text-lg font-bold text-brand">{t.isoTitle}</h2>
      <ul className="mt-3 list-disc space-y-2 pl-5 text-ink-soft">
        {t.iso.map((x, i) => <li key={i}><H html={x} /></li>)}
      </ul>

      <h2 className="mt-8 text-lg font-bold text-brand">{t.limitsTitle}</h2>
      <p className="mt-3 text-ink-soft"><H html={t.limitsHtml} /></p>

      <h2 className="mt-8 text-lg font-bold text-brand">{t.weTitle}</h2>
      <div className="mt-3 grid gap-4 sm:grid-cols-2">
        <div className="rounded-card border border-emerald-300/50 bg-emerald-50/40 p-4 text-sm text-ink-soft">
          <div className="font-semibold text-emerald-700">{t.weAre}</div>
          <ul className="mt-2 list-disc space-y-1.5 pl-5">
            {t.weAreList.map((x, i) => <li key={i}><H html={x} /></li>)}
          </ul>
        </div>
        <div className="rounded-card border border-line bg-brand-50/40 p-4 text-sm text-ink-soft">
          <div className="font-semibold text-ink">{t.weNot}</div>
          <ul className="mt-2 list-disc space-y-1.5 pl-5">
            {t.weNotList.map((x, i) => <li key={i}><H html={x} /></li>)}
          </ul>
        </div>
      </div>

      <h2 className="mt-8 text-lg font-bold text-brand">{t.whyTitle}</h2>
      <ul className="mt-3 list-disc space-y-2 pl-5 text-ink-soft">
        {t.why.map((x, i) => <li key={i}><H html={x} /></li>)}
      </ul>

      <h2 className="mt-8 text-lg font-bold text-brand">{t.contactTitle}</h2>
      <div className="mt-3 rounded-card border border-line bg-brand-50/40 p-5 text-sm leading-relaxed text-ink-soft">
        <a href={`mailto:${COMPANY.email}`} className="text-accent-600 underline">{COMPANY.email}</a>
      </div>

      <p className="mt-6 text-sm text-ink-muted">
        {t.moreHtml}{' '}
        <Link href="/iletisim" className="text-accent-600 underline">{t.moreLink}</Link>{' '}
        {t.moreTail}
      </p>
    </main>
  );
}
