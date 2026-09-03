import './globals.css';
import { Suspense } from 'react';
import { cookies, headers } from 'next/headers';
import { Plus_Jakarta_Sans } from 'next/font/google';
import { Nav } from '../components/Nav';
import { Footer } from '../components/Footer';
import { CookieBanner } from '../components/CookieBanner';
import { Analytics } from '../components/Analytics';
import { JsonLd } from '../components/JsonLd';
import { getRegion } from '../config/regions';

const SITE = 'https://cybertestify.com';
// (SEO — ÇOK-DİLLİ) Kök varsayılan başlık/açıklama/OG ve Organization yapısal verisi bölgeye (tr/de/en) göre.
// Başlık 50-60, açıklama ~150-160 karakter (Google kırpması olmasın). Bölge sayfaları generateMetadata ile
// yine EZER; bu yalnız varsayılanı (kendi metadata'sını vermeyen sayfalar) da doğru dile getirir.
type MetaLang = 'tr' | 'de' | 'en';
const META: Record<MetaLang, { title: string; desc: string; ogLocale: string; orgDesc: string }> = {
  tr: {
    title: 'CyberTestify — Dakikalar İçinde AI Güvenlik Taraması',
    desc: 'Yapay zekâ destekli otomatik web güvenlik ön değerlendirmesi (resmi pentest değil). Alan adınızı doğrulayın, paketinizi seçin, şifreli raporunuzu alın.',
    ogLocale: 'tr_TR',
    orgDesc: 'Web siteleri için yapay zekâ destekli, otomatik güvenlik ön-değerlendirme hizmeti; yalnızca doğrulanmış alan adlarında pasif ve kontrollü kontroller.',
  },
  de: {
    title: 'CyberTestify — KI-Websicherheits-Scan in Minuten',
    desc: 'KI-gestützte automatisierte Web-Sicherheits-Vorprüfung (kein formaler Pentest). Domain verifizieren, Paket wählen und Ihren verschlüsselten Bericht erhalten.',
    ogLocale: 'de_DE',
    orgDesc: 'KI-gestützter, automatisierter Web-Sicherheits-Vorprüfungsdienst; ausschließlich passive, kontrollierte Prüfungen auf verifizierten Domains.',
  },
  en: {
    title: 'CyberTestify — AI Web Security Scan in Minutes',
    desc: 'AI-powered automated web security pre-assessment (not a formal pentest). Verify your domain, choose a package, and get your encrypted report.',
    ogLocale: 'en_GB',
    orgDesc: 'AI-powered automated web security pre-assessment service; only passive, controlled checks on verified domains.',
  },
};

function metaLangFrom(lang: string): MetaLang {
  return lang === 'de' ? 'de' : lang === 'en' ? 'en' : 'tr';
}

// Organization — site geneli yapisal veri; açıklama ziyaretçi diline göre, alan/dil ise TÜM bölgeler.
function organizationLd(lang: MetaLang) {
  return {
    '@context': 'https://schema.org',
    '@type': 'Organization',
    name: 'CyberTestify',
    url: SITE,
    logo: `${SITE}/logo.svg`,
    email: 'support@cybertestify.com',
    description: META[lang].orgDesc,
    contactPoint: {
      '@type': 'ContactPoint',
      email: 'support@cybertestify.com',
      contactType: 'customer support',
      areaServed: ['TR', 'DE', 'GB'],
      availableLanguage: ['Turkish', 'German', 'English'],
    },
    sameAs: [] as string[],
  };
}

const jakarta = Plus_Jakarta_Sans({
  subsets: ['latin'],
  variable: '--font-jakarta',
  display: 'swap',
});

const SITE_URL = 'https://cybertestify.com';

// metadataBase: OG/canonical göreli URL'leri mutlağa çevirir. openGraph/twitter varsayılanları site-geneli
// (sayfalar generateMetadata ile başlık/açıklama/canonical'ı EZER). OG görseli app/opengraph-image.tsx'ten
// Next tarafından OTOMATIK eklenir. verification ENV varsa basılır (Vedat Search Console için doldurur).
export function generateMetadata() {
  const lang = metaLangFrom(getRegion(cookies().get('region')?.value).lang);
  const m = META[lang];
  return {
  metadataBase: new URL(SITE_URL),
  title: m.title,
  description: m.desc,
  applicationName: 'CyberTestify',
  // (SEO/canonical) SİTE-GENELİ varsayılan canonical VERİLMEZ. Eskiden '/tr' idi — kendi canonical'ını
  // set etMEYEN her sayfa (ör. /legal/*) Google'a "ben /tr'nin kopyasıyım" diyordu → GSC'de "kopya,
  // standart sayfa /tr" ve indexlenmeme. Ana sayfa canonical'ını [region]/page.tsx zaten kendi veriyor;
  // diğer sayfalar kendi canonical'ını (aşağıda legal/* dahil) verir; verilmezse Google kendine-canonical yapar.
  openGraph: {
    type: 'website',
    siteName: 'CyberTestify',
    locale: m.ogLocale,
    url: `${SITE_URL}/${lang}`,
    title: m.title,
    description: m.desc,
  },
  twitter: { card: 'summary_large_image', title: m.title, description: m.desc },
  robots: { index: true, follow: true },
  ...(process.env.GOOGLE_SITE_VERIFICATION
    ? { verification: { google: process.env.GOOGLE_SITE_VERIFICATION } }
    : {}),
  };
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  const region = getRegion(cookies().get('region')?.value);
  // Admin paneli MUSTERI sitesinden ayri: musteri Nav/Footer/CookieBanner GOSTERILMEZ
  // (admin'in kendi layout'u var — app/admin/layout.tsx).
  const isAdmin = (headers().get('x-pathname') ?? '').startsWith('/admin');

  return (
    <html lang={region.lang} dir={region.dir} className={jakarta.variable}>
      <body className="flex min-h-screen flex-col font-sans">
        {isAdmin ? (
          children
        ) : (
          <>
            <JsonLd data={organizationLd(metaLangFrom(region.lang))} />
            <Suspense fallback={null}><Analytics /></Suspense>
            <Nav region={region} />
            <div className="flex-1">{children}</div>
            <Footer region={region} />
            <CookieBanner />
          </>
        )}
      </body>
    </html>
  );
}
