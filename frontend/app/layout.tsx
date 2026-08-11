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
// Organization — site geneli yapisal veri (bir kez, layout'ta). sameAs bos (sosyal medya yok).
const ORGANIZATION_LD = {
  '@context': 'https://schema.org',
  '@type': 'Organization',
  name: 'CyberTestify',
  url: SITE,
  logo: `${SITE}/logo.svg`,
  email: 'support@cybertestify.com',
  description:
    'Web siteleri için yapay zekâ destekli, otomatik güvenlik ön-değerlendirme hizmeti; yalnızca doğrulanmış alan adlarında pasif ve kontrollü kontroller.',
  contactPoint: {
    '@type': 'ContactPoint',
    email: 'support@cybertestify.com',
    contactType: 'customer support',
    areaServed: 'TR',
    availableLanguage: ['Turkish'],
  },
  sameAs: [] as string[],
};

const jakarta = Plus_Jakarta_Sans({
  subsets: ['latin'],
  variable: '--font-jakarta',
  display: 'swap',
});

const SITE_URL = 'https://cybertestify.com';
const DEFAULT_TITLE = 'CyberTestify — Dakikalar İçinde Başlayan Otomatik Güvenlik Taraması';
const DEFAULT_DESC =
  'Sitenizin güvenliğini yapay zekâ destekli otomatik taramayla dakikalar içinde başlatın; süre pakete/kapsama göre değişir. KVKK’ya uygun veri işleme, şifreli raporlama, yalnızca doğrulanmış alan adları.';

// metadataBase: OG/canonical göreli URL'leri mutlağa çevirir. openGraph/twitter varsayılanları site-geneli
// (sayfalar generateMetadata ile başlık/açıklama/canonical'ı EZER). OG görseli app/opengraph-image.tsx'ten
// Next tarafından OTOMATIK eklenir. verification ENV varsa basılır (Vedat Search Console için doldurur).
export const metadata = {
  metadataBase: new URL(SITE_URL),
  title: DEFAULT_TITLE,
  description: DEFAULT_DESC,
  applicationName: 'CyberTestify',
  alternates: { canonical: '/tr' },
  openGraph: {
    type: 'website',
    siteName: 'CyberTestify',
    locale: 'tr_TR',
    url: `${SITE_URL}/tr`,
    title: DEFAULT_TITLE,
    description: DEFAULT_DESC,
  },
  twitter: { card: 'summary_large_image', title: DEFAULT_TITLE, description: DEFAULT_DESC },
  robots: { index: true, follow: true },
  ...(process.env.GOOGLE_SITE_VERIFICATION
    ? { verification: { google: process.env.GOOGLE_SITE_VERIFICATION } }
    : {}),
};

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
            <JsonLd data={ORGANIZATION_LD} />
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
