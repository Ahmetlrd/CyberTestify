import './globals.css';
import { cookies, headers } from 'next/headers';
import { Plus_Jakarta_Sans } from 'next/font/google';
import { Nav } from '../components/Nav';
import { Footer } from '../components/Footer';
import { CookieBanner } from '../components/CookieBanner';
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
    'Web siteleri için otonom, yapay zeka destekli güvenlik ön-değerlendirme hizmeti; yalnızca doğrulanmış alan adlarında pasif ve kontrollü kontroller.',
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

export const metadata = {
  title: 'CyberTestify — Dakikalar İçinde Başlayan Otonom Güvenlik Taraması',
  description:
    'Sitenizin güvenliğini tamamen otonom yapay zeka ile dakikalar içinde başlatın; süre pakete/kapsama göre değişir. KVKK uyumlu, şifreli raporlama, yalnızca doğrulanmış alan adları.',
  // Google Search Console dogrulamasi — ENV'den (GOOGLE_SITE_VERIFICATION). Env BOSSA etiket
  // HIC render edilmez (site bozulmaz). Doldurulunca her sayfanin <head>'ine basilir.
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
