import './globals.css';
import { cookies, headers } from 'next/headers';
import { Plus_Jakarta_Sans } from 'next/font/google';
import { Nav } from '../components/Nav';
import { Footer } from '../components/Footer';
import { CookieBanner } from '../components/CookieBanner';
import { getRegion } from '../config/regions';

const jakarta = Plus_Jakarta_Sans({
  subsets: ['latin'],
  variable: '--font-jakarta',
  display: 'swap',
});

export const metadata = {
  title: 'CyberTestify — Dakikalar İçinde Başlayan Otonom Güvenlik Taraması',
  description:
    'Sitenizin güvenliğini tamamen otonom yapay zeka ile dakikalar içinde başlatın; süre pakete/kapsama göre değişir. KVKK uyumlu, şifreli raporlama, yalnızca doğrulanmış alan adları.',
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
