import './globals.css';
import { Plus_Jakarta_Sans } from 'next/font/google';
import { Nav } from '../components/Nav';
import { Footer } from '../components/Footer';
import { CookieBanner } from '../components/CookieBanner';

const jakarta = Plus_Jakarta_Sans({
  subsets: ['latin'],
  variable: '--font-jakarta',
  display: 'swap',
});

export const metadata = {
  title: 'CyberTestify — 5 Dakikada Otonom Güvenlik Taraması',
  description:
    'Sitenizin güvenliğini, tamamen otonom yapay zeka ile 5 dakikada test edin. KVKK uyumlu, şifreli raporlama, yalnızca doğrulanmış alan adları.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="tr" className={jakarta.variable}>
      <body className="flex min-h-screen flex-col font-sans">
        <Nav />
        <div className="flex-1">{children}</div>
        <Footer />
        <CookieBanner />
      </body>
    </html>
  );
}
