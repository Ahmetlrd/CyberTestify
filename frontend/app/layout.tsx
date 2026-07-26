import { Footer } from '../components/Footer';
import { CookieBanner } from '../components/CookieBanner';

export const metadata = {
  title: 'CyberTestify',
  description: 'Kendi sitenizi doğrulayın, paket seçin, şifreli raporunuzu alın.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="tr">
      <body style={{ fontFamily: 'system-ui, sans-serif', maxWidth: 720, margin: '0 auto', padding: 24 }}>
        {children}
        <Footer />
        <CookieBanner />
      </body>
    </html>
  );
}
