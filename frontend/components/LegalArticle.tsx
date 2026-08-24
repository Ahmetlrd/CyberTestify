import Link from 'next/link';
import { cookies } from 'next/headers';
import { getRegion } from '../config/regions';

/**
 * Hukuki sayfalar için ortak sarmalayıcı + BÖLGE MATRİSİ. Yalnızca hukuki
 * metinleri hazır olan bölgelerde (region.legalReady) gerçek içerik gösterilir;
 * diğer bölgelerde net bir "hazırlanıyor" placeholder'ı görünür. Her bölgede
 * gerçek metin, o bölgenin mevzuatına göre ayrıca avukat onayı gerektirir.
 */
export function LegalArticle({ title, children }: { title: string; children: React.ReactNode }) {
  const region = getRegion(cookies().get('region')?.value);

  if (!region.legalReady) {
    return (
      <main className="container-page max-w-2xl py-20 text-center">
        <div className="card p-10">
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-brand-50 text-brand">
            <svg viewBox="0 0 24 24" className="h-6 w-6" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
              <path d="M9 12l2 2 4-4M12 3l7 4v6c0 4.5-3 7.8-7 9-4-1.2-7-4.5-7-9V7l7-4z" />
            </svg>
          </div>
          <h1 className="mt-5 text-2xl font-extrabold text-brand">{title}</h1>
          <p className="mt-3 text-ink-soft">
            Legal documents for the <strong>{region.label}</strong> region are being prepared and
            reviewed by local counsel before launch here.
          </p>
          <Link href={`/${region.code}`} className="btn-outline mt-6">
            ← Home
          </Link>
        </div>
      </main>
    );
  }

  return (
    <main className="container-page max-w-3xl py-12" style={{ lineHeight: 1.7 }}>
      <p className="text-sm">
        <Link href={`/${region.code}`} className="text-accent-600 hover:underline">
          ← Ana sayfa
        </Link>
      </p>
      <h1 className="text-2xl font-extrabold text-brand">{title}</h1>
      <div className="legal-body">{children}</div>
    </main>
  );
}
