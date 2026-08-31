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
          <Link href={`/${region.code}`} className="btn-outline group mt-6 shadow-sm hover:bg-brand-50">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden className="transition-transform group-hover:-translate-x-0.5"><path d="M19 12H5M11 18l-6-6 6-6" /></svg>
            Home
          </Link>
        </div>
      </main>
    );
  }

  return (
    <main className="container-page max-w-3xl py-12" style={{ lineHeight: 1.7 }}>
      {/* (UI) Geri butonu: eskiden minik düz metin bağlantısıydı; artık belirgin,
          ok animasyonlu buton (site btn-outline sistemiyle tutarlı). */}
      <Link href={`/${region.code}`} className="btn-outline group mb-7 shadow-sm hover:bg-brand-50">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden className="transition-transform group-hover:-translate-x-0.5"><path d="M19 12H5M11 18l-6-6 6-6" /></svg>
        Ana sayfa
      </Link>
      <h1 className="text-2xl font-extrabold text-brand">{title}</h1>
      <div className="legal-body">{children}</div>
    </main>
  );
}
