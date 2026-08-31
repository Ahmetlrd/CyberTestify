import Link from 'next/link';

/**
 * (Almanya /de) Almanca hukuki sayfalar için ortak sarmalayıcı. TR LegalArticle'dan AYRI —
 * cookie'ye değil, /de bağlamına özgü. İçerik TASLAK'tır: her sayfa üstünde "yayına çıkmadan
 * hukuk danışmanına gösterin" notu (avukat onayı) gösterilir. /tr'ye dokunmaz.
 */
export function DeLegalArticle({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <main className="container-page max-w-3xl py-12" style={{ lineHeight: 1.7 }}>
      {/* (UI) Geri butonu: eskiden minik düz metin bağlantısıydı; artık belirgin,
          ok animasyonlu buton (site btn-outline sistemiyle tutarlı). */}
      <Link href="/de" className="btn-outline group mb-7 shadow-sm hover:bg-brand-50">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden className="transition-transform group-hover:-translate-x-0.5"><path d="M19 12H5M11 18l-6-6 6-6" /></svg>
        Startseite
      </Link>
      <h1 className="text-2xl font-extrabold text-brand">{title}</h1>
      <div className="legal-body">{children}</div>
    </main>
  );
}
