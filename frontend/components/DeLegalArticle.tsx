import Link from 'next/link';

/**
 * (Almanya /de) Almanca hukuki sayfalar için ortak sarmalayıcı. TR LegalArticle'dan AYRI —
 * cookie'ye değil, /de bağlamına özgü. İçerik TASLAK'tır: her sayfa üstünde "yayına çıkmadan
 * hukuk danışmanına gösterin" notu (avukat onayı) gösterilir. /tr'ye dokunmaz.
 */
export function DeLegalArticle({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <main className="container-page max-w-3xl py-12" style={{ lineHeight: 1.7 }}>
      <p className="text-sm">
        <Link href="/de" className="text-accent-600 hover:underline">← Startseite</Link>
      </p>
      <h1 className="text-2xl font-extrabold text-brand">{title}</h1>
      <div
        role="note"
        style={{ margin: '12px 0 20px', padding: '10px 14px', borderRadius: 10, background: 'rgba(245,166,35,0.08)', border: '1px solid rgba(245,166,35,0.28)', fontSize: 13, color: 'var(--ink-soft, #4b5563)' }}
      >
        <strong>Hinweis (Entwurf):</strong> Dieser Text ist ein Entwurf und sollte vor der
        Veröffentlichung von einem Rechtsanwalt / einer Rechtsanwältin geprüft werden.
      </div>
      <div className="legal-body">{children}</div>
    </main>
  );
}
