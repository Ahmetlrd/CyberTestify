import Link from 'next/link';

/**
 * (United Kingdom /en) Shared wrapper for the English legal pages. Separate from the TR
 * LegalArticle and the DE DeLegalArticle — specific to the /en context. Content is a DRAFT:
 * every page shows a "review by a qualified solicitor before publication" note at the top.
 * Does not touch /tr or /de.
 */
export function EnLegalArticle({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <main className="container-page max-w-3xl py-12" style={{ lineHeight: 1.7 }}>
      <p className="text-sm">
        <Link href="/en" className="text-accent-600 hover:underline">← Home</Link>
      </p>
      <h1 className="text-2xl font-extrabold text-brand">{title}</h1>
      <div
        role="note"
        style={{ margin: '12px 0 20px', padding: '10px 14px', borderRadius: 10, background: 'rgba(245,166,35,0.08)', border: '1px solid rgba(245,166,35,0.28)', fontSize: 13, color: 'var(--ink-soft, #4b5563)' }}
      >
        <strong>Note (draft):</strong> This text is a draft and should be reviewed by a qualified
        solicitor before publication.
      </div>
      <div className="legal-body">{children}</div>
    </main>
  );
}
