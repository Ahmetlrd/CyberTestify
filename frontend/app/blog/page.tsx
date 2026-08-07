import Link from 'next/link';
import type { Metadata } from 'next';

const API = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000';

type Post = { title: string; description: string; slug: string; publishedAt: string | null };

export const metadata: Metadata = {
  title: 'Blog — CyberTestify',
  description: 'Web güvenliği, KVKK/ISO 27001/PCI-DSS hazırlığı ve güvenlik ön-değerlendirme üzerine yazılar.',
};

async function getPosts(): Promise<Post[]> {
  try {
    const r = await fetch(`${API}/blog/posts`, { next: { revalidate: 300 } });
    if (!r.ok) return [];
    return (await r.json()) as Post[];
  } catch {
    return [];
  }
}

function fmtDate(d: string | null): string {
  if (!d) return '';
  return new Date(d).toLocaleDateString('tr-TR', { year: 'numeric', month: 'long', day: 'numeric' });
}

export default async function BlogPage() {
  const posts = await getPosts();
  return (
    <main className="container-page max-w-3xl py-14">
      <header className="mb-10">
        <p className="eyebrow">Blog</p>
        <h1 className="mt-2 text-3xl font-extrabold text-brand sm:text-4xl">Güvenlik & Uyum Yazıları</h1>
        <p className="mt-2 text-ink-soft">Web güvenliği, KVKK/ISO 27001/PCI hazırlığı ve pratik ipuçları.</p>
      </header>

      {posts.length === 0 ? (
        <p className="text-sm text-ink-muted">Henüz yayınlanmış yazı yok.</p>
      ) : (
        <div className="space-y-5">
          {posts.map((p) => (
            <Link key={p.slug} href={`/blog/${p.slug}`} className="card block p-6 transition hover:border-accent/60">
              <h2 className="text-lg font-bold text-brand">{p.title}</h2>
              {p.description && <p className="mt-1.5 text-sm leading-relaxed text-ink-soft">{p.description}</p>}
              <p className="mt-3 text-xs text-ink-muted">{fmtDate(p.publishedAt)}</p>
            </Link>
          ))}
        </div>
      )}
    </main>
  );
}
