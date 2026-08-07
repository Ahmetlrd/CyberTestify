import Link from 'next/link';
import { notFound } from 'next/navigation';
import type { Metadata } from 'next';

const API = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000';
const SITE = 'https://cybertestify.com';

type Post = { title: string; description: string; slug: string; contentHtml: string; publishedAt: string | null };

async function getPost(slug: string): Promise<Post | null> {
  try {
    const r = await fetch(`${API}/blog/posts/${encodeURIComponent(slug)}`, { next: { revalidate: 300 } });
    if (!r.ok) return null;
    return (await r.json()) as Post;
  } catch {
    return null;
  }
}

export async function generateMetadata({ params }: { params: { slug: string } }): Promise<Metadata> {
  const post = await getPost(params.slug);
  if (!post) return { title: 'Yazı bulunamadı — CyberTestify' };
  const url = `${SITE}/blog/${post.slug}`;
  return {
    title: `${post.title} — CyberTestify`,
    description: post.description,
    alternates: { canonical: url },
    openGraph: {
      title: post.title,
      description: post.description,
      type: 'article',
      url,
      siteName: 'CyberTestify',
      publishedTime: post.publishedAt ?? undefined,
    },
    twitter: { card: 'summary_large_image', title: post.title, description: post.description },
  };
}

function fmtDate(d: string | null): string {
  if (!d) return '';
  return new Date(d).toLocaleDateString('tr-TR', { year: 'numeric', month: 'long', day: 'numeric' });
}

export default async function BlogPostPage({ params }: { params: { slug: string } }) {
  const post = await getPost(params.slug);
  if (!post) notFound();
  return (
    <main className="container-page max-w-3xl py-14">
      <Link href="/blog" className="text-sm font-semibold text-accent-600 hover:underline">← Tüm yazılar</Link>
      <article className="mt-6">
        <h1 className="text-3xl font-extrabold text-brand sm:text-4xl">{post.title}</h1>
        {post.publishedAt && <p className="mt-2 text-xs text-ink-muted">{fmtDate(post.publishedAt)}</p>}
        <div className="blog-body mt-8" dangerouslySetInnerHTML={{ __html: post.contentHtml }} />
      </article>
    </main>
  );
}
