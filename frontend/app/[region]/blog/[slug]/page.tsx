import Link from 'next/link';
import { notFound } from 'next/navigation';
import type { Metadata } from 'next';
import { JsonLd } from '../../../../components/JsonLd';
import { isRegionCode } from '../../../../config/regions';

const API = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000';
const SITE = 'https://cybertestify.com';

type Post = { title: string; description: string; slug: string; contentHtml: string; publishedAt: string | null };

function blogLang(region: string): 'tr' | 'de' | 'en' {
  return region === 'de' ? 'de' : region === 'en' ? 'en' : 'tr';
}

async function getPost(slug: string, lang: string): Promise<Post | null> {
  try {
    const r = await fetch(`${API}/blog/posts/${encodeURIComponent(slug)}?lang=${lang}`, { next: { revalidate: 300 } });
    if (!r.ok) return null;
    return (await r.json()) as Post;
  } catch {
    return null;
  }
}

export async function generateMetadata({ params }: { params: { region: string; slug: string } }): Promise<Metadata> {
  const lang = blogLang(params.region);
  const post = await getPost(params.slug, lang);
  if (!post) return { title: lang === 'de' ? 'Artikel nicht gefunden — CyberTestify' : lang === 'en' ? 'Article not found — CyberTestify' : 'Yazı bulunamadı — CyberTestify' };
  const url = `${SITE}/${params.region}/blog/${post.slug}`;
  return {
    title: `${post.title} — CyberTestify`,
    description: post.description,
    alternates: {
      canonical: url,
      languages: { tr: `${SITE}/tr/blog/${post.slug}`, de: `${SITE}/de/blog/${post.slug}`, en: `${SITE}/en/blog/${post.slug}` },
    },
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

export default async function BlogPostPage({ params }: { params: { region: string; slug: string } }) {
  if (!isRegionCode(params.region)) notFound();
  const lang = blogLang(params.region);
  const post = await getPost(params.slug, lang);
  if (!post) notFound();
  const url = `${SITE}/${params.region}/blog/${post.slug}`;
  const dateLocale = lang === 'de' ? 'de-DE' : lang === 'en' ? 'en-GB' : 'tr-TR';
  const fmtDate = (d: string | null) =>
    d ? new Date(d).toLocaleDateString(dateLocale, { year: 'numeric', month: 'long', day: 'numeric' }) : '';
  const backLabel = lang === 'de' ? '← Alle Artikel' : lang === 'en' ? '← All articles' : '← Tüm yazılar';
  const articleLd = {
    '@context': 'https://schema.org',
    '@type': 'Article',
    headline: post.title,
    description: post.description,
    inLanguage: lang,
    ...(post.publishedAt ? { datePublished: post.publishedAt, dateModified: post.publishedAt } : {}),
    author: { '@type': 'Organization', name: 'CyberTestify', url: SITE },
    publisher: {
      '@type': 'Organization',
      name: 'CyberTestify',
      logo: { '@type': 'ImageObject', url: `${SITE}/logo.svg` },
    },
    mainEntityOfPage: { '@type': 'WebPage', '@id': url },
    url,
  };
  return (
    <main className="container-page max-w-3xl py-14">
      <JsonLd data={articleLd} />
      <Link href={`/${params.region}/blog`} className="text-sm font-semibold text-accent-600 hover:underline">{backLabel}</Link>
      <article className="mt-6">
        <h1 className="text-3xl font-extrabold text-brand sm:text-4xl">{post.title}</h1>
        {post.publishedAt && <p className="mt-2 text-xs text-ink-muted">{fmtDate(post.publishedAt)}</p>}
        <div className="blog-body mt-8" dangerouslySetInnerHTML={{ __html: post.contentHtml }} />
      </article>
    </main>
  );
}
