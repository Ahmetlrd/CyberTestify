import Link from 'next/link';
import { notFound } from 'next/navigation';
import type { Metadata } from 'next';
import { isRegionCode } from '../../../config/regions';

const API = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000';
const SITE = 'https://cybertestify.com';

type Post = { title: string; description: string; slug: string; publishedAt: string | null; coverImageId?: string | null };
const coverUrl = (id?: string | null) => (id ? `${API}/blog/images/${id}` : null);

// Bölge -> blog dili. Şu an yalnız tr ve de blog var (us/ae görünmez). Bilinmeyen -> tr.
function blogLang(region: string): 'tr' | 'de' | 'en' {
  return region === 'de' ? 'de' : region === 'en' ? 'en' : 'tr';
}

// (Çok-dilli blog) UI metinleri dile göre. /de bağlamında Türkçe SIZMAZ.
const T = {
  tr: {
    eyebrow: 'Blog',
    title: 'Güvenlik & Uyum Yazıları',
    subtitle: 'Web güvenliği, KVKK/ISO 27001/PCI hazırlığı ve pratik ipuçları.',
    empty: 'Henüz yayınlanmış yazı yok.',
    metaTitle: 'Blog — CyberTestify',
    metaDesc: 'Web güvenliği, KVKK/ISO 27001/PCI-DSS hazırlığı ve güvenlik ön-değerlendirme üzerine yazılar.',
  },
  de: {
    eyebrow: 'Blog',
    title: 'Sicherheit & Compliance-Artikel',
    subtitle: 'Web-Sicherheit, DSGVO/ISO 27001/PCI-Vorbereitung und praktische Tipps.',
    empty: 'Bald auf Deutsch verfügbar.',
    metaTitle: 'Blog — CyberTestify',
    metaDesc: 'Artikel über Web-Sicherheit, DSGVO/ISO 27001/PCI-DSS-Vorbereitung und Sicherheitsbewertung.',
  },
  en: {
    eyebrow: 'Blog',
    title: 'Security & Compliance Articles',
    subtitle: 'Web security, UK GDPR/ISO 27001/PCI readiness and practical tips.',
    empty: 'Coming soon in English.',
    metaTitle: 'Blog — CyberTestify',
    metaDesc: 'Articles on web security, UK GDPR/ISO 27001/PCI-DSS readiness and security pre-assessment.',
  },
} as const;

export function generateMetadata({ params }: { params: { region: string } }): Metadata {
  const lang = blogLang(params.region);
  const t = T[lang];
  return {
    title: t.metaTitle,
    description: t.metaDesc,
    alternates: {
      canonical: `${SITE}/${params.region}/blog`,
      languages: { tr: `${SITE}/tr/blog`, de: `${SITE}/de/blog`, en: `${SITE}/en/blog`, 'x-default': `${SITE}/tr/blog` },
    },
    openGraph: { type: 'website', siteName: 'CyberTestify', url: `${SITE}/${params.region}/blog`, title: t.metaTitle, description: t.subtitle },
  };
}

async function getPosts(lang: string): Promise<Post[]> {
  try {
    const r = await fetch(`${API}/blog/posts?lang=${lang}`, { next: { revalidate: 300 } });
    if (!r.ok) return [];
    return (await r.json()) as Post[];
  } catch {
    return [];
  }
}

export default async function BlogPage({ params }: { params: { region: string } }) {
  if (!isRegionCode(params.region)) notFound();
  const lang = blogLang(params.region);
  const t = T[lang];
  const posts = await getPosts(lang);
  const dateLocale = lang === 'de' ? 'de-DE' : lang === 'en' ? 'en-GB' : 'tr-TR';
  const fmtDate = (d: string | null) =>
    d ? new Date(d).toLocaleDateString(dateLocale, { year: 'numeric', month: 'long', day: 'numeric' }) : '';
  return (
    <main className="container-page max-w-3xl py-14">
      <header className="mb-10">
        <p className="eyebrow">{t.eyebrow}</p>
        <h1 className="mt-2 text-3xl font-extrabold text-brand sm:text-4xl">{t.title}</h1>
        <p className="mt-2 text-ink-soft">{t.subtitle}</p>
      </header>

      {posts.length === 0 ? (
        <p className="text-sm text-ink-muted">{t.empty}</p>
      ) : (
        <div className="space-y-5">
          {posts.map((p) => {
            const cover = coverUrl(p.coverImageId);
            return (
              <Link key={p.slug} href={`/${params.region}/blog/${p.slug}`} className="card block overflow-hidden transition hover:border-accent/60">
                {cover && (
                  // eslint-disable-next-line @next/next/no-img-element
                  <img src={cover} alt={p.title} loading="lazy" className="h-44 w-full object-cover" />
                )}
                <div className="p-6">
                  <h2 className="text-lg font-bold text-brand">{p.title}</h2>
                  {p.description && <p className="mt-1.5 text-sm leading-relaxed text-ink-soft">{p.description}</p>}
                  <p className="mt-3 text-xs text-ink-muted">{fmtDate(p.publishedAt)}</p>
                </div>
              </Link>
            );
          })}
        </div>
      )}
    </main>
  );
}
