import type { MetadataRoute } from 'next';

const API = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000';
const SITE = 'https://cybertestify.com';

// Sitemap saatlik yenilenir; yeni yayinlanan blog makaleleri DB'den okunarak OTOMATIK eklenir.
export const revalidate = 3600;

export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
  let posts: Array<{ slug: string; publishedAt: string | null }> = [];
  try {
    const r = await fetch(`${API}/blog/posts`, { next: { revalidate: 3600 } });
    if (r.ok) posts = await r.json();
  } catch {
    /* API erisilemezse yalniz statik rotalar */
  }

  const now = new Date();
  const staticRoutes: MetadataRoute.Sitemap = [
    { url: `${SITE}/tr`, lastModified: now, changeFrequency: 'weekly', priority: 1 },
    { url: `${SITE}/tr/packages`, lastModified: now, changeFrequency: 'weekly', priority: 0.9 },
    { url: `${SITE}/blog`, lastModified: now, changeFrequency: 'daily', priority: 0.8 },
    { url: `${SITE}/login`, lastModified: now, changeFrequency: 'monthly', priority: 0.3 },
    { url: `${SITE}/register`, lastModified: now, changeFrequency: 'monthly', priority: 0.4 },
  ];

  const blogRoutes: MetadataRoute.Sitemap = posts.map((p) => ({
    url: `${SITE}/blog/${p.slug}`,
    lastModified: p.publishedAt ? new Date(p.publishedAt) : now,
    changeFrequency: 'monthly',
    priority: 0.7,
  }));

  return [...staticRoutes, ...blogRoutes];
}
