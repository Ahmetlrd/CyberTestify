import type { MetadataRoute } from 'next';

const API = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000';
const SITE = 'https://cybertestify.com';

// Sitemap 15 dk'da bir yenilenir; yeni yayinlanan blog makaleleri DB'den okunarak OTOMATIK
// eklenir (gunde 1 yayin icin ziyadesiyle yeterli, redeploy gerekmez).
export const revalidate = 900;

export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
  let posts: Array<{ slug: string; publishedAt: string | null }> = [];
  try {
    const r = await fetch(`${API}/blog/posts`, { next: { revalidate: 3600 } });
    if (r.ok) posts = await r.json();
  } catch {
    /* API erisilemezse yalniz statik rotalar */
  }

  const now = new Date();
  // Yalniz INDEKSLENEBILIR public icerik (login/register robots'ta Disallow — sitemap'te YOK).
  const staticRoutes: MetadataRoute.Sitemap = [
    { url: `${SITE}/tr`, lastModified: now, changeFrequency: 'weekly', priority: 1 },
    { url: `${SITE}/tr/packages`, lastModified: now, changeFrequency: 'weekly', priority: 0.9 },
    { url: `${SITE}/blog`, lastModified: now, changeFrequency: 'daily', priority: 0.8 },
    { url: `${SITE}/hakkimizda`, lastModified: now, changeFrequency: 'monthly', priority: 0.5 },
    { url: `${SITE}/iletisim`, lastModified: now, changeFrequency: 'monthly', priority: 0.4 },
    { url: `${SITE}/acik-kaynak`, lastModified: now, changeFrequency: 'yearly', priority: 0.3 },
  ];

  // (SEO) Hukuki sayfalar — footer'dan linkli, kendi canonical'ıyla indekslenmeli (eskiden /tr'ye
  // canonical veriyorlardı → GSC "kopya" diyordu). Sitemap'e ekleyerek keşif/indeks sinyali güçlenir.
  const legalSlugs = ['kullanim-kosullari', 'gizlilik', 'kvkk-aydinlatma', 'cerez', 'mesafeli-satis', 'on-bilgilendirme', 'iptal-iade', 'sorumluluk-reddi'];
  const legalRoutes: MetadataRoute.Sitemap = legalSlugs.map((slug) => ({
    url: `${SITE}/legal/${slug}`, lastModified: now, changeFrequency: 'yearly', priority: 0.3,
  }));

  const blogRoutes: MetadataRoute.Sitemap = posts.map((p) => ({
    url: `${SITE}/blog/${p.slug}`,
    lastModified: p.publishedAt ? new Date(p.publishedAt) : now,
    changeFrequency: 'monthly',
    priority: 0.7,
  }));

  return [...staticRoutes, ...legalRoutes, ...blogRoutes];
}
