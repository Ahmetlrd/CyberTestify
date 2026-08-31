import type { MetadataRoute } from 'next';

const API = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000';
const SITE = 'https://cybertestify.com';

// Sitemap 15 dk'da bir yenilenir; yeni yayinlanan blog makaleleri DB'den okunarak OTOMATIK
// eklenir (gunde 1 yayin icin ziyadesiyle yeterli, redeploy gerekmez).
export const revalidate = 900;

type Post = { slug: string; publishedAt: string | null };

export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
  let posts: Post[] = [], dePosts: Post[] = [], enPosts: Post[] = [];
  try {
    const [rTr, rDe, rEn] = await Promise.all([
      fetch(`${API}/blog/posts?lang=tr`, { next: { revalidate: 3600 } }),
      fetch(`${API}/blog/posts?lang=de`, { next: { revalidate: 3600 } }),
      fetch(`${API}/blog/posts?lang=en`, { next: { revalidate: 3600 } }),
    ]);
    if (rTr.ok) posts = await rTr.json();
    if (rDe.ok) dePosts = await rDe.json();
    if (rEn.ok) enPosts = await rEn.json();
  } catch {
    /* API erisilemezse yalniz statik rotalar */
  }

  const now = new Date();
  // (SEO/hreflang) Yapısal sayfalar 3 dilde (tr/de/en) AYNI yolla var → her giriş karşılıklı
  // hreflang + x-default taşır. Diller birbirine canonical VERMEZ; hreflang ile ilişkilenir.
  const langAlt = (path: string) => ({
    languages: {
      tr: `${SITE}/tr${path}`, de: `${SITE}/de${path}`, en: `${SITE}/en${path}`, 'x-default': `${SITE}/tr${path}`,
    },
  });
  const structural: MetadataRoute.Sitemap = (['tr', 'de', 'en'] as const).flatMap((lang) => [
    { url: `${SITE}/${lang}`, lastModified: now, changeFrequency: 'weekly' as const, priority: lang === 'tr' ? 1 : 0.8, alternates: langAlt('') },
    { url: `${SITE}/${lang}/packages`, lastModified: now, changeFrequency: 'weekly' as const, priority: lang === 'tr' ? 0.9 : 0.7, alternates: langAlt('/packages') },
    { url: `${SITE}/${lang}/blog`, lastModified: now, changeFrequency: 'daily' as const, priority: lang === 'tr' ? 0.8 : 0.6, alternates: langAlt('/blog') },
  ]);

  // (URL TUTARLILIĞI) Kurumsal sayfalar artık bölge-önekli (/{bölge}/hakkimizda …) ve her bölgede
  // KENDİ dilinde. Eski önek-siz adresler middleware'de 301 → burada YALNIZ yeni adresler listelenir.
  const corporate: MetadataRoute.Sitemap = (
    [['hakkimizda', 0.5, 'monthly'], ['iletisim', 0.4, 'monthly'], ['acik-kaynak', 0.3, 'yearly']] as const
  ).flatMap(([slug, prio, freq]) =>
    (['tr', 'de', 'en'] as const).map((lang) => ({
      url: `${SITE}/${lang}/${slug}`,
      lastModified: now,
      changeFrequency: freq as 'monthly' | 'yearly',
      priority: lang === 'tr' ? prio : prio - 0.1,
      alternates: langAlt(`/${slug}`),
    })),
  );

  // (SEO) Hukuki sayfalar — YALNIZ /tr indekslenebilir (kendi canonical'ıyla). /de ve /en hukuki
  // sayfaları noindex olduğu için sitemap'e ALINMAZ. TR hukuki ≠ DE/EN hukuki (farklı belge) → hreflang yok.
  const legalSlugs = ['kullanim-kosullari', 'gizlilik', 'kvkk-aydinlatma', 'cerez', 'mesafeli-satis', 'on-bilgilendirme', 'iptal-iade', 'sorumluluk-reddi'];
  const legalRoutes: MetadataRoute.Sitemap = legalSlugs.map((slug) => ({
    url: `${SITE}/tr/legal/${slug}`, lastModified: now, changeFrequency: 'yearly', priority: 0.3,
  }));

  // Blog yazıları — her dil KENDİ slug'ıyla (çeviriler farklı slug taşıdığından yazı-bazlı hreflang
  // VERİLMEZ; kırık hreflang'dan kaçınmak için yazılar kendi diliyle, alternates'sız listelenir).
  const blogRoutes = (lang: 'tr' | 'de' | 'en', list: Post[]): MetadataRoute.Sitemap =>
    list.map((p) => ({
      url: `${SITE}/${lang}/blog/${p.slug}`,
      lastModified: p.publishedAt ? new Date(p.publishedAt) : now,
      changeFrequency: 'monthly' as const,
      priority: 0.7,
    }));

  return [
    ...structural,
    ...corporate,
    ...legalRoutes,
    ...blogRoutes('tr', posts),
    ...blogRoutes('de', dePosts),
    ...blogRoutes('en', enPosts),
  ];
}
