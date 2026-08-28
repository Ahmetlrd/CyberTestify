import type { NextRequest } from 'next/server';

const API = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000';
const SITE = 'https://cybertestify.com';

// (SEO) Eski locale'siz /blog/<slug> URL'leri (Google eski yapıda indekslemişti). Blog artık
// /{dil}/blog/<slug>. Bu yol:
//  - Yazı hâlâ VARSA → doğru DİLE kalıcı 301 (tr → de → en önceliğiyle; çeviriler farklı slug taşıdığı
//    için slug hangi dilde bulunuyorsa oraya). Böylece eski link/otorite yeni URL'e geçer.
//  - Yazı SİLİNMİŞSE (hiçbir dilde yok) → 404 yerine 410 Gone (Google kalıcı kaldırıldığını anlar).
// Not: locale'siz /blog LİSTELEME → /tr/blog 301'i middleware'de yapılır; burada yalnız <slug> ele alınır.
export async function GET(_req: NextRequest, { params }: { params: { slug: string } }) {
  const slug = params.slug;
  const langs = ['tr', 'de', 'en'] as const;
  const found = (
    await Promise.all(
      langs.map(async (lang) => {
        try {
          const r = await fetch(`${API}/blog/posts/${encodeURIComponent(slug)}?lang=${lang}`, { next: { revalidate: 3600 } });
          return r.ok ? lang : null;
        } catch {
          return null;
        }
      }),
    )
  ).find(Boolean); // dizi sırası = öncelik: tr → de → en

  if (found) {
    return new Response(null, { status: 301, headers: { Location: `${SITE}/${found}/blog/${slug}` } });
  }
  // Kalıcı kaldırılmış: 410 Gone (sitemap'te zaten yok).
  return new Response('Gone', { status: 410, headers: { 'Content-Type': 'text/plain; charset=utf-8', 'X-Robots-Tag': 'noindex' } });
}
