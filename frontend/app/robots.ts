import type { MetadataRoute } from 'next';

const SITE = 'https://cybertestify.com';

// Kullaniciya ozel / islevsel yollar — indekslenmemeli (her bot icin kapali).
const DISALLOW = [
  '/dashboard',
  '/admin',
  '/pay',
  '/order',
  '/verify', // alan adi sahiplik dogrulama (kullaniciya ozel)
  '/verify-email',
  '/login',
  '/register',
  '/forgot-password',
  '/reset-password',
  '/schedules',
  '/auth', // (varsa) auth callback vb.
  '/api',
];

// AI arama/asistan botlari (GEO/AEO). Retrieval (gercek zamanli) + training crawler'lari:
// public sayfalara ACIKCA izinli, ozel yollar yukaridaki DISALLOW ile kapali.
const AI_BOTS = [
  'ChatGPT-User', 'Claude-Web', 'ClaudeBot', 'Claude-SearchBot', 'PerplexityBot', 'Amazonbot', 'YouBot', 'OAI-SearchBot', // retrieval/asistan
  'GPTBot', 'Google-Extended', 'CCBot', 'Bytespider', 'FacebookBot', 'Applebot-Extended', // training
];

export default function robots(): MetadataRoute.Robots {
  return {
    rules: [
      { userAgent: '*', allow: '/', disallow: DISALLOW },
      ...AI_BOTS.map((ua) => ({ userAgent: ua, allow: '/', disallow: DISALLOW })),
    ],
    sitemap: `${SITE}/sitemap.xml`,
    host: SITE,
  };
}
