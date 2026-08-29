import { GA_ID } from './consent';

/**
 * (GA4 huni event'leri) Tek noktadan gtag event gönderimi. Mevcut GA4 kurulumunu (Analytics.tsx'teki
 * gtag) kullanır — İKİNCİ snippet YOK. Consent Mode default = granted (consent.ts) olduğundan ayrı
 * gating gerekmez; yine de gtag hazır değilse sessizce no-op olur (double-fire üretmez).
 *
 * PII KURALI: buraya YALNIZCA teknik alanlar geçilir (region, package, value, currency, transaction_id,
 * method). E-posta / isim / telefon / hedef alan adı ASLA param olarak gönderilmez.
 */
export function trackEvent(name: string, params?: Record<string, unknown>): void {
  if (!GA_ID || typeof window === 'undefined') return;
  const clean: Record<string, unknown> = {};
  if (params) for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== '') clean[k] = v;

  // (TEŞHİS) ?gadebug=1 → olayı konsola yaz. Reklam engelleyici gtag.js'i bloklasa bile event'in
  // TETİKLENDİĞİ böylece görülür (Network'te /collect yoksa sorun kod değil, engelleyici/ağdır).
  try {
    if (window.location.search.includes('gadebug=1')) console.log('[GA4]', name, clean);
  } catch { /* noop */ }

  const g = (window as any).gtag;
  if (typeof g === 'function') { g('event', name, clean); return; }
  // gtag henüz hazır değilse KAYBETME: dataLayer'a kuyrukla — gtag.js yüklenince işlenir.
  try {
    (window as any).dataLayer = (window as any).dataLayer || [];
    (window as any).dataLayer.push(['event', name, clean]);
  } catch { /* noop */ }
}

/** Bölge kodundan GA4 para birimi (ISO 4217). begin_checkout/purchase için /tr→TRY, /de→EUR, /en→GBP. */
export function currencyForRegion(regionCode: string): string {
  return regionCode === 'de' ? 'EUR' : regionCode === 'en' ? 'GBP' : 'TRY';
}
