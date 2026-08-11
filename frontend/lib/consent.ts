// (GA4 + KVKK) Çerez onayı + Google Consent Mode v2 yardımcıları.
// Onay ÖNCESİ hiçbir izleme çerezi YAZILMAZ (Consent Mode default = denied; bkz Analytics.tsx).

export const GA_ID = process.env.NEXT_PUBLIC_GA_MEASUREMENT_ID || '';
export const CONSENT_KEY = 'cookieConsent'; // değer: 'granted' | 'denied'
export const OPEN_PREFS_EVENT = 'open-cookie-prefs';

export type ConsentState = 'granted' | 'denied';

export function getStoredConsent(): ConsentState | null {
  if (typeof window === 'undefined') return null;
  const v = window.localStorage.getItem(CONSENT_KEY);
  return v === 'granted' || v === 'denied' ? v : null;
}

// Consent Mode v2 — 4 anahtar birlikte güncellenir (analytics + ads).
export function applyConsent(state: ConsentState): void {
  if (typeof window === 'undefined') return;
  window.localStorage.setItem(CONSENT_KEY, state);
  const g: 'granted' | 'denied' = state;
  (window as any).gtag?.('consent', 'update', {
    ad_storage: g,
    analytics_storage: g,
    ad_user_data: g,
    ad_personalization: g,
  });
}

// Footer "Çerez tercihleri" -> banner'ı yeniden aç.
export function openCookiePrefs(): void {
  if (typeof window !== 'undefined') window.dispatchEvent(new Event(OPEN_PREFS_EVENT));
}
