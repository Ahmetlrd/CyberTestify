// (GA4 + KVKK) Çerez onayı + Google Consent Mode v2 yardımcıları.
// Onay ÖNCESİ hiçbir izleme çerezi YAZILMAZ (Consent Mode default = denied; bkz Analytics.tsx).

export const GA_ID = process.env.NEXT_PUBLIC_GA_MEASUREMENT_ID || '';
// (Microsoft Clarity) oturum kaydı/ısı haritası — KVKK: YALNIZ onay verilince yüklenir (aşağıda loadClarity).
export const CLARITY_ID = process.env.NEXT_PUBLIC_CLARITY_PROJECT_ID || '';
export const CONSENT_KEY = 'cookieConsent'; // değer: 'granted' | 'denied'
export const OPEN_PREFS_EVENT = 'open-cookie-prefs';

// Clarity tag'ini SADECE onay sonrası, bir kez enjekte et (onay öncesi hiç yüklenmez -> çerez/kayıt yok).
let clarityInjected = false;
export function loadClarity(): void {
  if (typeof window === 'undefined' || !CLARITY_ID || clarityInjected) return;
  clarityInjected = true;
  if ((window as any).clarity) return;
  (function (c: any, l: any, a: any, r: any, i: string) {
    c[a] = c[a] || function () { (c[a].q = c[a].q || []).push(arguments); };
    const t = l.createElement(r); t.async = 1; t.src = 'https://www.clarity.ms/tag/' + i;
    const y = l.getElementsByTagName(r)[0]; y.parentNode.insertBefore(t, y);
  })(window, document, 'clarity', 'script', CLARITY_ID);
}

export type ConsentState = 'granted' | 'denied';

export function getStoredConsent(): ConsentState | null {
  if (typeof window === 'undefined') return null;
  const v = window.localStorage.getItem(CONSENT_KEY);
  return v === 'granted' || v === 'denied' ? v : null;
}

// Consent Mode v2 — 4 anahtar birlikte güncellenir (analytics + ads). Onay verilince Clarity de yüklenir.
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
  if (state === 'granted') loadClarity(); // KVKK: yalnız onay sonrası
}

// Footer "Çerez tercihleri" -> banner'ı yeniden aç.
export function openCookiePrefs(): void {
  if (typeof window !== 'undefined') window.dispatchEvent(new Event(OPEN_PREFS_EVENT));
}
