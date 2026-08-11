// (Analitik) GA4 + Microsoft Clarity — HER ZAMAN AÇIK (site sahibinin kararıyla çerez onayı gating'i
// kaldırıldı). Banner yalnızca BİLGİLENDİRME amaçlıdır; hiçbir izlemeyi engellemez/koşula bağlamaz.

export const GA_ID = process.env.NEXT_PUBLIC_GA_MEASUREMENT_ID || '';
export const CLARITY_ID = process.env.NEXT_PUBLIC_CLARITY_PROJECT_ID || '';
export const NOTICE_KEY = 'cookieNotice'; // '1' = bilgilendirme kapatıldı
export const OPEN_PREFS_EVENT = 'open-cookie-prefs';

// Clarity tag'ini bir kez enjekte et (her zaman; onay gerektirmez).
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

export function noticeDismissed(): boolean {
  if (typeof window === 'undefined') return true;
  return window.localStorage.getItem(NOTICE_KEY) === '1';
}
export function dismissNotice(): void {
  if (typeof window !== 'undefined') window.localStorage.setItem(NOTICE_KEY, '1');
}

// Footer "Çerez tercihleri" -> bilgilendirme notunu yeniden aç.
export function openCookiePrefs(): void {
  if (typeof window !== 'undefined') window.dispatchEvent(new Event(OPEN_PREFS_EVENT));
}
