/**
 * (SÜTUN 0 — ÇEREZ SINIFLAMA) Çerezleri KAYNAĞINA/amacına göre ayırt eder.
 *
 * Analitik / 3rd-party çerezler (_ga, _ga_*, _gid, _fbp, _gcl_au, _clck, _clsk …) client-side JS'in
 * document.cookie ile YAZDIĞI çerezlerdir — sunucu Set-Cookie oturum çerezi DEĞİLdir. Bunlarda
 * HttpOnly teknik olarak İMKÂNSIZDIR (JS'in okuması gerekir), dolayısıyla "HttpOnly eksik" bir
 * ZAFİYET değildir. "Oturum çerezi" olarak sınıflanıp bulgu üretilmemelidir (halüsinasyon kaynağı).
 */
const ANALYTICS_COOKIE_RE =
  /^(_ga(_.*)?|_gid|_gat(_.*)?|__utm[a-z]?|_gcl_[a-z]+|_fbp|_fbc|fr|_clck|_clsk|_hj[a-z]*|_pk_[a-z]+|ajs_[a-z_]+|mp_[a-z0-9]+|amplitude_[a-z0-9]*|ph_[a-z0-9_]*|_uetsid|_uetvid|_pin_unauth|yandex_[a-z]+|ym_[a-z0-9]+)$/i;

/** Client-side analitik/3rd-party çerez mi? (oturum çerezi SAYILMAZ, HttpOnly bunlarda imkânsız). */
export function isAnalyticsCookie(name: string): boolean {
  return ANALYTICS_COOKIE_RE.test((name ?? '').trim());
}

// Gerçek SUNUCU oturum çerezi adı örüntüsü (token/jwt/session/sid/auth…). Analitik hariç.
const SESSION_COOKIE_RE = /(token|jwt|session|sid|auth|_session|connect\.sid|phpsessid|jsessionid|asp\.net)/i;

/** Sunucu-taraflı oturum çerezi adı mı? (analitik çerezler burada FALSE döner.) */
export function isSessionCookieName(name: string): boolean {
  const n = (name ?? '').trim();
  return !isAnalyticsCookie(n) && SESSION_COOKIE_RE.test(n);
}
