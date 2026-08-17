/**
 * (Tam Kapsamlı Pentest — Faz 2-B) OTURUM YÖNETİMİ DERİNLİĞİ + CSRF (WSTG-SESS). 5 kontrol.
 * HEPSİ read-only/gözlemsel — durum-değiştiren gönderim / gerçek CSRF saldırısı YOK.
 *
 * SÜTUN 0 SCOPING (Faz 2-A dersi): Bu kontroller GERÇEK bir SUNUCU-TARAFLI OTURUM ÇEREZİ (Set-Cookie
 * session çerezi) VARSA anlamlıdır. Firebase/Bearer-JWT/token-tabanlı SPA'da (Set-Cookie oturum çerezi
 * YOK) → tüm bölüm "Kapsam dışı — uygulanabilir giriş noktası yok" (Oturum Çerezi Bayrakları'nın
 * bearer oturumda yaptığı gibi). Token/JWT güvenliği ZATEN ayrı "JWT / Token Güvenliği" bölümünde.
 * HAYALET-BULGU YOK. Bulgu varsa "gösterge, doğrulama gerekir" dili; token/oturum REDAKTE.
 *
 *   1) CSRF koruması (SESS-05): oturum çerezinde SameSite + durum-değiştiren formda anti-CSRF token
 *   2) Oturum token entropisi (SESS-01): session-id yapısal analizi (uzunluk/charset/entropi)
 *   3) Oturum URL'de (SESS-04): session id URL/query'de ifşa mı
 *   4) Oturum zaman aşımı / eş-zamanlı (SESS-07/11): gözlemsel
 *   5) Çerez prefix (SESS-02): oturum çerezinde __Host-/__Secure- prefix eksik mi
 */
import { fetchClientCorpus } from './jsAnalysis.js';
import { isSessionCookieName } from './cookieClassify.js';
import type { AuthSession, CookieFlag } from './authSession.js';
import type { ActiveCheckEvidence, VFinding } from './activeVerifyEvidence.js';

type SessCookie = { name: string; value: string; flag: CookieFlag };

function parseCookieHeader(cookie?: string): Array<{ name: string; value: string }> {
  if (!cookie) return [];
  return cookie.split(';').map((p) => p.trim()).filter(Boolean).map((p) => {
    const i = p.indexOf('=');
    return i === -1 ? { name: p, value: '' } : { name: p.slice(0, i).trim(), value: p.slice(i + 1).trim() };
  });
}

const isJwt = (v: string) => /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(v);

// Kaba Shannon-tabanlı entropi tahmini (bit). Kısa/dar-charset/tekrarlı session-id zayıf sayılır.
function entropyBits(v: string): number {
  if (!v) return 0;
  const freq = new Map<string, number>();
  for (const ch of v) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of freq.values()) { const p = c / v.length; h -= p * Math.log2(p); }
  return h * v.length; // toplam bit
}

// ---- Saf analiz çekirdeği (BİRİM TEST edilebilir) ----
export function analyzeSessionSecurity(cookies: SessCookie[], homeHtml: string): { findings: VFinding[]; notes: string[] } {
  const findings: VFinding[] = [];
  const notes: string[] = [];

  // Durum-değiştiren (POST) formlarda anti-CSRF token var mı? (statik gözlem)
  const postForms = [...homeHtml.matchAll(/<form\b[^>]*method\s*=\s*["']?post["']?[^>]*>([\s\S]*?)<\/form>/gi)].map((m) => m[0]);
  const csrfInMeta = /<meta[^>]+name\s*=\s*["'](?:csrf-token|_csrf|xsrf-token)["']/i.test(homeHtml);
  const formsWithoutToken = postForms.filter((f) => !/<input[^>]+name\s*=\s*["'][^"']*(csrf|xsrf|authenticity|_token|__requestverification)/i.test(f));

  // ---- 5) ÇEREZ PREFIX + ---- 1) CSRF SameSite (oturum çerezi başına) ----
  const noPrefix = cookies.filter((c) => !/^__(Host|Secure)-/i.test(c.name));
  const noSameSite = cookies.filter((c) => !c.flag.sameSite || /none/i.test(c.flag.sameSite));

  if (noPrefix.length) {
    findings.push({
      check: 'cookie_prefix_missing', inputPoint: noPrefix.map((c) => c.name).join(', '), vulnerable: true,
      technique: 'oturum çerezi güvenlik prefix (__Host-/__Secure-) gözlemi',
      evidence: `Oturum çerez(ler)i \`${noPrefix.map((c) => c.name).join('`, `')}\` **__Host-/__Secure- prefix'i olmadan** ayarlanmış — prefix, çerezin yalnız HTTPS'te ve doğru kapsam/host'ta set edilmesini zorlar (alt-domain/enjeksiyon sertleştirmesi). Düşük-etkili sertleştirme boşluğu.`,
      confidence: 'high', severity: 'low', sideEffectRisk: 'none',
    });
  }

  // CSRF göstergesi: oturum çerezinde SameSite YOK + durum-değiştiren form anti-CSRF token'sız.
  if (noSameSite.length && (postForms.length === 0 || formsWithoutToken.length > 0) && !csrfInMeta) {
    findings.push({
      check: 'csrf_protection', inputPoint: noSameSite.map((c) => c.name).join(', '), vulnerable: true,
      technique: 'CSRF koruması gözlemi (SameSite + anti-CSRF token) — gösterge',
      evidence: `Oturum çerez(ler)inde **SameSite (Strict/Lax) yok**${postForms.length ? ` ve durum-değiştiren ${formsWithoutToken.length}/${postForms.length} POST formunda anti-CSRF token gözlemlenmedi` : ' (form gözlemlenmedi)'} — çerez-tabanlı oturumda **CSRF göstergesi**. Bu bir göstergedir (gerçek cross-origin saldırı YAPILMADI); SameSite + anti-CSRF token önerilir.`,
      confidence: 'medium', severity: 'medium', sideEffectRisk: 'none',
    });
  } else if (noSameSite.length === 0) {
    notes.push('Oturum çerez(ler)inde SameSite mevcut — CSRF için temel koruma var (olumlu).');
  }

  // ---- 2) OTURUM TOKEN ENTROPİSİ ----
  for (const c of cookies) {
    if (isJwt(c.value)) { notes.push(`\`${c.name}\` bir JWT (yapısal token) — klasik session-id entropi analizi geçerli değil; JWT güvenliği ayrı bölümde.`); continue; }
    if (!c.value) continue;
    const bits = entropyBits(c.value);
    const weak = c.value.length < 16 || bits < 64 || /^\d+$/.test(c.value);
    if (weak) {
      findings.push({
        check: 'weak_session_entropy', inputPoint: c.name, vulnerable: true,
        technique: 'oturum kimliği (session-id) yapısal entropi gözlemi — gösterge',
        evidence: `Oturum kimliği \`${c.name}\` yapısal olarak **zayıf/tahmin-edilebilir** görünüyor (uzunluk ${c.value.length}, ~${Math.round(bits)} bit entropi${/^\d+$/.test(c.value) ? ', tümü sayısal' : ''}) — değer REDAKTE. Yeterli değilse tahmin/brute riski. Gösterge; kesin değerlendirme için üretim token örneklemi gerekir. En az 128-bit rastgele session-id önerilir.`,
        confidence: 'medium', severity: 'medium', sideEffectRisk: 'none',
      });
    }
  }

  // ---- 4) OTURUM ZAMAN AŞIMI / EŞ-ZAMANLI (gözlemsel) ----
  notes.push('Oturum zaman aşımı ve eş-zamanlı oturum politikası GÖZLEMSELDİR; güvenli tek-gözlemle kesin doğrulanamaz (ikinci oturum/uzun bekleme gerektirir) — manuel test önerilir.');

  return { findings, notes };
}

export async function collectSessionDepthEvidence(host: string, session: AuthSession): Promise<ActiveCheckEvidence> {
  const corpus = await fetchClientCorpus(host);
  const flagByName = new Map<string, CookieFlag>((session.cookieFlags ?? []).map((f) => [f.name, f]));
  // GERÇEK sunucu Set-Cookie oturum çerezi: hem cookieFlags'te (Set-Cookie'den) hem Cookie header'ında değeri olan.
  const serverSessionCookies: SessCookie[] = parseCookieHeader(session.cookie)
    .filter((c) => isSessionCookieName(c.name) && flagByName.has(c.name))
    .map((c) => ({ name: c.name, value: c.value, flag: flagByName.get(c.name)! }));

  // ---- SÜTUN 0 SCOPING: sunucu oturum çerezi yoksa TÜM bölüm kapsam dışı (hayalet-bulgu önleme) ----
  if (serverSessionCookies.length === 0) {
    return {
      ok: true, pagesScanned: 1, inputsFound: 0, probesSent: 0, findings: [], stopped: null,
      notes: [`Sunucu-taraflı oturum çerezi (Set-Cookie session) gözlemlenmedi — oturum ${session.bearer ? '**Bearer/JWT token** ile' : 'çerez-dışı'} taşınıyor. Oturum ÇEREZİ güvenliği kontrolleri (CSRF SameSite / çerez-prefix / session-id entropi / oturum-URL'de) bu hedef için **kapsam dışıdır**. Token/JWT güvenliği ayrı **JWT / Token Güvenliği** bölümünde ele alınır.`],
    };
  }

  const { findings, notes } = analyzeSessionSecurity(serverSessionCookies, corpus.homeHtml);

  // ---- 3) OTURUM URL'DE (SESS-04) — session id URL/query'de ifşa mı ----
  const urlParamHit = corpus.homeHtml.match(/[?&](sid|jsessionid|phpsessid|session_?id|sess|asp\.?net_?sessionid|cfid|cftoken)=/i);
  const valueInUrl = serverSessionCookies.find((c) => c.value.length >= 8 && corpus.homeHtml.includes(c.value));
  if (urlParamHit || valueInUrl) {
    findings.push({
      check: 'session_in_url', inputPoint: urlParamHit ? urlParamHit[1] : (valueInUrl?.name ?? 'session'), vulnerable: true,
      technique: 'oturum kimliğinin URL/query içinde ifşası gözlemi',
      evidence: `Oturum kimliği ${urlParamHit ? `URL parametresi olarak (\`${urlParamHit[1]}=\`)` : 'çerez değeriyle bir URL içinde'} ifşa oluyor — URL'ler Referer başlığı, tarayıcı geçmişi, sunucu/proxy loglarında sızar (oturum çalma/fixation riski). Oturum kimliği yalnız HttpOnly çerezde taşınmalı, asla URL'de olmamalı.`,
      confidence: 'high', severity: 'high', sideEffectRisk: 'none',
    });
  }

  const cookieNames = serverSessionCookies.map((c) => c.name).join(', ');
  notes.push(`Gözlemlenen sunucu oturum çerezi: **${serverSessionCookies.length}** (${cookieNames}). Kontroller: SameSite/CSRF, __Host-/__Secure- prefix, session-id entropi, URL-ifşa, zaman-aşımı (gözlemsel).`);
  return { ok: true, pagesScanned: 1, inputsFound: serverSessionCookies.length, probesSent: 0, findings, stopped: null, notes };
}
