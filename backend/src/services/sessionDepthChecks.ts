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
export function analyzeSessionSecurity(cookies: SessCookie[], homeHtml: string, locale: string = 'tr'): { findings: VFinding[]; notes: string[] } {
  const de = locale === 'de', en = locale === 'en';
  const t = (trS: string, deS: string, enS?: string) => (de ? deS : en ? (enS ?? trS) : trS);
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
      technique: t('oturum çerezi güvenlik prefix (__Host-/__Secure-) gözlemi', 'Beobachtung des Sicherheits-Präfixes des Sitzungs-Cookies (__Host-/__Secure-)', 'session-cookie security prefix (__Host-/__Secure-) observation'),
      evidence: t(`Oturum çerez(ler)i \`${noPrefix.map((c) => c.name).join('`, `')}\` **__Host-/__Secure- prefix'i olmadan** ayarlanmış — prefix, çerezin yalnız HTTPS'te ve doğru kapsam/host'ta set edilmesini zorlar (alt-domain/enjeksiyon sertleştirmesi). Düşük-etkili sertleştirme boşluğu.`, `Das/die Sitzungs-Cookie(s) \`${noPrefix.map((c) => c.name).join('`, `')}\` wurde(n) **ohne __Host-/__Secure--Präfix** gesetzt — das Präfix erzwingt, dass das Cookie nur über HTTPS und mit dem korrekten Geltungsbereich/Host gesetzt wird (Härtung gegen Subdomain/Injektion). Härtungslücke mit geringer Auswirkung.`, `The session cookie(s) \`${noPrefix.map((c) => c.name).join('`, `')}\` are set **without a __Host-/__Secure- prefix** — the prefix forces the cookie to be set only over HTTPS and with the correct scope/host (hardening against subdomain/injection). A low-impact hardening gap.`),
      confidence: 'high', severity: 'low', sideEffectRisk: 'none',
    });
  }

  // CSRF göstergesi: oturum çerezinde SameSite YOK + durum-değiştiren form anti-CSRF token'sız.
  if (noSameSite.length && (postForms.length === 0 || formsWithoutToken.length > 0) && !csrfInMeta) {
    findings.push({
      check: 'csrf_protection', inputPoint: noSameSite.map((c) => c.name).join(', '), vulnerable: true,
      technique: t('CSRF koruması gözlemi (SameSite + anti-CSRF token) — gösterge', 'Beobachtung des CSRF-Schutzes (SameSite + Anti-CSRF-Token) — Indikator', 'CSRF-protection observation (SameSite + anti-CSRF token) — indicator'),
      evidence: `${t('Oturum çerez(ler)inde **SameSite (Strict/Lax) yok**', 'Das/die Sitzungs-Cookie(s) haben **kein SameSite (Strict/Lax)**', 'The session cookie(s) have **no SameSite (Strict/Lax)**')}${postForms.length ? t(` ve durum-değiştiren ${formsWithoutToken.length}/${postForms.length} POST formunda anti-CSRF token gözlemlenmedi`, ` und in ${formsWithoutToken.length}/${postForms.length} zustandsändernden POST-Formularen wurde kein Anti-CSRF-Token beobachtet`, ` and no anti-CSRF token was observed in ${formsWithoutToken.length}/${postForms.length} state-changing POST forms`) : t(' (form gözlemlenmedi)', ' (kein Formular beobachtet)', ' (no form observed)')}${t(' — çerez-tabanlı oturumda **CSRF göstergesi**. Bu bir göstergedir (gerçek cross-origin saldırı YAPILMADI); SameSite + anti-CSRF token önerilir.', ' — **CSRF-Indikator** bei einer cookie-basierten Sitzung. Dies ist ein Indikator (es wurde KEIN echter Cross-Origin-Angriff durchgeführt); SameSite + Anti-CSRF-Token werden empfohlen.', ' — a **CSRF indicator** in a cookie-based session. This is an indicator (NO real cross-origin attack was performed); SameSite + an anti-CSRF token are recommended.')}`,
      confidence: 'medium', severity: 'medium', sideEffectRisk: 'none',
    });
  } else if (noSameSite.length === 0) {
    notes.push(t('Oturum çerez(ler)inde SameSite mevcut — CSRF için temel koruma var (olumlu).', 'Das/die Sitzungs-Cookie(s) haben SameSite — ein grundlegender CSRF-Schutz ist vorhanden (positiv).', 'The session cookie(s) have SameSite — basic CSRF protection is present (positive).'));
  }

  // ---- 2) OTURUM TOKEN ENTROPİSİ ----
  for (const c of cookies) {
    if (isJwt(c.value)) { notes.push(t(`\`${c.name}\` bir JWT (yapısal token) — klasik session-id entropi analizi geçerli değil; JWT güvenliği ayrı bölümde.`, `\`${c.name}\` ist ein JWT (strukturiertes Token) — die klassische Session-ID-Entropieanalyse ist nicht anwendbar; die JWT-Sicherheit wird in einem separaten Abschnitt behandelt.`, `\`${c.name}\` is a JWT (structured token) — classic session-id entropy analysis does not apply; JWT security is covered in a separate section.`)); continue; }
    if (!c.value) continue;
    const bits = entropyBits(c.value);
    const weak = c.value.length < 16 || bits < 64 || /^\d+$/.test(c.value);
    if (weak) {
      findings.push({
        check: 'weak_session_entropy', inputPoint: c.name, vulnerable: true,
        technique: t('oturum kimliği (session-id) yapısal entropi gözlemi — gösterge', 'Beobachtung der strukturellen Entropie der Sitzungs-ID (Session-ID) — Indikator', 'session-id structural entropy observation — indicator'),
        evidence: `${t(`Oturum kimliği \`${c.name}\` yapısal olarak **zayıf/tahmin-edilebilir** görünüyor (uzunluk ${c.value.length}, ~${Math.round(bits)} bit entropi`, `Die Sitzungs-ID \`${c.name}\` erscheint strukturell **schwach/vorhersehbar** (Länge ${c.value.length}, ~${Math.round(bits)} Bit Entropie`, `The session id \`${c.name}\` appears structurally **weak/predictable** (length ${c.value.length}, ~${Math.round(bits)} bits of entropy`)}${/^\d+$/.test(c.value) ? t(', tümü sayısal', ', komplett numerisch', ', all numeric') : ''}${t(`) — değer REDAKTE. Yeterli değilse tahmin/brute riski. Gösterge; kesin değerlendirme için üretim token örneklemi gerekir. En az 128-bit rastgele session-id önerilir.`, `) — der Wert ist REDIGIERT. Falls unzureichend, besteht ein Raten-/Brute-Force-Risiko. Indikator; für eine eindeutige Bewertung ist eine Stichprobe von Produktions-Tokens erforderlich. Es wird eine zufällige Session-ID mit mindestens 128 Bit empfohlen.`, `) — the value is REDACTED. If insufficient, there is a guessing/brute-force risk. An indicator; a definitive assessment requires a sample of production tokens. A random session id of at least 128 bits is recommended.`)}`,
        confidence: 'medium', severity: 'medium', sideEffectRisk: 'none',
      });
    }
  }

  // ---- 4) OTURUM ZAMAN AŞIMI / EŞ-ZAMANLI (gözlemsel) ----
  notes.push(t('Oturum zaman aşımı ve eş-zamanlı oturum politikası GÖZLEMSELDİR; güvenli tek-gözlemle kesin doğrulanamaz (ikinci oturum/uzun bekleme gerektirir) — manuel test önerilir.', 'Die Sitzungs-Timeout- und Parallelsitzungs-Richtlinie ist BEOBACHTEND; sie kann mit einer einzelnen sicheren Beobachtung nicht eindeutig bestätigt werden (erfordert eine zweite Sitzung/langes Warten) — ein manueller Test wird empfohlen.', 'The session-timeout and concurrent-session policy is OBSERVATIONAL; it cannot be definitively confirmed with a single safe observation (requires a second session/long wait) — a manual test is recommended.'));

  return { findings, notes };
}

export async function collectSessionDepthEvidence(host: string, session: AuthSession, locale: string = 'tr'): Promise<ActiveCheckEvidence> {
  const de = locale === 'de', en = locale === 'en';
  const t = (trS: string, deS: string, enS?: string) => (de ? deS : en ? (enS ?? trS) : trS);
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
      notes: [`${t('Sunucu-taraflı oturum çerezi (Set-Cookie session) gözlemlenmedi — oturum ', 'Es wurde kein serverseitiges Sitzungs-Cookie (Set-Cookie session) beobachtet — die Sitzung wird ', 'No server-side session cookie (Set-Cookie session) was observed — the session is carried ')}${session.bearer ? t('**Bearer/JWT token** ile', 'per **Bearer/JWT-Token**', 'via a **Bearer/JWT token**') : t('çerez-dışı', 'nicht per Cookie', 'not via a cookie')}${t(` taşınıyor. Oturum ÇEREZİ güvenliği kontrolleri (CSRF SameSite / çerez-prefix / session-id entropi / oturum-URL'de) bu hedef için **kapsam dışıdır**. Token/JWT güvenliği ayrı **JWT / Token Güvenliği** bölümünde ele alınır.`, ` übertragen. Die Prüfungen zur Sitzungs-COOKIE-Sicherheit (CSRF SameSite / Cookie-Präfix / Session-ID-Entropie / Sitzung in URL) sind für dieses Ziel **außerhalb des Geltungsbereichs**. Die Token/JWT-Sicherheit wird im separaten Abschnitt **JWT / Token-Sicherheit** behandelt.`, `. The session-COOKIE security checks (CSRF SameSite / cookie prefix / session-id entropy / session in URL) are **out of scope** for this target. Token/JWT security is covered in the separate **JWT / Token Security** section.`)}`],
    };
  }

  const { findings, notes } = analyzeSessionSecurity(serverSessionCookies, corpus.homeHtml, locale);

  // ---- 3) OTURUM URL'DE (SESS-04) — session id URL/query'de ifşa mı ----
  const urlParamHit = corpus.homeHtml.match(/[?&](sid|jsessionid|phpsessid|session_?id|sess|asp\.?net_?sessionid|cfid|cftoken)=/i);
  const valueInUrl = serverSessionCookies.find((c) => c.value.length >= 8 && corpus.homeHtml.includes(c.value));
  if (urlParamHit || valueInUrl) {
    findings.push({
      check: 'session_in_url', inputPoint: urlParamHit ? urlParamHit[1] : (valueInUrl?.name ?? 'session'), vulnerable: true,
      technique: t('oturum kimliğinin URL/query içinde ifşası gözlemi', 'Beobachtung der Offenlegung der Sitzungs-ID in URL/Query', 'observation of session-id exposure in URL/query'),
      evidence: `${t('Oturum kimliği ', 'Die Sitzungs-ID wird ', 'The session id is ')}${urlParamHit ? t(`URL parametresi olarak (\`${urlParamHit[1]}=\`)`, `als URL-Parameter (\`${urlParamHit[1]}=\`)`, `as a URL parameter (\`${urlParamHit[1]}=\`)`) : t('çerez değeriyle bir URL içinde', 'mit dem Cookie-Wert innerhalb einer URL', 'with the cookie value inside a URL')}${t(` ifşa oluyor — URL'ler Referer başlığı, tarayıcı geçmişi, sunucu/proxy loglarında sızar (oturum çalma/fixation riski). Oturum kimliği yalnız HttpOnly çerezde taşınmalı, asla URL'de olmamalı.`, ` offengelegt — URLs lecken über den Referer-Header, den Browserverlauf sowie Server-/Proxy-Logs (Risiko von Sitzungsdiebstahl/Fixation). Die Sitzungs-ID sollte nur in einem HttpOnly-Cookie getragen werden und niemals in der URL stehen.`, ` exposed — URLs leak via the Referer header, browser history and server/proxy logs (session-theft/fixation risk). The session id should be carried only in an HttpOnly cookie and never in the URL.`)}`,
      confidence: 'high', severity: 'high', sideEffectRisk: 'none',
    });
  }

  const cookieNames = serverSessionCookies.map((c) => c.name).join(', ');
  notes.push(t(`Gözlemlenen sunucu oturum çerezi: **${serverSessionCookies.length}** (${cookieNames}). Kontroller: SameSite/CSRF, __Host-/__Secure- prefix, session-id entropi, URL-ifşa, zaman-aşımı (gözlemsel).`, `Beobachtete Server-Sitzungs-Cookies: **${serverSessionCookies.length}** (${cookieNames}). Prüfungen: SameSite/CSRF, __Host-/__Secure--Präfix, Session-ID-Entropie, URL-Offenlegung, Timeout (beobachtend).`, `Observed server session cookies: **${serverSessionCookies.length}** (${cookieNames}). Checks: SameSite/CSRF, __Host-/__Secure- prefix, session-id entropy, URL exposure, timeout (observational).`));
  return { ok: true, pagesScanned: 1, inputsFound: serverSessionCookies.length, probesSent: 0, findings, stopped: null, notes };
}
