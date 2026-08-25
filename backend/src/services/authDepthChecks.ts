/**
 * (Tam Kapsamlı Pentest — Faz 2-A) KİMLİK-DOĞRULAMA & KİMLİK DERİNLİĞİ (WSTG-ATHN/IDNT). 9 kontrol.
 *
 * GÜVENLİK KURALLARI — KOD-SEVİYESİNDE GARANTİ (auth testi en hassas alan):
 *  · GERÇEK test hesabını ASLA kilitleme → lockout testi THROWAWAY rastgele kullanıcı adıyla yapılır
 *    (assert: throwaway !== session.username). Enumerasyonda gerçek kullanıcıya YALNIZ 1 başarısız
 *    deneme (kilit eşiği ≥ birkaç; 1 deneme kilitlemez).
 *  · GERÇEK parola-sıfırlama e-postası TETİKLEME → reset gözlemi rastgele VAR OLMAYAN e-posta ile
 *    (@example.invalid); akış TAMAMLANMAZ, gerçek kullanıcıya/3. kişiye mail gitmez.
 *  · GERÇEK hesap OLUŞTURMA → kayıt politikası yalnız GET ile gözlenir; ASLA POST/kayıt yapılmaz.
 *  · Düşük hacim: brute-force/DoS YOK. Varsayılan-kimlik = küçük sabit liste, yalnız başarısız login.
 *  · Kanıtla-istismar etme: bir bypass/başarılı giriş bulunursa oturum KULLANILMAZ, yalnız raporlanır.
 *
 * SÜTUN 0: her bulgu gerçek gözleme dayanır; enumerasyon/lockout/reset "gösterge, doğrulama gerekir"
 * dilinde; gerekçesiz "kanıtlanmış" DENMEZ.
 */
import { createHash } from 'node:crypto';
import { fetchClientCorpus } from './jsAnalysis.js';
import { cachedOriginUrl, resolveOrigin } from './surfaceEvidence.js';
import { logScanStep } from './scanLogger.js';
import type { AuthSession } from './authSession.js';
import type { ActiveCheckEvidence, VFinding } from './activeVerifyEvidence.js';

const md5 = (s: string) => createHash('md5').update(s).digest('hex');

// (SÜTUN 0 — SPA/NO-LOGIN SCOPING) Login "endpoint"i GERÇEK bir sunucu login ucu mu? Firebase/istemci-
// taraflı SPA'da guessed uç SPA catch-all shell (== ana sayfa) veya 404 döner → GERÇEK DEĞİL. whoami/
// logout ile AYNI endpoint-provenance + SPA-catch-all disiplini. Yanlış-kimlikle 1 deneme yapılır.
async function isRealLoginEndpoint(loginUrl: string | null, homeShell: string): Promise<boolean> {
  if (!loginUrl) return false;
  const r = await attemptLogin(loginUrl, `ct-probe-${Math.floor(Math.random() * 1e9).toString(36)}@example.invalid`, `wrong-${Math.floor(Math.random() * 1e9).toString(36)}`, 'login-endpoint gerçeklik kontrolü');
  if (!r || r.status === 404) return false;
  if (homeShell && md5(r.body) === homeShell) return false;                 // SPA catch-all shell -> gerçek uç değil
  if (/<!doctype|<html[\s>]/i.test(r.body.slice(0, 200)) && !/^\s*[[{]/.test(r.body.trim())) return false; // HTML sayfa döndü
  // GERÇEK login işleme sinyali: token döndü / reddetti (4xx) / login-failure mesajı / JSON login yanıtı.
  return r.success || (r.status >= 400 && r.status < 500) || FAIL_RE.test(r.body.slice(0, 400)) || /^\s*[[{]/.test(r.body.trim());
}

// Güvenlik-sorusu tabanlı reset GERÇEK bir sunucu ucu mu? (var-olmayan e-posta ile GET; e-posta gitmez.)
async function observeSecurityQuestionReset(host: string, r: string, locale: string = 'tr'): Promise<{ real: boolean; finding: VFinding | null }> {
  const de = locale === 'de', en = locale === 'en';
  const t = (trS: string, deS: string, enS?: string) => (de ? deS : en ? (enS ?? trS) : trS);
  const secQ = new URL('/rest/user/security-question', `${cachedOriginUrl(host)}/`).toString();
  const sq = await probe(`${secQ}?email=${encodeURIComponent(`ct-reset-${r}@example.invalid`)}`, { label: 'reset: security-question gözlemi (var-olmayan e-posta)' });
  const real = !!sq && sq.status >= 200 && sq.status < 400 && /question|soru|"id"\s*:/i.test(sq.text) && !/<!doctype|<html[\s>]/i.test(sq.text.slice(0, 200));
  return real
    ? { real: true, finding: {
        check: 'weak_password_reset', inputPoint: '/rest/user/security-question', vulnerable: true,
        technique: t('parola sıfırlama mekanizması gözlemi (güvenlik sorusu) — gösterge', 'Beobachtung des Passwort-Zurücksetzungs-Mechanismus (Sicherheitsfrage) — Indikator', 'password-reset mechanism observation (security question) — indicator'),
        evidence: t('Parola sıfırlama **güvenlik sorusu** tabanlı görünüyor (security-question ucu yanıt verdi) — güvenlik soruları tahmin/OSINT ile aşılabilir; token-tabanlı e-posta sıfırlaması daha güvenli. Gösterge; GERÇEK sıfırlama e-postası tetiklenmedi.', 'Die Passwort-Zurücksetzung scheint auf einer **Sicherheitsfrage** zu basieren (der security-question-Endpunkt hat geantwortet) — Sicherheitsfragen können per Raten/OSINT überwunden werden; eine token-basierte E-Mail-Zurücksetzung ist sicherer. Indikator; es wurde KEINE echte Zurücksetzungs-E-Mail ausgelöst.', 'Password reset appears to be **security-question** based (the security-question endpoint responded) — security questions can be overcome via guessing/OSINT; a token-based e-mail reset is safer. An indicator; NO real reset e-mail was triggered.'),
        confidence: 'medium', severity: 'medium', sideEffectRisk: 'none',
      } }
    : { real: false, finding: null };
}

const REQ_TIMEOUT = 12_000;
const MIN_DELAY = 350;
let lastAt = 0;

type Probe = { status: number; text: string; ms: number; setCookie: string[]; cacheControl: string | null; pragma: string | null; location: string | null; contentType: string | null };

async function probe(url: string, opts: { method?: 'GET' | 'POST'; body?: string; contentType?: string; headers?: Record<string, string>; label?: string } = {}): Promise<Probe | null> {
  const wait = MIN_DELAY - (Date.now() - lastAt);
  if (wait > 0) await new Promise((r) => setTimeout(r, wait));
  lastAt = Date.now();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), REQ_TIMEOUT);
  const t0 = Date.now();
  try {
    const headers: Record<string, string> = { 'user-agent': 'CyberTestify-AuthDepth/1.0', accept: 'application/json,text/html,*/*', ...(opts.headers ?? {}) };
    if (opts.contentType) headers['content-type'] = opts.contentType;
    const res = await fetch(url, { method: opts.method ?? 'GET', body: opts.body, headers, redirect: 'manual', signal: ctrl.signal });
    const buf = Buffer.from(await res.arrayBuffer());
    const ms = Date.now() - t0;
    const gsc = (res.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie;
    const setCookie = typeof gsc === 'function' ? gsc.call(res.headers) : (res.headers.get('set-cookie') ? [res.headers.get('set-cookie')!] : []);
    logScanStep({ step: 'Kimlik-Doğrulama Derinliği', method: opts.method ?? 'GET', url, status: res.status, durationMs: ms, summary: opts.label });
    return { status: res.status, text: buf.subarray(0, 12_000).toString('utf-8'), ms, setCookie, cacheControl: res.headers.get('cache-control'), pragma: res.headers.get('pragma'), location: res.headers.get('location'), contentType: res.headers.get('content-type') };
  } catch {
    logScanStep({ step: 'Kimlik-Doğrulama Derinliği', method: opts.method ?? 'GET', url, status: 0, durationMs: Date.now() - t0, level: 'warn', summary: 'istek başarısız' });
    return null;
  } finally { clearTimeout(timer); }
}

const FAIL_RE = /invalid|incorrect|wrong|failed|hatalı|geçersiz|yanlış|unauthorized|denied|does ?n.t match|kullanıcı adı veya (parola|şifre)/i;
const SUCCESS_TOKEN_RE = /"(?:token|authentication|access_?token|jwt|id_?token)"\s*:\s*"[^"]{16,}/i;

// Login denemesi (JSON + form). Başarı = token/authentication JSON alanı veya oturum Set-Cookie + 2xx.
async function attemptLogin(loginUrl: string, user: string, pass: string, label: string): Promise<{ status: number; ms: number; body: string; success: boolean } | null> {
  const isApi = /\/(rest|api|graphql)\b/i.test(loginUrl) || /\/login\b/i.test(loginUrl);
  const attempts: Array<{ ct: string; body: string }> = isApi
    ? [{ ct: 'application/json', body: JSON.stringify({ email: user, username: user, user, password: pass, pass }) }]
    : [{ ct: 'application/x-www-form-urlencoded', body: `username=${encodeURIComponent(user)}&email=${encodeURIComponent(user)}&user=${encodeURIComponent(user)}&password=${encodeURIComponent(pass)}&pass=${encodeURIComponent(pass)}` }];
  let last: Probe | null = null;
  for (const a of attempts) {
    const r = await probe(loginUrl, { method: 'POST', body: a.body, contentType: a.ct, label });
    if (!r) continue;
    last = r;
    const sessionCookie = r.setCookie.some((c) => /(token|jwt|session|sid|connect\.sid|auth)=/i.test(c));
    const jsonToken = SUCCESS_TOKEN_RE.test(r.text);
    const success = (jsonToken || (sessionCookie && r.status >= 200 && r.status < 400)) && !FAIL_RE.test(r.text.slice(0, 300));
    if (success || r.status < 400) return { status: r.status, ms: r.ms, body: r.text, success };
  }
  return last ? { status: last.status, ms: last.ms, body: last.text, success: false } : null;
}

function findEndpoint(homeHtml: string, host: string, kws: RegExp, wellKnown: string[]): string | null {
  for (const m of homeHtml.matchAll(/(?:href|action)\s*=\s*["']([^"']+)["']/gi)) {
    if (kws.test(m[1])) { try { const u = new URL(m[1], `${cachedOriginUrl(host)}/`); if (u.hostname.toLowerCase() === host.toLowerCase()) return u.toString(); } catch { /* */ } }
  }
  return wellKnown.length ? new URL(wellKnown[0], `${cachedOriginUrl(host)}/`).toString() : null;
}

export async function collectAuthDepthEvidence(host: string, session: AuthSession, locale: string = 'tr'): Promise<ActiveCheckEvidence> {
  const de = locale === 'de', en = locale === 'en';
  const t = (trS: string, deS: string, enS?: string) => (de ? deS : en ? (enS ?? trS) : trS);
  const findings: VFinding[] = [];
  const notes: string[] = [];
  await resolveOrigin(host).catch(() => null);
  const origin = cachedOriginUrl(host);
  const corpus = await fetchClientCorpus(host);
  const homeHtml = corpus.homeHtml;
  const loginUrl = session.loginUrl || findEndpoint(homeHtml, host, /log[\s-]?in|sign[\s-]?in|giriş|oturum/i, ['/rest/user/login', '/api/login', '/login', '/api/auth/login']);
  let probes = 0;
  const rand = () => Math.floor(Math.random() * 1e9).toString(36);
  const httpsOk = origin.startsWith('https://');

  // ============ SÜTUN 0 — SPA / NO-LOGIN SCOPING (hayalet-bulgu önleme) ============
  // GERÇEK bir sunucu login VEYA reset ucu YOKSA (Firebase/istemci-taraflı SPA; guessed uçlar SPA
  // catch-all shell/404 döndü) → TÜM bölüm "Kapsam dışı — uygulanabilir giriş noktası yok". Böylece
  // sahte uca 5 başarısız login atıp "lockout yok" gibi HAYALET bulgu ÜRETİLMEZ (nomorelink bug'ı).
  const homeShell = homeHtml ? md5(homeHtml) : '';
  const loginRealistic = await isRealLoginEndpoint(loginUrl, homeShell); probes++;
  const resetReal = await observeSecurityQuestionReset(host, rand(), locale); probes++;
  if (!loginRealistic && !resetReal.real) {
    return { ok: true, pagesScanned: 1, inputsFound: 0, probesSent: probes, findings: [], stopped: null,
      notes: [t('Uygulanabilir bir SUNUCU kimlik-doğrulama uç noktası (login/reset/register) bu hedefte gözlemlenmedi — guessed uçlar SPA catch-all shell / 404 döndü (istemci-taraflı/SPA veya Firebase auth). Kimlik-doğrulama derinliği kontrolleri bu hedef için **kapsam dışıdır**.', 'Bei diesem Ziel wurde kein anwendbarer SERVER-Authentifizierungs-Endpunkt (Login/Reset/Register) beobachtet — die geratenen Endpunkte gaben ein SPA-Catch-all-Shell / 404 zurück (clientseitig/SPA oder Firebase-Auth). Die Prüfungen zur Authentifizierungstiefe sind für dieses Ziel **außerhalb des Geltungsbereichs**.')] };
  }

  // ---- 9) KİMLİK ŞİFRESİZ KANALDA (ATHN-01) — yalnız gerçek login ucu varsa ----
  if (loginRealistic && (!httpsOk || (loginUrl && loginUrl.startsWith('http://')))) {
    findings.push({
      check: 'auth_cleartext', inputPoint: loginUrl ?? origin, vulnerable: true,
      technique: t('kimlik bilgisi taşıma kanalı (HTTP/HTTPS) gözlemi', 'Beobachtung des Übertragungskanals der Anmeldedaten (HTTP/HTTPS)', 'credential transport channel (HTTP/HTTPS) observation'),
      evidence: `${t('Giriş ', 'Die Anmeldung ', 'The login ')}${!httpsOk ? t('hedefi HTTPS (443) üzerinden yanıt vermedi; iletişim düz metin (HTTP)', 'antwortete nicht über HTTPS (443); die Kommunikation erfolgt im Klartext (HTTP)', 'target did not respond over HTTPS (443); communication is in plaintext (HTTP)') : t('formu/POST\'u HTTP üzerinden yapılıyor', 'erfolgt per Formular/POST über HTTP', 'form/POST is performed over HTTP')}${t(' — kimlik bilgileri şifresiz taşınıyor, ağ üzerinde ele geçirilebilir.', ' — die Anmeldedaten werden unverschlüsselt übertragen und können im Netzwerk abgefangen werden.', ' — credentials are transmitted unencrypted and can be intercepted on the network.')}`,
      confidence: 'high', severity: 'high', sideEffectRisk: 'none',
    });
  }

  // ---- 1) ENUMERASYON (IDNT-04) — geçerli (test hesabı) vs geçersiz (rastgele), 1'er başarısız deneme ----
  if (loginRealistic && loginUrl && session.username) {
    const invalidUser = `ct-nouser-${rand()}@example.invalid`;
    const valid = await attemptLogin(loginUrl, session.username, `wrongpass-${rand()}`, 'enum: geçerli-kullanıcı yanlış-parola'); probes++;
    const invalid = await attemptLogin(loginUrl, invalidUser, `wrongpass-${rand()}`, 'enum: geçersiz-kullanıcı'); probes++;
    if (valid && invalid) {
      const msg = (b: string) => (b.match(FAIL_RE)?.[0] ?? '').toLowerCase();
      const statusDiff = valid.status !== invalid.status;
      const msgDiff = msg(valid.body) !== msg(invalid.body) && (valid.body.slice(0, 200) !== invalid.body.slice(0, 200));
      const timingDiff = Math.abs(valid.ms - invalid.ms) > 700 && Math.min(valid.ms, invalid.ms) > 0;
      if (statusDiff || msgDiff) {
        findings.push({
          check: 'user_enumeration', inputPoint: new URL(loginUrl).pathname, vulnerable: true,
          technique: t('hesap enumerasyonu (geçerli vs geçersiz kullanıcı yanıt farkı) — gösterge', 'Konto-Enumeration (Antwortunterschied gültiger vs. ungültiger Benutzer) — Indikator', 'account enumeration (response difference for valid vs invalid user) — indicator'),
          evidence: `${t('Giriş ucu, GEÇERLİ ve GEÇERSİZ kullanıcı için FARKLI yanıt veriyor (', 'Der Login-Endpunkt antwortet für einen GÜLTIGEN und einen UNGÜLTIGEN Benutzer UNTERSCHIEDLICH (', 'The login endpoint responds DIFFERENTLY for a VALID and an INVALID user (')}${statusDiff ? `${t('durum ', 'Status ', 'status ')}${valid.status} vs ${invalid.status}` : t('hata mesajı/gövde farkı', 'Unterschied in Fehlermeldung/Body', 'error-message/body difference')}${t(') — hesap enumerasyonu **göstergesi**. Bu bir göstergedir; tek-tip yanıt önerilir. (Kanıtlanmış hesap sızıntısı değil; doğrulama gerekir.)', ') — **Indikator** für Konto-Enumeration. Dies ist ein Indikator; eine einheitliche Antwort wird empfohlen. (Kein nachgewiesenes Konto-Leck; eine Bestätigung ist erforderlich.)', ') — an account-enumeration **indicator**. This is an indicator; a uniform response is recommended. (Not proven account leakage; verification is required.)')}`,
          confidence: 'medium', severity: 'medium', sideEffectRisk: 'none',
        });
      } else if (timingDiff) {
        notes.push(t(`Zamanlama farkı gözlemlendi (${valid.ms}ms vs ${invalid.ms}ms) — zayıf/gürültülü enumerasyon sinyali; tek başına güvenilir değil (bilgilendirici).`, `Zeitunterschied beobachtet (${valid.ms}ms vs ${invalid.ms}ms) — schwaches/verrauschtes Enumerationssignal; allein nicht zuverlässig (informativ).`, `Timing difference observed (${valid.ms}ms vs ${invalid.ms}ms) — a weak/noisy enumeration signal; not reliable on its own (informational).`));
      }
    }
  }

  // ---- 2) VARSAYILAN KİMLİK BİLGİLERİ (ATHN-02) — küçük sabit liste, SADECE başarısız beklenir ----
  if (loginRealistic && loginUrl) {
    const DEFAULTS: Array<[string, string]> = [['admin', 'admin'], ['admin', 'password'], ['admin', '123456'], ['administrator', 'administrator'], ['test', 'test'], ['root', 'root']];
    for (const [u, p] of DEFAULTS) {
      const r = await attemptLogin(loginUrl, u, p, `default-cred: ${u}`); probes++;
      if (r?.success) {
        findings.push({
          check: 'default_credentials', inputPoint: `${new URL(loginUrl).pathname} (${u}/****)`, vulnerable: true,
          technique: t('varsayılan kimlik bilgisi denemesi (oturum KULLANILMADI)', 'Versuch mit Standard-Anmeldedaten (Sitzung NICHT genutzt)', 'default-credential attempt (session NOT used)'),
          evidence: t(`Varsayılan kimlik çifti \`${u}\` / (parola gizli) giriş ucunda **KABUL EDİLDİ** — varsayılan hesap açık. (Kanıtla-istismar-etme: oturum kullanılmadı, yalnız gözlemlendi.)`, `Das Standard-Anmeldepaar \`${u}\` / (Passwort verborgen) wurde am Login-Endpunkt **AKZEPTIERT** — das Standardkonto ist offen. (Nachweisen-nicht-ausnutzen: die Sitzung wurde nicht genutzt, nur beobachtet.)`, `The default credential pair \`${u}\` / (password hidden) was **ACCEPTED** at the login endpoint — the default account is open. (Prove-don't-exploit: the session was not used, only observed.)`),
          confidence: 'high', severity: 'high', sideEffectRisk: 'none',
        });
        break; // bir tane yeter — istismar yok
      }
    }
  }

  // ---- 3) ZAYIF LOCKOUT / RATE-LIMIT (ATHN-03) — THROWAWAY kullanıcı (gerçek hesap ASLA) ----
  if (loginRealistic && loginUrl) {
    const throwaway = `ct-lockout-${rand()}@example.invalid`;
    if (throwaway === session.username) { /* imkânsız (rastgele) — güvenlik asserti */ } else {
      let blocked = false; let slow = false; const times: number[] = [];
      for (let i = 0; i < 5; i++) {
        const r = await attemptLogin(loginUrl, throwaway, `wrong-${rand()}`, `lockout-probe#${i + 1} (throwaway)`); probes++;
        if (!r) break;
        times.push(r.ms);
        if (r.status === 429 || /locked|too many|çok fazla|kilitlen|rate.?limit|try again later/i.test(r.body.slice(0, 300))) { blocked = true; break; }
      }
      if (times.length >= 4) slow = times[times.length - 1] > times[0] * 3 && times[times.length - 1] > 1500;
      if (!blocked && !slow && times.length >= 4) {
        findings.push({
          check: 'weak_lockout', inputPoint: new URL(loginUrl).pathname, vulnerable: true,
          technique: t('hesap kilitleme / login hız-sınırı gözlemi (throwaway kullanıcıyla)', 'Beobachtung der Kontosperrung / Login-Ratenbegrenzung (mit Wegwerf-Benutzer)', 'account lockout / login rate-limit observation (with a throwaway user)'),
          evidence: t(`Art arda ${times.length} başarısız giriş denemesinden sonra kilitleme, 429 veya belirgin gecikme gözlemlenmedi — **zayıf/yok lockout & rate-limit göstergesi** (brute-force'a açık olabilir). Gerçek hesap kilitlenmedi (throwaway kullanıcı kullanıldı).`, `Nach ${times.length} aufeinanderfolgenden fehlgeschlagenen Anmeldeversuchen wurde keine Sperrung, kein 429 und keine deutliche Verzögerung beobachtet — **Indikator für schwache/fehlende Sperrung & Ratenbegrenzung** (möglicherweise für Brute-Force anfällig). Es wurde kein echtes Konto gesperrt (ein Wegwerf-Benutzer wurde verwendet).`, `After ${times.length} consecutive failed login attempts, no lockout, 429 or noticeable delay was observed — **a weak/absent lockout & rate-limit indicator** (may be exposed to brute-force). No real account was locked (a throwaway user was used).`),
          confidence: 'medium', severity: 'medium', sideEffectRisk: 'none',
        });
      } else if (blocked) {
        notes.push(t('Login hız-sınırı/lockout gözlemlendi (art arda hatalı denemede engel) — olumlu.', 'Login-Ratenbegrenzung/Sperrung beobachtet (Blockade bei aufeinanderfolgenden Fehlversuchen) — positiv.', 'Login rate-limit/lockout observed (block on consecutive failed attempts) — positive.'));
      }
    }
  }

  // ---- 4) PAROLA SIFIRLAMA (ATHN-09) — GÖZLEM: security-question reset (yukarıda 1 kez probe edildi) ----
  {
    const resetUrl = findEndpoint(homeHtml, host, /forgot|reset|password|şifre|parola|kurtar/i, ['/rest/user/reset-password', '/api/auth/forgot', '/forgot-password', '/reset']);
    if (resetReal.finding) {
      findings.push(resetReal.finding);
    } else if (resetUrl) {
      notes.push(t('Parola sıfırlama ucu gözlemlendi; token/mekanizma statik olarak doğrulanamadı (gerçek e-posta tetiklenmedi) — bu bölüm için sınırlı.', 'Ein Passwort-Zurücksetzungs-Endpunkt wurde beobachtet; das Token/der Mechanismus konnte statisch nicht validiert werden (es wurde keine echte E-Mail ausgelöst) — für diesen Abschnitt eingeschränkt.', 'A password-reset endpoint was observed; the token/mechanism could not be validated statically (no real e-mail was triggered) — limited for this section.'));
    } else {
      notes.push(t('Gözlemlenebilir bir parola sıfırlama ucu bulunamadı — bu kontrol **kapsam dışı**.', 'Es wurde kein beobachtbarer Passwort-Zurücksetzungs-Endpunkt gefunden — diese Prüfung ist **außerhalb des Geltungsbereichs**.', 'No observable password-reset endpoint was found — this check is **out of scope**.'));
    }
  }

  // ---- 5) PAROLA/KAYIT POLİTİKASI (ATHN-07/IDNT-05) — SADECE GET, kayıt YOK ----
  {
    const pwInputs = [...homeHtml.matchAll(/<input\b[^>]*type\s*=\s*["']password["'][^>]*>/gi)].map((m) => m[0]);
    const weak = pwInputs.find((tag) => {
      const min = tag.match(/minlength\s*=\s*["']?(\d+)/i);
      const hasPattern = /\bpattern\s*=/i.test(tag);
      return (!min || parseInt(min[1], 10) < 8) && !hasPattern;
    });
    if (pwInputs.length && weak) {
      findings.push({
        check: 'weak_password_policy', inputPoint: 'parola alanı (client-side)', vulnerable: true,
        technique: t('parola politikası client-side gözlemi (kayıt YAPILMADI)', 'clientseitige Beobachtung der Passwortrichtlinie (KEINE Registrierung durchgeführt)', 'password-policy client-side observation (NO registration performed)'),
        evidence: t(`Parola alanı client-side olarak **minimum uzunluk (≥8) / karmaşıklık kuralı zorunlu kılmıyor** — zayıf parola politikası göstergesi (sunucu tarafı ayrıca doğrulanmalı; gerçek kayıt yapılmadı).`, `Das Passwortfeld erzwingt clientseitig **keine Mindestlänge (≥8) / keine Komplexitätsregel** — Indikator für eine schwache Passwortrichtlinie (die Serverseite muss zusätzlich validiert werden; es wurde keine echte Registrierung durchgeführt).`, `The password field client-side **does not enforce a minimum length (≥8) / complexity rule** — a weak password-policy indicator (the server side must also be validated; no real registration was performed).`),
        confidence: 'low', severity: 'low', sideEffectRisk: 'none',
      });
    } else if (!pwInputs.length) {
      notes.push(t('Ana sayfada client-side parola alanı gözlemlenmedi (SPA/ayrı sayfa olabilir) — parola politikası statik olarak sınırlı incelendi.', 'Auf der Startseite wurde kein clientseitiges Passwortfeld beobachtet (möglicherweise SPA/separate Seite) — die Passwortrichtlinie wurde statisch nur eingeschränkt geprüft.', 'No client-side password field was observed on the home page (may be SPA/separate page) — the password policy was only examined statically in a limited way.'));
    }
  }

  // ---- 6) "BENİ HATIRLA" KALICI ÇEREZ (ATHN-05) ----
  if (session.method === 'api' && session.bearer) {
    notes.push(t('Oturum bearer/token tabanlı (çerez-tabanlı "beni hatırla" kalıcı çerezi kapsam dışı).', 'Die Sitzung ist Bearer/Token-basiert (ein cookie-basiertes „Angemeldet bleiben"-Persistenz-Cookie ist außerhalb des Geltungsbereichs).', 'The session is bearer/token-based (a cookie-based "remember me" persistence cookie is out of scope).'));
  } else {
    const persistent = (session.cookieFlags ?? []).length; // ayrıntılı Max-Age erişimimiz yok; gözlem sınırlı
    if (!persistent) notes.push(t('Kalıcı "beni hatırla" çerezi gözlemlenmedi — bu kontrol sınırlı/kapsam dışı.', 'Es wurde kein persistentes „Angemeldet bleiben"-Cookie beobachtet — diese Prüfung ist eingeschränkt/außerhalb des Geltungsbereichs.', 'No persistent "remember me" cookie was observed — this check is limited/out of scope.'));
  }

  // ---- 7) AUTHENTICATED SAYFA CACHE (ATHN-06) — session ile authed uç, Cache-Control gözlemi ----
  {
    const authHeaders: Record<string, string> = {};
    if (session.cookie) authHeaders['cookie'] = session.cookie;
    if (session.bearer) { authHeaders['authorization'] = `Bearer ${session.bearer}`; authHeaders['cookie'] = `${authHeaders['cookie'] ? authHeaders['cookie'] + '; ' : ''}token=${session.bearer}`; }
    const candidates = ['/rest/user/whoami', '/api/me', '/account', '/rest/basket', '/api/user'];
    let checked = false;
    for (const p of candidates) {
      const u = new URL(p, `${cachedOriginUrl(host)}/`).toString();
      const r = await probe(u, { headers: authHeaders, label: 'cache: authed uç Cache-Control gözlemi' }); probes++;
      if (!r || r.status !== 200) continue;
      const isJson = /json/i.test(r.contentType ?? '') || /^\s*[[{]/.test(r.text.trim());
      if (!isJson) continue; // authed API yanıtı (shell değil)
      checked = true;
      const cc = (r.cacheControl ?? '').toLowerCase();
      const safe = /no-store|no-cache|private/.test(cc) || /no-cache/i.test(r.pragma ?? '');
      if (!safe) {
        findings.push({
          check: 'auth_page_cacheable', inputPoint: new URL(u).pathname, vulnerable: true,
          technique: t('authenticated yanıt cache başlığı gözlemi', 'Beobachtung des Cache-Headers der authentifizierten Antwort', 'authenticated-response cache-header observation'),
          evidence: t(`Kimlik-doğrulamalı yanıt (\`${new URL(u).pathname}\`) \`Cache-Control: no-store/no-cache/private\` içermiyor (gözlenen: \`${r.cacheControl ?? 'yok'}\`) — tarayıcı/ara-proxy hassas içeriği önbelleğe alabilir.`, `Die authentifizierte Antwort (\`${new URL(u).pathname}\`) enthält kein \`Cache-Control: no-store/no-cache/private\` (beobachtet: \`${r.cacheControl ?? 'keines'}\`) — Browser/Zwischen-Proxy können sensible Inhalte zwischenspeichern.`, `The authenticated response (\`${new URL(u).pathname}\`) does not contain \`Cache-Control: no-store/no-cache/private\` (observed: \`${r.cacheControl ?? 'none'}\`) — a browser/intermediate proxy could cache sensitive content.`),
          confidence: 'medium', severity: 'low', sideEffectRisk: 'none',
        });
      }
      break;
    }
    if (!checked) notes.push(t('Cache gözlemi için authenticated JSON uç noktası bulunamadı — bu kontrol sınırlı.', 'Für die Cache-Beobachtung wurde kein authentifizierter JSON-Endpunkt gefunden — diese Prüfung ist eingeschränkt.', 'No authenticated JSON endpoint was found for the cache observation — this check is limited.'));
  }

  // ---- 8) MFA VARLIK GÖSTERGESİ (ATHN-11) — bilgilendirici ----
  {
    const mfaHint = /\b(otp|totp|2fa|mfa|two[\s-]?factor|authenticator|verification code|doğrulama kodu|one[\s-]?time)\b/i.test(homeHtml)
      || (session.cookie ?? '').includes('totp') || /totp|mfa|2fa/i.test(corpus.sameOriginJs.map((f) => f.body.slice(0, 4000)).join(' '));
    notes.push(mfaHint
      ? t('MFA/2FA göstergesi gözlemlendi (login akışında ikinci faktör alanları/anahtarları) — olumlu (bilgilendirici).', 'MFA/2FA-Indikator beobachtet (Zweitfaktor-Felder/-Schlüssel im Login-Ablauf) — positiv (informativ).', 'An MFA/2FA indicator was observed (second-factor fields/keys in the login flow) — positive (informational).')
      : t('Login akışında MFA/2FA göstergesi gözlemlenmedi (bilgilendirici; ikinci faktör önerilir).', 'Im Login-Ablauf wurde kein MFA/2FA-Indikator beobachtet (informativ; ein zweiter Faktor wird empfohlen).', 'No MFA/2FA indicator was observed in the login flow (informational; a second factor is recommended).'));
  }

  notes.push(t(`Denenen: **${probes}** güvenli auth-probu (varsayılan-kimlik yalnız başarısız login; lockout THROWAWAY kullanıcıyla; reset var-olmayan e-posta ile; kayıt YAPILMADI; gerçek hesap kilitlenmedi).`, `Durchgeführt: **${probes}** sichere Auth-Probes (Standard-Anmeldedaten nur als fehlgeschlagener Login; Sperrung mit WEGWERF-Benutzer; Zurücksetzung mit nicht existierender E-Mail; KEINE Registrierung; kein echtes Konto gesperrt).`, `Performed: **${probes}** safe auth probes (default credentials only as a failed login; lockout with a THROWAWAY user; reset with a non-existent e-mail; NO registration; no real account locked).`));
  // Buraya YALNIZ gerçek bir sunucu login/reset ucu VARSA gelinir (yukarıdaki kapsam kapısı) → inputsFound=1.
  return { ok: true, pagesScanned: 1, inputsFound: 1, probesSent: probes, findings, stopped: null, notes };
}
