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
import { fetchClientCorpus } from './jsAnalysis.js';
import { cachedOriginUrl, resolveOrigin } from './surfaceEvidence.js';
import { logScanStep } from './scanLogger.js';
import type { AuthSession } from './authSession.js';
import type { ActiveCheckEvidence, VFinding } from './activeVerifyEvidence.js';

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

export async function collectAuthDepthEvidence(host: string, session: AuthSession): Promise<ActiveCheckEvidence> {
  const findings: VFinding[] = [];
  const notes: string[] = [];
  await resolveOrigin(host).catch(() => null);
  const origin = cachedOriginUrl(host);
  const corpus = await fetchClientCorpus(host);
  const homeHtml = corpus.homeHtml;
  const loginUrl = session.loginUrl || findEndpoint(homeHtml, host, /log[\s-]?in|sign[\s-]?in|giriş|oturum/i, ['/rest/user/login', '/api/login', '/login', '/api/auth/login']);
  let probes = 0;
  const rand = () => Math.floor(Math.random() * 1e9).toString(36);

  // ---- 9) KİMLİK ŞİFRESİZ KANALDA (ATHN-01) ----
  const httpsOk = origin.startsWith('https://');
  if (!httpsOk || (loginUrl && loginUrl.startsWith('http://'))) {
    findings.push({
      check: 'auth_cleartext', inputPoint: loginUrl ?? origin, vulnerable: true,
      technique: 'kimlik bilgisi taşıma kanalı (HTTP/HTTPS) gözlemi',
      evidence: `Giriş ${!httpsOk ? 'hedefi HTTPS (443) üzerinden yanıt vermedi; iletişim düz metin (HTTP)' : 'formu/POST\'u HTTP üzerinden yapılıyor'} — kimlik bilgileri şifresiz taşınıyor, ağ üzerinde ele geçirilebilir.`,
      confidence: 'high', severity: 'high', sideEffectRisk: 'none',
    });
  }

  // ---- 1) ENUMERASYON (IDNT-04) — geçerli (test hesabı) vs geçersiz (rastgele), 1'er başarısız deneme ----
  if (loginUrl && session.username) {
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
          technique: 'hesap enumerasyonu (geçerli vs geçersiz kullanıcı yanıt farkı) — gösterge',
          evidence: `Giriş ucu, GEÇERLİ ve GEÇERSİZ kullanıcı için FARKLI yanıt veriyor (${statusDiff ? `durum ${valid.status} vs ${invalid.status}` : 'hata mesajı/gövde farkı'}) — hesap enumerasyonu **göstergesi**. Bu bir göstergedir; tek-tip yanıt önerilir. (Kanıtlanmış hesap sızıntısı değil; doğrulama gerekir.)`,
          confidence: 'medium', severity: 'medium', sideEffectRisk: 'none',
        });
      } else if (timingDiff) {
        notes.push(`Zamanlama farkı gözlemlendi (${valid.ms}ms vs ${invalid.ms}ms) — zayıf/gürültülü enumerasyon sinyali; tek başına güvenilir değil (bilgilendirici).`);
      }
    }
  }

  // ---- 2) VARSAYILAN KİMLİK BİLGİLERİ (ATHN-02) — küçük sabit liste, SADECE başarısız beklenir ----
  if (loginUrl) {
    const DEFAULTS: Array<[string, string]> = [['admin', 'admin'], ['admin', 'password'], ['admin', '123456'], ['administrator', 'administrator'], ['test', 'test'], ['root', 'root']];
    for (const [u, p] of DEFAULTS) {
      const r = await attemptLogin(loginUrl, u, p, `default-cred: ${u}`); probes++;
      if (r?.success) {
        findings.push({
          check: 'default_credentials', inputPoint: `${new URL(loginUrl).pathname} (${u}/****)`, vulnerable: true,
          technique: 'varsayılan kimlik bilgisi denemesi (oturum KULLANILMADI)',
          evidence: `Varsayılan kimlik çifti \`${u}\` / (parola gizli) giriş ucunda **KABUL EDİLDİ** — varsayılan hesap açık. (Kanıtla-istismar-etme: oturum kullanılmadı, yalnız gözlemlendi.)`,
          confidence: 'high', severity: 'high', sideEffectRisk: 'none',
        });
        break; // bir tane yeter — istismar yok
      }
    }
  }

  // ---- 3) ZAYIF LOCKOUT / RATE-LIMIT (ATHN-03) — THROWAWAY kullanıcı (gerçek hesap ASLA) ----
  if (loginUrl) {
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
          technique: 'hesap kilitleme / login hız-sınırı gözlemi (throwaway kullanıcıyla)',
          evidence: `Art arda ${times.length} başarısız giriş denemesinden sonra kilitleme, 429 veya belirgin gecikme gözlemlenmedi — **zayıf/yok lockout & rate-limit göstergesi** (brute-force'a açık olabilir). Gerçek hesap kilitlenmedi (throwaway kullanıcı kullanıldı).`,
          confidence: 'medium', severity: 'medium', sideEffectRisk: 'none',
        });
      } else if (blocked) {
        notes.push('Login hız-sınırı/lockout gözlemlendi (art arda hatalı denemede engel) — olumlu.');
      }
    }
  }

  // ---- 4) PAROLA SIFIRLAMA (ATHN-09) — GÖZLEM: reset ucu + güvenlik-sorusu, GERÇEK e-posta YOK ----
  {
    const resetUrl = findEndpoint(homeHtml, host, /forgot|reset|password|şifre|parola|kurtar/i, ['/rest/user/reset-password', '/api/auth/forgot', '/forgot-password', '/reset']);
    const secQ = new URL('/rest/user/security-question', `${cachedOriginUrl(host)}/`).toString();
    const noneEmail = `ct-reset-${rand()}@example.invalid`;
    const sq = await probe(`${secQ}?email=${encodeURIComponent(noneEmail)}`, { label: 'reset: security-question gözlemi (var-olmayan e-posta)' }); probes++;
    if (sq && sq.status >= 200 && sq.status < 400 && /question|soru|"id"/i.test(sq.text)) {
      findings.push({
        check: 'weak_password_reset', inputPoint: '/rest/user/security-question', vulnerable: true,
        technique: 'parola sıfırlama mekanizması gözlemi (güvenlik sorusu) — gösterge',
        evidence: `Parola sıfırlama **güvenlik sorusu** tabanlı görünüyor (security-question ucu yanıt verdi) — güvenlik soruları tahmin/OSINT ile aşılabilir; token-tabanlı e-posta sıfırlaması daha güvenli. Gösterge; GERÇEK sıfırlama e-postası tetiklenmedi.`,
        confidence: 'medium', severity: 'medium', sideEffectRisk: 'none',
      });
    } else if (resetUrl) {
      notes.push('Parola sıfırlama ucu gözlemlendi; token/mekanizma statik olarak doğrulanamadı (gerçek e-posta tetiklenmedi) — bu bölüm için sınırlı.');
    } else {
      notes.push('Gözlemlenebilir bir parola sıfırlama ucu bulunamadı — bu kontrol **kapsam dışı**.');
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
        technique: 'parola politikası client-side gözlemi (kayıt YAPILMADI)',
        evidence: `Parola alanı client-side olarak **minimum uzunluk (≥8) / karmaşıklık kuralı zorunlu kılmıyor** — zayıf parola politikası göstergesi (sunucu tarafı ayrıca doğrulanmalı; gerçek kayıt yapılmadı).`,
        confidence: 'low', severity: 'low', sideEffectRisk: 'none',
      });
    } else if (!pwInputs.length) {
      notes.push('Ana sayfada client-side parola alanı gözlemlenmedi (SPA/ayrı sayfa olabilir) — parola politikası statik olarak sınırlı incelendi.');
    }
  }

  // ---- 6) "BENİ HATIRLA" KALICI ÇEREZ (ATHN-05) ----
  if (session.method === 'api' && session.bearer) {
    notes.push('Oturum bearer/token tabanlı (çerez-tabanlı "beni hatırla" kalıcı çerezi kapsam dışı).');
  } else {
    const persistent = (session.cookieFlags ?? []).length; // ayrıntılı Max-Age erişimimiz yok; gözlem sınırlı
    if (!persistent) notes.push('Kalıcı "beni hatırla" çerezi gözlemlenmedi — bu kontrol sınırlı/kapsam dışı.');
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
          technique: 'authenticated yanıt cache başlığı gözlemi',
          evidence: `Kimlik-doğrulamalı yanıt (\`${new URL(u).pathname}\`) \`Cache-Control: no-store/no-cache/private\` içermiyor (gözlenen: \`${r.cacheControl ?? 'yok'}\`) — tarayıcı/ara-proxy hassas içeriği önbelleğe alabilir.`,
          confidence: 'medium', severity: 'low', sideEffectRisk: 'none',
        });
      }
      break;
    }
    if (!checked) notes.push('Cache gözlemi için authenticated JSON uç noktası bulunamadı — bu kontrol sınırlı.');
  }

  // ---- 8) MFA VARLIK GÖSTERGESİ (ATHN-11) — bilgilendirici ----
  {
    const mfaHint = /\b(otp|totp|2fa|mfa|two[\s-]?factor|authenticator|verification code|doğrulama kodu|one[\s-]?time)\b/i.test(homeHtml)
      || (session.cookie ?? '').includes('totp') || /totp|mfa|2fa/i.test(corpus.sameOriginJs.map((f) => f.body.slice(0, 4000)).join(' '));
    notes.push(mfaHint
      ? 'MFA/2FA göstergesi gözlemlendi (login akışında ikinci faktör alanları/anahtarları) — olumlu (bilgilendirici).'
      : 'Login akışında MFA/2FA göstergesi gözlemlenmedi (bilgilendirici; ikinci faktör önerilir).');
  }

  notes.push(`Denenen: **${probes}** güvenli auth-probu (varsayılan-kimlik yalnız başarısız login; lockout THROWAWAY kullanıcıyla; reset var-olmayan e-posta ile; kayıt YAPILMADI; gerçek hesap kilitlenmedi).`);
  return { ok: true, pagesScanned: 1, inputsFound: loginUrl ? 1 : 0, probesSent: probes, findings, stopped: null, notes };
}
