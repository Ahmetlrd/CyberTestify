/**
 * (Tam Kapsamlı Pentest — FAZ B) BACKEND DETERMİNİSTİK LOGIN + OTURUM PAYLAŞIMI.
 *
 * MİMARİ KARAR: Şifre ASLA PentAGI ajanına/prompt'a gönderilmez. Backend login'i KENDİSİ yapar
 * (API-login öncelikli, headless form-login fallback) ve elde ettiği OTURUMU (cookie jar / bearer
 * token — ŞİFRE DEĞİL) kontrollere/ajana geçirir. Böylece kimlik bilgisi PentAGI flow log'larına
 * HİÇ ulaşmaz (Go tarafı credential-redaction yalnız son güvenlik ağıdır).
 *
 * Oturum, SESSION_CACHE'te host başına tutulur (discoverSurface in-flight cache deseni): aynı
 * taramanın 7+ kontrolü hedefe TEKRAR login denemeden TEK oturumu paylaşır.
 *
 * GÜVENLİK: yalnız hedef host + in-scope; iç ağ ASLA; yalnız TEST hesabı (FAZ A consent/beyan);
 * yalnız test.cybertestify.com'a karşı denendi (bkz FAZ B doğrulama).
 */
import puppeteer from 'puppeteer-core';
import { discoverSurface, type Surface } from './activeVerifyEvidence.js';
import { consumeTestCredential, type TestCredentialInput } from './testCredentials.js';
import { sendAuthLoginFailed } from './mailer.js';
import { type AuthSession, type CookieFlag, applyAuthHeaders, parseSetCookie } from './authSession.js';
import { prisma } from '../db.js';

export { applyAuthHeaders } from './authSession.js';
export type { AuthSession } from './authSession.js';

const CHROMIUM_PATH = process.env.PUPPETEER_EXECUTABLE_PATH || '/usr/bin/chromium-browser';
const LOGIN_TIMEOUT_MS = 12_000;
const MAX_API_TRIES = 5;               // API-login aday üst sınırı (form-login bütçesinden AYRI)
const SESSION_TTL_MS = 10 * 60 * 1000; // bir taramanın ömrü boyunca oturum paylaşılır

// Login uç noktası işaretleri (path'te) + kimlik alan adları + token alanları + 2FA göstergeleri.
const LOGIN_PATH_RE = /(login|signin|sign-in|sign_in|auth(?!or)|session|token|oauth\/token|users?\/sign_in)/i;
const TOKEN_FIELD_RE = /^(token|jwt|access_token|accessToken|authToken|id_token|bearer)$/i;
const AUTH_COOKIE_RE = /(token|jwt|session|sid|auth|connect\.sid|_session)/i;
const TWO_FACTOR_RE = /(two[- ]?factor|2fa|otp\b|one[- ]?time|authenticator|totp|verification code|doğrulama kodu|tek kullanımlık)/i;
const WELL_KNOWN_LOGIN = ['/rest/user/login', '/api/auth/login', '/api/login', '/api/sessions', '/auth/login', '/login', '/user/login', '/users/sign_in', '/api/v1/auth/login'];

export type AuthResult =
  | { ok: true; session: AuthSession; attempts: number }
  | { ok: false; reason: 'bad_credentials' | 'two_factor' | 'no_login_endpoint' | 'error'; attempts: number };

function sameHostAbs(pathOrUrl: string, host: string): string | null {
  try {
    const u = pathOrUrl.startsWith('http') ? new URL(pathOrUrl) : new URL(pathOrUrl, `https://${host}/`);
    if (u.hostname.toLowerCase() !== host.toLowerCase() || isInternalHostname(u.hostname)) return null;
    return u.toString();
  } catch { return null; }
}
function isInternalHostname(h: string): boolean {
  const x = h.toLowerCase().replace(/\.$/, '');
  if (x === 'localhost' || x.endsWith('.localhost') || x.endsWith('.internal') || x.endsWith('.local')) return true;
  const m = x.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) { const a = +m[1], b = +m[2]; if (a === 127 || a === 10 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return true; }
  return false;
}

// --- login denemesi sayacı (SESSION_CACHE paylaşımını KANITLAMAK için) --------
const loginAttemptsByHost = new Map<string, number>();
function bump(host: string) { loginAttemptsByHost.set(host, (loginAttemptsByHost.get(host) ?? 0) + 1); }
export function __loginAttemptsForHost(host: string): number { return loginAttemptsByHost.get(host) ?? 0; }

// Keşiften login uç adaylarını çıkar (ağ-trafiği apiWrites + iyi-bilinen yollar). En olası önce.
function loginCandidates(host: string, surf: Surface): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const add = (p: string) => { const u = sameHostAbs(p, host); if (u && !seen.has(u)) { seen.add(u); out.push(u); } };
  for (const w of surf.apiWrites) { // "POST /rest/user/login"
    const path = w.replace(/^\w+\s+/, '');
    if (LOGIN_PATH_RE.test(path)) add(path);
  }
  for (const p of WELL_KNOWN_LOGIN) add(p);
  return out;
}

// Tek bir API-login isteği: JSON body dene (email+username+password anahtarları). Token/cookie yakala.
async function tryApiLogin(url: string, creds: TestCredentialInput): Promise<{ session: AuthSession; twoFactor: boolean } | { twoFactor: boolean } | null> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), LOGIN_TIMEOUT_MS);
  try {
    const body = JSON.stringify({ email: creds.username, username: creds.username, user: creds.username, password: creds.password });
    const res = await fetch(url, {
      method: 'POST', signal: ctrl.signal, redirect: 'manual',
      headers: { 'content-type': 'application/json', accept: 'application/json, */*', 'user-agent': 'CyberTestify-AuthLogin/1.0' },
      body,
    });
    const text = (await res.text()).slice(0, 20_000);
    // (SPA catch-all) Next.js/Firebase gibi tek-sayfa uygulamalar HER yola index HTML'i (200)
    // döner. Bunu "login uç noktası VAR" sanmak sahte 'bad_credentials' üretir VE gerçek çözüm
    // olan headless form-login'i bütçeden eder. HTML yanıtı = API login endpoint'i DEĞİL -> null.
    const ctype = res.headers.get('content-type') ?? '';
    if (/text\/html/i.test(ctype) || /^\s*<(!doctype|html)/i.test(text)) return null;
    const twoFactor = TWO_FACTOR_RE.test(text);
    if (res.status < 200 || res.status >= 400) return { twoFactor };
    // (a) Set-Cookie — hem Cookie header değeri hem güvenlik-bayrağı analizi (FAZ C).
    const setCookies = (res.headers as any).getSetCookie?.() ?? [];
    const authCookies: string[] = [];
    const cookieFlags: CookieFlag[] = [];
    for (const c of setCookies as string[]) {
      const nv = c.split(';')[0];
      const name = nv.split('=')[0];
      cookieFlags.push(parseSetCookie(c));
      if (AUTH_COOKIE_RE.test(name)) authCookies.push(nv);
    }
    // (b) JSON body'de token alanı (Juice Shop: {authentication:{token}})
    let bearer: string | undefined;
    try {
      const j = JSON.parse(text);
      const scan = (o: any, depth = 0): void => {
        if (bearer || !o || typeof o !== 'object' || depth > 4) return;
        for (const [k, v] of Object.entries(o)) {
          if (typeof v === 'string' && TOKEN_FIELD_RE.test(k) && v.length > 20) { bearer = v; return; }
          if (v && typeof v === 'object') scan(v, depth + 1);
        }
      };
      scan(j);
    } catch { /* JSON değil */ }
    if (bearer || authCookies.length) {
      return { session: { method: 'api', loginUrl: url, cookie: authCookies.join('; ') || undefined, bearer, cookieFlags: cookieFlags.length ? cookieFlags : undefined, acquiredAt: Date.now() }, twoFactor };
    }
    return { twoFactor };
  } catch { return null; }
  finally { clearTimeout(timer); }
}

// Tarayıcı içinde (page.evaluate) oturum token'ını yakala. Sıra: (1) localStorage'da JWT-benzeri
// düz token, (2) Supabase (`sb-*-auth-token` JSON -> access_token), (3) Firebase (IndexedDB
// `firebaseLocalStorageDb` -> stsTokenManager.accessToken). Firebase/Supabase gibi client-SDK
// auth'lar oturumu COOKIE'de DEĞİL IndexedDB/localStorage'da tutar; bunları yakalamazsak SPA
// login'i "başarısız" görünürdü. Sadece OKUR; şifreyi kullanmaz.
async function extractBrowserToken(page: Awaited<ReturnType<Awaited<ReturnType<typeof puppeteer.launch>>['newPage']>>): Promise<string> {
  // (1)+(2) localStorage
  const lsToken = await page.evaluate(() => {
    try {
      for (const k of Object.keys(localStorage)) {
        const raw = localStorage.getItem(k) || '';
        if (!raw) continue;
        // Firebase (localStorage persistence): `firebase:authUser:<apiKey>:[DEFAULT]` JSON ->
        // stsTokenManager.accessToken (JWT idToken). Çoğu Firebase SPA cookie/IndexedDB DEĞİL
        // BURAYA yazar. (nomorelink.com bu şekilde.)
        if (/firebase:authUser/i.test(k) || raw.includes('stsTokenManager')) {
          try { const j = JSON.parse(raw); const at = j && j.stsTokenManager && j.stsTokenManager.accessToken; if (typeof at === 'string' && at.length > 20) return at; } catch { /* düz değil */ }
        }
        // Supabase: {"access_token":"...", ...} veya ["access_token", ...]
        if (/auth-token|supabase|sb-/i.test(k) && raw.includes('access_token')) {
          try { const j = JSON.parse(raw); const at = j.access_token || (Array.isArray(j) ? j[0] : ''); if (typeof at === 'string' && at.length > 20) return at; } catch { /* düz değil */ }
        }
        // Düz JWT-benzeri
        if (/token|jwt|access|id_token/i.test(k) && /^[A-Za-z0-9._-]{30,}$/.test(raw.replace(/^"|"$/g, ''))) return raw.replace(/^"|"$/g, '');
      }
    } catch { /* erişilemez */ }
    return '';
  });
  if (lsToken) return lsToken;
  // (3) Firebase IndexedDB
  const fbToken = await page.evaluate(async () => {
    try {
      const dbNames: string[] = [];
      // @ts-ignore - indexedDB.databases bazı sürümlerde yok
      if (typeof indexedDB.databases === 'function') { const list = await indexedDB.databases(); for (const d of list) if (d && d.name) dbNames.push(d.name); }
      const targets = dbNames.filter((n) => /firebase/i.test(n));
      for (const name of (targets.length ? targets : ['firebaseLocalStorageDb'])) {
        const token = await new Promise<string>((resolve) => {
          let done = false; const finish = (v: string) => { if (!done) { done = true; resolve(v); } };
          const req = indexedDB.open(name);
          req.onerror = () => finish('');
          req.onsuccess = () => {
            try {
              const db = req.result;
              const stores = Array.from(db.objectStoreNames);
              const sn = stores.find((s) => /firebaseLocalStorage/i.test(s)) || stores[0];
              if (!sn) return finish('');
              const getAll = db.transaction(sn, 'readonly').objectStore(sn).getAll();
              getAll.onerror = () => finish('');
              getAll.onsuccess = () => {
                for (const rec of (getAll.result || [])) {
                  const val: any = rec && typeof rec === 'object' && 'value' in rec ? (rec as any).value : rec;
                  const at = val && val.stsTokenManager && val.stsTokenManager.accessToken;
                  if (typeof at === 'string' && at.length > 20) return finish(at);
                }
                finish('');
              };
            } catch { finish(''); }
          };
        });
        if (token) return token;
      }
    } catch { /* yok */ }
    return '';
  }).catch(() => '');
  return fbToken;
}

// Headless form-login fallback: login sayfasını render et, kullanıcı/şifre alanlarını doldur, gönder,
// oluşan çerezi/localStorage/IndexedDB token'ını yakala. ŞİFRE yalnız tarayıcı içinde kullanılır, döndürülmez.
// SPA'larda (React/Next/Firebase) login formu JS ile render olduğundan password alanı için beklenir.
type FormLoginResult = { session?: AuthSession; twoFactor: boolean; formFound: boolean };
async function tryFormLogin(host: string, creds: TestCredentialInput): Promise<FormLoginResult | null> {
  let browser: Awaited<ReturnType<typeof puppeteer.launch>> | null = null;
  try {
    browser = await puppeteer.launch({ executablePath: CHROMIUM_PATH, headless: true, args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'] });
  } catch { return null; }
  const loginPages = ['/#/login', '/login', '/giris', '/giris-yap', '/hesap/giris', '/signin', '/sign-in', '/account/login', '/users/sign_in', '/'];
  const pwSel = 'input[type="password"]';
  let formFound = false;
  try {
    for (const lp of loginPages) {
      const url = sameHostAbs(lp, host);
      if (!url) continue;
      const page = await browser.newPage();
      try {
        await page.setUserAgent('CyberTestify-AuthLogin/1.0');
        await page.goto(url, { waitUntil: 'domcontentloaded', timeout: LOGIN_TIMEOUT_MS });
        // SPA: password alanı JS render'ı sonrası gelir — kısa süre bekle (yoksa bu rotayı geç).
        await page.waitForSelector(pwSel, { timeout: 6000 }).catch(() => {});
        if (!(await page.$(pwSel))) { await page.close().catch(() => {}); continue; }
        formFound = true;
        const bodyText = (await page.evaluate(() => document.body?.innerText ?? '')).slice(0, 20_000);
        const twoFactor = TWO_FACTOR_RE.test(bodyText);
        const userSel = (await page.$('input[type="email"]')) ? 'input[type="email"]'
          : (await page.$('input[name*="user" i], input[name*="email" i], input[id*="email" i], input[id*="user" i]')) ? 'input[name*="user" i], input[name*="email" i], input[id*="email" i], input[id*="user" i]'
          : 'input[type="text"]';
        await page.type(userSel, creds.username, { delay: 5 }).catch(() => {});
        await page.type(pwSel, creds.password, { delay: 5 }).catch(() => {});
        const submitted = await page.evaluate(() => {
          const b = document.querySelector('button[type="submit"], input[type="submit"], button#loginButton, button[aria-label*="login" i], button[aria-label*="giriş" i]') as HTMLElement | null;
          if (b) { b.click(); return true; }
          return false;
        });
        if (!submitted) await page.keyboard.press('Enter').catch(() => {});
        await page.waitForNetworkIdle({ idleTime: 800, timeout: 8000 }).catch(() => {});
        const bearer = await extractBrowserToken(page);
        const cookies = await page.cookies();
        const authCookies = cookies.filter((c) => AUTH_COOKIE_RE.test(c.name)).map((c) => `${c.name}=${c.value}`);
        const cookieFlags: CookieFlag[] = cookies.map((c) => ({ name: c.name, secure: !!c.secure, httpOnly: !!c.httpOnly, sameSite: (c as any).sameSite ?? null }));
        await page.close().catch(() => {});
        if (bearer || authCookies.length) {
          return { session: { method: 'form', loginUrl: url, cookie: authCookies.join('; ') || undefined, bearer: bearer || undefined, cookieFlags: cookieFlags.length ? cookieFlags : undefined, acquiredAt: Date.now() }, twoFactor, formFound };
        }
        return { twoFactor, formFound }; // form vardı ama oturum alınamadı -> bad_credentials
      } catch { await page.close().catch(() => {}); }
    }
    return { twoFactor: false, formFound }; // formFound=false ise hiç login formu yok -> no_login_endpoint
  } finally { await browser.close().catch(() => {}); }
}

/**
 * Bir host'a TEST hesabıyla login ol. Önce API-login (JSON, en fazla MAX_API_TRIES aday; SPA-HTML
 * yanıtları elenir), SONRA HER ZAMAN headless form-login (SPA/form-only/Firebase için). Başarı →
 * AuthSession (şifre YOK, yalnız cookie/bearer). 2FA göstergesi → two_factor.
 */
export async function login(host: string, creds: TestCredentialInput): Promise<AuthResult> {
  let attempts = 0;
  let sawTwoFactor = false;
  let sawEndpoint = false;
  const surf = await discoverSurface(host).catch(() => null);
  const candidates = surf ? loginCandidates(host, surf) : WELL_KNOWN_LOGIN.map((p) => sameHostAbs(p, host)).filter(Boolean) as string[];

  // 1) API-login (JSON). SPA-HTML/ağ yanıtları null döner -> endpoint SAYILMAZ ve form-login
  //    bütçesini TÜKETMEZ (ayrı MAX_API_TRIES sınırı). Böylece SPA catch-all sahte 'bad_credentials'
  //    üretip gerçek çözümü (form-login) engelleyemez.
  let apiTries = 0;
  for (const url of candidates) {
    if (apiTries >= MAX_API_TRIES) break;
    apiTries++; attempts++; bump(host);
    const r = await tryApiLogin(url, creds);
    if (r === null) continue;             // ağ hatası VEYA SPA-HTML — endpoint sayılmaz
    sawEndpoint = true;
    if (r.twoFactor) sawTwoFactor = true;
    if ('session' in r) return { ok: true, session: r.session, attempts };
  }

  // 2) headless form-login — HER ZAMAN dene. SPA/form-only/Firebase (IndexedDB token) için tek
  //    gerçek yoldur; API-login sonucundan BAĞIMSIZ çalışır.
  attempts++; bump(host);
  const r = await tryFormLogin(host, creds).catch(() => null);
  if (r) {
    if (r.formFound) sawEndpoint = true;   // login formu render oldu -> endpoint var (creds yanlışsa bad_credentials)
    if (r.twoFactor) sawTwoFactor = true;
    if (r.session) return { ok: true, session: r.session, attempts };
  }

  if (sawTwoFactor) return { ok: false, reason: 'two_factor', attempts };
  if (!sawEndpoint) return { ok: false, reason: 'no_login_endpoint', attempts };
  return { ok: false, reason: 'bad_credentials', attempts };
}

// --- SESSION_CACHE (host başına TEK login; 7+ kontrol paylaşır) ---------------
const SESSION_CACHE = new Map<string, { at: number; p: Promise<AuthResult> }>();
export function getAuthSession(host: string, creds: TestCredentialInput): Promise<AuthResult> {
  const c = SESSION_CACHE.get(host);
  if (c && Date.now() - c.at < SESSION_TTL_MS) return c.p;
  const p = login(host, creds);
  SESSION_CACHE.set(host, { at: Date.now(), p });
  return p;
}
export function __resetAuthState(host?: string): void {
  if (host) { SESSION_CACHE.delete(host); loginAttemptsByHost.delete(host); }
  else { SESSION_CACHE.clear(); loginAttemptsByHost.clear(); }
}

/**
 * Sipariş için authenticated oturum al: kimlik bilgisini TÜKET (FAZ A consume+purge) + login.
 * Başarısız → sipariş 'scan_failed' + KREDİ tanımla (nakit iade DEĞİL) + net müşteri e-postası.
 * SESSİZCE unauthenticated'e düşme YOK. (FAZ C'nin authenticated tarama girişinden çağrılacak.)
 */
export async function authenticateOrder(orderId: string): Promise<AuthResult> {
  const order = await prisma.order.findUniqueOrThrow({
    where: { id: orderId },
    include: { domain: { select: { hostname: true } } },
  });
  const creds = await consumeTestCredential(orderId, 'primary');
  if (!creds) {
    // Kimlik bilgisi yok (tüketilmiş/purge edilmiş/hiç saklanmamış) — 'credentials-missing' ayrı sebep.
    await failOrder(order.id, order.customerId, order.amountMinorUnit, false, 'no_login_endpoint');
    return { ok: false, reason: 'no_login_endpoint', attempts: 0 };
  }
  const result = await getAuthSession(order.domain.hostname, creds);
  if (!result.ok) {
    await failOrder(order.id, order.customerId, order.amountMinorUnit, result.reason === 'two_factor', result.reason);
  }
  return result;
}

async function failOrder(orderId: string, customerId: string, amountMinorUnit: number, twoFactor: boolean, reason: string): Promise<void> {
  // (İŞ 2) Kredi YOK. Sipariş scan_failed + sebep (admin görünürlüğü) + net müşteri e-postası.
  // İade gerekiyorsa Vedat admin panelinden görüp iyzico'dan MANUEL yapar.
  await prisma.order.update({ where: { id: orderId }, data: { status: 'scan_failed', failureReason: `auth_login_failed:${reason}` } });
  await sendAuthLoginFailed(orderId, twoFactor).catch(() => {});
  console.log(`[authLogin] Sipariş ${orderId} login başarısız (reason=${reason}) → scan_failed (kredi yok; gerekirse manuel iade).`);
}
