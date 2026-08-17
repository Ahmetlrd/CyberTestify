/**
 * (Tam Kapsamlı Pentest — FAZ C) DETERMİNİSTİK AUTHENTICATED KONTROLLER (ajansız).
 *
 * FAZ B'de backend'in aldığı OTURUMU (AuthSession — şifre değil) kullanarak, login-arkası bağlamda
 * GERÇEKTEN yeni değer katan kontroller. HEPSİ GET-only/gözlemsel; state-değiştiren istek YOK. Tüm
 * ağ probları mevcut ProbeCtx devre kesici + MIN_DELAY + prob tavanına tabidir.
 *
 *   A) Oturum çerezi bayrakları (Secure/HttpOnly/SameSite)   — login yanıtı Set-Cookie analizi
 *   B) Session fixation (login öncesi/sonrası session id)    — 1 unauth GET + karşılaştırma
 *   C) Logout / oturum geçersizleştirme                       — GET logout + token hâlâ geçerli mi
 *   D) Forced browsing / eksik fonksiyon-seviye yetki         — admin-benzeri yollara GET (düşük yetkili oturum)
 *
 * (E — authenticated injection/XSS/IDOR — ayrı: mevcut collectInjection/collectIdor motoru session ile.)
 */
import { createHash } from 'node:crypto';
import { cachedOriginUrl } from './surfaceEvidence.js';
import { ProbeCtx, type ActiveCheckEvidence, type VFinding } from './activeVerifyEvidence.js';
import { type AuthSession, applyAuthHeaders } from './authSession.js';
import { isSessionCookieName, isAnalyticsCookie } from './cookieClassify.js';

const md5 = (s: string) => createHash('md5').update(s).digest('hex');
const LOGIN_PAGE_RE = /(login|sign\s?in|giriş yap|oturum aç|password|şifre|kullanıcı adı|unauthorized|forbidden|access denied)/i;

function abs(host: string, p: string): string | null {
  try { const u = new URL(p, `${cachedOriginUrl(host)}/`); return u.hostname.toLowerCase() === host.toLowerCase() ? u.toString() : null; } catch { return null; }
}

// ======================================================================================
// A) Oturum çerezi bayrakları — login yanıtındaki Set-Cookie'lerin güvenlik bayrakları (ağ yok).
// ======================================================================================
export function collectCookieFlagsEvidence(session: AuthSession): ActiveCheckEvidence {
  const findings: VFinding[] = [];
  const notes: string[] = [];
  const flags = session.cookieFlags ?? [];
  // (SÜTUN 0 — ÇEREZ SINIFLAMA) YALNIZ gerçek SUNUCU oturum çerezleri değerlendirilir. Client-side
  // analitik çerezler (_ga/_gid/_fbp/_clck …) "oturum çerezi" DEĞİLdir ve HttpOnly bunlarda
  // imkânsızdır → asla "HttpOnly eksik" bulgusu üretilmez. ESKİ HATA: gerçek oturum çerezi
  // yoksa TÜM çerezlere düşülüp analitikler "Oturum çerezi HttpOnly eksik" diye işaretleniyordu.
  const sessionCookies = flags.filter((f) => isSessionCookieName(f.name));
  const analyticsSeen = flags.filter((f) => isAnalyticsCookie(f.name)).length;
  for (const f of sessionCookies) {
    const missing: string[] = [];
    if (!f.secure) missing.push('Secure');
    if (!f.httpOnly) missing.push('HttpOnly');
    if (!f.sameSite || /none/i.test(f.sameSite)) missing.push('SameSite (Strict/Lax)');
    if (missing.length) {
      findings.push({
        check: 'cookie_flags', inputPoint: `cookie:${f.name}`, vulnerable: true,
        technique: 'oturum çerezi güvenlik bayrağı analizi',
        evidence: `Oturum çerezi \`${f.name}\` şu güvenlik bayraklarından yoksun: ${missing.join(', ')}. (HttpOnly yoksa XSS ile çalınabilir; Secure yoksa düz HTTP'de sızabilir; SameSite yoksa CSRF riski.)`,
        confidence: 'high', severity: missing.includes('HttpOnly') ? 'medium' : 'low', sideEffectRisk: 'none',
      });
    }
  }
  if (!sessionCookies.length) {
    notes.push(
      analyticsSeen
        ? `Sunucu-taraflı oturum çerezi gözlemlenmedi; oturum bearer/token ile taşınıyor. Gözlenen ${analyticsSeen} çerez analitik/3rd-party (client-side JS) çerezidir — bunlar oturum çerezi değildir ve HttpOnly değerlendirmesine tabi tutulamaz. Oturum çerezi güvenlik bayrağı analizi bu hedef için **kapsam dışıdır**.`
        : 'Sunucu-taraflı oturum çerezi gözlemlenmedi (oturum bearer/token ile taşınıyor) — Set-Cookie güvenlik bayrağı analizi bu hedef için **kapsam dışıdır**.',
    );
  }
  return { ok: true, pagesScanned: 1, inputsFound: sessionCookies.length, probesSent: 0, findings, stopped: null, notes };
}

// ======================================================================================
// B) Session fixation — login ÖNCESİ session id, login SONRASI ile AYNI mı? (tek unauth GET)
// ======================================================================================
export async function collectSessionFixationEvidence(host: string, session: AuthSession): Promise<ActiveCheckEvidence> {
  const notes: string[] = [];
  const findings: VFinding[] = [];
  const postCookies = (session.cookie ?? '').split(';').map((s) => s.trim()).filter(Boolean);
  const postAuth = postCookies.map((c) => ({ name: c.split('=')[0], value: c.split('=').slice(1).join('=') })).filter((c) => isSessionCookieName(c.name));
  if (!postAuth.length) {
    notes.push('Oturum çerez-tabanlı değil (bearer/token) — session fixation (çerez yenileme) analizi bu hedef için **kapsam dışıdır**.');
    return { ok: true, pagesScanned: 1, inputsFound: 0, probesSent: 0, findings, stopped: null, notes };
  }
  // Login ÖNCESİ (unauth) ana sayfa GET — Set-Cookie session id yakala.
  let probes = 0;
  const preValues = new Map<string, string>();
  try {
    const ctrl = new AbortController(); const t = setTimeout(() => ctrl.abort(), 10_000);
    const res = await fetch(`${cachedOriginUrl(host)}/`, { signal: ctrl.signal, redirect: 'manual', headers: { 'user-agent': 'CyberTestify-ActiveVerify/1.0' } });
    clearTimeout(t); probes++;
    for (const line of ((res.headers as any).getSetCookie?.() ?? []) as string[]) {
      const nv = line.split(';')[0]; const name = nv.split('=')[0].trim();
      if (isSessionCookieName(name)) preValues.set(name, nv.split('=').slice(1).join('='));
    }
  } catch { /* ağ hatası -> aşağıda kapsam dışı */ }
  const compared = postAuth.filter((c) => preValues.has(c.name));
  if (!compared.length) {
    notes.push('Login öncesi eşleşen bir oturum çerezi gözlemlenemedi (sunucu login öncesi session çerezi vermiyor olabilir) — kesin fixation kanıtı için manuel test önerilir.');
    return { ok: true, pagesScanned: 1, inputsFound: postAuth.length, probesSent: probes, findings, stopped: null, notes };
  }
  for (const c of compared) {
    if (preValues.get(c.name) === c.value) {
      findings.push({
        check: 'session_fixation', inputPoint: `cookie:${c.name}`, vulnerable: true,
        technique: 'login öncesi/sonrası session id karşılaştırması',
        evidence: `\`${c.name}\` oturum çerezi login SONRASINDA da login ÖNCESİYLE AYNI değerde kaldı — sunucu girişte oturumu yenilemiyor (session fixation göstergesi).`,
        confidence: 'medium', severity: 'medium', sideEffectRisk: 'none',
      });
    }
  }
  return { ok: true, pagesScanned: 1, inputsFound: compared.length, probesSent: probes, findings, stopped: null, notes };
}

// ======================================================================================
// C) Logout / oturum geçersizleştirme — GET logout, sonra AYNI token korumalı kaynağa erişebiliyor mu?
// ======================================================================================
const WHOAMI_PATHS = ['/rest/user/whoami', '/api/whoami', '/api/me', '/me', '/api/account', '/api/user', '/api/users/me', '/rest/user/authentication-details', '/api/profile', '/account'];
const LOGOUT_PATHS = ['/rest/user/logout', '/logout', '/api/logout', '/api/auth/logout', '/signout', '/api/signout', '/users/sign_out'];

// Bir yanıtın "authenticated kaynak" (login sayfası/401/403 DEĞİL) olup olmadığı — kaba işaret.
function looksAuthed(status: number, text: string): boolean {
  if (status === 401 || status === 403) return false;
  if (status < 200 || status >= 400) return false;
  const head = text.slice(0, 1500);
  return !/unauthorized|forbidden|access denied|please log ?in|invalid token|jwt (expired|malformed)/i.test(head);
}

export async function collectLogoutEvidence(host: string, session: AuthSession): Promise<ActiveCheckEvidence> {
  const notes: string[] = [];
  const findings: VFinding[] = [];
  const ctx = new ProbeCtx();
  ctx.authHeaders = applyAuthHeaders({}, session);

  // (SÜTUN 0 — ENDPOINT PROVENANCE + SPA CATCH-ALL) Ana sayfa (shell) hash'i: WHOAMI_PATHS TAHMİN
  // listesidir. Bir yol SPA catch-all 200'ü (gövde = index.html shell, ayırt edici DEĞİL) dönüyorsa
  // o "gerçek endpoint" DEĞİLdir → bulguya KAYNAK olamaz. Böylece bu hedefte OLMAYAN bir uç noktaya
  // (ör. eğitim-verisi /rest/user/whoami) atıfta bulunan uydurma "logout geçersizleştirme" bulgusu üretilmez.
  const home = await ctx.fetchOnce(`${cachedOriginUrl(host)}/`);
  const shellHash = home && home.status === 200 ? md5(home.text) : '';
  const isDistinctiveAuthed = (r: { status: number; text: string } | null): boolean => {
    if (!r || !looksAuthed(r.status, r.text)) return false;
    const body = r.text ?? '';
    const isJson = /^\s*[[{]/.test(body.trim());
    const isShell = !!shellHash && md5(body) === shellHash; // SPA shell -> gerçekte gözlemlenen uç değil
    const isLoginish = LOGIN_PAGE_RE.test(body.slice(0, 800)) && !isJson;
    return !isShell && !isLoginish; // yalnız bu hedefte GERÇEKTEN ayırt edici yanıt veren uç
  };

  // 1) auth'la 200 dönen, AYIRT EDİCİ (SPA shell olmayan) bir korumalı uç bul (whoami-benzeri)
  let protectedUrl: string | null = null;
  for (const p of WHOAMI_PATHS) {
    if (ctx.stopped) break;
    const u = abs(host, p); if (!u) continue;
    const r = await ctx.fetchOnce(u);
    if (isDistinctiveAuthed(r)) { protectedUrl = u; break; }
  }
  if (!protectedUrl) {
    if (ctx.stopped) notes.push(ctx.stopped);
    notes.push('Oturumla 200 dönen, AYIRT EDİCİ (SPA catch-all shell olmayan) bir korumalı doğrulama uç noktası (whoami/profil) bu hedefte gözlemlenmedi — logout geçersizleştirme testi bu hedef için **kapsam dışıdır**.');
    return { ok: true, pagesScanned: 1, inputsFound: 0, probesSent: ctx.sent, findings, stopped: ctx.stopped, notes };
  }

  // 2) GET-only logout uç noktası bul + çağır (POST YOK)
  let logoutCalled = false;
  for (const p of LOGOUT_PATHS) {
    if (ctx.stopped) break;
    const u = abs(host, p); if (!u) continue;
    const r = await ctx.fetchOnce(u); // GET
    if (r && r.status > 0 && r.status < 500 && r.status !== 404) { logoutCalled = true; break; }
  }
  if (!logoutCalled) {
    if (ctx.stopped) notes.push(ctx.stopped);
    notes.push('Sunucu-taraflı (GET ile çağrılabilen) bir logout uç noktası bulunamadı — token istemci-tarafında geçersizleştiriliyor olabilir; sunucu-taraflı geçersizleştirme testi **kapsam dışıdır**.');
    return { ok: true, pagesScanned: 1, inputsFound: 1, probesSent: ctx.sent, findings, stopped: ctx.stopped, notes };
  }

  // 3) logout SONRASI aynı token ile korumalı kaynağa TEKRAR eriş — hâlâ AYIRT EDİCİ 200 ise bulgu
  const after = await ctx.fetchOnce(protectedUrl);
  if (isDistinctiveAuthed(after)) {
    findings.push({
      check: 'logout_invalidation', inputPoint: new URL(protectedUrl).pathname, vulnerable: true,
      technique: 'logout sonrası token yeniden kullanımı',
      evidence: `Logout çağrıldıktan SONRA da AYNI oturum token'ıyla korumalı uç (${new URL(protectedUrl).pathname}) 200 döndürdü — oturum sunucu tarafında geçersizleştirilmiyor.`,
      confidence: 'medium', severity: 'medium', sideEffectRisk: 'none',
    });
  }
  if (ctx.stopped) notes.push(ctx.stopped);
  return { ok: true, pagesScanned: 1, inputsFound: 1, probesSent: ctx.sent, findings, stopped: ctx.stopped, notes };
}

// ======================================================================================
// D) Forced browsing — admin-benzeri yollara ELDEKİ (düşük yetkili) oturumla GET.
// SPA yanlış-pozitifi önlemek için: yalnız ana-sayfa shell'inden FARKLI içerik/JSON dönen 200'ler.
// ======================================================================================
const ADMIN_PATHS = [
  '/api/admin', '/rest/admin', '/rest/admin/application-configuration', '/api/admin/users',
  '/api/Users', '/rest/products/reviews', '/metrics', '/actuator', '/actuator/env',
  '/admin/api', '/api/management', '/console', '/api/config', '/rest/admin/application-version',
];
export async function collectForcedBrowsingEvidence(host: string, session: AuthSession): Promise<ActiveCheckEvidence> {
  const notes: string[] = [];
  const findings: VFinding[] = [];
  const ctx = new ProbeCtx();
  ctx.authHeaders = applyAuthHeaders({}, session);

  // Ana sayfa (shell) hash'i — SPA'nın her rotaya döndüğü aynı HTML'i "bulgu" saymamak için.
  const home = await ctx.fetchOnce(`${cachedOriginUrl(host)}/`);
  const shellHash = home && home.status === 200 ? md5(home.text) : '';
  let tested = 0;
  for (const p of ADMIN_PATHS) {
    if (ctx.stopped) break;
    const u = abs(host, p); if (!u) continue;
    const r = await ctx.fetchOnce(u);
    if (!r) continue;
    tested++;
    if (r.status !== 200) continue;                       // 401/403/404 -> temiz
    const isJson = /^\s*[[{]/.test(r.text.trim());
    const isShell = shellHash && md5(r.text) === shellHash; // SPA shell -> gerçek erişim değil
    const isLoginRedirect = LOGIN_PAGE_RE.test(r.text.slice(0, 800)) && !isJson;
    if (isShell || isLoginRedirect) continue;
    if (isJson || r.len > 0) {
      findings.push({
        check: 'forced_browsing', inputPoint: new URL(u).pathname, vulnerable: true,
        technique: 'düşük yetkili oturumla forced browsing (GET)',
        evidence: `\`${new URL(u).pathname}\` uç noktası, düşük yetkili test hesabının oturumuyla **200** ve ${isJson ? 'JSON veri' : 'içerik'} döndürdü — eksik fonksiyon-seviye yetkilendirme (olası yetkisiz yönetim erişimi) göstergesi (dönen veri raporda gösterilmez).`,
        confidence: isJson ? 'medium' : 'low', severity: 'medium', sideEffectRisk: 'none',
      });
    }
  }
  if (ctx.stopped) notes.push(ctx.stopped);
  if (!tested) notes.push('Test edilebilir bir admin-benzeri uç noktası denenemedi.');
  return { ok: true, pagesScanned: 1, inputsFound: tested, probesSent: ctx.sent, findings, stopped: ctx.stopped, notes };
}
