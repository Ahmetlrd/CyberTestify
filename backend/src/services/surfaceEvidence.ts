/**
 * (Dış Yüzey & Yapılandırma) ORTAK KOD-TABANLI KANIT TOPLAMA — ajana GUVENMEZ.
 *
 * bundle_surface uyeleri (ssl_tls, header_leak, dns_email, cors_cookie, csp_analiz) icin
 * veriyi BACKEND KENDISI toplar (basit_tarama ile ayni kanitlanmis yaklasim): HTTP guvenlik
 * basliklari + Set-Cookie + CSP + CORS (Origin ile probe) + TLS sertifikasi/protokol/cipher +
 * DNS/e-posta (SPF/DKIM/DMARC/DNSSEC — Cloudflare DoH ile) + acikta kalan hassas dosyalar.
 * Rapor metnini KOD yazar; ajan ciktisina hic bakilmaz -> formattan bagimsiz, her zaman tutarli.
 *
 * Her kontrol ASLA throw ETMEZ (izole); ulasilamayan veri "tespit edilemedi" olur.
 */
import tls from 'node:tls';
import { createHash } from 'node:crypto';
import { classifyExposedFile } from './passiveExtras.js';
import { logScanStep } from './scanLogger.js';

const HTTP_TIMEOUT_MS = 9000;
const TLS_TIMEOUT_MS = 8000;
const DOH_TIMEOUT_MS = 8000;
const MAX_HTML = 1_500_000;

// Kayitli/apex alan adi — cok-parcali TLS'ler icin sade heuristik (co.uk vb. kabaca desteklenir).
const TWO_LEVEL_TLDS = new Set(['co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'com.tr', 'org.tr', 'net.tr', 'gov.tr', 'com.au', 'co.nz', 'co.jp']);
export function apexDomain(host: string): string {
  const p = host.toLowerCase().replace(/\.$/, '').split('.');
  if (p.length <= 2) return p.join('.');
  const lastTwo = p.slice(-2).join('.');
  if (TWO_LEVEL_TLDS.has(lastTwo)) return p.slice(-3).join('.');
  return lastTwo;
}

// ---- PROTOKOL ÇÖZÜMLEME: hedef HTTPS'e mi HTTP'ye mi yanıt veriyor? (https→http fallback) -----
// Bir hedef yalnız http:// ile açılıyorsa (443 kapalı/yanıtsız), tüm HTTP-tabanlı kontroller
// http:// üzerinden çalışmalı. Ayrıca HTTPS'in HİÇ olmaması KENDİ BAŞINA bir bulgudur (https_eksik).
// httpsWorks = 443'te TLS el sıkışması KURULDU mu (SERTİFİKA GEÇERLİLİĞİNDEN bağımsız; geçersiz
//   sertifika HTTPS'i "yok" saymaz — o ayrı bir bulgu). reachable = en az bir şema yanıt verdi.
export type TargetOrigin = { origin: string; scheme: 'https' | 'http' | null; httpsWorks: boolean; httpWorks: boolean; reachable: boolean };
const originCache = new Map<string, TargetOrigin>();

function tlsPortOpen(host: string): Promise<boolean> {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v: boolean) => { if (!done) { done = true; resolve(v); } };
    try {
      const s = tls.connect({ host, port: 443, servername: host, rejectUnauthorized: false, timeout: TLS_TIMEOUT_MS }, () => { s.destroy(); finish(true); });
      s.on('error', () => finish(false));
      s.on('timeout', () => { s.destroy(); finish(false); });
    } catch { finish(false); }
  });
}

async function httpResponds(host: string): Promise<boolean> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), HTTP_TIMEOUT_MS);
  try {
    await fetch(`http://${host}/`, { signal: ctrl.signal, redirect: 'manual', headers: { 'user-agent': 'CyberTestify-PassiveCheck/1.0' } });
    return true; // herhangi bir HTTP yanıtı (3xx/4xx/5xx dahil) = http açık
  } catch { return false; } finally { clearTimeout(timer); }
}

// SENKRON origin erişimi: resolveOrigin cache'inde varsa çözülen origin'i, YOKSA https://host'a
// düşer. Böylece https-hedeflerde davranış AYNEN korunur (https default); yalnız resolveOrigin
// önceden çağrılmış (cache sıcak) http-only hedeflerde http:// döner. Kullanmadan önce ilgili
// collector'da collectHttp/resolveOrigin çağrılmış olmalı (URL kurulmadan cache'i ısıtır).
export function cachedOriginUrl(host: string): string {
  return originCache.get(host)?.origin ?? `https://${host}`;
}

// Hedefin çalışan şemasını (https tercihli) çözer. Cache'li (aynı rapor içinde birçok kez çağrılır).
export async function resolveOrigin(host: string): Promise<TargetOrigin> {
  const cached = originCache.get(host);
  if (cached) return cached;
  const httpsWorks = await tlsPortOpen(host);
  let result: TargetOrigin;
  if (httpsWorks) {
    result = { origin: `https://${host}`, scheme: 'https', httpsWorks: true, httpWorks: false, reachable: true };
  } else {
    const httpWorks = await httpResponds(host);
    result = httpWorks
      ? { origin: `http://${host}`, scheme: 'http', httpsWorks: false, httpWorks: true, reachable: true }
      : { origin: `https://${host}`, scheme: null, httpsWorks: false, httpWorks: false, reachable: false };
  }
  originCache.set(host, result);
  logScanStep({ step: 'Protokol çözümleme', url: host, level: result.reachable ? 'info' : 'warn', summary: `scheme=${result.scheme ?? 'yok'} httpsWorks=${result.httpsWorks} reachable=${result.reachable}` });
  return result;
}

// ---- HTTP: basliklar + Set-Cookie + HTML ------------------------------------------
export type HttpEvidence = {
  ok: boolean;
  status?: number;
  headers: Map<string, string>; // lowercased
  setCookies: string[];         // ham Set-Cookie satirlari
  html: string;
  contentType: string;
  scheme: 'https' | 'http' | null; // hangi protokolle çekildi
  httpsWorks: boolean;             // 443 açık mı (false + reachable => https_eksik bulgusu)
  reachable: boolean;              // hedefe hiç ulaşıldı mı (false => "İncelenemedi", ASLA "temiz")
};

export async function collectHttp(host: string): Promise<HttpEvidence> {
  const headers = new Map<string, string>();
  const o = await resolveOrigin(host);
  const base: Pick<HttpEvidence, 'scheme' | 'httpsWorks' | 'reachable'> = { scheme: o.scheme, httpsWorks: o.httpsWorks, reachable: o.reachable };
  if (!o.reachable) { logScanStep({ step: 'Ana sayfa (HTTP)', method: 'GET', url: `${o.origin}/`, status: 0, level: 'warn', summary: 'Hedefe ulaşılamadı (reachable=false)' }); return { ok: false, headers, setCookies: [], html: '', contentType: '', ...base }; }
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), HTTP_TIMEOUT_MS);
  const _t0 = Date.now();
  try {
    const res = await fetch(`${o.origin}/`, {
      signal: ctrl.signal,
      redirect: 'follow',
      headers: { 'user-agent': 'CyberTestify-PassiveCheck/1.0', accept: 'text/html,*/*' },
    });
    res.headers.forEach((v, k) => headers.set(k.toLowerCase(), v));
    let setCookies: string[] = [];
    try {
      const gsc = (res.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie;
      if (typeof gsc === 'function') setCookies = gsc.call(res.headers);
      else if (headers.has('set-cookie')) setCookies = [headers.get('set-cookie')!];
    } catch { /* yoksa bos */ }
    let html = '';
    try {
      const buf = Buffer.from(await res.arrayBuffer());
      html = (buf.length > MAX_HTML ? buf.subarray(0, MAX_HTML) : buf).toString('utf-8');
    } catch { /* govde okunamadi */ }
    logScanStep({ step: 'Ana sayfa (HTTP)', method: 'GET', url: `${o.origin}/`, status: res.status, durationMs: Date.now() - _t0, sizeBytes: html.length, summary: `başlıklar alındı (${headers.size}); Set-Cookie: ${setCookies.length}` });
    return { ok: true, status: res.status, headers, setCookies, html, contentType: headers.get('content-type') ?? '', ...base };
  } catch (err) {
    logScanStep({ step: 'Ana sayfa (HTTP)', method: 'GET', url: `${o.origin}/`, status: 0, durationMs: Date.now() - _t0, level: 'error', summary: `İstek hatası: ${String((err as Error)?.name ?? 'err')}` });
    return { ok: false, headers, setCookies: [], html: '', contentType: '', ...base };
  } finally {
    clearTimeout(timer);
  }
}

// ============================================================================
// (BÖLÜM 1 — ÇOK SAYFA KAPSAMI) Pasif paketlerin KENDİ kontrollerini ana sayfa DIŞINDA da
// çalıştırabilmesi için paylaşılan sayfa toplayıcı. YALNIZ GET; sayfa üst sınırı + istekler-arası
// bekleme + devre kesici (art arda 5xx). Her sayfanın BAŞLIK + gövdesi + Set-Cookie'si döner.
// Hiçbir prob/payload GÖNDERMEZ — sadece keşfedilen sayfaları çeker (pasif). Aktif Doğrulama'nın
// prob/payload'ıyla KARIŞTIRILMAZ (paket farklılaşması korunur — bu yalnız GET-çekme).
// ============================================================================
export type PageEvidence = { url: string; status: number; headers: Map<string, string>; html: string; setCookies: string[] };
const PAGES_MAX = 15;            // toplanacak benzersiz sayfa üst sınırı (sonsuz büyüme YOK)
const PAGES_MIN_DELAY_MS = 250;  // istekler arası bekleme (hedefe nazik)
const PAGE_ASSET_RE = /\.(css|js|mjs|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|pdf|zip|rar|mp4|webm|webp|avif|json|xml|txt)(\?|$)/i;

async function fetchPage(url: string): Promise<PageEvidence | null> {
  const headers = new Map<string, string>();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), HTTP_TIMEOUT_MS);
  const t0 = Date.now();
  try {
    const res = await fetch(url, { signal: ctrl.signal, redirect: 'follow', headers: { 'user-agent': 'CyberTestify-PassiveCheck/1.0', accept: 'text/html,*/*' } });
    res.headers.forEach((v, k) => headers.set(k.toLowerCase(), v));
    let setCookies: string[] = [];
    try {
      const gsc = (res.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie;
      if (typeof gsc === 'function') setCookies = gsc.call(res.headers);
      else if (headers.has('set-cookie')) setCookies = [headers.get('set-cookie')!];
    } catch { /* yoksa boş */ }
    let html = '';
    try { const buf = Buffer.from(await res.arrayBuffer()); html = (buf.length > MAX_HTML ? buf.subarray(0, MAX_HTML) : buf).toString('utf-8'); } catch { /* gövde okunamadı */ }
    logScanStep({ step: 'Çok-sayfa kapsam', method: 'GET', url, status: res.status, durationMs: Date.now() - t0, sizeBytes: html.length, level: res.status >= 500 ? 'warn' : 'info' });
    return { url, status: res.status, headers, html, setCookies };
  } catch (err) {
    logScanStep({ step: 'Çok-sayfa kapsam', method: 'GET', url, status: 0, durationMs: Date.now() - t0, level: 'error', summary: `İstek hatası: ${String((err as Error)?.name ?? 'err')}` });
    return null;
  } finally {
    clearTimeout(timer);
  }
}

// (IN-FLIGHT CACHE) Aynı host için eş zamanlı 5 dış-yüzey alanı + basit TEK crawl paylaşır (hedefe
// 5 kez değil 1 kez GET seli gider). Kısa TTL — tek tarama penceresi. Test hook ile temizlenir.
const PAGES_CACHE = new Map<string, { at: number; p: Promise<PageEvidence[]> }>();
const PAGES_TTL_MS = 120_000;
export function __clearPagesCache(host?: string): void { if (host) PAGES_CACHE.delete(host); else PAGES_CACHE.clear(); }

// Ana sayfa + keşfedilen iç linkler (aynı host, asset/fragment hariç) — en fazla maxPages benzersiz
// içerikli sayfa. Devre kesici: art arda 3+ 5xx -> durur. Ana sayfaya erişilemezse boş döner.
export function collectPages(host: string, maxPages = PAGES_MAX): Promise<PageEvidence[]> {
  const cached = PAGES_CACHE.get(host);
  if (cached && Date.now() - cached.at < PAGES_TTL_MS) return cached.p;
  const p = collectPagesUncached(host, maxPages);
  PAGES_CACHE.set(host, { at: Date.now(), p });
  return p;
}
async function collectPagesUncached(host: string, maxPages = PAGES_MAX): Promise<PageEvidence[]> {
  const o = await resolveOrigin(host);
  if (!o.reachable) return [];
  const homeUrl = `${o.origin}/`;
  const home = await fetchPage(homeUrl);
  if (!home || home.status === 0) return [];
  const pages: PageEvidence[] = [home];
  const md5 = (s: string) => createHash('md5').update(s).digest('hex');
  const seenHash = new Set<string>([md5(home.html)]);
  const seenUrl = new Set<string>([homeUrl]);
  // ana sayfadan iç link keşfi
  const targets: string[] = [];
  const hostBare = host.replace(/^www\./, '');
  for (const m of home.html.matchAll(/href\s*=\s*["']([^"'#]+)["']/gi)) {
    if (targets.length >= maxPages * 3) break;
    let abs: string;
    try { abs = m[1].startsWith('http') ? m[1] : new URL(m[1].replace(/&amp;/g, '&'), homeUrl).toString(); } catch { continue; }
    try {
      const u = new URL(abs);
      if (u.hostname.replace(/^www\./, '') !== hostBare) continue; // yalnız aynı host
      if (PAGE_ASSET_RE.test(u.pathname)) continue;
      const norm = `${u.origin}${u.pathname}${u.search}`;
      if (!seenUrl.has(norm)) { seenUrl.add(norm); targets.push(norm); }
    } catch { /* atla */ }
  }
  let consec5xx = 0;
  for (const t of targets) {
    if (pages.length >= maxPages) break;
    await new Promise((r) => setTimeout(r, PAGES_MIN_DELAY_MS)); // rate-limit (nazik)
    const p = await fetchPage(t);
    if (!p) continue;
    if (p.status >= 500) { consec5xx++; if (consec5xx >= 3) { logScanStep({ step: 'Çok-sayfa kapsam', level: 'circuit_breaker', summary: 'Art arda 3+ 5xx — çok-sayfa toplama durduruldu.' }); break; } }
    else consec5xx = 0;
    if (p.status !== 200 || !p.html) continue;
    const h = md5(p.html);
    if (seenHash.has(h)) continue; // aynı içerik (SPA shell / kopya) -> benzersiz sayma
    seenHash.add(h);
    pages.push(p);
  }
  return pages;
}

// ---- CORS: Origin ile probe -------------------------------------------------------
export type CorsEvidence = { ok: boolean; testedOrigin: string; acao?: string; acac?: string; reflected: boolean; wildcard: boolean };
const CORS_PROBE_ORIGIN = 'https://cybertestify-cors-probe.example';

export async function collectCors(host: string): Promise<CorsEvidence> {
  const o = await resolveOrigin(host);
  if (!o.reachable) return { ok: false, testedOrigin: CORS_PROBE_ORIGIN, reflected: false, wildcard: false };
  return collectCorsForUrl(`${o.origin}/`);
}

// (BÖLÜM 1 — SAYFA-BAZLI CORS) Belirli bir URL'e zararsız bir Origin başlığıyla GET atıp CORS
// yanıt başlıklarını okur (payload YOK — yalnız Origin request-header'ı; pasif). Farklı path'ler
// (ör. /api/) farklı CORS politikasına sahip olabilir; bu, sayfa-bazlı değerlendirmeyi sağlar.
export async function collectCorsForUrl(url: string): Promise<CorsEvidence> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), HTTP_TIMEOUT_MS);
  const t0 = Date.now();
  try {
    const res = await fetch(url, { signal: ctrl.signal, redirect: 'manual', headers: { 'user-agent': 'CyberTestify-PassiveCheck/1.0', origin: CORS_PROBE_ORIGIN } });
    const acao = res.headers.get('access-control-allow-origin') ?? undefined;
    const acac = res.headers.get('access-control-allow-credentials') ?? undefined;
    logScanStep({ step: 'CORS kontrolü', method: 'GET', url, status: res.status, durationMs: Date.now() - t0, summary: `ACAO=${acao ?? 'yok'} ACAC=${acac ?? 'yok'}` });
    return { ok: true, testedOrigin: CORS_PROBE_ORIGIN, acao, acac, reflected: acao === CORS_PROBE_ORIGIN, wildcard: acao === '*' };
  } catch {
    return { ok: false, testedOrigin: CORS_PROBE_ORIGIN, reflected: false, wildcard: false };
  } finally {
    clearTimeout(timer);
  }
}

// ---- TLS: sertifika + protokol + cipher + zayif surum tespiti ----------------------
export type TlsEvidence = {
  found: boolean;
  cn?: string;
  san: string[];
  issuer?: string;
  notAfter?: string;
  daysLeft?: number;
  protocol?: string;
  cipher?: string;
  hostnameMatch?: boolean;
  weakProtocols: string[]; // desteklenen eski surumler (TLSv1, TLSv1.1)
};

function hostMatches(host: string, cn: string | undefined, san: string[]): boolean {
  const names = [cn, ...san].filter(Boolean) as string[];
  const h = host.toLowerCase();
  return names.some((n) => {
    const name = n.toLowerCase().trim();
    if (name === h) return true;
    if (name.startsWith('*.')) {
      const base = name.slice(2);
      const hp = h.split('.');
      return hp.length >= 2 && hp.slice(1).join('.') === base;
    }
    return false;
  });
}

function tlsHandshake(host: string, opts: tls.ConnectionOptions): Promise<tls.TLSSocket | null> {
  return new Promise((resolve) => {
    let done = false;
    const d = (v: tls.TLSSocket | null) => { if (!done) { done = true; resolve(v); } };
    try {
      const s = tls.connect({ host, port: 443, servername: host, rejectUnauthorized: false, timeout: TLS_TIMEOUT_MS, ...opts }, () => d(s));
      s.on('error', () => d(null));
      s.on('timeout', () => { s.destroy(); d(null); });
    } catch { d(null); }
  });
}

async function probeVersion(host: string, version: 'TLSv1' | 'TLSv1.1'): Promise<boolean> {
  try {
    const s = await tlsHandshake(host, { minVersion: version, maxVersion: version });
    if (s) { s.end(); return true; }
    return false;
  } catch {
    return false; // surum yerelde devre disi ise "desteklenmiyor/bilinmiyor" -> weak sayma
  }
}

export async function collectTls(host: string): Promise<TlsEvidence> {
  const s = await tlsHandshake(host, {});
  if (!s) return { found: false, san: [], weakProtocols: [] };
  const cert = s.getPeerCertificate();
  const protocol = s.getProtocol() ?? undefined;
  const cipher = s.getCipher()?.name;
  const cn = (cert?.subject as { CN?: string } | undefined)?.CN;
  const san = (cert?.subjectaltname ?? '').split(',').map((x) => x.trim().replace(/^DNS:/i, '')).filter(Boolean);
  const iss = cert?.issuer as { O?: string; CN?: string } | undefined;
  const issuer = [iss?.O, iss?.CN].filter(Boolean).join(' — ') || undefined;
  const notAfter = cert?.valid_to;
  let daysLeft: number | undefined;
  if (notAfter) {
    const exp = new Date(notAfter);
    if (!isNaN(exp.getTime())) daysLeft = Math.round((exp.getTime() - Date.now()) / 86400000);
  }
  const hostnameMatch = cn || san.length ? hostMatches(host, cn, san) : undefined;
  s.end();
  // Zayif surum probe'lari (paralel).
  const [v10, v11] = await Promise.all([probeVersion(host, 'TLSv1'), probeVersion(host, 'TLSv1.1')]);
  const weakProtocols = [v10 ? 'TLS 1.0' : '', v11 ? 'TLS 1.1' : ''].filter(Boolean);
  return { found: !!(cn || notAfter), cn, san, issuer, notAfter, daysLeft, protocol, cipher, hostnameMatch, weakProtocols };
}

// ---- DNS / e-posta: Cloudflare DoH -------------------------------------------------
export type DnsEvidence = {
  ok: boolean;
  // queried=false: DNS SORGUSU BAŞARISIZ/timeout oldu -> "kayıt yok" DEĞİL, "sorgulanamadı" (Yüksek risk üretMEZ).
  spf?: { record: string; all: '-all' | '~all' | '+all' | '?all' | 'yok'; queried: boolean };
  dmarc?: { record: string; policy: 'none' | 'quarantine' | 'reject' | 'yok'; queried: boolean };
  dkim?: { found: boolean; selector?: string };
  dnssec?: boolean;
  mxCount: number;
  checkedDomain: string; // SPF/DMARC'ın bakıldığı ad (org/apex) — rapor tutarlılığı için
};

// DoH endpoint'leri — Cloudflare + Google (ikisi de application/dns-json). Biri timeout/hata verirse
// digerine geç; geçici DNS hatasinin "kayit yok" gibi raporlanmasini onler (İŞ 2).
const DOH_ENDPOINTS = [
  (n: string, t: string) => `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(n)}&type=${t}`,
  (n: string, t: string) => `https://dns.google/resolve?name=${encodeURIComponent(n)}&type=${t}`,
];
const dohSleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function dohFetchOnce(url: string): Promise<{ answers: string[]; ad: boolean } | null> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), DOH_TIMEOUT_MS);
  try {
    const res = await fetch(url, { signal: ctrl.signal, headers: { accept: 'application/dns-json' } });
    if (!res.ok) return null;
    const j = (await res.json()) as { AD?: boolean; Answer?: Array<{ data?: string }> };
    const answers = (j.Answer ?? []).map((a) => String(a.data ?? '').replace(/^"|"$/g, '').replace(/"\s+"/g, ''));
    return { answers, ad: !!j.AD };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

// Retry + çoklu resolver. Hepsi başarısızsa null (= SORGULANAMADI, "kayıt yok" DEĞİL — çağıran ayırır).
async function doh(name: string, type: string): Promise<{ answers: string[]; ad: boolean } | null> {
  for (let attempt = 0; attempt < 2; attempt++) {
    for (const ep of DOH_ENDPOINTS) {
      const r = await dohFetchOnce(ep(name, type));
      if (r) return r;
    }
    if (attempt === 0) await dohSleep(250);
  }
  return null;
}

const DKIM_SELECTORS = ['default', 'google', 'selector1', 'selector2', 'k1', 'mail', 's1', 'dkim'];

export async function collectDns(host: string): Promise<DnsEvidence> {
  const apex = apexDomain(host);
  const [txt, dmarcTxt, dnskey, mx] = await Promise.all([
    doh(apex, 'TXT'),
    doh(`_dmarc.${apex}`, 'TXT'),
    doh(apex, 'DNSKEY'),
    doh(apex, 'MX'),
  ]);
  if (!txt && !dmarcTxt && !dnskey && !mx) return { ok: false, mxCount: 0, checkedDomain: apex };

  // SPF — txt===null ise SORGU BAŞARISIZ (queried:false); değilse yanıt içinde SPF ara.
  let spf: DnsEvidence['spf'];
  const spfRec = txt ? txt.answers.find((a) => /^v=spf1/i.test(a.trim())) : undefined;
  if (spfRec) {
    const all = /[-]all/i.test(spfRec) ? '-all' : /~all/i.test(spfRec) ? '~all' : /\+all/i.test(spfRec) ? '+all' : /\?all/i.test(spfRec) ? '?all' : 'yok';
    spf = { record: spfRec.trim().slice(0, 300), all, queried: true };
  } else {
    spf = { record: '', all: 'yok', queried: txt !== null }; // txt===null -> sorgulanamadı
  }

  // DMARC — aynı mantık: dmarcTxt===null ise sorgu başarısız.
  let dmarc: DnsEvidence['dmarc'];
  const dmarcRec = dmarcTxt ? dmarcTxt.answers.find((a) => /v=DMARC1/i.test(a)) : undefined;
  if (dmarcRec) {
    const p = dmarcRec.match(/\bp\s*=\s*(none|quarantine|reject)/i)?.[1]?.toLowerCase() as 'none' | 'quarantine' | 'reject' | undefined;
    dmarc = { record: dmarcRec.trim().slice(0, 300), policy: p ?? 'none', queried: true };
  } else {
    dmarc = { record: '', policy: 'yok', queried: dmarcTxt !== null };
  }

  // DKIM (yaygin selector'lari dene)
  let dkim: DnsEvidence['dkim'] = { found: false };
  for (const sel of DKIM_SELECTORS) {
    const r = await doh(`${sel}._domainkey.${apex}`, 'TXT');
    if (r && r.answers.some((a) => /v=DKIM1|(^|;)\s*p\s*=/i.test(a))) { dkim = { found: true, selector: sel }; break; }
  }

  // DNSSEC: DNSKEY kaydi VEYA herhangi bir cevabin AD (authenticated data) bayragi
  const dnssec = !!(dnskey?.answers.length) || !!txt?.ad || !!dmarcTxt?.ad || !!dnskey?.ad;

  const mxCount = (mx?.answers ?? []).length;
  return { ok: true, spf, dmarc, dkim, dnssec, mxCount, checkedDomain: apex };
}

// ---- Acikta kalan hassas dosyalar (header_leak) -----------------------------------
export type ExposedFileResult = { path: string; exposed: boolean; reason: string };
const EXPOSED_CANDIDATES = ['/.git/config', '/.env', '/.git/HEAD', '/backup.zip', '/.DS_Store', '/wp-config.php.bak',
  // (İŞ 1) /ftp (Juice Shop) + yaygın hassas dizin/dosyalar. classifyExposedFile GERÇEK içerik/dizin
  // listesi ister (SPA catch-all 200 -> "kapalı"; yanlış-pozitif yok).
  '/ftp', '/backup', '/backups', '/uploads', '/files', '/admin', '/.svn/entries', '/.htaccess', '/config.php.bak', '/db.sql', '/dump.sql'];

async function safeGetForExpose(url: string): Promise<{ ok: boolean; status: number; text: string; contentType: string }> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), HTTP_TIMEOUT_MS);
  try {
    const res = await fetch(url, { signal: ctrl.signal, redirect: 'follow', headers: { 'user-agent': 'CyberTestify-PassiveCheck/1.0' } });
    const buf = Buffer.from(await res.arrayBuffer());
    const text = (buf.length > 20000 ? buf.subarray(0, 20000) : buf).toString('utf-8');
    return { ok: res.ok, status: res.status, text, contentType: res.headers.get('content-type') ?? '' };
  } catch {
    return { ok: false, status: 0, text: '', contentType: '' };
  } finally {
    clearTimeout(timer);
  }
}

export async function collectExposedFiles(host: string, homepageHtml: string, de: boolean = false): Promise<ExposedFileResult[]> {
  const out: ExposedFileResult[] = [];
  const o = await resolveOrigin(host);
  if (!o.reachable) return out; // hedefe ulaşılamadı -> "kontrol yapılamadı" (boş; ASLA "hepsi kapalı/temiz" değil)
  for (const path of EXPOSED_CANDIDATES) {
    const fetched = await safeGetForExpose(`${o.origin}${path}`);
    const { verdict, reason } = classifyExposedFile(path, fetched, homepageHtml, de);
    out.push({ path, exposed: verdict === 'exposed', reason });
  }
  return out;
}
