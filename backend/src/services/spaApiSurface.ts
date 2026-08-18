/**
 * (Faz 7 — Seviye 1, headless YOK) SPA YÜZEY KEŞFİ: JS bundle string literallerinden GERÇEK API uçları
 * çıkarır, read-only doğrular ve mevcut yüzeye (discoverSurface) BESLER. Yeni BULGU üretmez — yalnız YÜZEY.
 * Hem Aktif Doğrulama hem Tam Kapsamlı yararlanır.
 *
 * SÜTUN 0 (en kritik): yalnız BU hedefin KENDİ bundle'ında LİTERAL geçen uçlar. Tahmin/başka-hedef
 * (Juice Shop /rest, vulnweb) UYDURMA YOK. ENDPOINT VARLIĞI ZAFİYET DEĞİLDİR. SPA-catch-all shell
 * (md5==home) elenir. 3P/CDN/analitik host'lar yüzeye eklenmez. Firebase apiKey bulgu DEĞİL (public);
 * Firestore/RTDB REST fuzz'lanmaz; ama Cloud Functions (*.cloudfunctions.net) test-edilebilir yüzeydir.
 * READ-ONLY (GET); deterministik.
 */
import { createHash } from 'node:crypto';
import { fetchClientCorpus } from './jsAnalysis.js';
import { cachedOriginUrl } from './surfaceEvidence.js';
import { applyAuthHeaders, type AuthSession } from './authSession.js';
import { logScanStep } from './scanLogger.js';
import type { InputPoint } from './activeVerifyEvidence.js';

export type SpaApiDiscovery = { candidates: number; validated: number; shellEliminated: number; endpoints: string[] };

const REQ_TIMEOUT = 9_000;
const MIN_DELAY = 180;
let lastAt = 0;
const md5 = (s: string) => createHash('md5').update(s).digest('hex');

// API-işaretli aynı-origin yol literalleri (router-view'ları ELE: yalnız açık API markerleri).
const API_PATH_RE = /["'`](\/(?:api|rest|graphql|internal|backend|service|gateway|functions)\/[\w/.\-]*|\/v[0-9]+\/[\w/.\-]*)["'`]/gi;
const ABS_URL_RE = /["'`](https?:\/\/[\w.\-]+(?:\:\d+)?\/[\w/.\-]*)["'`]/gi;
// 3P/CDN/analitik/asset host'ları — hedefin API'si DEĞİL, yüzeye eklenmez.
const THIRD_PARTY_HOST_RE = /(google-analytics|googletagmanager|doubleclick|gstatic|fonts\.google|firebasestorage|firestore\.googleapis|firebaseio|identitytoolkit|securetoken|googleapis\.com|facebook|fbcdn|jsdelivr|unpkg|cdnjs|cloudflare|bootstrapcdn|sentry|hotjar|segment|mixpanel|amplitude|intercom|stripe|recaptcha|cookiebot|hcaptcha)\./i;
const ASSET_RE = /\.(js|css|png|jpe?g|svg|gif|webp|ico|woff2?|ttf|map|mp4|webm|pdf)(\?|$)/i;

type Cand = { url: string; path: string; isCloudFn: boolean };

export function mineSpaEndpoints(corpusText: string, host: string, origin: string): Cand[] {
  const out = new Map<string, Cand>();
  const add = (url: string, path: string, isCloudFn: boolean) => { if (!out.has(url) && out.size < 24) out.set(url, { url, path, isCloudFn }); };
  // (a) aynı-origin API-işaretli yollar
  for (const m of corpusText.matchAll(API_PATH_RE)) {
    let p = m[1];
    if (/[{}]|:[a-zA-Z]|\$\{|\*|\s/.test(p)) continue;          // template/dinamik → çözülemez, atla
    p = p.replace(/[#].*$/, '');
    if (ASSET_RE.test(p.split('?')[0]) || p.length > 120) continue;
    try { const u = new URL(p.split('?')[0], `${origin}/`); if (u.hostname.toLowerCase() !== host.toLowerCase()) continue; add(u.toString(), p, false); } catch { /* atla */ }
  }
  // (b) mutlak URL'ler: yalnız aynı-host VEYA *.cloudfunctions.net (ilan edilen backend)
  for (const m of corpusText.matchAll(ABS_URL_RE)) {
    const raw = m[1];
    let u: URL; try { u = new URL(raw); } catch { continue; }
    const h = u.hostname.toLowerCase();
    if (ASSET_RE.test(u.pathname)) continue;
    const isCloudFn = /\.cloudfunctions\.net$/i.test(h) || /\.run\.app$/i.test(h);
    if (h === host.toLowerCase()) { if (/\/(api|rest|graphql|v[0-9]+|functions)\//i.test(u.pathname)) add(`${u.origin}${u.pathname}`.split('?')[0], u.pathname, false); continue; }
    if (isCloudFn) { add(`${u.origin}${u.pathname}`.split('?')[0], u.pathname, true); continue; }
    // diğer tüm host'lar (3P/analitik/Firestore/CDN) → yüzeye EKLENMEZ
  }
  return [...out.values()];
}

async function probe(url: string, headers: Record<string, string>): Promise<{ status: number; text: string; ct: string } | null> {
  const w = MIN_DELAY - (Date.now() - lastAt); if (w > 0) await new Promise((r) => setTimeout(r, w));
  lastAt = Date.now();
  const ctrl = new AbortController(); const t = setTimeout(() => ctrl.abort(), REQ_TIMEOUT); const t0 = Date.now();
  try {
    const res = await fetch(url, { redirect: 'manual', signal: ctrl.signal, headers: { 'user-agent': 'CyberTestify-SPA/1.0', accept: 'application/json,*/*', ...headers } });
    const buf = Buffer.from(await res.arrayBuffer());
    const text = buf.subarray(0, 100_000).toString('utf-8');
    logScanStep({ step: 'SPA Yüzey Keşfi', method: 'GET', url, status: res.status, durationMs: Date.now() - t0, sizeBytes: buf.length });
    return { status: res.status, text, ct: res.headers.get('content-type') ?? '' };
  } catch { logScanStep({ step: 'SPA Yüzey Keşfi', method: 'GET', url, status: 0, level: 'warn', durationMs: Date.now() - t0 }); return null; }
  finally { clearTimeout(t); }
}

const isJson = (ct: string, text: string) => /json/i.test(ct) || /^\s*[[{]/.test(text.trim());
const isHtmlShell = (text: string) => /^\s*<(!doctype|html)/i.test(text.trim());

/** JS bundle'dan API uçlarını çıkar + read-only doğrula. Doğrulanan uçlar {inputs, apiReads} + istatistik. */
export async function discoverSpaApiSurface(host: string, session?: AuthSession): Promise<{ inputs: InputPoint[]; apiReads: string[]; stats: SpaApiDiscovery }> {
  const empty = { inputs: [], apiReads: [], stats: { candidates: 0, validated: 0, shellEliminated: 0, endpoints: [] } };
  const corpus = await fetchClientCorpus(host).catch(() => null);
  if (!corpus || !corpus.reachable) return empty;
  const origin = cachedOriginUrl(host);
  const shellHash = md5(corpus.homeHtml);
  const text = corpus.homeHtml + '\n' + corpus.sameOriginJs.map((f) => f.body).join('\n') + '\n' + corpus.inlineScripts.join('\n');
  const cands = mineSpaEndpoints(text, host, origin).filter((c) => !THIRD_PARTY_HOST_RE.test(c.url));
  if (cands.length === 0) return { ...empty, stats: { candidates: 0, validated: 0, shellEliminated: 0, endpoints: [] } };

  const authHeaders = session ? applyAuthHeaders({}, session) : {};
  const inputs: InputPoint[] = []; const apiReads: string[] = []; const endpoints: string[] = [];
  let validated = 0; let shellEliminated = 0;
  for (const c of cands.slice(0, 16)) {
    const r = await probe(c.url, authHeaders as Record<string, string>);
    if (!r) continue;
    if (r.status >= 500) continue;
    if (r.text && md5(r.text) === shellHash) { shellEliminated++; continue; } // SPA catch-all shell → gerçek uç değil
    if (isHtmlShell(r.text)) { shellEliminated++; continue; }
    // Gerçek API: JSON döndü VEYA auth-kapılı (401/403/405) non-HTML yanıt (uç var ama korumalı = geçerli yüzey)
    const authGated = [401, 403, 405].includes(r.status) && !isHtmlShell(r.text);
    if (!isJson(r.ct, r.text) && !authGated) continue;
    validated++;
    let u: URL; try { u = new URL(c.url); } catch { continue; }
    endpoints.push(u.pathname);
    // Literal'de query param varsa InputPoint; yoksa apiReads (parametresiz yüzey)
    const rawParams: Record<string, string> = {};
    u.searchParams.forEach((v, k) => { rawParams[k] = v || '1'; });
    const paramKeys = Object.keys(rawParams);
    if (paramKeys.length) for (const k of paramKeys) inputs.push({ method: 'GET', action: `${u.origin}${u.pathname}`, param: k, params: { ...rawParams }, source: 'url' });
    else apiReads.push(`GET ${u.pathname}`);
  }
  return { inputs, apiReads, stats: { candidates: cands.length, validated, shellEliminated, endpoints: endpoints.slice(0, 20) } };
}
