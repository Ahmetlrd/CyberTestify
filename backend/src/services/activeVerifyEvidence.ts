/**
 * (Aktif Doğrulama — injection_verify + idor_verify) KOD-TABANLI AKTIF PROB MOTORU.
 *
 * "Kanıtla, istismar etme" ilkesi KOD SEVIYESINDE: backend hedefe SINIRLI, zararsiz probe'lar
 * gonderip yalnizca VARLIK KANITI toplar (veri cekmez, yazmaz, silmez). PentAGI ajani HIC calismaz
 * (bundle_surface deseni) — Turkce rapor metnini activeVerifyReports.ts yazar.
 *
 * GUVENLIK (hedefi koru — E maddesi):
 *  - Input noktasi basina az sayida probe; istekler arasi min gecikme (DoS'lamamak icin).
 *  - Devre kesici: art arda 3+ 5xx -> DUR; yanit suresi baseline'in 3 katini asarsa -> DUR
 *    (zaman-tabanli SQLi probe'u HARIC — orada gecikme zaten beklenen kanit); 429/WAF-blok -> DUR.
 *  - Yalniz hedef host; harici host'a ASLA istek yok; redirect izlenmez.
 *  - SQLi: yalniz tek-tirnak (hata imzasi) + tek zaman-tabanli dogrulama. Veri cekme YOK.
 *  - XSS: yalniz benzersiz zararsiz isaret; JS calistirma YOK, stored XSS denenmez.
 *  - IDOR: yalniz GET; komsu ID; DONEN VERI SAKLANMAZ (sadece uzunluk/hash/durum karsilastirilir).
 */
import { randomBytes, createHash } from 'node:crypto';
import puppeteer from 'puppeteer-core';
import { collectHttp } from './surfaceEvidence.js';

// Headless render (SPA keşfi) — PDF üretimiyle AYNI sistem Chromium'unu kullanır (ek kurulum yok).
const CHROMIUM_PATH = process.env.PUPPETEER_EXECUTABLE_PATH || '/usr/bin/chromium-browser';
const HEADLESS_PAGE_TIMEOUT_MS = 10000;   // sayfa basina sert timeout
const HEADLESS_MAX_PAGES = 8;             // headless'te taranacak sayfa ust siniri (perf)
const MAX_CONCURRENT_HEADLESS = 3;        // es zamanli tarayici instance ust siniri (kaynak korumasi)

const MIN_DELAY_MS = 1200;         // istekler arasi min bekleme (hedefi yormamak)
const REQ_TIMEOUT_MS = 10000;
const MAX_INPUTS = 6;              // taranacak input noktasi ust siniri
const SLOW_FACTOR = 3;             // baseline * 3'u asan yanit -> devre kesici (zaman-tabanli haric)
const SLOW_FLOOR_MS = 2500;        // baseline cok kucukse gurultuden kacinmak icin taban
const TIME_PROBE_DELAY_S = 3;      // zaman-tabanli SQLi gecikme saniyesi

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// ---- Probe motoru + devre kesici ---------------------------------------------------
type ProbeResult = { status: number; ms: number; text: string; len: number };
class ProbeCtx {
  baseline = 0;
  consec5xx = 0;
  stopped: string | null = null;
  sent = 0;
  private last = 0;
  async fetchOnce(url: string, opts: { method?: 'GET' | 'POST'; body?: string; contentType?: string; expectSlow?: boolean } = {}): Promise<ProbeResult | null> {
    if (this.stopped) return null;
    const wait = MIN_DELAY_MS - (Date.now() - this.last);
    if (wait > 0) await sleep(wait);
    this.last = Date.now();
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), REQ_TIMEOUT_MS);
    const t0 = Date.now();
    try {
      const headers: Record<string, string> = { 'user-agent': 'CyberTestify-ActiveVerify/1.0', accept: 'text/html,*/*' };
      if (opts.contentType) headers['content-type'] = opts.contentType;
      const res = await fetch(url, { method: opts.method ?? 'GET', body: opts.body, headers, redirect: 'manual', signal: ctrl.signal });
      const ms = Date.now() - t0;
      this.sent++;
      const buf = Buffer.from(await res.arrayBuffer());
      const text = (buf.length > 200_000 ? buf.subarray(0, 200_000) : buf).toString('utf-8');
      // --- Devre kesici degerlendirmesi ---
      if (res.status >= 500) { this.consec5xx++; if (this.consec5xx >= 3) this.stopped = 'Hedef art arda 3+ kez 5xx döndürdü (hedefe zarar veriyor olabiliriz — otomatik durduruldu).'; }
      else this.consec5xx = 0;
      if (res.status === 429) this.stopped = 'Hedef 429 (hız sınırı) döndürdü — otomatik durduruldu.';
      if (res.status === 403 && /cloudflare|access denied|request blocked|web application firewall|mod_security|incapsula|sucuri|forbidden/i.test(text)) this.stopped = 'WAF/güvenlik duvarı bloğu (403) algılandı — bu kontrol durduruldu.';
      if (!opts.expectSlow && this.baseline > 0 && ms > SLOW_FACTOR * this.baseline && ms > SLOW_FLOOR_MS) this.stopped = `Yanıt süresi baseline'ın ${SLOW_FACTOR} katını aştı (hedef yavaşlıyor — otomatik durduruldu).`;
      return { status: res.status, ms, text, len: buf.length };
    } catch {
      this.sent++;
      return { status: 0, ms: Date.now() - t0, text: '', len: 0 };
    } finally {
      clearTimeout(timer);
    }
  }
}

// ---- Ortak: hedef host + baseline + input kesfi -----------------------------------
function sameHost(u: string, host: string): boolean {
  try { const p = new URL(u); return p.hostname.toLowerCase() === host.toLowerCase(); } catch { return false; }
}
function absUrl(raw: string, host: string): string | null {
  try {
    const u = raw.startsWith('http') ? new URL(raw) : new URL(raw, `https://${host}/`);
    return sameHost(u.toString(), host) ? u.toString() : null;
  } catch { return null; }
}

export type InputPoint = { method: 'GET' | 'POST'; action: string; param: string; params: Record<string, string>; source: 'url' | 'form' };

// HTML'den (ve ana sayfa URL'sinden) GET query param + form alanlarini kesfet (deterministik).
function discoverInputs(host: string, html: string): InputPoint[] {
  const out: InputPoint[] = [];
  const seen = new Set<string>();
  const push = (ip: InputPoint) => { const k = `${ip.method} ${ip.action} ${ip.param}`; if (!seen.has(k)) { seen.add(k); out.push(ip); } };

  // 1) Linklerdeki query param'lar (href="...?a=1&b=2") — asset (png/webp/js/css vb.) linkleri HARIC.
  for (const m of html.matchAll(/href\s*=\s*["']([^"']*\?[^"']+)["']/gi)) {
    const abs = absUrl(m[1].replace(/&amp;/g, '&'), host);
    if (!abs) continue;
    try {
      const u = new URL(abs);
      if (CRAWL_ASSET_RE.test(u.pathname)) continue; // logo.png?v=1 gibi asset cache-buster'lari test noktasi degil
      const params: Record<string, string> = {};
      u.searchParams.forEach((v, k) => { params[k] = v; });
      for (const p of Object.keys(params)) push({ method: 'GET', action: `${u.origin}${u.pathname}`, param: p, params: { ...params }, source: 'url' });
    } catch { /* atla */ }
  }

  // 2) Form'lar (<form action method> + <input/textarea name>)
  for (const fm of html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)) {
    const attrs = fm[1];
    const inner = fm[2];
    const method = (/method\s*=\s*["']?\s*post/i.test(attrs) ? 'POST' : 'GET') as 'GET' | 'POST';
    const actionRaw = attrs.match(/action\s*=\s*["']([^"']*)["']/i)?.[1] ?? '/';
    const action = absUrl(actionRaw || '/', host);
    if (!action) continue;
    const params: Record<string, string> = {};
    for (const im of inner.matchAll(/<(?:input|textarea|select)\b[^>]*\bname\s*=\s*["']([^"']+)["'][^>]*>/gi)) {
      const name = im[1];
      if (/^(csrf|_token|authenticity_token|captcha)/i.test(name)) continue; // token alanlarini deneme
      params[name] = 'test';
    }
    for (const p of Object.keys(params)) push({ method, action, param: p, params: { ...params }, source: 'form' });
  }
  return out.slice(0, MAX_INPUTS);
}

// GET query string kur (probe deger enjekte edilerek)
function buildGetUrl(ip: InputPoint, injectValue: string): string {
  const u = new URL(ip.action);
  for (const [k, v] of Object.entries(ip.params)) u.searchParams.set(k, k === ip.param ? injectValue : (v || '1'));
  return u.toString();
}
function buildFormBody(ip: InputPoint, injectValue: string): string {
  const usp = new URLSearchParams();
  for (const [k, v] of Object.entries(ip.params)) usp.set(k, k === ip.param ? injectValue : (v || 'test'));
  return usp.toString();
}

// ======================================================================================
// ORTAK KESIF (depth-1 hafif crawl) — homepage-only'den daha genis kapsam.
// Ana sayfa + ayni host'taki ic linkler + kucuk "iyi bilinen path/param" listesi taranir;
// bulunan TUM input noktalari/ID uc noktalari/formlar birlestirilir. Devre kesici + MIN_DELAY
// + toplam sayfa ust siniri (sinirsiz crawl YOK). 7 kontrol AYNI crawl'i paylasir (in-flight
// cache) — hedefe 7 kez degil, TEK kez crawl istegi gider. Bu YALNIZ kapsami buyutur; hicbir
// istek hedefin durumunu/verisini degistirmez (GET keşif).
// ======================================================================================
const CRAWL_MAX_PAGES = 10;        // homepage + ~9 ic sayfa (link havuzundan)
const CRAWL_HARD_CAP = 16;         // toplam sayfa (link + iyi-bilinen path) mutlak ust siniri
const CRAWL_ASSET_RE = /\.(css|js|mjs|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|pdf|zip|rar|mp4|webm|webp|avif|json|xml|txt)(\?|$)/i;
const WELL_KNOWN_PATHS = ['/search?q=cybertestify', '/contact', '/login', '/register', '/api/', '/products?id=1', '/urun?id=1', '/?id=1'];

export type Surface = {
  ok: boolean;
  method: 'static' | 'headless'; // kesif yontemi (ham HTML mi, JS-render mi)
  pagesScanned: number;       // BENZERSIZ icerikli sayfa sayisi (ayni SPA shell tekrar sayilmaz)
  urlsFetched: number;        // toplam cekilen URL (dedup oncesi)
  jsRendered: boolean;        // hedef JS ile render ediliyor gorunuyor (ham HTML'de link/form yok)
  homeHtml: string;
  homeHeaders: Map<string, string>;
  inputs: InputPoint[];
  idEndpoints: Array<{ url: string; idParam: string; idValue: number; kind: 'query' | 'path' }>;
  uploadForms: Array<{ action: string; fileField: string; otherFields: string[] }>;
  massAssignForm: { action: string; fields: string[] } | null;
};

async function crawlSurface(host: string): Promise<Surface> {
  const empty: Surface = { ok: false, method: 'static', pagesScanned: 0, urlsFetched: 0, jsRendered: false, homeHtml: '', homeHeaders: new Map(), inputs: [], idEndpoints: [], uploadForms: [], massAssignForm: null };
  const home = await collectHttp(host);
  if (!home.ok) return empty;

  // Ana sayfadaki ayni-host ic linkleri topla (asset/harici/fragment HARIC).
  const homeUrl = `https://${host}/`;
  const linkSet = new Set<string>();
  for (const m of home.html.matchAll(/href\s*=\s*["']([^"'#]+)["']/gi)) {
    const abs = absUrl(m[1].replace(/&amp;/g, '&'), host);
    if (!abs) continue;
    try {
      const u = new URL(abs);
      if (CRAWL_ASSET_RE.test(u.pathname)) continue;
      const norm = `${u.origin}${u.pathname}${u.search}`;
      if (norm !== homeUrl) linkSet.add(norm);
    } catch { /* atla */ }
  }
  const targets: string[] = [...linkSet].slice(0, CRAWL_MAX_PAGES - 1);
  for (const p of WELL_KNOWN_PATHS) { const a = absUrl(p, host); if (a && a !== homeUrl && !targets.includes(a)) targets.push(a); }

  // JS-RENDER (SPA) tespiti: ham HTML'de <a href>/<form> yok/az + script agirlikli + tipik kok div.
  const anchors = (home.html.match(/<a\s[^>]*href\s*=/gi) ?? []).length;
  const formCount = (home.html.match(/<form\b/gi) ?? []).length;
  const scriptCount = (home.html.match(/<script\b/gi) ?? []).length;
  const spaShell = /<div[^>]+(id|class)\s*=\s*["'](root|app|__next|__nuxt|q-app)\b|__NEXT_DATA__|window\.__NUXT__|ng-version=/i.test(home.html);
  const jsRendered = (anchors <= 2 && formCount === 0) && (scriptCount >= 1) && (spaShell || home.html.length < 30000);

  // Sayfalari cek — AYNI icerikli (hash) sayfayi tekrar SAYMA (SPA catch-all tek shell dondurur).
  const ctx = new ProbeCtx();
  const md5 = (s: string) => createHash('md5').update(s).digest('hex');
  const seenUrl = new Set<string>([homeUrl]);
  const seenHash = new Set<string>([md5(home.html)]);
  let urlsFetched = 1;
  const pages: Array<{ url: string; html: string }> = [{ url: homeUrl, html: home.html }];
  for (const t of targets) {
    if (ctx.stopped || urlsFetched >= CRAWL_HARD_CAP) break;
    if (seenUrl.has(t)) continue;
    seenUrl.add(t);
    const r = await ctx.fetchOnce(t);
    urlsFetched++;
    if (r && r.status === 200 && r.text.length > 0) {
      const h = md5(r.text);
      if (seenHash.has(h)) continue; // ayni SPA shell / duplike icerik -> benzersiz sayma
      seenHash.add(h);
      pages.push({ url: t, html: r.text });
    }
  }

  // Tum sayfalardan input/ID/form kesiflerini birlestir (dedup).
  const inputs: InputPoint[] = []; const seenIn = new Set<string>();
  const idEndpoints: Surface['idEndpoints'] = []; const seenId = new Set<string>();
  const uploadForms: Surface['uploadForms'] = []; const seenUp = new Set<string>();
  let massAssignForm: Surface['massAssignForm'] = null;
  for (const pg of pages) {
    for (const ip of discoverInputs(host, pg.html)) { const k = `${ip.method} ${ip.action} ${ip.param}`; if (!seenIn.has(k)) { seenIn.add(k); inputs.push(ip); } }
    for (const e of discoverIdEndpoints(host, pg.html)) { const k = `${e.kind}:${e.idParam}:${(() => { try { const u = new URL(e.url); return u.origin + u.pathname; } catch { return e.url; } })()}`; if (!seenId.has(k)) { seenId.add(k); idEndpoints.push(e); } }
    for (const f of discoverUploadForms(host, pg.html)) { const k = `${f.action}:${f.fileField}`; if (!seenUp.has(k)) { seenUp.add(k); uploadForms.push(f); } }
    if (!massAssignForm) massAssignForm = discoverMassAssignForm(host, pg.html);
  }
  return { ok: true, method: 'static', pagesScanned: pages.length, urlsFetched, jsRendered, homeHtml: home.html, homeHeaders: home.headers, inputs, idEndpoints, uploadForms, massAssignForm };
}

// ======================================================================================
// HEADLESS (JS-render) KESIF — SPA siteleri icin. PDF ile AYNI sistem Chromium'u; SADECE
// render edilmis DOM'dan link/form/input TOPLAR — form doldurma/submit/tiklama/etkilesim YOK.
// Es zamanli tarayici sayisi semafor ile sinirli; sayfa basina sert timeout; kaynak blocklama.
// ======================================================================================
let headlessActive = 0;
const headlessQueue: Array<() => void> = [];
async function acquireHeadless(): Promise<void> {
  if (headlessActive < MAX_CONCURRENT_HEADLESS) { headlessActive++; return; }
  await new Promise<void>((res) => headlessQueue.push(res)); // slot serbest kalinca devral (sayac release'te korunur)
}
function releaseHeadless(): void {
  const next = headlessQueue.shift();
  if (next) next(); // slot bir sonraki bekleyene devredilir (sayac AYNI kalir)
  else headlessActive--;
}
let chromiumUnavailable = false; // bir kez basarisiz olursa tekrar deneme (perf)

async function crawlHeadless(host: string): Promise<Surface | null> {
  if (chromiumUnavailable) return null;
  const homeUrl = `https://${host}/`;
  await acquireHeadless();
  let browser: Awaited<ReturnType<typeof puppeteer.launch>> | null = null;
  try {
    browser = await puppeteer.launch({ executablePath: CHROMIUM_PATH, headless: true, args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'] });
  } catch {
    chromiumUnavailable = true; // Chromium yok/baslatilamadi -> statik'e dus
    releaseHeadless();
    return null;
  }
  try {
    const pages: Array<{ url: string; html: string }> = [];
    const seenUrl = new Set<string>();
    const seenHash = new Set<string>();
    const md5 = (s: string) => createHash('md5').update(s).digest('hex');
    let consec5xx = 0;
    let stopped = false;

    // Tek sayfayi render edip render-edilmis HTML'i dondur. HARD-GUARD: yalniz ayni host, ic-ag ASLA.
    const renderOne = async (url: string): Promise<string | null> => {
      try { const u = new URL(url); if (u.hostname.toLowerCase() !== host.toLowerCase() || isInternalHost(u.hostname)) return null; } catch { return null; }
      const page = await browser!.newPage();
      try {
        await page.setUserAgent('CyberTestify-ActiveVerify/1.0');
        await page.setRequestInterception(true);
        page.on('request', (req) => {
          const rt = req.resourceType();
          // Perf: gorsel/font/media/stylesheet blokla. Guvenlik: ic-ag isteklerini blokla.
          let block = rt === 'image' || rt === 'font' || rt === 'media' || rt === 'stylesheet';
          try { if (isInternalHost(new URL(req.url()).hostname)) block = true; } catch { /* yoksay */ }
          if (block) req.abort().catch(() => {}); else req.continue().catch(() => {});
        });
        const resp = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: HEADLESS_PAGE_TIMEOUT_MS });
        const st = resp?.status() ?? 0;
        if (st >= 500) { consec5xx++; if (consec5xx >= 3) stopped = true; } else consec5xx = 0;
        if (st === 429) stopped = true;
        // JS render'in oturmasi icin kisa bekleme (networkidle; asilirsa yoksay).
        await page.waitForNetworkIdle({ idleTime: 500, timeout: 4000 }).catch(() => {});
        return await page.content();
      } catch { return null; } finally { await page.close().catch(() => {}); }
    };

    // 1) Ana sayfayi render et
    const homeHtml = await renderOne(homeUrl);
    if (!homeHtml) return null;
    seenUrl.add(homeUrl); seenHash.add(md5(homeHtml));
    pages.push({ url: homeUrl, html: homeHtml });

    // 2) Render-edilmis DOM'dan ic linkleri topla (JS ile eklenenler DAHIL)
    const linkSet = new Set<string>();
    for (const m of homeHtml.matchAll(/href\s*=\s*["']([^"'#]+)["']/gi)) {
      const abs = absUrl(m[1].replace(/&amp;/g, '&'), host);
      if (!abs) continue;
      try { const u = new URL(abs); if (CRAWL_ASSET_RE.test(u.pathname)) continue; const norm = `${u.origin}${u.pathname}${u.search}`; if (norm !== homeUrl) linkSet.add(norm); } catch { /* atla */ }
    }
    const targets = [...linkSet].slice(0, HEADLESS_MAX_PAGES - 1);
    for (const p of WELL_KNOWN_PATHS) { const a = absUrl(p, host); if (a && a !== homeUrl && !targets.includes(a)) targets.push(a); }

    // 3) Sayfalari render et (benzersiz icerik + sayfa ust siniri)
    for (const t of targets) {
      if (stopped || pages.length >= HEADLESS_MAX_PAGES || seenUrl.size >= CRAWL_HARD_CAP) break;
      if (seenUrl.has(t)) continue; seenUrl.add(t);
      const html = await renderOne(t);
      if (!html) continue;
      const h = md5(html);
      if (seenHash.has(h)) continue; // ayni shell -> benzersiz sayma
      seenHash.add(h);
      pages.push({ url: t, html });
    }

    // 4) Render-edilmis sayfalardan input/ID/form kesfini birlestir (MEVCUT extractor'lar)
    const inputs: InputPoint[] = []; const seenIn = new Set<string>();
    const idEndpoints: Surface['idEndpoints'] = []; const seenId = new Set<string>();
    const uploadForms: Surface['uploadForms'] = []; const seenUp = new Set<string>();
    let massAssignForm: Surface['massAssignForm'] = null;
    for (const pg of pages) {
      for (const ip of discoverInputs(host, pg.html)) { const k = `${ip.method} ${ip.action} ${ip.param}`; if (!seenIn.has(k)) { seenIn.add(k); inputs.push(ip); } }
      for (const e of discoverIdEndpoints(host, pg.html)) { const k = `${e.kind}:${e.idParam}:${(() => { try { const u = new URL(e.url); return u.origin + u.pathname; } catch { return e.url; } })()}`; if (!seenId.has(k)) { seenId.add(k); idEndpoints.push(e); } }
      for (const f of discoverUploadForms(host, pg.html)) { const k = `${f.action}:${f.fileField}`; if (!seenUp.has(k)) { seenUp.add(k); uploadForms.push(f); } }
      if (!massAssignForm) massAssignForm = discoverMassAssignForm(host, pg.html);
    }
    return { ok: true, method: 'headless', pagesScanned: pages.length, urlsFetched: seenUrl.size, jsRendered: true, homeHtml, homeHeaders: new Map(), inputs, idEndpoints, uploadForms, massAssignForm };
  } catch {
    return null;
  } finally {
    await browser.close().catch(() => {});
    releaseHeadless();
  }
}

// HIBRIT: once hizli statik kesif; SPA supheli + statik input BULAMADIYSA headless'e dus.
async function buildSurface(host: string): Promise<Surface> {
  const stat = await crawlSurface(host);
  const staticSurfaceCount = stat.inputs.length + stat.idEndpoints.length + stat.uploadForms.length + (stat.massAssignForm ? 1 : 0);
  // Statik zaten input buldu -> headless GEREKSIZ (perf). Yalniz SPA supheli + 0 input -> headless.
  if (stat.ok && staticSurfaceCount === 0 && stat.jsRendered) {
    const hl = await crawlHeadless(host).catch(() => null);
    if (hl && hl.ok) return hl; // render sonucu (input bulsa da bulmasa da) — daha guclu kapsam bilgisi
  }
  return stat;
}

// In-flight cache: ayni host icin es zamanli 7 kontrol TEK crawl paylasir.
const SURFACE_CACHE = new Map<string, { at: number; p: Promise<Surface> }>();
const SURFACE_TTL_MS = 120_000;
export function discoverSurface(host: string): Promise<Surface> {
  const c = SURFACE_CACHE.get(host);
  if (c && Date.now() - c.at < SURFACE_TTL_MS) return c.p;
  const p = buildSurface(host).catch(() => ({ ok: false, method: 'static', pagesScanned: 0, urlsFetched: 0, jsRendered: false, homeHtml: '', homeHeaders: new Map(), inputs: [], idEndpoints: [], uploadForms: [], massAssignForm: null } as Surface));
  SURFACE_CACHE.set(host, { at: Date.now(), p });
  return p;
}

// SPA/JS-render uyari notu — giris noktasi bulunamayan taramalarda yaniltici olmamak icin.
// method=headless ise SPA render EDILDI -> "gercekten yok" (daha guclu temiz); method=static+jsRendered
// ise render EDILEMEDI -> "bilmiyoruz" (kapsam sinirli).
export function spaHint(surf: Surface): string {
  if (!surf.jsRendered) return '';
  if (surf.method === 'headless')
    return ' **Not:** Hedef JavaScript ile render edilen (SPA) bir uygulamadır ve bu tarama sayfalar **headless tarayıcı ile render edilerek** yapılmıştır; buna rağmen test edilebilir giriş noktası bulunamaması, render sonrası sayfada gerçekten giriş noktası olmadığını gösterir (ham-HTML sınırlaması değil — daha güçlü bir "temiz" göstergesi; yine de kimlik-doğrulamalı akışlar kapsam dışıdır).';
  return ' **Not:** Hedef büyük olasılıkla JavaScript ile render edilen (SPA) bir uygulamadır; menü/bağlantı ve formlar tarayıcıda oluşturulduğundan ham-HTML taramasında giriş noktaları görünmeyebilir — headless render bu taramada kullanılamadı, bu nedenle kapsam sınırlıdır ve "giriş noktası bulunamadı" güvenlik kanıtı değildir.';
}

// ======================================================================================
// ODEME-ONCESI HIZLI KAPSAM SINYALI — bundle_active_verify icin. SADECE statik (headless YOK),
// ana sayfa + ~3 ic link; kaba bir "test edilecek giris noktasi var mi" sinyali. Ucuz/hizli
// (asil tarama odeme sonrasi headless dahil calisir). Hedefi yormamak icin gecikme YOK ama ~4 GET.
// ======================================================================================
export type ScopeSignal = { reachable: boolean; jsRendered: boolean; inputCount: number; pagesScanned: number; lowSignal: boolean };

async function quickGet(url: string): Promise<string | null> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 8000);
  try {
    const res = await fetch(url, { signal: ctrl.signal, redirect: 'follow', headers: { 'user-agent': 'CyberTestify-PassiveCheck/1.0', accept: 'text/html,*/*' } });
    if (!res.ok) return null;
    const buf = Buffer.from(await res.arrayBuffer());
    return (buf.length > 300_000 ? buf.subarray(0, 300_000) : buf).toString('utf-8');
  } catch { return null; } finally { clearTimeout(timer); }
}

export async function quickScopeSignal(host: string): Promise<ScopeSignal> {
  const home = await collectHttp(host);
  if (!home.ok) return { reachable: false, jsRendered: false, inputCount: 0, pagesScanned: 0, lowSignal: false };
  // SPA sinyali (crawlSurface ile AYNI heuristik)
  const anchors = (home.html.match(/<a\s[^>]*href\s*=/gi) ?? []).length;
  const formCount = (home.html.match(/<form\b/gi) ?? []).length;
  const scriptCount = (home.html.match(/<script\b/gi) ?? []).length;
  const spaShell = /<div[^>]+(id|class)\s*=\s*["'](root|app|__next|__nuxt|q-app)\b|__NEXT_DATA__|window\.__NUXT__|ng-version=/i.test(home.html);
  const jsRendered = (anchors <= 2 && formCount === 0) && (scriptCount >= 1) && (spaShell || home.html.length < 30000);

  // Ana sayfa + en fazla 3 ic link (asset HARIC) — hizli.
  const homeUrl = `https://${host}/`;
  const links: string[] = []; const seenL = new Set<string>([homeUrl]);
  for (const m of home.html.matchAll(/href\s*=\s*["']([^"'#]+)["']/gi)) {
    if (links.length >= 3) break;
    const abs = absUrl(m[1].replace(/&amp;/g, '&'), host);
    if (!abs) continue;
    try { const u = new URL(abs); if (CRAWL_ASSET_RE.test(u.pathname)) continue; const norm = `${u.origin}${u.pathname}${u.search}`; if (!seenL.has(norm)) { seenL.add(norm); links.push(norm); } } catch { /* atla */ }
  }
  const pages: string[] = [home.html];
  for (const l of links) { const html = await quickGet(l); if (html) pages.push(html); }

  const inputs = new Set<string>(); const ids = new Set<string>(); const uploads = new Set<string>(); let mass = false;
  for (const html of pages) {
    for (const ip of discoverInputs(host, html)) inputs.add(`${ip.method} ${ip.action} ${ip.param}`);
    for (const e of discoverIdEndpoints(host, html)) ids.add(`${e.kind}:${e.idParam}`);
    for (const f of discoverUploadForms(host, html)) uploads.add(`${f.action}:${f.fileField}`);
    if (!mass && discoverMassAssignForm(host, html)) mass = true;
  }
  const inputCount = inputs.size + ids.size + uploads.size + (mass ? 1 : 0);
  // Dusuk sinyal: SPA supheli VEYA hic input yok.
  const lowSignal = jsRendered || inputCount === 0;
  return { reachable: true, jsRendered, inputCount, pagesScanned: pages.length, lowSignal };
}

// Kesif yontemi seffaflik notu (rapor icin).
export function discoveryMethodNote(surf: Surface): string {
  return surf.method === 'headless'
    ? 'Bu tarama, JavaScript ile render edilen (SPA) hedef tespit edildiği için sayfalar **headless tarayıcı ile render edilerek** gerçekleştirilmiştir.'
    : 'Standart HTML taraması yeterli kapsam sağladığından JavaScript render (headless) kullanılmadı.';
}

// ======================================================================================
// injection_verify — SQLi (hata + zaman) + XSS (yansima)
// ======================================================================================
const SQL_ERROR_RE = /(SQL syntax|mysql_fetch|mysqli|you have an error in your sql|ORA-\d{4,5}|PLS-\d|PostgreSQL.*ERROR|pg_query|SQLite3?::|SQLSTATE\[|Microsoft OLE DB Provider|ODBC SQL Server|Unclosed quotation mark|quoted string not properly terminated|syntax error at or near|Warning: pg_|Warning: mysql)/i;

export type InjFinding = { inputPoint: string; type: 'SQLi' | 'XSS'; technique: 'error-based' | 'time-based' | 'reflection'; evidence: string; severity: 'high' | 'medium' | 'low'; confidence: 'high' | 'medium' | 'low' };
export type InjEvidence = { ok: boolean; baseUrl: string; pagesScanned: number; inputsFound: number; inputsTested: number; probesSent: number; payloadsSent: number; findings: InjFinding[]; stopped: string | null; notes: string[] };

// Zararsiz, veri-degistirmeyen SQLi HATA-tetikleyici varyantlari (yalniz response'ta hata imzasi arar).
const SQLI_ERROR_PAYLOADS = ["'", '"', "' OR '1'='1"];
// Context-aware zararsiz XSS isaret payload'lari (JS CALISTIRMAZ; yalniz yansima kontrolu).
const XSS_MARKER = 'cxt9137xmark';
const XSS_PAYLOADS = [`${XSS_MARKER}"><cxmark>`, `${XSS_MARKER}'><cxmark>`];
const INJ_MAX_INPUTS = 6;

export async function collectInjectionEvidence(host: string): Promise<InjEvidence> {
  const surf = await discoverSurface(host);
  if (!surf.ok) return { ok: false, baseUrl: `https://${host}/`, pagesScanned: 0, inputsFound: 0, inputsTested: 0, probesSent: 0, payloadsSent: 0, findings: [], stopped: null, notes: ['Hedef ana sayfası çekilemedi (bağlantı kurulamadı).'] };
  const inputs = surf.inputs.slice(0, INJ_MAX_INPUTS);
  const ctx = new ProbeCtx();
  const findings: InjFinding[] = [];
  const notes: string[] = [];
  let tested = 0;
  let payloads = 0;

  const base = await ctx.fetchOnce(`https://${host}/`);
  if (base) ctx.baseline = base.ms;
  const send = async (ip: InputPoint, val: string, expectSlow = false): Promise<ProbeResult | null> =>
    ip.method === 'GET'
      ? ctx.fetchOnce(buildGetUrl(ip, val), { expectSlow })
      : ctx.fetchOnce(ip.action, { method: 'POST', body: buildFormBody(ip, val), contentType: 'application/x-www-form-urlencoded', expectSlow });

  for (const ip of inputs) {
    if (ctx.stopped) break;
    tested++;
    const label = `${ip.method} ${new URL(ip.action).pathname}?${ip.param}`;

    // --- SQLi hata-tabanli: birkac zararsiz varyant; ilk hata imzasinda dur ---
    let sqlErrorFound = false;
    for (const q of SQLI_ERROR_PAYLOADS) {
      if (ctx.stopped || sqlErrorFound) break;
      payloads++;
      const r = await send(ip, q);
      if (r && SQL_ERROR_RE.test(r.text)) {
        sqlErrorFound = true;
        const sig = r.text.match(SQL_ERROR_RE)?.[0] ?? 'SQL hata imzası';
        findings.push({ inputPoint: label, type: 'SQLi', technique: 'error-based', evidence: `Yanıtta veritabanı hata imzası görüldü ("${q}" payload'ı ile): "${sig.slice(0, 60)}"`, severity: 'high', confidence: 'high' });
      }
    }

    // --- XSS yansima: birkac context marker ---
    for (const xp of XSS_PAYLOADS) {
      if (ctx.stopped) break;
      payloads++;
      const xr = await send(ip, xp);
      if (xr && xr.text.includes(xp)) {
        findings.push({ inputPoint: label, type: 'XSS', technique: 'reflection', evidence: 'Zararsız işaret dizesi yanıt HTML’inde KAÇIRILMADAN (unencoded) yansıdı — yansıyan XSS göstergesi.', severity: 'high', confidence: 'high' });
        break;
      } else if (xr && xr.text.includes(XSS_MARKER)) {
        findings.push({ inputPoint: label, type: 'XSS', technique: 'reflection', evidence: 'İşaret dizesi yansıdı ancak kodlanmış/kısmen kaçırılmış görünüyor — bağlama göre risk; manuel doğrulama önerilir.', severity: 'low', confidence: 'low' });
        break;
      }
    }

    // --- SQLi zaman-tabanli (KOSULLU): hata bulunmadiysa blind dogrulama ---
    if (!sqlErrorFound && !ctx.stopped) {
      payloads++;
      const tr = await send(ip, `1' AND SLEEP(${TIME_PROBE_DELAY_S})-- -`, true);
      if (tr && tr.status > 0 && tr.ms >= (ctx.baseline + (TIME_PROBE_DELAY_S * 1000) - 700)) {
        findings.push({ inputPoint: label, type: 'SQLi', technique: 'time-based', evidence: `Zaman-tabanlı probe (SLEEP ${TIME_PROBE_DELAY_S}s) yanıt süresini ~${(tr.ms / 1000).toFixed(1)}s'ye çıkardı (baseline ~${(ctx.baseline / 1000).toFixed(1)}s) — blind SQLi göstergesi.`, severity: 'high', confidence: 'medium' });
      }
    }
  }

  if (ctx.stopped) notes.push(ctx.stopped);
  if (!inputs.length) notes.push(`Taranan ${surf.pagesScanned} benzersiz sayfada test edilebilir GET parametresi veya form alanı bulunamadı (giriş noktası yok).` + spaHint(surf));
  return { ok: true, baseUrl: `https://${host}/`, pagesScanned: surf.pagesScanned, inputsFound: inputs.length, inputsTested: tested, probesSent: ctx.sent, payloadsSent: payloads, findings, stopped: ctx.stopped, notes };
}

// ======================================================================================
// idor_verify — kimlik-dogrulamasiz numaralandirilabilir kaynak (sinirli kapsam)
// ======================================================================================
export type IdorFinding = { endpoint: string; idParam: string; observation: string; differentResource: boolean; severity: 'high' | 'medium' | 'low' };
export type IdorEvidence = { ok: boolean; pagesScanned: number; candidates: number; endpointsTested: number; probesSent: number; findings: IdorFinding[]; stopped: string | null; notes: string[] };
const IDOR_MAX = 8;

// Ana sayfa HTML'inden sayisal/predictable ID iceren URL adaylarini bul.
function discoverIdEndpoints(host: string, html: string): Array<{ url: string; idParam: string; idValue: number; kind: 'query' | 'path' }> {
  const out: Array<{ url: string; idParam: string; idValue: number; kind: 'query' | 'path' }> = [];
  const seen = new Set<string>();
  for (const m of html.matchAll(/href\s*=\s*["']([^"']+)["']/gi)) {
    const abs = absUrl(m[1].replace(/&amp;/g, '&'), host);
    if (!abs) continue;
    try {
      const u = new URL(abs);
      // (a) query'de sayisal id (?id=123, ?user=45, ?p=7)
      for (const [k, v] of u.searchParams.entries()) {
        if (/^\d{1,9}$/.test(v) && /(^id$|_id$|^user|^account|^order|^invoice|^p$|^pid$|^uid$)/i.test(k)) {
          const key = `q:${u.origin}${u.pathname}:${k}`;
          if (!seen.has(key)) { seen.add(key); out.push({ url: u.toString(), idParam: k, idValue: parseInt(v, 10), kind: 'query' }); }
        }
      }
      // (b) path'te sayisal segment (/user/123, /orders/45)
      const pm = u.pathname.match(/^(.*\/)(\d{1,9})(\/?)$/);
      if (pm) {
        const key = `p:${u.origin}${pm[1]}`;
        if (!seen.has(key)) { seen.add(key); out.push({ url: u.toString(), idParam: pm[1].replace(/^.*\/([^/]+)\/$/, '$1') || 'path-id', idValue: parseInt(pm[2], 10), kind: 'path' }); }
      }
    } catch { /* atla */ }
  }
  return out.slice(0, MAX_INPUTS);
}
function withId(url: string, kind: 'query' | 'path', idParam: string, newVal: number): string {
  const u = new URL(url);
  if (kind === 'query') u.searchParams.set(idParam, String(newVal));
  else u.pathname = u.pathname.replace(/(\d{1,9})(\/?)$/, `${newVal}$2`);
  return u.toString();
}
// Genel 404/hata sayfasi mi? (icerik saklamadan, sadece kaba isaret)
function looksLikeNotFound(status: number, text: string): boolean {
  if (status === 404 || status === 403 || status === 401) return true;
  return /not found|bulunamadı|404|access denied|erişim engellendi|oturum aç|login required/i.test(text.slice(0, 2000));
}

export async function collectIdorEvidence(host: string): Promise<IdorEvidence> {
  const surf = await discoverSurface(host);
  if (!surf.ok) return { ok: false, pagesScanned: 0, candidates: 0, endpointsTested: 0, probesSent: 0, findings: [], stopped: null, notes: ['Hedef ana sayfası çekilemedi (bağlantı kurulamadı).'] };
  const eps = surf.idEndpoints.slice(0, IDOR_MAX);
  const ctx = new ProbeCtx();
  const findings: IdorFinding[] = [];
  const notes: string[] = [];
  let tested = 0;

  const base = await ctx.fetchOnce(`https://${host}/`);
  if (base) ctx.baseline = base.ms;

  for (const ep of eps) {
    if (ctx.stopped) break;
    tested++;
    const epLabel = ep.kind === 'query' ? `${new URL(ep.url).pathname}?${ep.idParam}=${ep.idValue}` : new URL(ep.url).pathname;
    // Orijinal (id = N)
    const orig = await ctx.fetchOnce(ep.url);
    if (!orig || orig.status === 0 || ctx.stopped) continue;
    const origNF = looksLikeNotFound(orig.status, orig.text);
    // Komsu (id = N-1, yoksa N+1)
    const neighborVal = ep.idValue > 1 ? ep.idValue - 1 : ep.idValue + 1;
    const nUrl = withId(ep.url, ep.kind, ep.idParam, neighborVal);
    const nb = await ctx.fetchOnce(nUrl);
    if (!nb || ctx.stopped) continue;
    const nbNF = looksLikeNotFound(nb.status, nb.text);
    // Kanit (VERI SAKLANMADAN): komsu 200 + genel-404 DEGIL + orijinalden FARKLI uzunluk => farkli kaynak.
    const different = nb.status === 200 && !nbNF && Math.abs(nb.len - orig.len) > 64;
    if (different && !origNF) {
      findings.push({ endpoint: epLabel, idParam: ep.idParam, observation: `Kimlik doğrulaması olmadan komşu ID (${neighborVal}) için 200 yanıt ve orijinalden farklı içerik döndü (uzunluk farkı). Numaralandırılabilir kaynak erişimi göstergesi.`, differentResource: true, severity: 'medium' });
    } else if (nb.status === 200 && !nbNF && origNF) {
      findings.push({ endpoint: epLabel, idParam: ep.idParam, observation: `Komşu ID (${neighborVal}) için 200 yanıt döndü; orijinal ID erişilebilir bir kaynak vermemişti — numaralandırma ile erişilebilir kayıt göstergesi (manuel doğrulama önerilir).`, differentResource: true, severity: 'low' });
    }
  }

  if (ctx.stopped) notes.push(ctx.stopped);
  if (!eps.length) notes.push(`Taranan ${surf.pagesScanned} benzersiz sayfada sayısal/tahmin-edilebilir ID içeren bir uç nokta (ör. \`?id=123\`, \`/user/45\`) bulunamadı.` + spaHint(surf));
  return { ok: true, pagesScanned: surf.pagesScanned, candidates: eps.length, endpointsTested: tested, probesSent: ctx.sent, findings, stopped: ctx.stopped, notes };
}

// ======================================================================================
// ORTAK — FAZ B/C/D (SSRF, RCE, Dosya Yükleme, İş Mantığı, Race/Mass-Assignment)
// Hepsi in-band; PentAGI'siz; ProbeCtx devre kesici + tek-deneme (retry YOK) ile.
// ======================================================================================
export type SideEffectRisk = 'none' | 'possible' | 'confirmed';
export type VFinding = {
  check: string; inputPoint: string; vulnerable: boolean; technique: string;
  evidence: string; confidence: 'high' | 'medium' | 'low'; severity: 'high' | 'medium' | 'low';
  sideEffectRisk: SideEffectRisk;
};
export type ActiveCheckEvidence = { ok: boolean; pagesScanned: number; inputsFound: number; probesSent: number; findings: VFinding[]; stopped: string | null; notes: string[] };

const OOB_ECHO_BASE = (process.env.PUBLIC_API_URL ?? 'https://api.cybertestify.com').replace(/\/$/, '');
const OOB_ECHO_HOST = (() => { try { return new URL(OOB_ECHO_BASE).hostname.toLowerCase(); } catch { return 'api.cybertestify.com'; } })();
const SLEEP_S = 5;                 // echo gecikmesi + rce sleep suresi
const randToken = () => randomBytes(16).toString('hex');

// HARD-GUARD (koda gomulu): ic ag / bulut metadata / localhost ASLA hedeflenmez.
function isInternalHost(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/\.$/, '');
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.internal') || h.endsWith('.local')) return true;
  if (h === '169.254.169.254' || h === 'metadata.google.internal' || h === '100.100.100.200') return true;
  if (h === '::1' || h === '0.0.0.0') return true;
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const a = +m[1], b = +m[2];
    if (a === 127 || a === 10 || a === 0 || a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
  }
  return false;
}

// ======================================================================================
// FAZ B.1 — ssrf_verify (in-band, OOB YOK): kontrollu-gecikme echo URL + zaman farki
// ======================================================================================
const FETCH_PARAM_RE = /(^|_)(url|uri|link|webhook|callback|image|img|src|source|dest|destination|redirect|redir|feed|proxy|fetch|load|domain|site|target|host|page|ref|next|return|continue|file|path|preview|thumb|avatar|logo)$/i;

export async function collectSsrfEvidence(host: string): Promise<ActiveCheckEvidence> {
  const surf = await discoverSurface(host);
  if (!surf.ok) return { ok: false, pagesScanned: 0, inputsFound: 0, probesSent: 0, findings: [], stopped: null, notes: ['Hedef ana sayfası çekilemedi.'] };
  const inputs = surf.inputs.filter((ip) => FETCH_PARAM_RE.test(ip.param)).slice(0, 5);
  const ctx = new ProbeCtx();
  const findings: VFinding[] = [];
  const notes: string[] = [];
  const base = await ctx.fetchOnce(`https://${host}/`);
  if (base) ctx.baseline = base.ms;

  for (const ip of inputs) {
    if (ctx.stopped) break;
    const token = randToken();
    const echoUrl = `${OOB_ECHO_BASE}/oob/echo/${token}`;
    // HARD-GUARD: probe URL yalniz kendi echo host'umuz olabilir; ic ag ASLA.
    try { const eh = new URL(echoUrl).hostname.toLowerCase(); if (eh !== OOB_ECHO_HOST || isInternalHost(eh)) continue; } catch { continue; }
    const label = `${ip.method} ${new URL(ip.action).pathname}?${ip.param}`;
    const r = ip.method === 'GET'
      ? await ctx.fetchOnce(buildGetUrl(ip, echoUrl), { expectSlow: true })
      : await ctx.fetchOnce(ip.action, { method: 'POST', body: buildFormBody(ip, echoUrl), contentType: 'application/x-www-form-urlencoded', expectSlow: true });
    if (r && r.status > 0 && r.ms >= ctx.baseline + (SLEEP_S * 1000) - 1000) {
      // (esik: baseline + ~SLEEP_S sn) — kontrollu gecikme hedefin yanitina yansidi
      findings.push({ check: 'ssrf', inputPoint: label, vulnerable: true, technique: 'time-based (kontrollü gecikme echo)', evidence: `Parametreye kontrolümüzdeki gecikmeli URL verildiğinde hedefin yanıtı ~${(r.ms / 1000).toFixed(1)}s'ye çıktı (baseline ~${(ctx.baseline / 1000).toFixed(1)}s) — sunucu-taraflı fetch (SSRF) göstergesi.`, confidence: 'medium', severity: 'high', sideEffectRisk: 'none' });
    }
  }
  if (ctx.stopped) notes.push(ctx.stopped);
  if (!inputs.length) notes.push(`Taranan ${surf.pagesScanned} benzersiz sayfada sunucu-taraflı fetch tetikleyebilecek bir parametre (url/webhook/image vb.) bulunamadı.` + spaHint(surf));
  return { ok: true, pagesScanned: surf.pagesScanned, inputsFound: inputs.length, probesSent: ctx.sent, findings, stopped: ctx.stopped, notes };
}

// ======================================================================================
// FAZ B.2 — rce_verify (in-band): SADECE zaman-tabanli zararsiz sleep payload'lari
// ======================================================================================
// HARD-GUARD: yalniz bu sabit, zararsiz gecikme payload'lari. Dosya/ag/komut YOK.
const RCE_SLEEP_PAYLOADS = [`; sleep ${SLEEP_S} #`, `| sleep ${SLEEP_S}`, `$(sleep ${SLEEP_S})`, `\`sleep ${SLEEP_S}\``];

export async function collectRceEvidence(host: string): Promise<ActiveCheckEvidence> {
  const surf = await discoverSurface(host);
  if (!surf.ok) return { ok: false, pagesScanned: 0, inputsFound: 0, probesSent: 0, findings: [], stopped: null, notes: ['Hedef ana sayfası çekilemedi.'] };
  const inputs = surf.inputs.slice(0, 4);
  const ctx = new ProbeCtx();
  const findings: VFinding[] = [];
  const notes: string[] = [];
  const base = await ctx.fetchOnce(`https://${host}/`);
  if (base) ctx.baseline = base.ms;

  for (const ip of inputs) {
    if (ctx.stopped) break;
    const label = `${ip.method} ${new URL(ip.action).pathname}?${ip.param}`;
    let hit = false;
    for (const payload of RCE_SLEEP_PAYLOADS.slice(0, 3)) { // input basina en fazla 3 zaman-tabanli deneme, retry YOK
      if (ctx.stopped || hit) break;
      const val = `1${payload}`;
      const r = ip.method === 'GET'
        ? await ctx.fetchOnce(buildGetUrl(ip, val), { expectSlow: true })
        : await ctx.fetchOnce(ip.action, { method: 'POST', body: buildFormBody(ip, val), contentType: 'application/x-www-form-urlencoded', expectSlow: true });
      if (r && r.status > 0 && r.ms >= ctx.baseline + (SLEEP_S * 1000) - 700) {
        hit = true;
        findings.push({ check: 'rce', inputPoint: label, vulnerable: true, technique: 'time-based (blind, sleep)', evidence: `Zaman-tabanlı zararsız gecikme payload'ı yanıt süresini ~${(r.ms / 1000).toFixed(1)}s'ye çıkardı (baseline ~${(ctx.baseline / 1000).toFixed(1)}s) — blind komut çalıştırma göstergesi.`, confidence: 'medium', severity: 'high', sideEffectRisk: 'none' });
      }
    }
  }
  if (ctx.stopped) notes.push(ctx.stopped);
  if (!inputs.length) notes.push(`Taranan ${surf.pagesScanned} benzersiz sayfada komuta ulaşabilecek bir giriş parametresi bulunamadı.` + spaHint(surf));
  return { ok: true, pagesScanned: surf.pagesScanned, inputsFound: inputs.length, probesSent: ctx.sent, findings, stopped: ctx.stopped, notes };
}

// ======================================================================================
// FAZ C — file_upload_verify: tek zararsiz/inert dosya yukleme probu; geri cagirma YOK
// ======================================================================================
function discoverUploadForms(host: string, html: string): Array<{ action: string; fileField: string; otherFields: string[] }> {
  const out: Array<{ action: string; fileField: string; otherFields: string[] }> = [];
  for (const fm of html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)) {
    const inner = fm[2];
    const fileField = inner.match(/<input\b[^>]*type=["']file["'][^>]*\bname=["']([^"']+)["']/i)?.[1]
      ?? inner.match(/<input\b[^>]*\bname=["']([^"']+)["'][^>]*type=["']file["']/i)?.[1];
    if (!fileField) continue;
    const action = absUrl(fm[1].match(/action\s*=\s*["']([^"']*)["']/i)?.[1] || '/', host);
    if (!action) continue;
    const others: string[] = [];
    for (const im of inner.matchAll(/<input\b[^>]*\bname=["']([^"']+)["']/gi)) if (im[1] !== fileField && !/^(csrf|_token|authenticity_token)/i.test(im[1])) others.push(im[1]);
    out.push({ action, fileField, otherFields: others.slice(0, 8) });
  }
  return out.slice(0, 2);
}
function buildMultipart(fileField: string, filename: string, fileType: string, fileContent: string, other: string[]): { body: string; contentType: string } {
  const boundary = '----cybertestify' + randToken();
  let body = '';
  for (const f of other) body += `--${boundary}\r\nContent-Disposition: form-data; name="${f}"\r\n\r\ntest\r\n`;
  body += `--${boundary}\r\nContent-Disposition: form-data; name="${fileField}"; filename="${filename}"\r\nContent-Type: ${fileType}\r\n\r\n${fileContent}\r\n`;
  body += `--${boundary}--\r\n`;
  return { body, contentType: `multipart/form-data; boundary=${boundary}` };
}
const UPLOAD_REJECT_RE = /(not allowed|invalid file|unsupported|desteklenmeyen|geçersiz dosya|izin veril|reddedild|file type|yalnızca|only .* allowed|hata|error)/i;

export async function collectFileUploadEvidence(host: string): Promise<ActiveCheckEvidence> {
  const surf = await discoverSurface(host);
  if (!surf.ok) return { ok: false, pagesScanned: 0, inputsFound: 0, probesSent: 0, findings: [], stopped: null, notes: ['Hedef ana sayfası çekilemedi.'] };
  const forms = surf.uploadForms.slice(0, 3);
  const ctx = new ProbeCtx();
  const findings: VFinding[] = [];
  const notes: string[] = [];
  const base = await ctx.fetchOnce(`https://${host}/`);
  if (base) ctx.baseline = base.ms;

  for (const f of forms) {
    if (ctx.stopped) break;
    // Zararsiz, INERT, cift-uzantili test dosyasi (calistirilamaz). GERI CAGIRILMAZ.
    const { body, contentType } = buildMultipart(f.fileField, 'cybertestify_probe.php.txt', 'text/plain', 'CYBERTESTIFY-UPLOAD-PROBE (inert, non-executable test file)', f.otherFields);
    const r = await ctx.fetchOnce(f.action, { method: 'POST', body, contentType }); // tek deneme, retry YOK
    const label = new URL(f.action).pathname;
    if (!r || ctx.stopped) continue;
    const accepted = (r.status === 200 || r.status === 201 || r.status === 302) && !UPLOAD_REJECT_RE.test(r.text);
    if (accepted) {
      findings.push({ check: 'file_upload', inputPoint: label, vulnerable: true, technique: 'inert file accepted (double-extension)', evidence: `Çift uzantılı (.php.txt) zararsız test dosyası, açık bir doğrulama reddi olmadan kabul edilmiş görünüyor (HTTP ${r.status}). Yükleme filtresi zayıf olabilir; kesin doğrulama için manuel test gerekir (dosya GERİ ÇAĞIRILMADI/çalıştırılmadı).`, confidence: 'low', severity: 'medium', sideEffectRisk: 'possible' });
    }
  }
  if (ctx.stopped) notes.push(ctx.stopped);
  if (!forms.length) notes.push(`Taranan ${surf.pagesScanned} benzersiz sayfada dosya yükleme formu (input type=file) bulunamadı.` + spaHint(surf));
  return { ok: true, pagesScanned: surf.pagesScanned, inputsFound: forms.length, probesSent: ctx.sent, findings, stopped: ctx.stopped, notes };
}

// ======================================================================================
// FAZ D.1 — business_logic_verify: GÖZLEM + GET-tabanli adim-atlama (MUTASYON/ISTEK-YAZMA YOK)
// KOD-GUVENCESI: bu kontrol hicbir state-degistiren istek (POST/PUT/...) GONDERMEZ -> tamamlama IMKANSIZ.
// ======================================================================================
const STEP_SKIP_RE = /\/(success|completed?|confirm(ation)?|thank[-_]?you|tesekkur|onay|basarili|receipt|invoice)\b/i;
const PRICE_FIELD_RE = /name=["'](price|amount|total|cost|fiyat|tutar|qty|quantity|adet|miktar|discount|indirim)["']/i;

export async function collectBusinessLogicEvidence(host: string): Promise<ActiveCheckEvidence> {
  const surf = await discoverSurface(host);
  if (!surf.ok) return { ok: false, pagesScanned: 0, inputsFound: 0, probesSent: 0, findings: [], stopped: null, notes: ['Hedef ana sayfası çekilemedi.'] };
  const html = surf.homeHtml;
  const ctx = new ProbeCtx();
  const findings: VFinding[] = [];
  const notes: string[] = [];

  // (a) İstemci-tarafli fiyat/miktar alani (hidden veya duz) — GOZLEM (istek yok)
  const hiddenPrice = html.match(new RegExp(`<input[^>]*type=["']hidden["'][^>]*${PRICE_FIELD_RE.source}`, 'i')) || html.match(new RegExp(`<input[^>]*${PRICE_FIELD_RE.source}[^>]*type=["']hidden["']`, 'i'));
  if (hiddenPrice) {
    findings.push({ check: 'business_logic', inputPoint: 'form (hidden price/qty)', vulnerable: true, technique: 'observation (client-controllable amount)', evidence: 'Formda gizli (hidden) bir fiyat/miktar alanı gözlemlendi. Bu alan istemci tarafında değiştirilebilir; sunucu-taraflı fiyat/miktar doğrulaması yapılmıyorsa fiyat manipülasyonu riski oluşur (kesin doğrulama kimlik-doğrulamalı manuel test gerektirir).', confidence: 'low', severity: 'low', sideEffectRisk: 'none' });
  }

  // (b) Adim-atlama: success/confirm sayfalarina DOGRUDAN GET (yalniz GET; tamamlama YOK).
  // Linkler TUM taranan sayfalardan toplanir (surf.inputs degil, tum sayfalarin href'leri).
  const links = new Set<string>();
  for (const m of html.matchAll(/href\s*=\s*["']([^"']+)["']/gi)) { const abs = absUrl(m[1].replace(/&amp;/g, '&'), host); if (abs && STEP_SKIP_RE.test(abs)) links.add(abs); }
  for (const e of surf.idEndpoints) { if (STEP_SKIP_RE.test(e.url)) links.add(e.url); }
  const base = await ctx.fetchOnce(`https://${host}/`);
  if (base) ctx.baseline = base.ms;
  for (const url of [...links].slice(0, 4)) {
    if (ctx.stopped) break;
    const r = await ctx.fetchOnce(url); // GET — state degistirmez
    if (r && r.status === 200 && !/oturum|login|giriş yap|unauthorized|403|yetkisiz/i.test(r.text.slice(0, 2000))) {
      findings.push({ check: 'business_logic', inputPoint: new URL(url).pathname, vulnerable: true, technique: 'observation (step-skip, GET only)', evidence: `Bir "başarılı/onay" adımı sayfası (${new URL(url).pathname}) ön koşul olmadan doğrudan GET ile erişilebilir göründü — adım-atlama (business logic) göstergesi olabilir; manuel doğrulama önerilir.`, confidence: 'low', severity: 'low', sideEffectRisk: 'none' });
    }
  }
  if (ctx.stopped) notes.push(ctx.stopped);
  if (!findings.length) notes.push(`Taranan ${surf.pagesScanned} benzersiz sayfada gözlemlenebilir bir istemci-tarafı fiyat/miktar alanı veya doğrudan erişilebilir "onay" adımı bulunamadı.` + spaHint(surf));
  return { ok: true, pagesScanned: surf.pagesScanned, inputsFound: (hiddenPrice ? 1 : 0) + links.size, probesSent: ctx.sent, findings, stopped: ctx.stopped, notes };
}

// ======================================================================================
// FAZ D.2 — race_massassign_verify: TEK mass-assignment POST probu + race YÜZEY notu
// KOD-GUVENCESI: tamamlama/odeme uc noktalari blocklist ile ATLANIR; TEK istek, retry YOK;
// yalniz POST (PUT/PATCH/DELETE asla). Gercek yetki degisikligi TEYIT EDILMEZ.
// ======================================================================================
const COMPLETION_BLOCKLIST_RE = /(pay|payment|checkout|charge|billing|order[-_]?(complete|confirm|place)|purchase|subscribe|abone|iade|refund|delete|remove|sil|iptal|cancel)/i;

function discoverMassAssignForm(host: string, html: string): { action: string; fields: string[] } | null {
  for (const fm of html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)) {
    const attrs = fm[1];
    if (!/method\s*=\s*["']?\s*post/i.test(attrs)) continue;
    const action = absUrl(attrs.match(/action\s*=\s*["']([^"']*)["']/i)?.[1] || '/', host);
    if (!action || COMPLETION_BLOCKLIST_RE.test(action)) continue; // HARD-GUARD: tamamlama uc noktalarini atla
    const inner = fm[2];
    const fields: string[] = [];
    for (const im of inner.matchAll(/<input\b[^>]*\bname=["']([^"']+)["']/gi)) if (!/^(csrf|_token|authenticity_token|captcha)/i.test(im[1])) fields.push(im[1]);
    // Kayit/profil benzeri form (email/username/name iceren)
    if (fields.some((f) => /email|user|name|isim|ad|profil|account/i.test(f))) return { action, fields: fields.slice(0, 10) };
  }
  return null;
}

export async function collectRaceMassAssignEvidence(host: string): Promise<ActiveCheckEvidence> {
  const surf = await discoverSurface(host);
  if (!surf.ok) return { ok: false, pagesScanned: 0, inputsFound: 0, probesSent: 0, findings: [], stopped: null, notes: ['Hedef ana sayfası çekilemedi.'] };
  const form = surf.massAssignForm;
  const ctx = new ProbeCtx();
  const findings: VFinding[] = [];
  const notes: string[] = [];
  const base = await ctx.fetchOnce(`https://${host}/`);
  if (base) ctx.baseline = base.ms;

  if (form) {
    // Sahte/test verisi + fazladan isAdmin/role alani. TEK POST, retry YOK.
    const usp = new URLSearchParams();
    for (const f of form.fields) usp.set(f, /email/i.test(f) ? `cybertestify-probe+${randToken().slice(0, 8)}@example.com` : 'cybertestify-test');
    usp.set('isAdmin', 'true'); usp.set('role', 'admin'); usp.set('is_admin', 'true');
    const r = ctx.stopped ? null : await ctx.fetchOnce(form.action, { method: 'POST', body: usp.toString(), contentType: 'application/x-www-form-urlencoded' });
    const label = new URL(form.action).pathname;
    if (r && r.status > 0 && !ctx.stopped) {
      const accepted = (r.status === 200 || r.status === 201 || r.status === 302) && !/(error|hata|invalid|geçersiz|reddedil|not allowed|zorunlu|required)/i.test(r.text.slice(0, 3000));
      if (accepted) {
        findings.push({ check: 'race_massassign', inputPoint: label, vulnerable: true, technique: 'mass-assignment (extra isAdmin/role field)', evidence: `Kayıt/profil benzeri forma fazladan "isAdmin/role" alanları eklendiğinde istek açık bir reddedilme olmadan kabul edildi (HTTP ${r.status}). Mass-assignment (over-posting) göstergesi; yetki değişikliği TEYİT EDİLMEDİ (sadece ilk yanıt gözlemlendi).`, confidence: 'low', severity: 'medium', sideEffectRisk: 'possible' });
      }
    }
  }
  // Race yüzeyi — otomatik yıkıcı paralel yazma YAPILMAZ (güvenlik); not olarak belirtilir.
  notes.push('Race-condition (eşzamanlılık) testi, tüketilebilir bir kaynağı (kupon/stok) gerçekten değiştirme riski taşıdığından bu otomatik taramada **çalıştırılmadı**; güvenli/test edilebilir bir uç nokta ile manuel doğrulama önerilir.');
  if (ctx.stopped) notes.push(ctx.stopped);
  if (!form) notes.push(`Taranan ${surf.pagesScanned} benzersiz sayfada mass-assignment için uygun (tamamlama/ödeme dışı) kayıt/profil formu bulunamadı.` + spaHint(surf));
  return { ok: true, pagesScanned: surf.pagesScanned, inputsFound: form ? 1 : 0, probesSent: ctx.sent, findings, stopped: ctx.stopped, notes };
}
