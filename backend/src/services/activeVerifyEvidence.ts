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
import { collectHttp } from './surfaceEvidence.js';

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

  // 1) Linklerdeki query param'lar (href="...?a=1&b=2")
  for (const m of html.matchAll(/href\s*=\s*["']([^"']*\?[^"']+)["']/gi)) {
    const abs = absUrl(m[1].replace(/&amp;/g, '&'), host);
    if (!abs) continue;
    try {
      const u = new URL(abs);
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
// injection_verify — SQLi (hata + zaman) + XSS (yansima)
// ======================================================================================
const SQL_ERROR_RE = /(SQL syntax|mysql_fetch|mysqli|you have an error in your sql|ORA-\d{4,5}|PLS-\d|PostgreSQL.*ERROR|pg_query|SQLite3?::|SQLSTATE\[|Microsoft OLE DB Provider|ODBC SQL Server|Unclosed quotation mark|quoted string not properly terminated|syntax error at or near|Warning: pg_|Warning: mysql)/i;

export type InjFinding = { inputPoint: string; type: 'SQLi' | 'XSS'; technique: 'error-based' | 'time-based' | 'reflection'; evidence: string; severity: 'high' | 'medium' | 'low'; confidence: 'high' | 'medium' | 'low' };
export type InjEvidence = { ok: boolean; baseUrl: string; inputsFound: number; inputsTested: number; probesSent: number; findings: InjFinding[]; stopped: string | null; notes: string[] };

export async function collectInjectionEvidence(host: string): Promise<InjEvidence> {
  const home = await collectHttp(host);
  if (!home.ok) return { ok: false, baseUrl: `https://${host}/`, inputsFound: 0, inputsTested: 0, probesSent: 0, findings: [], stopped: null, notes: ['Hedef ana sayfası çekilemedi (bağlantı kurulamadı).'] };
  const inputs = discoverInputs(host, home.html);
  const ctx = new ProbeCtx();
  const findings: InjFinding[] = [];
  const notes: string[] = [];
  let tested = 0;

  // Baseline (temiz istek) — devre kesici + zaman-tabanli karsilastirma icin.
  const base = await ctx.fetchOnce(`https://${host}/`);
  if (base) ctx.baseline = base.ms;

  const XSS_MARKER = 'cxt9137xmark'; // benzersiz, zararsiz; JS calistirmaz
  const XSS_PAYLOAD = `${XSS_MARKER}"><cxmark>`;

  for (const ip of inputs) {
    if (ctx.stopped) break;
    tested++;
    const label = `${ip.method} ${new URL(ip.action).pathname}?${ip.param}`;

    // --- Probe 1: SQLi hata-tabanli (tek tirnak) ---
    const q = "'";
    let r: ProbeResult | null;
    if (ip.method === 'GET') r = await ctx.fetchOnce(buildGetUrl(ip, q));
    else r = await ctx.fetchOnce(ip.action, { method: 'POST', body: buildFormBody(ip, q), contentType: 'application/x-www-form-urlencoded' });
    let sqlErrorFound = false;
    if (r && SQL_ERROR_RE.test(r.text)) {
      sqlErrorFound = true;
      const sig = r.text.match(SQL_ERROR_RE)?.[0] ?? 'SQL hata imzası';
      findings.push({ inputPoint: label, type: 'SQLi', technique: 'error-based', evidence: `Yanıtta veritabanı hata imzası görüldü: "${sig.slice(0, 60)}"`, severity: 'high', confidence: 'high' });
    }

    // --- Probe 2: XSS yansima (benzersiz isaret) ---
    if (!ctx.stopped) {
      let xr: ProbeResult | null;
      if (ip.method === 'GET') xr = await ctx.fetchOnce(buildGetUrl(ip, XSS_PAYLOAD));
      else xr = await ctx.fetchOnce(ip.action, { method: 'POST', body: buildFormBody(ip, XSS_PAYLOAD), contentType: 'application/x-www-form-urlencoded' });
      if (xr && xr.text.includes(`${XSS_MARKER}"><cxmark>`)) {
        findings.push({ inputPoint: label, type: 'XSS', technique: 'reflection', evidence: 'Zararsız işaret dizesi yanıt HTML’inde KAÇIRILMADAN (unencoded) yansıdı — yansıyan XSS göstergesi.', severity: 'high', confidence: 'high' });
      } else if (xr && xr.text.includes(XSS_MARKER)) {
        findings.push({ inputPoint: label, type: 'XSS', technique: 'reflection', evidence: 'İşaret dizesi yansıdı ancak kodlanmış/kısmen kaçırılmış görünüyor — bağlama göre risk; manuel doğrulama önerilir.', severity: 'low', confidence: 'low' });
      }
    }

    // --- Probe 3 (KOSULLU): SQLi zaman-tabanli — hata bulunmadiysa blind dogrulama ---
    if (!sqlErrorFound && !ctx.stopped) {
      const payload = `1' AND SLEEP(${TIME_PROBE_DELAY_S})-- -`;
      let tr: ProbeResult | null;
      if (ip.method === 'GET') tr = await ctx.fetchOnce(buildGetUrl(ip, payload), { expectSlow: true });
      else tr = await ctx.fetchOnce(ip.action, { method: 'POST', body: buildFormBody(ip, payload), contentType: 'application/x-www-form-urlencoded', expectSlow: true });
      // Kanit: gecikme ~ SLEEP suresi kadar (baseline + ~3s). Yanlis-pozitif riski: agir sayfa.
      if (tr && tr.status > 0 && tr.ms >= (ctx.baseline + (TIME_PROBE_DELAY_S * 1000) - 700)) {
        findings.push({ inputPoint: label, type: 'SQLi', technique: 'time-based', evidence: `Zaman-tabanlı probe (SLEEP ${TIME_PROBE_DELAY_S}s) yanıt süresini ~${(tr.ms / 1000).toFixed(1)}s'ye çıkardı (baseline ~${(ctx.baseline / 1000).toFixed(1)}s) — blind SQLi göstergesi.`, severity: 'high', confidence: 'medium' });
      }
    }
  }

  if (ctx.stopped) notes.push(ctx.stopped);
  if (!inputs.length) notes.push('Ana sayfada test edilebilir GET parametresi veya form alanı bulunamadı (giriş noktası yok).');
  return { ok: true, baseUrl: `https://${host}/`, inputsFound: inputs.length, inputsTested: tested, probesSent: ctx.sent, findings, stopped: ctx.stopped, notes };
}

// ======================================================================================
// idor_verify — kimlik-dogrulamasiz numaralandirilabilir kaynak (sinirli kapsam)
// ======================================================================================
export type IdorFinding = { endpoint: string; idParam: string; observation: string; differentResource: boolean; severity: 'high' | 'medium' | 'low' };
export type IdorEvidence = { ok: boolean; candidates: number; endpointsTested: number; probesSent: number; findings: IdorFinding[]; stopped: string | null; notes: string[] };

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
  const home = await collectHttp(host);
  if (!home.ok) return { ok: false, candidates: 0, endpointsTested: 0, probesSent: 0, findings: [], stopped: null, notes: ['Hedef ana sayfası çekilemedi (bağlantı kurulamadı).'] };
  const eps = discoverIdEndpoints(host, home.html);
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
  if (!eps.length) notes.push('Ana sayfada sayısal/tahmin-edilebilir ID içeren bir uç nokta (ör. `?id=123`, `/user/45`) bulunamadı.');
  return { ok: true, candidates: eps.length, endpointsTested: tested, probesSent: ctx.sent, findings, stopped: ctx.stopped, notes };
}
