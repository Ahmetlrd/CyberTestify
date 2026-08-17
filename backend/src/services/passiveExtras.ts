import { promises as dns } from 'node:dns';

/**
 * (Ek Pasif Kontroller) — DETERMINISTIK, AGENT'SIZ, LLM'SIZ.
 *
 * Her fonksiyon hedef host'u alir, hedefin KENDI DNS'ine veya HTTP'sine (yapisal
 * olarak kapsam-ici) sorgu yapar ve SABIT PassiveCheckResult semasi doner. Hicbir
 * LLM cagrisi YOK -> sifir Anthropic/PentAGI maliyeti, sifir yorumlama riski.
 *
 * Kurallar: hicbir fonksiyon exception FIRLATMAZ (hepsi status:"error" doner);
 * runner Promise.allSettled ile izole eder; HTTP timeout ~9sn, max govde ~1.5MB.
 * Kapsam: istekler yalniz hedef host / hedefin apex domain'i / hedefin alt alan
 * adi (mta-sts.<domain>) veya tek referans (hstspreload.org) icin yapilir; her HTTP
 * istegi assertTargetScope ile dogrulanir (hedef disina cikan istek YOK).
 *
 * UYUM BEYANI YOK: yalniz present/absent/misconfigured gibi notr dil; "uyumludur" DEMEZ.
 */

// Saklanan rapor markdown'inda ana bulgular ile "Ek Pasif Kontroller"i ayiran isaret.
// reports.ts indirmede bunu ayirip PDF'te AYRI/renkli bir bolum olarak render eder.
export const PASSIVE_EXTRAS_DELIM = '===PASSIVE_EXTRAS===';

export type PassiveCheckStatus = 'present' | 'absent' | 'misconfigured' | 'error' | 'skipped';

export interface PassiveCheckResult {
  id: string;
  title: string;
  status: PassiveCheckStatus;
  summary: string;
  details?: Record<string, unknown>;
  evidence?: string[];
}

const HTTP_TIMEOUT_MS = 9000;
const MAX_BYTES = 1_500_000;
const HSTS_API = 'hstspreload.org';

function apexDomain(host: string): string {
  return host.replace(/^www\./i, '');
}

// Kapsam guvencesi: verilen url host'u hedefe (veya hedefin apex/alt-alanina ya da
// tek referans hstspreload.org'a) ait mi? Degilse istek YAPILMAZ.
function inTargetScope(urlHost: string, targetHost: string): boolean {
  const u = urlHost.toLowerCase();
  const apex = apexDomain(targetHost).toLowerCase();
  return u === targetHost.toLowerCase() || u === apex || u.endsWith('.' + apex) || u === HSTS_API;
}

interface FetchOut {
  ok: boolean;
  status: number;
  text: string;
  contentType: string;
  error?: string;
}

// Guvenli HTTP GET: timeout + boyut siniri + hedef-kapsam kontrolu; ASLA throw etmez.
async function safeGet(url: string, targetHost: string): Promise<FetchOut> {
  let host = '';
  try {
    host = new URL(url).hostname;
  } catch {
    return { ok: false, status: 0, text: '', contentType: '', error: 'gecersiz url' };
  }
  if (!inTargetScope(host, targetHost)) {
    return { ok: false, status: 0, text: '', contentType: '', error: 'kapsam disi (istek yapilmadi)' };
  }
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), HTTP_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      signal: ctrl.signal,
      redirect: 'follow',
      headers: { 'user-agent': 'CyberTestify-PassiveCheck/1.0' },
    });
    const cl = Number(res.headers.get('content-length') ?? '0');
    const contentType = res.headers.get('content-type') ?? '';
    if (cl && cl > MAX_BYTES) {
      return { ok: res.ok, status: res.status, text: '', contentType, error: 'yanit cok buyuk (atlandi)' };
    }
    const buf = Buffer.from(await res.arrayBuffer());
    const text = buf.length > MAX_BYTES ? buf.subarray(0, MAX_BYTES).toString('utf-8') : buf.toString('utf-8');
    return { ok: res.ok, status: res.status, text, contentType };
  } catch (e) {
    const err = (e as Error).name === 'AbortError' ? 'zaman asimi' : (e as Error).message || 'baglanti hatasi';
    return { ok: false, status: 0, text: '', contentType: '', error: err };
  } finally {
    clearTimeout(timer);
  }
}

async function txt(name: string): Promise<string[]> {
  const recs = await dns.resolveTxt(name); // string[][]
  return recs.map((parts) => parts.join(''));
}

// ---- DNS paketleri (dns_email) --------------------------------------------

async function checkCaa(host: string): Promise<PassiveCheckResult> {
  const id = 'caa', title = 'CAA Kaydı (Sertifika Yetkilisi Kısıtı)';
  try {
    const domain = apexDomain(host);
    const recs = await dns.resolveCaa(domain).catch(() => [] as Array<Record<string, string>>);
    const issuers = recs
      .map((r) => (r as Record<string, string>).issue || (r as Record<string, string>).issuewild)
      .filter(Boolean);
    if (!recs.length) {
      return { id, title, status: 'absent', summary: 'CAA kaydı yok — herhangi bir sertifika yetkilisi (CA) bu domain için sertifika çıkarabilir.' };
    }
    return {
      id, title, status: 'present',
      summary: `CAA kaydı mevcut; sertifika çıkarımı ${issuers.length} yetkiliyle sınırlı.`,
      details: { issuers, records: recs },
    };
  } catch (e) {
    return { id, title, status: 'error', summary: `Kontrol edilemedi: ${(e as Error).message}` };
  }
}

async function checkBimi(host: string): Promise<PassiveCheckResult> {
  const id = 'bimi', title = 'BIMI Kaydı';
  try {
    const name = `default._bimi.${apexDomain(host)}`;
    const recs = await txt(name).catch(() => [] as string[]);
    if (!recs.length) return { id, title, status: 'absent', summary: 'BIMI kaydı bulunamadı.' };
    const rec = recs.find((r) => /v=BIMI1\b/i.test(r)) ?? recs[0];
    if (!/^v=BIMI1\b/i.test(rec.trim())) {
      return { id, title, status: 'misconfigured', summary: 'BIMI TXT kaydı var ama "v=BIMI1;" ile başlamıyor.', details: { record: rec } };
    }
    return { id, title, status: 'present', summary: 'Geçerli BIMI kaydı mevcut.', details: { record: rec } };
  } catch (e) {
    return { id, title, status: 'error', summary: `Kontrol edilemedi: ${(e as Error).message}` };
  }
}

async function checkMtaSts(host: string): Promise<PassiveCheckResult> {
  const id = 'mta_sts', title = 'MTA-STS (E-posta Aktarım Güvenliği)';
  try {
    const domain = apexDomain(host);
    const recs = await txt(`_mta-sts.${domain}`).catch(() => [] as string[]);
    const hasDns = recs.some((r) => /v=STSv1\b/i.test(r));
    const policy = await safeGet(`https://mta-sts.${domain}/.well-known/mta-sts.txt`, host);
    if (!hasDns && !policy.ok) {
      return { id, title, status: 'absent', summary: 'MTA-STS DNS kaydı ve policy dosyası bulunamadı.' };
    }
    const body = policy.text || '';
    const versionOk = /(^|\n)\s*version:\s*STSv1/i.test(body);
    const modeMatch = body.match(/(^|\n)\s*mode:\s*(enforce|testing|none)/i);
    const mode = modeMatch ? modeMatch[2].toLowerCase() : undefined;
    if (!hasDns || !policy.ok || !versionOk || !mode) {
      return {
        id, title, status: 'misconfigured',
        summary: 'MTA-STS eksik/hatalı yapılandırılmış (DNS kaydı, policy dosyası veya version/mode satırı eksik).',
        details: { dnsRecord: hasDns, policyFetched: policy.ok, policyError: policy.error, versionOk, mode },
      };
    }
    return { id, title, status: 'present', summary: `MTA-STS aktif (mode: ${mode}).`, details: { mode } };
  } catch (e) {
    return { id, title, status: 'error', summary: `Kontrol edilemedi: ${(e as Error).message}` };
  }
}

async function checkTlsRpt(host: string): Promise<PassiveCheckResult> {
  const id = 'tls_rpt', title = 'TLS-RPT (SMTP TLS Raporlama)';
  try {
    const recs = await txt(`_smtp._tls.${apexDomain(host)}`).catch(() => [] as string[]);
    const rec = recs.find((r) => /v=TLSRPTv1\b/i.test(r));
    if (!rec) return { id, title, status: 'absent', summary: 'TLS-RPT kaydı bulunamadı.' };
    return { id, title, status: 'present', summary: 'TLS-RPT kaydı mevcut.', details: { record: rec } };
  } catch (e) {
    return { id, title, status: 'error', summary: `Kontrol edilemedi: ${(e as Error).message}` };
  }
}

// ---- header_leak ----------------------------------------------------------

async function checkSecurityTxt(host: string): Promise<PassiveCheckResult> {
  const id = 'security_txt', title = 'security.txt (Güvenlik İletişim Politikası)';
  try {
    let r = await safeGet(`https://${host}/.well-known/security.txt`, host);
    let where = '/.well-known/security.txt';
    if (!r.ok || !r.text.trim()) {
      const legacy = await safeGet(`https://${host}/security.txt`, host);
      if (legacy.ok && legacy.text.trim()) { r = legacy; where = '/security.txt'; }
    }
    if (!r.ok || !r.text.trim()) return { id, title, status: 'absent', summary: 'security.txt bulunamadı.' };
    const hasContact = /(^|\n)\s*Contact:\s*\S+/i.test(r.text);
    const hasExpires = /(^|\n)\s*Expires:\s*\S+/i.test(r.text);
    if (!hasContact || !hasExpires) {
      const missing = [!hasContact && 'Contact', !hasExpires && 'Expires'].filter(Boolean).join(', ');
      return { id, title, status: 'misconfigured', summary: `security.txt var ama zorunlu alan eksik: ${missing}.`, details: { location: where, hasContact, hasExpires } };
    }
    return { id, title, status: 'present', summary: `security.txt geçerli (${where}).`, details: { location: where } };
  } catch (e) {
    return { id, title, status: 'error', summary: `Kontrol edilemedi: ${(e as Error).message}` };
  }
}

// HSTS preload snapshot cache (24s) — canli API'ye her istekte vurulmaz.
const hstsCache = new Map<string, { at: number; status: PassiveCheckStatus; summary: string; details?: Record<string, unknown> }>();
const HSTS_TTL_MS = 24 * 60 * 60 * 1000;

async function checkHstsPreload(host: string): Promise<PassiveCheckResult> {
  const id = 'hsts_preload', title = 'HSTS Preload Listesi Durumu';
  const domain = apexDomain(host);
  const cached = hstsCache.get(domain);
  if (cached && Date.now() - cached.at < HSTS_TTL_MS) {
    return { id, title, status: cached.status, summary: cached.summary, details: cached.details };
  }
  try {
    const r = await safeGet(`https://${HSTS_API}/api/v2/status?domain=${encodeURIComponent(domain)}`, host);
    if (!r.ok || !r.text) {
      const out = { id, title, status: 'skipped' as const, summary: 'Preload listesi şu an kontrol edilemedi.' };
      return out;
    }
    const data = JSON.parse(r.text) as { status?: string };
    const preloaded = data.status === 'preloaded';
    const res = {
      status: (preloaded ? 'present' : 'absent') as PassiveCheckStatus,
      summary: preloaded
        ? 'Domain, tarayıcı HSTS preload listesinde.'
        : `Domain HSTS preload listesinde değil (durum: ${data.status ?? 'bilinmiyor'}).`,
      details: { hstsStatus: data.status },
    };
    hstsCache.set(domain, { at: Date.now(), ...res });
    return { id, title, ...res };
  } catch (e) {
    return { id, title, status: 'skipped', summary: `Preload listesi kontrol edilemedi: ${(e as Error).message}` };
  }
}

async function checkMixedContent(host: string): Promise<PassiveCheckResult> {
  const id = 'mixed_content', title = 'Karışık İçerik (Mixed Content)';
  try {
    const r = await safeGet(`https://${host}/`, host);
    if (!r.ok || !r.text) return { id, title, status: 'error', summary: `Ana sayfa alınamadı: ${r.error ?? 'HTTP ' + r.status}` };
    // Yalniz statik HTML: src/href attribute'larinda http:// (JS RENDER YOK).
    const matches = [...r.text.matchAll(/(?:src|href)\s*=\s*["'](http:\/\/[^"']+)["']/gi)].map((m) => m[1]);
    const unique = [...new Set(matches)];
    if (!unique.length) return { id, title, status: 'absent', summary: 'Ana sayfada http:// ile başlayan karışık içerik kaynağı görülmedi.' };
    const shown = unique.slice(0, 20);
    const extra = unique.length - shown.length;
    return {
      id, title, status: 'misconfigured',
      summary: `Ana sayfada ${unique.length} adet güvensiz (http://) kaynak referansı bulundu.`,
      details: { count: unique.length },
      evidence: extra > 0 ? [...shown, `+${extra} tane daha`] : shown,
    };
  } catch (e) {
    return { id, title, status: 'error', summary: `Kontrol edilemedi: ${(e as Error).message}` };
  }
}

// ---- Hassas dosya ifsasi (MERKEZI catch-all/format dogrulama) -------------
//
// KOK NEDEN (gercek yanlis-pozitif): nomorelink.com gibi SPA/catch-all siteler var
// OLMAYAN her path'e ana sayfa HTML'ini HTTP 200 ile doner. "200 mu? -> acik" naif
// mantigi .git/.env'i YANLISLIKLA "acik/kritik" isaretliyordu. Gercekten acik sayilmasi
// icin: (1) icerik dosyanin BEKLENEN formatina uymali VE (2) ana sayfayla AYNI olmamali.

export type ExposedVerdict = 'exposed' | 'not-exposed' | 'inconclusive';

function normalizeBody(s: string): string {
  return s.replace(/\s+/g, ' ').trim().toLowerCase();
}

/** İçerik, ana sayfanın (`/`) içeriğiyle (neredeyse) aynı mı? → catch-all/SPA. */
function looksLikeHomepage(body: string, homepage: string): boolean {
  if (!homepage) return false;
  const a = normalizeBody(body);
  const b = normalizeBody(homepage);
  if (!a || !b) return false;
  const HEAD = 300;
  if (a.slice(0, HEAD) === b.slice(0, HEAD)) return true; // ayni bas -> catch-all
  // Kisa dosyalar: biri digerini tamamen iceriyorsa (SPA shell) yine catch-all.
  if (a.length > 40 && (b.includes(a) || a.includes(b))) return true;
  return false;
}

// GERCEK dizin listesi mi? (Apache/nginx autoindex VEYA Juice Shop /ftp gibi dosya-linkli listeleme).
// SPA shell'i buraya DUSMEZ (o zaten looksLikeHomepage ile elenir); burada yalniz gercek listeleme.
export function looksLikeDirListing(b: string): boolean {
  if (/<title>\s*index of\s*\//i.test(b) || /<h1>\s*index of\s*\//i.test(b)) return true;
  if (/directory listing (for|of)/i.test(b) || /Parent Directory<\/a>/i.test(b)) return true;
  // Birden fazla, uzantili dosya linki (ör. Juice Shop /ftp: *.bak, *.md, *.pdf, *.coupons_data...).
  const links = b.match(/<a[^>]+href=["'][^"']+\.(bak|sql|zip|gz|tar|tgz|md|json|ya?ml|conf|log|pdf|txt|env|db|sqlite|key|pem|coupons_data)\b/gi);
  return !!links && links.length >= 2;
}

// Dosya-turu "gercekten o dosya mi" imzalari (format izleri). Dizin yollari icin dizin-listesi imzasi.
const FILE_SIGNATURES: Record<string, (b: string) => boolean> = {
  '/.git/config': (b) => /\[core\]/i.test(b) || /repositoryformatversion\s*=/i.test(b),
  '/.git/HEAD': (b) => /^\s*ref:\s*refs\//im.test(b),
  '/.env': (b) => /^[A-Z][A-Z0-9_]*=/m.test(b),
  '/backup.zip': (b) => b.startsWith('PK'), // ZIP magic
  '/backup.sql': (b) => /\b(CREATE TABLE|INSERT INTO|DROP TABLE)\b/i.test(b),
  '/.DS_Store': (b) => b.includes('Bud1'),
  '/wp-config.php': (b) => /define\s*\(\s*['"]DB_/i.test(b),
  '/wp-config.php.bak': (b) => /define\s*\(\s*['"]DB_/i.test(b) || /<\?php/i.test(b),
  // (İŞ 1) Dizinler -> gercek dizin listesi (autoindex / dosya-linkli). SPA catch-all elenir.
  '/ftp': looksLikeDirListing,
  '/ftp/': looksLikeDirListing,
  '/backup': looksLikeDirListing,
  '/backups': looksLikeDirListing,
  '/uploads': looksLikeDirListing,
  '/files': looksLikeDirListing,
  '/admin': looksLikeDirListing,
  // (İŞ 1) Dosyalar -> format imzasi.
  '/.svn/entries': (b) => /^\s*\d+\s*[\r\n]/.test(b) || /\bsvn:\b/i.test(b) || /has-props/i.test(b),
  '/.htaccess': (b) => /(RewriteEngine|RewriteRule|Order\s+(allow|deny)|Deny\s+from|Require\s+all|<Files|AuthType|ErrorDocument)/i.test(b),
  '/config.php.bak': (b) => /<\?php/i.test(b) && /(define\s*\(\s*['"](DB_|APP_|SECRET)|\$(db|database|password|secret))/i.test(b),
  '/db.sql': (b) => /\b(CREATE TABLE|INSERT INTO|DROP TABLE|MySQL dump|PostgreSQL database dump)\b/i.test(b),
  '/dump.sql': (b) => /\b(CREATE TABLE|INSERT INTO|DROP TABLE|MySQL dump|PostgreSQL database dump)\b/i.test(b),
};

/**
 * MERKEZI karar: bir hassas dosya GERCEKTEN acik mi? (prompt VE deterministik kontrol
 * ayni mantigi kullanir). Sadece HTTP 200 YETMEZ — format + catch-all dogrulamasi sart.
 */
export function classifyExposedFile(
  path: string,
  fetched: FetchOut,
  homepage: string,
): { verdict: ExposedVerdict; reason: string } {
  if (!fetched.ok || fetched.status !== 200 || !fetched.text.trim()) {
    return { verdict: 'not-exposed', reason: `HTTP ${fetched.status || 'hata'} / boş gövde — erişilebilir değil` };
  }
  const body = fetched.text;
  // (2) Catch-all: ana sayfayla ayni mi?
  if (looksLikeHomepage(body, homepage)) {
    return { verdict: 'not-exposed', reason: 'içerik ana sayfayla aynı (SPA/catch-all yönlendirme; dosya gerçekten açık değil)' };
  }
  const isHtml = /^\s*<(!doctype|html)\b/i.test(body.trimStart()) || fetched.contentType.includes('text/html');
  const sig = FILE_SIGNATURES[path];
  // (1) Beklenen format imzasi.
  if (sig) {
    if (sig(body)) return { verdict: 'exposed', reason: 'beklenen dosya formatı doğrulandı (catch-all değil)' };
    return {
      verdict: 'not-exposed',
      reason: `HTTP 200 ama içerik beklenen dosya formatına uymuyor${isHtml ? ' (HTML döndü — muhtemelen catch-all)' : ''}`,
    };
  }
  // Imza tanimli degil: HTML donduyse catch-all say; degilse kesin diyemeyiz.
  if (isHtml) return { verdict: 'not-exposed', reason: 'HTTP 200 ama HTML döndü (muhtemelen catch-all)' };
  return { verdict: 'inconclusive', reason: 'HTTP 200, format imzası tanımlı değil — manuel doğrulama gerekir' };
}

const SENSITIVE_PATHS = ['/.git/config', '/.git/HEAD', '/.env', '/backup.zip', '/backup.sql', '/.DS_Store', '/wp-config.php',
  '/ftp', '/backup', '/backups', '/uploads', '/files', '/admin', '/.svn/entries', '/.htaccess', '/config.php.bak', '/db.sql', '/dump.sql'];

/** Deterministik hassas-dosya ifsasi kontrolu — classifyExposedFile ile catch-all/format ayrimi yapar. */
async function checkExposedFiles(host: string): Promise<PassiveCheckResult> {
  const id = 'exposed_files', title = 'Hassas Dosya İfşası (.git / .env / yedek)';
  try {
    const home = await safeGet(`https://${host}/`, host);
    const homepage = home.ok ? home.text : '';
    const exposed: string[] = [];
    const notes: string[] = [];
    for (const p of SENSITIVE_PATHS) {
      const r = await safeGet(`https://${host}${p}`, host);
      const c = classifyExposedFile(p, r, homepage);
      if (c.verdict === 'exposed') {
        exposed.push(p);
        notes.push(`${p}: 🔴 AÇIK — ${c.reason}`);
      } else if (r.status === 200) {
        // 200 dondu ama acik degil: raporda "neden acik degil" gorunsun (seffaflik).
        notes.push(`${p}: HTTP 200 ama ${c.verdict === 'inconclusive' ? 'belirsiz' : 'erişilebilir değil'} — ${c.reason}`);
      }
    }
    if (exposed.length) {
      return {
        id, title, status: 'misconfigured',
        summary: `${exposed.length} hassas dosya GERÇEKTEN erişilebilir (içerik doğrulandı, catch-all DEĞİL): ${exposed.join(', ')}.`,
        details: { exposed },
        evidence: notes,
      };
    }
    return {
      id, title, status: 'absent',
      summary: 'Yaygın hassas dosyaların hiçbiri gerçekten erişilebilir değil. (HTTP 200 dönenler catch-all/SPA veya yanlış format olduğundan açık SAYILMADI.)',
      evidence: notes.length ? notes : undefined,
    };
  } catch (e) {
    return { id, title, status: 'error', summary: `Kontrol edilemedi: ${(e as Error).message}` };
  }
}

// ---- basit_tarama ---------------------------------------------------------

async function checkRobotsSitemap(host: string): Promise<PassiveCheckResult> {
  const id = 'robots_sitemap', title = 'robots.txt & sitemap.xml';
  try {
    const robots = await safeGet(`https://${host}/robots.txt`, host);
    const disallows = robots.ok
      ? [...robots.text.matchAll(/(^|\n)\s*Disallow:\s*(\S+)/gi)].map((m) => m[2]).filter((p) => p && p !== '/')
      : [];
    const uniqDis = [...new Set(disallows)];
    const sitemap = await safeGet(`https://${host}/sitemap.xml`, host);
    const urlCount = sitemap.ok ? (sitemap.text.match(/<loc>/gi)?.length ?? 0) : 0;

    if (!robots.ok && !sitemap.ok) {
      return { id, title, status: 'absent', summary: 'robots.txt ve sitemap.xml bulunamadı.' };
    }
    const shownDis = uniqDis.slice(0, 30);
    const extraDis = uniqDis.length - shownDis.length;
    return {
      id, title, status: 'present',
      summary: `robots.txt ${robots.ok ? 'var' : 'yok'} (${uniqDis.length} Disallow yolu), sitemap.xml ${sitemap.ok ? `var (~${urlCount} URL)` : 'yok'}.`,
      details: { robotsFound: robots.ok, disallowCount: uniqDis.length, sitemapFound: sitemap.ok, sitemapUrlCount: urlCount },
      evidence: shownDis.length ? (extraDis > 0 ? [...shownDis, `+${extraDis} tane daha`] : shownDis) : undefined,
    };
  } catch (e) {
    return { id, title, status: 'error', summary: `Kontrol edilemedi: ${(e as Error).message}` };
  }
}

// (SÜTUN 0 — "VAR" ≠ "GEÇERLİ/DOLU") Parse edilebilir ama BOŞ/default içerik ([] , {apps:[]},
// default template) "mevcut ve geçerli" diye sunulmamalı → fonksiyonel gerçek kayıt var mı bak.
function assetContentPopulated(id: string, parsed: unknown): boolean {
  if (id === 'assetlinks') {
    // Android assetlinks: dolu dizi + en az bir gerçek statement (relation + target.package_name/sha256).
    if (!Array.isArray(parsed) || parsed.length === 0) return false;
    return parsed.some((e: any) =>
      e && typeof e === 'object' &&
      (e.target?.package_name ||
        (Array.isArray(e.target?.sha256_cert_fingerprints) && e.target.sha256_cert_fingerprints.length > 0)));
  }
  // apple-app-site-association: applinks/webcredentials/appclips'ten en az biri DOLU olmalı.
  if (parsed && typeof parsed === 'object') {
    const o = parsed as Record<string, any>;
    const al = o.applinks;
    const alPop = !!al && ((Array.isArray(al.details) && al.details.length > 0) || (Array.isArray(al.apps) && al.apps.length > 0));
    const wcPop = Array.isArray(o.webcredentials?.apps) && o.webcredentials.apps.length > 0;
    const acPop = Array.isArray(o.appclips?.apps) && o.appclips.apps.length > 0;
    return !!(alPop || wcPop || acPop);
  }
  return false;
}

async function jsonAssetCheck(host: string, path: string, id: string, title: string): Promise<PassiveCheckResult> {
  try {
    const r = await safeGet(`https://${host}${path}`, host);
    if (!r.ok || !r.text.trim()) return { id, title, status: 'absent', summary: `${path} bulunamadı.` };
    let parsed: unknown;
    try {
      parsed = JSON.parse(r.text);
    } catch {
      return { id, title, status: 'misconfigured', summary: `${path} mevcut ama geçerli JSON değil.`, details: { location: path } };
    }
    // "var" ≠ "geçerli/dolu": boş/default içerik fonksiyonel değildir.
    if (!assetContentPopulated(id, parsed)) {
      return { id, title, status: 'misconfigured', summary: `${path} var ama boş/default (fonksiyonel değil) — geçerli kayıt içermiyor.`, details: { location: path } };
    }
    return { id, title, status: 'present', summary: `${path} mevcut ve dolu/geçerli JSON.`, details: { location: path } };
  } catch (e) {
    return { id, title, status: 'error', summary: `Kontrol edilemedi: ${(e as Error).message}` };
  }
}

const checkAssetLinks = (host: string) =>
  jsonAssetCheck(host, '/.well-known/assetlinks.json', 'assetlinks', 'Android Digital Asset Links');
const checkAasa = (host: string) =>
  jsonAssetCheck(host, '/.well-known/apple-app-site-association', 'apple_app_site_association', 'Apple App Site Association');

// ---- subdomain_takeover (CT log derin) ------------------------------------

async function checkCtSubdomains(host: string): Promise<PassiveCheckResult> {
  const id = 'ct_subdomains', title = 'Sertifika Şeffaflığı — Keşfedilen Alt Alan Adları';
  try {
    const domain = apexDomain(host);
    // crt.sh referans allowlist'te; JSON ciktisi. (Not: bu host hstspreload degil ama
    // scope-lock'ta crt.sh zaten allowlist'te — safeGet yalniz hedef/apex/hstspreload'a
    // izin verdiginden burada dogrudan fetch + kendi kapsam notu kullaniyoruz.)
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), HTTP_TIMEOUT_MS);
    let names: string[] = [];
    let queried = false; // crt.sh gercekten JSON dondurebildi mi?
    try {
      const res = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, {
        signal: ctrl.signal, headers: { 'user-agent': 'CyberTestify-PassiveCheck/1.0' },
      });
      const body = await res.text();
      if (res.ok && body.trim().startsWith('[')) {
        queried = true;
        const rows = JSON.parse(body) as Array<{ name_value?: string }>;
        const set = new Set<string>();
        for (const row of rows) {
          for (const n of (row.name_value ?? '').split(/\n/)) {
            const name = n.trim().toLowerCase().replace(/^\*\./, '');
            if (name.endsWith(domain)) set.add(name);
          }
        }
        names = [...set].sort();
      }
    } finally {
      clearTimeout(timer);
    }
    // crt.sh yanit vermediyse/bos dondu ise: "yok" DEME — "sorgulanamadi" (skipped) de.
    if (!queried) return { id, title, status: 'skipped', summary: 'Sertifika Şeffaflığı logu (crt.sh) şu an sorgulanamadı; daha sonra tekrar denenebilir.' };
    if (!names.length) return { id, title, status: 'absent', summary: 'CT loglarında bu domaine ait benzersiz alt alan adı bulunamadı.' };
    const shown = names.slice(0, 100);
    const extra = names.length - shown.length;
    return {
      id, title, status: 'present',
      summary: `Sertifika Şeffaflığı loglarından ${names.length} benzersiz alt alan adı keşfedildi (geçmiş dahil).`,
      details: { count: names.length },
      evidence: extra > 0 ? [...shown, `+${extra} tane daha`] : shown,
    };
  } catch (e) {
    return { id, title, status: 'error', summary: `Kontrol edilemedi: ${(e as Error).message}` };
  }
}

// ---- paket -> kontrol eslemesi + runner -----------------------------------

type CheckFn = (host: string) => Promise<PassiveCheckResult>;

const CHECKS_BY_PACKAGE: Record<string, CheckFn[]> = {
  dns_email: [checkCaa, checkBimi, checkMtaSts, checkTlsRpt],
  header_leak: [checkSecurityTxt, checkHstsPreload, checkMixedContent, checkExposedFiles],
  basit_tarama: [checkRobotsSitemap, checkAssetLinks, checkAasa],
  subdomain_takeover: [checkCtSubdomains],
  // (Yanlis-pozitif fix) iso/pci artik DETERMINISTIK, catch-all-farkinda hassas-dosya
  // kontrolu de alir — ajanin yorumuna ek OTORITE zemin (ISO vs PCI celiskisi tekrarlanmasin).
  pci_hazirlik: [checkExposedFiles],
  iso27001_hazirlik: [checkExposedFiles],
};

export function hasPassiveExtras(packageKey: string): boolean {
  return (CHECKS_BY_PACKAGE[packageKey]?.length ?? 0) > 0;
}

/** Paket icin ek pasif kontrolleri IZOLE calistirir (biri patlarsa digerleri etkilenmez). */
export async function runPassiveExtras(host: string, packageKey: string): Promise<PassiveCheckResult[]> {
  const checks = CHECKS_BY_PACKAGE[packageKey];
  if (!checks?.length) return [];
  const settled = await Promise.allSettled(checks.map((fn) => fn(host)));
  return settled.map((s, i) =>
    s.status === 'fulfilled'
      ? s.value
      : { id: `check_${i}`, title: 'Ek Kontrol', status: 'error' as const, summary: 'Kontrol beklenmedik şekilde başarısız oldu.' },
  );
}

const STATUS_LABEL: Record<PassiveCheckStatus, string> = {
  present: '🟢 Var',
  absent: '⚪ Yok',
  misconfigured: '🟠 Hatalı Yapılandırma',
  error: '⚠️ Kontrol Edilemedi',
  skipped: '⏭️ Atlandı',
};

/** PassiveCheckResult[] -> PDF/markdown "Ek Pasif Kontroller" bolumu (kod-tabanli, notr dil). */
export function renderPassiveExtrasMarkdown(results: PassiveCheckResult[]): string {
  if (!results.length) return '';
  const rows = results
    .map((r) => `| ${r.title} | ${STATUS_LABEL[r.status]} | ${r.summary.replace(/\|/g, '\\|')} |`)
    .join('\n');
  const evidence = results
    .filter((r) => r.evidence?.length)
    .map((r) => {
      const items = r.evidence!.map((e) => `  - \`${e.replace(/`/g, '')}\``).join('\n');
      return `**${r.title}:**\n${items}`;
    })
    .join('\n\n');

  return [
    '## Ek Pasif Kontroller (Otomatik / Kod-tabanlı)',
    '',
    '> Bu bölüm yapay zeka ajanı tarafından DEĞİL, deterministik kod tarafından üretilmiştir; ' +
      'yalnızca dışarıdan gözlemlenebilir kayıtların varlık/yapılandırma durumunu bildirir (bir uyum beyanı değildir).',
    '',
    '| Kontrol | Durum | Özet |',
    '|---------|-------|------|',
    rows,
    evidence ? '\n### Ayrıntılar\n\n' + evidence : '',
  ].join('\n');
}
