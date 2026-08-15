/**
 * (Keşif Paketi — bundle_recon) ORTAK KOD-TABANLI KANIT TOPLAMA — ajana GUVENMEZ.
 *
 * bundle_recon uyeleri (subdomain_takeover, api_discovery, cms_cve) icin veriyi BACKEND
 * KENDISI toplar; PentAGI ajani HIC calismaz (bundle_surface/bundle_compliance deseni):
 *   - subdomain_takeover: crt.sh (Certificate Transparency) + Cloudflare DoH CNAME cozumleme +
 *     sabit "dangling servis imzasi" listesiyle esleme.
 *   - api_discovery: sabit yaygin dokuman yollari + OpenAPI/Swagger JSON parse + hassas uc nokta.
 *   - cms_cve: header/meta/HTML parmak izi (CMS+surum) + NVD API 2.0 (CPE) ile BILINEN CVE listesi.
 *
 * CVE bilgisi ASLA serbest metinden gelmez: yalnizca NVD'nin (NIST) yapisal cevabindan alinir ve
 * her CVE ID'si `CVE-YYYY-NNNN+` regex'i ile dogrulanir. Turkce rapor cumlesini HER ZAMAN kod yazar.
 * Her kontrol ASLA throw ETMEZ (izole); ulasilamayan veri "tespit edilemedi" olur.
 */
import { apexDomain, collectHttp, cachedOriginUrl, collectPages, type HttpEvidence, type PageEvidence } from './surfaceEvidence.js';

const HTTP_TIMEOUT_MS = 9000;
const CRTSH_TIMEOUT_MS = 20000;
const DOH_TIMEOUT_MS = 7000;
const NVD_TIMEOUT_MS = 20000;
const MAX_SUBDOMAINS_RESOLVE = 100; // CNAME cozulecek alt domain ust siniri (envanter/display ile hizali)
const DOH_CONCURRENCY = 12;
const MAX_CVES_LISTED = 12;

// ---- kucuk yardimcilar --------------------------------------------------------------
async function safeGet(url: string, timeoutMs = HTTP_TIMEOUT_MS): Promise<{ ok: boolean; status: number; text: string; contentType: string }> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: ctrl.signal, redirect: 'follow', headers: { 'user-agent': 'CyberTestify-PassiveCheck/1.0', accept: '*/*' } });
    const buf = Buffer.from(await res.arrayBuffer());
    const text = (buf.length > 300_000 ? buf.subarray(0, 300_000) : buf).toString('utf-8');
    return { ok: res.ok, status: res.status, text, contentType: res.headers.get('content-type') ?? '' };
  } catch {
    return { ok: false, status: 0, text: '', contentType: '' };
  } finally {
    clearTimeout(timer);
  }
}

async function doh(name: string, type: string): Promise<{ status: number; answers: Array<{ type: number; data: string }> } | null> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), DOH_TIMEOUT_MS);
  try {
    const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`, {
      signal: ctrl.signal,
      headers: { accept: 'application/dns-json' },
    });
    if (!res.ok) return null;
    const j = (await res.json()) as { Status?: number; Answer?: Array<{ type?: number; data?: string }> };
    return { status: j.Status ?? -1, answers: (j.Answer ?? []).map((a) => ({ type: a.type ?? 0, data: String(a.data ?? '').replace(/\.$/, '') })) };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function pMap<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let idx = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (idx < items.length) {
      const cur = idx++;
      out[cur] = await fn(items[cur]);
    }
  });
  await Promise.all(workers);
  return out;
}

// ======================================================================================
// 1) subdomain_takeover — CT loglari + CNAME + dangling imza
// ======================================================================================
// Bilinen "dangling" (terk edilmis) servis imzalari — can-i-take-over-xyz'den derlenmis alt-set.
// suffix: CNAME hedefinin ait oldugu servis alan-eki; fp: servisin "yok" cevabindaki metin(ler).
const DANGLING_SIGS: Array<{ service: string; suffixes: string[]; fp: string[] }> = [
  { service: 'GitHub Pages', suffixes: ['github.io'], fp: ["There isn't a GitHub Pages site here", 'For root URLs (like http://example.com/) you must provide an index.html file'] },
  { service: 'Heroku', suffixes: ['herokuapp.com', 'herokudns.com'], fp: ['No such app', 'herokucdn.com/error-pages/no-such-app.html'] },
  { service: 'AWS S3', suffixes: ['s3.amazonaws.com', 's3-website', 'amazonaws.com'], fp: ['NoSuchBucket', 'The specified bucket does not exist'] },
  { service: 'Microsoft Azure', suffixes: ['azurewebsites.net', 'cloudapp.azure.com', 'cloudapp.net', 'trafficmanager.net', 'blob.core.windows.net', 'azureedge.net'], fp: ['404 Web Site not found'] },
  { service: 'Fastly', suffixes: ['fastly.net'], fp: ['Fastly error: unknown domain'] },
  { service: 'Shopify', suffixes: ['myshopify.com'], fp: ['Sorry, this shop is currently unavailable', 'Only one step left!'] },
  { service: 'Zendesk', suffixes: ['zendesk.com'], fp: ['Help Center Closed'] },
  { service: 'Surge.sh', suffixes: ['surge.sh'], fp: ['project not found'] },
  { service: 'Bitbucket', suffixes: ['bitbucket.io'], fp: ['Repository not found'] },
  { service: 'Ghost', suffixes: ['ghost.io'], fp: ['The thing you were looking for is no longer here'] },
  { service: 'Netlify', suffixes: ['netlify.app', 'netlify.com'], fp: ['Not Found - Request ID'] },
  { service: 'Pantheon', suffixes: ['pantheonsite.io'], fp: ['The gods are wise', '404 error unknown site'] },
  { service: 'Tumblr', suffixes: ['domains.tumblr.com'], fp: ["Whatever you were looking for doesn't currently exist at this address"] },
  { service: 'WordPress.com', suffixes: ['wordpress.com'], fp: ['Do you want to register'] },
  { service: 'Readme.io', suffixes: ['readme.io'], fp: ["Project doesnt exist... yet!"] },
  { service: 'Unbounce', suffixes: ['unbouncepages.com'], fp: ['The requested URL was not found on this server'] },
  { service: 'Cargo', suffixes: ['cargocollective.com'], fp: ['404 Not Found'] },
  { service: 'Help Scout', suffixes: ['helpscoutdocs.com'], fp: ['No settings were found for this company'] },
  // --- ek servisler (Grok geliştirmesi) — can-i-take-over-xyz'den derlenmiş, gerçek "yok" imzalarıyla ---
  { service: 'Read the Docs', suffixes: ['readthedocs.io', 'readthedocs.org'], fp: ['unknown to Read the Docs', "The page you're looking for could not be found"] },
  { service: 'WP Engine', suffixes: ['wpengine.com'], fp: ["The site you were looking for couldn't be found"] },
  { service: 'Strikingly', suffixes: ['s.strikinglydns.com', 'strikingly.com'], fp: ["But if you're looking to build your own website", 'page not found'] },
  { service: 'Acquia', suffixes: ['acquia-sites.com', 'acsitefactory.com'], fp: ['The site you are looking for could not be found', 'Web Site Not Found'] },
  { service: 'UserVoice', suffixes: ['uservoice.com'], fp: ['This UserVoice subdomain is currently available'] },
  { service: 'Campaign Monitor', suffixes: ['createsend.com'], fp: ['Double check the URL', 'Trying to access your account?'] },
  { service: 'Intercom', suffixes: ['custom.intercom.help'], fp: ['This page is reserved for artistic dogs', "Uh oh. That page doesn't exist"] },
  { service: 'Tilda', suffixes: ['tilda.ws'], fp: ['Please renew your subscription'] },
  { service: 'Webflow', suffixes: ['proxy-ssl.webflow.com', 'proxy.webflow.com'], fp: ["The page you are looking for doesn't exist or has been moved"] },
  { service: 'Wix', suffixes: ['wixdns.net'], fp: ['Error ConnectYourDomain occurred'] },
];

export type DanglingHit = { sub: string; cname: string; service: string; confidence: 'confirmed' | 'suspected'; note: string };
export type SubCnameState = 'dangling' | 'suspected' | 'managed' | 'active' | 'nocname';
export type SubEvidence = {
  ok: boolean;                 // veri kaynagi (CT) gecerli yanit verdi mi (= dataSource==='ok')
  dataSource: 'ok' | 'unavailable'; // 'ok': en az bir CT kaynagi calisti (0 sonuc gercek negatif); 'unavailable': ikisi de erisilemedi
  total: number;               // benzersiz alt domain sayisi
  resolved: number;            // CNAME cozulen sayi
  subdomains: string[];        // bulunan tum alt domainler (rapor envanteri, kapali ust sinir)
  cnames: Array<{ sub: string; cname?: string; state: SubCnameState }>; // cozulen her alt domain + CNAME + durum
  managedCnames: Array<{ sub: string; cname: string; service: string }>; // bilinen servise CNAME (canli — bilgi)
  dangling: DanglingHit[];
};

function matchService(cnameTarget: string): { service: string; fp: string[] } | null {
  const t = cnameTarget.toLowerCase();
  for (const s of DANGLING_SIGS) if (s.suffixes.some((suf) => t.endsWith(suf) || t.includes(suf))) return { service: s.service, fp: s.fp };
  return null;
}

function addName(set: Set<string>, raw: string | undefined, apex: string) {
  if (!raw) return;
  for (const nm of String(raw).split(/\n+/)) {
    const n = nm.trim().toLowerCase().replace(/^\*\./, '');
    if (!n || n.includes(' ') || !n.endsWith(apex) || n === apex) continue;
    set.add(n);
  }
}

// crt.sh (birincil) sik sik 502/timeout/000 doner; basarisizsa certSpotter'a (yedek) dus.
// KRITIK: "gercek 0 sonuc" ile "veri kaynagina ulasilamadi"yi ayirt et -> sourceOk. En az bir
// CT kaynagi GECERLI (2xx + parse-edilebilir JSON dizi) yanit verdiyse sourceOk=true (dizi bos
// olsa bile gercek negatif sonuc). Ikisi de hata/timeout verdiyse sourceOk=false (unavailable).
async function collectCtNames(apex: string): Promise<{ names: string[]; sourceOk: boolean }> {
  const set = new Set<string>();
  let sourceOk = false;
  // 1) crt.sh — birkac kez dene
  for (let attempt = 0; attempt < 3; attempt++) {
    const r = await safeGet(`https://crt.sh/?q=%25.${encodeURIComponent(apex)}&output=json`, CRTSH_TIMEOUT_MS);
    if (r.ok && r.text && /^\s*\[/.test(r.text)) {
      try {
        const arr = JSON.parse(r.text) as Array<{ name_value?: string; common_name?: string }>;
        for (const row of arr) { addName(set, row.name_value, apex); addName(set, row.common_name, apex); }
        sourceOk = true; // gecerli JSON dizi geldi (bos olsa bile gercek sonuc)
      } catch { /* parse hatasi -> yedek */ }
      break;
    }
    if (attempt < 2) await new Promise((res) => setTimeout(res, 1500));
  }
  // 2) crt.sh ise yaramadiysa certSpotter (yedek CT kaynagi)
  if (!sourceOk || set.size === 0) {
    const r = await safeGet(`https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(apex)}&include_subdomains=true&expand=dns_names`, CRTSH_TIMEOUT_MS);
    if (r.ok && r.text && /^\s*\[/.test(r.text)) {
      try {
        const arr = JSON.parse(r.text) as Array<{ dns_names?: string[] }>;
        for (const row of arr) for (const n of row.dns_names ?? []) addName(set, n, apex);
        sourceOk = true;
      } catch { /* yoksay */ }
    }
  }
  return { names: [...set].sort(), sourceOk };
}

export async function collectSubdomains(host: string): Promise<SubEvidence> {
  const apex = apexDomain(host);
  const { names, sourceOk } = await collectCtNames(apex);
  // Veri kaynagina ulasilamadi (crt.sh + certSpotter ikisi de hata/timeout) -> "unavailable".
  // ASLA "0 bulundu / temiz" gibi sunma (Grok A). sourceOk true ise names bos olsa da GERCEK negatif.
  if (!sourceOk) return { ok: false, dataSource: 'unavailable', total: 0, resolved: 0, subdomains: [], cnames: [], managedCnames: [], dangling: [] };

  const toResolve = names.slice(0, MAX_SUBDOMAINS_RESOLVE);
  const cnameResults = await pMap(toResolve, DOH_CONCURRENCY, async (sub) => {
    const r = await doh(sub, 'CNAME');
    const cname = r?.answers.find((a) => a.type === 5)?.data; // type 5 = CNAME
    return { sub, cname };
  });

  const managedCnames: SubEvidence['managedCnames'] = [];
  const dangling: DanglingHit[] = [];
  // Sadece bilinen servise CNAME veren azinlik icin govde/imza kontrolu yap (fetch sayisini sinirlar).
  const candidates = cnameResults.filter((c): c is { sub: string; cname: string } => !!c.cname && !!matchService(c.cname));
  await pMap(candidates, 8, async ({ sub, cname }) => {
    const svc = matchService(cname)!;
    // Hedef CNAME'in A kaydi NXDOMAIN mi? (guclu dangling sinyali)
    const aRec = await doh(cname, 'A');
    const targetNx = aRec?.status === 3; // NXDOMAIN
    const page = await safeGet(`https://${sub}/`);
    const body = page.text;
    const matchedFp = svc.fp.find((f) => body.includes(f));
    if (matchedFp) {
      // (Grok B1) CNAME hedefi + HTTP yanıt imzası KOMBİNASYONU — hangi imzayla eşleştiği kayda geçer.
      dangling.push({ sub, cname, service: svc.service, confidence: 'confirmed', note: `CNAME "${cname}" (${svc.service}) + yanıt gövdesinde devralma imzası eşleşti: "${matchedFp}".` });
    } else if (targetNx) {
      dangling.push({ sub, cname, service: svc.service, confidence: 'suspected', note: `CNAME hedefi (${cname}) çözümlenemiyor (NXDOMAIN); servis kaydı boşta olabilir — manuel doğrulama önerilir.` });
    } else {
      managedCnames.push({ sub, cname, service: svc.service });
    }
  });

  // Cozulen her alt domain icin durum tablosu (yeni fetch YOK — zaten toplanan veriyi tasir).
  const danglingByS = new Map(dangling.map((d) => [d.sub, d.confidence]));
  const managedBySet = new Set(managedCnames.map((m) => m.sub));
  const cnames: SubEvidence['cnames'] = cnameResults.map(({ sub, cname }) => {
    const dc = danglingByS.get(sub);
    const state: SubCnameState = dc === 'confirmed' ? 'dangling' : dc === 'suspected' ? 'suspected' : managedBySet.has(sub) ? 'managed' : cname ? 'active' : 'nocname';
    return { sub, cname, state };
  });

  return {
    ok: true,
    dataSource: 'ok',
    total: names.length,
    resolved: toResolve.length,
    subdomains: names.slice(0, 100),
    cnames,
    managedCnames,
    dangling,
  };
}

// ======================================================================================
// 2) api_discovery — yaygin dokuman yollari + OpenAPI/Swagger parse
// ======================================================================================
const API_PATHS = ['/openapi.json', '/swagger.json', '/v2/api-docs', '/v3/api-docs', '/api-docs', '/api/docs', '/api/v1/docs', '/swagger-ui.html', '/swagger/index.html', '/redoc', '/.well-known/openapi.json', '/graphql'];
const SENSITIVE_RE = /(admin|internal|debug|token|secret|password|passwd|credential|export|dump|backup|user|account|payment|invoice|upload|delete|drop|config|env|key)/i;
// (Grok B2) admin/debug/internal isimli uc noktalar AYRI isaretlenir (genel "hassas"tan daha yuksek dikkat).
const ADMIN_RE = /(admin|debug|internal|sysadmin|superuser|root|manage|console|actuator)/i;

export type ApiSpec = { path: string; title?: string; version?: string; endpointCount: number; sensitive: Array<{ method: string; path: string; noAuth: boolean; adminLike: boolean }>; hasGlobalAuth: boolean };
export type ApiEvidence = {
  ok: boolean;
  tried: Array<{ path: string; status: number }>; // denenen TUM yollar + HTTP durumu (rapor tam-liste tablosu)
  reachable: Array<{ path: string; status: number; kind: 'spec' | 'ui' | 'graphql' }>;
  spec?: ApiSpec;
  // (BÖLÜM 1 — SİTE HARİTASI BESLEMESİ) collectPages'in bulduğu sayfalardan çıkarılan aday yollar.
  pagesScanned: number;                 // keşif için değerlendirilen benzersiz sayfa
  minedTried: Array<{ path: string; source: string; status: number; sensitive: boolean }>; // site-haritasından türeyen + denenen adaylar
};

// (BÖLÜM 1) Keşfedilen sayfaların link/script/form referanslarından API + idari-görünümlü YOL ADAYLARINI
// çıkar (kaynağıyla birlikte). PASİF: yalnız string çıkarımı; payload YOK. Aday YOLLARIN VARLIĞI sonradan
// GET ile denenir (Keşif'in kendi "bu uç var mı" tespiti — Dış Yüzey'in dosya-içerik kontrolü DEĞİL).
const API_LIKE_RE = /^\/(?:api|rest|v\d+|graphql|swagger|openapi|oauth|auth|gateway)(?:\/|$|\.)/i;
export function minePathCandidatesFromPages(pages: PageEvidence[], host: string): Array<{ path: string; source: string; sensitive: boolean; api: boolean }> {
  const out = new Map<string, { path: string; source: string; sensitive: boolean; api: boolean }>();
  const hostBare = host.replace(/^www\./, '');
  const consider = (raw: string, sourcePath: string) => {
    if (!raw || out.size >= 20) return;
    let p: string;
    try { const u = new URL(raw, `http://${host}/`); if (u.hostname.replace(/^www\./, '') !== hostBare) return; p = u.pathname; } catch { return; }
    if (!p.startsWith('/') || p.length < 2 || p.length > 80 || /[{}<>*\s]|\.\.|:[a-z]/i.test(p)) return;
    const api = API_LIKE_RE.test(p);
    const sensitive = SENSITIVE_RE.test(p);
    if (!api && !sensitive) return; // yalnız API veya idari-görünümlü yollar (gürültü değil)
    const key = p.replace(/\/+$/, '');
    if (!out.has(key)) out.set(key, { path: p, source: sourcePath, sensitive, api });
  };
  for (const pg of pages) {
    let src = '/'; try { src = new URL(pg.url).pathname; } catch { /* */ }
    for (const m of pg.html.matchAll(/(?:href|src|action)\s*=\s*["']([^"'#?]+)/gi)) consider(m[1].replace(/&amp;/g, '&'), src);
    for (const m of pg.html.matchAll(/["'`](\/(?:api|rest|v\d+|graphql|admin|internal)[\w/.-]*)["'`]/gi)) consider(m[1], src); // inline script string literalleri
  }
  return [...out.values()].slice(0, 15);
}

function parseOpenApi(path: string, json: unknown): ApiSpec | null {
  const doc = json as Record<string, any>;
  if (!doc || typeof doc !== 'object') return null;
  const isOpenApi = 'openapi' in doc || 'swagger' in doc || 'paths' in doc;
  if (!isOpenApi) return null;
  const info = (doc.info ?? {}) as { title?: string; version?: string };
  const paths = (doc.paths ?? {}) as Record<string, Record<string, any>>;
  const hasGlobalAuth = Array.isArray(doc.security) && doc.security.length > 0;
  const sensitive: ApiSpec['sensitive'] = [];
  let endpointCount = 0;
  for (const [p, methods] of Object.entries(paths)) {
    if (!methods || typeof methods !== 'object') continue;
    for (const [m, op] of Object.entries(methods)) {
      if (!/^(get|post|put|patch|delete|options|head)$/i.test(m)) continue;
      endpointCount++;
      const opSec = op && typeof op === 'object' ? (op as any).security : undefined;
      const opHasAuth = Array.isArray(opSec) ? opSec.length > 0 : hasGlobalAuth;
      const opId = String((op as any)?.operationId ?? '');
      if (SENSITIVE_RE.test(p) || SENSITIVE_RE.test(opId)) {
        sensitive.push({ method: m.toUpperCase(), path: p, noAuth: !opHasAuth, adminLike: ADMIN_RE.test(p) || ADMIN_RE.test(opId) });
      }
    }
  }
  return { path, title: info.title, version: info.version, endpointCount, sensitive: sensitive.slice(0, 40), hasGlobalAuth };
}

export async function collectApi(host: string, mined: Array<{ path: string; source: string; sensitive: boolean; api: boolean }> = [], pagesScanned = 1): Promise<ApiEvidence> {
  const results = await pMap(API_PATHS, 8, async (path) => {
    const r = await safeGet(`${cachedOriginUrl(host)}${path}`);
    return { path, r };
  });
  const reachable: ApiEvidence['reachable'] = [];
  let spec: ApiSpec | undefined;
  let anyOk = false;
  // (BÖLÜM 1) Site-haritasından türeyen adayları da dene (varlık/durum + api-benzeri ise şema parse).
  const minedTried: ApiEvidence['minedTried'] = [];
  const minedProbe = await pMap(mined, 6, async (c) => ({ c, r: await safeGet(`${cachedOriginUrl(host)}${c.path}`) }));
  for (const { c, r } of minedProbe) {
    if (r.status > 0) anyOk = true;
    minedTried.push({ path: c.path, source: c.source, status: r.status, sensitive: c.sensitive });
    if (c.api && r.status === 200 && r.text) {
      const looksJson = r.contentType.includes('json') || /^\s*[{[]/.test(r.text);
      if (looksJson) { let j: unknown; try { j = JSON.parse(r.text); } catch { j = null; } const parsed = j ? parseOpenApi(c.path, j) : null; if (parsed) { reachable.push({ path: c.path, status: r.status, kind: 'spec' }); if (!spec || parsed.endpointCount > spec.endpointCount) spec = parsed; } }
    }
  }
  for (const { path, r } of results) {
    if (r.status > 0) anyOk = true;
    if (r.status !== 200 || !r.text) continue;
    const looksJson = r.contentType.includes('json') || /^\s*[{[]/.test(r.text);
    if (looksJson) {
      let json: unknown;
      try { json = JSON.parse(r.text); } catch { json = null; }
      const parsed = json ? parseOpenApi(path, json) : null;
      if (parsed) {
        reachable.push({ path, status: r.status, kind: 'spec' });
        if (!spec || parsed.endpointCount > spec.endpointCount) spec = parsed;
        continue;
      }
    }
    if (path === '/graphql') {
      // Yanlis pozitif kaciniyoruz: SPA catch-all (HTML) "data" kelimesi icerebilir. Sadece GERCEK
      // GraphQL yaniti isaretle -> JSON govde + GraphQL'e ozgu imza (__schema / data|errors alani /
      // "must provide query" tipi hata). HTML (<...>) ile baslayan yanit ASLA sayilmaz.
      const isHtml = /^\s*</.test(r.text);
      const jsonish = r.contentType.includes('json') || /^\s*\{/.test(r.text);
      if (!isHtml && jsonish && /"__schema"|"data"\s*:|"errors"\s*:|must provide (a )?query|GraphQL/i.test(r.text)) {
        reachable.push({ path, status: r.status, kind: 'graphql' });
      }
      continue;
    }
    // Swagger/ReDoc arayuzu — HTML icinde arayuze ozgu isaret. Genel SPA sayfasi elenir.
    if (/swagger-ui|swaggerui|redoc|openapi|api documentation|swagger\.json|api-docs/i.test(r.text)) reachable.push({ path, status: r.status, kind: 'ui' });
  }
  const tried = results.map(({ path, r }) => ({ path, status: r.status }));
  return { ok: anyOk, tried, reachable, spec, pagesScanned, minedTried };
}

// ======================================================================================
// 3) cms_cve — parmak izi (CMS+surum) + NVD (CPE) ile BILINEN CVE
// ======================================================================================
const CVE_ID_RE = /^CVE-\d{4}-\d{4,}$/;
// CMS -> NVD CPE vendor:product (URL-encoded parca). Joomla! product'i "joomla\!" (%5C%21).
const CMS_CPE: Record<string, string> = {
  WordPress: 'wordpress:wordpress',
  Joomla: 'joomla:joomla%5C%21',
  Drupal: 'drupal:drupal',
  TYPO3: 'typo3:typo3',
  Magento: 'magento:magento',
  PrestaShop: 'prestashop:prestashop',
  MediaWiki: 'mediawiki:mediawiki',
};

export type CveItem = { id: string; severity: string; score: number; summary: string };
export type CmsEvidence = {
  ok: boolean;             // ana sayfa cekildi mi
  cms?: string;
  version?: string;
  evidence: string[];      // tespit gerekcesi
  extras: string[];        // WooCommerce, jQuery vb.
  cpeQueried?: string;     // NVD'ye sorulan CPE (varsa)
  cveOk: boolean;          // NVD ulasildi mi
  cveTotal: number;        // NVD'de eslesen toplam
  cves: CveItem[];         // ciddiyet'e gore siralanmis ilk N
};

function detectCms(http: HttpEvidence): { cms?: string; version?: string; evidence: string[]; extras: string[] } {
  const html = http.html;
  const evidence: string[] = [];
  const extras: string[] = [];
  let cms: string | undefined;
  let version: string | undefined;

  const gen = html.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i)?.[1];
  const xgen = http.headers.get('x-generator');
  const xpb = http.headers.get('x-powered-by');

  const genStr = [gen, xgen].filter(Boolean).join(' ');
  if (/wordpress/i.test(genStr) || /\/wp-(content|includes)\//i.test(html)) {
    cms = 'WordPress';
    evidence.push(gen && /wordpress/i.test(gen) ? `Meta generator: "${gen}"` : '/wp-content/ veya /wp-includes/ yolları HTML’de görüldü');
    version = genStr.match(/wordpress\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i)?.[1];
  } else if (/joomla/i.test(genStr) || /\/media\/(jui|system)\//i.test(html) || /option=com_/i.test(html)) {
    cms = 'Joomla';
    evidence.push(gen && /joomla/i.test(gen) ? `Meta generator: "${gen}"` : 'Joomla’ya özgü yollar/parametreler HTML’de görüldü');
    version = genStr.match(/joomla!?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i)?.[1];
  } else if (/drupal/i.test(genStr) || /Drupal\.settings|\/sites\/(all|default)\//i.test(html) || http.headers.has('x-drupal-cache') || http.headers.has('x-drupal-dynamic-cache')) {
    cms = 'Drupal';
    evidence.push(gen && /drupal/i.test(gen) ? `Meta generator: "${gen}"` : 'Drupal’a özgü izler (Drupal.settings / /sites/ / X-Drupal-* başlığı) görüldü');
    version = genStr.match(/drupal\s*([0-9]+(?:\.[0-9]+)*)/i)?.[1];
  } else if (/typo3/i.test(genStr) || /typo3conf|typo3temp/i.test(html)) {
    cms = 'TYPO3'; evidence.push('TYPO3 izleri görüldü'); version = genStr.match(/typo3\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i)?.[1];
  } else if (/magento/i.test(genStr) || /\/static\/version\d|Magento_/i.test(html) || http.headers.has('x-magento-cache-debug')) {
    cms = 'Magento'; evidence.push('Magento izleri görüldü');
  } else if (/prestashop/i.test(genStr) || /prestashop/i.test(html)) {
    cms = 'PrestaShop'; evidence.push('PrestaShop izleri görüldü'); version = genStr.match(/prestashop\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i)?.[1];
  } else if (/mediawiki/i.test(genStr)) {
    cms = 'MediaWiki'; evidence.push(`Meta generator: "${gen}"`); version = genStr.match(/mediawiki\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i)?.[1];
  }

  // Eklenti/kutuphane ipuclari (bilgi amacli)
  if (/woocommerce/i.test(html)) extras.push('WooCommerce (WordPress e-ticaret eklentisi) tespit edildi');
  if (xpb) extras.push(`X-Powered-By: ${xpb}`);
  const jq = html.match(/jquery[.-]?([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.js/i)?.[1];
  if (jq) extras.push(`jQuery ${jq}`);
  const server = http.headers.get('server');
  if (server) extras.push(`Server: ${server}`);

  return { cms, version, evidence, extras };
}

// meta generator'da surum yoksa yaygin surum dosyalarini dene (bir ek fetch, deterministik).
async function sniffVersion(host: string, cms: string): Promise<string | undefined> {
  if (cms === 'WordPress') {
    const r = await safeGet(`${cachedOriginUrl(host)}/readme.html`);
    if (r.status === 200) return r.text.match(/Version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i)?.[1];
  } else if (cms === 'Drupal') {
    const r = await safeGet(`${cachedOriginUrl(host)}/CHANGELOG.txt`);
    if (r.status === 200) return r.text.match(/Drupal\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?),/i)?.[1];
  }
  return undefined;
}

// (Grok B3) CMS parmak izi zayifsa (generator/HTML gizlenmis) — BILINEN CMS yollarinin VARLIGINI
// dene. KIRMIZI CIZGI: yalniz GET + govde imzasi (existence) — LOGIN/POST/parola DENEMESI YOK.
// Yanit govdesindeki CMS'e ozgu imza ile dogrular (tek basina 200 yetmez -> catch-all yanlis-poziti onler).
const CMS_PATH_SIGS: Array<{ cms: string; paths: string[]; bodyRe: RegExp }> = [
  { cms: 'WordPress', paths: ['/wp-login.php', '/wp-json/'], bodyRe: /wordpress|wp-submit|user_login|"namespace":\s*"wp\/v2"|\/wp-includes\//i },
  { cms: 'Joomla', paths: ['/administrator/'], bodyRe: /joomla|com_login|mod-login|option=com_/i },
  { cms: 'Drupal', paths: ['/user/login', '/core/CHANGELOG.txt'], bodyRe: /drupal|user-login-form|form_id"\s+value="user_login|Drupal\.settings/i },
  { cms: 'Magento', paths: ['/admin/', '/downloader/'], bodyRe: /magento|mage\/|Magento_|Magento Downloader/i },
  { cms: 'TYPO3', paths: ['/typo3/'], bodyRe: /typo3/i },
];

async function sniffCmsByPaths(host: string): Promise<{ cms?: string; evidence?: string }> {
  for (const sig of CMS_PATH_SIGS) {
    for (const p of sig.paths) {
      const r = await safeGet(`${cachedOriginUrl(host)}${p}`);
      // 200/401/403 (mevcut ama korumali da olabilir) + govde CMS imzasi -> VARLIK dogrulandi.
      if ((r.status === 200 || r.status === 401 || r.status === 403) && sig.bodyRe.test(r.text)) {
        return { cms: sig.cms, evidence: `${sig.cms}'e özgü yol mevcut ve içerik imzası eşleşti: \`${p}\` (yalnız varlık kontrolü — giriş/parola denemesi yapılmadı)` };
      }
    }
  }
  return {};
}

// Kaba surum karsilastirma (RC/beta ekleri sayisal parcaya indirgenir).
function vParts(v: string): number[] { return v.split(/[^0-9]+/).filter(Boolean).map(Number); }
function vCmp(a: string, b: string): number {
  const A = vParts(a), B = vParts(b);
  for (let i = 0; i < Math.max(A.length, B.length); i++) { const x = A[i] ?? 0, y = B[i] ?? 0; if (x !== y) return x < y ? -1 : 1; }
  return 0;
}
// Bu cpeMatch, tespit edilen surumu ACIKCA SINIRLANMIS bir araligla (veya birebir surumle) kapsiyor mu?
// Surumsuz "tum surumler" (wildcard) eslesmeleri HARIC — bunlar eski/kesin-olmayan CPE verisidir ve
// guncel bir surum icin yanlis pozitif uretir ( or. WordPress 6.x'e 2009 CVE'si dusmesi).
function cpeMatchCoversVersion(cm: any, ver: string): boolean {
  if (!cm || cm.vulnerable === false) return false;
  const sI = cm.versionStartIncluding, sE = cm.versionStartExcluding, eI = cm.versionEndIncluding, eE = cm.versionEndExcluding;
  const hasBound = sI || sE || eI || eE;
  if (hasBound) {
    if (sI && vCmp(ver, sI) < 0) return false;
    if (sE && vCmp(ver, sE) <= 0) return false;
    if (eI && vCmp(ver, eI) > 0) return false;
    if (eE && vCmp(ver, eE) >= 0) return false;
    return true;
  }
  // Aralik yok: yalniz criteria'daki BIREBIR surum eslesirse kabul (wildcard '*'/'-' -> haric).
  const cver = String(cm.criteria ?? '').split(':')[5] ?? '';
  return cver !== '' && cver !== '*' && cver !== '-' && vCmp(cver, ver) === 0;
}
function cveCoversVersion(cve: any, prodDecoded: string, ver: string): boolean {
  const needle = `:a:${prodDecoded}:`;
  for (const conf of (cve.configurations ?? []) as any[]) {
    for (const node of (conf.nodes ?? []) as any[]) {
      for (const cm of (node.cpeMatch ?? []) as any[]) {
        if (String(cm.criteria ?? '').includes(needle) && cpeMatchCoversVersion(cm, ver)) return true;
      }
    }
  }
  return false;
}

async function nvdLookup(cpeProdEnc: string, version: string): Promise<{ ok: boolean; total: number; cves: CveItem[] }> {
  const cpe = `cpe:2.3:a:${cpeProdEnc}:${encodeURIComponent(version)}:*:*:*:*:*:*:*`;
  const r = await safeGet(`https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=${cpe}&resultsPerPage=200`, NVD_TIMEOUT_MS);
  if (!r.ok || !r.text) return { ok: false, total: 0, cves: [] };
  let j: any;
  try { j = JSON.parse(r.text); } catch { return { ok: false, total: 0, cves: [] }; }
  const prodDecoded = decodeURIComponent(cpeProdEnc); // 'wordpress:wordpress' / 'joomla:joomla\!'
  const items: CveItem[] = [];
  for (const v of (j.vulnerabilities ?? []) as any[]) {
    const c = v?.cve;
    const id = String(c?.id ?? '');
    if (!CVE_ID_RE.test(id)) continue; // format-dogrulama (bozuk kayit koruması)
    // Surumu ACIKCA sinirlanmis araliktan kapsamayan (wildcard/tum-surum) kayitlari ELE — yanlis pozitif.
    if (!cveCoversVersion(c, prodDecoded, version)) continue;
    let severity = 'UNKNOWN';
    let score = 0;
    const m = c.metrics ?? {};
    for (const k of ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']) {
      if (Array.isArray(m[k]) && m[k][0]) {
        const cd = m[k][0].cvssData ?? {};
        severity = (cd.baseSeverity ?? m[k][0].baseSeverity ?? 'UNKNOWN').toString().toUpperCase();
        score = Number(cd.baseScore ?? 0);
        break;
      }
    }
    const summary = (Array.isArray(c.descriptions) ? c.descriptions.find((d: any) => d.lang === 'en')?.value : '') ?? '';
    items.push({ id, severity, score, summary: summary.slice(0, 180) });
  }
  items.sort((a, b) => b.score - a.score);
  // total = surum-dogrulanmis (filtrelenmis) sayi; ham NVD toplamindan farkli olabilir (kasitli).
  return { ok: true, total: items.length, cves: items.slice(0, MAX_CVES_LISTED) };
}

export async function collectCms(host: string, http?: HttpEvidence): Promise<CmsEvidence> {
  const page = http ?? (await collectHttp(host));
  if (!page.ok) return { ok: false, evidence: [], extras: [], cveOk: false, cveTotal: 0, cves: [] };
  const det = detectCms(page);
  let cms = det.cms;
  let version = det.version;
  const extras = det.extras;
  const evidence = [...det.evidence];
  // (Grok B3) Ana sayfa/HTML parmak izi CMS vermediyse: bilinen CMS yollarının VARLIĞIYLA doğrula
  // (yalnız GET/existence — login denemesi YOK). Generator gizlenmiş kurulumları yakalar.
  if (!cms) {
    const byPath = await sniffCmsByPaths(host).catch(() => ({} as { cms?: string; evidence?: string }));
    if (byPath.cms) { cms = byPath.cms; if (byPath.evidence) evidence.push(byPath.evidence); }
  }
  if (cms && !version) version = await sniffVersion(host, cms).catch(() => undefined);

  let cveOk = false; let cveTotal = 0; let cves: CveItem[] = []; let cpeQueried: string | undefined;
  if (cms && version && CMS_CPE[cms]) {
    cpeQueried = `${CMS_CPE[cms]}:${version}`;
    const res = await nvdLookup(CMS_CPE[cms], version);
    cveOk = res.ok; cveTotal = res.total; cves = res.cves;
  }
  return { ok: true, cms, version, evidence, extras, cpeQueried, cveOk, cveTotal, cves };
}

// ======================================================================================
// TUM KESIF KANITI (tek noktadan; uc alan paralel)
// ======================================================================================
export type ReconEvidence = { host: string; sub: SubEvidence; api: ApiEvidence; cms: CmsEvidence };

export async function collectReconEvidence(host: string): Promise<ReconEvidence> {
  const http = await collectHttp(host);
  // (BÖLÜM 1) PAYLAŞILAN site haritası (in-flight cache — Dış Yüzey/Uyum ile AYNI crawl, tekrar GET seli
  // YOK) -> API/idari-görünümlü yol adaylarını çıkar ve API/Swagger keşfini ZENGİNLEŞTİR (sabit listeye EK).
  const pages = await collectPages(host).catch(() => [] as PageEvidence[]);
  const mined = minePathCandidatesFromPages(pages, host);
  const [sub, api, cms] = await Promise.all([
    collectSubdomains(host).catch(() => ({ ok: false, dataSource: 'unavailable', total: 0, resolved: 0, subdomains: [], cnames: [], managedCnames: [], dangling: [] } as SubEvidence)),
    collectApi(host, mined, Math.max(1, pages.length)).catch(() => ({ ok: false, tried: [], reachable: [], pagesScanned: Math.max(1, pages.length), minedTried: [] } as ApiEvidence)),
    collectCms(host, http).catch(() => ({ ok: false, evidence: [], extras: [], cveOk: false, cveTotal: 0, cves: [] } as CmsEvidence)),
  ]);
  return { host, sub, api, cms };
}
