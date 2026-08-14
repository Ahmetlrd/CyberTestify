/**
 * (Aktif Doğrulama — injection_verify + idor_verify) KOD-TABANLI AKTIF PROB MOTORU.
 *
 * "Kanıtla, istismar etme" ilkesi KOD SEVIYESINDE: backend hedefe SINIRLI, zararsiz probe'lar
 * gonderip yalnizca VARLIK KANITI toplar (veri cekmez, yazmaz, silmez). PentAGI ajani HIC calismaz
 * (bundle_surface deseni) — Turkce rapor metnini activeVerifyReports.ts yazar.
 *
 * GUVENLIK (hedefi koru — E maddesi):
 *  - Input noktasi basina az sayida probe; istekler arasi min gecikme (DoS'lamamak icin).
 *  - Devre kesici: art arda 5+ 5xx -> DUR (form-POST agresifligi icin 3'ten 5'e cekildi; hedefin
 *    GERCEKTEN cokmesini onleyecek alt sinir KORUNUR); yanit suresi baseline'in 3 katini asarsa -> DUR
 *    (zaman-tabanli SQLi probe'u HARIC — orada gecikme zaten beklenen kanit); 429/WAF-blok -> DUR.
 *  - Yalniz hedef host; harici host'a ASLA istek yok; redirect izlenmez.
 *  - SQLi: yalniz tek-tirnak (hata imzasi) + tek zaman-tabanli dogrulama. Veri cekme YOK.
 *  - XSS: yalniz benzersiz zararsiz isaret; JS calistirma YOK, stored XSS denenmez.
 *  - IDOR: yalniz GET; komsu ID; DONEN VERI SAKLANMAZ (sadece uzunluk/hash/durum karsilastirilir).
 */
import { randomBytes, createHash } from 'node:crypto';
import puppeteer from 'puppeteer-core';
import { collectHttp, resolveOrigin, cachedOriginUrl } from './surfaceEvidence.js';
import { requestAgentScenarios, type AgentSuggestion } from './agentAdvisor.js';
import { type AuthSession, applyAuthHeaders } from './authSession.js';
import { logScanStep } from './scanLogger.js';

// Headless render (SPA keşfi) — PDF üretimiyle AYNI sistem Chromium'unu kullanır (ek kurulum yok).
const CHROMIUM_PATH = process.env.PUPPETEER_EXECUTABLE_PATH || '/usr/bin/chromium-browser';
const HEADLESS_PAGE_TIMEOUT_MS = 10000;   // sayfa basina sert timeout
const HEADLESS_MAX_PAGES = 8;             // headless'te taranacak sayfa ust siniri (perf)
const MAX_CONCURRENT_HEADLESS = 3;        // es zamanli tarayici instance ust siniri (kaynak korumasi)
const HEADLESS_PRECHECK_TIMEOUT_MS = 6000; // odeme-oncesi TEK-sayfa on-kontrol icin daha kisa timeout

const MIN_DELAY_MS = 1200;         // istekler arasi min bekleme (hedefi yormamak)
const REQ_TIMEOUT_MS = 10000;
const MAX_INPUTS = 6;              // taranacak input noktasi ust siniri (statik kesif ic havuz)
const MAX_PROBES_PER_CHECK = 280;  // kontrol basina TOPLAM prob tavani (form-POST agresiflik + payload cesitliligi icin 220->280; bu bir IS TAVANI, zarar-koruma DEGIL — asil koruma 5xx/yavaslama/429 devre kesici)
const SLOW_FACTOR = 3;             // baseline * 3'u asan yanit -> devre kesici (zaman-tabanli haric)
const SLOW_FLOOR_MS = 2500;        // baseline cok kucukse gurultuden kacinmak icin taban
const TIME_PROBE_DELAY_S = 3;      // zaman-tabanli SQLi gecikme saniyesi

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// ---- Probe motoru + devre kesici ---------------------------------------------------
type ProbeResult = { status: number; ms: number; text: string; len: number };
export class ProbeCtx {
  baseline = 0;
  consec5xx = 0;
  stopped: string | null = null;
  sent = 0;
  // (FAZ C) authenticated bağlam: verilirse HER probe'a Cookie/Authorization eklenir (session-aware).
  authHeaders?: Record<string, string>;
  // (GÖZLEMLENEBİLİRLİK) log adımı adı (hangi kontrol probe atıyor). Collector set eder (ör. "Enjeksiyon Doğrulama").
  label = 'Aktif prob';
  private last = 0;
  async fetchOnce(url: string, opts: { method?: 'GET' | 'POST'; body?: string; contentType?: string; expectSlow?: boolean } = {}): Promise<ProbeResult | null> {
    if (this.stopped) return null;
    if (this.sent >= MAX_PROBES_PER_CHECK) {
      this.stopped = `Toplam prob üst sınırına (${MAX_PROBES_PER_CHECK}) ulaşıldı — otomatik durduruldu.`;
      logScanStep({ step: this.label, level: 'circuit_breaker', summary: this.stopped });
      return null;
    }
    const wait = MIN_DELAY_MS - (Date.now() - this.last);
    if (wait > 0) await sleep(wait);
    this.last = Date.now();
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), REQ_TIMEOUT_MS);
    const t0 = Date.now();
    try {
      const headers: Record<string, string> = { 'user-agent': 'CyberTestify-ActiveVerify/1.0', accept: 'text/html,*/*' };
      if (opts.contentType) headers['content-type'] = opts.contentType;
      if (this.authHeaders) Object.assign(headers, this.authHeaders); // (FAZ C) authenticated probe
      const res = await fetch(url, { method: opts.method ?? 'GET', body: opts.body, headers, redirect: 'manual', signal: ctrl.signal });
      const ms = Date.now() - t0;
      this.sent++;
      const buf = Buffer.from(await res.arrayBuffer());
      const text = (buf.length > 200_000 ? buf.subarray(0, 200_000) : buf).toString('utf-8');
      // --- Devre kesici degerlendirmesi ---
      if (res.status >= 500) { this.consec5xx++; if (this.consec5xx >= 5) this.stopped = 'Hedef art arda 5+ kez 5xx döndürdü (hedefe zarar veriyor olabiliriz — otomatik durduruldu).'; }
      else this.consec5xx = 0;
      if (res.status === 429) this.stopped = 'Hedef 429 (hız sınırı) döndürdü — otomatik durduruldu.';
      if (res.status === 403 && /cloudflare|access denied|request blocked|web application firewall|mod_security|incapsula|sucuri|forbidden/i.test(text)) this.stopped = 'WAF/güvenlik duvarı bloğu (403) algılandı — bu kontrol durduruldu.';
      if (!opts.expectSlow && this.baseline > 0 && ms > SLOW_FACTOR * this.baseline && ms > SLOW_FLOOR_MS) this.stopped = `Yanıt süresi baseline'ın ${SLOW_FACTOR} katını aştı (hedef yavaşlıyor — otomatik durduruldu).`;
      // (GÖZLEMLENEBİLİRLİK) her prob: method+URL (maskeli) + status + süre + boyut. body loglanmaz.
      logScanStep({ step: this.label, method: opts.method ?? 'GET', url, status: res.status, durationMs: ms, sizeBytes: buf.length, level: this.stopped ? 'circuit_breaker' : res.status >= 500 ? 'warn' : 'info', summary: this.stopped ?? undefined });
      return { status: res.status, ms, text, len: buf.length };
    } catch (err) {
      this.sent++;
      const ms = Date.now() - t0;
      logScanStep({ step: this.label, method: opts.method ?? 'GET', url, status: 0, durationMs: ms, level: 'error', summary: `İstek hatası: ${String((err as Error)?.name ?? 'err')}` });
      return { status: 0, ms, text: '', len: 0 };
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
    const u = raw.startsWith('http') ? new URL(raw) : new URL(raw, `${cachedOriginUrl(host)}/`);
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
// (FORM-POST GÜVENLİK KAPISI) Gerçek POST göndermeden ÖNCE formu sınıflandır. Kalıcı/geri-alınamaz
// yan etki üreten form TÜRLERİNE (yorum/iletişim/kayıt/parola-sıfırlama/ödeme/abonelik) ASLA POST
// gönderilmez — bunlar müşteriye/üçüncü kişiye gerçek kayıt/e-posta/hesap/finansal etki yaratır.
// login/arama/filtre ve bu listeye GİRMEYEN formlar test edilebilir. Muğlaksa GÜVENLİ tarafta kal.
// ======================================================================================
export type FormCategory = 'login' | 'search' | 'other' | 'comment' | 'contact' | 'signup' | 'password_reset' | 'payment' | 'subscribe';
const FORBIDDEN_FORM_CATS = new Set<FormCategory>(['comment', 'contact', 'signup', 'password_reset', 'payment', 'subscribe']);
const FORBIDDEN_REASON: Record<string, string> = {
  comment: 'yorum/mesaj yayınlama (kalıcı içerik oluşturur)',
  contact: 'iletişim formu (gerçek e-posta gönderir)',
  signup: 'kayıt/hesap oluşturma (kalıcı hesap oluşturur)',
  password_reset: 'parola sıfırlama (gerçek kullanıcıya e-posta/SMS tetikler)',
  payment: 'sepet/ödeme/checkout (finansal etki)',
  subscribe: 'abonelik/bülten (kalıcı kayıt + e-posta)',
};
// Ortak kapı: form YASAK türe giriyorsa okunur sebep, değilse null (POST'a izin var).
export function forbiddenFormReason(action: string, fields: string[]): string | null {
  const cat = formCategory(action, fields);
  return FORBIDDEN_FORM_CATS.has(cat) ? (FORBIDDEN_REASON[cat] ?? cat) : null;
}
export function formCategory(action: string, fields: string[]): FormCategory {
  const hay = (action + ' ' + fields.join(' ')).toLowerCase();
  const has = (re: RegExp) => re.test(hay);
  const hasPw = fields.some((f) => /pass|sifre|şifre|pwd/i.test(f));
  // Sıra ÖNEMLİ: en riskli/özgül kalıplar önce (forgot-password login'e benzeyebilir).
  if (has(/forgot|reset|recover|sifre.?sifirla|şifre.?sıfırla|password.?reset|lost.?password|unuttu/)) return 'password_reset';
  if (has(/checkout|\bcart\b|sepet|basket|\bpay\b|payment|odeme|ödeme|billing|fatura|\border\b|sipari[sş]|credit.?card|kredi.?kart|iban/)) return 'payment';
  if (has(/comment|yorum|review|degerlendir|değerlendir|feedback|guestbook|rating|\breply\b|geri.?bildirim|contact.?us/)) return 'comment';
  if (has(/subscribe|newsletter|abone|bulten|bülten|mailing.?list/)) return 'subscribe';
  if (has(/signup|sign.?up|register|kayit|kayıt|create.?account|hesap.?olustur|hesap.?oluştur|\bjoin\b|uye.?ol|üye.?ol/)) return 'signup';
  // parola + (tekrar/e-posta) alanı + login DEĞİLSE -> kayıt formu (hesap oluşturur).
  if (hasPw && fields.some((f) => /confirm|repeat|again|tekrar|email|e-?posta|mail/i.test(f)) && !has(/login|signin|sign.?in|giris|giriş|logon/)) return 'signup';
  if (has(/contact|iletisim|iletişim|message|mesaj/) && fields.some((f) => /email|e-?posta|mail|subject|konu|message|mesaj/i.test(f))) return 'contact';
  // (İş A) Action yolu NET bir login ucu ise (parola alanı görünmese bile — çok adımlı/SPA login,
  // ör. önce yalnız kullanıcı adı istenen akış), signup DEĞİLSE login say. Login mass-assign hedefi değildir.
  if (has(/\/(login|signin|sign-in|log-in|logon|auth\/login)(\b|\/|\?|$)/) && !has(/signup|sign-?up|register|kayit|kayıt/)) return 'login';
  // login: parola alanı + login-benzeri eylem/kullanıcı alanı. Bypass testi GÜVENLİ (kayıt oluşturmaz).
  if (hasPw && (has(/login|signin|sign.?in|giris|giriş|logon|authenticate|oturum|logon/) || fields.some((f) => /user|kullanic|kullanıc|email|login|logon/i.test(f)))) return 'login';
  if (fields.some((f) => /^(q|s|query|search|ara|arama|keyword|kelime|term|filter|filtre|sort|siralama|sıralama|category|kategori)$/i.test(f)) || has(/search|\bara\b|filter|filtre|sorgu/)) return 'search';
  return 'other';
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
const WELL_KNOWN_PATHS = ['/search?q=cybertestify', '/contact', '/login', '/register', '/api/', '/products?id=1', '/urun?id=1', '/?id=1',
  // (A) REST/API koleksiyon kalıpları — jenerik, hedefe özel DEĞİL; yalnız GET. Link olmayan
  // API backend'lerinde uç keşfini artırır. Sabit-liste; CRAWL_HARD_CAP ve devre-kesici DEĞİŞMEZ.
  '/rest/', '/api/v1/', '/v1/', '/v2/', '/rest/products', '/rest/users', '/api/products', '/api/users'];
// (A+B+C) API keşfi sabitleri. Swagger/OpenAPI spec yolları (B) + REST koleksiyon probe'ları (A/C).
// Hepsi YALNIZ GET; spec'te POST/PUT/DELETE görülse bile ASLA yazma isteği gönderilmez.
const SWAGGER_PATHS = ['/swagger.json', '/openapi.json', '/api-docs', '/v2/api-docs', '/v3/api-docs', '/swagger/v1/swagger.json', '/api/swagger.json', '/v2/swagger.json', '/api/v3/openapi.json'];
const REST_API_PROBE_PATHS = ['/rest/products', '/rest/users', '/api/products', '/api/users', '/api/v1/products', '/v1/products', '/products', '/users'];
const API_SPEC_MAX_PATHS = 14; // spec'ten işlenecek en fazla yol (aşırı büyük spec'lere karşı)
const API_SEED_MAX = 12;       // API keşfinden eklenen en fazla input + idEndpoint (kapsam sınırı)
// (FAZ C+) GENEL authenticated SPA hash-route listesi — herhangi bir SPA'da login sonrası tipik hesap
// alanları (Juice-Shop'a ÖZEL değil; yaygın rota adları). Yalnız oturum varken gezilir; olmayan rotalar
// SPA shell döndürüp benzersiz-içerik dedup ile elenir. Login-arkası form/API'ler ancak bu rotalar
// render edilince DOM'a/trafiğe gelir (aksi halde ana sayfa + login-öncesi linkler sığ kalır).
const AUTH_SPA_HASH_ROUTES = [
  '#/profile', '#/account', '#/settings', '#/orders', '#/order-history', '#/address', '#/addresses',
  '#/saved-address', '#/basket', '#/cart', '#/wishlist', '#/wallet', '#/payment', '#/saved-payment-methods',
  '#/security', '#/privacy-security', '#/2fa', '#/dashboard', '#/me', '#/user/profile',
];
// Yakalanan XHR/fetch trafiginde gurultu (socket/analytics/i18n) + degersiz cache-buster param'lar.
const API_NOISE_PATH_RE = /(\/socket\.io\/|\/sockjs|__webpack|hot-update|\/assets\/|\/i18n\/|analytics|gtag|\/collect\b|\/rum\b|\/beacon\b)/i;
const API_NOISE_PARAM_RE = /^(_|t|ts|v|ver|cb|cache|rand|nonce|sid|eio|transport|timestamp|__.*|hash|token|jwt|key)$/i;
const API_WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

export type Surface = {
  ok: boolean;
  method: 'static' | 'headless'; // kesif yontemi (ham HTML mi, JS-render mi)
  pagesScanned: number;       // BENZERSIZ icerikli sayfa sayisi (ayni SPA shell tekrar sayilmaz)
  urlsFetched: number;        // toplam cekilen URL (dedup oncesi)
  jsRendered: boolean;        // hedef JS ile render ediliyor gorunuyor (ham HTML'de link/form yok)
  homeHtml: string;
  homeHeaders: Map<string, string>;
  inputs: InputPoint[];
  idEndpoints: Array<{ url: string; idParam: string; idValue: number; kind: 'query' | 'path'; siblingIds?: number[] }>;
  uploadForms: Array<{ action: string; fileField: string; otherFields: string[]; source?: 'dom' | 'network' }>;
  massAssignForm: { action: string; fields: string[] } | null;
  apiWrites: string[];        // GOZLEMLENEN durum-degistiren API uclari ("POST /rest/user/login") — PROBE EDILMEZ
  apiReads: string[];         // (FAZ C+) GOZLEMLENEN authenticated OKUMA API uclari ("GET /api/Addresss") — ajan ADAYI + IDOR turetme
  // (İŞ 2) SPA formlari <form action> tasimaz + XHR ile submit eder (biz yazmalari abort ederiz) -> klasik
  // form kesfi bos kalir. Cozum: SUBMIT ETMEDEN render-edilmis DOM'dan form alanlarini (input/select/
  // textarea) OKU; ozellikle ilginc alanlari (role/isAdmin/price/coupon/gizli) isaretle. SALT-GOZLEM.
  domForms: Array<{ url: string; fields: string[]; interesting: string[] }>;
  // (A+B+C) API/REST keşfi teşhis bilgisi (dürüstlük/log): spec bulundu mu, kaç yol işlendi.
  apiSpecFound?: boolean;
  apiSpecPaths?: number;
  // (BÖLÜM B) Sayfa/script içinden çıkarılan API yol adayları (probe için) + kimlik-doğrulama-kilitli
  // (401/403/auth-400) keşfedilen uç sayısı (şeffaflık: yüzey haritalandı ama kapsam dışı).
  minedApiPaths?: string[];
  apiAuthGated?: number;
};

// Ağ-trafiğinde dosya-yükleme uç noktası işareti: path'te upload/file/avatar/image/attachment vb.
// (multipart/form-data content-type ile birlikte değerlendirilir — bkz crawlHeadless apiReqs işleme).
const UPLOAD_PATH_RE = /(upload|\bfile\b|avatar|attachment|\bimage\b|\bimg\b|\bphoto\b|\bmedia\b|profile[-_]?pic)/i;

// Yakalanan bir ağ isteği DOSYA-YÜKLEME ucu mu? (item 4) SAF fonksiyon (testlenebilir):
// yalnız yazma-metodu (POST/PUT/PATCH/DELETE) + (multipart/form-data VEYA upload-benzeri path) +
// ödeme/tamamlama DEĞİL. crawlHeadless bunu DOM taramasına EK giriş noktası üretmek için kullanır.
export function isNetworkUploadCandidate(method: string, ctype: string, pathname: string): boolean {
  if (!API_WRITE_METHODS.has((method || '').toUpperCase())) return false;
  if (COMPLETION_BLOCKLIST_RE.test(pathname)) return false;
  return /multipart\/form-data/.test(ctype || '') || UPLOAD_PATH_RE.test(pathname);
}

// (İŞ 2) Ilginc alan adlari — yetki-yukseltme (priv) ve is-mantigi/fiyat (price) icin.
const DOMFORM_PRIV_RE = /^(role|roles|isadmin|is[_-]?admin|admin|privilege|privileges|priv|usergroup|user[_-]?group|group|grade|accesslevel|access[_-]?level|perm|permission|permissions)$/i;
const DOMFORM_PRICE_RE = /^(price|amount|total|cost|fiyat|tutar|qty|quantity|adet|discount|indirim|coupon|kupon|miktar|balance|credit|bakiye)$/i;
const DOMFORM_FIELD_TAG_RE = /<(input|select|textarea)\b([^>]*)>/gi;
const DOMFORM_ATTR_RE = (name: string) => new RegExp(`\\b${name}\\s*=\\s*["']([^"']+)["']`, 'i');

/**
 * (İŞ 2) SALT-OKUNUR DOM form-alani cikarimi. Render-edilmis HTML'den input/select/textarea alan
 * adlarini (name, yoksa id) toplar; gizli (type=hidden) + ilginc (priv/price) alanlari isaretler.
 * HICBIR submit/yazma YOK — yalniz yapisal gozlem. SAF fonksiyon (testlenebilir).
 * Anlamli form yoksa (ör. tek arama kutusu) null doner.
 */
export function discoverDomFormFields(html: string): { fields: string[]; interesting: string[] } | null {
  if (!html) return null;
  const fields: string[] = []; const seen = new Set<string>();
  const interesting = new Set<string>();
  const nameRe = DOMFORM_ATTR_RE('name'); const idRe = DOMFORM_ATTR_RE('id');
  const typeRe = DOMFORM_ATTR_RE('type');
  for (const m of html.matchAll(DOMFORM_FIELD_TAG_RE)) {
    const attrs = m[2] || '';
    const nm = (attrs.match(nameRe)?.[1] || attrs.match(idRe)?.[1] || '').trim();
    if (!nm || nm.length > 40) continue;
    const type = (attrs.match(typeRe)?.[1] || '').toLowerCase();
    if (type === 'submit' || type === 'button' || type === 'reset' || type === 'file') continue; // dosya=upload kesfi
    if (!seen.has(nm)) { seen.add(nm); fields.push(nm); }
    if (DOMFORM_PRIV_RE.test(nm) || DOMFORM_PRICE_RE.test(nm)) interesting.add(nm);
    if (type === 'hidden') interesting.add(nm); // gizli alan istemciden degistirilebilir -> ilginc
  }
  // Anlamli form: >=2 alan VEYA en az 1 ilginc alan (register/profil/checkout formu).
  if (fields.length < 2 && interesting.size === 0) return null;
  return { fields: fields.slice(0, 20), interesting: [...interesting].slice(0, 12) };
}

/** (İŞ 2) domForm etiketi — ajana aday olarak verilir; allowed-list'te BIREBIR yer alir (parse guard). */
export function domFormLabel(d: { url: string; fields: string[] }): string {
  return `form ${d.url} [${d.fields.slice(0, 12).join(',')}]`;
}

async function crawlSurface(host: string): Promise<Surface> {
  const empty: Surface = { ok: false, method: 'static', pagesScanned: 0, urlsFetched: 0, jsRendered: false, homeHtml: '', homeHeaders: new Map(), inputs: [], idEndpoints: [], uploadForms: [], massAssignForm: null, apiWrites: [], apiReads: [], domForms: [] };
  const home = await collectHttp(host);
  if (!home.ok) return empty;

  // Ana sayfadaki ayni-host ic linkleri topla (asset/harici/fragment HARIC).
  const homeUrl = `${cachedOriginUrl(host)}/`;
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
  ctx.label = "Keşif/Crawl";
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
  const domForms: Surface['domForms'] = []; const seenDf = new Set<string>();
  for (const pg of pages) {
    for (const ip of discoverInputs(host, pg.html)) { const k = `${ip.method} ${ip.action} ${ip.param}`; if (!seenIn.has(k)) { seenIn.add(k); inputs.push(ip); } }
    for (const e of discoverIdEndpoints(host, pg.html)) { const k = `${e.kind}:${e.idParam}:${(() => { try { const u = new URL(e.url); return u.origin + u.pathname; } catch { return e.url; } })()}`; if (!seenId.has(k)) { seenId.add(k); idEndpoints.push(e); } }
    for (const f of discoverUploadForms(host, pg.html)) { const k = `${f.action}:${f.fileField}`; if (!seenUp.has(k)) { seenUp.add(k); uploadForms.push(f); } }
    if (!massAssignForm) massAssignForm = discoverMassAssignForm(host, pg.html);
    const df = discoverDomFormFields(pg.html); if (df) { const k = df.fields.join(','); if (!seenDf.has(k)) { seenDf.add(k); domForms.push({ url: pg.url, fields: df.fields, interesting: df.interesting }); } }
  }
  // (BÖLÜM B-2) Tüm taranan sayfalardan API yol adaylarını çıkar (probe'u mergeApiSurface yapar).
  const minedApiPaths = [...new Set(pages.flatMap((pg) => mineApiPaths(pg.html)))].slice(0, 12);
  return { ok: true, method: 'static', pagesScanned: pages.length, urlsFetched, jsRendered, homeHtml: home.html, homeHeaders: home.headers, inputs, idEndpoints, uploadForms, massAssignForm, apiWrites: [], apiReads: [], domForms: domForms.slice(0, 10), minedApiPaths };
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

async function crawlHeadless(host: string, session?: AuthSession): Promise<Surface | null> {
  if (chromiumUnavailable) return null;
  const homeUrl = `${cachedOriginUrl(host)}/`;
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
    // PASIF DINLEME: sayfanin organik olarak attigi ayni-host XHR/fetch istekleri (gercek API yuzeyi).
    // Biz EKSTRA istek/etkilesim TETIKLEMIYORUZ — sadece gozlemliyoruz.
    const apiReqs: Array<{ method: string; url: string; ctype: string }> = [];

    // Tek sayfayi render edip render-edilmis HTML'i dondur. HARD-GUARD: yalniz ayni host, ic-ag ASLA.
    const renderOne = async (url: string): Promise<string | null> => {
      try { const u = new URL(url); if (u.hostname.toLowerCase() !== host.toLowerCase() || isInternalHost(u.hostname)) return null; } catch { return null; }
      const page = await browser!.newPage();
      try {
        await page.setUserAgent('CyberTestify-ActiveVerify/1.0');
        // (FAZ C) authenticated crawl: oturumu tarayıcıya enjekte et (login-arkası içerik render olsun).
        if (session) {
          if (session.bearer) {
            await page.setExtraHTTPHeaders({ authorization: `Bearer ${session.bearer}` }).catch(() => {});
            // SPA'lar token'ı localStorage'dan okur (ör. Juice Shop 'token'); yükleme öncesi yaz.
            await page.evaluateOnNewDocument((t: string) => { try { localStorage.setItem('token', t); localStorage.setItem('access_token', t); } catch { /* erişilemez */ } }, session.bearer).catch(() => {});
          }
          if (session.cookie) {
            const cookies = session.cookie.split(';').map((kv) => { const i = kv.indexOf('='); return { name: kv.slice(0, i).trim(), value: kv.slice(i + 1).trim(), url: `${cachedOriginUrl(host)}/` }; }).filter((c) => c.name);
            if (cookies.length) await page.setCookie(...cookies).catch(() => {});
          }
        }
        await page.setRequestInterception(true);
        page.on('request', (req) => {
          const rt = req.resourceType();
          const rurl = req.url();
          // Perf: gorsel/font/media/stylesheet blokla. Guvenlik: ic-ag isteklerini blokla.
          let block = rt === 'image' || rt === 'font' || rt === 'media' || rt === 'stylesheet';
          try { if (isInternalHost(new URL(rurl).hostname)) block = true; } catch { /* yoksay */ }
          // PASIF YAKALA: ayni-host XHR/fetch (gercek API yuzeyi). SADECE gozlemliyoruz.
          if (!block && (rt === 'xhr' || rt === 'fetch')) {
            try {
              if (new URL(rurl).hostname.toLowerCase() === host.toLowerCase()) {
                apiReqs.push({ method: req.method(), url: rurl, ctype: (req.headers()['content-type'] || '').toLowerCase() });
                // GUVENLIK (kesif PASIF kalmali): SPA'nin organik olarak attigi YAZMA (POST/PUT/PATCH/DELETE)
                // istegini GOZLE (kaydet) ama SUNUCUYA ULASTIRMA -> abort. Boylece kesif sirasinda hicbir
                // yazma gerceklesmez; endpoint yalnizca ADAY olarak kaydedilir. Okuma (GET) render icin gecer.
                if (API_WRITE_METHODS.has(req.method().toUpperCase())) block = true;
              }
            } catch { /* yoksay */ }
          }
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
    // (FAZ C+) AUTHENTICATED SPA: login-arkası içerik hash-route'larda olur (#/basket, #/address ...).
    // Eski crawl bunları DIŞLIYORDU (href regex #'i eliyordu + fragment dedup ile ana sayfaya çöküyordu)
    // -> authenticated yüzey SIĞ kalıyordu. Artık: DOM'daki #/... linkleri + GENEL authenticated route
    // wordlist'i (Juice-Shop'a özel DEĞİL) fragment KORUNARAK gezilir. Oturum yoksa bu adım atlanır.
    const hashTargets: string[] = [];
    if (session) {
      const seenH = new Set<string>();
      const addHash = (route: string) => { if (!/^#\//.test(route)) return; const full = `${homeUrl}${route}`; if (!seenH.has(full)) { seenH.add(full); hashTargets.push(full); } };
      for (const m of homeHtml.matchAll(/href\s*=\s*["'](#\/[^"'\s]+)["']/gi)) addHash(m[1]);
      for (const r of AUTH_SPA_HASH_ROUTES) addHash(r);
    }
    const maxPages = session ? 20 : HEADLESS_MAX_PAGES;   // authenticated crawl daha geniş (hash-route'lar)
    const hardCap = session ? 26 : CRAWL_HARD_CAP;
    const targets = [...linkSet].slice(0, maxPages - 1);
    for (const p of WELL_KNOWN_PATHS) { const a = absUrl(p, host); if (a && a !== homeUrl && !targets.includes(a)) targets.push(a); }
    for (const h of hashTargets) if (!targets.includes(h)) targets.push(h);

    // 3) Sayfalari render et (benzersiz icerik + sayfa ust siniri). Hash-route'lar farkli icerik dondururse
    // benzersiz sayilir; var-olmayan route SPA shell'i (ana sayfa) dondurup icerik-hash dedup ile elenir.
    for (const t of targets) {
      if (stopped || pages.length >= maxPages || seenUrl.size >= hardCap) break;
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
    const domForms: Surface['domForms'] = []; const seenDf = new Set<string>();
    for (const pg of pages) {
      for (const ip of discoverInputs(host, pg.html)) { const k = `${ip.method} ${ip.action} ${ip.param}`; if (!seenIn.has(k)) { seenIn.add(k); inputs.push(ip); } }
      for (const e of discoverIdEndpoints(host, pg.html)) { const k = `${e.kind}:${e.idParam}:${(() => { try { const u = new URL(e.url); return u.origin + u.pathname; } catch { return e.url; } })()}`; if (!seenId.has(k)) { seenId.add(k); idEndpoints.push(e); } }
      for (const f of discoverUploadForms(host, pg.html)) { const k = `${f.action}:${f.fileField}`; if (!seenUp.has(k)) { seenUp.add(k); uploadForms.push(f); } }
      if (!massAssignForm) massAssignForm = discoverMassAssignForm(host, pg.html);
      // (İŞ 2) SALT-OKUNUR DOM form-alani kesfi (SPA formlari icin — submit YOK).
      const df = discoverDomFormFields(pg.html); if (df) { const k = df.fields.join(','); if (!seenDf.has(k)) { seenDf.add(k); domForms.push({ url: pg.url, fields: df.fields, interesting: df.interesting }); } }
    }

    // 5) YAKALANAN API YUZEYI -> input havuzuna EKLE (gercek SPA API'leri: /rest/products/search?q= gibi).
    const apiWrites = new Set<string>();
    const apiReads = new Set<string>();
    // Okuma-API gurultusu (surekli/altyapi cagrilari — yuzey degeri yok).
    const API_READ_NOISE_RE = /(whoami|languages?|application-(version|configuration)|challenges?|captcha|health\b|status\b|\/version\b|config(uration)?\b|metrics|i18n|socket|sockjs|\/rest\/languages|quantitys?)/i;
    for (const r of apiReqs) {
      let u: URL;
      try { u = new URL(r.url); } catch { continue; }
      if (API_NOISE_PATH_RE.test(u.pathname)) continue;
      const base = `${u.origin}${u.pathname}`;
      if (API_WRITE_METHODS.has(r.method.toUpperCase())) {
        // DOSYA YUKLEME ucu mu? (multipart/form-data content-type VEYA path'te upload/file/avatar/...).
        // Odeme/tamamlama uclari HARIC (guvenlik). Boyle bir uc -> Dosya Yukleme kontrolune BESLE
        // (mevcut DOM <input type=file> taramasina EK). Mevcut kural: tek seferlik zararsiz/inert dosya.
        if (isNetworkUploadCandidate(r.method, r.ctype, u.pathname)) {
          const base = `${u.origin}${u.pathname}`;
          const key = `${base}:file`;
          if (!seenUp.has(key)) { seenUp.add(key); uploadForms.push({ action: base, fileField: 'file', otherFields: [], source: 'network' }); }
          continue;
        }
        // Durum-degistiren API ucu — PROBE EDILMEZ, sadece raporda gozlem notu.
        apiWrites.add(`${r.method.toUpperCase()} ${u.pathname}`);
        continue;
      }
      // GET/HEAD/OPTIONS (okuma) — test edilebilir input.
      // (a) query param'lar -> GET InputPoint (injection/ssrf/rce test eder)
      const params: Record<string, string> = {};
      u.searchParams.forEach((v, k) => { params[k] = v; });
      for (const k of Object.keys(params)) {
        if (API_NOISE_PARAM_RE.test(k)) continue;
        const key = `GET ${base} ${k}`;
        if (!seenIn.has(key)) { seenIn.add(key); inputs.push({ method: 'GET', action: base, param: k, params: { ...params }, source: 'url' }); }
      }
      // (b) sayisal path segmenti -> idEndpoint (IDOR yalniz GET okur — guvenli)
      const pm = u.pathname.match(/^(.*\/)(\d{1,9})(\/?)$/);
      if (pm) {
        const key = `p:path-id:${u.origin}${pm[1]}`;
        if (!seenId.has(key)) { seenId.add(key); idEndpoints.push({ url: `${u.origin}${u.pathname}`, idParam: 'path-id', idValue: parseInt(pm[2], 10), kind: 'path' }); }
      }
      // (c) (FAZ C+) authenticated OKUMA API ucu (api/rest/graphql-benzeri) -> apiReads (ajan ADAYI + IDOR
      // turetme). Gozlemsel: uygulamanin KENDI trafigi; biz yazma istegi ATMAYIZ.
      if (!API_READ_NOISE_RE.test(u.pathname) && (/^\/(api|rest|graphql|v\d+)\//i.test(u.pathname) || u.pathname.split('/').filter(Boolean).length >= 2)) {
        apiReads.add(`${r.method.toUpperCase()} ${u.pathname}`);
      }
    }

    const minedApiPaths = [...new Set([homeHtml, ...pages.map((p) => p.html)].flatMap((h) => mineApiPaths(h)))].slice(0, 12);
    return { ok: true, method: 'headless', pagesScanned: pages.length, urlsFetched: seenUrl.size, jsRendered: true, homeHtml, homeHeaders: new Map(), inputs, idEndpoints, uploadForms, massAssignForm, apiWrites: [...apiWrites].slice(0, 20), apiReads: [...apiReads].slice(0, 30), domForms: domForms.slice(0, 10), minedApiPaths };
  } catch {
    return null;
  } finally {
    await browser.close().catch(() => {});
    releaseHeadless();
  }
}

// (SORUN 1 fix) Input ENJEKSİYON-DEĞERİ önceliklendirmesi. Kök neden: yüksek-değerli enjekte edilebilir
// uç (ör. /rest/products/search?q) düşük-değerli gürültü (redirect/ref/login param'ları) tarafından
// INJ_MAX_INPUTS tavanının DIŞINA itilip test edilmiyordu; sıra da run-to-run değişince sonuç tutarsızdı.
// Bu STABİL (deterministik) sıralama, yüksek-değerli input'ları ÖNE alır -> her taramada aynı, tutarlı test.
function inputInjectionRank(ip: InputPoint): number {
  let s = 0;
  let path = '';
  try { path = new URL(ip.action).pathname.toLowerCase(); } catch { /* yoksay */ }
  const p = ip.param.toLowerCase();
  if (/\/(rest|api|graphql|v\d+)\//.test(path)) s += 5;                                   // API ucu
  if (/search|query|find|list|products?|users?|orders?|items?|accounts?|feedbacks?/.test(path)) s += 3;
  if (/^(q|query|search|s|id|name|user|email|cat|category|sort|filter|order|term|keyword)$/.test(p)) s += 4; // klasik enjekte param
  if (ip.source === 'url') s += 1;                                                          // GET query -> enjeksiyona açık
  if (/^(to|url|uri|return|return_to|redirect|redir|ref|ref_cta|ref_loc|ref_page|source|source_repo|utm_[a-z]+|next|continue|file|callback|cb)$/.test(p)) s -= 4; // gürültü
  if (/redirect|signup|signin|\/login|logout|oauth|auth\/callback/.test(path)) s -= 2;
  return s;
}
// Kararlı sıralama (rank desc, esitlikte path+param alfabetik) -> deterministik + önceliklendirilmiş.
function prioritizeInputs<T extends Surface>(surf: T): T {
  surf.inputs = [...surf.inputs].sort((a, b) => {
    const d = inputInjectionRank(b) - inputInjectionRank(a);
    if (d !== 0) return d;
    return `${a.action} ${a.param}`.localeCompare(`${b.action} ${b.param}`);
  });
  return surf;
}

// ======================================================================================
// (A+B+C) API/REST KEŞFİ — link/HTML olmasa da uç noktası çıkarır. YALNIZ GET.
//  B) Swagger/OpenAPI spec'i (varsa) bulur, `paths`'ten gerçek uçları + query param'ları çıkarır.
//  A) Bilinen REST koleksiyon yollarını GET ile dener.
//  C) 200 + JSON dizi/obje dönen koleksiyon uçlarını ID-türetme (collectionBasesFrom) girdisine ekler.
// "Kanıtla — istismar etme" AYNEN: hiçbir POST/PUT/DELETE gönderilmez; yalnız keşif/GET.
// ======================================================================================
function safeJsonParse(text: string): any {
  const t = text.trim();
  if (t.length > 3_000_000 || !(t.startsWith('{') || t.startsWith('['))) return null;
  try { return JSON.parse(t); } catch { return null; }
}
// OpenAPI 3 (servers[].url) veya Swagger 2 (basePath) taban yolunu çıkar (host'u YOK say — kendi origin'imiz).
function specBasePath(spec: any): string {
  if (spec && typeof spec.basePath === 'string') return spec.basePath.replace(/\/+$/, '');
  const srv = spec && Array.isArray(spec.servers) && spec.servers[0] && spec.servers[0].url;
  if (typeof srv === 'string') { try { return new URL(srv, 'http://x').pathname.replace(/\/+$/, ''); } catch { return srv.startsWith('/') ? srv.replace(/\/+$/, '') : ''; } }
  return '';
}
// Son (sayısal olmayan) segment koleksiyon-anlamlı mı? (/rest/products -> evet)
function isCollectionPath(pathname: string): boolean {
  const segs = pathname.replace(/\/+$/, '').replace(/\/\d{1,9}$/, '').split('/').filter(Boolean);
  return segs.length >= 1 && COLLECTION_LAST_SEG_RE.test(segs[segs.length - 1]);
}
// (BÖLÜM B) Sayfa HTML'i + inline <script> metninden API yol ADAYLARINI çıkar (SALT-OKUNUR; JS
// ÇALIŞTIRILMAZ). fetch()/axios/url: string literalleri + /rest//api//v1/ önekli yollar. Template
// placeholder ({id}, :id, ${...}) ve asset yolları elenir. Yalnız keşif adayı üretir.
const API_MINE_RE = /["'`](\/(?:rest|api|v\d+|graphql|products?|users?|orders?|accounts?|customers?|items?|invoices?|categories|vendors?)[\w/.-]*)["'`]/gi;
function mineApiPaths(html: string): string[] {
  if (!html) return [];
  const found = new Set<string>();
  for (const m of html.matchAll(API_MINE_RE)) {
    let p = m[1];
    if (/[{}]|:[a-zA-Z]|\$\{|\*|\s/.test(p)) continue;        // template/placeholder ele
    try { if (CRAWL_ASSET_RE.test(new URL(p, 'http://x').pathname)) continue; } catch { continue; }
    p = p.replace(/[?#].*$/, '').replace(/\/+$/, '');          // query/fragment/trailing slash at
    if (p.length > 1 && p.length < 80) found.add(p);
  }
  return [...found].slice(0, 12);
}
async function collectApiSurface(host: string, session?: AuthSession, minedPaths: string[] = []): Promise<{ inputs: InputPoint[]; idEndpoints: Surface['idEndpoints']; specFound: boolean; specPaths: number; authGated: number }> {
  const origin = cachedOriginUrl(host);
  const ctx = new ProbeCtx();
  if (session) ctx.authHeaders = applyAuthHeaders({}, session);
  const inputs: InputPoint[] = []; const seenIn = new Set<string>();
  const idEndpoints: Surface['idEndpoints'] = []; const seenId = new Set<string>();
  const addInput = (action: string, param: string, params: Record<string, string>) => {
    const k = `GET ${action} ${param}`; if (seenIn.has(k) || inputs.length + idEndpoints.length >= API_SEED_MAX) return;
    seenIn.add(k); inputs.push({ method: 'GET', action, param, params, source: 'url' });
  };
  const addId = (url: string, idVal: number) => {
    let u: URL; try { u = new URL(url); } catch { return; }
    const key = `p:${u.origin}${u.pathname.replace(/\/\d{1,9}\/?$/, '')}`;
    if (seenId.has(key) || inputs.length + idEndpoints.length >= API_SEED_MAX) return;
    seenId.add(key); idEndpoints.push({ url: u.toString(), idParam: 'path-id', idValue: idVal, kind: 'path' });
  };

  // --- B) Swagger/OpenAPI spec keşfi (ilk geçerli spec kazanır) ---
  let specFound = false; let specPaths = 0;
  for (const sp of SWAGGER_PATHS) {
    if (ctx.stopped || specFound) break;
    const r = await ctx.fetchOnce(origin + sp);
    if (!r || r.status !== 200) continue;
    const spec = safeJsonParse(r.text);
    if (!spec || !spec.paths || typeof spec.paths !== 'object') continue;
    specFound = true;
    const base = specBasePath(spec);
    for (const [rawPath, ops] of Object.entries<any>(spec.paths)) {
      if (specPaths >= API_SPEC_MAX_PATHS || inputs.length + idEndpoints.length >= API_SEED_MAX) break;
      if (!ops || typeof ops !== 'object' || !('get' in ops)) continue; // YALNIZ GET tanımlı uçlar
      specPaths++;
      const fullPath = (base + (rawPath.startsWith('/') ? rawPath : '/' + rawPath)).replace(/\/{2,}/g, '/');
      const concrete = fullPath.replace(/\{[^}]+\}/g, '1'); // {id}/{username} -> 1 (güvenli örnek)
      if (/\{[^}]+\}/.test(fullPath)) addId(origin + concrete, 1);          // path parametreli uç -> IDOR adayı
      else if (isCollectionPath(concrete)) addId(origin + concrete.replace(/\/+$/, '') + '/1', 1); // koleksiyon -> türetme
      const getOp = ops.get;
      const qps = (getOp && Array.isArray(getOp.parameters) ? getOp.parameters : []).filter((p: any) => p && p.in === 'query' && p.name).map((p: any) => String(p.name)).slice(0, 4);
      for (const q of qps) addInput(origin + concrete, q, { [q]: '1' });     // query param -> enjeksiyon adayı
    }
  }

  // --- A+C) Bilinen REST + (B-2) sayfadan çıkarılan koleksiyon yollarını GET dene ---
  // 200 + JSON -> ID-türetme girdisi (C). 401/403/auth-400 -> "kimlik-doğrulama-kilitli yüzey"
  // sayılır (B-3 şeffaflık: keşfedildi ama unauth kapsam dışı). Hepsi YALNIZ GET.
  let authGated = 0; const seenProbe = new Set<string>();
  const probePaths = [...REST_API_PROBE_PATHS, ...minedPaths].filter((p) => { const k = p.replace(/\/+$/, ''); if (seenProbe.has(k)) return false; seenProbe.add(k); return true; }).slice(0, 20);
  for (const p of probePaths) {
    if (ctx.stopped) break;
    const r = await ctx.fetchOnce(origin + p);
    if (!r || r.status === 0) continue;
    // (B-3) auth-duvarı: 401/403 veya 400 + kimlik-doğrulama imalı gövde -> keşfedildi, kapsam dışı.
    if (r.status === 401 || r.status === 403 || (r.status === 400 && /auth|yetki|token|credential|unauthor|kimlik/i.test(r.text.slice(0, 200)))) { authGated++; continue; }
    if (inputs.length + idEndpoints.length >= API_SEED_MAX) continue;
    if (r.status !== 200 || safeJsonParse(r.text) === null) continue;      // yalnız 200 + JSON dizi/obje
    if (isCollectionPath(p)) addId(origin + p.replace(/\/+$/, '') + '/1', 1);
  }

  return { inputs: inputs.slice(0, API_SEED_MAX), idEndpoints: idEndpoints.slice(0, API_SEED_MAX), specFound, specPaths, authGated };
}
// API keşfini mevcut yüzeye BİRLEŞTİR (dedup). Mevcut input/idEndpoint'ler korunur; yalnız YENİ eklenir.
async function mergeApiSurface(surf: Surface, host: string, session?: AuthSession): Promise<Surface> {
  const api = await collectApiSurface(host, session, surf.minedApiPaths ?? []).catch(() => null);
  if (!api) return surf;
  const inK = (i: InputPoint) => `${i.method} ${i.action} ${i.param}`;
  const seenIn = new Set(surf.inputs.map(inK));
  for (const ip of api.inputs) { const k = inK(ip); if (!seenIn.has(k)) { seenIn.add(k); surf.inputs.push(ip); } }
  const idK = (e: Surface['idEndpoints'][number]) => { try { const u = new URL(e.url); return `${e.kind}:${u.origin}${u.pathname.replace(/\/\d{1,9}\/?$/, '')}`; } catch { return e.url; } };
  const seenId = new Set(surf.idEndpoints.map(idK));
  for (const e of api.idEndpoints) { const k = idK(e); if (!seenId.has(k)) { seenId.add(k); surf.idEndpoints.push(e); } }
  surf.apiSpecFound = api.specFound; surf.apiSpecPaths = api.specPaths; surf.apiAuthGated = api.authGated;
  return surf;
}

// HIBRIT: once hizli statik kesif; SPA supheli + statik input BULAMADIYSA headless'e dus.
// (FAZ C) session verilirse -> DOĞRUDAN authenticated headless crawl (login-arkası yüzey).
async function buildSurface(host: string, session?: AuthSession): Promise<Surface> {
  let surf: Surface;
  if (session) {
    const hl = await crawlHeadless(host, session).catch(() => null);
    surf = hl && hl.ok ? hl : await crawlSurface(host); // headless yok/başarısız -> statik (unauth) fallback
  } else {
    const stat = await crawlSurface(host);
    const staticSurfaceCount = stat.inputs.length + stat.idEndpoints.length + stat.uploadForms.length + (stat.massAssignForm ? 1 : 0);
    // Statik zaten input buldu -> headless GEREKSIZ (perf). Yalniz SPA supheli + 0 input -> headless.
    if (stat.ok && staticSurfaceCount === 0 && stat.jsRendered) {
      const hl = await crawlHeadless(host).catch(() => null);
      surf = hl && hl.ok ? hl : stat;
    } else surf = stat;
  }
  // (A+B+C) Crawl'dan SONRA API/REST keşfini birleştir — link/HTML olmasa da uç çıkar (YALNIZ GET).
  // Hedefe ulaşıldıysa dener; ulaşılamadıysa (surf.ok=false) atlar -> "İncelenemedi" mantığı korunur.
  if (surf.ok) surf = await mergeApiSurface(surf, host, session).catch(() => surf);
  return prioritizeInputs(surf);
}

// In-flight cache: ayni host icin es zamanli 7 kontrol TEK crawl paylasir. (FAZ C) authenticated crawl
// AYRI cache anahtarı (host + '#auth') kullanır — unauth ve auth yüzeyler karışmaz.
const SURFACE_CACHE = new Map<string, { at: number; p: Promise<Surface> }>();
const SURFACE_TTL_MS = 120_000;
const EMPTY_SURFACE: Surface = { ok: false, method: 'static', pagesScanned: 0, urlsFetched: 0, jsRendered: false, homeHtml: '', homeHeaders: new Map(), inputs: [], idEndpoints: [], uploadForms: [], massAssignForm: null, apiWrites: [], apiReads: [], domForms: [] };
// TEST hook — ardışık TAZE crawl'ları doğrulamak için (SORUN 1 tutarlılık testi).
export function __clearSurfaceCache(host?: string): void {
  if (host) { SURFACE_CACHE.delete(host); SURFACE_CACHE.delete(`${host}#auth`); } else SURFACE_CACHE.clear();
}
export function discoverSurface(host: string, session?: AuthSession): Promise<Surface> {
  const key = session ? `${host}#auth` : host;
  const c = SURFACE_CACHE.get(key);
  if (c && Date.now() - c.at < SURFACE_TTL_MS) return c.p;
  const p = buildSurface(host, session).catch(() => ({ ...EMPTY_SURFACE, homeHeaders: new Map() } as Surface));
  SURFACE_CACHE.set(key, { at: Date.now(), p });
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
// ODEME-ONCESI HIZLI KAPSAM SINYALI — bundle_active_verify icin. Once ucuz statik kontrol;
// statik BOSSA (SPA olabilir) TEK-sayfa headless render ile teyit et (asil tarama gibi
// tam multi-page crawl DEGIL — sadece ana sayfa). Boylece Juice Shop gibi zengin SPA'larda
// YANLIS ALARM olmaz; nomorelink gibi gercekten bos landing SPA'da uyari dogru cikar.
// Headless yok/timeout/hata -> BELIRSIZ -> uyari GOSTERME (musteriyi bosuna korkutma).
// ======================================================================================
export type ScopeSignal = { reachable: boolean; jsRendered: boolean; inputCount: number; pagesScanned: number; lowSignal: boolean; method: 'static' | 'headless' };

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

function countInputsIn(host: string, htmls: string[]): number {
  const inputs = new Set<string>(); const ids = new Set<string>(); const uploads = new Set<string>(); let mass = false;
  for (const html of htmls) {
    for (const ip of discoverInputs(host, html)) inputs.add(`${ip.method} ${ip.action} ${ip.param}`);
    for (const e of discoverIdEndpoints(host, html)) ids.add(`${e.kind}:${e.idParam}`);
    for (const f of discoverUploadForms(host, html)) uploads.add(`${f.action}:${f.fileField}`);
    if (!mass && discoverMassAssignForm(host, html)) mass = true;
  }
  return inputs.size + ids.size + uploads.size + (mass ? 1 : 0);
}

// TEK sayfa (ana sayfa) headless render — on-kontrol icin hafif. Semafor + resource-block +
// ic-ag hard-guard mevcut headless ile AYNI. Basarisiz/timeout -> null.
async function renderHomepageHeadless(host: string): Promise<string | null> {
  if (chromiumUnavailable) return null;
  const homeUrl = `${cachedOriginUrl(host)}/`;
  try { const u = new URL(homeUrl); if (u.hostname.toLowerCase() !== host.toLowerCase() || isInternalHost(u.hostname)) return null; } catch { return null; }
  await acquireHeadless();
  let browser: Awaited<ReturnType<typeof puppeteer.launch>> | null = null;
  try {
    browser = await puppeteer.launch({ executablePath: CHROMIUM_PATH, headless: true, args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'] });
  } catch {
    chromiumUnavailable = true;
    releaseHeadless();
    return null;
  }
  try {
    const page = await browser.newPage();
    try {
      await page.setUserAgent('CyberTestify-PassiveCheck/1.0');
      await page.setRequestInterception(true);
      page.on('request', (req) => {
        const rt = req.resourceType();
        let block = rt === 'image' || rt === 'font' || rt === 'media' || rt === 'stylesheet';
        try { if (isInternalHost(new URL(req.url()).hostname)) block = true; } catch { /* yoksay */ }
        if (block) req.abort().catch(() => {}); else req.continue().catch(() => {});
      });
      await page.goto(homeUrl, { waitUntil: 'domcontentloaded', timeout: HEADLESS_PRECHECK_TIMEOUT_MS });
      await page.waitForNetworkIdle({ idleTime: 500, timeout: 3000 }).catch(() => {});
      return await page.content();
    } catch { return null; } finally { await page.close().catch(() => {}); }
  } finally {
    await browser.close().catch(() => {});
    releaseHeadless();
  }
}

export async function quickScopeSignal(host: string): Promise<ScopeSignal> {
  const home = await collectHttp(host);
  if (!home.ok) return { reachable: false, jsRendered: false, inputCount: 0, pagesScanned: 0, lowSignal: false, method: 'static' };
  // SPA sinyali (crawlSurface ile AYNI heuristik) — bilgi amacli.
  const anchors = (home.html.match(/<a\s[^>]*href\s*=/gi) ?? []).length;
  const formCount = (home.html.match(/<form\b/gi) ?? []).length;
  const scriptCount = (home.html.match(/<script\b/gi) ?? []).length;
  const spaShell = /<div[^>]+(id|class)\s*=\s*["'](root|app|__next|__nuxt|q-app)\b|__NEXT_DATA__|window\.__NUXT__|ng-version=/i.test(home.html);
  const jsRendered = (anchors <= 2 && formCount === 0) && (scriptCount >= 1) && (spaShell || home.html.length < 30000);

  // 1) UCUZ STATIK: ana sayfa + en fazla 3 ic link (asset HARIC).
  const homeUrl = `${cachedOriginUrl(host)}/`;
  const links: string[] = []; const seenL = new Set<string>([homeUrl]);
  for (const m of home.html.matchAll(/href\s*=\s*["']([^"'#]+)["']/gi)) {
    if (links.length >= 3) break;
    const abs = absUrl(m[1].replace(/&amp;/g, '&'), host);
    if (!abs) continue;
    try { const u = new URL(abs); if (CRAWL_ASSET_RE.test(u.pathname)) continue; const norm = `${u.origin}${u.pathname}${u.search}`; if (!seenL.has(norm)) { seenL.add(norm); links.push(norm); } } catch { /* atla */ }
  }
  const pages: string[] = [home.html];
  for (const l of links) { const html = await quickGet(l); if (html) pages.push(html); }
  const staticCount = countInputsIn(host, pages);

  // Statik zaten input buldu -> DUSUK DEGIL (hizli, headless'e gerek yok). Wikipedia vb.
  if (staticCount > 0) return { reachable: true, jsRendered, inputCount: staticCount, pagesScanned: pages.length, lowSignal: false, method: 'static' };

  // 2) STATIK BOS -> TEK-sayfa HEADLESS render ile teyit (Juice Shop gibi SPA'da icerik var mi).
  const renderedHtml = await renderHomepageHeadless(host).catch(() => null);
  if (renderedHtml === null) {
    // Headless yok/timeout/hata -> BELIRSIZ -> uyari GOSTERME (lowSignal:false).
    return { reachable: true, jsRendered, inputCount: 0, pagesScanned: pages.length, lowSignal: false, method: 'static' };
  }
  const renderedCount = countInputsIn(host, [renderedHtml]);
  // Render sonrasi da input yoksa -> GERCEKTEN dusuk kapsam -> UYAR. Varsa -> uyarma.
  const lowSignal = renderedCount === 0;
  return { reachable: true, jsRendered, inputCount: renderedCount, pagesScanned: 1, lowSignal, method: 'headless' };
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
const SQL_ERROR_RE = /(SQL syntax|mysql_fetch|mysqli|you have an error in your sql|ORA-\d{4,5}|PLS-\d|PostgreSQL.*ERROR|pg_query|SQLite3?::|SQLITE_ERROR|SQLITE_CONSTRAINT|no such column|near ".{0,40}": syntax error|unrecognized token|SQLSTATE\[|Microsoft OLE DB Provider|ODBC SQL Server|Unclosed quotation mark|quoted string not properly terminated|syntax error at or near|Warning: pg_|Warning: mysql|Sequelize\w*Error)/i;

export type InjFinding = { inputPoint: string; type: 'SQLi' | 'XSS'; technique: 'error-based' | 'time-based' | 'reflection' | 'boolean-based'; evidence: string; severity: 'high' | 'medium' | 'low'; confidence: 'high' | 'medium' | 'low' };
export type InjEvidence = { ok: boolean; baseUrl: string; pagesScanned: number; inputsFound: number; inputsTested: number; probesSent: number; payloadsSent: number; findings: InjFinding[]; stopped: string | null; notes: string[]; verboseError?: { endpoint: string; sig: string }; formsTested: number; formsSkipped: Array<{ action: string; reason: string }> };

// (İŞ B) ZATEN toplanan hata yanıtı GÖVDESİNDE ayrıntılı-hata-sayfası imzası — UYDURMA YOK, yalnız
// GERÇEK yanıtı okur. KONSERVATİF: jenerik "500" değil; framework hata-sayfası/stack-trace/dosya-yolu
// imzaları. "ASP.NET" gibi normal sayfalarda da geçen genel kelimeler DIŞARIDA (yanlış-pozitif önle).
// (10/10 Bölüm 1.4) Host-agnostik: .NET + PHP + Python + Java imzaları. PHP Warning/Fatal mesaj gövdesi
// tipik olarak 100+ karakter (fonksiyon adı + dosya yolu) olduğundan "on line N"e kadar mesafe 200'e açıldı
// (aksi halde en yaygın PHP hatası kaçırılıyordu). "Warning:"/"Fatal error:" ÖN EKİ + "on line \d+" şartı
// yanlış-pozitifi düşük tutar. Ek olarak ham PHP/MySQL sızıntı imzaları (mysql_*, ODBC/JDBC hata metni).
const VERBOSE_ERROR_RE = /Server Error in .{0,60}Application|\.NET Framework Version|Stack Trace:|System\.(Data\.SqlClient|Web\.HttpException|NullReferenceException|InvalidOperationException)|[A-Za-z]:\\(inetpub|Windows|wwwroot|Users)\\|(?:Fatal error|Warning|Parse error|Notice):.{0,200}?\bon line \d+|Traceback \(most recent call last\)|\bat [\w.$/]+\([\w$]+\.java:\d+\)|\b(?:mysql_fetch_(?:array|assoc|row)|mysqli?_query|pg_query)\s*\(|supplied argument is not a valid MySQL/i;

// Zararsiz, veri-degistirmeyen SQLi HATA-tetikleyici varyantlari (yalniz response'ta hata imzasi arar).
// (FORM-POST agresiflik) cesitlilik bir kademe artirildi: comment/parantez/backslash varyantlari da.
const SQLI_ERROR_PAYLOADS = ["'", '"', "' OR '1'='1", "')", "';", "' OR 1=1-- -", '\\', '"))'];
// Context-aware zararsiz XSS isaret payload'lari (JS CALISTIRMAZ; yalniz kacirilmadan yansima kontrolu).
// tag-context, single-quote-attr, double-quote-attr, URL/js-context, SVG/onerror marker'lari.
const XSS_MARKER = 'cxt9137xmark';
const XSS_PAYLOADS = [`${XSS_MARKER}"><cxmark>`, `${XSS_MARKER}'><cxmark>`, `${XSS_MARKER}" cxa=x`, `${XSS_MARKER}');cx//`, `${XSS_MARKER}</title><cxmark>`];
const INJ_MAX_INPUTS = 26; // (İş B.1) giris noktasi kapsami +%30 (20->26); devre kesici/rate-limit AYNEN korunur
const INJ_PATH_MAX = 16;   // (İş B.1) path-ID uc noktasi ust siniri 12->16

export async function collectInjectionEvidence(host: string, session?: AuthSession): Promise<InjEvidence> {
  const surf = await discoverSurface(host, session);
  if (!surf.ok) return { ok: false, baseUrl: `${cachedOriginUrl(host)}/`, pagesScanned: 0, inputsFound: 0, inputsTested: 0, probesSent: 0, payloadsSent: 0, findings: [], stopped: null, notes: ['Hedef ana sayfası çekilemedi (bağlantı kurulamadı).'], formsTested: 0, formsSkipped: [] };
  const inputs = surf.inputs.slice(0, INJ_MAX_INPUTS);
  const ctx = new ProbeCtx();
  ctx.label = "Enjeksiyon (SQLi/XSS) Doğrulama";
  if (session) ctx.authHeaders = applyAuthHeaders({}, session); // (FAZ C) authenticated probe
  const findings: InjFinding[] = [];
  const notes: string[] = [];
  let tested = 0;
  let payloads = 0;
  // (FORM-POST GÜVENLİK KAPISI) Kalıcı yan-etkili form türlerine POST ATMA; test edilen/atlanan formları izle.
  const testedFormActions = new Set<string>();
  const skippedForms = new Map<string, string>(); // action -> okunur sebep (YASAK)
  // (İŞ B) Toplanan yanıt gövdelerinde ayrıntılı-hata-sayfası imzası (ilk eşleşme saklanır; redakte).
  let verboseError: { endpoint: string; sig: string } | null = null;
  const scanVerbose = (url: string, r: ProbeResult | null) => {
    if (verboseError || !r || !r.text) return;
    const m = r.text.match(VERBOSE_ERROR_RE);
    if (m) { try { verboseError = { endpoint: new URL(url).pathname, sig: m[0].replace(/\s+/g, ' ').slice(0, 120) }; } catch { verboseError = { endpoint: url, sig: m[0].slice(0, 120) }; } }
  };

  // (FORM-POST ŞEFFAFLIĞI) YASAK formları ÖNCEDEN sınıflandır — devre kesici erken dursa bile atlanan
  // formlar rapora tam yansısın (ve loop bu formlara zaten POST atmaz).
  for (const ip of inputs) {
    if (ip.method === 'POST' && ip.source === 'form') {
      const cat = formCategory(ip.action, Object.keys(ip.params));
      if (FORBIDDEN_FORM_CATS.has(cat) && !skippedForms.has(ip.action)) skippedForms.set(ip.action, FORBIDDEN_REASON[cat] ?? cat);
    }
  }
  const base = await ctx.fetchOnce(`${cachedOriginUrl(host)}/`);
  if (base) ctx.baseline = base.ms;
  const send = async (ip: InputPoint, val: string, expectSlow = false): Promise<ProbeResult | null> => {
    const url = ip.method === 'GET' ? buildGetUrl(ip, val) : ip.action;
    const r = ip.method === 'GET'
      ? await ctx.fetchOnce(url, { expectSlow })
      : await ctx.fetchOnce(ip.action, { method: 'POST', body: buildFormBody(ip, val), contentType: 'application/x-www-form-urlencoded', expectSlow });
    scanVerbose(url, r); // GERÇEK yanıt gövdesini imza için tara (ek istek YOK)
    return r;
  };

  for (const ip of inputs) {
    if (ctx.stopped) break;
    // (FORM-POST GÜVENLİK KAPISI) POST form ise ÖNCE sınıflandır; YASAK türe (yorum/iletişim/kayıt/
    // parola-sıfırlama/ödeme/abonelik) gerçek POST ATMA — kalıcı/geri-alınamaz yan etki yaratır.
    if (ip.method === 'POST' && ip.source === 'form') {
      const cat = formCategory(ip.action, Object.keys(ip.params));
      if (FORBIDDEN_FORM_CATS.has(cat)) { if (!skippedForms.has(ip.action)) skippedForms.set(ip.action, FORBIDDEN_REASON[cat] ?? cat); continue; }
      testedFormActions.add(ip.action);
    }
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
        // (İş B.3) TAM yansıma: payload (< > " dâhil) AYNEN, encode edilmeden döndü -> yüksek güven.
        findings.push({ inputPoint: label, type: 'XSS', technique: 'reflection', evidence: 'İşaret dizesi yanıt HTML’inde TAM ve ENCODE EDİLMEDEN yansıdı (özel karakterler `< > "` kaçırılmadan döndü) — yüksek güvenli yansıyan XSS göstergesi.', severity: 'high', confidence: 'high' });
        break;
      } else if (xr && xr.text.includes(XSS_MARKER)) {
        // (İş B.3) KISMİ yansıma: yalnız işaret dizesi döndü, özel karakterler kaçırılmış/encode edilmiş -> düşük güven.
        findings.push({ inputPoint: label, type: 'XSS', technique: 'reflection', evidence: 'İşaret dizesi yansıdı ancak KISMİ/ENCODE EDİLMİŞ (özel karakterler `< > "` kaçırılmış) — bağlama bağlı düşük güvenli gösterge; manuel doğrulama önerilir.', severity: 'low', confidence: 'low' });
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

    // --- (İŞ 1) BOOLEAN-TABANLI SQLi: TRUE (1=1) vs FALSE (1=2) koşullu yanıtları KIYASLA ---
    // Yalnız sayısal/ID-benzeri giriş noktalarında (boolean koşulun anlamlı olduğu yer) + hata-tabanlı
    // SQLi zaten bulunmadıysa. Sayısal değer için "N AND 1=1/1=2", string için "v' AND '1'='1/'2".
    // FALSE-POZİTİF önlemi: aday fark bulunursa TRUE tekrar gönderilir; TRUE stabil ve FALSE'tan
    // KALICI farklı olmalı (dinamik sayfa gürültüsü elenir). Fark yoksa: gerçek "temiz", güven yükseltme YOK.
    const boolBase = ip.params?.[ip.param] ?? '';
    const boolTarget = /^\d{1,9}$/.test(boolBase) || ID_LIKE_PARAM_RE.test(ip.param);
    if (!sqlErrorFound && !ctx.stopped && boolTarget) {
      const isNum = /^\d{1,9}$/.test(boolBase);
      const b = isNum ? boolBase : (boolBase || '1');
      const truePay = isNum ? `${b} AND 1=1` : `${b}' AND '1'='1`;
      const falsePay = isNum ? `${b} AND 1=2` : `${b}' AND '1'='2`;
      payloads += 2;
      const tRes = await send(ip, truePay);
      const fRes = await send(ip, falsePay);
      const bigDiff = (a: ProbeResult, c: ProbeResult) => a.status !== c.status || Math.abs(a.len - c.len) > Math.max(80, 0.15 * Math.max(a.len, c.len, 1));
      if (tRes && fRes && tRes.status > 0 && fRes.status > 0 && !ctx.stopped && bigDiff(tRes, fRes)) {
        // Stabilite: TRUE'yu tekrar gönder; ilk TRUE'ya yakın (stabil) VE FALSE'tan hâlâ farklı olmalı.
        payloads++;
        const tRes2 = await send(ip, truePay);
        const stable = !!tRes2 && tRes2.status > 0 && Math.abs(tRes2.len - tRes.len) <= Math.max(80, 0.05 * Math.max(tRes.len, 1)) && bigDiff(tRes2, fRes);
        if (stable) {
          findings.push({ inputPoint: label, type: 'SQLi', technique: 'boolean-based', evidence: `Boolean-tabanlı karşılaştırma: TRUE koşulu (\`${truePay}\`) → HTTP ${tRes.status}/${tRes.len} bayt; FALSE koşulu (\`${falsePay}\`) → HTTP ${fRes.status}/${fRes.len} bayt. TRUE yanıtı tekrarda tutarlı (${tRes2!.len} bayt), FALSE'tan KALICI içerik farkı — boolean-based SQL enjeksiyonu göstergesi (girdinin sorgu mantığını değiştirdiğini gösterir).`, severity: 'high', confidence: 'high' });
        }
      }
    }
  }

  // --- (BÖLÜM B) PATH-ID hata-tabanlı SQLi: REST/Swagger keşfiyle bulunan path uçlarında (ör.
  // /products/1) sayısal segmente zararsız tek tırnak eklenip yanıtta DB hata imzası aranır. YALNIZ
  // GET; veri değişmez. Query/form input'ları ZATEN yukarıda test edildi -> path uçları burada.
  const pathEps = surf.idEndpoints.filter((e) => e.kind === 'path').slice(0, INJ_PATH_MAX);
  let pathTested = 0;
  for (const ep of pathEps) {
    if (ctx.stopped) break;
    pathTested++;
    const label = `GET ${(() => { try { return new URL(ep.url).pathname; } catch { return ep.url; } })()} [path-id]`;
    let hit = false;
    for (const q of ["'", "')", "' AND '1'='1"]) {
      if (ctx.stopped || hit) break;
      payloads++;
      let injUrl: string;
      try { const u = new URL(ep.url); u.pathname = u.pathname.replace(/(\d{1,9})(\/?)$/, `$1${q}$2`); injUrl = u.toString(); } catch { continue; }
      const r = await ctx.fetchOnce(injUrl);
      scanVerbose(injUrl, r); // (İŞ B) path-ID probe yanıtını da ayrıntılı-hata imzası için tara
      if (r && SQL_ERROR_RE.test(r.text)) {
        hit = true;
        const sig = r.text.match(SQL_ERROR_RE)?.[0] ?? 'SQL hata imzası';
        findings.push({ inputPoint: label, type: 'SQLi', technique: 'error-based', evidence: `Path parametresine zararsız tek tırnak ("${q}") eklendiğinde yanıtta veritabanı hata imzası görüldü: "${sig.slice(0, 60)}"`, severity: 'high', confidence: 'high' });
      }
    }
  }

  if (ctx.stopped) notes.push(ctx.stopped);
  const totalTestable = inputs.length + pathEps.length;
  if (!totalTestable) notes.push(`Taranan ${surf.pagesScanned} benzersiz sayfada test edilebilir GET parametresi, form alanı veya path uç noktası bulunamadı (giriş noktası yok).` + spaHint(surf));
  const seenSkip = new Set<string>();
  const formsSkipped = [...skippedForms.entries()].map(([action, reason]) => { let p = action; try { p = new URL(action).pathname; } catch { /* ham */ } return { action: p, reason }; }).filter((f) => { const k = `${f.action}|${f.reason}`; if (seenSkip.has(k)) return false; seenSkip.add(k); return true; });
  if (formsSkipped.length) notes.push(`Güvenlik gereği ${formsSkipped.length} form gerçek POST testinden HARİÇ tutuldu (kalıcı yan etki riski): ${formsSkipped.map((f) => `${f.action} (${f.reason})`).join('; ')}.`);
  return { ok: true, baseUrl: `${cachedOriginUrl(host)}/`, pagesScanned: surf.pagesScanned, inputsFound: totalTestable, inputsTested: tested + pathTested, probesSent: ctx.sent, payloadsSent: payloads, findings, stopped: ctx.stopped, notes, verboseError: verboseError ?? undefined, formsTested: testedFormActions.size, formsSkipped };
}

// ======================================================================================
// idor_verify — kimlik-dogrulamasiz numaralandirilabilir kaynak (sinirli kapsam)
// ======================================================================================
export type IdorFinding = { endpoint: string; idParam: string; observation: string; differentResource: boolean; severity: 'high' | 'medium' | 'low' };
export type IdorEvidence = { ok: boolean; pagesScanned: number; candidates: number; endpointsTested: number; probesSent: number; findings: IdorFinding[]; stopped: string | null; notes: string[] };
const IDOR_MAX = 30; // (İş 2) keşfedilen TÜM sayısal ID adayları sistematik test edilsin (22->30)
// (İş B.2) IDOR yalnız strict discoverIdEndpoints'e değil, KEŞFEDİLEN TÜM id-parametreli GET giriş
// noktalarına genişletilir. id-benzeri parametre adları (sayısal değer şart değil — yoksa 1 varsayılır).
const ID_LIKE_PARAM_RE = /(^id$|_id$|^user|^account|^order|^invoice|^p$|^pid$|^uid$|^num$|^no$|^item|^product|^news|^cat$|^category|^page$|^record|^ref$|^doc)/i;
// (İş 2) Sayfalama/navigasyon paramları IDOR adayı DEĞİLDİR — bunlar meşru olarak farklı içerik döndürür
// (page=1 ≠ page=2) ve içerik-farkı kıyasında YANLIŞ-POZİTİF üretir. IDOR yalnız KAYNAK-kimliği içindir.
const PAGINATION_PARAM_RE = /^(p|pg|page|pageno|pagenumber|offset|start|limit|per_?page|size|count|skip|from|to|index)$/i;
function idorEndpointKey(url: string): string { try { const u = new URL(url); return `${u.origin}${u.pathname}`; } catch { return url; } }
function idorCandidatesFrom(surf: Surface): Surface['idEndpoints'] {
  const out: Surface['idEndpoints'] = [...surf.idEndpoints];
  const seen = new Set(out.map((e) => `${e.kind}:${idorEndpointKey(e.url)}:${e.idParam}`));
  for (const ip of surf.inputs) {
    if (ip.method !== 'GET') continue;
    if (PAGINATION_PARAM_RE.test(ip.param)) continue; // sayfalama -> yanlış-pozitif; IDOR adayı değil
    const rawVal = ip.params?.[ip.param];
    const numeric = !!rawVal && /^\d{1,9}$/.test(rawVal);
    // (İş 2) IDOR adayı: id-benzeri param ADI VEYA sayısal DEĞER (kaynak-id niteliğinde). Böylece
    // sitenin tüm sayfalarından toplanan TÜM sayısal ID adayları sistematik olarak test edilir.
    if (!ID_LIKE_PARAM_RE.test(ip.param) && !numeric) continue;
    const idValue = numeric ? parseInt(rawVal!, 10) : 1;
    let url: string;
    try { const u = new URL(ip.action); u.searchParams.set(ip.param, String(idValue)); url = u.toString(); } catch { continue; }
    const key = `query:${idorEndpointKey(url)}:${ip.param}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ url, idParam: ip.param, idValue, kind: 'query' });
  }
  return out;
}

// Ana sayfa HTML'inden sayisal/predictable ID iceren URL adaylarini bul.
// (10/10 Bölüm 1.2) Ayrica AYNI koleksiyon ucu icin sayfada GORULEN tum gercek ID'leri (siblingIds)
// toplar — IDOR testinde rastgele/komsu tahmin yerine sitenin KENDI verisinden gorulen ID'lerle denenir.
function discoverIdEndpoints(host: string, html: string): Array<{ url: string; idParam: string; idValue: number; kind: 'query' | 'path'; siblingIds?: number[] }> {
  const out: Array<{ url: string; idParam: string; idValue: number; kind: 'query' | 'path'; key: string }> = [];
  const seen = new Set<string>();
  const idsByKey = new Map<string, Set<number>>();
  const addId = (key: string, val: number) => { let s = idsByKey.get(key); if (!s) { s = new Set(); idsByKey.set(key, s); } s.add(val); };
  for (const m of html.matchAll(/href\s*=\s*["']([^"']+)["']/gi)) {
    const abs = absUrl(m[1].replace(/&amp;/g, '&'), host);
    if (!abs) continue;
    try {
      const u = new URL(abs);
      // (a) query'de sayisal id (?id=123, ?user=45, ?p=7)
      for (const [k, v] of u.searchParams.entries()) {
        if (/^\d{1,9}$/.test(v) && /(^id$|_id$|^user|^account|^order|^invoice|^p$|^pid$|^uid$)/i.test(k)) {
          const key = `q:${u.origin}${u.pathname}:${k}`;
          addId(key, parseInt(v, 10)); // her gorulen ID'yi (ilk olmasa da) koleksiyona ekle
          if (!seen.has(key)) { seen.add(key); out.push({ url: u.toString(), idParam: k, idValue: parseInt(v, 10), kind: 'query', key }); }
        }
      }
      // (b) path'te sayisal segment (/user/123, /orders/45)
      const pm = u.pathname.match(/^(.*\/)(\d{1,9})(\/?)$/);
      if (pm) {
        const key = `p:${u.origin}${pm[1]}`;
        addId(key, parseInt(pm[2], 10));
        if (!seen.has(key)) { seen.add(key); out.push({ url: u.toString(), idParam: pm[1].replace(/^.*\/([^/]+)\/$/, '$1') || 'path-id', idValue: parseInt(pm[2], 10), kind: 'path', key }); }
      }
    } catch { /* atla */ }
  }
  // GERCEK sibling ID'leri ekle (orijinalden farkli, en fazla 5 — gercekci IDOR denemesi icin).
  return out.slice(0, MAX_INPUTS).map(({ key, ...e }) => {
    const siblings = [...(idsByKey.get(key) ?? [])].filter((v) => v !== e.idValue).slice(0, 5);
    return siblings.length ? { ...e, siblingIds: siblings } : e;
  });
}
// Koleksiyon-benzeri uçtan sıralı sayısal ID TÜRETME (item 1). /rest/products/search gibi liste
// uçlarından /rest/products/{1..N} türetilir; ardışık ID'ler aynı JSON yapısında FARKLI içerik
// döndürürse numaralandırılabilir kaynak (olası IDOR) göstergesi. GET-only, content-diff.
const IDOR_DERIVE_MAX_BASES = 3;   // türetilecek en fazla koleksiyon bazı
const DERIVE_IDS_PER_BASE = 3;     // her baz için denenen ardışık ID sayısı (1..N; makul, 1-5 arası)
const COLLECTION_LAST_SEG_RE = /^(products?|users?|accounts?|orders?|items?|invoices?|customers?|articles?|posts?|comments?|messages?|files?|photos?|images?|feedbacks?|reviews?|baskets?|cards?|addresses?|profiles?|memories?|complaints?)$/i;
// Kesfedilen yuzeyden (input action'lari + idEndpoint URL'leri) koleksiyon bazlari cikar.
function collectionBasesFrom(surf: Surface): string[] {
  const bases = new Set<string>();
  const consider = (rawUrl: string) => {
    let u: URL; try { u = new URL(rawUrl); } catch { return; }
    const path = u.pathname.replace(/\/+$/, '').replace(/\/(search|list|all|index|find|query)$/i, '').replace(/\/\d{1,9}$/, '');
    if (!path || CRAWL_ASSET_RE.test(path)) return;
    const segs = path.split('/').filter(Boolean);
    if (segs.length < 2) return;                                  // tek-segment generic sayfalari ele
    if (!COLLECTION_LAST_SEG_RE.test(segs[segs.length - 1])) return; // cogul/liste-anlamli son segment sarti
    bases.add(`${u.origin}${path}`);
  };
  for (const ip of surf.inputs) consider(ip.action);
  for (const e of surf.idEndpoints) consider(e.url);
  return [...bases];
}

function withId(url: string, kind: 'query' | 'path', idParam: string, newVal: number): string {
  const u = new URL(url);
  if (kind === 'query') u.searchParams.set(idParam, String(newVal));
  else u.pathname = u.pathname.replace(/(\d{1,9})(\/?)$/, `${newVal}$2`);
  return u.toString();
}
// JSON YAPI (shape) imzasi — anahtar iskeletini (degerleri DEGIL) ozetler. Iki yanit ayni yapida ama
// farkli icerikli mi anlamak icin. Veri SAKLANMAZ; yalniz yapisal imza + icerik hash'i karsilastirilir.
function jsonKeyShape(v: unknown, depth = 0): string {
  if (depth > 5) return '~';
  if (Array.isArray(v)) return '[' + (v.length ? jsonKeyShape(v[0], depth + 1) : '') + ']';
  if (v && typeof v === 'object') return '{' + Object.keys(v as object).sort().map((k) => k + ':' + jsonKeyShape((v as any)[k], depth + 1)).join(',') + '}';
  return typeof v;
}
function tryJsonShape(text: string): string | null {
  const t = text.trim();
  if (!(t.startsWith('{') || t.startsWith('['))) return null;
  try { return jsonKeyShape(JSON.parse(t)); } catch { return null; }
}

// Genel 404/hata sayfasi mi? (icerik saklamadan, sadece kaba isaret)
function looksLikeNotFound(status: number, text: string): boolean {
  if (status === 404 || status === 403 || status === 401) return true;
  return /not found|bulunamadı|404|access denied|erişim engellendi|oturum aç|login required/i.test(text.slice(0, 2000));
}

export async function collectIdorEvidence(host: string, session?: AuthSession): Promise<IdorEvidence> {
  const surf = await discoverSurface(host, session);
  if (!surf.ok) return { ok: false, pagesScanned: 0, candidates: 0, endpointsTested: 0, probesSent: 0, findings: [], stopped: null, notes: ['Hedef ana sayfası çekilemedi (bağlantı kurulamadı).'] };
  const eps = idorCandidatesFrom(surf).slice(0, IDOR_MAX); // (İş B.2) tüm id-parametreli GET uçları
  const ctx = new ProbeCtx();
  ctx.label = "Yetkisiz Erişim (IDOR) Doğrulama";
  if (session) ctx.authHeaders = applyAuthHeaders({}, session); // (FAZ C) authenticated probe
  const findings: IdorFinding[] = [];
  const notes: string[] = [];
  let tested = 0;

  const base = await ctx.fetchOnce(`${cachedOriginUrl(host)}/`);
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
    // ICERIK KARSILASTIRMA (VERI SAKLANMADAN): sadece boyut degil.
    //  - JSON ise: ayni YAPI (key iskeleti) ama farkli ICERIK (hash) => guclu IDOR gostergesi
    //    (ayni boyutta olsa bile baska bir kaydin verisi olabilir).
    //  - Aksi halde: kaba uzunluk farki.
    const md5 = (s: string) => createHash('md5').update(s).digest('hex');
    const oShape = tryJsonShape(orig.text); const nShape = tryJsonShape(nb.text);
    // Ayni JSON yapisi + farkli hash => ayni boyutta olsa bile farkli kayit (guclu gosterge).
    const sameShapeDiffContent = oShape !== null && nShape !== null && oShape === nShape && md5(orig.text) !== md5(nb.text) && orig.text.trim().length > 2;
    const lenDiff = Math.abs(nb.len - orig.len) > 64; // HTML'de dinamik token/zaman gurultusune karsi kaba esik
    const different = nb.status === 200 && !nbNF && (sameShapeDiffContent || lenDiff);
    if (different && !origNF) {
      const how = sameShapeDiffContent
        ? 'aynı YAPIDA (JSON iskeleti) ancak FARKLI İÇERİKLİ yanıt döndü — büyük olasılıkla başka bir kaydın verisi (dönen veri raporda gösterilmez)'
        : lenDiff ? 'orijinalden farklı boyutta/içerikli yanıt döndü' : 'orijinalden farklı içerikli yanıt döndü';
      findings.push({ endpoint: epLabel, idParam: ep.idParam, observation: `Kimlik doğrulaması olmadan komşu ID (${neighborVal}) için 200 yanıt ve ${how}. Numaralandırılabilir kaynak erişimi (olası IDOR) göstergesi.`, differentResource: true, severity: sameShapeDiffContent ? 'medium' : 'low' });
    } else if (nb.status === 200 && !nbNF && origNF) {
      findings.push({ endpoint: epLabel, idParam: ep.idParam, observation: `Komşu ID (${neighborVal}) için 200 yanıt döndü; orijinal ID erişilebilir bir kaynak vermemişti — numaralandırma ile erişilebilir kayıt göstergesi (manuel doğrulama önerilir).`, differentResource: true, severity: 'low' });
    }
    // (10/10 Bölüm 1.2) GERÇEK-ID denemesi: rastgele/komşu tahmin yerine, sitenin KENDİ sayfalarında
    // GÖRÜLEN gerçek ID'lerle test (ör. bir listeleme sayfasında geçen id=5, id=8...). Daha güçlü kanıt.
    for (const realId of (ep.siblingIds ?? []).slice(0, 5)) { // (İş 2) daha fazla gerçek sibling ID sistematik denenir
      if (ctx.stopped) break;
      const rr = await ctx.fetchOnce(withId(ep.url, ep.kind, ep.idParam, realId));
      if (!rr || ctx.stopped) continue;
      const rNF = looksLikeNotFound(rr.status, rr.text);
      const rShape = tryJsonShape(rr.text);
      const rSameShapeDiff = oShape !== null && rShape !== null && oShape === rShape && md5(orig.text) !== md5(rr.text) && orig.text.trim().length > 2;
      const rDiff = rr.status === 200 && !rNF && (rSameShapeDiff || Math.abs(rr.len - orig.len) > 64);
      if (rDiff && !origNF) {
        const how = rSameShapeDiff ? 'aynı YAPIDA (JSON iskeleti) ancak FARKLI İÇERİKLİ yanıt döndü (dönen veri raporda gösterilmez)' : 'orijinalden farklı içerikli yanıt döndü';
        findings.push({ endpoint: epLabel, idParam: ep.idParam, observation: `Kimlik doğrulaması olmadan, sitenin KENDİ sayfalarında GÖRÜLEN gerçek bir ID (${realId}) için ${how}. Rastgele/komşu tahmin değil — koleksiyonda gözlemlenen gerçekçi ID ile erişildi (daha güçlü IDOR göstergesi).`, differentResource: true, severity: rSameShapeDiff ? 'medium' : 'low' });
        break; // ilk gerçek-ID kanıtı yeterli; ek prob gönderme
      }
    }
  }

  // --- (2) KOLEKSIYON-BENZERI UCLARDAN TURETILMIS sirali ID denemesi (GET-only, content-diff) ---
  // /rest/products/search gibi liste uclarindan /rest/products/{1..N} TURETILIR; ardisik ID'ler ayni
  // JSON YAPIsinda FARKLI icerik dondururse -> numaralandirilabilir kaynak (olasi IDOR) gostergesi.
  // Tum istekler ayni ProbeCtx uzerinden -> circuit breaker + 130 prob tavanina DAHIL. Veri SAKLANMAZ.
  const md5f = (s: string) => createHash('md5').update(s).digest('hex');
  const epsPathBases = new Set(eps.filter((e) => e.kind === 'path').map((e) => { try { const u = new URL(e.url); return u.origin + u.pathname.replace(/\/\d{1,9}\/?$/, ''); } catch { return ''; } }));
  const derivedBases = collectionBasesFrom(surf).filter((b) => !epsPathBases.has(b)).slice(0, IDOR_DERIVE_MAX_BASES);
  for (const base of derivedBases) {
    if (ctx.stopped) break;
    tested++;
    const got: Array<{ id: number; shape: string | null; hash: string; len: number; ok: boolean }> = [];
    for (let id = 1; id <= DERIVE_IDS_PER_BASE; id++) {
      if (ctx.stopped) break;
      const r = await ctx.fetchOnce(`${base}/${id}`);
      if (!r || r.status === 0) continue;
      got.push({ id, shape: tryJsonShape(r.text), hash: md5f(r.text), len: r.len, ok: r.status === 200 && !looksLikeNotFound(r.status, r.text) });
    }
    const ok200 = got.filter((g) => g.ok);
    // Ayni JSON YAPIsi + >=2 farkli hash => farkli kayitlar (guclu gosterge). Aksi: kaba uzunluk farki.
    const byShape = new Map<string, Set<string>>();
    for (const g of ok200) if (g.shape) { if (!byShape.has(g.shape)) byShape.set(g.shape, new Set()); byShape.get(g.shape)!.add(g.hash); }
    const shapeEnum = [...byShape.values()].some((hs) => hs.size >= 2);
    const lenEnum = !shapeEnum && ok200.length >= 2 && new Set(ok200.map((g) => g.hash)).size >= 2 && (Math.max(...ok200.map((g) => g.len)) - Math.min(...ok200.map((g) => g.len)) > 64);
    if (shapeEnum || lenEnum) {
      const path = (() => { try { return new URL(base).pathname; } catch { return base; } })();
      findings.push({ endpoint: `${path}/{id}`, idParam: 'path-id', observation: `Koleksiyon-benzeri uçtan türetilen sıralı ID'ler (${ok200.map((g) => g.id).join(', ')}) kimlik doğrulaması olmadan 200 döndürdü ve ${shapeEnum ? 'aynı YAPIDA (JSON iskeleti) FARKLI İÇERİKLİ' : 'farklı boyutlu/içerikli'} yanıtlar üretti — numaralandırılabilir kaynak erişimi (olası IDOR) göstergesi (dönen veri raporda gösterilmez).`, differentResource: true, severity: shapeEnum ? 'medium' : 'low' });
    }
  }

  const totalCandidates = eps.length + derivedBases.length;
  if (derivedBases.length) notes.push(`Ayrıca **${derivedBases.length}** koleksiyon-benzeri uçtan (ör. \`${(() => { try { return new URL(derivedBases[0]).pathname; } catch { return derivedBases[0]; } })()}\`) sıralı sayısal ID'ler (\`/{1..${DERIVE_IDS_PER_BASE}}\`) türetilip GET ile içerik-farkı yöntemiyle test edildi.`);
  if (ctx.stopped) notes.push(ctx.stopped);
  if (!totalCandidates) notes.push(`Taranan ${surf.pagesScanned} benzersiz sayfada sayısal/tahmin-edilebilir ID içeren bir uç nokta (ör. \`?id=123\`, \`/user/45\`) veya sıralı ID türetilebilecek koleksiyon ucu bulunamadı.` + spaHint(surf));
  return { ok: true, pagesScanned: surf.pagesScanned, candidates: totalCandidates, endpointsTested: tested, probesSent: ctx.sent, findings, stopped: ctx.stopped, notes };
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
// agentStatus (ajan kontrolleri icin): 'analyzed' = advisory GERCEKTEN cagrildi (aday vardi) ;
// 'no_candidate' = pasif kesifle hic aday yuzey yoktu, advisory CAGRILMADI ; 'unavailable' = advisory
// cagrildi ama tamamlanamadi (anahtar yok/timeout/hata). Rapor bu ucunu NET ayirir (dururstluk).
export type ActiveCheckEvidence = { ok: boolean; pagesScanned: number; inputsFound: number; probesSent: number; findings: VFinding[]; stopped: string | null; notes: string[]; agentUsed?: boolean; agentStatus?: 'analyzed' | 'no_candidate' | 'unavailable' };

// (İş Mantığı + Race) SINIRLI PentAGI ajan onerileri — host basina TEK cagri, iki kontrol PAYLASIR.
// (Bölüm 2 — İZOLE/DENEYSEL advisory) Advisory (PentAGI-tarzı LLM önceliklendirme sinyali) yalnızca
// AÇIKÇA izin verilen hedeflerde çalışır — VARSAYILAN: KAPALI. ACTIVE_VERIFY_ADVISOR_HOSTS env'i virgülle
// ayrılmış host listesi (ör. "testaspnet.vulnweb.com"); boş/tanımsız -> advisory HER hedefte kapalı ve
// kontroller %100 deterministik çalışır. Canlıya default açık DEĞİL (kritik: uzak LLM'e yüzey verisi
// gönderme yalnız izin verilen deney hedeflerinde). Advisory'nin önerdiği confidence/severity ASLA
// doğrudan kabul edilmez (çağıran kod nötrler); nihai sınıflandırma deterministik taxonomy'nindir.
function advisorAllowed(host: string): boolean {
  const allow = (process.env.ACTIVE_VERIFY_ADVISOR_HOSTS ?? '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  return allow.includes(host.toLowerCase());
}
const AGENT_CACHE = new Map<string, { at: number; p: Promise<AgentSuggestion[] | null> }>();
function getAgentScenarios(host: string, surf: Surface): Promise<AgentSuggestion[] | null> {
  if (!advisorAllowed(host)) return Promise.resolve(null); // izole: default KAPALI -> deterministik fallback
  const c = AGENT_CACHE.get(host);
  if (c && Date.now() - c.at < 180_000) return c.p;
  const forms = [...(surf.massAssignForm ? [surf.massAssignForm.action] : []), ...surf.uploadForms.map((f) => f.action)];
  const p = requestAgentScenarios(host, {
    inputs: surf.inputs.map((i) => ({ method: i.method, action: i.action, param: i.param })),
    forms, apiWrites: surf.apiWrites,
  }).catch(() => null);
  AGENT_CACHE.set(host, { at: Date.now(), p });
  return p;
}
// Ajanin sectigi inputPoint etiketini GUVENLI bir GET URL'sine cevir (ayni host + ic-ag ASLA).
function agentInputToUrl(label: string, host: string): string | null {
  const m = label.match(/^(?:GET|POST|HEAD|PUT|PATCH|DELETE)\s+(.+)$/i);
  let rest = (m ? m[1] : label).trim().replace(/\?$/, '');
  if (rest.includes('?') && !/=/.test(rest.split('?')[1] || '')) rest = rest + '=1'; // "path?param" -> "path?param=1"
  try {
    const u = rest.startsWith('http') ? new URL(rest) : new URL(rest.startsWith('/') ? rest : `/${rest}`, `${cachedOriginUrl(host)}/`);
    if (u.hostname.toLowerCase() !== host.toLowerCase() || isInternalHost(u.hostname)) return null;
    return u.toString();
  } catch { return null; }
}

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

export async function collectSsrfEvidence(host: string, session?: AuthSession): Promise<ActiveCheckEvidence> {
  const surf = await discoverSurface(host, session);
  if (!surf.ok) return { ok: false, pagesScanned: 0, inputsFound: 0, probesSent: 0, findings: [], stopped: null, notes: ['Hedef ana sayfası çekilemedi.'] };
  const inputs = surf.inputs.filter((ip) => FETCH_PARAM_RE.test(ip.param)).slice(0, 6);
  const ctx = new ProbeCtx();
  if (session) ctx.authHeaders = applyAuthHeaders({}, session); // (FAZ C) authenticated probe
  const findings: VFinding[] = [];
  const notes: string[] = [];
  const base = await ctx.fetchOnce(`${cachedOriginUrl(host)}/`);
  if (base) ctx.baseline = base.ms;

  for (const ip of inputs) {
    if (ctx.stopped) break;
    // (FORM-POST GÜVENLİK KAPISI) YASAK türdeki forma gerçek POST atma.
    if (ip.method === 'POST' && ip.source === 'form' && forbiddenFormReason(ip.action, Object.keys(ip.params))) continue;
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

export async function collectRceEvidence(host: string, session?: AuthSession): Promise<ActiveCheckEvidence> {
  const surf = await discoverSurface(host, session);
  if (!surf.ok) return { ok: false, pagesScanned: 0, inputsFound: 0, probesSent: 0, findings: [], stopped: null, notes: ['Hedef ana sayfası çekilemedi.'] };
  const inputs = surf.inputs.slice(0, 4);
  const ctx = new ProbeCtx();
  if (session) ctx.authHeaders = applyAuthHeaders({}, session); // (FAZ C) authenticated probe
  const findings: VFinding[] = [];
  const notes: string[] = [];
  const base = await ctx.fetchOnce(`${cachedOriginUrl(host)}/`);
  if (base) ctx.baseline = base.ms;

  for (const ip of inputs) {
    if (ctx.stopped) break;
    // (FORM-POST GÜVENLİK KAPISI) YASAK türdeki forma gerçek POST atma.
    if (ip.method === 'POST' && ip.source === 'form' && forbiddenFormReason(ip.action, Object.keys(ip.params))) continue;
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
function discoverUploadForms(host: string, html: string): Array<{ action: string; fileField: string; otherFields: string[]; source: 'dom' }> {
  const out: Array<{ action: string; fileField: string; otherFields: string[]; source: 'dom' }> = [];
  for (const fm of html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)) {
    const inner = fm[2];
    const fileField = inner.match(/<input\b[^>]*type=["']file["'][^>]*\bname=["']([^"']+)["']/i)?.[1]
      ?? inner.match(/<input\b[^>]*\bname=["']([^"']+)["'][^>]*type=["']file["']/i)?.[1];
    if (!fileField) continue;
    const action = absUrl(fm[1].match(/action\s*=\s*["']([^"']*)["']/i)?.[1] || '/', host);
    if (!action) continue;
    const others: string[] = [];
    for (const im of inner.matchAll(/<input\b[^>]*\bname=["']([^"']+)["']/gi)) if (im[1] !== fileField && !/^(csrf|_token|authenticity_token)/i.test(im[1])) others.push(im[1]);
    out.push({ action, fileField, otherFields: others.slice(0, 8), source: 'dom' });
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
  const base = await ctx.fetchOnce(`${cachedOriginUrl(host)}/`);
  if (base) ctx.baseline = base.ms;

  for (const f of forms) {
    if (ctx.stopped) break;
    // (FORM-POST GÜVENLİK KAPISI) Yükleme formu aslında kayıt/iletişim/yorum formuysa (ör. avatar-yükleme
    // içeren signup, ekli iletişim formu) gerçek POST atma — kalıcı hesap/e-posta/kayıt yaratabilir.
    if (forbiddenFormReason(f.action, [f.fileField, ...f.otherFields])) continue;
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
  const netForms = forms.filter((f) => f.source === 'network').length;
  if (netForms > 0) notes.push(`Bu kontrolde, DOM'daki \`<input type=file>\` formlarına **ek olarak**, JS render sırasında gözlemlenen ağ trafiğinden (multipart/form-data veya upload/file/avatar gibi yollar) **${netForms}** dosya-yükleme ucu keşfedilip test edildi.`);
  if (ctx.stopped) notes.push(ctx.stopped);
  if (!forms.length) notes.push(`Taranan ${surf.pagesScanned} benzersiz sayfada dosya yükleme formu (input type=file) veya ağ trafiğinde dosya-yükleme ucu bulunamadı.` + spaHint(surf));
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
  const base = await ctx.fetchOnce(`${cachedOriginUrl(host)}/`);
  if (base) ctx.baseline = base.ms;
  for (const url of [...links].slice(0, 4)) {
    if (ctx.stopped) break;
    const r = await ctx.fetchOnce(url); // GET — state degistirmez
    if (r && r.status === 200 && !/oturum|login|giriş yap|unauthorized|403|yetkisiz/i.test(r.text.slice(0, 2000))) {
      findings.push({ check: 'business_logic', inputPoint: new URL(url).pathname, vulnerable: true, technique: 'observation (step-skip, GET only)', evidence: `Bir "başarılı/onay" adımı sayfası (${new URL(url).pathname}) ön koşul olmadan doğrudan GET ile erişilebilir göründü — adım-atlama (business logic) göstergesi olabilir; manuel doğrulama önerilir.`, confidence: 'low', severity: 'low', sideEffectRisk: 'none' });
    }
  }
  // (c) SINIRLI PentAGI AJAN: bulunan yuzeyden is-mantigi acisindan ilginc GET uclarini SECER (JSON).
  // Ajan HTTP ATMAZ — backend onerilen inputPoint'i GUVENLI GET ile dogrular. Basarisiz -> fallback.
  let agentUsed = false;
  const scenarios = await getAgentScenarios(host, surf).catch(() => null);
  if (scenarios !== null) {
    agentUsed = true;
    for (const s of scenarios.filter((x) => x.check === 'business_logic').slice(0, 4)) {
      if (ctx.stopped) break;
      const url = agentInputToUrl(s.inputPoint, host); // ayni-host + ic-ag guard
      if (!url) continue;
      const r = await ctx.fetchOnce(url); // GET-only (state degistirmez)
      if (r && r.status > 0 && r.status < 500 && !/oturum|login|giriş yap|unauthorized|403|yetkisiz/i.test(r.text.slice(0, 1500))) {
        findings.push({ check: 'business_logic', inputPoint: (() => { try { return new URL(url).pathname; } catch { return s.inputPoint; } })(), vulnerable: true, technique: 'PentAGI ajanı seçti + backend GET ile doğruladı', evidence: `⚠️ DOLAYLI/ZAYIF GÖSTERGE — doğrudan zafiyet kanıtı DEĞİLDİR. Tek dayanak: bu uç nokta PentAGI ajanınca iş-mantığı açısından aday seçildi ve backend GET ile erişilebilir bulundu (HTTP ${r.status}). Fiyat/miktar/rol gibi alanların sunucu-taraflı doğrulanıp doğrulanmadığı TEST EDİLMEDİ; bu davranışsal bir işarettir, gerçek bir açık olup olmadığı KESİNLİKLE manuel doğrulama gerektirir (dönen veri gösterilmez).`, confidence: 'low', severity: s.severity === 'high' ? 'medium' : s.severity, sideEffectRisk: 'none' });
      }
    }
  }

  if (ctx.stopped) notes.push(ctx.stopped);
  if (agentUsed) notes.push('Bu kontrol, keşfedilen yüzey üzerinde **yapay zekâ destekli advisory (tek LLM çağrısı) ile analiz edilmiştir** (advisory yalnızca yapılandırılmış öneri üretir; tüm istekler backend’in güvenli GET fonksiyonlarından geçer; advisory doğrudan HTTP atmaz).');
  if (!findings.length) notes.push(`Taranan ${surf.pagesScanned} benzersiz sayfada gözlemlenebilir bir istemci-tarafı fiyat/miktar alanı veya doğrudan erişilebilir "onay" adımı bulunamadı.` + spaHint(surf));
  return { ok: true, pagesScanned: surf.pagesScanned, inputsFound: (hiddenPrice ? 1 : 0) + links.size, probesSent: ctx.sent, findings, stopped: ctx.stopped, notes, agentUsed };
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
  const base = await ctx.fetchOnce(`${cachedOriginUrl(host)}/`);
  if (base) ctx.baseline = base.ms;

  // (FORM-POST GÜVENLİK KAPISI — KRİTİK) Mass-assignment (over-posting) YALNIZ gerçek KAYIT/GÜNCELLEME
  // formunda anlamlıdır. İki ayrı sebeple POST atlanır:
  //  (a) YASAK tür (kayıt/iletişim/parola/ödeme/abonelik) -> gerçek POST kalıcı hesap/e-posta/kayıt yaratır.
  //  (b) login/arama formu -> mass-assignment HEDEFİ DEĞİLDİR (login zaten "Giriş Baypası" kontrolünde
  //      test edilir); over-posting alanı eklemek yanıltıcı sinyal üretir. Bunlar da atlanır.
  // Geriye YALNIZ 'other' (yasak-olmayan, login/arama-olmayan) create/update formu kalır — pre-auth'ta
  // nadirdir; yoksa bu kontrol o hedefte "İncelenemedi" (güvenli test edilebilir giriş noktası yok).
  const massCat = form ? formCategory(form.action, form.fields) : null;
  const massBlockReason = !form ? null
    : (forbiddenFormReason(form.action, form.fields)
       ?? (massCat === 'login' ? 'giriş (login) formu — mass-assignment/over-posting hedefi değildir (Giriş Baypası kontrolünde ayrıca test edilir)'
           : massCat === 'search' ? 'arama/filtre formu — kayıt/güncelleme (over-posting) hedefi değildir'
           : null));
  if (form && massBlockReason) {
    let p = form.action; try { p = new URL(form.action).pathname; } catch { /* ham */ }
    notes.push(`Mass-assignment adayı form (${p}) gerçek POST testinden HARİÇ tutuldu: ${massBlockReason}. Güvenli, YASAK olmayan bir kayıt/güncelleme (over-posting) giriş noktası bulunmadığından bu kontrol bu hedefte kimlik-doğrulaması olmadan güvenle test edilemedi (kimlik-doğrulamalı derin test Tam Kapsamlı Pentest kapsamındadır).`);
  }
  if (form && !massBlockReason) {
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
  // SINIRLI PentAGI AJAN: race/mass-assign acisindan ilginc uclari SECER (JSON). Ajan HTTP ATMAZ;
  // backend YALNIZ GET-gozlem yapar (yeni POST/yikici paralel yazma YOK — mevcut tek-POST deterministik).
  let agentUsed = false;
  const scenarios = await getAgentScenarios(host, surf).catch(() => null);
  if (scenarios !== null) {
    agentUsed = true;
    for (const s of scenarios.filter((x) => x.check === 'race_massassign').slice(0, 4)) {
      if (ctx.stopped) break;
      const url = agentInputToUrl(s.inputPoint, host);
      if (!url) continue;
      const r = await ctx.fetchOnce(url); // GET-only gozlem
      if (r && r.status > 0 && r.status < 500 && !/oturum|login|giriş yap|unauthorized|403|yetkisiz/i.test(r.text.slice(0, 1500))) {
        findings.push({ check: 'race_massassign', inputPoint: (() => { try { return new URL(url).pathname; } catch { return s.inputPoint; } })(), vulnerable: true, technique: 'PentAGI ajanı seçti + backend GET ile gözlemledi', evidence: `⚠️ DOLAYLI/ZAYIF GÖSTERGE — doğrudan zafiyet kanıtı DEĞİLDİR. Tek dayanak: bu uç nokta PentAGI ajanınca over-posting/eşzamanlılık açısından aday seçildi ve backend GET ile erişilebilir bulundu (HTTP ${r.status}). Yetki değişikliği/kupon tüketimi gibi kesin doğrulama yıkıcı olduğundan YAPILMADI; gerçek bir açık olup olmadığı manuel test gerektirir.`, confidence: 'low', severity: 'low', sideEffectRisk: 'none' });
      }
    }
  }

  // Race yüzeyi — otomatik yıkıcı paralel yazma YAPILMAZ (güvenlik); not olarak belirtilir.
  notes.push('Race-condition (eşzamanlılık) testi, tüketilebilir bir kaynağı (kupon/stok) gerçekten değiştirme riski taşıdığından bu otomatik taramada **çalıştırılmadı**; güvenli/test edilebilir bir uç nokta ile manuel doğrulama önerilir.');
  if (agentUsed) notes.push('Bu kontrol, keşfedilen yüzey üzerinde **yapay zekâ destekli advisory (tek LLM çağrısı) ile analiz edilmiştir** (advisory yalnızca yapılandırılmış öneri üretir; hiçbir yıkıcı/state-değiştiren istek advisory tarafından tetiklenmez, tüm istekler backend’in güvenli fonksiyonlarından geçer).');
  if (ctx.stopped) notes.push(ctx.stopped);
  if (!form) notes.push(`Taranan ${surf.pagesScanned} benzersiz sayfada mass-assignment için uygun (tamamlama/ödeme dışı) kayıt/profil formu bulunamadı.` + spaHint(surf));
  // (İş A düzeltmesi) POST engellendiyse (yasak/login/arama) GERÇEK test yapılmadı -> inputsFound=0 ki
  // Pozitif Güvence/kontrol tablosu bunu "Temiz" değil "İncelenemedi/Kapsam dışı" göstersin (dürüstlük).
  const massTested = !!form && !massBlockReason;
  return { ok: true, pagesScanned: surf.pagesScanned, inputsFound: massTested ? 1 : 0, probesSent: ctx.sent, findings, stopped: ctx.stopped, notes, agentUsed };
}
