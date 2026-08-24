/**
 * (Tam Kapsamlı Pentest — Client-Side / JS Analizi) PASİF/STATİK JS bundle analizi. Tarayıcının
 * zaten yüklediği JS'leri çekip 3 kontrol yapar — aktif istismar YOK, yalnız GET + statik okuma:
 *   A) JS'te sızmış GERÇEK sır (özel anahtar/AWS/Stripe sk_live/GitHub/Slack/DB string…)
 *   B) Source-map ifşası (.map erişilebilir → kaynak kod sızıntısı)
 *   C) Bilinen-zafiyetli JS kütüphanesi (sürüm-tabanlı, MUHAFAZAKÂR CVE eşleme)
 *
 * SÜTUN 0: Her bulgu GERÇEKTEN çekilen dosyaya/pattern'e dayanır (uydurma yok). Tasarım-gereği-PUBLIC
 * anahtarlar (Firebase apiKey, GTM/GA ID, Google Maps browser key, Stripe pk_, reCAPTCHA site key)
 * "ifşa/zafiyet" SAYILMAZ → "bilgilendirici: public-by-design" olarak ETİKETLENİR (nomorelink dersi).
 *
 * (Faz 1-B) fetchClientCorpus: home HTML + same-origin JS'i TEK sefer çeker (60s cache) ve hem bu
 * modül hem clientSideChecks.ts paylaşır (çift fetch yok).
 */
import { resolveOrigin, cachedOriginUrl } from './surfaceEvidence.js';
import { logScanStep } from './scanLogger.js';
import type { ActiveCheckEvidence, VFinding } from './activeVerifyEvidence.js';

const MAX_JS_FILES = 15;          // taranacak en fazla same-origin JS dosyası
const MAX_BYTES = 2_000_000;      // dosya başına okuma tavanı (sourceMappingURL genelde sonda)
const MAX_MAP_TRIES = 12;
const REQ_TIMEOUT = 12_000;
const MIN_DELAY = 250;            // istekler arası minimum gecikme (nazik)
let lastAt = 0;

type Fetched = { status: number; text: string; len: number; url: string };

export async function getCapped(url: string, cap = MAX_BYTES): Promise<Fetched | null> {
  const wait = MIN_DELAY - (Date.now() - lastAt);
  if (wait > 0) await new Promise((r) => setTimeout(r, wait));
  lastAt = Date.now();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), REQ_TIMEOUT);
  const t0 = Date.now();
  try {
    const res = await fetch(url, { redirect: 'follow', signal: ctrl.signal, headers: { 'user-agent': 'CyberTestify-JSAnalysis/1.0', accept: '*/*' } });
    const buf = Buffer.from(await res.arrayBuffer());
    const text = (buf.length > cap ? buf.subarray(0, cap) : buf).toString('utf-8');
    logScanStep({ step: 'Client-Side / JS Analizi', method: 'GET', url, status: res.status, durationMs: Date.now() - t0, sizeBytes: buf.length });
    return { status: res.status, text, len: buf.length, url };
  } catch {
    logScanStep({ step: 'Client-Side / JS Analizi', method: 'GET', url, status: 0, durationMs: Date.now() - t0, level: 'warn', summary: 'JS/HTML çekilemedi' });
    return null;
  } finally {
    clearTimeout(timer);
  }
}

const sameHost = (u: string, host: string) => { try { return new URL(u).hostname.toLowerCase() === host.toLowerCase(); } catch { return false; } };
const absUrl = (raw: string, host: string): string | null => {
  try { return new URL(raw, `${cachedOriginUrl(host)}/`).toString(); } catch { return null; }
};
// Sırrın son ~6 karakterini bırakıp gerisini maskele (GERÇEK sır raporda AÇIKÇA gösterilmez).
const redact = (s: string): string => {
  const t = s.trim();
  if (t.length <= 10) return '••••••';
  return t.slice(0, 4) + '…' + '•'.repeat(6) + '…' + t.slice(-4);
};

// ================= PAYLAŞILAN CORPUS (Faz 1-A + 1-B tek fetch) =================
export type ClientJsFile = { url: string; body: string };
export type ClientCorpus = {
  origin: string; reachable: boolean; homeHtml: string;
  inlineScripts: string[];
  sameOriginJs: ClientJsFile[];
  externalScripts: string[];
  scriptTags: Array<{ url: string; external: boolean; hasIntegrity: boolean }>;
  styleTags: Array<{ url: string; external: boolean; hasIntegrity: boolean }>;
  blankLinks: Array<{ href: string; hasRelSafe: boolean; external: boolean }>;
  fetches: number;
};
const corpusCache = new Map<string, { at: number; corpus: ClientCorpus }>();

export async function fetchClientCorpus(host: string): Promise<ClientCorpus> {
  const cached = corpusCache.get(host);
  if (cached && Date.now() - cached.at < 60_000) return cached.corpus;
  await resolveOrigin(host).catch(() => null);
  const origin = cachedOriginUrl(host);
  const empty: ClientCorpus = { origin, reachable: false, homeHtml: '', inlineScripts: [], sameOriginJs: [], externalScripts: [], scriptTags: [], styleTags: [], blankLinks: [], fetches: 1 };
  const home = await getCapped(`${origin}/`);
  if (!home || home.status >= 400 || !home.text) { corpusCache.set(host, { at: Date.now(), corpus: empty }); return empty; }
  const html = home.text;

  const scriptTags: ClientCorpus['scriptTags'] = [];
  const scriptSrcs: string[] = [];
  const inlineScripts: string[] = [];
  for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
    const attrs = m[1]; const body = m[2];
    const src = attrs.match(/\bsrc\s*=\s*["']([^"']+)["']/i)?.[1];
    if (src) {
      const u = absUrl(src, host); if (!u) continue;
      scriptTags.push({ url: u, external: !sameHost(u, host), hasIntegrity: /\bintegrity\s*=/i.test(attrs) });
      scriptSrcs.push(u);
    } else if (body.trim()) inlineScripts.push(body);
  }
  const styleTags: ClientCorpus['styleTags'] = [];
  for (const m of html.matchAll(/<link\b([^>]*)>/gi)) {
    const attrs = m[1];
    if (!/\brel\s*=\s*["']?[^"'>]*stylesheet/i.test(attrs)) continue;
    const href = attrs.match(/\bhref\s*=\s*["']([^"']+)["']/i)?.[1]; if (!href) continue;
    const u = absUrl(href, host); if (!u) continue;
    styleTags.push({ url: u, external: !sameHost(u, host), hasIntegrity: /\bintegrity\s*=/i.test(attrs) });
  }
  const blankLinks: ClientCorpus['blankLinks'] = [];
  for (const m of html.matchAll(/<a\b([^>]*)>/gi)) {
    const attrs = m[1];
    if (!/\btarget\s*=\s*["']?_blank/i.test(attrs)) continue;
    const href = attrs.match(/\bhref\s*=\s*["']([^"']+)["']/i)?.[1] ?? '';
    const rel = attrs.match(/\brel\s*=\s*["']([^"']*)["']/i)?.[1] ?? '';
    const abs = absUrl(href, host);
    blankLinks.push({ href: href.slice(0, 200), hasRelSafe: /noopener|noreferrer/i.test(rel), external: abs ? !sameHost(abs, host) : /^https?:\/\//i.test(href) });
  }

  const sameOriginJs: ClientJsFile[] = [];
  const externalScripts: string[] = [];
  let fetches = 1;
  for (const u of scriptSrcs) {
    if (sameHost(u, host)) {
      if (sameOriginJs.length >= MAX_JS_FILES) continue;
      const r = await getCapped(u); fetches++;
      if (r && r.status < 400 && r.text) sameOriginJs.push({ url: u, body: r.text });
    } else externalScripts.push(u);
  }

  const corpus: ClientCorpus = { origin, reachable: true, homeHtml: html, inlineScripts, sameOriginJs, externalScripts, scriptTags, styleTags, blankLinks, fetches };
  corpusCache.set(host, { at: Date.now(), corpus });
  return corpus;
}

// ============================ A) GERÇEK SIRLAR ============================
const REAL_SECRET_RULES: Array<{ id: string; re: RegExp; why: string }> = [
  { id: 'private_key', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g, why: 'Özel anahtar (private key) — imzalama/şifre çözme yetkisi verir.' },
  { id: 'aws_akia', re: /\bAKIA[0-9A-Z]{16}\b/g, why: 'AWS erişim anahtarı kimliği (AKIA…) — AWS hesabına programatik erişim.' },
  { id: 'gcp_service_account', re: /"type"\s*:\s*"service_account"[\s\S]{0,400}?"private_key"\s*:\s*"-----BEGIN/g, why: 'Google Cloud service-account JSON (private_key içeriyor) — sunucu kimliği.' },
  { id: 'stripe_secret', re: /\bsk_live_[0-9a-zA-Z]{20,}\b/g, why: 'Stripe GİZLİ anahtarı (sk_live_) — ödeme hesabında tam yetki (publishable pk_ İLE KARIŞTIRMA).' },
  { id: 'github_token', re: /\bgh[posru]_[0-9A-Za-z]{36,}\b/g, why: 'GitHub kişisel erişim/uygulama token’ı — depo/kod erişimi.' },
  { id: 'gitlab_token', re: /\bglpat-[0-9A-Za-z_-]{20,}\b/g, why: 'GitLab kişisel erişim token’ı.' },
  { id: 'slack_token', re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g, why: 'Slack API token’ı — çalışma alanı erişimi.' },
  { id: 'db_conn_string', re: /\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqps?):\/\/[^\s"'`]+:[^\s"'`@]+@[^\s"'`/]+/gi, why: 'Kimlik bilgili veritabanı/servis bağlantı dizesi (kullanıcı:parola@host) — doğrudan erişim.' },
  { id: 'sendgrid_key', re: /\bSG\.[0-9A-Za-z_-]{16,}\.[0-9A-Za-z_-]{16,}\b/g, why: 'SendGrid API anahtarı — e-posta gönderim yetkisi.' },
  { id: 'twilio_key', re: /\bSK[0-9a-fA-F]{32}\b/g, why: 'Twilio API anahtarı göstergesi.' },
];

// PUBLIC-BY-DESIGN (istismar edilebilir SIR DEĞİL) — bulgu değil, "bilgilendirici" olarak etiketlenir.
const PUBLIC_BY_DESIGN_RULES: Array<{ id: string; label: string; labelDe: string; re: RegExp }> = [
  { id: 'google_api_key', label: 'Google API anahtarı (Firebase/Maps browser key — public-by-design, referer/kota ile sınırlanır)', labelDe: 'Google-API-Schlüssel (Firebase/Maps Browser-Key — public-by-design, durch Referer/Kontingent begrenzt)', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { id: 'stripe_publishable', label: 'Stripe publishable key (pk_ — public-by-design, gizli değildir)', labelDe: 'Stripe Publishable Key (pk_ — public-by-design, nicht geheim)', re: /\bpk_(?:live|test)_[0-9a-zA-Z]{20,}\b/g },
  { id: 'ga_measurement', label: 'GA/GTM/Ads ölçüm kimliği (public-by-design)', labelDe: 'GA-/GTM-/Ads-Mess-ID (public-by-design)', re: /\b(?:G-[A-Z0-9]{6,}|GTM-[A-Z0-9]{5,}|UA-\d{4,}-\d+|AW-\d{6,})\b/g },
  { id: 'recaptcha_site', label: 'reCAPTCHA SITE key (public-by-design; secret key ayrıdır)', labelDe: 'reCAPTCHA SITE-Key (public-by-design; der Secret-Key ist separat)', re: /\b6L[0-9A-Za-z_-]{38}\b/g },
  { id: 'firebase_cfg', label: 'Firebase istemci yapılandırması (apiKey/authDomain/projectId — public-by-design, güvenlik Firebase kurallarındadır)', labelDe: 'Firebase-Client-Konfiguration (apiKey/authDomain/projectId — public-by-design, die Sicherheit liegt in den Firebase-Regeln)', re: /(?:authDomain|messagingSenderId|storageBucket)\s*:\s*["'][^"']+["']/g },
];

// ============================ C) BİLİNEN-ZAFİYETLİ KÜTÜPHANELER ============================
type VulnRange = { ltOr?: string; geLt?: [string, string]; cves: string; note: string };
const KNOWN_VULN_LIBS: Record<string, { display: string; ranges: VulnRange[]; eol?: string }> = {
  jquery: { display: 'jQuery', ranges: [
    { ltOr: '3.5.0', cves: 'CVE-2020-11022, CVE-2020-11023 (XSS)', note: '<3.5.0: htmlPrefilter kaynaklı XSS' },
    { ltOr: '1.9.0', cves: 'CVE-2012-6708, CVE-2015-9251 (XSS)', note: '<1.9.0: selector/ajax XSS' },
  ] },
  angular: { display: 'AngularJS (1.x)', eol: 'AngularJS 1.x EOL (Ocak 2022) — güvenlik yaması almıyor', ranges: [
    { ltOr: '1.99.0', cves: 'CVE-2024-21490 (ReDoS) + AngularJS 1.x EOL', note: 'AngularJS 1.x EOL; sürüme göre sandbox-bypass/ReDoS' },
  ] },
  bootstrap: { display: 'Bootstrap', ranges: [
    { ltOr: '3.4.1', cves: 'CVE-2018-14041/14042, CVE-2019-8331 (XSS)', note: '<3.4.1: data-* özniteliklerinde XSS' },
    { geLt: ['4.0.0', '4.3.1'], cves: 'CVE-2019-8331 (XSS)', note: '4.0–4.3.0: tooltip/popover XSS' },
  ] },
  lodash: { display: 'Lodash', ranges: [
    { ltOr: '4.17.21', cves: 'CVE-2021-23337 (komut enj.), CVE-2020-8203 (prototype pollution)', note: '<4.17.21: template/zipObjectDeep' },
  ] },
  moment: { display: 'Moment.js', ranges: [
    { ltOr: '2.29.4', cves: 'CVE-2022-31129 (ReDoS)', note: '<2.29.4: uzun girdi ReDoS' },
  ] },
  handlebars: { display: 'Handlebars', ranges: [
    { ltOr: '4.7.7', cves: 'CVE-2021-23369, CVE-2021-23383 (prototype pollution / şablon RCE)', note: '<4.7.7: derleyici prototype pollution' },
  ] },
  dompurify: { display: 'DOMPurify', ranges: [
    { ltOr: '2.4.0', cves: 'çeşitli mXSS bypass (ör. CVE-2020-26870)', note: '<2.4.0: mutation-XSS bypass' },
  ] },
  axios: { display: 'Axios', ranges: [
    { ltOr: '0.21.2', cves: 'CVE-2021-3749 (ReDoS)', note: '<0.21.2: trim ReDoS' },
    { geLt: ['0.22.0', '1.6.0'], cves: 'CVE-2023-45857 (XSRF token sızıntısı)', note: '<1.6.0: 3rd-party host’a XSRF-TOKEN sızması' },
  ] },
};

function parseVer(v: string): number[] | null {
  const m = v.match(/(\d+)\.(\d+)(?:\.(\d+))?/);
  return m ? [+m[1], +m[2], +(m[3] ?? 0)] : null;
}
function cmp(a: number[], b: number[]): number { for (let i = 0; i < 3; i++) { if ((a[i] ?? 0) !== (b[i] ?? 0)) return (a[i] ?? 0) - (b[i] ?? 0); } return 0; }
function matchVuln(lib: string, version: string): { cves: string; note: string } | null {
  const db = KNOWN_VULN_LIBS[lib]; if (!db) return null;
  const ver = parseVer(version); if (!ver) return null;
  for (const r of db.ranges) {
    if (r.ltOr && cmp(ver, parseVer(r.ltOr)!) < 0) return { cves: r.cves, note: db.eol ? `${r.note}. ${db.eol}` : r.note };
    if (r.geLt && cmp(ver, parseVer(r.geLt[0])!) >= 0 && cmp(ver, parseVer(r.geLt[1])!) < 0) return { cves: r.cves, note: r.note };
  }
  return null;
}

const LIB_NAME_RE = /(jquery|angular|react|vue|lodash|underscore|moment|bootstrap|handlebars|dompurify|axios|d3|three|backbone|knockout|ember)/i;
function detectLib(url: string, body: string): { lib: string; display: string; version: string | null } | null {
  const nameM = url.match(LIB_NAME_RE) || body.slice(0, 500).match(LIB_NAME_RE);
  if (!nameM) return null;
  const lib = nameM[1].toLowerCase();
  const display = KNOWN_VULN_LIBS[lib]?.display ?? (lib.charAt(0).toUpperCase() + lib.slice(1));
  const fromUrl = url.match(new RegExp(lib + '[.\\-/@]?v?(\\d+\\.\\d+\\.\\d+)', 'i')) || url.match(/[?&]ver(?:sion)?=(\d+\.\d+\.\d+)/i);
  const fromBanner = body.slice(0, 3000).match(new RegExp(lib + '[^0-9]{0,20}v?(\\d+\\.\\d+\\.\\d+)', 'i')) || body.slice(0, 3000).match(/VERSION\s*[:=]\s*["'](\d+\.\d+\.\d+)["']/i);
  const version = fromUrl?.[1] ?? fromBanner?.[1] ?? null;
  return { lib, display, version };
}
export { detectLib, matchVuln };

// (Doğrulama için) tek metni tarayıp GERÇEK-sır bulgularını + public-by-design etiketlerini döndürür.
export function scanTextForSecrets(text: string, where = 'test', de: boolean = false): { findings: VFinding[]; publicByDesign: string[] } {
  const findings: VFinding[] = []; const publicSeen = new Set<string>();
  scanSecrets(text, where, findings, publicSeen, de);
  return { findings, publicByDesign: [...publicSeen] };
}

export async function collectJsAnalysisEvidence(host: string, de: boolean = false): Promise<ActiveCheckEvidence> {
  const t = (trS: string, deS: string) => (de ? deS : trS);
  const findings: VFinding[] = [];
  const notes: string[] = [];
  const c = await fetchClientCorpus(host);
  if (!c.reachable) {
    return { ok: true, pagesScanned: 0, inputsFound: 0, probesSent: 1, findings, stopped: null,
      notes: [t('Ana sayfa HTML çekilemedi — istemci-tarafı/JS analizi bu hedef için **kapsam dışıdır**.', 'Startseiten-HTML konnte nicht abgerufen werden — die clientseitige/JS-Analyse ist für dieses Ziel **außerhalb des Geltungsbereichs**.')] };
  }

  const publicSeen = new Set<string>();
  const libsDetected: string[] = [];
  const libSeen = new Set<string>();
  let mapsTried = 0, probes = c.fetches;

  // INLINE script'ler: sır + public-by-design.
  for (const [i, code] of c.inlineScripts.entries()) scanSecrets(code, `inline-script#${i + 1}`, findings, publicSeen, de);

  // SAME-ORIGIN JS: A) sır, B) source-map, C) kütüphane.
  for (const f of c.sameOriginJs) {
    const short = (() => { try { return new URL(f.url).pathname.split('/').pop() || f.url; } catch { return f.url; } })();
    scanSecrets(f.body, short, findings, publicSeen, de);
    if (mapsTried < MAX_MAP_TRIES) {
      const mapUrl = sourceMapUrl(f.url, f.body);
      if (mapUrl) {
        mapsTried++; probes++;
        const mr = await getCapped(mapUrl, 1_000_000);
        if (mr && mr.status === 200 && /"version"\s*:\s*3|"sources"\s*:\s*\[/.test(mr.text)) {
          const sources = (mr.text.match(/"sources"\s*:\s*\[([\s\S]*?)\]/)?.[1] ?? '');
          const srcCount = (sources.match(/"/g)?.length ?? 0) / 2 | 0;
          const sample = [...sources.matchAll(/"([^"]*(?:src|app|components?|pages?|services?)[^"]*\.[jt]sx?)"/gi)].slice(0, 3).map((m) => m[1]);
          findings.push({
            check: 'source_map_exposure', inputPoint: new URL(mapUrl).pathname, vulnerable: true,
            technique: 'source-map erişilebilirliği',
            evidence: `Erişilebilir source-map (${new URL(mapUrl).pathname}) — orijinal kaynak ağacı ifşa oluyor (${srcCount} kaynak dosya${sample.length ? `; ör. ${sample.join(', ')}` : ''}). İç dosya yolları/yorumlar sızabilir.`,
            confidence: 'high', severity: 'low', sideEffectRisk: 'none',
          });
        }
      }
    }
    const lib = detectLib(f.url, f.body);
    if (lib && !libSeen.has(lib.lib)) {
      libSeen.add(lib.lib);
      libsDetected.push(`${lib.display}${lib.version ? ` ${lib.version}` : t(' (sürüm okunamadı)', ' (Version nicht lesbar)')}`);
      if (lib.version) {
        const v = matchVuln(lib.lib, lib.version);
        if (v) findings.push({
          check: 'vulnerable_js_lib', inputPoint: `${lib.display} ${lib.version}`, vulnerable: true,
          technique: 'sürüm-tabanlı kütüphane zafiyet göstergesi (retire.js mantığı)',
          evidence: `${lib.display} sürüm ${lib.version} tespit edildi — bu sürümde bilinen güvenlik açığı: ${v.cves}. ${v.note}. Sürüm-tabanlı göstergedir; **yama/backport teyidi gerekir** (dağıtımınız yamalı olabilir).`,
          confidence: 'medium', severity: 'medium', sideEffectRisk: 'none',
        });
      }
    }
  }

  // Harici (CDN) script'ler: yalnız URL'den lib+sürüm (fetch YOK) — CVE eşle.
  for (const u of c.externalScripts) {
    const lib = detectLib(u, '');
    if (lib && lib.version && !libSeen.has(lib.lib)) {
      libSeen.add(lib.lib);
      libsDetected.push(`${lib.display} ${lib.version}${t(' (harici/CDN)', ' (extern/CDN)')}`);
      const v = matchVuln(lib.lib, lib.version);
      if (v) findings.push({
        check: 'vulnerable_js_lib', inputPoint: `${lib.display} ${lib.version} (CDN)`, vulnerable: true,
        technique: 'sürüm-tabanlı kütüphane zafiyet göstergesi (harici CDN, URL’den sürüm)',
        evidence: `${lib.display} sürüm ${lib.version} (harici CDN) — bilinen güvenlik açığı: ${v.cves}. ${v.note}. Sürüm-tabanlı göstergedir; yama teyidi gerekir.`,
        confidence: 'medium', severity: 'medium', sideEffectRisk: 'none',
      });
    }
  }

  notes.push(t(`Tarandı: **${c.sameOriginJs.length}** same-origin JS dosyası + **${c.inlineScripts.length}** inline script; **${libsDetected.length}** kütüphane tespit edildi; **${mapsTried}** source-map adayı denendi. (${c.externalScripts.length} harici/CDN script sürüm için incelendi.)`, `Gescannt: **${c.sameOriginJs.length}** Same-Origin-JS-Dateien + **${c.inlineScripts.length}** Inline-Skripte; **${libsDetected.length}** Bibliothek(en) erkannt; **${mapsTried}** Source-Map-Kandidat(en) geprüft. (${c.externalScripts.length} externe/CDN-Skripte auf Version untersucht.)`));
  if (libsDetected.length) notes.push(t(`Tespit edilen kütüphaneler: ${libsDetected.join(' · ')}.`, `Erkannte Bibliotheken: ${libsDetected.join(' · ')}.`));
  if (publicSeen.size) notes.push(t(`Bilgilendirici (public-by-design — istismar edilebilir sır DEĞİL, bulgu sayılmaz): ${[...publicSeen].join(' · ')}.`, `Informativ (public-by-design — KEIN ausnutzbares Geheimnis, zählt nicht als Befund): ${[...publicSeen].join(' · ')}.`));
  if (!c.sameOriginJs.length && !c.inlineScripts.length) notes.push(t('Sayfada analiz edilebilir JS bulunamadı (ör. sunucu-render, JS’siz sayfa) — bu hedefte JS analizi sınırlıdır.', 'Keine analysierbaren JS auf der Seite gefunden (z. B. serverseitig gerendert, Seite ohne JS) — die JS-Analyse ist bei diesem Ziel eingeschränkt.'));

  return { ok: true, pagesScanned: 1, inputsFound: c.sameOriginJs.length, probesSent: probes, findings, stopped: null, notes };
}

// //# sourceMappingURL=... (dosya sonunda) veya <js>.map adayı.
function sourceMapUrl(jsUrl: string, body: string): string | null {
  const m = body.match(/[#@]\s*sourceMappingURL\s*=\s*([^\s'"*]+)/);
  if (m && m[1] && !m[1].startsWith('data:')) {
    try { return new URL(m[1], jsUrl).toString(); } catch { /* */ }
  }
  return jsUrl + '.map';
}

// A) tek metinde sır tara — GERÇEK sır → finding; public-by-design → publicSeen (bilgilendirici).
function scanSecrets(text: string, where: string, findings: VFinding[], publicSeen: Set<string>, de: boolean = false): void {
  for (const rule of PUBLIC_BY_DESIGN_RULES) {
    rule.re.lastIndex = 0;
    if (rule.re.test(text)) publicSeen.add(de ? rule.labelDe : rule.label);
  }
  for (const rule of REAL_SECRET_RULES) {
    rule.re.lastIndex = 0;
    const m = rule.re.exec(text);
    if (m) {
      findings.push({
        check: 'js_secret', inputPoint: `${where}:${rule.id}`, vulnerable: true,
        technique: 'JS bundle statik sır taraması (regex)',
        evidence: `\`${where}\` içinde hassas sır göstergesi: ${rule.why} (Değer REDAKTE: \`${redact(m[0])}\`.) İstemci JS'i herkese açıktır; buradaki gerçek sır ele geçirilebilir — derhal döndürülmeli/geçersizleştirilmeli.`,
        confidence: rule.id === 'private_key' || rule.id === 'gcp_service_account' || rule.id === 'db_conn_string' ? 'high' : 'medium',
        severity: 'high', sideEffectRisk: 'none',
      });
    }
  }
}
