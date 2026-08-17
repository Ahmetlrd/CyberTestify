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

async function getCapped(url: string, cap = MAX_BYTES): Promise<Fetched | null> {
  const wait = MIN_DELAY - (Date.now() - lastAt);
  if (wait > 0) await new Promise((r) => setTimeout(r, wait));
  lastAt = Date.now();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), REQ_TIMEOUT);
  const t0 = Date.now();
  try {
    const res = await fetch(url, { redirect: 'manual', signal: ctrl.signal, headers: { 'user-agent': 'CyberTestify-JSAnalysis/1.0', accept: '*/*' } });
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

// ============================ A) GERÇEK SIRLAR ============================
// Her biri: yakala + neden hassas. PUBLIC-BY-DESIGN olanlar (aşağıda) BURADA DEĞİL.
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
const PUBLIC_BY_DESIGN_RULES: Array<{ id: string; label: string; re: RegExp }> = [
  { id: 'google_api_key', label: 'Google API anahtarı (Firebase/Maps browser key — public-by-design, referer/kota ile sınırlanır)', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { id: 'stripe_publishable', label: 'Stripe publishable key (pk_ — public-by-design, gizli değildir)', re: /\bpk_(?:live|test)_[0-9a-zA-Z]{20,}\b/g },
  { id: 'ga_measurement', label: 'GA/GTM/Ads ölçüm kimliği (public-by-design)', re: /\b(?:G-[A-Z0-9]{6,}|GTM-[A-Z0-9]{5,}|UA-\d{4,}-\d+|AW-\d{6,})\b/g },
  { id: 'recaptcha_site', label: 'reCAPTCHA SITE key (public-by-design; secret key ayrıdır)', re: /\b6L[0-9A-Za-z_-]{38}\b/g },
  { id: 'firebase_cfg', label: 'Firebase istemci yapılandırması (apiKey/authDomain/projectId — public-by-design, güvenlik Firebase kurallarındadır)', re: /(?:authDomain|messagingSenderId|storageBucket)\s*:\s*["'][^"']+["']/g },
];

// ============================ C) BİLİNEN-ZAFİYETLİ KÜTÜPHANELER ============================
// MUHAFAZAKÂR: yalnız GÜVENLE okunan sürüm eşlenir; aralık AÇIK; "istismar edilebilir" DEMEZ.
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

// Kütüphane + sürüm tespiti: (1) URL/dosya adı, (2) dosya banner'ı. Sürüm okunamazsa CVE eşleme YOK.
const LIB_NAME_RE = /(jquery|angular|react|vue|lodash|underscore|moment|bootstrap|handlebars|dompurify|axios|d3|three|backbone|knockout|ember)/i;
function detectLib(url: string, body: string): { lib: string; display: string; version: string | null } | null {
  const nameM = url.match(LIB_NAME_RE) || body.slice(0, 500).match(LIB_NAME_RE);
  if (!nameM) return null;
  const lib = nameM[1].toLowerCase();
  const display = KNOWN_VULN_LIBS[lib]?.display ?? (lib.charAt(0).toUpperCase() + lib.slice(1));
  // Sürüm: URL'de (jquery-3.4.1 / jquery.min.js?ver=3.4.1) veya banner'da (v3.4.1 / VERSION="3.4.1").
  const fromUrl = url.match(new RegExp(lib + '[.\\-/@]?v?(\\d+\\.\\d+\\.\\d+)', 'i')) || url.match(/[?&]ver(?:sion)?=(\d+\.\d+\.\d+)/i);
  const fromBanner = body.slice(0, 3000).match(new RegExp(lib + '[^0-9]{0,20}v?(\\d+\\.\\d+\\.\\d+)', 'i')) || body.slice(0, 3000).match(/VERSION\s*[:=]\s*["'](\d+\.\d+\.\d+)["']/i);
  const version = fromUrl?.[1] ?? fromBanner?.[1] ?? null;
  return { lib, display, version };
}

export async function collectJsAnalysisEvidence(host: string): Promise<ActiveCheckEvidence> {
  const findings: VFinding[] = [];
  const notes: string[] = [];
  await resolveOrigin(host).catch(() => null);
  const origin = cachedOriginUrl(host);

  // 1) Ana sayfa HTML → script src'leri + inline script'ler.
  const home = await getCapped(`${origin}/`);
  if (!home || home.status >= 400 || !home.text) {
    return { ok: true, pagesScanned: 0, inputsFound: 0, probesSent: 1, findings, stopped: null,
      notes: ['Ana sayfa HTML çekilemedi — istemci-tarafı/JS analizi bu hedef için **kapsam dışıdır**.'] };
  }
  const html = home.text;
  const scriptSrcs = [...html.matchAll(/<script[^>]+src\s*=\s*["']([^"']+)["']/gi)].map((m) => m[1]);
  const inlineScripts = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi)].map((m) => m[1]).filter((s) => s.trim().length > 0);

  const sameOriginJs: string[] = [];
  const externalJs: string[] = [];
  for (const src of scriptSrcs) {
    const u = absUrl(src, host); if (!u) continue;
    (sameHost(u, host) ? sameOriginJs : externalJs).push(u);
  }

  let jsScanned = 0, probes = 1, mapsTried = 0;
  const publicSeen = new Set<string>();       // public-by-design (bilgilendirici)
  const libsDetected: string[] = [];
  const libSeen = new Set<string>();

  // 2) INLINE script'ler: sır + public-by-design + lib banner.
  for (const [i, code] of inlineScripts.entries()) {
    scanSecrets(code, `inline-script#${i + 1}`, findings, publicSeen);
  }

  // 3) SAME-ORIGIN JS: çek + A/B/C.
  for (const u of sameOriginJs.slice(0, MAX_JS_FILES)) {
    const r = await getCapped(u); probes++;
    if (!r || r.status >= 400 || !r.text) continue;
    jsScanned++;
    const short = new URL(u).pathname.split('/').pop() || u;
    // A) sırlar
    scanSecrets(r.text, short, findings, publicSeen);
    // B) source map
    if (mapsTried < MAX_MAP_TRIES) {
      const mapUrl = sourceMapUrl(u, r.text);
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
    // C) kütüphane + sürüm + CVE
    const lib = detectLib(u, r.text);
    if (lib && !libSeen.has(lib.lib)) {
      libSeen.add(lib.lib);
      libsDetected.push(`${lib.display}${lib.version ? ` ${lib.version}` : ' (sürüm okunamadı)'}`);
      if (lib.version) {
        const v = matchVuln(lib.lib, lib.version);
        if (v) findings.push({
          check: 'vulnerable_js_lib', inputPoint: `${lib.display} ${lib.version}`, vulnerable: true,
          technique: 'sürüm-tabanlı kütüphane zafiyet göstergesi (retire.js mantığı)',
          evidence: `${lib.display} sürüm ${lib.version} tespit edildi — bu sürümde bilinen güvenlik açığı: ${v.cves}. ${v.note}. Sürüm-tabanlı göstergedir; **yama/backport teyidi gerekir** (dağıtımınız yamalı olabilir).`,
          confidence: 'medium', severity: 'medium', sideEffectRisk: 'none',
        });
      }
      // sürüm yoksa: tespit edildi ama CVE eşleme YOK (CMS/CVE disiplini).
    }
  }

  // Harici (CDN) script'ler: yalnız URL'den lib+sürüm (fetch YOK) — CVE eşle.
  for (const u of externalJs) {
    const lib = detectLib(u, '');
    if (lib && lib.version && !libSeen.has(lib.lib)) {
      libSeen.add(lib.lib);
      libsDetected.push(`${lib.display} ${lib.version} (harici/CDN)`);
      const v = matchVuln(lib.lib, lib.version);
      if (v) findings.push({
        check: 'vulnerable_js_lib', inputPoint: `${lib.display} ${lib.version} (CDN)`, vulnerable: true,
        technique: 'sürüm-tabanlı kütüphane zafiyet göstergesi (harici CDN, URL’den sürüm)',
        evidence: `${lib.display} sürüm ${lib.version} (harici CDN) — bilinen güvenlik açığı: ${v.cves}. ${v.note}. Sürüm-tabanlı göstergedir; yama teyidi gerekir.`,
        confidence: 'medium', severity: 'medium', sideEffectRisk: 'none',
      });
    }
  }

  // --- POZİTİF GÜVENCE + BİLGİLENDİRİCİ (gerçek sayılar) ---
  notes.push(`Tarandı: **${jsScanned}** same-origin JS dosyası + **${inlineScripts.length}** inline script; **${libsDetected.length}** kütüphane tespit edildi; **${mapsTried}** source-map adayı denendi. (${externalJs.length} harici/CDN script sürüm için incelendi.)`);
  if (libsDetected.length) notes.push(`Tespit edilen kütüphaneler: ${libsDetected.join(' · ')}.`);
  if (publicSeen.size) notes.push(`Bilgilendirici (public-by-design — istismar edilebilir sır DEĞİL, bulgu sayılmaz): ${[...publicSeen].join(' · ')}.`);
  if (!sameOriginJs.length && !inlineScripts.length) notes.push('Sayfada analiz edilebilir JS bulunamadı (ör. sunucu-render, JS’siz sayfa) — bu hedefte JS analizi sınırlıdır.');

  return { ok: true, pagesScanned: 1, inputsFound: jsScanned, probesSent: probes, findings, stopped: null, notes };
}

// //# sourceMappingURL=... (dosya sonunda) veya <js>.map adayı.
function sourceMapUrl(jsUrl: string, body: string): string | null {
  const m = body.match(/[#@]\s*sourceMappingURL\s*=\s*([^\s'"*]+)/);
  if (m && m[1] && !m[1].startsWith('data:')) {
    try { return new URL(m[1], jsUrl).toString(); } catch { /* */ }
  }
  return jsUrl + '.map'; // yaygın konvansiyon — erişilebilirse doğrulanır
}

// A) tek metinde sır tara — GERÇEK sır → finding; public-by-design → publicSeen (bilgilendirici).
function scanSecrets(text: string, where: string, findings: VFinding[], publicSeen: Set<string>): void {
  for (const rule of PUBLIC_BY_DESIGN_RULES) {
    rule.re.lastIndex = 0;
    if (rule.re.test(text)) publicSeen.add(rule.label);
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
