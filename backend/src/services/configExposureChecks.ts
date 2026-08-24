/**
 * (Tam Kapsamlı Pentest — Faz 3-A) YAPILANDIRMA/İFŞA + GİRDİ/HEADER DERİNLİĞİ (WSTG-CONF/INFO/INPV).
 * 10 kontrol; hepsi DETERMİNİSTİK + GÜVENLİ (statik ayrıştırma + güvenli GET/OPTIONS/TRACE probu).
 *
 * SÜTUN 0 (Faz 0 provenance + Faz 2-A dersi): Tahmin edilen yol SPA catch-all 200'ü (== ana sayfa shell
 * md5) veya HTML shell dönüyorsa GERÇEK DEĞİLDİR → bulgu ÜRETİLMEZ. Yalnız gerçekten erişilebilen,
 * AYIRT EDİCİ yanıt = bulgu. Hayalet-bulgu YOK. GÜVENLİK: PUT/DELETE gibi YIKICI method ATILMAZ (yalnız
 * OPTIONS/TRACE/GET); D5 stored-XSS SADECE aday işaretler (form GÖNDERMEZ, veri OLUŞTURMAZ).
 *
 * Grup D (girdi/header): D1 Host header injection · D2 HTTP parameter pollution · D3 HTTP methods/TRACE
 *   · D4 mixed content · D5 stored-XSS giriş noktası (yalnız aday).
 * Grup E (yapılandırma/ifşa): E1 yedek/eski dosya · E2 admin arayüz · E3 cloud storage · E4 cache/
 *   poisoning göstergesi · E5 yorum & metadata sızıntısı.
 */
import { createHash } from 'node:crypto';
import { fetchClientCorpus } from './jsAnalysis.js';
import { cachedOriginUrl, resolveOrigin } from './surfaceEvidence.js';
import { logScanStep } from './scanLogger.js';
import type { AuthSession } from './authSession.js';
import type { ActiveCheckEvidence, VFinding } from './activeVerifyEvidence.js';

const md5 = (s: string) => createHash('md5').update(s).digest('hex');
const REQ_TIMEOUT = 12_000;
const MIN_DELAY = 250;
let lastAt = 0;

type Probe = { status: number; text: string; headers: Headers; ms: number };
async function probe(url: string, opts: { method?: string; headers?: Record<string, string>; label: string } = { label: 'config/exposure probe' }): Promise<Probe | null> {
  const wait = MIN_DELAY - (Date.now() - lastAt); if (wait > 0) await new Promise((r) => setTimeout(r, wait));
  lastAt = Date.now();
  const ctrl = new AbortController(); const timer = setTimeout(() => ctrl.abort(), REQ_TIMEOUT); const t0 = Date.now();
  try {
    const res = await fetch(url, { method: opts.method ?? 'GET', redirect: 'manual', signal: ctrl.signal, headers: { 'user-agent': 'CyberTestify-Config/1.0', accept: '*/*', ...(opts.headers ?? {}) } });
    const buf = Buffer.from(await res.arrayBuffer());
    logScanStep({ step: opts.label, method: opts.method ?? 'GET', url, status: res.status, durationMs: Date.now() - t0, sizeBytes: buf.length });
    return { status: res.status, text: buf.subarray(0, 200_000).toString('utf-8'), headers: res.headers, ms: Date.now() - t0 };
  } catch { logScanStep({ step: opts.label, method: opts.method ?? 'GET', url, status: 0, level: 'warn', durationMs: Date.now() - t0 }); return null; }
  finally { clearTimeout(timer); }
}
const isHtmlShell = (body: string) => /<!doctype html|<html[\s>]/i.test(body.slice(0, 300));
const abs = (host: string, p: string) => new URL(p, `${cachedOriginUrl(host)}/`).toString();
const HOST_PROBE = 'ct-hostinj-probe.example.com';

// ================= SAF/BİRİM-TEST EDİLEBİLİR YARDIMCILAR =================
export function detectMixedContent(html: string, pageIsHttps: boolean): string[] {
  if (!pageIsHttps) return [];
  const out = new Set<string>();
  for (const m of html.matchAll(/(?:src|href)\s*=\s*["'](http:\/\/[^"']+)["']/gi)) {
    const u = m[1];
    if (/\.(png|jpe?g|gif|svg|webp|ico|css|js|woff2?)(\?|$)/i.test(u) || /<(script|iframe|link|img)/i.test(html.slice(Math.max(0, (m.index ?? 0) - 40), m.index))) out.add(u);
  }
  return [...out].slice(0, 10);
}
export function findCloudBuckets(text: string): string[] {
  const out = new Set<string>();
  for (const m of text.matchAll(/https?:\/\/([a-z0-9.-]+\.s3[.-][a-z0-9-]*\.?amazonaws\.com|s3\.amazonaws\.com\/[a-z0-9._-]+|storage\.googleapis\.com\/[a-z0-9._-]+|[a-z0-9-]+\.storage\.googleapis\.com|[a-z0-9]+\.blob\.core\.windows\.net)/gi)) out.add(m[0]);
  return [...out].slice(0, 6);
}
export function scanCommentLeak(text: string, where: string): VFinding[] {
  const findings: VFinding[] = [];
  const comments = [...text.matchAll(/<!--([\s\S]*?)-->/g)].map((m) => m[1]).join('\n');
  const hay = comments + '\n' + text;
  const hits: string[] = [];
  if (/\b(todo|fixme|hack|debug|xxx|bug)\b[:\- ]/i.test(comments)) hits.push('dev yorumu (TODO/FIXME/DEBUG)');
  const privIp = hay.match(/\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b/);
  if (privIp) hits.push(`iç IP (${privIp[0]})`);
  const intHost = hay.match(/\b[a-z0-9-]+\.(?:internal|local|corp|intranet|lan)\b/i);
  if (intHost) hits.push(`iç hostname (${intHost[0]})`);
  const path = hay.match(/(?:\/(?:var|home|usr|opt|etc)\/[\w./-]+|[A-Z]:\\[\w\\.-]+)/);
  if (path) hits.push(`sunucu dosya yolu (${(path[0] || '').slice(0, 40)})`);
  if (hits.length) findings.push({
    check: 'comment_metadata_leak', inputPoint: where, vulnerable: true,
    technique: 'HTML/JS yorum & metadata sızıntısı (statik)',
    evidence: `\`${where}\` içinde geliştirici/iç bilgi sızıntısı göstergesi: ${hits.join(', ')} — üretimde kaldırılmalı (iç altyapı/yorum ifşası saldırgana yol gösterir; değerler kısaltıldı).`,
    confidence: 'medium', severity: 'low', sideEffectRisk: 'none',
  });
  return findings;
}

// ================= GRUP D: GİRDİ/HEADER =================
export async function collectInputHeaderEvidence(host: string, session: AuthSession, de: boolean = false): Promise<ActiveCheckEvidence> {
  const t = (trS: string, deS: string) => (de ? deS : trS);
  void session;
  const findings: VFinding[] = []; const notes: string[] = [];
  await resolveOrigin(host).catch(() => null);
  const origin = cachedOriginUrl(host);
  const pageIsHttps = origin.startsWith('https://');
  const corpus = await fetchClientCorpus(host);
  if (!corpus.reachable) return { ok: true, pagesScanned: 0, inputsFound: 0, probesSent: 1, findings, stopped: null, notes: [t('Ana sayfa çekilemedi — girdi/header derinliği bu hedef için **kapsam dışıdır**.', 'Startseite konnte nicht abgerufen werden — die Eingabe-/Header-Tiefenprüfung ist für dieses Ziel **außerhalb des Geltungsbereichs**.')] };
  let probes = 1;

  // D4) MIXED CONTENT (statik)
  const mixed = detectMixedContent(corpus.homeHtml, pageIsHttps);
  for (const u of mixed) findings.push({
    check: 'mixed_content', inputPoint: u.slice(0, 100), vulnerable: true,
    technique: 'HTTPS sayfada HTTP kaynak yüklenmesi (mixed content) — statik',
    evidence: `HTTPS sayfa, **HTTP** üzerinden bir kaynak yüklüyor (\`${u.slice(0, 80)}\`) — aktif mixed content ise ortadaki-adam içerik enjekte edebilir; tarayıcı da engelleyebilir. Tüm kaynaklar HTTPS olmalı.`,
    confidence: 'high', severity: /\.(js)(\?|$)|<script|<iframe/i.test(u) ? 'medium' : 'low', sideEffectRisk: 'none',
  });

  // D1) HOST HEADER INJECTION — sahte Host/X-Forwarded-Host; yanıtta yansıma? (read-only)
  const hi = await probe(`${origin}/`, { headers: { 'x-forwarded-host': HOST_PROBE, 'x-forwarded-server': HOST_PROBE, 'x-host': HOST_PROBE }, label: 'D1 host-header injection' }); probes++;
  if (hi) {
    const loc = hi.headers.get('location') ?? '';
    if (hi.text.includes(HOST_PROBE) || loc.includes(HOST_PROBE)) findings.push({
      check: 'host_header_injection', inputPoint: '/', vulnerable: true,
      technique: 'Host / X-Forwarded-Host yansıması gözlemi — gösterge',
      evidence: `Gönderilen sahte \`X-Forwarded-Host: ${HOST_PROBE}\` değeri yanıtta (${loc.includes(HOST_PROBE) ? 'Location/yönlendirme' : 'gövde/mutlak link'}) yansıdı — Host header injection göstergesi (parola-sıfırlama zehirlemesi/cache poisoning'e yol açabilir). Gösterge; gerçek istismar YAPILMADI. Host değerini allowlist ile sabitleyin.`,
      confidence: 'medium', severity: 'medium', sideEffectRisk: 'none',
    });
  }

  // D3) HTTP METHODS / TRACE — OPTIONS keşfi + TRACE gözlemi (PUT/DELETE ATILMAZ)
  const optRes = await probe(`${origin}/`, { method: 'OPTIONS', label: 'D3 OPTIONS method keşfi' }); probes++;
  const allow = optRes?.headers.get('allow') ?? '';
  if (/TRACE/i.test(allow)) {
    findings.push({ check: 'dangerous_http_method', inputPoint: 'OPTIONS Allow', vulnerable: true, technique: 'HTTP method keşfi (OPTIONS Allow)', evidence: `Sunucu \`Allow: ${allow}\` ile **TRACE** metodunu listeliyor — Cross-Site Tracing (XST) riski. TRACE kapatılmalı.`, confidence: 'high', severity: 'medium', sideEffectRisk: 'none' });
  } else {
    // TRACE gözlemi (read-only; state değişmez)
    const tr = await probe(`${origin}/`, { method: 'TRACE', label: 'D3 TRACE gözlemi' }).catch(() => null); probes++;
    if (tr && tr.status === 200 && /TRACE\s+\/|x-forwarded|user-agent/i.test(tr.text.slice(0, 300))) findings.push({
      check: 'dangerous_http_method', inputPoint: 'TRACE', vulnerable: true, technique: 'TRACE metodu gözlemi', evidence: 'Sunucu **TRACE** metoduna 200 + istek yankısı döndürüyor — Cross-Site Tracing (XST) göstergesi. TRACE kapatılmalı.', confidence: 'high', severity: 'medium', sideEffectRisk: 'none',
    });
  }
  if (allow && /\b(PUT|DELETE|PATCH)\b/i.test(allow)) notes.push(t(`OPTIONS Allow durum-değiştiren method(lar) listeliyor (${allow}) — REST API'lerde olağan olabilir; yetkilendirme sunucuda zorunlu kılınmalı (bilgilendirici; PUT/DELETE GÖNDERİLMEDİ).`, `OPTIONS Allow listet zustandsändernde Methode(n) auf (${allow}) — bei REST-APIs kann dies üblich sein; die Autorisierung muss serverseitig erzwungen werden (informativ; PUT/DELETE NICHT GESENDET).`));

  // D2) HTTP PARAMETER POLLUTION — gözlemsel (SPA'da genelde ayırt-edici davranış yok)
  const paramUrl = [...corpus.homeHtml.matchAll(/(?:href|action)\s*=\s*["']([^"']*\?[^"']*=[^"']*)["']/gi)].map((m) => m[1]).find((u) => { try { return new URL(u, `${origin}/`).hostname.toLowerCase() === host.toLowerCase(); } catch { return false; } });
  if (paramUrl) {
    try {
      const u = new URL(paramUrl.replace(/&amp;/g, '&'), `${origin}/`); const p = [...u.searchParams.keys()][0];
      if (p) {
        const a = await probe(`${u.origin}${u.pathname}?${p}=ctA`, { label: 'D2 HPP a' }); probes++;
        const dbl = await probe(`${u.origin}${u.pathname}?${p}=ctA&${p}=ctB`, { label: 'D2 HPP a&b' }); probes++;
        if (a && dbl && a.status === dbl.status && !isHtmlShell(dbl.text) && md5(a.text) !== md5(dbl.text)) notes.push(t(`HTTP Parameter Pollution gözlemi: \`${p}\` parametresi tekrarlandığında yanıt değişiyor — tutarsız işleme göstergesi (bilgilendirici; gözlemsel).`, `HTTP-Parameter-Pollution-Beobachtung: Bei Wiederholung des Parameters \`${p}\` ändert sich die Antwort — Indikator für inkonsistente Verarbeitung (informativ; beobachtend).`));
        else notes.push(t('HTTP Parameter Pollution için ayırt-edici davranış gözlemlenmedi (SPA/tek-tip yanıt).', 'Kein unterscheidbares Verhalten für HTTP Parameter Pollution beobachtet (SPA/einheitliche Antwort).'));
      }
    } catch { /* */ }
  } else notes.push(t('Parametreli same-origin uç gözlemlenmedi — HPP için test edilebilir yüzey yok.', 'Kein parametrisierter Same-Origin-Endpunkt beobachtet — keine testbare Angriffsfläche für HPP.'));

  // D5) STORED-XSS GİRİŞ NOKTASI — SADECE ADAY (GÖNDERİM/KAYIT YOK)
  const persistFields = [...corpus.homeHtml.matchAll(/<(?:textarea|input)\b[^>]*\bname\s*=\s*["']([^"']*(?:comment|message|review|feedback|bio|about|description|note|content|post|title|name)[^"']*)["']/gi)].map((m) => m[1]);
  if (persistFields.length) {
    findings.push({
      check: 'stored_xss_candidate', inputPoint: [...new Set(persistFields)].slice(0, 5).join(', '), vulnerable: true,
      technique: 'stored-XSS ADAY giriş noktası (statik — GÖNDERİM YOK)',
      evidence: `Kalıcı/paylaşılan bağlama yansıyabilecek giriş alan(lar)ı gözlemlendi (\`${[...new Set(persistFields)].slice(0, 5).join('`, `')}\`) — **stored-XSS için ADAY** giriş noktası. Bu yalnızca bir adaydır; **hiçbir veri gönderilmedi/kaydedilmedi**, dinamik doğrulama gerekir (düşük güven).`,
      confidence: 'low', severity: 'low', sideEffectRisk: 'none',
    });
  }

  notes.push(t(`Denenen: **${probes}** güvenli girdi/header probu (yalnız GET/OPTIONS/TRACE — PUT/DELETE GÖNDERİLMEDİ; stored-XSS yalnız aday, veri OLUŞTURULMADI). Mixed content: ${mixed.length} HTTP kaynak.`, `Durchgeführt: **${probes}** sichere Eingabe-/Header-Proben (nur GET/OPTIONS/TRACE — PUT/DELETE NICHT GESENDET; Stored-XSS nur als Kandidat, keine Daten ERZEUGT). Mixed Content: ${mixed.length} HTTP-Ressourcen.`));
  return { ok: true, pagesScanned: 1, inputsFound: 1, probesSent: probes, findings, stopped: null, notes };
}

// ================= GRUP E: YAPILANDIRMA/İFŞA =================
const BACKUP_PATHS = ['/.env', '/.env.bak', '/config.bak', '/config.php.bak', '/wp-config.php.bak', '/backup.zip', '/backup.tar.gz', '/db.sql', '/database.sql', '/.git/config', '/.svn/entries', '/.DS_Store', '/index.php~', '/app.js.map'];
const ADMIN_PATHS = ['/admin', '/administrator', '/wp-admin/', '/admin/login', '/manager/html', '/phpmyadmin/', '/server-status', '/actuator', '/actuator/env', '/.git/', '/console'];

export async function collectConfigExposureEvidence(host: string, session: AuthSession, de: boolean = false): Promise<ActiveCheckEvidence> {
  const t = (trS: string, deS: string) => (de ? deS : trS);
  void session;
  const findings: VFinding[] = []; const notes: string[] = [];
  const origin = cachedOriginUrl(host);
  const corpus = await fetchClientCorpus(host);
  if (!corpus.reachable) return { ok: true, pagesScanned: 0, inputsFound: 0, probesSent: 1, findings, stopped: null, notes: [t('Ana sayfa çekilemedi — yapılandırma/ifşa derinliği bu hedef için **kapsam dışıdır**.', 'Startseite konnte nicht abgerufen werden — die Konfigurations-/Offenlegungs-Tiefenprüfung ist für dieses Ziel **außerhalb des Geltungsbereichs**.')] };
  const shellHash = md5(corpus.homeHtml);
  let probes = 1, backupTried = 0, adminTried = 0;

  // E1) YEDEK/ESKİ DOSYA — SPA catch-all shell = GERÇEK DEĞİL (Faz 0 provenance)
  for (const p of BACKUP_PATHS) {
    const r = await probe(abs(host, p), { label: `E1 yedek dosya ${p}` }); probes++; backupTried++;
    if (!r || r.status !== 200 || !r.text) continue;
    if (md5(r.text) === shellHash) continue;           // SPA catch-all shell -> gerçek dosya değil
    if (isHtmlShell(r.text)) continue;                  // HTML sayfası -> yedek dosya değil
    const looksReal = /(=|\[core\]|BEGIN|password|secret|api[_-]?key|CREATE TABLE|INSERT INTO|<\?php|\bconst\b|version)/i.test(r.text.slice(0, 500)) || /\.(sql|env|config)/i.test(p);
    if (!looksReal) continue;
    findings.push({ check: 'backup_file_exposed', inputPoint: p, vulnerable: true, technique: 'erişilebilir yedek/eski/referanssız dosya (güvenli GET)', evidence: `\`${p}\` dışarıdan **erişilebilir** ve ayırt-edici (yedek/config) içerik döndürüyor (200; SPA shell değil) — kaynak kodu/kimlik bilgisi/yapılandırma sızıntısı riski (içerik raporda gösterilmez). Public dizinden kaldırılmalı.`, confidence: 'high', severity: /\.env|\.git|config|\.sql|secret/i.test(p) ? 'high' : 'medium', sideEffectRisk: 'none' });
  }

  // E2) ADMIN ARAYÜZ — aynı provenance kuralı
  for (const p of ADMIN_PATHS) {
    const r = await probe(abs(host, p), { label: `E2 admin arayüz ${p}` }); probes++; adminTried++;
    if (!r || r.status !== 200 || !r.text) continue;
    if (md5(r.text) === shellHash) continue;           // SPA catch-all -> gerçek admin değil
    const adminish = /(admin|yönetim|dashboard|phpmyadmin|actuator|server-status|login|parola|password|manager)/i.test(r.text.slice(0, 1500));
    if (!adminish) continue;
    findings.push({ check: 'admin_interface_exposed', inputPoint: p, vulnerable: true, technique: 'yönetici arayüzü dışarıdan erişilebilirlik (güvenli GET)', evidence: `\`${p}\` dışarıdan **erişilebilir** bir yönetim/araç arayüzü döndürüyor (200; SPA shell değil) — yönetim yüzeyi ağ/kimlik-doğrulama arkasına alınmalı, dışarıya açılmamalı.`, confidence: 'medium', severity: /server-status|actuator|phpmyadmin|\.git/i.test(p) ? 'high' : 'medium', sideEffectRisk: 'none' });
  }

  // E3) CLOUD STORAGE — HTML/JS'te bucket referansı + listelenebilir mi
  const corpusText = corpus.homeHtml + '\n' + corpus.sameOriginJs.map((f) => f.body).join('\n') + '\n' + corpus.inlineScripts.join('\n');
  const buckets = findCloudBuckets(corpusText);
  for (const b of buckets.slice(0, 4)) {
    const r = await probe(b, { label: `E3 cloud bucket ${b}` }); probes++;
    if (r && r.status === 200 && /<ListBucketResult|<Contents>|<Blobs>|"items"\s*:/i.test(r.text.slice(0, 800))) {
      findings.push({ check: 'cloud_bucket_listable', inputPoint: b.slice(0, 80), vulnerable: true, technique: 'public cloud storage bucket listelenebilirlik gözlemi', evidence: `Kaynaklarda referans verilen bulut deposu (\`${b.slice(0, 70)}\`) **listelenebilir** (dizin listesi döndü) — yanlış yapılandırılmış public bucket, tüm nesnelerin envanteri sızabilir. Liste iznini kapatın; hassas nesneleri private yapın.`, confidence: 'high', severity: 'high', sideEffectRisk: 'none' });
    }
  }
  if (buckets.length) notes.push(t(`Kaynaklarda ${buckets.length} bulut-depo referansı gözlemlendi (asset için public olabilir; yalnız listelenebilir olan bulgu sayıldı).`, `In den Ressourcen wurden ${buckets.length} Cloud-Storage-Referenz(en) beobachtet (für Assets ggf. öffentlich; nur auflistbare wurden als Befund gezählt).`));

  // E4) CACHE HEADER / POISONING GÖSTERGESİ — güvenli gözlem
  const cp = await probe(`${origin}/`, { headers: { 'x-forwarded-host': HOST_PROBE }, label: 'E4 cache/poisoning gözlemi' }); probes++;
  if (cp) {
    const cc = (cp.headers.get('cache-control') ?? '').toLowerCase();
    const cacheable = /public|max-age=[1-9]/.test(cc) || cp.headers.get('age') != null;
    const reflectsUnkeyed = cp.text.includes(HOST_PROBE) || (cp.headers.get('location') ?? '').includes(HOST_PROBE);
    const vary = (cp.headers.get('vary') ?? '').toLowerCase();
    if (cacheable && reflectsUnkeyed && !/x-forwarded-host|host/.test(vary)) findings.push({
      check: 'cache_poisoning_indicator', inputPoint: '/', vulnerable: true, technique: 'cache poisoning göstergesi (unkeyed header yansıması + cacheable) — gözlem', evidence: `Yanıt **önbelleklenebilir** (\`Cache-Control: ${cc || 'yok'}\`) ve **unkeyed** bir başlık (X-Forwarded-Host) yansıtıyor; \`Vary\` bu başlığı içermiyor — web cache poisoning **göstergesi** (zehirlenmiş yanıt başkalarına servis edilebilir). Gösterge; gerçek zehirleme YAPILMADI. Unkeyed girdiyi yansıtmayın veya Vary'e ekleyin.`, confidence: 'medium', severity: 'medium', sideEffectRisk: 'none',
    });
  }

  // E5) YORUM & METADATA SIZINTISI (statik) — home HTML + inline + same-origin JS
  findings.push(...scanCommentLeak(corpus.homeHtml, 'ana sayfa HTML'));
  corpus.inlineScripts.forEach((code, i) => findings.push(...scanCommentLeak(code, `inline-script#${i + 1}`)));
  for (const f of corpus.sameOriginJs) findings.push(...scanCommentLeak(f.body, (() => { try { return new URL(f.url).pathname.split('/').pop() || f.url; } catch { return f.url; } })()));

  notes.push(t(`Denenen: **${backupTried}** yedek/eski dosya + **${adminTried}** admin yolu (SPA catch-all shell 200'ler ELENDİ — gerçek/ayırt-edici olmayan yanıt bulgu sayılmadı); **${buckets.length}** bulut-depo referansı; yorum/metadata statik tarandı.`, `Durchgeführt: **${backupTried}** Backup-/Alt-Dateien + **${adminTried}** Admin-Pfade (SPA-Catch-all-Shell-200er AUSGEFILTERT — nicht echte/nicht unterscheidbare Antworten wurden nicht als Befund gezählt); **${buckets.length}** Cloud-Storage-Referenz(en); Kommentare/Metadaten statisch gescannt.`));
  return { ok: true, pagesScanned: 1, inputsFound: 1, probesSent: probes, findings, stopped: null, notes };
}
