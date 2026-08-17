/**
 * (Tam Kapsamlı Pentest — Faz 5) TAŞIMA KATMANI, CORS & GÜVENLİK BAŞLIĞI DERİNLİĞİ + SUBDOMAIN TAKEOVER.
 * Hepsi deterministik + read-only/pasif: veri değiştirme, DoS, takeover-claim, cipher istismarı YOK.
 * SADECE 6. pakete (Tam Kapsamlı) girer.
 *
 * SÜTUN 0 provenance: bulgular yalnız hedefte GERÇEKTEN gözlenen origin/subdomain/protokol/başlık üzerinden.
 * DE-DUP: sertifika süre/hostname/zincir yalnız GERÇEK sorun varsa raporlanır (cert türü); başka bölümde
 * cert kontrolü olmadığından çift-CT yok. TLS bölümü cipher/protokol (weak_tls) — cert ile ayrı tür.
 */
import tls from 'node:tls';
import { fetchClientCorpus } from './jsAnalysis.js';
import { mineApiPaths } from './apiSecurityChecks.js';
import { cachedOriginUrl, resolveOrigin } from './surfaceEvidence.js';
import { collectSubdomains } from './reconEvidence.js';
import { logScanStep } from './scanLogger.js';
import type { ActiveCheckEvidence, VFinding } from './activeVerifyEvidence.js';

const REQ_TIMEOUT = 10_000;
const CORS_PROBE_ORIGIN = 'https://cybertestify-cors-probe.test';

async function getHeaders(url: string, extra?: Record<string, string>): Promise<{ status: number; headers: Headers } | null> {
  const ctrl = new AbortController(); const t = setTimeout(() => ctrl.abort(), REQ_TIMEOUT); const t0 = Date.now();
  try {
    const res = await fetch(url, { redirect: 'manual', signal: ctrl.signal, headers: { 'user-agent': 'CyberTestify-Transport/1.0', ...(extra ?? {}) } });
    logScanStep({ step: 'Taşıma & Başlık Derinliği', method: 'GET', url, status: res.status, durationMs: Date.now() - t0 });
    return { status: res.status, headers: res.headers };
  } catch { logScanStep({ step: 'Taşıma & Başlık Derinliği', method: 'GET', url, status: 0, level: 'warn' }); return null; }
  finally { clearTimeout(t); }
}

// ——— TLS handshake (read-only; istismar yok) ———
type Handshake = { ok: boolean; protocol?: string | null; cipher?: string; cert?: tls.PeerCertificate };
function tlsHandshake(host: string, opts: tls.ConnectionOptions): Promise<Handshake> {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v: Handshake) => { if (done) return; done = true; try { sock.destroy(); } catch { /* yoksay */ } resolve(v); };
    let sock: tls.TLSSocket;
    try {
      sock = tls.connect({ host, port: 443, servername: host, timeout: 8000, rejectUnauthorized: false, ...opts }, () => {
        finish({ ok: true, protocol: sock.getProtocol(), cipher: (sock.getCipher() || {}).name, cert: sock.getPeerCertificate() });
      });
    } catch { resolve({ ok: false }); return; } // node protokolü hiç desteklemiyorsa (ör. TLSv1 devre dışı derleme)
    sock.on('error', () => finish({ ok: false }));
    sock.on('timeout', () => finish({ ok: false }));
    setTimeout(() => finish({ ok: false }), 9000);
  });
}

export async function collectTransportSecurityEvidence(host: string): Promise<ActiveCheckEvidence> {
  const findings: VFinding[] = []; const notes: string[] = [];
  await resolveOrigin(host).catch(() => null);
  const origin = cachedOriginUrl(host);
  let probes = 0;

  // ————————————————— H1 CORS —————————————————
  const corpus = await fetchClientCorpus(host);
  const corpusText = corpus.reachable ? corpus.homeHtml + '\n' + corpus.sameOriginJs.map((f) => f.body).join('\n') : '';
  const corsTargets = [`${origin}/`, ...mineApiPaths(corpusText).slice(0, 3).map((p) => { try { return new URL(p, `${origin}/`).toString(); } catch { return ''; } }).filter(Boolean)];
  const corsSeen = new Set<string>();
  for (const url of corsTargets) {
    const r = await getHeaders(url, { Origin: CORS_PROBE_ORIGIN }); probes++;
    if (!r) continue;
    const acao = (r.headers.get('access-control-allow-origin') ?? '').trim();
    const acac = (r.headers.get('access-control-allow-credentials') ?? '').trim().toLowerCase();
    let ep: string; try { ep = new URL(url).pathname; } catch { ep = url; }
    const key = acao + '|' + acac + '|' + (acao === CORS_PROBE_ORIGIN ? ep : acao);
    if (corsSeen.has(key)) continue; corsSeen.add(key);
    if (acao === CORS_PROBE_ORIGIN && acac === 'true') findings.push({ check: 'cors_credentials', inputPoint: ep, vulnerable: true, technique: 'CORS origin yansıma gözlemi (tek güvenli istek) — reflected + credentials', evidence: `Uç (\`${ep}\`) kurgu \`Origin\`'i **yansıtıyor** (ACAO=gönderilen origin) **ve** \`Access-Control-Allow-Credentials: true\` — kimlik-bilgili (çerez/oturum) veriler herhangi bir kökene sızabilir (NET kötü yapılandırma). Origin'i allowlist'leyin; credentials ile wildcard/yansıtma KULLANMAYIN.`, confidence: 'high', severity: 'high', sideEffectRisk: 'none' });
    else if (acao === CORS_PROBE_ORIGIN) findings.push({ check: 'cors_reflect', inputPoint: ep, vulnerable: true, technique: 'CORS origin yansıma gözlemi (tek güvenli istek) — reflected, credentials yok', evidence: `Uç (\`${ep}\`) kurgu \`Origin\`'i yansıtıyor (ACAO=gönderilen origin) ancak \`credentials\` yok — public API tasarımı **olabilir**; yine de gereksizse origin allowlist'i önerilir (gösterge, doğrulama gerekir).`, confidence: 'medium', severity: 'medium', sideEffectRisk: 'none' });
    else if (acao === '*' && acac !== 'true') notes.push(`CORS: \`${ep}\` \`Access-Control-Allow-Origin: *\` (credentials yok) — public kaynak için yaygın/kabul edilebilir (bilgilendirici).`);
  }
  // null origin kabulü (tek gözlem)
  const nullR = await getHeaders(`${origin}/`, { Origin: 'null' }); probes++;
  if (nullR && (nullR.headers.get('access-control-allow-origin') ?? '').trim().toLowerCase() === 'null') findings.push({ check: 'cors_null', inputPoint: new URL(origin).host, vulnerable: true, technique: 'CORS null-origin kabul gözlemi', evidence: `Sunucu \`Origin: null\`'ı **yansıtıyor** (ACAO: null) — sandboxed iframe/yerel dosya bağlamından cross-origin erişime zemin (gösterge, doğrulama gerekir).`, confidence: 'medium', severity: 'medium', sideEffectRisk: 'none' });
  if (corsTargets.length === 0) notes.push('CORS: test edilebilir gerçek uç bulunamadı — CORS alt-kontrolü bu hedefte kapsam dışı.');

  // ————————————————— H3 TLS PROTOKOL / CIPHER —————————————————
  const protoTests: Array<{ v: 'TLSv1' | 'TLSv1.1' | 'TLSv1.2' | 'TLSv1.3'; label: string }> = [
    { v: 'TLSv1', label: 'TLS 1.0' }, { v: 'TLSv1.1', label: 'TLS 1.1' }, { v: 'TLSv1.2', label: 'TLS 1.2' }, { v: 'TLSv1.3', label: 'TLS 1.3' },
  ];
  const supported: string[] = []; const weakProto: string[] = []; let anyHandshake = false; let cert: tls.PeerCertificate | undefined;
  for (const p of protoTests) {
    const hs = await tlsHandshake(host, { minVersion: p.v, maxVersion: p.v }); probes++;
    if (hs.ok) { anyHandshake = true; supported.push(p.label); if (p.v === 'TLSv1' || p.v === 'TLSv1.1') weakProto.push(p.label); if (hs.cert && Object.keys(hs.cert).length) cert = hs.cert; }
  }
  if (weakProto.length) findings.push({ check: 'weak_tls_protocol', inputPoint: `${host}:443`, vulnerable: true, technique: 'TLS protokol handshake gözlemi (read-only) — eski protokol', evidence: `Sunucu **${weakProto.join(', ')}** (eski/kaldırılması önerilen protokol) el sıkışmasını kabul ediyor — protokol-düşürme (downgrade) yüzeyi. Yalnız TLS 1.2/1.3 bırakılmalı. (Yalnız handshake gözlemi; istismar yok.)`, confidence: 'high', severity: 'medium', sideEffectRisk: 'none' });
  // Zayıf cipher (RC4/3DES/DES/EXPORT/NULL) — tek deneme
  const weakHs = await tlsHandshake(host, { minVersion: 'TLSv1', maxVersion: 'TLSv1.2', ciphers: 'RC4-SHA:RC4-MD5:DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:EXP-RC4-MD5:NULL-SHA:aNULL:eNULL' }); probes++;
  if (weakHs.ok && weakHs.cipher && !/^(TLS_AES|TLS_CHACHA|ECDHE|DHE)/i.test(weakHs.cipher) && /RC4|3DES|DES|NULL|EXPORT|MD5/i.test(weakHs.cipher)) findings.push({ check: 'weak_tls_cipher', inputPoint: `${host}:443`, vulnerable: true, technique: 'TLS zayıf cipher handshake gözlemi (read-only)', evidence: `Sunucu **zayıf cipher** (\`${weakHs.cipher}\` — RC4/3DES/NULL/EXPORT sınıfı) el sıkışmasını kabul etti — trafik gizliliği/bütünlüğü zayıflar. Modern AEAD cipher'lara (ECDHE + AES-GCM/CHACHA20) geçin. (Yalnız gözlem.)`, confidence: 'high', severity: 'medium', sideEffectRisk: 'none' });
  if (anyHandshake) {
    notes.push(`TLS: desteklenen protokoller — **${supported.join(', ') || '(tespit edilemedi)'}**${supported.includes('TLS 1.2') || supported.includes('TLS 1.3') ? ' (TLS 1.2/1.3 mevcut — olumlu)' : ''}.`);
    // Sertifika: yalnız GERÇEK sorun (süre dolmuş / hostname uyumsuz / self-signed) bulgu olur — de-dup: cert türü tek yerde.
    if (cert && Object.keys(cert).length) {
      const now = Date.now(); const to = cert.valid_to ? Date.parse(cert.valid_to) : NaN;
      const expired = !Number.isNaN(to) && to < now;
      const selfSigned = !!cert.issuer && !!cert.subject && JSON.stringify(cert.issuer) === JSON.stringify(cert.subject);
      const names = [cert.subject?.CN, ...(String(cert.subjectaltname ?? '').match(/DNS:([^,\s]+)/g) ?? []).map((s) => s.replace('DNS:', ''))].filter(Boolean).map((s) => String(s).toLowerCase());
      const hostnameOk = names.some((n) => n === host.toLowerCase() || (n.startsWith('*.') && host.toLowerCase().endsWith(n.slice(1))));
      if (expired) findings.push({ check: 'cert_expired', inputPoint: `${host}:443`, vulnerable: true, technique: 'sertifika geçerlilik gözlemi (handshake)', evidence: `TLS **sertifikasının süresi dolmuş** (valid_to: ${cert.valid_to}) — tarayıcılar siteyi güvensiz işaretler. Sertifikayı yenileyin.`, confidence: 'high', severity: 'high', sideEffectRisk: 'none' });
      else if (selfSigned) findings.push({ check: 'cert_self_signed', inputPoint: `${host}:443`, vulnerable: true, technique: 'sertifika zincir gözlemi (handshake)', evidence: `TLS sertifikası **kendinden imzalı** görünüyor (issuer==subject) — güven zinciri yok, MITM/tarayıcı uyarısı riski. Güvenilir bir CA sertifikası kullanın.`, confidence: 'medium', severity: 'medium', sideEffectRisk: 'none' });
      else if (names.length && !hostnameOk) findings.push({ check: 'cert_hostname', inputPoint: `${host}:443`, vulnerable: true, technique: 'sertifika hostname eşleşme gözlemi (handshake)', evidence: `TLS sertifikası ana bilgisayar adıyla **eşleşmiyor** (CN/SAN: ${names.slice(0, 3).join(', ')}) — tarayıcı uyarısı/MITM riski. Doğru alan adı için sertifika sağlayın.`, confidence: 'medium', severity: 'medium', sideEffectRisk: 'none' });
      else notes.push('TLS sertifikası (süre/hostname/zincir) handshake sırasında geçerli görünüyor — belirgin sertifika sorunu gözlenmedi (olumlu).');
    }
  } else notes.push('TLS: 443 üzerinde handshake gözlemlenemedi (HTTPS yok veya erişilemedi) — TLS protokol/cipher değerlendirmesi bu hedef için sınırlıdır.');

  // ————————————————— H4 GÜVENLİK BAŞLIĞI DERİNLİĞİ —————————————————
  const hr = await getHeaders(`${origin}/`); probes++;
  if (hr) {
    const H = hr.headers;
    const hsts = H.get('strict-transport-security'); const xfo = H.get('x-frame-options'); const csp = H.get('content-security-policy');
    const referrer = H.get('referrer-policy'); const perms = H.get('permissions-policy'); const xcto = H.get('x-content-type-options');
    if (!hsts) findings.push({ check: 'hsts_missing', inputPoint: new URL(origin).host, vulnerable: true, technique: 'HSTS (Strict-Transport-Security) başlık gözlemi', evidence: `HTTPS yanıtında **Strict-Transport-Security yok** — ilk bağlantı HTTPS'e zorlanmıyor, MITM/downgrade riski. \`max-age≥15768000; includeSubDomains; preload\` önerilir.`, confidence: 'high', severity: 'medium', sideEffectRisk: 'none' });
    else { const m = hsts.match(/max-age\s*=\s*(\d+)/i); const age = m ? parseInt(m[1], 10) : 0; if (age < 15552000) findings.push({ check: 'hsts_weak', inputPoint: new URL(origin).host, vulnerable: true, technique: 'HSTS max-age yeterlilik gözlemi', evidence: `HSTS mevcut ama \`max-age=${age}\` **kısa** (< 180 gün) — koruma penceresi dar. \`max-age≥15768000\` (1 yıl) + \`includeSubDomains\` önerilir (gösterge).`, confidence: 'high', severity: 'low', sideEffectRisk: 'none' }); else notes.push(`HSTS mevcut (max-age=${age}${/includesubdomains/i.test(hsts) ? '; includeSubDomains' : ''}${/preload/i.test(hsts) ? '; preload' : ''}) — olumlu.`); }
    if (!xfo && !(csp && /frame-ancestors/i.test(csp))) findings.push({ check: 'clickjacking', inputPoint: new URL(origin).host, vulnerable: true, technique: 'clickjacking koruması (X-Frame-Options / CSP frame-ancestors) çift-mekanizma gözlemi', evidence: `Sayfada **ne \`X-Frame-Options\` ne de CSP \`frame-ancestors\`** var — clickjacking için tarayıcı-taraflı koruma yok. \`X-Frame-Options: SAMEORIGIN\` veya CSP \`frame-ancestors 'self'\` ekleyin.`, confidence: 'high', severity: 'medium', sideEffectRisk: 'none' });
    if (csp && /unsafe-inline|unsafe-eval|(^|[\s;])\*([\s;]|$)/i.test(csp)) findings.push({ check: 'csp_weak', inputPoint: new URL(origin).host, vulnerable: true, technique: 'CSP direktif zayıflık analizi (unsafe-inline/unsafe-eval/*)', evidence: `Content-Security-Policy mevcut ama zayıflatıcı direktif içeriyor (\`${(csp.match(/unsafe-inline|unsafe-eval|\*/i) || [''])[0]}\`) — XSS azaltması büyük ölçüde etkisiz. nonce/hash tabanlı politikaya geçin (sertleştirme boşluğu).`, confidence: 'medium', severity: 'low', sideEffectRisk: 'none' });
    else if (!csp) findings.push({ check: 'csp_missing', inputPoint: new URL(origin).host, vulnerable: true, technique: 'CSP varlık gözlemi', evidence: `Content-Security-Policy başlığı **yok** — enjekte edilen script'lere karşı tarayıcı-taraflı azaltma katmanı bulunmuyor (sertleştirme boşluğu, düşük).`, confidence: 'high', severity: 'low', sideEffectRisk: 'none' });
    if (!referrer) findings.push({ check: 'referrer_policy', inputPoint: new URL(origin).host, vulnerable: true, technique: 'Referrer-Policy başlık gözlemi', evidence: `Referrer-Policy başlığı yok — dış bağlantılara adres/oturum bilgisi sızabilir (bilgilendirici). \`Referrer-Policy: strict-origin-when-cross-origin\` önerilir.`, confidence: 'high', severity: 'low', sideEffectRisk: 'none' });
    if (!perms) findings.push({ check: 'permissions_policy', inputPoint: new URL(origin).host, vulnerable: true, technique: 'Permissions-Policy başlık gözlemi', evidence: `Permissions-Policy başlığı yok — tarayıcı özellik erişimi (kamera/mikrofon/konum) kısıtlanmıyor (bilgilendirici sertleştirme).`, confidence: 'high', severity: 'low', sideEffectRisk: 'none' });
    if (!xcto) findings.push({ check: 'mime_sniffing', inputPoint: new URL(origin).host, vulnerable: true, technique: 'X-Content-Type-Options (nosniff) başlık gözlemi', evidence: `X-Content-Type-Options başlığı yok — tarayıcı içerik türünü tahmin edip (MIME-sniffing) zararlı içeriği çalıştırabilir. \`X-Content-Type-Options: nosniff\` ekleyin (bilgilendirici).`, confidence: 'high', severity: 'low', sideEffectRisk: 'none' });
  } else notes.push('Güvenlik başlığı derinliği: HTTPS ana sayfa başlıkları okunamadı — bu alt-kontrol sınırlı.');

  notes.push(`Denenen: **${probes}** güvenli gözlem (CORS origin probu + TLS handshake + başlık okuması). Veri değiştirme / DoS / cipher istismarı / takeover-claim YOK. Sertifika geçerliliği yalnız GERÇEK sorunda bulgu (çift-CT yok).`);
  return { ok: true, pagesScanned: 1, inputsFound: corsTargets.length + supported.length, probesSent: probes, findings, stopped: null, notes };
}

// ————————————————— H2 SUBDOMAIN TAKEOVER (dangling DNS) — collectSubdomains motorunu sarar —————————————————
export async function collectSubdomainTakeoverEvidence(host: string): Promise<ActiveCheckEvidence> {
  const findings: VFinding[] = []; const notes: string[] = [];
  const sub = await collectSubdomains(host).catch(() => null);
  if (!sub) return { ok: true, pagesScanned: 0, inputsFound: 0, probesSent: 1, findings, stopped: null, notes: ['Subdomain takeover: alt-alan verisi toplanamadı — bu alt-kontrol sınırlı.'] };
  if (sub.dataSource === 'unavailable') return { ok: true, pagesScanned: 0, inputsFound: 0, probesSent: 1, findings, stopped: 'CT veri kaynağına ulaşılamadı', notes: ['Subdomain takeover: Certificate Transparency kaynaklarına (crt.sh/certSpotter) ulaşılamadı — **incelenemedi** (temiz değil).'] };
  for (const d of sub.dangling) {
    const high = d.confidence === 'confirmed';
    findings.push({ check: 'subdomain_takeover', inputPoint: d.sub, vulnerable: true, technique: `dangling DNS / subdomain takeover ${high ? 'imza eşleşmesi (güvenli GET)' : 'şüphesi (CNAME NXDOMAIN)'}`, evidence: `${d.note} — OLASI subdomain takeover (${d.service}); saldırganca devralınıp phishing/itibar riski. Kullanılmayan CNAME kaydını kaldırın. (Yalnız DNS çözümü + tek güvenli GET; kayıt/claim YAPILMADI.)`, confidence: high ? 'high' : 'medium', severity: high ? 'high' : 'medium', sideEffectRisk: 'none' });
  }
  if (sub.managedCnames.length) notes.push(`${sub.managedCnames.length} alt-alan bilinen 3P servise CNAME veriyor ancak **canlı/sahiplenilmiş** (dangling değil) — bilgilendirici.`);
  notes.push(`Keşfedilen alt-alan: **${sub.total}** (CT logu), CNAME çözülen: **${sub.resolved}**, dangling takeover göstergesi: **${sub.dangling.length}**. Uydurma alt-alan yok — yalnız CT'de gözlenenler. Hiçbir kayıt/registrasyon/claim yapılmadı.`);
  return { ok: true, pagesScanned: sub.resolved, inputsFound: sub.total, probesSent: sub.resolved + 1, findings, stopped: null, notes };
}
