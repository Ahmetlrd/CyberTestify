/**
 * (Uyum Paketi / bundle_compliance) DETERMINISTIK RAPOR — KVKK Ön Uyum + PCI-DSS Hazırlık +
 * ISO 27001 Hazırlık. bundle_surface ile AYNI desen: her alan {findings, fixText}|null döndürür,
 * combineComplianceAreas TEK rapora birleştirir. Veri KODDAN toplanır (ajan/PentAGI YOK).
 *
 * ÖNEMLİ (KVKK dili): Bu bir RESMİ uyum/sertifikasyon beyanı DEĞİLDİR. "uyumlu/uyumsuz" gibi
 * kesin hukuki hüküm KURULMAZ; yalnızca "dışarıdan gözlemlenebilir" teknik gösterge var/yok
 * olarak raporlanır (Gözlemlendi / Gözlemlenmedi / İnceleme gerekli).
 */
import { collectHttp, collectTls, collectExposedFiles } from './surfaceEvidence.js';

type Level = 'low' | 'medium' | 'high';
const RISK_WORD = { low: 'Düşük', medium: 'Orta', high: 'Yüksek' } as const;
function levelRank(l: Level): number { return l === 'high' ? 2 : l === 'medium' ? 1 : 0; }

function assemble(level: Level, summaryBullets: string[], genelSentence: string, sections: string): string {
  return (
    `## YÖNETİCİ ÖZETİ\n\n${summaryBullets.join('\n')}\n\n` +
    `## GENEL DEĞERLENDİRME\n\n**Risk Seviyesi: ${RISK_WORD[level]}**\n\n${genelSentence}\n\n` +
    `${sections}`
  );
}
function extractLevel(findings: string): Level | null {
  const m = findings.match(/Risk Seviyesi:\s*(Y[uü]ksek|Orta|D[uü][sş][uü]k)/i);
  if (!m) return null;
  const w = m[1].toLocaleLowerCase('tr');
  return /y[uü]ksek/.test(w) ? 'high' : /orta/.test(w) ? 'medium' : 'low';
}
function areaHeadline(findings: string): string {
  const m = findings.match(/Genel de[ğg]erlendirme özeti:\s*([^\n]+)/i) || findings.match(/^-\s*\*\*[^\n]+?\*\*\s*[—–-]\s*([^\n]+)/m);
  return m ? m[1].trim().replace(/\*\*/g, '') : '';
}
function detailOnly(findings: string): string {
  const parts = findings.split(/(?=^## )/m);
  return parts.slice(2).join('').replace(/^## /gm, '### ').trim();
}

const CAUTION = '> Bu bölüm dışarıdan gözlemlenebilir teknik göstergeleri ilgili ilke/madde ile eşler; **resmi bir uyum/uygunluk denetimi veya sertifikasyon beyanı DEĞİLDİR**. Kesin uygunluk için kapsamlı, ayrı bir denetim gerekir.';

// ======================================================================================
// PCI-DSS Hazırlık Ön-Değerlendirmesi
// ======================================================================================
export async function generatePciReport(host: string): Promise<{ findings: string; fixText: string } | null> {
  const [http, tls] = await Promise.all([collectHttp(host), collectTls(host)]);
  if (!http.ok && !tls.found) return null;
  const exposed = await collectExposedFiles(host, http.html);
  const exposedHits = exposed.filter((e) => e.exposed);

  const HDRS = ['strict-transport-security', 'content-security-policy', 'x-frame-options', 'x-content-type-options'];
  const missingHdrs = HDRS.filter((h) => !http.headers.has(h));
  const cookies = http.setCookies.map(parseCookie);
  const insecureCookies = cookies.filter((c) => !c.secure || !c.httpOnly);
  const server = http.headers.get('server') ?? '';
  const versionBanner = /\d+\.\d+/.test(server) || /\d/.test(http.headers.get('x-powered-by') ?? '');
  const tlsBad = tls.hostnameMatch === false || (tls.daysLeft != null && tls.daysLeft < 0) || tls.weakProtocols.length > 0;

  let level: Level = 'low';
  if (exposedHits.length || tlsBad) level = 'high';
  else if (missingHdrs.length >= 2 || insecureCookies.length || versionBanner) level = 'medium';

  const st = (present: boolean) => (present ? 'Mevcut' : 'Eksik');
  const rows = [
    `| Req 4.2.1 — Aktarımda güçlü şifreleme | TLS ${tls.protocol ?? 'tespit edilemedi'}${tls.weakProtocols.length ? `, zayıf sürüm: ${tls.weakProtocols.join(', ')}` : ''}${tls.daysLeft != null ? `, sertifika ${tls.daysLeft >= 0 ? tls.daysLeft + ' gün' : 'SÜRESİ DOLMUŞ'}` : ''} | ${tlsBad ? 'Eksik' : 'Mevcut'} | ${tlsBad ? 'TLS 1.2+ zorunlu kıl, zayıf sürüm/sertifika sorununu gider' : 'Güncel; sürdürün'} |`,
    `| Req 6.4 — Güvenlik başlıkları | ${missingHdrs.length ? 'Eksik: ' + missingHdrs.join(', ') : 'HSTS/CSP/X-Frame/X-Content-Type mevcut'} | ${missingHdrs.length >= 2 ? 'Eksik' : missingHdrs.length === 1 ? 'Kısmi' : 'Mevcut'} | Eksik güvenlik başlıklarını ekleyin |`,
    `| Req 8 — Oturum/çerez güvenliği | ${cookies.length ? `${insecureCookies.length}/${cookies.length} çerezde Secure/HttpOnly eksik` : 'Ana sayfada Set-Cookie gözlemlenmedi'} | ${insecureCookies.length ? 'Eksik' : 'Mevcut'} | Çerezlere Secure + HttpOnly + SameSite ekleyin |`,
    `| Req 2.2 — Güvenli yapılandırma (sürüm ifşası) | ${server ? 'Server: ' + server : 'Server banner gözlemlenmedi'}${versionBanner ? ' (sürüm ifşası)' : ''} | ${versionBanner ? 'Eksik' : 'Mevcut'} | Sunucu/teknoloji sürüm bilgisini gizleyin |`,
    `| Req 3 — Veri ifşası (açıkta dosya) | ${exposedHits.length ? '⚠️ Açık: ' + exposedHits.map((e) => e.path).join(', ') : 'Yaygın hassas yollar erişilebilir değil'} | ${exposedHits.length ? 'Eksik' : 'Mevcut'} | Açıkta kalan dosyalara erişimi engelleyin |`,
  ].join('\n');

  const bullets = [
    `- **Genel risk seviyesi: ${RISK_WORD[level]}** — ${level === 'high' ? 'PCI-DSS açısından öncelikli ele alınması gereken dışarıdan gözlemlenebilir eksiklik(ler) var.' : level === 'medium' ? 'kısa vadede giderilmesi önerilen gözlemlenebilir eksikler var.' : 'dışarıdan gözlemlenebilir belirgin bir eksiklik öne çıkmadı.'}`,
    `- TLS: ${tlsBad ? '⚠️ sorun' : 'sağlam'} · Başlıklar: ${missingHdrs.length} eksik · Çerez: ${insecureCookies.length} eksik bayraklı · Açıkta dosya: ${exposedHits.length ? '⚠️ ' + exposedHits.length : 'yok'}.`,
    '- **Önerilen ilk adım:** En yüksek etkili eksikten başlayın; hazır düzeltmeler "AI Çözüm Önerileri" bölümünde.',
  ];
  const genel =
    (level === 'high'
      ? 'Dışarıdan gözlemlenebilir, PCI-DSS ile ilişkili öncelikli eksiklik(ler) tespit edildi (örn. açıkta dosya veya zayıf TLS).'
      : level === 'medium'
        ? 'Dışarıdan gözlemlenebilir, kısa vadede giderilmesi önerilen PCI-DSS ilişkili eksikler var.'
        : 'Dışarıdan gözlemlenebilir belirgin bir PCI-DSS ilişkili eksiklik öne çıkmadı.') +
    ' Bu bir resmî ASV/QSA testi veya uygunluk beyanı değildir; iç ağ/CDE, segmentasyon ve sızma testi kapsam dışıdır.';

  const findings = assemble(level, bullets, genel,
    `${CAUTION}\n\n## PCI-DSS GÖZLEM TABLOSU\n\n| Gereksinim | Gözlem | Gözlemlenebilir kontrol | Öneri |\n|-----------|--------|------------------------|-------|\n${rows}\n`);
  const fixText = buildComplianceFix(host, 'PCI-DSS', { tlsBad, missingHdrs, insecureCookies: insecureCookies.length > 0, versionBanner, exposed: exposedHits.map((e) => e.path), weak: tls.weakProtocols });
  return { findings, fixText };
}

// ======================================================================================
// ISO/IEC 27001 Annex A Hazırlık Kontrol Listesi
// ======================================================================================
export async function generateIso27001Report(host: string): Promise<{ findings: string; fixText: string } | null> {
  const [http, tls] = await Promise.all([collectHttp(host), collectTls(host)]);
  if (!http.ok && !tls.found) return null;
  const exposed = await collectExposedFiles(host, http.html);
  const exposedHits = exposed.filter((e) => e.exposed);
  const HDRS = ['strict-transport-security', 'content-security-policy', 'x-frame-options', 'x-content-type-options'];
  const missingHdrs = HDRS.filter((h) => !http.headers.has(h));
  const server = http.headers.get('server') ?? '';
  const versionBanner = /\d+\.\d+/.test(server) || /\d/.test(http.headers.get('x-powered-by') ?? '');
  const tlsBad = tls.hostnameMatch === false || (tls.daysLeft != null && tls.daysLeft < 0) || tls.weakProtocols.length > 0;
  const policy = await hasPolicyPage(host, http.html);

  let level: Level = 'low';
  if (exposedHits.length || tlsBad) level = 'high';
  else if (missingHdrs.length >= 2 || versionBanner || !policy.found) level = 'medium';

  const rows = [
    `| A.8.24 — Kriptografi | TLS ${tls.protocol ?? 'tespit edilemedi'}${tls.weakProtocols.length ? `, zayıf: ${tls.weakProtocols.join(', ')}` : ''} | ${tlsBad ? 'Eksik' : 'Mevcut'} | TLS 1.2+ ve geçerli sertifika sürdürün |`,
    `| A.8.23/A.8.9 — Güvenlik başlıkları | ${missingHdrs.length ? 'Eksik: ' + missingHdrs.join(', ') : 'Temel başlıklar mevcut'} | ${missingHdrs.length >= 2 ? 'Eksik' : missingHdrs.length === 1 ? 'Kısmi' : 'Mevcut'} | Eksik başlıkları ekleyin |`,
    `| A.8.9 — Güvenli yapılandırma (sürüm ifşası) | ${server ? 'Server: ' + server : 'banner gözlemlenmedi'}${versionBanner ? ' (sürüm ifşası)' : ''} | ${versionBanner ? 'Eksik' : 'Mevcut'} | Sürüm bilgisini gizleyin |`,
    `| A.8.12 — Veri sızıntısı (açıkta dosya) | ${exposedHits.length ? '⚠️ Açık: ' + exposedHits.map((e) => e.path).join(', ') : 'Hassas yollar erişilebilir değil'} | ${exposedHits.length ? 'Eksik' : 'Mevcut'} | Erişimi engelleyin |`,
    `| A.5.1 — Politikalar | ${policy.found ? `Politika sayfası erişilebilir (${policy.where})` : 'Gizlilik/güvenlik politikası sayfası gözlemlenmedi'} | ${policy.found ? 'Mevcut' : 'İnceleme gerekli'} | Erişilebilir bir politika sayfası yayınlayın |`,
  ].join('\n');

  const bullets = [
    `- **Genel risk seviyesi: ${RISK_WORD[level]}** — ${level === 'high' ? 'Annex A açısından öncelikli, dışarıdan gözlemlenebilir eksiklik(ler) var.' : level === 'medium' ? 'kısa vadede giderilmesi önerilen gözlemlenebilir eksikler var.' : 'belirgin bir gözlemlenebilir eksiklik öne çıkmadı.'}`,
    `- TLS: ${tlsBad ? '⚠️ sorun' : 'sağlam'} · Başlıklar: ${missingHdrs.length} eksik · Açıkta dosya: ${exposedHits.length ? '⚠️ ' + exposedHits.length : 'yok'} · Politika sayfası: ${policy.found ? 'var' : 'gözlemlenmedi'}.`,
    '- **Önerilen ilk adım:** En yüksek etkili eksikten başlayın; hazır düzeltmeler "AI Çözüm Önerileri" bölümünde.',
  ];
  const genel =
    (level === 'high'
      ? 'Dışarıdan gözlemlenebilir, ISO 27001 Annex A ile ilişkili öncelikli eksiklik(ler) tespit edildi.'
      : level === 'medium'
        ? 'Dışarıdan gözlemlenebilir, kısa vadede giderilmesi önerilen Annex A ilişkili eksikler var.'
        : 'Dışarıdan gözlemlenebilir belirgin bir Annex A ilişkili eksiklik öne çıkmadı.') +
    ' Bu bir ISO 27001 denetimi/sertifikasyonu değildir; ISMS kapsamı, dokümantasyon ve iç süreçler kapsam dışıdır.';

  const findings = assemble(level, bullets, genel,
    `${CAUTION}\n\n## ISO 27001 ANNEX A GÖZLEM TABLOSU\n\n| Madde | Gözlem | Gözlemlenebilir kontrol | Öneri |\n|-------|--------|------------------------|-------|\n${rows}\n`);
  const fixText = buildComplianceFix(host, 'ISO 27001', { tlsBad, missingHdrs, insecureCookies: false, versionBanner, exposed: exposedHits.map((e) => e.path), weak: tls.weakProtocols, policyMissing: !policy.found });
  return { findings, fixText };
}

// ======================================================================================
// KVKK Ön Uyum Kontrolü (temkinli dil — resmi uyum beyanı DEĞİL)
// ======================================================================================
export async function generateKvkkReport(host: string): Promise<{ findings: string; fixText: string } | null> {
  const http = await collectHttp(host);
  if (!http.ok) return null;
  const s = await collectKvkkSignals(host, http);

  const trackingNoConsent = s.trackers.length > 0 && !s.cookieBanner;
  const gaps: string[] = [];
  if (!s.policyFound) gaps.push('aydınlatma/gizlilik metni');
  if (!s.cookieBanner) gaps.push('çerez rıza banner’ı');
  if (!s.contactFound) gaps.push('veri sorumlusu/iletişim bilgisi');

  let level: Level = 'low';
  if (trackingNoConsent) level = 'high';
  else if (gaps.length >= 1 || s.preConsentCookies > 0) level = 'medium';

  const durum = (found: boolean) => (found ? 'Gözlemlendi' : 'Gözlemlenmedi');
  const rows = [
    `| Aydınlatma yükümlülüğü (m.10) | ${s.policyFound ? `Gizlilik/aydınlatma metni erişilebilir (${s.policyWhere})` : 'Kontrol edilen sayfalarda gözlemlenmedi'} | ${durum(s.policyFound)} | Erişilebilir bir aydınlatma metni/gizlilik politikası yayınlayın |`,
    `| Açık rıza — çerezler (m.5) | ${s.cookieBanner ? 'Çerez rıza banner’ı gözlemlendi' : 'Çerez rıza banner’ı gözlemlenmedi'}${s.preConsentCookies > 0 ? `; ana sayfa yanıtında rızadan önce ${s.preConsentCookies} çerez bırakılıyor` : ''} | ${s.cookieBanner && s.preConsentCookies === 0 ? 'Gözlemlendi' : 'İnceleme gerekli'} | Rıza öncesi izleyici çerez bırakmayın; açık rıza banner’ı ekleyin |`,
    `| Üçüncü taraf aktarım/izleyiciler (m.8-9) | ${s.trackers.length ? 'Gözlemlenen: ' + s.trackers.join(', ') : 'Ana sayfada belirgin izleyici gözlemlenmedi'} | ${s.trackers.length ? (s.cookieBanner ? 'Gözlemlendi (rıza mekanizması var)' : 'İnceleme gerekli') : 'Gözlemlenmedi'} | İzleyicileri açık rızaya bağlayın; aydınlatmada belirtin |`,
    `| Veri sorumlusu / VERBIS (m.16) | ${s.contactFound ? `İletişim/veri sorumlusu bilgisi gözlemlendi (${s.contactWhere})` : 'Kontrol edilen sayfalarda gözlemlenmedi'} | ${durum(s.contactFound)} | Veri sorumlusu kimliği ve iletişim/VERBIS bilgisini yayınlayın |`,
    `| Veri güvenliği tedbirleri (m.12) | Site HTTPS üzerinden sunuluyor${http.headers.has('strict-transport-security') ? ' (HSTS mevcut)' : ''} | Gözlemlendi | Taşıma güvenliğini (HTTPS/HSTS) sürdürün |`,
  ].join('\n');

  const bullets = [
    `- **Genel risk seviyesi: ${RISK_WORD[level]}** — ${level === 'high' ? 'rıza mekanizması gözlemlenmeden izleyici çerez/servis kullanımı dikkat çekiyor.' : level === 'medium' ? 'dışarıdan gözlemlenebilir bazı KVKK hazırlık eksikleri var.' : 'dışarıdan gözlemlenebilir belirgin bir KVKK hazırlık eksiği öne çıkmadı.'}`,
    `- Aydınlatma: ${s.policyFound ? 'var' : 'gözlemlenmedi'} · Çerez rızası: ${s.cookieBanner ? 'var' : 'gözlemlenmedi'} · İzleyici: ${s.trackers.length || 'yok'} · İletişim/VERBIS: ${s.contactFound ? 'var' : 'gözlemlenmedi'}.`,
    '- **Önerilen ilk adım:** ' + (trackingNoConsent ? 'Rıza öncesi izleyici çerezleri durdurun ve açık rıza banner’ı ekleyin.' : 'Eksik gözlemlenen kalemleri tamamlayın (aydınlatma/iletişim).') + ' Hazır adımlar "AI Çözüm Önerileri" bölümünde.',
  ];
  const genel =
    (level === 'high'
      ? 'Açık rıza mekanizması gözlemlenmeden üçüncü taraf izleyici/çerez kullanımı gibi, dışarıdan gözlemlenebilir öncelikli hazırlık eksiği dikkat çekiyor.'
      : level === 'medium'
        ? 'Dışarıdan gözlemlenebilir bazı KVKK hazırlık eksikleri var; kısa vadede tamamlanması önerilir.'
        : 'Dışarıdan gözlemlenebilir belirgin bir KVKK hazırlık eksiği öne çıkmadı.') +
    ' Bu bir hukuki danışmanlık veya resmî KVKK uyum beyanı değildir; yalnızca dışarıdan gözlemlenebilir göstergeleri ilkelerle eşler.';

  const findings = assemble(level, bullets, genel,
    `${CAUTION}\n\n## KVKK GÖZLEM TABLOSU\n\n| KVKK İlkesi/Konu | Gözlem | Durum | Öneri |\n|------------------|--------|-------|-------|\n${rows}\n`);
  const fixText = buildKvkkFix(host, { policyMissing: !s.policyFound, bannerMissing: !s.cookieBanner, trackingNoConsent, contactMissing: !s.contactFound, preConsentCookies: s.preConsentCookies });
  return { findings, fixText };
}

// ---- KVKK sinyalleri (kucuk, pasif ek collector'lar) --------------------------------
type KvkkSignals = { policyFound: boolean; policyWhere: string; cookieBanner: boolean; trackers: string[]; preConsentCookies: number; contactFound: boolean; contactWhere: string };

async function fetchPageText(url: string): Promise<{ ok: boolean; html: string }> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 8000);
  try {
    const res = await fetch(url, { signal: ctrl.signal, redirect: 'follow', headers: { 'user-agent': 'CyberTestify-PassiveCheck/1.0' } });
    if (!res.ok) return { ok: false, html: '' };
    const buf = Buffer.from(await res.arrayBuffer());
    return { ok: true, html: (buf.length > 400000 ? buf.subarray(0, 400000) : buf).toString('utf-8') };
  } catch {
    return { ok: false, html: '' };
  } finally {
    clearTimeout(timer);
  }
}

const POLICY_RE = /(gizlilik|ayd[ıi]nlatma|kvkk|çerez politikas|cookie policy|privacy policy)/i;
const CONTACT_RE = /(verbis|veri sorumlusu|mersis|iletişim|künye|[\w.-]+@[\w.-]+\.\w{2,})/i;

async function hasPolicyPage(host: string, homeHtml: string): Promise<{ found: boolean; where: string }> {
  if (POLICY_RE.test(homeHtml)) return { found: true, where: 'ana sayfa' };
  for (const p of ['/gizlilik', '/gizlilik-politikasi', '/kvkk', '/aydinlatma-metni', '/privacy']) {
    const r = await fetchPageText(`https://${host}${p}`);
    if (r.ok && POLICY_RE.test(r.html)) return { found: true, where: p };
  }
  return { found: false, where: '' };
}

async function collectKvkkSignals(host: string, http: { html: string; setCookies: string[] }): Promise<KvkkSignals> {
  const html = http.html;
  const policy = await hasPolicyPage(host, html);
  const cookieBanner = /(cookieconsent|cookie-consent|cookie-banner|çerez.{0,20}(kabul|onay|tercih)|kabul et.{0,10}çerez|accept.{0,6}cookies|onetrust|cookiebot|iubenda)/i.test(html);
  const trackers: string[] = [];
  if (/googletagmanager|GTM-[A-Z0-9]+/i.test(html)) trackers.push('Google Tag Manager');
  if (/google-analytics|gtag\/js|\bG-[A-Z0-9]{6,}\b/.test(html)) trackers.push('Google Analytics');
  if (/connect\.facebook\.net|fbq\(/i.test(html)) trackers.push('Facebook Pixel');
  if (/clarity\.ms/i.test(html)) trackers.push('Microsoft Clarity');
  if (/hotjar|hj\(/i.test(html)) trackers.push('Hotjar');
  const preConsentCookies = http.setCookies.length;

  let contactFound = CONTACT_RE.test(html);
  let contactWhere = contactFound ? 'ana sayfa' : '';
  if (!contactFound) {
    for (const p of ['/iletisim', '/hakkimizda', '/kvkk', '/contact']) {
      const r = await fetchPageText(`https://${host}${p}`);
      if (r.ok && CONTACT_RE.test(r.html)) { contactFound = true; contactWhere = p; break; }
    }
  }
  return { policyFound: policy.found, policyWhere: policy.where, cookieBanner, trackers, preConsentCookies, contactFound, contactWhere };
}

type Cookie = { name: string; secure: boolean; httpOnly: boolean };
function parseCookie(raw: string): Cookie {
  return { name: raw.split('=')[0]?.trim() || '(çerez)', secure: /;\s*secure/i.test(raw), httpOnly: /;\s*httponly/i.test(raw) };
}

// ======================================================================================
// FIX URETICILERI (koda gomulu, temkinli; PCI/ISO ortak + KVKK ozel)
// ======================================================================================
function buildComplianceFix(host: string, framework: string, o: { tlsBad: boolean; missingHdrs: string[]; insecureCookies: boolean; versionBanner: boolean; exposed: string[]; weak: string[]; policyMissing?: boolean }): string {
  const HNAME: Record<string, string> = {
    'strict-transport-security': 'Strict-Transport-Security', 'content-security-policy': 'Content-Security-Policy',
    'x-frame-options': 'X-Frame-Options', 'x-content-type-options': 'X-Content-Type-Options',
  };
  const HVAL: Record<string, string> = {
    'strict-transport-security': 'max-age=31536000; includeSubDomains', 'content-security-policy': "default-src 'self'; frame-ancestors 'self'",
    'x-frame-options': 'SAMEORIGIN', 'x-content-type-options': 'nosniff',
  };
  const parts: string[] = [`Aşağıdaki adımlar ${host} için ${framework} ile ilişkili, dışarıdan gözlemlenen eksiklikleri gidermeye yöneliktir.`];
  if (o.tlsBad || o.weak.length) parts.push(`### Şifreleme (TLS)\n\nYalnızca TLS 1.2+ kabul edin${o.weak.length ? ` (gözlemlenen zayıf sürüm: ${o.weak.join(', ')})` : ''}; sertifikayı geçerli/otomatik-yenilenir (certbot/ACME) tutun.\n\n\`\`\`nginx\nssl_protocols TLSv1.2 TLSv1.3;\nssl_prefer_server_ciphers on;\n\`\`\``);
  if (o.missingHdrs.length) parts.push(`### Güvenlik başlıkları\n\nSunucu yanıtına ekleyin:\n\n\`\`\`nginx\n${o.missingHdrs.map((h) => `add_header ${HNAME[h]} "${HVAL[h]}" always;`).join('\n')}\n\`\`\``);
  if (o.insecureCookies) parts.push('### Çerez bayrakları\n\nOturum çerezlerine `Secure; HttpOnly; SameSite=Lax` ekleyin (çapraz-site gerekiyorsa `SameSite=None; Secure`).');
  if (o.versionBanner) parts.push('### Sürüm ifşasını kapatın\n\nSunucu/teknoloji sürümünü gizleyin (Nginx: `server_tokens off;`; uygulama başlıklarından `X-Powered-By` kaldırın).');
  if (o.exposed.length) parts.push(`### Açıkta kalan dosyalar\n\nErişimi engelleyin: ${o.exposed.map((p) => `\`${p}\``).join(', ')}.\n\n\`\`\`nginx\nlocation ~ /\\.(git|env|ht) { deny all; return 404; }\n\`\`\``);
  if (o.policyMissing) parts.push('### Politika sayfası\n\nErişilebilir bir gizlilik/güvenlik politikası sayfası yayınlayın (A.5.1).');
  if (parts.length === 1) parts.push(`Dışarıdan gözlemlenen belirgin bir ${framework} eksikliği bulunmadı; mevcut yapılandırmayı sürdürün.`);
  return parts.join('\n\n');
}

function buildKvkkFix(host: string, o: { policyMissing: boolean; bannerMissing: boolean; trackingNoConsent: boolean; contactMissing: boolean; preConsentCookies: number }): string {
  const parts: string[] = [`Aşağıdaki adımlar ${host} için dışarıdan gözlemlenen KVKK hazırlık eksiklerini gidermeye yöneliktir (resmî uyum beyanı değildir).`];
  if (o.policyMissing) parts.push('### Aydınlatma metni / Gizlilik politikası\n\nKVKK m.10 kapsamında; hangi kişisel verilerin, hangi amaçla, hangi hukuki sebeple işlendiğini ve VERBIS/veri sorumlusu bilgisini içeren erişilebilir bir metin yayınlayın (footer’dan linkleyin).');
  if (o.bannerMissing || o.trackingNoConsent || o.preConsentCookies > 0) parts.push('### Çerez açık rızası\n\nİzleyici/analitik çerezleri **rıza alınmadan ÖNCE bırakmayın**. Kategorili (zorunlu/analitik/pazarlama) bir çerez rıza banner’ı ekleyin; yalnızca onaylanan kategoriler yüklensin (ör. Cookiebot/OneTrust/iubenda veya açık kaynak bir çözüm).');
  if (o.contactMissing) parts.push('### Veri sorumlusu / iletişim\n\nVeri sorumlusu kimliğini, iletişim bilgisini ve (varsa) VERBIS kaydını sitede erişilebilir kılın (ör. /iletisim veya aydınlatma metni içinde).');
  parts.push('### Not\n\nBu öneriler dışarıdan gözlemlenebilir teknik göstergelere dayanır; tam uyum için veri envanteri, saklama/imha politikası ve gerekli sözleşmeler dâhil kapsamlı bir hukuki değerlendirme gereklidir.');
  return parts.join('\n\n');
}

// ======================================================================================
// BUNDLE: Uyum Paketi — KVKK + PCI + ISO'yu TEK raporda birlestir (worst-case)
// ======================================================================================
const COMPLIANCE_AREAS: Array<{ title: string; gen: (h: string) => Promise<{ findings: string; fixText: string } | null> }> = [
  { title: 'KVKK Ön Uyum Kontrolü', gen: generateKvkkReport },
  { title: 'PCI-DSS Hazırlık Ön-Değerlendirmesi', gen: generatePciReport },
  { title: 'ISO 27001 Hazırlık Kontrol Listesi', gen: generateIso27001Report },
];

export function combineComplianceAreas(results: Array<{ findings: string; fixText: string } | null>): { findings: string; fixText: string } | null {
  if (results.every((r) => r === null)) return null;
  const levels = results.map((r) => (r ? extractLevel(r.findings) : null));
  const ranked = levels.map((lv, i) => ({ lv, i })).filter((x): x is { lv: Level; i: number } => x.lv !== null).sort((a, b) => levelRank(b.lv) - levelRank(a.lv));
  const worstIdx = ranked.length ? ranked[0].i : -1;
  const worst: Level = worstIdx >= 0 ? (levels[worstIdx] as Level) : 'low';
  const worstTitle = worstIdx >= 0 ? COMPLIANCE_AREAS[worstIdx].title : '';
  const worstHl = worstIdx >= 0 && results[worstIdx] ? areaHeadline(results[worstIdx]!.findings) : '';

  const summary: string[] = [];
  summary.push(
    worst === 'low'
      ? `- **Genel risk seviyesi: Düşük** — uyum hazırlığınız 3 çerçevede (KVKK/PCI-DSS/ISO 27001) dışarıdan incelendi; belirgin bir eksik öne çıkmadı.`
      : `- **Genel risk seviyesi: ${RISK_WORD[worst]}** — 3 çerçeve incelendi; en yüksek hazırlık eksiği **${worstTitle}** alanında${worstHl ? ` (${worstHl})` : ''}.`,
  );
  COMPLIANCE_AREAS.forEach((a, i) => {
    const r = results[i]; const lv = levels[i];
    if (!r || !lv) { summary.push(`- **${a.title}:** veri toplanamadı.`); return; }
    summary.push(`- **${a.title}:** ${RISK_WORD[lv]}`);
  });
  summary.push('- **Önerilen ilk adım:** En yüksek eksikli çerçeveden başlayın; hazır adımlar "AI Çözüm Önerileri" bölümünde. Bu rapor resmî bir uyum/sertifikasyon beyanı değildir.');

  const genelSentence =
    (worst === 'high'
      ? `En yüksek hazırlık eksiği **${worstTitle}** alanında${worstHl ? ` (${worstHl})` : ''}; öncelikli ele alınması önerilir.`
      : worst === 'medium'
        ? `Öne çıkan alan **${worstTitle}**; kısa vadede giderilmesi önerilir.`
        : 'Üç çerçevede de dışarıdan gözlemlenebilir belirgin bir eksik öne çıkmadı.') +
    ' Bu rapor dışarıdan gözlemlenebilir göstergeleri ilgili ilke/madde ile eşler; **resmî bir uyum denetimi/sertifikasyon beyanı DEĞİLDİR.** Aşağıda her çerçeve ayrı ayrı raporlanmıştır.';

  const areaSections = COMPLIANCE_AREAS.map((a, i) => {
    const r = results[i];
    if (!r) return `## ${a.title}\n\n> Bu çerçeve için veri toplanamadı; diğerleri tam raporlanmıştır.\n`;
    return `## ${a.title}\n\n${detailOnly(r.findings)}\n`;
  }).join('\n');

  const findings =
    `## YÖNETİCİ ÖZETİ\n\n${summary.join('\n')}\n\n` +
    `## GENEL DEĞERLENDİRME\n\n**Risk Seviyesi: ${RISK_WORD[worst]}**\n\n${genelSentence}\n\n` +
    `${areaSections}`;

  const fixParts = COMPLIANCE_AREAS.map((a, i) => {
    const r = results[i];
    if (!r || !r.fixText.trim()) return '';
    return `### ${a.title}\n\n${r.fixText.trim()}`;
  }).filter(Boolean);
  const fixText = 'Bu bölüm, uyum ön-değerlendirmenizde dışarıdan gözlemlenen eksikler için çerçeve çerçeve düzeltme adımları içerir (resmî uyum beyanı değildir).\n\n' + fixParts.join('\n\n');

  return { findings, fixText };
}

export async function generateBundleComplianceReport(host: string): Promise<{ findings: string; fixText: string } | null> {
  const results = await Promise.all(COMPLIANCE_AREAS.map((a) => a.gen(host).catch(() => null)));
  return combineComplianceAreas(results);
}
