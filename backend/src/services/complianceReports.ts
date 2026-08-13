/**
 * (Uyum Paketi / bundle_compliance) DETERMINISTIK RAPOR — KVKK Ön Uyum + PCI-DSS Hazırlık +
 * ISO 27001 Hazırlık. Veri KODDAN toplanır (ajan/PentAGI YOK). Kanıt TEK SEFER toplanır
 * (collectComplianceEvidence) ve 3 çerçeve saf builder'a beslenir → verimli + derin.
 *
 * ÖNEMLİ (KVKK/uyum dili): Bu bir RESMİ uyum/sertifikasyon beyanı DEĞİLDİR. "uyumlu/uyumsuz"
 * gibi kesin hukuki hüküm KURULMAZ; yalnızca "dışarıdan gözlemlenebilir" teknik gösterge
 * var/yok olarak raporlanır (Gözlemlendi / Gözlemlenmedi / İnceleme gerekli).
 */
import { collectHttp, collectTls, collectExposedFiles, resolveOrigin, cachedOriginUrl, type HttpEvidence, type TlsEvidence, type ExposedFileResult } from './surfaceEvidence.js';
import { unscannableReport } from './unscannable.js';

type Level = 'low' | 'medium' | 'high';
const RISK_WORD = { low: 'Düşük', medium: 'Orta', high: 'Yüksek' } as const;
function levelRank(l: Level): number { return l === 'high' ? 2 : l === 'medium' ? 1 : 0; }

function assemble(level: Level, summaryBullets: string[], genelSentence: string, sections: string): string {
  return (
    `## YÖNETİCİ ÖZETİ\n\n${summaryBullets.join('\n')}\n\n` +
    `## GENEL DEĞERLENDİRME\n\n**Risk Seviyesi: ${RISK_WORD[level]}**\n\n${genelSentence}\n\n${sections}`
  );
}
function extractLevel(findings: string): Level | null {
  const m = findings.match(/Risk Seviyesi:\s*(Y[uü]ksek|Orta|D[uü][sş][uü]k)/i);
  if (!m) return null;
  const w = m[1].toLocaleLowerCase('tr');
  return /y[uü]ksek/.test(w) ? 'high' : /orta/.test(w) ? 'medium' : 'low';
}
function areaHeadline(findings: string): string {
  const m = findings.match(/^-\s*\*\*Genel risk seviyesi:[^\n]+?\*\*\s*[—–-]\s*([^\n]+)/mi);
  return m ? m[1].trim().replace(/\*\*/g, '') : '';
}
function detailOnly(findings: string): string {
  const parts = findings.split(/(?=^## )/m);
  return parts.slice(2).join('').replace(/^## /gm, '### ').trim();
}
const CAUTION = '> Bu bölüm dışarıdan gözlemlenebilir teknik göstergeleri ilgili ilke/madde ile eşler; **resmî bir uyum/uygunluk denetimi veya sertifikasyon beyanı DEĞİLDİR.** Kesin uygunluk için kapsamlı, ayrı bir denetim gerekir.';

type Priority = { sev: Level; text: string; horizon: 'quick' | 'medium'; impact?: string };
type Area = { findings: string; fixText: string; priorities: Priority[] };
// Guvenlik basliklari mini-gozlem tablosu (6 baslik) — PCI/ISO derinlik icin.
function headerMiniTable(headers: Map<string, string>): string {
  const rows = SEC_HDRS.map((h) => {
    const v = headers.get(h.h);
    return `| ${h.n} | ${v ? 'Var' : 'Yok'} | ${v ? v.slice(0, 60) : '—'} |`;
  }).join('\n');
  return `| Başlık | Durum | Değer/Not |\n|--------|-------|-----------|\n${rows}`;
}
const SCOPE = {
  kvkk: '> **Kapsam:** Yalnızca dışarıdan gözlemlenebilir göstergeler (sayfa/çerez/izleyici/form) değerlendirildi; veri envanteri, saklama-imha politikası, açık rıza metinlerinin içeriği ve veri işleme sözleşmeleri iç değerlendirme gerektirir.',
  pci: '> **Kapsam:** Dış yüzey (TLS, güvenlik başlıkları, çerez, sürüm ifşası, açıkta dosya, test izleri) değerlendirildi; iç ağ/CDE, ağ segmentasyonu, loglama-izleme (Req 10) ve resmî ASV taraması bu ön-değerlendirmenin dışındadır.',
  iso: '> **Kapsam:** Dışarıdan gözlemlenebilir teknik kontroller değerlendirildi; ISMS kapsamı, politika-prosedür dokümantasyonu, erişim yönetimi ve iç süreçler ayrı bir uygunluk denetimi gerektirir.',
};

// ======================================================================================
// TEK-SEFER KANIT TOPLAMA (tüm çerçeveler için paylaşılan; pasif, salt-okuma)
// ======================================================================================
type Form = { insecureAction: boolean; hasPassword: boolean; hasEmail: boolean; passwordAutocompleteRisk: boolean };
type ComplianceEvidence = {
  http: HttpEvidence;
  tls: TlsEvidence;
  exposed: ExposedFileResult[];
  // KVKK sinyalleri
  policyFound: boolean; policyWhere: string;
  cookieBanner: boolean;
  trackers: string[];
  preConsentCookies: number;
  contactFound: boolean; contactWhere: string;
  // ortak derived
  forms: Form[];
  thirdPartyDomains: string[];
  versionDisclosure: string[];
  stagingTraces: string[];
  infoLeak: string[];
  securityTxt: boolean;
  httpsRedirect: 'yes' | 'no' | 'unknown';
  httpOnly: boolean; // HTTPS(443) yok -> şifresiz iletişim (KVKK m.12 / PCI Req 4 / ISO A.8.24 eksiği)
};

async function fetchPageText(url: string, redirect: RequestRedirect = 'follow'): Promise<{ ok: boolean; status: number; html: string; location?: string }> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 8000);
  try {
    const res = await fetch(url, { signal: ctrl.signal, redirect, headers: { 'user-agent': 'CyberTestify-PassiveCheck/1.0' } });
    let html = '';
    try { const b = Buffer.from(await res.arrayBuffer()); html = (b.length > 400000 ? b.subarray(0, 400000) : b).toString('utf-8'); } catch { /* */ }
    return { ok: res.ok, status: res.status, html, location: res.headers.get('location') ?? undefined };
  } catch {
    return { ok: false, status: 0, html: '' };
  } finally {
    clearTimeout(timer);
  }
}

const POLICY_RE = /(gizlilik|ayd[ıi]nlatma|kvkk|çerez politikas|cookie policy|privacy policy)/i;
const CONTACT_RE = /(verbis|veri sorumlusu|mersis|[\w.-]+@[\w.-]+\.\w{2,})/i;
const TRACKER_DATA: Record<string, string> = {
  'Google Tag Manager': 'etiket/olay yönetimi — diğer izleyicileri tetikler',
  'Google Analytics': 'kullanım, cihaz, yaklaşık konum ve davranış verisi',
  'Facebook Pixel': 'dönüşüm ve kimlik eşleme (Meta hesabıyla ilişkilendirme)',
  'Microsoft Clarity': 'oturum kaydı, tıklama/kaydırma ısı haritası',
  'Hotjar': 'oturum kaydı ve ısı haritası',
  'LinkedIn Insight': 'dönüşüm ve profil eşleme',
  'TikTok Pixel': 'dönüşüm ve kimlik eşleme',
};

function analyzeForms(html: string): Form[] {
  const forms: Form[] = [];
  const blocks = html.match(/<form\b[\s\S]{0,4000}?<\/form>/gi) ?? [];
  for (const f of blocks.slice(0, 8)) {
    const action = f.match(/action\s*=\s*["']([^"']*)["']/i)?.[1] ?? '';
    const hasPassword = /type\s*=\s*["']?password/i.test(f);
    const hasEmail = /type\s*=\s*["']?email/i.test(f) || /name\s*=\s*["'][^"']*e-?mail/i.test(f);
    // Sifre alani autocomplete="off"/"new-password"/"current-password" ile korunmamis mi?
    const pwAc = f.match(/<input[^>]*type\s*=\s*["']?password[^>]*>/i)?.[0] ?? '';
    const passwordAutocompleteRisk = hasPassword && !/autocomplete\s*=\s*["']?(off|new-password|current-password)/i.test(pwAc);
    forms.push({ insecureAction: /^http:\/\//i.test(action), hasPassword, hasEmail, passwordAutocompleteRisk });
  }
  return forms;
}
function thirdPartyDomains(html: string, host: string): string[] {
  const apex = host.split('.').slice(-2).join('.');
  const set = new Set<string>();
  for (const m of html.matchAll(/https?:\/\/([a-z0-9.-]+\.[a-z]{2,})/gi)) {
    const d = m[1].toLowerCase();
    if (!d.endsWith(apex)) set.add(d.replace(/^www\./, ''));
  }
  return Array.from(set).slice(0, 15);
}
function versionDisclosure(headers: Map<string, string>, html: string): string[] {
  const out: string[] = [];
  const server = headers.get('server') ?? '';
  if (/\d+\.\d+/.test(server)) out.push(`Server: ${server}`);
  const xpb = headers.get('x-powered-by');
  if (xpb) out.push(`X-Powered-By: ${xpb}`);
  const asp = headers.get('x-aspnet-version') || headers.get('x-aspnetmvc-version');
  if (asp) out.push(`ASP.NET: ${asp}`);
  const gen = html.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i)?.[1];
  if (gen) out.push(`Meta generator: ${gen}`);
  return out;
}
function stagingTraces(html: string, headers: Map<string, string>): string[] {
  const out: string[] = [];
  if (/sourceMappingURL/i.test(html)) out.push('Kaynak haritası (sourceMappingURL) referansı — üretimde kapatılması önerilir');
  if (/(staging|test|dev)\.[a-z0-9-]+\.[a-z]{2,}/i.test(html)) out.push('HTML içinde staging/test/dev alt alan adı referansı');
  if (/(Whoops,|Traceback \(most recent|Fatal error:|Warning: [a-z_]+\(\)|Exception in thread|stack trace)/i.test(html)) out.push('Ayrıntılı hata/istisna izi (debug modu açık olabilir)');
  if (headers.get('x-debug') || /debug\s*=\s*true/i.test(html)) out.push('Debug göstergesi (X-Debug / debug=true)');
  return out;
}
function infoLeakSigns(html: string, headers: Map<string, string>): string[] {
  const out: string[] = [];
  const emails = Array.from(new Set((html.match(/[\w.+-]+@[\w.-]+\.\w{2,}/g) ?? []).map((e) => e.toLowerCase()))).slice(0, 5);
  if (emails.length) out.push(`Sayfada açık e-posta adres(ler)i: ${emails.join(', ')}`);
  if (/\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/.test(html)) out.push('HTML içinde iç ağ (private) IP adresi referansı');
  if (/<!--[\s\S]{0,200}(TODO|FIXME|password|api[_-]?key|secret)[\s\S]{0,200}-->/i.test(html)) out.push('HTML yorumlarında hassas ifade (TODO/anahtar/parola) izi');
  return out;
}

async function hasPolicyPage(host: string, homeHtml: string): Promise<{ found: boolean; where: string }> {
  if (POLICY_RE.test(homeHtml)) return { found: true, where: 'ana sayfa (link/metin)' };
  for (const p of ['/gizlilik', '/gizlilik-politikasi', '/kvkk', '/aydinlatma-metni', '/privacy']) {
    const r = await fetchPageText(`${cachedOriginUrl(host)}${p}`);
    if (r.ok && r.status < 400 && POLICY_RE.test(r.html)) return { found: true, where: p };
  }
  return { found: false, where: '' };
}

export async function collectComplianceEvidence(host: string): Promise<ComplianceEvidence | null> {
  const o = await resolveOrigin(host); // cache'i ısıt -> alt fetch'ler http-only'de de çalışır
  const [http, tls] = await Promise.all([collectHttp(host), collectTls(host)]);
  if (!http.ok && !tls.found) return null;
  const html = http.html;
  const [exposed, policy, securityTxtRes, httpRes] = await Promise.all([
    collectExposedFiles(host, html),
    hasPolicyPage(host, html),
    fetchPageText(`${cachedOriginUrl(host)}/.well-known/security.txt`),
    fetchPageText(`http://${host}/`, 'manual'),
  ]);
  const httpOnly = o.reachable && !o.httpsWorks; // HTTPS(443) yok -> şifresiz iletişim (KVKK m.12 / PCI Req 4 eksiği)

  // KVKK: cerez banner / izleyiciler / iletisim
  const cookieBanner = /(cookieconsent|cookie-consent|cookie-banner|çerez.{0,25}(kabul|onay|tercih|ayar)|kabul et.{0,12}çerez|accept.{0,8}cookies|onetrust|cookiebot|iubenda|klaro|tarteaucitron)/i.test(html);
  const trackers: string[] = [];
  if (/googletagmanager|GTM-[A-Z0-9]+/i.test(html)) trackers.push('Google Tag Manager');
  if (/google-analytics|gtag\/js|\bG-[A-Z0-9]{6,}\b/.test(html)) trackers.push('Google Analytics');
  if (/connect\.facebook\.net|fbq\(/i.test(html)) trackers.push('Facebook Pixel');
  if (/clarity\.ms/i.test(html)) trackers.push('Microsoft Clarity');
  if (/static\.hotjar|hj\(/i.test(html)) trackers.push('Hotjar');
  if (/snap\.licdn\.com|_linkedin_partner_id/i.test(html)) trackers.push('LinkedIn Insight');
  if (/analytics\.tiktok|ttq\./i.test(html)) trackers.push('TikTok Pixel');

  let contactFound = CONTACT_RE.test(html);
  let contactWhere = contactFound ? 'ana sayfa' : '';
  if (!contactFound) {
    for (const p of ['/iletisim', '/hakkimizda', '/kvkk', '/contact']) {
      const r = await fetchPageText(`${cachedOriginUrl(host)}${p}`);
      if (r.ok && CONTACT_RE.test(r.html)) { contactFound = true; contactWhere = p; break; }
    }
  }

  const httpsRedirect: 'yes' | 'no' | 'unknown' = httpRes.status >= 300 && httpRes.status < 400 && /^https:/i.test(httpRes.location ?? '')
    ? 'yes' : httpRes.status === 200 ? 'no' : 'unknown';

  return {
    http, tls, exposed,
    policyFound: policy.found, policyWhere: policy.where,
    cookieBanner, trackers, preConsentCookies: http.setCookies.length, contactFound, contactWhere,
    forms: analyzeForms(html),
    thirdPartyDomains: thirdPartyDomains(html, host),
    versionDisclosure: versionDisclosure(http.headers, html),
    stagingTraces: stagingTraces(html, http.headers),
    infoLeak: infoLeakSigns(html, http.headers),
    securityTxt: securityTxtRes.ok && securityTxtRes.status < 400 && /contact:/i.test(securityTxtRes.html),
    httpsRedirect,
    httpOnly,
  };
}

// helpers for tables
function parseCookieFlags(raw: string): { name: string; secure: boolean; httpOnly: boolean } {
  return { name: raw.split('=')[0]?.trim() || '(çerez)', secure: /;\s*secure/i.test(raw), httpOnly: /;\s*httponly/i.test(raw) };
}
const SEC_HDRS: Array<{ h: string; n: string }> = [
  { h: 'strict-transport-security', n: 'HSTS' }, { h: 'content-security-policy', n: 'CSP' },
  { h: 'x-frame-options', n: 'X-Frame-Options' }, { h: 'x-content-type-options', n: 'X-Content-Type-Options' },
  { h: 'referrer-policy', n: 'Referrer-Policy' }, { h: 'permissions-policy', n: 'Permissions-Policy' },
];

// ======================================================================================
// KVKK Ön Uyum (temkinli dil)
// ======================================================================================
function buildKvkkArea(ev: ComplianceEvidence): Area {
  const trackingNoConsent = ev.trackers.length > 0 && !ev.cookieBanner;
  const dataForms = ev.forms.filter((f) => f.hasPassword || f.hasEmail);
  const gaps: string[] = [];
  if (!ev.policyFound) gaps.push('aydınlatma/gizlilik metni');
  if (!ev.cookieBanner) gaps.push('çerez rıza banner’ı');
  if (!ev.contactFound) gaps.push('veri sorumlusu/iletişim bilgisi');

  let level: Level = 'low';
  if (trackingNoConsent) level = 'high';
  else if (gaps.length >= 1 || ev.preConsentCookies > 0 || (dataForms.length > 0 && !ev.policyFound)) level = 'medium';

  const durum = (b: boolean) => (b ? 'Gözlemlendi' : 'Gözlemlenmedi');
  const rows = [
    `| Aydınlatma yükümlülüğü (m.10) | ${ev.policyFound ? `Gizlilik/aydınlatma metni erişilebilir (${ev.policyWhere})` : 'Kontrol edilen sayfalarda (ana sayfa + yaygın yollar) gözlemlenmedi'} | ${durum(ev.policyFound)} | Erişilebilir bir aydınlatma metni/gizlilik politikası yayınlayın |`,
    `| Açık rıza — çerezler (m.5) | ${ev.cookieBanner ? 'Çerez rıza banner’ı gözlemlendi' : 'Çerez rıza banner’ı gözlemlenmedi'}${ev.preConsentCookies > 0 ? `; ana sayfa yanıtında rızadan önce ${ev.preConsentCookies} çerez bırakılıyor` : ''} | ${ev.cookieBanner && ev.preConsentCookies === 0 ? 'Gözlemlendi' : 'İnceleme gerekli'} | Rıza öncesi izleyici çerez bırakmayın; açık rıza banner’ı ekleyin |`,
    `| Üçüncü taraf aktarım/izleyiciler (m.8-9) | ${ev.trackers.length ? 'Gözlemlenen: ' + ev.trackers.join(', ') : 'Ana sayfada belirgin izleyici gözlemlenmedi'} | ${ev.trackers.length ? (ev.cookieBanner ? 'Gözlemlendi (rıza mekanizması var)' : 'İnceleme gerekli') : 'Gözlemlenmedi'} | İzleyicileri açık rızaya bağlayın; aydınlatmada açıkça belirtin |`,
    `| Veri sorumlusu / VERBIS (m.16) | ${ev.contactFound ? `İletişim/veri sorumlusu bilgisi gözlemlendi (${ev.contactWhere})` : 'Kontrol edilen sayfalarda gözlemlenmedi'} | ${durum(ev.contactFound)} | Veri sorumlusu kimliği ve iletişim/VERBIS bilgisini yayınlayın |`,
    ev.httpOnly
      ? `| Veri güvenliği tedbirleri (m.12) | ⚠️ Site **HTTPS DESTEKLEMİYOR** — kişisel veri şifresiz (düz metin) taşınıyor, ağ üzerinde dinlenebilir/değiştirilebilir | Eksik | Geçerli TLS sertifikası kurup tüm trafiği HTTPS’e taşıyın (m.12 teknik tedbir) + HSTS ekleyin |`
      : `| Veri güvenliği tedbirleri (m.12) | Site HTTPS üzerinden sunuluyor${ev.http.headers.has('strict-transport-security') ? ' (HSTS mevcut)' : ''}${ev.httpsRedirect === 'yes' ? ', HTTP→HTTPS yönlendirmesi var' : ''} | Gözlemlendi | Taşıma güvenliğini (HTTPS/HSTS) sürdürün |`,
  ].join('\n');

  // İzleyici detayı (hangi veriyi toplayabilir)
  const trackerDetail = ev.trackers.length
    ? '## İZLEYİCİ DETAYI\n\n' + ev.trackers.map((t) => `- **${t}** — muhtemel toplanan veri: ${TRACKER_DATA[t] ?? 'kullanım/etkileşim verisi'}.`).join('\n') +
      `\n\n${trackingNoConsent ? '> Bu izleyiciler, gözlemlenebilir bir açık rıza mekanizması OLMADAN yükleniyor görünüyor; KVKK m.5 açısından açık rıza öncesi işleme dikkat gerektirir.' : '> İzleyiciler mevcut; rıza mekanizmasının bunları rıza sonrası tetiklediğini uygulama içinde doğrulayın.'}\n\n`
    : '';

  // Form gözlemi
  const formSection = ev.forms.length
    ? `## FORM GÖZLEMİ (kişisel veri toplama)\n\n- Ana sayfada ${ev.forms.length} form gözlemlendi; ${dataForms.length} tanesi kişisel veri (e-posta/parola) alanı içeriyor.\n` +
      `- Form gönderimi: ${ev.forms.some((f) => f.insecureAction) ? '⚠️ en az bir form HTTP (şifresiz) adrese gönderiyor' : 'gözlemlenen formlar güvenli (HTTPS/görece) adrese gönderiyor'}.\n` +
      `- Aydınlatma/rıza referansı: ${ev.policyFound ? 'sitede aydınlatma metni erişilebilir' : 'kişisel veri toplayan form(lar) varken aydınlatma metni gözlemlenmedi — form yanında açık rıza/aydınlatma bağlantısı önerilir'}.\n\n`
    : '## FORM GÖZLEMİ\n\n- Ana sayfada kişisel veri toplayan form gözlemlenmedi.\n\n';

  const bullets = [
    `- **Genel risk seviyesi: ${RISK_WORD[level]}** — ${level === 'high' ? 'rıza mekanizması gözlemlenmeden izleyici çerez/servis kullanımı dikkat çekiyor.' : level === 'medium' ? 'dışarıdan gözlemlenebilir bazı KVKK hazırlık eksikleri var.' : 'dışarıdan gözlemlenebilir belirgin bir KVKK hazırlık eksiği öne çıkmadı.'}`,
    `- Aydınlatma: ${ev.policyFound ? 'var' : 'gözlemlenmedi'} · Çerez rızası: ${ev.cookieBanner ? 'var' : 'gözlemlenmedi'} · İzleyici: ${ev.trackers.length || 'yok'} · İletişim/VERBIS: ${ev.contactFound ? 'var' : 'gözlemlenmedi'} · Veri formu: ${dataForms.length}.`,
    '- **Önerilen ilk adım:** ' + (trackingNoConsent ? 'Rıza öncesi izleyici çerezleri durdurun ve açık rıza banner’ı ekleyin.' : 'Eksik gözlemlenen kalemleri (aydınlatma/iletişim) tamamlayın.') + ' Hazır adımlar "AI Çözüm Önerileri" bölümünde.',
  ];
  const genel =
    (level === 'high'
      ? 'Açık rıza mekanizması gözlemlenmeden üçüncü taraf izleyici/çerez kullanımı gibi, dışarıdan gözlemlenebilir öncelikli hazırlık eksiği dikkat çekiyor.'
      : level === 'medium'
        ? 'Dışarıdan gözlemlenebilir bazı KVKK hazırlık eksikleri var; kısa vadede tamamlanması önerilir.'
        : 'Dışarıdan gözlemlenebilir belirgin bir KVKK hazırlık eksiği öne çıkmadı.') +
    ' Bu bir hukuki danışmanlık veya resmî KVKK uyum beyanı değildir; yalnızca dışarıdan gözlemlenebilir göstergeleri ilkelerle eşler.';

  const comment = trackingNoConsent
    ? `En dikkat çeken gözlem: üçüncü taraf izleyiciler (${ev.trackers.join(', ')}) açık rıza mekanizması görülmeden yükleniyor. Bu, KVKK m.5 (açık rıza) açısından uygulamada en sık idari yaptırıma konu olan eksikliklerden biridir. ${ev.policyFound ? 'Aydınlatma metni erişilebilir görünüyor' : 'Ayrıca erişilebilir bir aydınlatma metni gözlemlenmedi'}${ev.contactFound ? '' : '; veri sorumlusu/iletişim bilgisi de kontrol edilen sayfalarda bulunamadı'}.`
    : gaps.length
      ? `Dışarıdan gözlemlenebilir başlıca eksik(ler): ${gaps.join(', ')}. ${ev.trackers.length ? `İzleyiciler (${ev.trackers.join(', ')}) mevcut; bunların rıza SONRASI tetiklendiğini uygulama içinde doğrulayın.` : 'Belirgin bir izleyici gözlemlenmedi.'} Temel taşıma güvenliği (HTTPS${ev.http.headers.has('strict-transport-security') ? '/HSTS' : ''}) mevcut.`
      : `Dışarıdan gözlemlenebilir temel KVKK göstergeleri (aydınlatma, çerez rızası, iletişim) mevcut görünüyor. İçerik yeterliliği, veri envanteri ve saklama-imha politikası iç değerlendirme gerektirir.`;
  const findings = assemble(level, bullets, genel,
    `${CAUTION}\n\n## DEĞERLENDİRME (Ne gördük / Ne görmedik)\n\n${comment}\n\n## KVKK GÖZLEM TABLOSU\n\n| KVKK İlkesi/Konu | Gözlem | Durum | Öneri |\n|------------------|--------|-------|-------|\n${rows}\n\n${trackerDetail}${formSection}${SCOPE.kvkk}\n`);
  const fixText = buildKvkkFix(ev, { policyMissing: !ev.policyFound, bannerMissing: !ev.cookieBanner, trackingNoConsent, contactMissing: !ev.contactFound, preConsentCookies: ev.preConsentCookies });
  const priorities: Priority[] = [];
  if (trackingNoConsent) priorities.push({ sev: 'high', text: 'KVKK — Çerez açık rızası ekleyin ve rıza öncesi izleyici çerezleri durdurun.', horizon: 'medium', impact: 'En yüksek yasal risk — uygulamada en sık idari yaptırıma konu olan eksiklik' });
  if (!ev.policyFound) priorities.push({ sev: 'medium', text: 'KVKK — Erişilebilir aydınlatma metni / gizlilik politikası yayınlayın.', horizon: 'medium', impact: 'Şeffaflık yükümlülüğünü karşılar (m.10)' });
  if (!ev.contactFound) priorities.push({ sev: 'medium', text: 'KVKK — Veri sorumlusu ve iletişim bilgisini sitede erişilebilir kılın.', horizon: 'quick', impact: 'Düşük eforlu; VERBIS/şeffaflık için gerekli' });
  return { findings, fixText, priorities };
}

// ======================================================================================
// PCI-DSS Hazırlık
// ======================================================================================
function buildPciArea(ev: ComplianceEvidence): Area {
  const { tls, http } = ev;
  const exposedHits = ev.exposed.filter((e) => e.exposed);
  const missingHdrs = SEC_HDRS.slice(0, 4).filter((h) => !http.headers.has(h.h)); // HSTS/CSP/XFO/XCTO
  const cookies = http.setCookies.map(parseCookieFlags);
  const insecureCookies = cookies.filter((c) => !c.secure || !c.httpOnly);
  const versionBanner = ev.versionDisclosure.length > 0;
  const tlsBad = ev.httpOnly || tls.hostnameMatch === false || (tls.daysLeft != null && tls.daysLeft < 0) || tls.weakProtocols.length > 0;
  const pwAutocomplete = ev.forms.some((f) => f.passwordAutocompleteRisk);
  const insecureForm = ev.forms.some((f) => f.insecureAction);

  let level: Level = 'low';
  if (exposedHits.length || tlsBad || ev.stagingTraces.length) level = 'high';
  else if (missingHdrs.length >= 2 || insecureCookies.length || versionBanner || pwAutocomplete || insecureForm || ev.httpsRedirect === 'no') level = 'medium';

  const st = (bad: boolean, partial = false) => (bad ? 'Eksik' : partial ? 'Kısmi' : 'Mevcut');
  const rows = [
    ev.httpOnly
      ? `| Req 4.2.1 — Aktarımda güçlü şifreleme | ⚠️ Site **HTTPS DESTEKLEMİYOR** — kart/hassas veri şifresiz (düz metin) taşınıyor | Eksik | Geçerli TLS 1.2+ sertifikası kurup tüm trafiği HTTPS’e taşıyın |`
      : `| Req 4.2.1 — Aktarımda güçlü şifreleme | TLS ${tls.protocol ?? 'tespit edilemedi'}${tls.weakProtocols.length ? `, zayıf sürüm: ${tls.weakProtocols.join(', ')}` : ''}${tls.daysLeft != null ? `, sertifika ${tls.daysLeft >= 0 ? tls.daysLeft + ' gün' : 'SÜRESİ DOLMUŞ'}` : ''} | ${st(tlsBad)} | TLS 1.2+ zorunlu; sertifikayı geçerli tutun |`,
    `| Req 4.1 — HTTPS zorunluluğu | HSTS: ${http.headers.has('strict-transport-security') ? 'var' : 'yok'}; HTTP→HTTPS yönlendirme: ${ev.httpsRedirect === 'yes' ? 'var' : ev.httpsRedirect === 'no' ? '⚠️ yok (HTTP 200 dönüyor)' : 'belirlenemedi'} | ${st(!http.headers.has('strict-transport-security') || ev.httpsRedirect === 'no')} | HSTS ekleyin + tüm HTTP’yi HTTPS’e yönlendirin |`,
    `| Req 6.4 — Güvenlik başlıkları | ${missingHdrs.length ? 'Eksik: ' + missingHdrs.map((h) => h.n).join(', ') : 'HSTS/CSP/X-Frame/X-Content-Type mevcut'} | ${st(missingHdrs.length >= 2, missingHdrs.length === 1)} | Eksik güvenlik başlıklarını ekleyin |`,
    `| Req 8 — Oturum/çerez + otomatik doldurma | ${cookies.length ? `${insecureCookies.length}/${cookies.length} çerezde Secure/HttpOnly eksik` : 'Ana sayfada Set-Cookie gözlemlenmedi'}${pwAutocomplete ? '; parola alanında autocomplete kapatılmamış' : ''} | ${st(insecureCookies.length > 0 || pwAutocomplete)} | Çerez bayrakları + parola alanında autocomplete="off" |`,
    `| Req 2.2 — Güvenli yapılandırma (sürüm ifşası) | ${ev.versionDisclosure.length ? ev.versionDisclosure.join('; ') : 'Belirgin sürüm ifşası gözlemlenmedi'} | ${st(versionBanner)} | Sürüm/teknoloji banner’larını gizleyin |`,
    `| Req 6.5 — Test/staging izleri | ${ev.stagingTraces.length ? '⚠️ ' + ev.stagingTraces.join('; ') : 'Belirgin test/staging/debug izi gözlemlenmedi'} | ${st(ev.stagingTraces.length > 0)} | Debug/kaynak-haritası/test izlerini üretimden kaldırın |`,
    `| Req 3 — Veri ifşası (açıkta dosya) | ${exposedHits.length ? '⚠️ Açık: ' + exposedHits.map((e) => e.path).join(', ') : 'Yaygın hassas yollar erişilebilir değil'} | ${st(exposedHits.length > 0)} | Açıkta kalan dosyalara erişimi engelleyin |`,
  ].join('\n');

  const bullets = [
    `- **Genel risk seviyesi: ${RISK_WORD[level]}** — ${level === 'high' ? 'PCI-DSS açısından öncelikli, dışarıdan gözlemlenebilir eksiklik(ler) var.' : level === 'medium' ? 'kısa vadede giderilmesi önerilen gözlemlenebilir eksikler var.' : 'dışarıdan gözlemlenebilir belirgin bir eksiklik öne çıkmadı.'}`,
    `- TLS: ${tlsBad ? '⚠️ sorun' : 'sağlam'} · HSTS/redirect: ${http.headers.has('strict-transport-security') && ev.httpsRedirect !== 'no' ? 'ok' : '⚠️'} · Başlık: ${missingHdrs.length} eksik · Çerez: ${insecureCookies.length} · Sürüm ifşası: ${ev.versionDisclosure.length} · Test izi: ${ev.stagingTraces.length} · Açıkta dosya: ${exposedHits.length}.`,
    '- **Önerilen ilk adım:** En yüksek etkili eksikten (açıkta dosya / zayıf TLS / test izi) başlayın; hazır düzeltmeler "AI Çözüm Önerileri" bölümünde.',
  ];
  const genel =
    (level === 'high'
      ? 'Dışarıdan gözlemlenebilir, PCI-DSS ile ilişkili öncelikli eksiklik(ler) tespit edildi (örn. açıkta dosya, zayıf TLS veya test/staging izi).'
      : level === 'medium'
        ? 'Dışarıdan gözlemlenebilir, kısa vadede giderilmesi önerilen PCI-DSS ilişkili eksikler var.'
        : 'Dışarıdan gözlemlenebilir belirgin bir PCI-DSS ilişkili eksiklik öne çıkmadı.') +
    ' Bu bir resmî ASV/QSA testi veya uygunluk beyanı değildir; iç ağ/CDE, segmentasyon ve sızma testi kapsam dışıdır.';

  const topPci = exposedHits.length ? 'dışarıdan erişilebilir hassas dosya' : tlsBad ? 'zayıf TLS/sertifika duruşu' : ev.stagingTraces.length ? 'üretimde test/staging/debug izi' : missingHdrs.length >= 2 ? 'eksik tarayıcı güvenlik başlıkları' : '';
  const comment = topPci
    ? `Kart verisi işleyen bir ortamda en dikkat çeken dış gözlem: **${topPci}**. ${exposedHits.length || tlsBad || ev.stagingTraces.length ? 'Bu tür bulgular PCI-DSS ön-değerlendirmesinde öncelikli kabul edilir.' : 'Güvenlik başlıkları, tarayıcı seviyesindeki savunmayı doğrudan etkiler (Req 6.4).'} Aktarım güvenliği ${tls.protocol ?? 'tespit edilemedi'}${tls.daysLeft != null ? `, sertifika ${tls.daysLeft >= 0 ? tls.daysLeft + ' gün geçerli' : 'süresi dolmuş'}` : ''}; HTTPS zorunluluğu HSTS ${http.headers.has('strict-transport-security') ? 'ile bildiriliyor' : 'ile bildirilmiyor'}${ev.httpsRedirect === 'no' ? ' ve HTTP→HTTPS yönlendirmesi gözlemlenmedi' : ''}.`
    : `Dışarıdan gözlemlenebilir dış yüzey (TLS, başlıklar, çerez, sürüm ifşası, açık dosya, test izleri) belirgin bir PCI-DSS ilişkili eksik göstermedi. İç ağ/CDE, ağ segmentasyonu ve loglama (Req 10) bu ön-değerlendirmenin dışındadır ve ayrı bir ASV/QSA süreci gerektirir.`;
  const findings = assemble(level, bullets, genel,
    `${CAUTION}\n\n## DEĞERLENDİRME (Ne gördük / Ne görmedik)\n\n${comment}\n\n## PCI-DSS GÖZLEM TABLOSU\n\n| Gereksinim | Gözlem | Gözlemlenebilir kontrol | Öneri |\n|-----------|--------|------------------------|-------|\n${rows}\n\n## GÜVENLİK BAŞLIKLARI DETAYI (Req 6.4)\n\n${headerMiniTable(http.headers)}\n\n${SCOPE.pci}\n`);
  const fixText = buildComplianceFix(ev, 'PCI-DSS', { tlsBad, missingHdrs: missingHdrs.map((h) => h.h), insecureCookies: insecureCookies.length > 0, versionBanner, exposed: exposedHits.map((e) => e.path), extra: [...(ev.httpsRedirect === 'no' ? ['HTTP→HTTPS yönlendirmesi ekleyin (tüm trafiği HTTPS’e zorlayın).'] : []), ...(pwAutocomplete ? ['Parola/hassas form alanlarına `autocomplete="off"` (veya `new-password`) ekleyin.'] : []), ...(ev.stagingTraces.length ? ['Debug modunu kapatın; kaynak haritalarını (sourceMappingURL) ve test/staging izlerini üretimden kaldırın.'] : [])] });
  const priorities: Priority[] = [];
  if (exposedHits.length) priorities.push({ sev: 'high', text: `PCI-DSS (Req 3) — Açıkta kalan dosyalara erişimi engelleyin: ${exposedHits.map((e) => e.path).join(', ')}.`, horizon: 'quick', impact: 'Doğrudan veri ifşası riski' });
  if (tlsBad) priorities.push({ sev: 'high', text: 'PCI-DSS (Req 4) — TLS’i güçlendirin (zayıf sürüm/sertifika sorununu giderin).', horizon: 'quick', impact: 'Aktarımda kart verisi güvenliği için kritik' });
  if (ev.stagingTraces.length) priorities.push({ sev: 'high', text: 'PCI-DSS (Req 6) — Test/staging/debug izlerini üretimden kaldırın.', horizon: 'quick', impact: 'Saldırı yüzeyini ve bilgi ifşasını azaltır' });
  if (missingHdrs.length >= 2) priorities.push({ sev: 'medium', text: 'PCI-DSS (Req 6.4) — Eksik güvenlik başlıklarını ekleyin.', horizon: 'quick', impact: 'XSS/clickjacking yüzeyini kapatır' });
  if (ev.httpsRedirect === 'no') priorities.push({ sev: 'medium', text: 'PCI-DSS (Req 4.1) — Tüm HTTP trafiğini HTTPS’e yönlendirin + HSTS.', horizon: 'quick', impact: 'Şifresiz erişimi engeller' });
  if (pwAutocomplete) priorities.push({ sev: 'medium', text: 'PCI-DSS (Req 8) — Parola/hassas form alanlarında autocomplete’i kapatın.', horizon: 'quick', impact: 'Paylaşımlı cihazda kimlik sızıntısını azaltır' });
  return { findings, fixText, priorities };
}

// ======================================================================================
// ISO 27001 Annex A Hazırlık
// ======================================================================================
function buildIsoArea(ev: ComplianceEvidence): Area {
  const { tls, http } = ev;
  const exposedHits = ev.exposed.filter((e) => e.exposed);
  const missingHdrs = SEC_HDRS.slice(0, 4).filter((h) => !http.headers.has(h.h));
  const versionBanner = ev.versionDisclosure.length > 0;
  const tlsBad = ev.httpOnly || tls.hostnameMatch === false || (tls.daysLeft != null && tls.daysLeft < 0) || tls.weakProtocols.length > 0;

  let level: Level = 'low';
  if (exposedHits.length || tlsBad || ev.infoLeak.length >= 2) level = 'high';
  else if (missingHdrs.length >= 2 || versionBanner || !ev.policyFound || ev.infoLeak.length || !ev.securityTxt) level = 'medium';

  const st = (bad: boolean, partial = false) => (bad ? 'Eksik' : partial ? 'Kısmi' : 'Mevcut');
  const rows = [
    `| A.8.24 — Kriptografi | TLS ${tls.protocol ?? 'tespit edilemedi'}${tls.weakProtocols.length ? `, zayıf: ${tls.weakProtocols.join(', ')}` : ''} | ${st(tlsBad)} | TLS 1.2+ ve geçerli sertifika sürdürün |`,
    `| A.8.23/A.8.9 — Güvenlik başlıkları | ${missingHdrs.length ? 'Eksik: ' + missingHdrs.map((h) => h.n).join(', ') : 'Temel başlıklar mevcut'} | ${st(missingHdrs.length >= 2, missingHdrs.length === 1)} | Eksik başlıkları ekleyin |`,
    `| A.8.9 — Güvenli yapılandırma (sürüm ifşası) | ${ev.versionDisclosure.length ? ev.versionDisclosure.join('; ') : 'banner gözlemlenmedi'} | ${st(versionBanner)} | Sürüm bilgisini gizleyin |`,
    `| A.8.12 — Veri sızıntısı | ${exposedHits.length ? '⚠️ Açıkta dosya: ' + exposedHits.map((e) => e.path).join(', ') : ev.infoLeak.length ? '⚠️ ' + ev.infoLeak.join('; ') : 'Belirgin sızıntı göstergesi gözlemlenmedi'} | ${st(exposedHits.length > 0 || ev.infoLeak.length > 0)} | Açık dosya/bilgi sızıntısı göstergelerini giderin |`,
    `| A.5.1 — Politikalar | ${ev.policyFound ? `Politika sayfası erişilebilir (${ev.policyWhere})` : 'Gizlilik/güvenlik politikası sayfası gözlemlenmedi'} | ${st(!ev.policyFound)} | Erişilebilir bir politika sayfası yayınlayın |`,
    `| A.5.7/A.6 — Zafiyet bildirim kanalı | security.txt: ${ev.securityTxt ? 'mevcut' : 'gözlemlenmedi'} | ${st(!ev.securityTxt)} | /.well-known/security.txt ile bildirim kanalı tanımlayın |`,
    `| A.15 — Üçüncü taraf bağımlılıkları | ${ev.thirdPartyDomains.length ? `${ev.thirdPartyDomains.length} dış alan adı gözlemlendi` : 'Belirgin dış bağımlılık gözlemlenmedi'} | Bilgilendirme | Dış bağımlılıkları envanterleyin/değerlendirin |`,
  ].join('\n');

  const leakSection = ev.infoLeak.length ? '## BİLGİ SIZINTISI GÖSTERGELERİ\n\n' + ev.infoLeak.map((x) => `- ⚠️ ${x}`).join('\n') + '\n\n' : '';
  const tpSection = ev.thirdPartyDomains.length
    ? '## ÜÇÜNCÜ TARAF BAĞIMLILIKLARI (görünür)\n\nSayfada yüklenen dış alan adları (tedarikçi/veri işleyen envanteri için):\n\n' + ev.thirdPartyDomains.map((d) => `- ${d}`).join('\n') + '\n\n> Her dış bağımlılık bir tedarik zinciri/veri işleyen riski taşır (A.15); envanterlenip değerlendirilmelidir.\n\n'
    : '';

  const bullets = [
    `- **Genel risk seviyesi: ${RISK_WORD[level]}** — ${level === 'high' ? 'Annex A açısından öncelikli, dışarıdan gözlemlenebilir eksiklik(ler) var.' : level === 'medium' ? 'kısa vadede giderilmesi önerilen gözlemlenebilir eksikler var.' : 'belirgin bir gözlemlenebilir eksiklik öne çıkmadı.'}`,
    `- TLS: ${tlsBad ? '⚠️' : 'ok'} · Başlık: ${missingHdrs.length} eksik · Sızıntı göstergesi: ${ev.infoLeak.length} · Politika: ${ev.policyFound ? 'var' : 'yok'} · security.txt: ${ev.securityTxt ? 'var' : 'yok'} · Dış bağımlılık: ${ev.thirdPartyDomains.length}.`,
    '- **Önerilen ilk adım:** En yüksek etkili eksikten başlayın; hazır düzeltmeler "AI Çözüm Önerileri" bölümünde.',
  ];
  const genel =
    (level === 'high'
      ? 'Dışarıdan gözlemlenebilir, ISO 27001 Annex A ile ilişkili öncelikli eksiklik(ler) tespit edildi.'
      : level === 'medium'
        ? 'Dışarıdan gözlemlenebilir, kısa vadede giderilmesi önerilen Annex A ilişkili eksikler var.'
        : 'Dışarıdan gözlemlenebilir belirgin bir Annex A ilişkili eksiklik öne çıkmadı.') +
    ' Bu bir ISO 27001 denetimi/sertifikasyonu değildir; ISMS kapsamı, dokümantasyon ve iç süreçler kapsam dışıdır.';

  const topIso = exposedHits.length ? 'veri sızıntısı (açıkta dosya)' : tlsBad ? 'kriptografi (TLS) duruşu' : ev.infoLeak.length ? 'bilgi sızıntısı göstergeleri' : !ev.policyFound ? 'erişilebilir politika sayfası eksikliği' : !ev.securityTxt ? 'zafiyet bildirim kanalı (security.txt) eksikliği' : '';
  const comment = topIso
    ? `Annex A açısından en dikkat çeken dış gözlem: **${topIso}**. Dışarıdan bakıldığında ${missingHdrs.length ? `${missingHdrs.length} temel güvenlik başlığı eksik (A.8.23)` : 'temel güvenlik başlıkları mevcut'}, TLS ${tls.protocol ?? 'tespit edilemedi'} (A.8.24)${ev.thirdPartyDomains.length ? ` ve ${ev.thirdPartyDomains.length} dış servis bağımlılığı (A.15)` : ''} gözlemlendi. Bunlar teknik kontrolün bir kısmıdır; ISMS kapsamı ve dokümantasyon iç denetim gerektirir.`
    : `Dışarıdan gözlemlenebilir teknik kontroller (TLS, başlıklar, sızıntı göstergeleri, politika görünürlüğü) belirgin bir Annex A eksiği göstermedi. ISMS kapsamı, politika-prosedür dokümantasyonu ve erişim yönetimi bu ön-değerlendirmenin dışındadır.`;
  const findings = assemble(level, bullets, genel,
    `${CAUTION}\n\n## DEĞERLENDİRME (Ne gördük / Ne görmedik)\n\n${comment}\n\n## ISO 27001 ANNEX A GÖZLEM TABLOSU\n\n| Madde | Gözlem | Gözlemlenebilir kontrol | Öneri |\n|-------|--------|------------------------|-------|\n${rows}\n\n${leakSection}${tpSection}${SCOPE.iso}\n`);
  const fixText = buildComplianceFix(ev, 'ISO 27001', { tlsBad, missingHdrs: missingHdrs.map((h) => h.h), insecureCookies: false, versionBanner, exposed: exposedHits.map((e) => e.path), policyMissing: !ev.policyFound, extra: [...(ev.securityTxt ? [] : ['`/.well-known/security.txt` ile bir zafiyet bildirim kanalı yayınlayın (A.5.7).']), ...(ev.thirdPartyDomains.length ? ['Görünen dış bağımlılıkları (üçüncü taraf servisler) envanterleyip veri-işleyen değerlendirmesine dâhil edin (A.15).'] : [])] });
  const priorities: Priority[] = [];
  if (exposedHits.length) priorities.push({ sev: 'high', text: 'ISO 27001 (A.8.12) — Açıkta kalan dosya/bilgi sızıntısını giderin.', horizon: 'quick', impact: 'Veri sızıntısını doğrudan durdurur' });
  if (tlsBad) priorities.push({ sev: 'high', text: 'ISO 27001 (A.8.24) — TLS yapılandırmasını güçlendirin.', horizon: 'quick', impact: 'Kriptografi kontrolü için temel' });
  if (ev.infoLeak.length >= 2) priorities.push({ sev: 'high', text: 'ISO 27001 (A.8.12) — Bilgi sızıntısı göstergelerini (IP/yorum/e-posta) giderin.', horizon: 'quick', impact: 'İç bilgi ifşasını azaltır' });
  if (!ev.securityTxt) priorities.push({ sev: 'medium', text: 'ISO 27001 (A.5.7) — /.well-known/security.txt ile zafiyet bildirim kanalı yayınlayın.', horizon: 'quick', impact: 'Hızlı ve düşük eforlu kazanım' });
  if (!ev.policyFound) priorities.push({ sev: 'medium', text: 'ISO 27001 (A.5.1) — Erişilebilir bir güvenlik/gizlilik politikası yayınlayın.', horizon: 'medium', impact: 'Politika kontrolü için görünür kanıt' });
  if (ev.thirdPartyDomains.length) priorities.push({ sev: 'medium', text: 'ISO 27001 (A.15) — Görünen üçüncü taraf bağımlılıklarını envanterleyip değerlendirin.', horizon: 'medium', impact: 'Tedarik zinciri riskini yönetir' });
  return { findings, fixText, priorities };
}

// ======================================================================================
// FIX URETICILERI
// ======================================================================================
const HNAME: Record<string, string> = { 'strict-transport-security': 'Strict-Transport-Security', 'content-security-policy': 'Content-Security-Policy', 'x-frame-options': 'X-Frame-Options', 'x-content-type-options': 'X-Content-Type-Options' };
const HVAL: Record<string, string> = { 'strict-transport-security': 'max-age=31536000; includeSubDomains', 'content-security-policy': "default-src 'self'; frame-ancestors 'self'", 'x-frame-options': 'SAMEORIGIN', 'x-content-type-options': 'nosniff' };

function buildComplianceFix(ev: ComplianceEvidence, framework: string, o: { tlsBad: boolean; missingHdrs: string[]; insecureCookies: boolean; versionBanner: boolean; exposed: string[]; policyMissing?: boolean; extra?: string[] }): string {
  const parts: string[] = [`Aşağıdaki adımlar ${ev.http.contentType ? '' : ''}${framework} ile ilişkili, dışarıdan gözlemlenen eksiklikleri gidermeye yöneliktir.`];
  if (o.tlsBad || ev.tls.weakProtocols.length) parts.push(`### Şifreleme (TLS)\n\nYalnızca TLS 1.2+ kabul edin${ev.tls.weakProtocols.length ? ` (gözlemlenen zayıf: ${ev.tls.weakProtocols.join(', ')})` : ''}; sertifikayı geçerli/otomatik-yenilenir (certbot/ACME) tutun.\n\n\`\`\`nginx\nssl_protocols TLSv1.2 TLSv1.3;\nssl_prefer_server_ciphers on;\n\`\`\``);
  if (o.missingHdrs.length) parts.push(`### Güvenlik başlıkları\n\n\`\`\`nginx\n${o.missingHdrs.map((h) => `add_header ${HNAME[h]} "${HVAL[h]}" always;`).join('\n')}\n\`\`\``);
  if (o.insecureCookies) parts.push('### Çerez bayrakları\n\nOturum çerezlerine `Secure; HttpOnly; SameSite=Lax` ekleyin.');
  if (o.versionBanner) parts.push('### Sürüm ifşasını kapatın\n\nNginx: `server_tokens off;`; uygulama yanıtlarından `X-Powered-By`/`X-AspNet-Version` başlıklarını kaldırın; `<meta generator>` etiketini gizleyin.');
  if (o.exposed.length) parts.push(`### Açıkta kalan dosyalar\n\nErişimi engelleyin: ${o.exposed.map((p) => `\`${p}\``).join(', ')}.\n\n\`\`\`nginx\nlocation ~ /\\.(git|env|ht) { deny all; return 404; }\n\`\`\``);
  if (o.policyMissing) parts.push('### Politika sayfası\n\nErişilebilir bir gizlilik/güvenlik politikası sayfası yayınlayın.');
  // (KESİK+TEKRAR GUARD) Eskiden her 'extra' için başlık = cümlenin ilk 60 karakteri (truncate) +
  // hemen altında TAM cümle basılıyordu -> aynı öneri kesik+tam iki kez görünüyordu. Artık tek
  // başlık altında, her öneri TEK ve TAM cümle olarak madde halinde.
  if (o.extra?.length) parts.push(`### Ek öneriler\n\n${o.extra.map((e) => `- ${e}`).join('\n')}`);
  if (parts.length === 1) parts.push(`Dışarıdan gözlemlenen belirgin bir ${framework} eksikliği bulunmadı; mevcut yapılandırmayı sürdürün.`);
  return parts.join('\n\n');
}

function buildKvkkFix(ev: ComplianceEvidence, o: { policyMissing: boolean; bannerMissing: boolean; trackingNoConsent: boolean; contactMissing: boolean; preConsentCookies: number }): string {
  const parts: string[] = [`Aşağıdaki adımlar dışarıdan gözlemlenen KVKK hazırlık eksiklerini gidermeye yöneliktir (resmî uyum beyanı değildir).`];
  if (o.policyMissing) parts.push('### Aydınlatma metni / Gizlilik politikası\n\nKVKK m.10 kapsamında; hangi kişisel verilerin, hangi amaçla ve hukuki sebeple işlendiğini + veri sorumlusu/VERBIS bilgisini içeren erişilebilir bir metin yayınlayın (footer’dan linkleyin).');
  if (o.bannerMissing || o.trackingNoConsent || o.preConsentCookies > 0) parts.push(`### Çerez açık rızası\n\nİzleyici/analitik çerezleri **rıza alınmadan ÖNCE bırakmayın**${ev.trackers.length ? ` (gözlemlenen izleyiciler: ${ev.trackers.join(', ')})` : ''}. Kategorili (zorunlu/analitik/pazarlama) bir çerez rıza banner’ı ekleyin; yalnızca onaylanan kategoriler yüklensin (Cookiebot/OneTrust/iubenda/Klaro vb.).`);
  if (o.contactMissing) parts.push('### Veri sorumlusu / iletişim\n\nVeri sorumlusu kimliğini, iletişim bilgisini ve (varsa) VERBIS kaydını sitede erişilebilir kılın.');
  parts.push('### Not\n\nBu öneriler dışarıdan gözlemlenebilir teknik göstergelere dayanır; tam uyum için veri envanteri, saklama/imha politikası ve gerekli sözleşmeler dâhil kapsamlı bir hukuki değerlendirme gereklidir.');
  return parts.join('\n\n');
}

// ======================================================================================
// BUNDLE birleştirme
// ======================================================================================
const AREA_TITLES = ['KVKK Ön Uyum Kontrolü', 'PCI-DSS Hazırlık Ön-Değerlendirmesi', 'ISO 27001 Hazırlık Kontrol Listesi'];

export function combineComplianceAreas(results: Array<{ findings: string; fixText: string } | null>, priorities: Priority[] = []): { findings: string; fixText: string } | null {
  if (results.every((r) => r === null)) return null;
  const levels = results.map((r) => (r ? extractLevel(r.findings) : null));
  const ranked = levels.map((lv, i) => ({ lv, i })).filter((x): x is { lv: Level; i: number } => x.lv !== null).sort((a, b) => levelRank(b.lv) - levelRank(a.lv));
  const worstIdx = ranked.length ? ranked[0].i : -1;
  const worst: Level = worstIdx >= 0 ? (levels[worstIdx] as Level) : 'low';
  const worstTitle = worstIdx >= 0 ? AREA_TITLES[worstIdx] : '';
  const worstHl = worstIdx >= 0 && results[worstIdx] ? areaHeadline(results[worstIdx]!.findings) : '';

  const summary: string[] = [];
  summary.push(
    worst === 'low'
      ? `- **Genel risk seviyesi: Düşük** — uyum hazırlığınız 3 çerçevede (KVKK/PCI-DSS/ISO 27001) dışarıdan incelendi; belirgin bir eksik öne çıkmadı.`
      : `- **Genel risk seviyesi: ${RISK_WORD[worst]}** — 3 çerçeve incelendi; en yüksek hazırlık eksiği **${worstTitle}** alanında${worstHl ? ` (${worstHl})` : ''}.`,
  );
  AREA_TITLES.forEach((t, i) => {
    const lv = levels[i];
    summary.push(results[i] && lv ? `- **${t}:** ${RISK_WORD[lv]}` : `- **${t}:** veri toplanamadı.`);
  });
  summary.push('- **Önerilen ilk adım:** En yüksek eksikli çerçeveden başlayın; hazır adımlar "AI Çözüm Önerileri" bölümünde. Bu rapor resmî bir uyum/sertifikasyon beyanı değildir.');

  const genelSentence =
    (worst === 'high'
      ? `En yüksek hazırlık eksiği **${worstTitle}** alanında${worstHl ? ` (${worstHl})` : ''}; öncelikli ele alınması önerilir.`
      : worst === 'medium'
        ? `Öne çıkan alan **${worstTitle}**; kısa vadede giderilmesi önerilir.`
        : 'Üç çerçevede de dışarıdan gözlemlenebilir belirgin bir eksik öne çıkmadı.') +
    ' Bu rapor dışarıdan gözlemlenebilir göstergeleri ilgili ilke/madde ile eşler; **resmî bir uyum denetimi/sertifikasyon beyanı DEĞİLDİR.** Aşağıda her çerçeve ayrı ayrı raporlanmıştır.';

  const areaSections = AREA_TITLES.map((t, i) => {
    const r = results[i];
    if (!r) return `## ${t}\n\n> Bu çerçeve için veri toplanamadı; diğerleri tam raporlanmıştır.\n`;
    return `## ${t}\n\n${detailOnly(r.findings)}\n`;
  }).join('\n');

  // ÖNCELİKLİ AKSİYONLAR — HIZLI KAZANIMLAR (config/1-2 gün) vs ORTA VADELİ (içerik/süreç isteyen).
  // Her grup severity'e göre (yüksek->orta) sıralı; tekrarlar ayıklanır.
  const seen = new Set<string>();
  const uniq = [...priorities].sort((a, b) => levelRank(b.sev) - levelRank(a.sev)).filter((p) => { const k = p.text.toLocaleLowerCase('tr'); if (seen.has(k)) return false; seen.add(k); return true; });
  const quick = uniq.filter((p) => p.horizon === 'quick').slice(0, 8);
  const medium = uniq.filter((p) => p.horizon === 'medium').slice(0, 8);
  const renderGroup = (items: Priority[]) => items.map((p, i) => `${i + 1}. **[${RISK_WORD[p.sev]}]** ${p.text}${p.impact ? ` → *${p.impact}*` : ''}`).join('\n');
  const prioritySection = uniq.length
    ? `## ÖNCELİKLİ AKSİYONLAR\n\nDışarıdan gözlemlenen boşluklar, uygulama eforuna göre iki grupta önceliklendirildi:\n\n` +
      (quick.length ? `### ⚡ Hızlı Kazanımlar (genellikle sunucu/yapılandırma — 1-2 gün)\n\n${renderGroup(quick)}\n\n` : '') +
      (medium.length ? `### 🗓️ Orta Vadeli (içerik/süreç/entegrasyon gerektirir)\n\n${renderGroup(medium)}\n\n` : '')
    : '';

  const findings =
    `## YÖNETİCİ ÖZETİ\n\n${summary.join('\n')}\n\n` +
    `## GENEL DEĞERLENDİRME\n\n**Risk Seviyesi: ${RISK_WORD[worst]}**\n\n${genelSentence}\n\n${prioritySection}${areaSections}`;

  const fixParts = AREA_TITLES.map((t, i) => {
    const r = results[i];
    return r && r.fixText.trim() ? `### ${t}\n\n${r.fixText.trim()}` : '';
  }).filter(Boolean);
  const fixText = 'Bu bölüm, uyum ön-değerlendirmenizde dışarıdan gözlemlenen eksikler için çerçeve çerçeve düzeltme adımları içerir (resmî uyum beyanı değildir).\n\n' + fixParts.join('\n\n');

  return { findings, fixText };
}

export async function generateBundleComplianceReport(host: string): Promise<{ findings: string; fixText: string } | null> {
  const o = await resolveOrigin(host);
  // (DÜRÜSTLÜK) Hedefe ulaşılamadı -> "İncelenemedi" (null->Düşük fallback DEĞİL).
  if (!o.reachable) return unscannableReport(host, 'uyum ön-değerlendirme kontrolleri');
  const ev = await collectComplianceEvidence(host);
  if (!ev) return unscannableReport(host, 'uyum ön-değerlendirme kontrolleri');
  // 3 cerceve AYNI kanittan (tek-sefer toplandi) — saf builder'lar.
  const areas = [buildKvkkArea(ev), buildPciArea(ev), buildIsoArea(ev)];
  const priorities = areas.flatMap((a) => a.priorities);
  return combineComplianceAreas(areas.map((a) => ({ findings: a.findings, fixText: a.fixText })), priorities);
}
