import MarkdownIt from 'markdown-it';
import puppeteer from 'puppeteer-core';

/**
 * (3) Rapor PDF uretimi — SAF FORMATLAMA/RENDER. Ek LLM cagrisi YOK, ek Anthropic
 * maliyeti YOK: icerik (bulgular + varsa fix onerileri) zaten uretilmis Markdown;
 * burada yalnizca marka kimligine uygun, sunulabilir bir PDF'e donusturuluyor.
 *
 * Motor: markdown-it (MD->HTML) + puppeteer-core ile headless Chromium (HTML->PDF).
 * Chromium sistemden gelir (PUPPETEER_EXECUTABLE_PATH; Docker'da apk chromium).
 *
 * Marka (frontend/tailwind.config.ts brief): derin teal #123F3A + amber CTA #F5A623.
 */

const md = new MarkdownIt({
  html: false, // GUVENLIK: ajan uretimi icerikte ham HTML'e izin verme (PDF injection)
  linkify: true,
  breaks: false,
});

export interface ReportPdfMeta {
  hostname: string;
  packageName: string;
  packageKey?: string; // (KVKK pilotu) pakete-ozel render dallanmasi icin
  createdAt: Date;
  locale: 'tr' | 'en';
}

export interface ReportPdfOptions {
  fixMarkdown?: string | null; // unlock edilmisse fix onerileri Markdown'i
  fixLocked?: boolean; // fix onerisi VAR ama satin alinmamis (kilitli goster)
  extrasMarkdown?: string | null; // Ek Pasif Kontroller (kod-tabanli) — ayri/renkli bolum
  // (ORNEK PDF) Ust "Genel Degerlendirme" kutusunun risk seviyesini AÇIKÇA belirle. Yalnizca
  // ORNEK raporlar kullanir (statik govdedeki risk severity-parse'a takilmayabilir); GERCEK
  // raporlar bunu ASLA gecmez -> onlarin assessRisk/assessBasit mantigi AYNEN korunur.
  assessOverride?: { level: 'high' | 'medium' | 'low'; sentence?: string } | null;
}

const CHROMIUM_PATH = process.env.PUPPETEER_EXECUTABLE_PATH || '/usr/bin/chromium-browser';

const L = {
  tr: {
    brandTagline: 'Otomatik Güvenlik Tarama Raporu',
    target: 'Hedef', pkg: 'Paket', date: 'Tarih',
    fixTitle: 'AI Çözüm Önerileri',
    fixLocked: 'Bu premium bölüm, yukarıda tespit edilen HER bulgu için adım adım düzeltme talimatı ve panoya kopyalanmaya hazır yapılandırma örnekleri (Nginx/sunucu ayarları, güvenlik başlıkları vb.) içerir.',
    fixLockedCta: '🔓 Kilidi açmak için “AI Çözüm Önerileri” eklentisini satın alın.',
    fixEmpty: 'Bu tarama için ayrıntılı düzeltme önerisi içeriği üretilemedi. “AI Çözüm Önerileri” eklentisi, tespit edilen her bulgu için adım adım düzeltme talimatı ve hazır yapılandırma örnekleri sunar.',
    footerLegal: 'Yapay zeka üretimi pasif tarama raporu — resmi denetim/sertifikasyon değildir. Gizlidir.',
    page: 'Sayfa',
    assessTitle: 'Genel Değerlendirme',
    riskHigh: 'Yüksek Risk', riskMedium: 'Orta Risk', riskMediumHigh: 'Orta-Yüksek Risk', riskLow: 'Düşük Risk',
    assessHigh: 'Bu taramada acil müdahale gerektiren kritik güvenlik bulguları tespit edildi; öncelikli olarak ele alınması önerilir.',
    assessMedium: 'Bu taramada kısa vadede giderilmesi önerilen önemli güvenlik bulguları tespit edildi.',
    assessLow: 'Bu taramada ciddi/kritik bir güvenlik açığı öne çıkmadı; rapor iyileştirme fırsatlarını listeler.',
  },
  en: {
    brandTagline: 'Automated Security Scan Report',
    target: 'Target', pkg: 'Package', date: 'Date',
    fixTitle: 'AI Fix Suggestions',
    fixLocked: 'This premium section contains step-by-step remediation for EACH finding above, plus ready-to-paste configuration examples (Nginx/server settings, security headers, etc.).',
    fixLockedCta: '🔓 Purchase the “AI Fix Suggestions” add-on to unlock it.',
    fixEmpty: 'Detailed remediation content could not be produced for this scan. The “AI Fix Suggestions” add-on provides step-by-step remediation and ready-to-use configuration examples for each finding.',
    footerLegal: 'AI-generated passive scan report — not an official audit/certification. Confidential.',
    page: 'Page',
    assessTitle: 'Overall Assessment',
    riskHigh: 'High Risk', riskMedium: 'Medium Risk', riskMediumHigh: 'Medium-High Risk', riskLow: 'Low Risk',
    assessHigh: 'This scan surfaced critical security findings that require prompt action; they should be prioritised.',
    assessMedium: 'This scan surfaced important security findings that should be addressed in the near term.',
    assessLow: 'This scan did not surface a serious/critical vulnerability; the report lists improvement opportunities.',
  },
} as const;

// Rapor metnindeki siddet sinyallerinden GENEL RISK seviyesi turetir (ek LLM YOK).
// NEGASYON-FARKINDA: "KRITIK: Tespit edilmemistir" gibi "yok" ifadeleri sayilmaz;
// oncelikle etiketli bulgu siddeti ("Siddet: Orta" / "Severity: High") aranir, yoksa
// negasyonla-elenen bolum basliklari. applicability ("Uygulanabilirlik: YUKSEK") sayilmaz.
function assessRisk(md: string, locale: 'tr' | 'en'): { level: 'high' | 'medium' | 'low'; label: string; sentence: string } {
  const t = L[locale];
  // (a) etiketli bulgu siddeti: "Siddet/Şiddet/Severity: <kw>" — en guvenilir sinyal.
  const labeled = (kw: string) => new RegExp(`(ş|s)iddet\\s*[:：]\\s*[*_> ]*(${kw})|severity\\s*[:：]\\s*[*_> ]*(${kw})`, 'i');
  // (b) bolum basligi "<kw> SEVIYE" / "<kw> (..)" — ama yakininda "yok/tespit edilmemis/none" varsa SAYMA.
  const heading = (kw: string) => new RegExp(`(${kw})\\s*(seviye|severity|\\()`, 'i');
  const negated = (kw: string) =>
    new RegExp(`(${kw})[\\s\\S]{0,70}?(tespit\\s+edilmem|bulunmam|bulunma(dı|maz)|yok\\b|hi[çc]\\b|none|not\\s+(detected|found)|:\\s*0\\b)`, 'i');
  const has = (kw: string) => labeled(kw).test(md) || (heading(kw).test(md) && !negated(kw).test(md));

  const K = 'kr[iİ]t[iİ]k|critical';
  const H = 'y[uüÜ]ksek|high';
  const M = 'orta|medium';

  if (has(K)) return { level: 'high', label: t.riskHigh, sentence: t.assessHigh };
  if (has(H) || has(M)) return { level: 'medium', label: t.riskMedium, sentence: t.assessMedium };
  return { level: 'low', label: t.riskLow, sentence: t.assessLow };
}

// (basit_tarama) Guvenlik BASLIKLARINI koddan parse edip BAGIMSIZ, deterministik risk
// seviyesi hesaplar — ajanin metinde yazdigi "Düşük/Orta/Yüksek" ifadesine GUVENMEZ (ajan
// tutarsiz olabiliyor: ustte "Düşük" deyip altta CSP/X-Frame eksik birakabiliyor). Prompt
// (madde A.3) HTTP GÜVENLİK BAŞLIKLARI bolumunu ZORUNLU tablo yaptigi icin tablo/satir-ici
// her iki formattan da baslik durumunu (Var/Yok) okur. Parse edilemezse assessRisk fallback.
// KOD HESAPLAMASI KAZANIR: rozet + ozet cumlesi bu hesaptan gelir, ajan metninden DEGIL.
const BASIT_HEADERS: Array<{ key: string; re: RegExp }> = [
  { key: 'csp', re: /content-security-policy|(?<![a-z-])csp(?![a-z])/i },
  { key: 'xfo', re: /x-frame-options/i },
  { key: 'xcto', re: /x-content-type-options/i },
  { key: 'hsts', re: /strict-transport-security|(?<![a-z-])hsts(?![a-z])/i },
  { key: 'referrer', re: /referrer-policy/i },
  { key: 'permissions', re: /permissions-policy|feature-policy/i },
];

// Bir metin parcasindan baslik durumunu (var/yok) cikarir. Once "Durum: <deger>" (tablo
// hucresi VEYA satir-ici) ifadesine bakar; yoksa parcanin genelinden yok/var sinyali arar.
function headerStatusFrom(chunk: string): 'present' | 'absent' | null {
  const ABSENT = /(yok|eksik|absent|missing|❌|✗|✘|bulunmuyor|bulunma|mevcut de[ğg]il|tan[ıi]ml[ıi] de[ğg]il|ayarlanmam)/i;
  const PRESENT = /(var\b|mevcut|present|✅|✓|✔|ayarlanm[ıi][şs]|tan[ıi]ml[ıi]\b|set\b)/i;
  const m = chunk.match(/durum\s*[:：]\s*([^\n|]{0,24})/i);
  const probe = m ? m[1] : chunk;
  if (ABSENT.test(probe)) return 'absent';
  if (PRESENT.test(probe)) return 'present';
  if (ABSENT.test(chunk)) return 'absent';
  if (PRESENT.test(chunk)) return 'present';
  return null;
}

// Rapordan guvenlik basliklarinin var/yok durumunu okur (tablo satiri VEYA "N. Baslik" +
// "Durum:" satir-ici). Baslik adini YALNIZ satir/hucre BASINDA arar (aciklama icindeki
// gecisi — ör. CSP notunda "X-Content-Type-Options eksik" — yanlis eslesmesin).
function parseBasitHeaders(md: string): { present: Set<string>; absent: Set<string> } {
  const present = new Set<string>();
  const absent = new Set<string>();
  const lines = md.split('\n');
  for (let i = 0; i < lines.length; i++) {
    // satir basindaki markdown/liste isaretlerini ve tablo hucre ayiracini soy.
    const lead = lines[i].replace(/^[\s|>*_#-]*(?:\d+[.)]\s*)?[\s*_]*/, '');
    const hit = BASIT_HEADERS.find((h) => h.re.test(lead.slice(0, 40)));
    if (!hit || present.has(hit.key) || absent.has(hit.key)) continue;
    // durum ayni satirda (tablo) VEYA sonraki 2 satirda (satir-ici "Durum:") olabilir.
    const window = [lines[i], lines[i + 1] ?? '', lines[i + 2] ?? ''].join('\n');
    const st = headerStatusFrom(window);
    if (st === 'present') present.add(hit.key);
    else if (st === 'absent') absent.add(hit.key);
  }
  return { present, absent };
}

export function assessBasit(
  md: string,
  t: { riskHigh: string; riskMedium: string; riskMediumHigh: string; riskLow: string; assessHigh: string; assessMedium: string; assessLow: string },
): { level: 'high' | 'medium-high' | 'medium' | 'low'; label: string; sentence: string } {
  const mk = (level: 'high' | 'medium-high' | 'medium' | 'low') => ({
    level,
    label: level === 'high' ? t.riskHigh : level === 'medium-high' ? t.riskMediumHigh : level === 'medium' ? t.riskMedium : t.riskLow,
    sentence:
      level === 'high'
        ? 'Ziyaretçilere doğrudan güvenlik uyarısı gösterebilecek acil bir sorun (ör. sertifika süresi/hostname) tespit edildi; öncelikli olarak giderilmesi önerilir.'
        : level === 'medium-high'
          ? 'Öncelikli giderilmesi önerilen, tek başına yüksek etkili bir yapılandırma eksikliği tespit edildi.'
          : level === 'medium'
            ? 'Öncelikli giderilmesi önerilen önemli güvenlik başlığı eksiklikleri tespit edildi; taşıma güvenliği (TLS) genel olarak sağlam.'
            : 'Ciddi/kritik bir güvenlik açığı öne çıkmadı; rapor yalnızca küçük iyileştirme fırsatlarını listeler.',
  });

  // (1) Rapor KOD-yazimi oldugundan GENEL DEĞERLENDİRME'deki ACIK "Risk Seviyesi: X"i oku —
  //     tek dogruluk kaynagi; rozet ile metin GARANTI tutarli. "Orta-Yüksek" ONCE eslesmeli.
  const m = md.slice(0, 1500).match(/risk\s*seviyesi\s*[:：]\s*\**\s*(orta[-\s]?y[uü]ksek|kr[iİ]t[iİ]k|y[uü]ksek|orta|d[uü][sş][uü]k)/i);
  if (m) {
    const kw = m[1].toLocaleLowerCase('tr');
    if (/orta[-\s]?y[uü]ksek/.test(kw)) return mk('medium-high');
    if (/kr[iı]t[iı]k|y[uü]ksek/.test(kw)) return mk('high');
    if (/orta/.test(kw)) return mk('medium');
    if (/d[uü][sş][uü]k/.test(kw)) return mk('low');
  }

  // (2) Acik ifade yoksa (eski/ajan raporu): HTTP baslik tablosundan turet.
  const { present, absent } = parseBasitHeaders(md);
  if (present.size + absent.size === 0) return assessRisk(md, 'tr'); // (3) son care
  const crit = absent.has('csp') || absent.has('xfo');
  if (crit || absent.size >= 3) return mk('medium');
  return mk('low');
}

// (KVKK PILOTU) Durum sutununu (Uygun/Dikkat/Eksik) SAYARAK deterministik risk + kontrol
// ozeti uretir — LLM'in tutarsiz etiketine GUVENME. Severity-tabanli assessRisk KVKK'da
// calismiyordu (KVKK "Uygun/Dikkat/Eksik" kullanir, "kritik/yuksek" degil) — bu onu duzeltir.
export function assessKvkk(md: string, t: { riskHigh: string; riskMedium: string; riskLow: string }): {
  level: 'high' | 'medium' | 'low';
  label: string;
  sentence: string;
  eksik: number;
  dikkat: number;
  uygun: number;
  total: number;
} {
  // TABLO HUCRESI olarak gecen Durum degerlerini say. TOLERANSLI: hucre basinda kalan
  // ikon/isaret (🔴 ❌ ✓ vb.) VEYA bosluk olabilir → `[^\w|]*` ile yut. Boylece hem notr
  // "| Eksik |" hem de sanitize sonrasi "| 🔴 Eksik |" / "| ❌ Eksik |" sayilir.
  const count = (kw: RegExp) => (md.match(kw) ?? []).length;
  const cell = (w: string) => new RegExp(`\\|\\s*(?:[^\\w|]*\\s*)?${w}\\s*\\|`, 'giu');
  let eksik = count(cell('eksik'));
  let dikkat = count(cell('dikkat'));
  let uygun = count(cell('uygun'));
  let total = eksik + dikkat + uygun;
  // Geri-donus: tablo yoksa "Durum: Eksik" gibi satir-ici durum ifadelerini say (prose'da
  // gecen kelimeyi degil, yalniz "Durum/Sonuc: <deger>" kalibini) — total 0 kalmasin.
  if (total === 0) {
    const inline = (w: string) =>
      count(new RegExp(`(?:durum|sonu[cç]|de[gğ]erlendirme)\\s*[:：]\\s*[^\\n|]{0,4}?${w}\\b`, 'gi'));
    eksik = inline('eksik');
    dikkat = inline('dikkat');
    uygun = inline('uygun');
    total = eksik + dikkat + uygun;
  }
  // Kritik/Yuksek -> riza mekanizmasi tamamen yok + izleyiciler rizasiz (cok Eksik).
  // Orta -> bazi eksikler ama temel mekanizmalar var. Dusuk -> sadece kucuk firsatlar.
  let level: 'high' | 'medium' | 'low';
  if (eksik >= 3) level = 'high';
  else if (eksik >= 1 || dikkat >= 2) level = 'medium';
  else level = 'low';
  const label = level === 'high' ? t.riskHigh : level === 'medium' ? t.riskMedium : t.riskLow;
  const sentence =
    level === 'high'
      ? 'KVKK açısından öncelikli ele alınması gereken önemli hazırlık eksiklikleri tespit edildi (rıza mekanizması ve/veya temel bilgilendirme/veri sorumlusu yükümlülükleri).'
      : level === 'medium'
        ? 'Bazı KVKK hazırlık eksiklikleri tespit edildi; kısa vadede iyileştirilmesi önerilir. Temel mekanizmaların bir kısmı mevcut.'
        : 'Belirgin bir KVKK hazırlık eksikliği öne çıkmadı; rapor yalnızca küçük iyileştirme fırsatlarını listeler.';
  return { level, label, sentence, eksik, dikkat, uygun, total };
}

// CyberTestify kalkan logosu (inline SVG — dis kaynak yok).
const LOGO_SVG = `
<svg width="34" height="34" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path d="M12 2L4 5v6c0 5 3.4 8.5 8 11 4.6-2.5 8-6 8-11V5l-8-3z" fill="#F5A623"/>
  <path d="M9.2 12.2l1.9 1.9 3.9-4.1" stroke="#123F3A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
</svg>`.trim();

// Deterministik (kod-yazimi) rapor ureten paketler — rozet acik "Risk Seviyesi"den okunur.
const DETERMINISTIC_PDF_PKGS = new Set(['basit_tarama', 'ssl_tls', 'header_leak', 'dns_email', 'cors_cookie', 'csp_analiz', 'bundle_surface', 'bundle_compliance', 'bundle_recon', 'injection_verify', 'idor_verify', 'bundle_active_verify', 'ssrf_verify', 'rce_verify', 'file_upload_verify', 'business_logic_verify', 'race_massassign_verify']);
// Birlesik bundle raporlari: ust kutu cumlesi = GENEL DEĞERLENDİRME govde cumlesi (worst-case alana ozgu).
const BUNDLE_COMBINED_PKGS = new Set(['bundle_surface', 'bundle_compliance', 'bundle_recon', 'bundle_active_verify']);

function escapeHtml(s: string): string {
  return s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c] as string));
}

export function buildHtml(bodyMd: string, meta: ReportPdfMeta, opts: ReportPdfOptions): string {
  const t = L[meta.locale];
  const dateStr = meta.createdAt.toLocaleDateString(meta.locale === 'tr' ? 'tr-TR' : 'en-GB', {
    year: 'numeric', month: 'long', day: 'numeric',
  });

  // Ust banner zaten Hedef/Paket/Tarih'i gosteriyor; markdown'in kendi baslik+meta
  // blogunu (ilk '---' cizgisine kadar) at ki tekrar olmasin. Yalniz H1 ile basliyorsa.
  let effectiveMd = bodyMd;
  if (effectiveMd.startsWith('# ')) {
    const hr = effectiveMd.indexOf('\n---\n');
    if (hr !== -1 && hr < 500) effectiveMd = effectiveMd.slice(hr + 5);
  }
  // GUVENLIK AGI: eski raporlarda kalan bos "## Ekran Goruntuleri / _Yok_" bolumunu at
  // (yeni raporlar bunu zaten uretmiyor — bkz report.ts renderReportMarkdown).
  effectiveMd = effectiveMd.replace(
    /\n*(?:---\s*\n)?\s*#{1,6}\s*(?:Ekran\s*Gör?[uü]nt[uü]leri|Screenshots)\s*\n+_?(?:Yok|None)_?\s*(?=\n---|\s*$)/gi,
    '',
  );

  // Genel Degerlendirme (banner altina) — risk seviyesi (ek LLM YOK).
  const isKvkk = meta.packageKey === 'kvkk_hazirlik';
  let assessBox: string;
  if (opts.assessOverride) {
    // (ORNEK PDF) Ust kutu riski AÇIKÇA verildi — statik ornek govdesindeki risk ifadesi
    // severity-parse'a takilmayabildiginden ust kutu <-> govde TUTARLILIGINI garanti eder.
    // GERCEK raporlar bu opt'u gecmez; onlarin assessRisk/assessBasit mantigi DEGISMEZ.
    const lv = opts.assessOverride.level;
    const label = lv === 'high' ? t.riskHigh : lv === 'medium' ? t.riskMedium : t.riskLow;
    const sentence = opts.assessOverride.sentence ?? (lv === 'high' ? t.assessHigh : lv === 'medium' ? t.assessMedium : t.assessLow);
    assessBox = `<div class="assess assess-${lv}">
    <div class="assess-head"><span class="assess-title">${escapeHtml(t.assessTitle)}</span>
      <span class="risk-badge risk-${lv}">${escapeHtml(label)}</span></div>
    <p class="assess-body">${escapeHtml(sentence)}</p></div>`;
  } else if (meta.packageKey === 'bundle_full_pentest') {
    // (Tam Kapsamlı Pentest — blocker fix) Authenticated rapor KENDİ dinamik "Değerlendirme Özeti
    // (Authenticated)" kutusunu + "## GENEL DEĞERLENDİRME" (doğru risk) içerir. Üstte AYRICA bir
    // risk-rozeti kutusu RENDER ETME — aksi halde assessRisk bu formatı yanlış okuyup "Düşük Risk"
    // statik metnini basıyordu (SQLi/Yüksek içeren raporda "Düşük" yazıyordu). Tek, doğru kutu kalsın.
    assessBox = '';
  } else if (isKvkk) {
    // (KVKK PILOTU) Durum sayimindan DETERMINISTIK risk + notr "Kontrol Ozeti" kutusu.
    const k = assessKvkk(effectiveMd, t);
    const needImprove = k.eksik + k.dikkat;
    // NOTR ifade — "uyum skoru/uyumlu/uyumsuz" YOK (UYUM BEYANI YOK kurali).
    // NOT: total===0 durumunda ASLA hata/teknik metin gosterme (musteriye sizmasin) —
    // sessiz, notr ve makul bir yonlendirme cumlesine dus (kok cozum: sanitize + toleransli
    // sayim zaten total'i doldurur; bu yalniz gercekten tablosuz/bozuk cikti icin son care).
    const summaryLine =
      k.total > 0
        ? `${needImprove}/${k.total} kontrol alanı iyileştirme gerektiriyor (Eksik: ${k.eksik} · Dikkat: ${k.dikkat} · Uygun: ${k.uygun}).`
        : 'Öne çıkan hazırlık eksiklikleri için aşağıdaki bulgular ve "Önerilen Aksiyonlar" bölümüne bakınız.';
    assessBox = `<div class="assess assess-${k.level}">
    <div class="assess-head"><span class="assess-title">${escapeHtml(t.assessTitle)}</span>
      <span class="risk-badge risk-${k.level}">${escapeHtml(k.label)}</span></div>
    <p class="assess-body">${escapeHtml(k.sentence)}</p></div>
    <div class="ctrl-summary"><span class="ctrl-title">Hazırlık Durumu Özeti</span>
      <span class="ctrl-line">${escapeHtml(summaryLine)}</span></div>`;
  } else {
    // basit_tarama: yeni prompt raporda ACIK risk seviyesi (YÖNETİCİ ÖZETİ/GENEL DEĞERLENDİRME)
    // yazar → kutu ile rapor metni TUTARLI olsun diye once onu oku (assessBasit); digerlerinde
    // severity-tabanli assessRisk. Boylece "metin Orta der ama kutu Düşük" tutarsizligi olmaz.
    // Deterministik (kod-yazimi) paketler GENEL DEĞERLENDİRME'ye acik "Risk Seviyesi: X" yazar;
    // assessBasit once onu okur -> rozet metinle GARANTI tutarli. Digerlerinde severity-tabanli.
    const risk = DETERMINISTIC_PDF_PKGS.has(meta.packageKey ?? '') ? assessBasit(effectiveMd, t) : assessRisk(effectiveMd, meta.locale);
    // (bundle_surface) Ust kutu cumlesi = GENEL DEĞERLENDİRME govde cumlesi (worst-case ALANA
    // ozgu, koddan uretilen) — sabit/gelisiguzel "ör. sertifika/hostname" ornegi YERINE gercek
    // bulgu. Boylece kutu <-> YÖNETİCİ ÖZETİ/GENEL DEĞERLENDİRME HER ZAMAN tutarli. (Yalniz
    // bundle_surface; basit_tarama ve digerleri DEGISMEZ.)
    if (BUNDLE_COMBINED_PKGS.has(meta.packageKey ?? '')) {
      const g = effectiveMd.match(/##\s*GENEL DEĞERLENDİRME\s*\n+\*\*Risk Seviyesi:[^\n]*\*\*\s*\n+([^\n]+)/);
      if (g) risk.sentence = g[1].trim().replace(/\*\*/g, ''); // kutu duz metin — markdown ** temizle
    }
    assessBox = `<div class="assess assess-${risk.level}">
    <div class="assess-head"><span class="assess-title">${escapeHtml(t.assessTitle)}</span>
      <span class="risk-badge risk-${risk.level}">${escapeHtml(risk.label)}</span></div>
    <p class="assess-body">${escapeHtml(risk.sentence)}</p></div>`;
  }
  const fixTitle = isKvkk ? 'Önerilen Aksiyonlar' : t.fixTitle;

  let bodyHtml = md.render(effectiveMd);

  // Ek Pasif Kontroller (kod-tabanli) — ana bulgulardan GORSEL olarak ayri, farkli renk.
  // Markdown zaten "## Ek Pasif Kontroller" basligi + notu icerir; kutu icine sarariz.
  if (opts.extrasMarkdown && opts.extrasMarkdown.trim()) {
    bodyHtml += `<div class="extras-section">${md.render(opts.extrasMarkdown)}</div>`;
  }

  // Fix onerileri bolumu — 3 DURUM ve KOD GARANTISI: (1) unlock+icerik -> icerigi goster;
  // (2) kilitli (icerik var, satin alinmamis) -> upsell kutusu; (3) HIC icerik yok (ajan
  // ===FIX_SUGGESTIONS=== yazmadi) -> nazik "uretilemedi" notu. Boylece "AI Çözüm Önerileri"
  // bolumu HER raporda MUTLAKA yer alir, ASLA sessizce kaybolmaz (KVKK haric — onun kendi
  // "Önerilen Aksiyonlar" akisi var).
  if (opts.fixMarkdown && opts.fixMarkdown.trim()) {
    bodyHtml += `<div class="fix-section"><h2>${escapeHtml(fixTitle)}</h2>${md.render(opts.fixMarkdown)}</div>`;
  } else if (opts.fixLocked) {
    bodyHtml += `<div class="fix-locked"><h2>🔒 ${escapeHtml(fixTitle)}</h2><p>${escapeHtml(t.fixLocked)}</p><p class="fix-cta">${escapeHtml(t.fixLockedCta)}</p></div>`;
  } else if (!isKvkk) {
    bodyHtml += `<div class="fix-locked"><h2>🔒 ${escapeHtml(fixTitle)}</h2><p>${escapeHtml(t.fixEmpty)}</p><p class="fix-cta">${escapeHtml(t.fixLockedCta)}</p></div>`;
  }

  return `<!doctype html><html lang="${meta.locale}"><head><meta charset="utf-8">
<style>
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; }
  body {
    font-family: -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, "Noto Sans", sans-serif;
    color: #1b2b28; font-size: 12px; line-height: 1.55; -webkit-print-color-adjust: exact; print-color-adjust: exact;
  }
  .cover-band {
    background: linear-gradient(135deg, #123F3A 0%, #0A2E2A 100%); color: #EEF5F3;
    padding: 22px 34px; display: flex; align-items: center; gap: 14px;
  }
  .cover-band .brand { font-size: 20px; font-weight: 700; letter-spacing: .3px; color: #ffffff; }
  .cover-band .brand span { color: #F5A623; }
  .cover-band .tagline { font-size: 11px; color: #9Fc4bc; margin-top: 2px; }
  .meta {
    display: flex; gap: 26px; padding: 14px 34px; background: #EEF5F3;
    border-bottom: 3px solid #F5A623; font-size: 11px;
  }
  .meta .k { color: #5FA396; text-transform: uppercase; letter-spacing: .5px; font-size: 9px; font-weight: 700; }
  .meta .v { color: #123F3A; font-weight: 600; font-size: 12.5px; }
  .content { padding: 20px 34px 30px; }
  /* Genel Degerlendirme kutusu (banner alti) */
  .assess { border-radius: 8px; padding: 14px 16px; margin: 4px 0 20px; border: 1px solid #DCEAE6; background: #F6FAF8; }
  .assess-high { background: #FCECEA; border-color: #F1C9C4; }
  .assess-medium-high { background: #FBE7D6; border-color: #EFC194; }
  .assess-medium { background: #FDF3DE; border-color: #F5D9A0; }
  .assess-low { background: #EEF5F3; border-color: #CFE5DF; }
  .assess-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
  .assess-title { font-size: 13px; font-weight: 700; color: #123F3A; text-transform: uppercase; letter-spacing: .5px; }
  .assess-body { margin: 8px 0 0; font-size: 12px; color: #1b2b28; }
  .risk-badge { color: #fff; padding: 3px 12px; border-radius: 12px; font-size: 11px; font-weight: 700; white-space: nowrap; }
  .risk-high { background: #B3261E; }
  .risk-medium-high { background: #C4581C; } /* koyu turuncu — Yüksek (kırmızı) ile Orta (amber) arası */
  .risk-medium { background: #E0940E; }
  .risk-low { background: #1C6B60; }
  /* (KVKK) Notr "Hazirlik Durumu Ozeti" kutusu — uyum skoru DEGIL */
  .ctrl-summary { display: flex; align-items: baseline; gap: 10px; margin: -8px 0 20px; padding: 10px 14px;
    background: #EEF5F3; border: 1px solid #CFE5DF; border-radius: 8px; }
  .ctrl-title { font-size: 11px; font-weight: 700; color: #14514A; text-transform: uppercase; letter-spacing: .5px; white-space: nowrap; }
  .ctrl-line { font-size: 12px; color: #1b2b28; }
  /* (KVKK) Durum hucresi renk + ikon (Uygun=yesil, Dikkat=turuncu, Eksik=kirmizi) */
  td.st-eksik { border-left: 4px solid #B3261E; } td.st-eksik .sev-badge { background: #B3261E; }
  td.st-dikkat { border-left: 4px solid #E0940E; } td.st-dikkat .sev-badge { background: #E0940E; }
  td.st-uygun { border-left: 4px solid #1C6B60; } td.st-uygun .sev-badge { background: #1C6B60; }
  h1 { color: #123F3A; font-size: 20px; margin: 6px 0 14px; border-bottom: 2px solid #DCEAE6; padding-bottom: 8px; }
  h2 { color: #14514A; font-size: 15px; margin: 20px 0 8px; }
  h3 { color: #1C6B60; font-size: 13px; margin: 14px 0 6px; }
  p { margin: 6px 0; }
  a { color: #14514A; }
  code { background: #EEF5F3; padding: 1px 5px; border-radius: 3px; font-size: 11px; }
  pre { background: #0A2E2A; color: #DCEAE6; padding: 12px 14px; border-radius: 6px; overflow-x: auto; font-size: 10.5px; }
  pre code { background: none; color: inherit; padding: 0; }
  ul, ol { margin: 6px 0 6px 4px; padding-left: 20px; }
  li { margin: 3px 0; }
  table { border-collapse: collapse; width: 100%; margin: 12px 0; font-size: 11px; }
  th { background: #123F3A; color: #fff; text-align: left; padding: 8px 10px; font-weight: 600; }
  td { padding: 7px 10px; border-bottom: 1px solid #DCEAE6; vertical-align: top; }
  tr:nth-child(even) td { background: #F6FAF8; }
  blockquote { margin: 10px 0; padding: 8px 14px; background: #FDECC8; border-left: 4px solid #F5A623; border-radius: 0 4px 4px 0; }
  hr { border: none; border-top: 1px solid #DCEAE6; margin: 18px 0; }
  /* Siddet (severity) renk kodlari — inline script <td>'lere sinif ekler */
  td.sev-critical { border-left: 4px solid #B3261E; }
  td.sev-critical .sev-badge { background: #B3261E; }
  td.sev-high { border-left: 4px solid #D64545; }
  td.sev-high .sev-badge { background: #D64545; }
  td.sev-medium { border-left: 4px solid #F5A623; }
  td.sev-medium .sev-badge { background: #E0940E; }
  td.sev-low { border-left: 4px solid #9AA0A6; }
  td.sev-low .sev-badge { background: #9AA0A6; }
  td.sev-info { border-left: 4px solid #5FA396; }
  td.sev-info .sev-badge { background: #5FA396; }
  .sev-badge { color: #fff; padding: 1px 7px; border-radius: 10px; font-size: 9.5px; font-weight: 700; white-space: nowrap; }
  /* Ek Pasif Kontroller — kod-tabanli, ana bulgulardan ayri (mavi-gri tema) */
  .extras-section { margin-top: 24px; padding: 4px 16px 14px; background: #F3F7FA; border: 1px solid #C9DCE8; border-left: 4px solid #2B6C9B; border-radius: 8px; }
  .extras-section h2 { color: #2B6C9B; font-size: 15px; }
  .extras-section blockquote { background: #E6EFF6; border-left-color: #2B6C9B; color: #274b63; }
  .extras-section th { background: #2B6C9B; }
  .extras-section h3 { color: #35618a; }
  .fix-section { margin-top: 22px; padding-top: 4px; border-top: 2px solid #F5A623; }
  .fix-section h2 { color: #E0940E; }
  .fix-locked { margin-top: 22px; padding: 14px; background: #EEF5F3; border: 1px dashed #5FA396; border-radius: 6px; color: #14514A; }
  .fix-locked h2 { color: #5FA396; margin: 0 0 4px; font-size: 14px; }
  .fix-locked .fix-cta { margin: 8px 0 0; font-weight: 600; color: #14514A; }
</style></head>
<body>
  <div class="cover-band">
    ${LOGO_SVG}
    <div>
      <div class="brand">Cyber<span>Testify</span></div>
      <div class="tagline">${escapeHtml(t.brandTagline)}</div>
    </div>
  </div>
  <div class="meta">
    <div><div class="k">${escapeHtml(t.target)}</div><div class="v">${escapeHtml(meta.hostname)}</div></div>
    <div><div class="k">${escapeHtml(t.pkg)}</div><div class="v">${escapeHtml(meta.packageName)}</div></div>
    <div><div class="k">${escapeHtml(t.date)}</div><div class="v">${escapeHtml(dateStr)}</div></div>
  </div>
  <div class="content">${assessBox}${bodyHtml}</div>
  <script>
    // Siddet kelimelerine gore tablo hucrelerini renklendir (TR+EN, buyuk/kucuk duyarsiz).
    (function () {
      var map = [
        // (KVKK) Durum degerleri — TAM eslesme + ikon (yesil/turuncu/kirmizi).
        { cls: 'st-uygun', re: /^uygun$/i, icon: '🟢 ' },
        { cls: 'st-dikkat', re: /^dikkat$/i, icon: '🟠 ' },
        { cls: 'st-eksik', re: /^eksik$/i, icon: '🔴 ' },
        { cls: 'sev-critical', re: /\\b(kritik|critical)\\b/i },
        { cls: 'sev-high', re: /\\b(y[uü]ksek|high)\\b/i },
        { cls: 'sev-medium', re: /\\b(orta|medium)\\b/i },
        { cls: 'sev-low', re: /\\b(d[uü][sş][uü]k|low)\\b/i },
        { cls: 'sev-info', re: /\\b(bilgi|info|informational)\\b/i },
      ];
      document.querySelectorAll('td').forEach(function (td) {
        var txt = (td.textContent || '').trim();
        if (txt.length > 24) return; // yalniz kisa "durum/siddet" hucreleri
        // Turkce buyuk-I sorunu: "KRİTİK".toLowerCase() != "kritik"; tr locale ile normalize.
        var norm = txt.toLocaleLowerCase('tr');
        for (var i = 0; i < map.length; i++) {
          if (map[i].re.test(norm)) {
            td.classList.add(map[i].cls);
            td.innerHTML = '<span class="sev-badge">' + (map[i].icon || '') + txt + '</span>';
            break;
          }
        }
      });
    })();
  </script>
</body></html>`;
}

/**
 * Markdown rapor + (opsiyonel) fix onerilerini markali PDF Buffer'ina cevirir.
 * Ek LLM cagrisi yapmaz. Chromium'u her cagride acip kapatir (rapor seyrek uretilir).
 */
export async function renderReportPdf(
  bodyMarkdown: string,
  meta: ReportPdfMeta,
  opts: ReportPdfOptions = {},
): Promise<Buffer> {
  const html = buildHtml(bodyMarkdown, meta, opts);
  const t = L[meta.locale];

  const browser = await puppeteer.launch({
    executablePath: CHROMIUM_PATH,
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--font-render-hinting=none'],
  });
  try {
    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: 'load' });
    const pdf = await page.pdf({
      format: 'A4',
      printBackground: true,
      margin: { top: '14mm', bottom: '18mm', left: '0mm', right: '0mm' },
      displayHeaderFooter: true,
      headerTemplate: '<div></div>',
      footerTemplate: `
        <div style="width:100%; font-size:8px; color:#5FA396; padding:0 12mm;
                    display:flex; justify-content:space-between; align-items:center;">
          <span style="max-width:78%;">${escapeHtml(t.footerLegal)}</span>
          <span>${escapeHtml(t.page)} <span class="pageNumber"></span>/<span class="totalPages"></span></span>
        </div>`,
    });
    return Buffer.from(pdf);
  } finally {
    await browser.close();
  }
}

// --- (Faz 3) Aktif Test Yetkilendirme Beyanı PDF'i — SAF RENDER (ek LLM YOK) --------
export interface ConsentPdfData {
  legalName: string;
  companyName?: string | null;
  hostname: string;
  packageName: string;
  does: string[];
  doesNot: string[];
  riskText: string;
  version: string;
  createdAt: Date;
  ip?: string | null;
}

function buildConsentHtml(d: ConsentPdfData): string {
  const dateStr = d.createdAt.toLocaleString('tr-TR', { dateStyle: 'long', timeStyle: 'short' });
  const li = (items: string[], color: string) =>
    items.map((i) => `<li style="margin:4px 0;"><span style="color:${color};font-weight:700;">•</span> ${escapeHtml(i)}</li>`).join('');
  return `<!doctype html><html lang="tr"><head><meta charset="utf-8"><style>
  * { box-sizing: border-box; } html,body { margin:0; padding:0; }
  body { font-family: -apple-system,"Segoe UI",Roboto,Arial,"Noto Sans",sans-serif; color:#1b2b28; font-size:12px; line-height:1.55; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .band { background:linear-gradient(135deg,#123F3A 0%,#0A2E2A 100%); color:#EEF5F3; padding:22px 34px; display:flex; align-items:center; gap:14px; }
  .brand { font-size:20px; font-weight:700; color:#fff; } .brand span { color:#F5A623; }
  .tagline { font-size:11px; color:#9Fc4bc; margin-top:2px; }
  .meta { display:flex; flex-wrap:wrap; gap:22px; padding:14px 34px; background:#EEF5F3; border-bottom:3px solid #F5A623; font-size:11px; }
  .meta .k { color:#5FA396; text-transform:uppercase; letter-spacing:.5px; font-size:9px; font-weight:700; }
  .meta .v { color:#123F3A; font-weight:600; font-size:12.5px; }
  .content { padding:20px 34px 30px; }
  h1 { color:#123F3A; font-size:19px; margin:4px 0 14px; }
  h2 { color:#14514A; font-size:14px; margin:18px 0 6px; }
  ul { list-style:none; padding-left:2px; margin:6px 0; }
  .risk { background:#FDECC8; border-left:4px solid #F5A623; padding:12px 14px; border-radius:0 6px 6px 0; margin:10px 0; }
  .decl { margin-top:18px; padding:14px 16px; background:#F6FAF8; border:1px solid #DCEAE6; border-radius:8px; }
  .decl .row { display:flex; justify-content:space-between; padding:3px 0; border-bottom:1px dashed #DCEAE6; }
  .foot { margin-top:20px; font-size:10px; color:#5FA396; border-top:1px solid #DCEAE6; padding-top:10px; }
  </style></head><body>
  <div class="band">${LOGO_SVG}<div><div class="brand">Cyber<span>Testify</span></div><div class="tagline">Aktif Test Yetkilendirme Beyanı</div></div></div>
  <div class="meta">
    <div><div class="k">Hedef</div><div class="v">${escapeHtml(d.hostname)}</div></div>
    <div><div class="k">Paket</div><div class="v">${escapeHtml(d.packageName)}</div></div>
    <div><div class="k">Tarih</div><div class="v">${escapeHtml(dateStr)}</div></div>
    <div><div class="k">Metin Sürümü</div><div class="v">${escapeHtml(d.version)}</div></div>
  </div>
  <div class="content">
    <h1>Aktif Test Yetkilendirme Beyanı</h1>
    <p>Bu belge, aşağıda kimliği beyan edilen kişinin, belirtilen hedef için “aktif-hafif” (active-light)
    bir güvenlik taraması yapılmasına dair yetkilendirmesini ve risk kabulünü kayıt altına alır.</p>
    <h2>Bu tarama NE YAPAR</h2><ul>${li(d.does, '#1C6B60')}</ul>
    <h2>Bu tarama NE YAPMAZ</h2><ul>${li(d.doesNot, '#B3261E')}</ul>
    <h2>Risk Kabul Beyanı</h2>
    <div class="risk">${escapeHtml(d.riskText)}</div>
    <h2>Beyan Eden</h2>
    <div class="decl">
      <div class="row"><span>Yasal Ad</span><strong>${escapeHtml(d.legalName)}</strong></div>
      ${d.companyName ? `<div class="row"><span>Şirket/Unvan</span><strong>${escapeHtml(d.companyName)}</strong></div>` : ''}
      <div class="row"><span>Onay Zamanı</span><strong>${escapeHtml(dateStr)}</strong></div>
      <div class="row"><span>IP Adresi</span><strong>${escapeHtml(d.ip ?? '-')}</strong></div>
      <div class="row"><span>Risk Kabulü</span><strong>Evet (işaretlendi)</strong></div>
    </div>
    <p class="foot">Bu beyan, elektronik imza yerine geçen bir irade beyanıdır (kriptografik e-imza değildir).
    Beyan sahibi, taramaya konu alan adının/altyapının sahibi veya yetkilisi olduğunu; sorumluluğun kendisine
    ait olduğunu kabul eder. CyberTestify, tarama sırasında oluşabilecek dolaylı zararlardan sorumlu tutulamaz.
    Bu belge otomatik olarak üretilmiştir.</p>
  </div>
  </body></html>`;
}

export async function renderConsentPdf(d: ConsentPdfData): Promise<Buffer> {
  const browser = await puppeteer.launch({
    executablePath: CHROMIUM_PATH,
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--font-render-hinting=none'],
  });
  try {
    const page = await browser.newPage();
    await page.setContent(buildConsentHtml(d), { waitUntil: 'load' });
    const pdf = await page.pdf({
      format: 'A4', printBackground: true,
      margin: { top: '12mm', bottom: '14mm', left: '0mm', right: '0mm' },
      displayHeaderFooter: true, headerTemplate: '<div></div>',
      footerTemplate: `<div style="width:100%; font-size:8px; color:#5FA396; padding:0 12mm; text-align:right;">
        CyberTestify — Aktif Test Yetkilendirme Beyanı · Sayfa <span class="pageNumber"></span>/<span class="totalPages"></span></div>`,
    });
    return Buffer.from(pdf);
  } finally {
    await browser.close();
  }
}
