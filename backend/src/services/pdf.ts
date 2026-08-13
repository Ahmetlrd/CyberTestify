import MarkdownIt from 'markdown-it';
import puppeteer from 'puppeteer-core';
import { createHash } from 'node:crypto';
import { lookupFinding, lookupByType, findingDetail, type FindingType } from './findingTaxonomy.js';

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

  // (0) TARANAMADI/İNCELENEMEDİ: hedefe hiç ulaşılamadıysa bu "temiz/düşük" DEĞİLDİR. Nötr bir
  //     "İncelenemedi" rozeti göster (amber; ASLA yeşil-düşük). "Güvenli" imasından kaçınır.
  // NOT: Türkçe "İ" (U+0130) JS'te /i flag'iyle "i"ye eşlenmez -> önce tr-locale ile küçült.
  if (/risk\s*seviyesi\s*[:：]\s*\*{0,2}\s*incelenemedi|tarama\s*(yap[ıi]lamad|y[uü]r[uü]t[uü]lemed)|ula[şs][ıi]lamad[ıi][ğg][ıi] i[çc]in kontrol/.test(md.slice(0, 1500).toLocaleLowerCase('tr'))) {
    return { level: 'medium', label: 'İncelenemedi', sentence: 'Hedefe ulaşılamadığı için tarama yürütülemedi; bu sonuç sitenin GÜVENLİ olduğu anlamına GELMEZ. Erişim sağlanınca yeniden taranmalıdır.' };
  }

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

// ============================================================================
// (PROFESYONEL RAPOR İSKELETİ — Aikido tarzı sunum, İÇERİK bizim dürüst çizgimiz)
// Kapak / Zafiyet Dağılımı / Master Bulgu Tablosu / Sözlük — hepsi MEVCUT markdown
// gövdesinden TÜRETİLİR (uydurma YOK). Gövde/ton/disclaimer/AI-kilit DEĞİŞMEZ.
// ============================================================================

// Deterministik Rapor No + Doğrulama Kodu (aynı rapor -> aynı numara; rastgelelik YOK).
function reportIdentifiers(hostname: string, createdAt: Date): { reportNo: string; verifyCode: string } {
  const y = createdAt.getUTCFullYear();
  const mo = String(createdAt.getUTCMonth() + 1).padStart(2, '0');
  const d = String(createdAt.getUTCDate()).padStart(2, '0');
  const h = createHash('sha256').update(`${hostname}|${createdAt.toISOString()}`).digest('hex').toUpperCase();
  return { reportNo: `CT-${y}${mo}${d}-${h.slice(0, 4)}`, verifyCode: `${h.slice(4, 8)}-${h.slice(8, 12)}` };
}

type Sev = 'critical' | 'high' | 'medium' | 'low';
type Finding = { title: string; sev: Sev; type?: FindingType; endpoint?: string; evidence?: string; confidence?: string };
function normSev(s: string): Sev | null {
  const x = s.toLocaleLowerCase('tr');
  if (/krit[iı]k|critical/.test(x)) return 'critical';
  if (/y[üu]ksek|high/.test(x)) return 'high';
  if (/orta|medium/.test(x)) return 'medium';
  if (/d[üu][şs][üu]k|low/.test(x)) return 'low';
  return null;
}
function stripMd(s: string): string {
  return s.replace(/`([^`]*)`/g, '$1').replace(/\*\*([^*]*)\*\*/g, '$1').replace(/\[([^\]]*)\]\([^)]*\)/g, '$1').replace(/[*_]/g, '').trim();
}

// (MÜŞTERİ-GÖRÜNÜR JARGON) "PentAGI" iç kod adı HİÇBİR müşteri-görünür yerde geçmemeli — konumlandırma
// "yapay zekâ destekli advisory". İç motor adını dış-dünya diline çevir (içerik/anlam DEĞİŞMEZ).
function sanitizeJargon(md: string): string {
  return md
    // "Otonom Analiz Motoru" = müşteri-görünür isim. İç mimari adları (PentAGI/LLM/advisory/ajan/backend GET)
    // müşteriye GÖSTERİLMEZ. NOT: "yapay zeka üretimidir" uyarısı + sınır-ötesi bilgilendirme AYRICA korunur.
    .replace(/yapay\s*zek[âa]\s*destekli\s*advisory\s*\(tek\s*LLM\s*[çc]a[ğg]r[ıi]s[ıi]\)/gi, 'Otonom Analiz Motoru')
    .replace(/yapay\s*zek[âa]\s*destekli\s*advisory/gi, 'Otonom Analiz Motoru')
    .replace(/AI\s*advisory\s*analiz\s*etti/gi, 'Otonom Analiz Motoru değerlendirdi')
    .replace(/s[ıi]n[ıi]rl[ıi][- ]otonom\s*ajan\s*katman[ıi]yla/gi, 'otonom analiz motoruyla')
    .replace(/s[ıi]n[ıi]rl[ıi]\/kontroll[üu]\s*otonom\s*ajan\s*analiziyle/gi, 'otonom analiz motoruyla')
    .replace(/sınırlı-otonom ajan katmanıyla/gi, 'otonom analiz motoruyla')
    .replace(/\(?\s*tek\s*LLM\s*[çc]a[ğg]r[ıi]s[ıi]\s*\)?/gi, '')
    .replace(/\badvisory\b/gi, 'otonom analiz')
    .replace(/PentAGI\s*aj[aı]n[ıi]?\s*bu\s*u[çc]\s*noktay[ıi]/gi, 'Otonom Analiz Motoru bu uç noktayı')
    .replace(/PentAGI\s*aj[aı]n[ıi]?\s*se[çc]ti\s*\+\s*backend\s*GET\s*ile\s*do[ğg]rulad[ıi]/gi, 'Otonom Analiz Motoru seçti, erişilebilirliği doğrulandı')
    .replace(/PentAGI\s*aj[aı]n[ıi]?/gi, 'Otonom Analiz Motoru')
    .replace(/İleri analiz(le)? bu uç noktayı/gi, 'Otonom Analiz Motoru bu uç noktayı')
    .replace(/İleri analizle seçildi, backend ile doğrulandı/gi, 'Otonom Analiz Motoru seçti, erişilebilirliği doğrulandı')
    .replace(/PentAGI/gi, 'Otonom Analiz Motoru')
    .replace(/\bLLM\b/gi, 'Otonom Analiz Motoru')
    // "ajana/... gönderilmez" -> motor diline
    .replace(/aj[aı]na\/yapay zek[âa] destekli analiz['’]?y[ei]/gi, 'Otonom Analiz Motoru’na')
    .replace(/aj[aı]na\/PentAGI['’]?y[ei]/gi, 'Otonom Analiz Motoru’na');
}

// Markdown gövdesindeki ŞİDDET içeren bulgu tablolarından (TESPİT EDİLEN RİSKLER / BULGULAR /
// Risk Matrisi) bulgu satırlarını (başlık + şiddet) çıkarır. Şiddet kolonu OLMAYAN tablolar
// (KVKK Uygun/Dikkat/Eksik, Kontrol Listesi Güven vb.) ATLANIR -> uyum raporunda 0 zafiyet.
// İç-jargon temizliği — master tablo/başlıkta ASLA "PentAGI", "backend GET ile doğruladı",
// "ajanı seçti" gibi ifadeler + payload/parantez teknik detayı GÖRÜNMEZ (2.3'te kalır).
function cleanTitle(raw: string): string {
  let t = raw
    .replace(/pentagi\s*aj[aı]n[ıi]?\s*se[çc]ti\s*\+?\s*/gi, '')
    .replace(/backend\s*get\s*ile\s*do[ğg]rulad[ıi]/gi, '')
    .replace(/aj[aı]n[ıi]?\s*se[çc]ti/gi, '')
    .replace(/pentagi/gi, '')
    .replace(/\s*\((?:sqli|xss)\s*g[öo]sterge[a-zçğıöşü ':=\-0-9]*\)/gi, '') // "(SQLi göstergesi: ' OR 1=1--)"
    .replace(/\s{2,}/g, ' ')
    .replace(/^[\s+•\-]+|[\s+]+$/g, '')
    .trim();
  return t;
}

function parseFindings(md: string, locale: 'tr' | 'en'): { rows: Finding[]; counts: Record<Sev, number> } {
  const counts: Record<Sev, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  const rows: Finding[] = [];
  const seen = new Set<string>();
  const lines = md.split('\n');
  let curSection = ''; // en yakın önceki ## BÖLÜM başlığı (ör. "İş Mantığı Doğrulama"). ### alt-başlıklar bağlam DEĞİL.
  let i = 0;
  while (i < lines.length) {
    const hm = lines[i].match(/^##\s+(.+?)\s*$/); // yalnız H2 (## ) bölüm başlığı
    if (hm) { curSection = stripMd(hm[1]); i++; continue; }
    if (!/^\s*\|.*\|\s*$/.test(lines[i])) { i++; continue; }
    // tablo bloğu topla
    const block: string[] = [];
    while (i < lines.length && /^\s*\|.*\|\s*$/.test(lines[i])) { block.push(lines[i]); i++; }
    if (block.length < 2) continue;
    const cells = (r: string) => r.replace(/^\s*\|/, '').replace(/\|\s*$/, '').split('|').map((c) => c.trim());
    const header = cells(block[0]).map((h) => h.toLocaleLowerCase('tr'));
    const sevCol = header.findIndex((h) => /[şs]iddet|severity|ciddiyet/.test(h));
    if (sevCol === -1) continue; // şiddet kolonu yoksa bulgu tablosu değil
    const techCol = header.findIndex((h) => /teknik|technique|t[üu]r\b|tip\b|\btype\b/.test(h));
    const endpointCol = header.findIndex((h) => /giri[şs]|u[çc] nokta|endpoint|uc nokta|yol\b|path/.test(h));
    let titleCol = header.findIndex((h) => /bulgu|ba[şs]l[ıi]k|title|finding/.test(h));
    if (titleCol === -1) titleCol = endpointCol;
    if (titleCol === -1) titleCol = header.findIndex((h, idx) => idx !== sevCol && !/^#|^no$|^s[ıi]ra/.test(h));
    if (titleCol === -1) titleCol = 0;
    const nameCol = techCol !== -1 ? techCol : titleCol;
    // Kanıt/açıklama kolonu — kartın "Nasıl Tespit Edildi"/açıklama için GERÇEK veri.
    const evidCol = header.findIndex((h) => /kan[ıi]t|evidence|k[ıi]sa a[çc][ıi]klama|a[çc][ıi]klama|not\b/.test(h));
    const confCol = header.findIndex((h) => /g[üu]ven\b|confidence/.test(h)); // güven kolonu (varsa)
    for (let r = 1; r < block.length; r++) {
      if (/^\s*\|[\s:|-]+\|\s*$/.test(block[r])) continue; // ayraç satırı
      const c = cells(block[r]);
      const sev = normSev(c[sevCol] ?? '');
      if (!sev) continue;
      const rawName = stripMd(c[nameCol] ?? c[titleCol] ?? '').replace(/^\d+[).]?\s*/, '');
      if (!rawName) continue;
      // Sınıflandırma: ŞİDDET ve KANIT/AÇIKLAMA kolonlarını DIŞLA. Açıklama metnindeki yabancı
      // anahtar kelimeler (ör. CSP bulgusunun açıklamasında "XSS" geçmesi) bulguyu YANLIŞ türe
      // eşliyordu (başlık "CSP eksik" ama master "Yansıyan XSS" gösteriyordu). Tür/başlık, uç
      // nokta + teknik + başlık kolonlarından gelir; açıklama sınıflandırmayı KİRLETMEZ.
      const classifyText = c.filter((_, idx) => idx !== sevCol && idx !== evidCol && idx !== confCol).map(stripMd).join(' ');
      // ÖNCE başlık/tür/uç-nokta kolonları, SONRA bölüm başlığı, EN SON çare tam satır (kanıt dahil).
      // Kanıt en sona bırakılır: başlık/bölümden sınıflanan bulgular (ör. "CSP eksik") kanıttaki
      // yabancı kelimeden (XSS) etkilenmez; yalnız hiç sınıflanamayan satırlar kanıta düşer.
      const fullRowText = c.filter((_, idx) => idx !== sevCol && idx !== confCol).map(stripMd).join(' ');
      const info = lookupFinding(classifyText, locale) ?? lookupFinding(curSection, locale) ?? lookupFinding(fullRowText, locale);
      const title = info ? info.label : (cleanTitle(rawName) || cleanTitle(curSection) || rawName);
      // Uç nokta: entry kolonundan (nameCol'dan farklıysa). "GET /rest/..." gibi.
      let endpoint = endpointCol !== -1 && endpointCol !== nameCol ? stripMd(c[endpointCol] ?? '') : '';
      if (endpoint.length > 60) endpoint = endpoint.slice(0, 60) + '…';
      const evidence = evidCol !== -1 ? stripMd(c[evidCol] ?? '') : '';
      // Güven (varsa) — DÜŞÜK/dolaylı kanıtı master tabloda da görünür kılmak için (yalnız detay kartında değil).
      const confidence = confCol !== -1 ? stripMd(c[confCol] ?? '') : '';
      const key = (info ? info.type : title.toLocaleLowerCase('tr')).slice(0, 48);
      if (seen.has(key)) continue;
      seen.add(key);
      rows.push({ title, sev, type: info?.type, endpoint: endpoint || undefined, evidence: evidence || undefined, confidence: confidence || undefined });
      counts[sev]++;
    }
  }
  return { rows, counts };
}

const SEV_META: Record<Sev, { tr: string; en: string; cls: string }> = {
  critical: { tr: 'Kritik', en: 'Critical', cls: 'sev-critical' },
  high: { tr: 'Yüksek', en: 'High', cls: 'sev-high' },
  medium: { tr: 'Orta', en: 'Medium', cls: 'sev-medium' },
  low: { tr: 'Düşük', en: 'Low', cls: 'sev-low' },
};

// 2.1 Zafiyet Dağılımı — gerçek sayılardan bar grafiği + sayı tablosu (0'lar da çizilir, dürüst).
function buildDistribution(counts: Record<Sev, number>, locale: 'tr' | 'en', unscannable = false): string {
  const order: Sev[] = ['critical', 'high', 'medium', 'low'];
  const max = Math.max(1, ...order.map((s) => counts[s]));
  const total = order.reduce((a, s) => a + counts[s], 0);
  const bars = order.map((s) => {
    const h = Math.round((counts[s] / max) * 80); // px (maks 80)
    return `<div class="dist-col"><div class="dist-num">${counts[s]}</div><div class="dist-bar ${SEV_META[s].cls}-bg" style="height:${h}px"></div><div class="dist-lbl">${locale === 'tr' ? SEV_META[s].tr : SEV_META[s].en}</div></div>`;
  }).join('');
  // (DÜRÜSTLÜK) Hedefe ulaşılamadıysa 0/0/0/0 "temiz" DEĞİL "incelenemedi"dir — açıkça belirt.
  const intro = unscannable
    ? (locale === 'tr' ? '⚠️ Hedefe ulaşılamadığı için kontroller çalıştırılamadı; aşağıdaki sıfırlar bir güvenlik değerlendirmesi <strong>DEĞİLDİR</strong> (0 = incelenemedi, “temiz” değil).' : '⚠️ The target could not be reached, so checks did not run; the zeros below are <strong>NOT</strong> a security assessment (0 = not scanned, not "clean").')
    : total === 0
    ? (locale === 'tr' ? 'Bu taramada açık bir zafiyet göstergesi tespit edilmedi. Çalıştırılan kontroller ve gözlemler aşağıdaki bölümlerde ayrıntılıdır.' : 'No open vulnerability indicator was detected in this scan. Executed checks and observations are detailed in the sections below.')
    : (locale === 'tr' ? `Bu taramada toplam <strong>${total}</strong> bulgu göstergesi tespit edildi; şiddet dağılımı aşağıdadır.` : `A total of <strong>${total}</strong> finding indicators were detected; the severity distribution is below.`);
  return `<h2 id="s-dist">${locale === 'tr' ? '2.1 Zafiyet Dağılımı' : '2.1 Vulnerability Distribution'}</h2>
  <div class="dist-chart">${bars}</div>
  <p>${intro}</p>`;
}

// 2.2 Master Bulgu Tablosu — ID (CT-N) + Başlık + Durum + Şiddet. Boşsa dürüst "temiz" satırı.
function buildMasterTable(rows: Finding[], locale: 'tr' | 'en', unscannable = false): string {
  const rank: Record<Sev, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  const sorted = [...rows].sort((a, b) => rank[a.sev] - rank[b.sev]);
  const head = locale === 'tr' ? ['ID', 'Başlık', 'Durum', 'Şiddet'] : ['ID', 'Title', 'State', 'Severity'];
  const open = locale === 'tr' ? 'Açık' : 'Open';
  let body: string;
  if (unscannable) {
    // (DÜRÜSTLÜK) Hedefe ulaşılamadı -> "Temiz" satırı YERİNE açık uyarı; nötr gri "İncelenemedi" (risk rengi YOK).
    body = `<tr><td>—</td><td colspan="2">${locale === 'tr' ? 'Hedefe ulaşılamadığı için kontroller çalıştırılamadı — sonuç değerlendirilemez (“temiz” anlamına gelmez).' : 'The target could not be reached, so checks did not run — result cannot be assessed (does not mean "clean").'}</td><td><span class="sev-badge" style="background:#6B7280">${locale === 'tr' ? 'İncelenemedi' : 'Not scanned'}</span></td></tr>`;
  } else if (sorted.length === 0) {
    body = `<tr><td>—</td><td colspan="2">${locale === 'tr' ? 'Bu taramada açık zafiyet göstergesi tespit edilmedi.' : 'No open vulnerability indicator detected in this scan.'}</td><td><span class="sev-badge" style="background:#1C6B60">${locale === 'tr' ? 'Temiz' : 'Clean'}</span></td></tr>`;
  } else {
    body = sorted.map((f, idx) => {
      const sm = SEV_META[f.sev];
      // Başlığa UÇ NOKTA (varsa) — "SQL Enjeksiyon göstergesi — /rest/products/search?q". Payload/teknik master'da DEĞİL.
      // DÜŞÜK/dolaylı güven -> master'da AÇIKÇA işaretle (detay kartıyla sınırlı kalmasın). Hem "Güven"
      // kolonundan hem de kanıt metnindeki "DOLAYLI/ZAYIF GÖSTERGE" ifadesinden tespit et (sağlam).
      const lowConf = /d[üu][şs][üu]k|low/i.test(f.confidence ?? '') || /dolayl[ıi][\s/]*zay[ıi]f g[öo]sterge|zay[ıi]f g[öo]sterge|doğrudan.*kan[ıi]t.*de[ğg]il/i.test(f.evidence ?? '');
      const confTag = lowConf ? ` <span class="mt-ep">· güven: düşük (dolaylı gösterge)</span>` : '';
      const titleCell = (f.endpoint ? `${escapeHtml(f.title)} <span class="mt-ep">— ${escapeHtml(f.endpoint)}</span>` : escapeHtml(f.title)) + confTag;
      return `<tr><td>CT-${idx + 1}</td><td>${titleCell}</td><td>${open}</td><td class="${sm.cls}"><span class="sev-badge">${locale === 'tr' ? sm.tr : sm.en}</span></td></tr>`;
    }).join('');
  }
  return `<h2 id="s-master">${locale === 'tr' ? '2.2 Master Bulgu Tablosu' : '2.2 Master Findings Table'}</h2>
  <table class="master"><thead><tr>${head.map((h) => `<th>${h}</th>`).join('')}</tr></thead><tbody>${body}</tbody></table>`;
}

// 2.3 Detaylı Bulgular — her GERÇEK bulgu için blok: CT-N + başlık + şiddet + Durum + İŞ ETKİSİ +
// Referans (CWE/OWASP). İş Etkisi/CWE deterministik eşlemeden (findingTaxonomy); eşleme yoksa blok
// ATLANIR (UYDURMA YOK). Sadece GERÇEK raporlarda (örneklerin kendi İş Etkisi bölümleri zaten var).
function buildDetailedFindings(rows: Finding[], locale: 'tr' | 'en'): string {
  const rank: Record<Sev, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  const sorted = [...rows].sort((a, b) => rank[a.sev] - rank[b.sev]);
  const blocks: string[] = [];
  const L = locale === 'tr'
    ? { state: 'Durum: Açık', ep: 'Etkilenen nokta', desc: 'Açıklama', how: 'Nasıl Tespit Edildi', impact: 'İş Etkisi', fix: 'Çözüm Önerisi', ref: 'Referans' }
    : { state: 'State: Open', ep: 'Affected point', desc: 'Description', how: 'How it was detected', impact: 'Business Impact', fix: 'Recommended Fix', ref: 'Reference' };
  sorted.forEach((f, idx) => {
    if (!f.type) return; // UYDURMA YOK — sınıflanmadıysa kart yazma (bulgu 2.2'de yine görünür)
    const info = lookupByType(f.type, locale);
    const det = findingDetail(f.type, locale);
    const sm = SEV_META[f.sev];
    // Açıklama = türe-özgü tanım + (varsa) GERÇEK uç nokta. NASIL TESPİT = önce GERÇEK kanıt (taranan
    // veriden), yoksa türe-özgü zararsız-gösterge yedeği. ÇALIŞAN EXPLOIT YOK — yalnız gösterge.
    const howText = (f.evidence && f.evidence.length > 8) ? f.evidence : det.how;
    blocks.push(`<div class="finding-block">
      <h3 id="s-fb-${idx + 1}">CT-${idx + 1} · ${escapeHtml(f.title)}${f.endpoint ? ` <span class="mt-ep">— ${escapeHtml(f.endpoint)}</span>` : ''}</h3>
      <div class="fb-meta"><span class="sev-badge badge-${f.sev}">${locale === 'tr' ? sm.tr : sm.en}</span> · ${L.state}</div>
      <p><strong>${L.desc}:</strong> ${escapeHtml(det.desc)}${f.endpoint ? ` <strong>${L.ep}:</strong> <code>${escapeHtml(f.endpoint)}</code>` : ''}</p>
      <p><strong>${L.how}:</strong> ${escapeHtml(howText)}</p>
      <p><strong>${L.impact}:</strong> ${escapeHtml(info.impact)}</p>
      <p><strong>${L.fix}:</strong> ${escapeHtml(det.fix)}</p>
      <p class="finding-ref"><strong>${L.ref}:</strong> ${escapeHtml(info.cwe)} · OWASP ${escapeHtml(info.owasp)}</p>
    </div>`);
  });
  if (!blocks.length) return '';
  return `<h2 id="s-detail">${locale === 'tr' ? '2.3 Detaylı Bulgular' : '2.3 Detailed Findings'}</h2>${blocks.join('')}`;
}

// (YÖNETİCİ ÖZETİ) İyileştirme Öncelikleri — parse edilen GERÇEK bulgulardan DETERMİNİSTİK 3 grup:
// En Acil (yüksek/kritik, config-dışı) · Hızlı Kazanım (sunucu/config, 1-2 gün) · Orta Vadeli (süreç/
// kod/manuel). UYDURMA YOK — bulgu yoksa madde yok. Yönetici "ne yapmalıyım"ı 30 saniyede alır.
const CONFIG_TYPES = new Set<FindingType>(['clickjacking', 'mime_sniffing', 'csp_missing', 'referrer_policy', 'hsts_missing', 'weak_tls', 'weak_key', 'cert', 'version_disclosure', 'spf', 'dmarc', 'dkim', 'dnssec', 'cors', 'cookie_flags', 'exposed_files', 'exposed_api_docs']);
function buildPriorities(rows: Finding[], locale: 'tr' | 'en'): string {
  if (!rows.length) return '';
  const rank: Record<Sev, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  const urgent: string[] = [], quick: string[] = [], process: string[] = [];
  [...rows].sort((a, b) => rank[a.sev] - rank[b.sev]).forEach((f) => {
    const name = f.title + (f.endpoint ? ` (${f.endpoint})` : '');
    if (f.type && CONFIG_TYPES.has(f.type)) quick.push(name);
    else if (f.sev === 'critical' || f.sev === 'high') urgent.push(name);
    else process.push(name);
  });
  const grp = (title: string, items: string[]) => items.length ? `<p class="pri-grp"><strong>${title}:</strong> ${escapeHtml(items.join('; '))}.</p>` : '';
  const body = grp(locale === 'tr' ? '⚡ En Acil / Öncelikli' : '⚡ Most Urgent', urgent)
    + grp(locale === 'tr' ? '🛠 Hızlı Kazanım (sunucu yapılandırması, ~1-2 gün)' : '🛠 Quick Wins (~1-2 days)', quick)
    + grp(locale === 'tr' ? '🗓 Orta Vadeli / Süreç (manuel doğrulama veya kod/mimari)' : '🗓 Medium-term / Process', process);
  if (!body) return '';
  return `<div class="priorities"><h3>${locale === 'tr' ? 'İyileştirme Öncelikleri' : 'Improvement Priorities'}</h3>${body}</div>`;
}

// (PREMIUM) Pozitif Güvence — "KONTROL ÖZETİ" tablosunda TEMİZ (✓ / kanıt yok / gösterge yok /
// vektör yok) çıkan kontrolleri tek blokta toplar. UYDURMA YOK: yalnız gerçekten çalıştırılıp temiz
// çıkanlar; kapsam-dışı olanlar hariç. Müşteri "neyin GÜVENLİ olduğunu" da görür.
function buildPositiveAssurance(md: string, locale: 'tr' | 'en'): string {
  const lines = md.split('\n');
  const clean: string[] = [];
  const seen = new Set<string>();
  let i = 0;
  while (i < lines.length) {
    if (!/^\s*\|.*\|\s*$/.test(lines[i])) { i++; continue; }
    const block: string[] = [];
    while (i < lines.length && /^\s*\|.*\|\s*$/.test(lines[i])) { block.push(lines[i]); i++; }
    if (block.length < 2) continue;
    const cells = (r: string) => r.replace(/^\s*\|/, '').replace(/\|\s*$/, '').split('|').map((c) => c.trim());
    const header = cells(block[0]).map((h) => h.toLocaleLowerCase('tr'));
    const kCol = header.findIndex((h) => /kontrol/.test(h));
    const sCol = header.findIndex((h) => /sonu[çc]/.test(h));
    if (kCol === -1 || sCol === -1) continue; // yalnız KONTROL ÖZETİ tablosu
    for (let r = 1; r < block.length; r++) {
      if (/^\s*\|[\s:|-]+\|\s*$/.test(block[r])) continue;
      const c = cells(block[r]);
      const sonuc = (c[sCol] ?? '').toLocaleLowerCase('tr');
      const isClean = /✓|kan[ıi]t yok|g[öo]sterge yok|vekt[öo]r yok|temiz/.test(sonuc);
      const scopeOut = /kapsam d|giri[şs] noktas[ıi] yok/.test(sonuc);
      if (!isClean || scopeOut) continue;
      const name = stripMd(c[kCol] ?? '');
      const key = name.toLocaleLowerCase('tr');
      if (!name || seen.has(key)) continue;
      seen.add(key);
      clean.push(name);
    }
  }
  if (clean.length < 2) return ''; // tek/hiç temiz kontrolde blok gösterme
  return `<div class="assurance"><h3>${locale === 'tr' ? 'Pozitif Güvence' : 'Positive Assurance'}</h3>
  <p>${locale === 'tr'
    ? `Şu kontroller çalıştırıldı ve belirgin bir zafiyet göstergesi bulunamadı: ${escapeHtml(clean.join(', '))}. Bu alanlar, tarama anındaki gözlemlerde temiz görünmektedir (kesin güvence için düzenli tekrar önerilir).`
    : `The following controls were executed with no significant vulnerability indicator: ${escapeHtml(clean.join(', '))}.`}</p></div>`;
}

// Ek — Sözlük: yalnız RAPORDA GEÇEN terimler (bloat yok).
const GLOSSARY_TERMS: Array<{ re: RegExp; term: string; tr: string; en: string }> = [
  { re: /\bSQLi\b|SQL enjeksiyon|SQL Injection/i, term: 'SQL Injection', tr: 'Kullanıcı girdisinin veritabanı sorgusuna karışabildiği bir enjeksiyon zafiyeti.', en: 'An injection flaw where user input reaches a database query.' },
  { re: /\bXSS\b|Cross-Site Scripting|yans[ıi]yan/i, term: 'XSS', tr: 'Cross-Site Scripting — sayfaya kötü amaçlı betik enjekte edilebilmesi.', en: 'Cross-Site Scripting — injection of malicious scripts into pages.' },
  { re: /\bIDOR\b/i, term: 'IDOR', tr: 'Yetkisiz Nesne Erişimi — kimlik parametresiyle başka kaydın erişilebilmesi.', en: 'Insecure Direct Object Reference — accessing others’ records via ID manipulation.' },
  { re: /\bSSRF\b/i, term: 'SSRF', tr: 'Server-Side Request Forgery — sunucuyu istenmeyen isteklere zorlama.', en: 'Server-Side Request Forgery.' },
  { re: /\bCSRF\b/i, term: 'CSRF', tr: 'Cross-Site Request Forgery — kullanıcının istemsiz işlem yapmasını sağlama.', en: 'Cross-Site Request Forgery.' },
  { re: /\bCWE\b/i, term: 'CWE', tr: 'Common Weakness Enumeration — zafiyet türleri sınıflandırması.', en: 'Common Weakness Enumeration.' },
  { re: /\bOWASP\b/i, term: 'OWASP', tr: 'Açık web uygulama güvenliği topluluğu; Top 10 ve test kılavuzlarıyla bilinir.', en: 'Open Web Application Security Project.' },
  { re: /\bTLS\b|SSL/i, term: 'TLS', tr: 'Taşıma katmanı şifrelemesi (HTTPS’in temeli).', en: 'Transport Layer Security.' },
  { re: /\bHSTS\b|Strict-Transport-Security/i, term: 'HSTS', tr: 'Tarayıcıyı yalnız HTTPS kullanmaya zorlayan güvenlik başlığı.', en: 'HTTP Strict Transport Security header.' },
  { re: /\bCSP\b|Content-Security-Policy/i, term: 'CSP', tr: 'İçerik Güvenlik Politikası — XSS/enjeksiyon azaltma başlığı.', en: 'Content Security Policy.' },
  { re: /\bCORS\b/i, term: 'CORS', tr: 'Kaynaklar-arası paylaşım politikası; gevşek yapılandırma risklidir.', en: 'Cross-Origin Resource Sharing.' },
  { re: /\bJWT\b/i, term: 'JWT', tr: 'JSON Web Token — oturum/yetki taşıyan imzalı belirteç.', en: 'JSON Web Token.' },
  { re: /\bKVKK\b/i, term: 'KVKK', tr: 'Kişisel Verilerin Korunması Kanunu (Türkiye).', en: 'Turkish Personal Data Protection Law.' },
  { re: /VERB[İi]S/i, term: 'VERBİS', tr: 'Veri Sorumluları Sicil Bilgi Sistemi (KVKK kayıt sistemi).', en: 'Turkish data controllers’ registry.' },
  { re: /clickjacking|X-Frame-Options/i, term: 'Clickjacking', tr: 'Sayfanın görünmez iframe içine alınıp kullanıcı tıklamalarının kandırılması.', en: 'Tricking clicks via invisible framing.' },
  { re: /forced browsing|yetki y[üu]kseltme/i, term: 'Forced Browsing', tr: 'Menüde olmayan (ör. yönetici) uç noktalara URL bilerek erişme.', en: 'Accessing hidden endpoints by guessing URLs.' },
];
function buildGlossary(md: string, locale: 'tr' | 'en'): string {
  const hits = GLOSSARY_TERMS.filter((g) => g.re.test(md));
  if (hits.length === 0) return '';
  const rows = hits.map((g) => `<tr><td><strong>${escapeHtml(g.term)}</strong></td><td>${escapeHtml(locale === 'tr' ? g.tr : g.en)}</td></tr>`).join('');
  return `<h2 id="s-glossary">${locale === 'tr' ? 'Ek — Sözlük' : 'Appendix — Glossary'}</h2>
  <table class="glossary"><tbody>${rows}</tbody></table>`;
}

// TOC için: içerik HTML'indeki h1/h2 başlıklara id ata + sıralı (id,metin) listesi çıkar (ana
// bölümler; h3 alt-başlıklar TOC'a girmez). Var olan id'ler korunur.
function injectTocIds(html: string): { html: string; entries: { id: string; text: string }[] } {
  const entries: { id: string; text: string }[] = [];
  let n = 0;
  const out = html.replace(/<(h1|h2)([^>]*)>([\s\S]*?)<\/\1>/g, (_m, tag, attrs, inner) => {
    let id = (attrs.match(/id="([^"]+)"/) || [])[1];
    if (!id) { id = `toc-${++n}`; attrs = ` id="${id}"${attrs}`; }
    const text = String(inner).replace(/<[^>]+>/g, '').replace(/&amp;/g, '&').replace(/🔒|🔓/g, '').trim();
    if (text) entries.push({ id, text });
    return `<${tag}${attrs}>${inner}</${tag}>`;
  });
  return { html: out, entries };
}
// TOC: temiz bölüm listesi (numaralı). Sayfa no YAZMIYORUZ — Chromium target-counter'ı
// desteklemiyor ve Y-tahmini sayfa sınırlarında ±1 sapıyor; YANLIŞ sayfa no yazmak "uydurma
// sayı yasağı"na aykırı olurdu. Bölüm adları + tıklanır bağlantı (PDF içi) verilir.
function buildTocPage(entries: { id: string; text: string }[], locale: 'tr' | 'en'): string {
  // TEK numaralandırma: başlık metnindeki manuel "1./2./2.1" ön-eki kullanılır (otomatik <ol> sayacı
  // EKLENMEZ -> "1. 1. Yönetici Özeti" çakışması biter). "N.N" alt bölümler girintili gösterilir.
  const rows = entries.map((e) => {
    const sub = /^\d+\.\d+\s/.test(e.text.trim());
    return `<div class="toc-row${sub ? ' toc-sub' : ''}"><a href="#${e.id}">${escapeHtml(e.text)}</a></div>`;
  }).join('');
  return `<div class="toc-page"><h1>${locale === 'tr' ? 'İçindekiler' : 'Table of Contents'}</h1>${rows}</div>`;
}

// Tekrar eden AYNI blockquote'ları (ör. her kontrolden sonra kelime-kelime tekrarlanan
// "Kapsam ve yöntem" notu) BİR kereye indir — ilkini tut, sonrakileri kaldır.
function dedupeBlockquotes(html: string): string {
  const seen = new Set<string>();
  return html.replace(/<blockquote>[\s\S]*?<\/blockquote>/g, (m) => {
    const key = m.replace(/\s+/g, ' ').trim().toLocaleLowerCase('tr');
    if (key.length < 60) return m; // kısa notları tekilleştirme (yanlış-pozitif önle)
    if (seen.has(key)) return '';
    seen.add(key);
    return m;
  });
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
  // (JARGON) İç motor adı "PentAGI" müşteri-görünür metinde geçmesin.
  effectiveMd = sanitizeJargon(effectiveMd);

  // Bulgu parse'ı ÖNCE (rozet tutarlılığı için gerekli): uyum paketleri severity'li ZAFİYET
  // değil hazırlık ön-değerlendirmesidir -> dağılım/master GÖSTERİLMEZ.
  const isCompliance = ['kvkk_hazirlik', 'bundle_compliance', 'pci_hazirlik', 'iso27001_hazirlik'].includes(meta.packageKey ?? '');
  const parsed = isCompliance ? null : parseFindings(effectiveMd, meta.locale);

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
    // (ROZET TUTARLILIĞI) Severity'li AKTİF bulgu YOK (master "Temiz") ama rozet Yüksek diyorsa
    // çelişki doğuyor (config/başlık eksikleri "zafiyet" değildir). 0 bulguda Yüksek'i "İyileştirilebilir"e
    // indir -> rozet ↔ master TUTARLI. (Orta/Düşük dokunulmaz; Basit'in "Temiz+Orta" hali korunur.)
    if (parsed && parsed.rows.length === 0 && (risk.level === 'high' || risk.level === 'medium-high')) {
      risk.level = 'medium';
      risk.label = meta.locale === 'tr' ? 'İyileştirilebilir' : 'Improvable';
    }
    assessBox = `<div class="assess assess-${risk.level}">
    <div class="assess-head"><span class="assess-title">${escapeHtml(t.assessTitle)}</span>
      <span class="risk-badge risk-${risk.level}">${escapeHtml(risk.label)}</span></div>
    <p class="assess-body">${escapeHtml(risk.sentence)}</p></div>`;
  }
  const fixTitle = isKvkk ? 'Önerilen Aksiyonlar' : t.fixTitle;
  const loc = meta.locale;

  // Ek Pasif Kontroller (kod-tabanli) — AYRI blok (ana bulgulardan görsel olarak ayrı).
  const extrasHtml = opts.extrasMarkdown && opts.extrasMarkdown.trim()
    ? `<div class="extras-section">${md.render(opts.extrasMarkdown)}</div>` : '';

  // AI ÇÖZÜM ÖNERİLERİ (bölüm 4) — 3 DURUM: (1) unlock+içerik -> göster; (2) kilitli -> upsell;
  // (3) içerik yok -> nazik not. GERÇEK=kilitli / ÖRNEK=açık mantığı DEĞİŞMEZ.
  let fixHtml = '';
  if (opts.fixMarkdown && opts.fixMarkdown.trim()) {
    fixHtml = `<div class="fix-section"><h2 id="s-ai">${escapeHtml(fixTitle)}</h2>${md.render(opts.fixMarkdown)}</div>`;
  } else if (opts.fixLocked) {
    fixHtml = `<div class="fix-locked"><h2 id="s-ai">🔒 ${escapeHtml(fixTitle)}</h2><p>${escapeHtml(t.fixLocked)}</p><p class="fix-cta">${escapeHtml(t.fixLockedCta)}</p></div>`;
  } else if (!isKvkk) {
    fixHtml = `<div class="fix-locked"><h2 id="s-ai">🔒 ${escapeHtml(fixTitle)}</h2><p>${escapeHtml(t.fixEmpty)}</p><p class="fix-cta">${escapeHtml(t.fixLockedCta)}</p></div>`;
  }

  // (PROFESYONEL İSKELET) TÜRETİLEN bölümler — gövde/ton/disclaimer DEĞİŞMEZ.
  const { reportNo, verifyCode } = reportIdentifiers(meta.hostname, meta.createdAt);
  // (parsed/isCompliance yukarıda hesaplandı — rozet tutarlılığı için.)
  // (DÜRÜSTLÜK) Hedefe ulaşılamadı/tarama yürütülemedi -> master "Temiz" DEĞİL "İncelenemedi",
  // dağılımdaki 0'lar "temiz" değil "incelenemedi" olarak işaretlenir. (assessBasit rozeti zaten nötr yapıyor.)
  const unscannable = /risk\s*seviyesi\s*[:：]\s*\*{0,2}\s*incelenemedi|tarama\s*(yap[ıi]lamad|y[uü]r[uü]t[uü]lemed)|ula[şs][ıi]lamad[ıi][ğg][ıi] i[çc]in kontrol/.test(effectiveMd.slice(0, 2000).toLocaleLowerCase('tr'));
  const distMasterHtml = parsed ? buildDistribution(parsed.counts, loc, unscannable) + buildMasterTable(parsed.rows, loc, unscannable) : '';
  // 2.3 Detaylı Bulgular (İş Etkisi + CWE) yalnız GERÇEK raporlarda; örneklerde (assessOverride) kendi var.
  const detailedHtml = parsed && !opts.assessOverride ? buildDetailedFindings(parsed.rows, loc) : '';
  // (PREMIUM) Pozitif Güvence — KONTROL ÖZETİ'ndeki TEMİZ (✓) kontrollerden türetilir (uydurma yok).
  const isPremium = ['bundle_active_verify', 'bundle_full_pentest'].includes(meta.packageKey ?? '');
  const assuranceHtml = isPremium && !opts.assessOverride ? buildPositiveAssurance(effectiveMd, loc) : '';
  const glossaryHtml = buildGlossary(effectiveMd, loc);
  const notCert = loc === 'tr' ? 'Bu rapor resmi sızma testi / sertifikasyon değildir.' : 'This report is not a formal penetration test / certification.';
  const sealTitle = loc === 'tr' ? 'CyberTestify Güvenlik Taraması — Tamamlandı' : 'CyberTestify Security Scan — Completed';

  // (TEK YAPI) effectiveMd'yi ## bölümlerine ayır; İÇERİK SİLİNMEZ, DOĞRU bölüme TAŞINIR:
  // - "YÖNETİCİ ÖZETİ" -> 1. Yönetici Özeti (öne alınır)
  // - "GENEL DEĞERLENDİRME" -> ATILIR (üst risk kutusuyla MÜKERRER; kutu kalır)
  // - "ÖNCELİKLİ AKSİYONLAR" -> 1.2 İyileştirme Öncelikleri
  // - kontrol detayları / metodoloji / sonraki adımlar / yasal -> 3. Kontrol Özeti ve Metodoloji (H3'e indirilir; TOC temiz)
  const summaryParts: string[] = [];
  const detailParts: string[] = [];
  let hasExec = false;
  for (const chunk of effectiveMd.split(/\n(?=##\s)/)) {
    const hm = chunk.match(/^##\s+(.+?)\s*(?:\n|$)/);
    const tt = hm ? stripMd(hm[1]).toLocaleLowerCase('tr') : '';
    if (!tt) { if (chunk.trim()) detailParts.push(chunk.replace(/^###\s/gm, '#### ').replace(/^##\s/gm, '### ')); continue; }
    if (/^bulgular$/.test(tt)) continue; // boş "## Bulgular" wrapper
    if (/y[öo]netici [öo]zeti|executive summary/.test(tt)) { hasExec = true; summaryParts.push(chunk.replace(/^##[^\n]*\n?/, '').trim()); continue; }
    if (/genel de[ğg]erlendirme|overall assessment/.test(tt)) continue; // MÜKERRER -> at
    if (/[öo]ncelikli aksiyonlar|priority actions|iyile[şs]tirme [öo]ncelik/.test(tt)) { summaryParts.push(chunk.replace(/^###\s/gm, '#### ').replace(/^##\s/gm, '### ')); continue; }
    detailParts.push(chunk.replace(/^###\s/gm, '#### ').replace(/^##\s/gm, '### ')); // detay -> H3
  }
  const reorganize = hasExec && !opts.assessOverride;
  const H2 = (id: string, tr: string, en: string) => `<h2 id="${id}">${escapeHtml(loc === 'tr' ? tr : en)}</h2>`;

  let contentInner0: string;
  if (reorganize) {
    // (KAPSAM-DIŞI SADELEŞTİRME) Hedefin mimarisine UYMAYAN / giriş noktası olmayan kontroller
    // (bulgu YOK) yarım-sayfa "NE KONTROL EDİLDİ/BULGULAR" bloğu olarak açılmasın; TEK "İnceleme
    // Notu" kutusunda toplanır. GERÇEKTEN çalışan (⚠ gösterge/bulgu olan) kontroller TAM blok kalır.
    const scopeOut: string[] = [];
    const keptDetail = detailParts.filter((chunk) => {
      const hm = chunk.match(/^###\s+(.+?)\s*(?:\n|$)/);
      const name = hm ? stripMd(hm[1]).trim() : '';
      const isControlBlock = /NE KONTROL ED[İi]LD[İi]|####?\s*BULGULAR/i.test(chunk);
      const isScopeOut = /kapsam d[ıi][şs][ıi]|uygulanabilir giri[şs] noktas[ıi] yok|giri[şs] noktas[ıi] yok/i.test(chunk);
      // GERÇEK bulgu = tabloda ŞİDDET satırı ("… | Yüksek |"). "zafiyet göstergesi bulunamadı" prozunu
      // yanlışlıkla bulgu sayma (yanlış-negatif collapse'ı önle).
      const hasSevRow = /^\s*\|.*\b(y[üu]ksek|orta|d[üu][şs][üu]k|krit[iı]k)\b.*\|\s*$/im.test(chunk);
      if (name && isControlBlock && isScopeOut && !hasSevRow) { scopeOut.push(name); return false; }
      return true;
    });
    const scopeNote = scopeOut.length
      ? `<div class="scope-note"><strong>${loc === 'tr' ? 'İnceleme Notu' : 'Review Note'}:</strong> ${loc === 'tr'
          ? `Şu kontroller, hedefin mimarisine uygulanabilir bir giriş noktası bulunmadığından mimari gereği kapsam dışı bırakılmıştır (Kontrol Özeti tablosunda da işaretlidir): ${escapeHtml(scopeOut.join(', '))}.`
          : `The following controls were excluded as no applicable entry point exists for the target architecture (also marked in the Control Summary): ${escapeHtml(scopeOut.join(', '))}.`}</div>`
      : '';
    // (YÖNETİCİ ÖZETİ KISALTMA) Bulgusu olan raporlarda özetteki uzun per-kontrol madde listesini AT
    // (bilgi §3 KONTROL ÖZETİ tablosunda AYNEN durur — veri kaybı yok, tekrar önlenir) + türetilmiş
    // İyileştirme Öncelikleri ekle. Bulgusuz raporlarda özet zaten kısa -> dokunma.
    const hasVuln = !!(parsed && parsed.rows.length);
    let execMd = summaryParts.join('\n\n');
    if (hasVuln) {
      execMd = execMd.split('\n').filter((line) => {
        const bm = line.match(/^\s*[-*]\s+\*\*(.+?):\*\*/);
        if (!bm) return true; // madde değil -> tut
        return /genel risk|kapsam|[öo]nerilen/.test(bm[1].toLocaleLowerCase('tr')); // yalnız üst-düzey madde tut
      }).join('\n');
    }
    const summaryBody = dedupeBlockquotes(md.render(execMd)) + (hasVuln ? buildPriorities(parsed!.rows, loc) : '');
    const detailBody = scopeNote + dedupeBlockquotes(md.render(keptDetail.join('\n\n')));
    const hasFindings = !!(distMasterHtml || detailedHtml);
    const findingsSection = hasFindings ? H2('s-findings', '2. Bulgular', '2. Findings') + distMasterHtml + detailedHtml + assuranceHtml : '';
    const cn = hasFindings ? 3 : 2; // bulgu bölümü yoksa (uyum) numara boşluğu olmasın
    // AI ve Ekler bölümlerini de numarala (TOC tek-numara okur) — kilit emojisi korunur.
    const fixNum = fixHtml.replace(/<h2 id="s-ai">(🔒 )?/, (_m, lock) => `<h2 id="s-ai">${lock ?? ''}${cn + 1}. `);
    const glossNum = glossaryHtml.replace(/<h2 id="s-glossary">/, `<h2 id="s-glossary">${cn + 2}. `);
    // (TOC HİZASI) "Ek Pasif Kontroller" bölümü §3 (Kontrol Özeti) altında bir alt-bölümdür ->
    // h3'e indir ki TOC'ta ayrı numarasız satır olarak görünüp numaralandırmayı bozmasın.
    const extrasSub = extrasHtml.replace(/<h2\b/g, '<h3').replace(/<\/h2>/g, '</h3>');
    contentInner0 =
      H2('s-summary', '1. Yönetici Özeti', '1. Executive Summary') + assessBox + summaryBody +
      findingsSection +
      H2('s-controls', `${cn}. Kontrol Özeti ve Metodoloji`, `${cn}. Controls & Methodology`) + detailBody +
      extrasSub + fixNum + glossNum;
  } else {
    // Yapısız gövde / örnek PDF: mevcut akış (assessBox + dağılım/master + gövde + AI + sözlük).
    const bodyHtml = dedupeBlockquotes(md.render(effectiveMd) + extrasHtml + fixHtml);
    contentInner0 = `${assessBox}${distMasterHtml}${detailedHtml}${bodyHtml}${glossaryHtml}`;
  }
  const { html: contentInner, entries: tocEntries } = injectTocIds(contentInner0);
  const tocPage = buildTocPage(tocEntries, meta.locale);

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
  /* ---- KAPAK SAYFASI (markalı, page-break-after) ---- */
  .cover { height: 262mm; display: flex; flex-direction: column; justify-content: space-between;
    background: linear-gradient(160deg, #0A2E2A 0%, #123F3A 55%, #0d332e 100%); color: #EEF5F3;
    padding: 30px 40px 26px; page-break-after: always; }
  .cover-top { display: flex; align-items: center; gap: 12px; }
  .cover-top .brand { font-size: 22px; font-weight: 700; color: #fff; }
  .cover-top .brand span { color: #F5A623; }
  .cover-mid { text-align: center; margin-top: -30px; }
  .cover-datebadge { display: inline-block; border: 1px solid #5FA396; color: #9Fc4bc; border-radius: 14px;
    padding: 4px 14px; font-size: 12px; font-weight: 600; }
  .cover-title { font-size: 40px; font-weight: 800; color: #fff; margin: 16px 0 6px; letter-spacing: .5px; }
  .cover-sub { font-size: 15px; color: #B9D6CE; }
  .cover-seal { margin: 34px auto 0; max-width: 380px; border: 1.5px solid #F5A623; border-radius: 12px;
    padding: 16px 18px; background: rgba(245,166,35,.06); }
  .cover-seal .seal-title { font-size: 13.5px; font-weight: 800; color: #F5A623; margin-bottom: 8px; }
  .cover-seal .seal-row { font-size: 12px; color: #DCEAE6; margin: 2px 0; font-variant-numeric: tabular-nums; }
  .cover-foot { text-align: center; font-size: 10.5px; color: #7FB0A6; border-top: 1px solid rgba(255,255,255,.12); padding-top: 12px; }
  /* ---- İÇİNDEKİLER ---- */
  .toc-page { padding: 30px 40px; page-break-after: always; }
  .toc-page h1 { font-size: 24px; border: none; color: #123F3A; margin-bottom: 18px; }
  .toc-row { margin: 7px 0; font-size: 12.5px; border-bottom: 1px dotted #E1ECE8; padding-bottom: 5px; }
  .toc-row.toc-sub { border-bottom: none; margin: 3px 0 3px 22px; padding-bottom: 0; font-size: 12px; }
  .toc-row a { color: #14514A; text-decoration: none; font-weight: 600; }
  .toc-row.toc-sub a { color: #35618a; font-weight: 500; }
  /* ---- 2.1 Zafiyet Dağılımı ---- */
  .dist-chart { display: flex; align-items: flex-end; gap: 20px; height: 108px; padding: 6px 10px 0;
    border-bottom: 2px solid #DCEAE6; margin: 10px 0 6px; }
  .dist-col { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: flex-end; height: 100%; }
  .dist-num { font-size: 14px; font-weight: 800; color: #123F3A; margin-bottom: 4px; }
  .dist-bar { width: 64%; min-height: 3px; border-radius: 4px 4px 0 0; }
  .dist-lbl { margin-top: 6px; font-size: 11px; font-weight: 600; color: #14514A; }
  .sev-critical-bg { background: #B3261E; } .sev-high-bg { background: #D64545; }
  .sev-medium-bg { background: #E0940E; } .sev-low-bg { background: #9AA0A6; }
  /* ---- 2.2 Master tablo + Sözlük ---- */
  .priorities { margin: 12px 0 6px; padding: 12px 16px; background: #FBFDFC; border: 1px solid #DCEAE6; border-left: 4px solid #F5A623; border-radius: 8px; }
  .priorities h3 { margin: 0 0 6px; color: #123F3A; font-size: 13px; }
  .priorities .pri-grp { margin: 5px 0; font-size: 11.5px; }
  .assurance { margin: 14px 0 6px; padding: 12px 16px; background: #EEF7F1; border: 1px solid #CFE5DB; border-left: 4px solid #1C6B60; border-radius: 8px; }
  .assurance h3 { margin: 0 0 5px; color: #14514A; font-size: 13px; }
  .assurance p { margin: 0; font-size: 11.5px; color: #274b41; }
  .scope-note { margin: 10px 0 14px; padding: 10px 14px; background: #F3F7FA; border: 1px solid #C9DCE8;
    border-left: 4px solid #2B6C9B; border-radius: 6px; font-size: 11.5px; color: #274b63; }
  .mt-ep { color: #5b6b67; font-weight: 400; font-size: 10.5px; }
  .finding-block code { background: #EEF5F3; padding: 1px 5px; border-radius: 3px; font-size: 10.5px; word-break: break-all; }
  /* (TABLO TAŞMA) uzun uç nokta/path hücreyi taşırmasın; satır kaymasın. */
  td { overflow-wrap: anywhere; word-break: break-word; }
  td code { overflow-wrap: anywhere; word-break: break-all; }
  table.master td:first-child, table.master th:first-child { white-space: nowrap; width: 46px; }
  table.master td:nth-child(3), table.master th:nth-child(3) { white-space: nowrap; width: 74px; }
  table.glossary th { display: none; }
  table.glossary td:first-child { white-space: nowrap; width: 130px; color: #14514A; }
  /* ---- 2.3 Detaylı Bulgular (İş Etkisi + Referans) ---- */
  .finding-block { border: 1px solid #DCEAE6; border-left: 4px solid #5FA396; border-radius: 8px;
    padding: 8px 14px 10px; margin: 10px 0; background: #FBFDFC; page-break-inside: avoid; }
  .finding-block h3 { margin: 2px 0 4px; color: #123F3A; font-size: 13px; }
  .finding-block .fb-meta { font-size: 10.5px; color: #5b6b67; margin-bottom: 4px; }
  .finding-block p { margin: 4px 0; font-size: 11.5px; }
  .finding-block .finding-ref { font-size: 10.5px; color: #35618a; }
  .badge-critical { background: #B3261E; } .badge-high { background: #D64545; }
  .badge-medium { background: #E0940E; } .badge-low { background: #9AA0A6; }
</style></head>
<body>
  <div class="cover">
    <div class="cover-top">${LOGO_SVG}<div class="brand">Cyber<span>Testify</span></div></div>
    <div class="cover-mid">
      <div class="cover-datebadge">${escapeHtml(dateStr)}</div>
      <div class="cover-title">${escapeHtml(t.brandTagline)}</div>
      <div class="cover-sub">${escapeHtml(meta.hostname)} &nbsp;·&nbsp; ${escapeHtml(meta.packageName)}</div>
      <div class="cover-seal">
        <div class="seal-title">${escapeHtml(sealTitle)}</div>
        <div class="seal-row">${meta.locale === 'tr' ? 'Rapor No' : 'Report No'}: <strong>${reportNo}</strong></div>
        <div class="seal-row">${meta.locale === 'tr' ? 'Doğrulama Kodu' : 'Verification Code'}: <strong>${verifyCode}</strong></div>
        <div class="seal-row">${escapeHtml(t.date)}: ${escapeHtml(dateStr)}</div>
      </div>
    </div>
    <div class="cover-foot">${escapeHtml(notCert)}</div>
  </div>
  ${tocPage}
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
    <div><div class="k">${meta.locale === 'tr' ? 'Rapor No' : 'Report No'}</div><div class="v">${reportNo}</div></div>
  </div>
  <div class="content">${contentInner}</div>
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
  const { reportNo } = reportIdentifiers(meta.hostname, meta.createdAt);
  const confidential = meta.locale === 'tr' ? 'Gizli' : 'Confidential';

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
      // (HER SAYFA) CyberTestify | Gizli | Rapor No: CT-… | Sayfa X / Y
      footerTemplate: `
        <div style="width:100%; font-size:8px; color:#5FA396; padding:0 12mm;
                    display:flex; justify-content:space-between; align-items:center;">
          <span style="max-width:78%;">CyberTestify | ${escapeHtml(confidential)} | ${escapeHtml(t.footerLegal)}</span>
          <span>${escapeHtml(reportNo)} &nbsp;·&nbsp; ${escapeHtml(t.page)} <span class="pageNumber"></span>/<span class="totalPages"></span></span>
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
