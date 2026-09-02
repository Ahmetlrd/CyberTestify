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
  locale: 'tr' | 'en' | 'de';
}

export interface ReportPdfOptions {
  fixMarkdown?: string | null; // unlock edilmisse fix onerileri Markdown'i
  fixLocked?: boolean; // fix onerisi VAR ama satin alinmamis (kilitli goster)
  extrasMarkdown?: string | null; // Ek Pasif Kontroller (kod-tabanli) — ayri/renkli bolum
  // (ORNEK PDF) Ust "Genel Degerlendirme" kutusunun risk seviyesini AÇIKÇA belirle. Yalnizca
  // ORNEK raporlar kullanir (statik govdedeki risk severity-parse'a takilmayabilir); GERCEK
  // raporlar bunu ASLA gecmez -> onlarin assessRisk/assessBasit mantigi AYNEN korunur.
  assessOverride?: { level: 'high' | 'medium' | 'low'; sentence?: string } | null;
  // (ORNEK PDF) Ornek raporlarda HIC tarih gosterme: kapak rozeti, muhur "Tarih:" satiri ve ust
  // banner "Tarih" alani gizlenir; Rapor No da tarih icermeyen "CT-ÖRNEK-XXXX" formatina doner.
  // GERCEK raporlar bunu ASLA gecmez -> tarih/rapor-no mantigi aynen korunur.
  hideDate?: boolean;
  // (ORNEK PDF) Ornek raporun basina belirgin bir uyari afisi koyar ( or. "bilerek zafiyetli test
  // uygulamasi"). Yalnizca sample-report yolu kullanir; GERCEK musteri raporlari ASLA gecmez.
  sampleNotice?: string | null;
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
    footerLegal: 'Otomatik güvenlik tarama raporu — resmi denetim/sertifikasyon değildir. Gizlidir.',
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
    footerLegal: 'Automated security scan report — not an official audit/certification. Confidential.',
    page: 'Page',
    assessTitle: 'Overall Assessment',
    riskHigh: 'High Risk', riskMedium: 'Medium Risk', riskMediumHigh: 'Medium-High Risk', riskLow: 'Low Risk',
    assessHigh: 'This scan surfaced critical security findings that require prompt action; they should be prioritised.',
    assessMedium: 'This scan surfaced important security findings that should be addressed in the near term.',
    assessLow: 'This scan did not surface a serious/critical vulnerability; the report lists improvement opportunities.',
  },
  de: {
    brandTagline: 'Automatisierter Sicherheits-Scan-Bericht',
    target: 'Ziel', pkg: 'Paket', date: 'Datum',
    fixTitle: 'KI-Lösungsempfehlungen',
    fixLocked: 'Dieser Premium-Abschnitt enthält für JEDEN oben festgestellten Befund eine Schritt-für-Schritt-Behebung sowie einsatzbereite Konfigurationsbeispiele (Nginx-/Servereinstellungen, Sicherheitsheader usw.).',
    fixLockedCta: '🔓 Erwerben Sie das Add-on „KI-Lösungsempfehlungen“, um ihn freizuschalten.',
    fixEmpty: 'Für diesen Scan konnten keine detaillierten Behebungsempfehlungen erzeugt werden. Das Add-on „KI-Lösungsempfehlungen“ liefert für jeden Befund eine Schritt-für-Schritt-Behebung und einsatzbereite Konfigurationsbeispiele.',
    footerLegal: 'Automatisierter Sicherheits-Scan-Bericht — kein offizielles Audit / keine Zertifizierung. Vertraulich.',
    page: 'Seite',
    assessTitle: 'Gesamtbewertung',
    riskHigh: 'Hohes Risiko', riskMedium: 'Mittleres Risiko', riskMediumHigh: 'Mittleres bis hohes Risiko', riskLow: 'Geringes Risiko',
    assessHigh: 'Dieser Scan hat kritische Sicherheitsbefunde zutage gefördert, die umgehendes Handeln erfordern; sie sollten priorisiert werden.',
    assessMedium: 'Dieser Scan hat wichtige Sicherheitsbefunde zutage gefördert, die kurzfristig behoben werden sollten.',
    assessLow: 'Dieser Scan hat keine schwerwiegende/kritische Schwachstelle zutage gefördert; der Bericht listet Verbesserungsmöglichkeiten auf.',
  },
} as const;

// Rapor metnindeki siddet sinyallerinden GENEL RISK seviyesi turetir (ek LLM YOK).
// NEGASYON-FARKINDA: "KRITIK: Tespit edilmemistir" gibi "yok" ifadeleri sayilmaz;
// oncelikle etiketli bulgu siddeti ("Siddet: Orta" / "Severity: High") aranir, yoksa
// negasyonla-elenen bolum basliklari. applicability ("Uygulanabilirlik: YUKSEK") sayilmaz.
function assessRisk(md: string, locale: 'tr' | 'en' | 'de'): { level: 'high' | 'medium' | 'low'; label: string; sentence: string } {
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
  locale: 'tr' | 'en' | 'de' = 'tr',
): { level: 'high' | 'medium-high' | 'medium' | 'low'; label: string; sentence: string } {
  const mk = (level: 'high' | 'medium-high' | 'medium' | 'low') => ({
    level,
    label: level === 'high' ? t.riskHigh : level === 'medium-high' ? t.riskMediumHigh : level === 'medium' ? t.riskMedium : t.riskLow,
    sentence:
      level === 'high'
        ? p3(locale, 'Ziyaretçilere doğrudan güvenlik uyarısı gösterebilecek acil bir sorun (ör. sertifika süresi/hostname) tespit edildi; öncelikli olarak giderilmesi önerilir.', 'An urgent issue that can show visitors a direct security warning (e.g. certificate validity/hostname) was detected; it should be fixed with priority.', 'Ein dringendes Problem, das Besuchern eine direkte Sicherheitswarnung anzeigen kann (z. B. Zertifikatsgültigkeit/Hostname), wurde festgestellt; es sollte vorrangig behoben werden.')
        : level === 'medium-high'
          ? p3(locale, 'Öncelikli giderilmesi önerilen, tek başına yüksek etkili bir yapılandırma eksikliği tespit edildi.', 'A single high-impact configuration gap recommended for priority remediation was detected.', 'Eine einzelne, stark wirksame Konfigurationslücke wurde festgestellt, deren vorrangige Behebung empfohlen wird.')
          : level === 'medium'
            ? p3(locale, 'Öncelikli giderilmesi önerilen önemli güvenlik başlığı eksiklikleri tespit edildi; taşıma güvenliği (TLS) genel olarak sağlam.', 'Important security-header gaps recommended for priority remediation were detected; transport security (TLS) is generally sound.', 'Wichtige Lücken bei Sicherheitsheadern wurden festgestellt, deren vorrangige Behebung empfohlen wird; die Transportsicherheit (TLS) ist insgesamt solide.')
            : p3(locale, 'Ciddi/kritik bir güvenlik açığı öne çıkmadı; rapor yalnızca küçük iyileştirme fırsatlarını listeler.', 'No serious/critical vulnerability stood out; the report lists only minor improvement opportunities.', 'Es ist keine schwerwiegende/kritische Schwachstelle hervorgetreten; der Bericht listet nur geringfügige Verbesserungsmöglichkeiten auf.'),
  });

  // (0) TARANAMADI/İNCELENEMEDİ: hedefe hiç ulaşılamadıysa bu "temiz/düşük" DEĞİLDİR. Nötr bir
  //     "İncelenemedi" rozeti göster (amber; ASLA yeşil-düşük). "Güvenli" imasından kaçınır.
  // NOT: Türkçe "İ" (U+0130) JS'te /i flag'iyle "i"ye eşlenmez -> önce tr-locale ile küçült.
  if (/risk\s*seviyesi\s*[:：]\s*\*{0,2}\s*incelenemedi|risikostufe\s*[:：]\s*\*{0,2}\s*nicht\s*pr[üu]fbar|tarama\s*(yap[ıi]lamad|y[uü]r[uü]t[uü]lemed)|ula[şs][ıi]lamad[ıi][ğg][ıi] i[çc]in kontrol/.test(md.slice(0, 1500).toLocaleLowerCase('tr'))) {
    return { level: 'medium', label: p3(locale, 'İncelenemedi', 'Not scanned', 'Nicht geprüft'), sentence: p3(locale, 'Hedefe ulaşılamadığı için tarama yürütülemedi; bu sonuç sitenin GÜVENLİ olduğu anlamına GELMEZ. Erişim sağlanınca yeniden taranmalıdır.', 'The scan could not run because the target was unreachable; this result does NOT mean the site is SECURE. It should be re-scanned once reachable.', 'Der Scan konnte nicht ausgeführt werden, da das Ziel nicht erreichbar war; dieses Ergebnis bedeutet NICHT, dass die Website SICHER ist. Sie sollte erneut gescannt werden, sobald sie erreichbar ist.') };
  }

  // (1) Rapor KOD-yazimi oldugundan GENEL DEĞERLENDİRME'deki ACIK "Risk Seviyesi: X"i oku —
  //     tek dogruluk kaynagi; rozet ile metin GARANTI tutarli. "Orta-Yüksek" ONCE eslesmeli.
  // (3 BÖLGE) Türkçe "Risk Seviyesi" + Almanca "Risikostufe" + İngilizce "Risk Level".
  const m = md.slice(0, 1500).match(/(?:risk\s*seviyesi|risikostufe|risk\s*level)\s*[:：]\s*\**\s*(orta[-\s]?y[uü]ksek|kr[iİ]t[iİ]k|y[uü]ksek|orta|d[uü][sş][uü]k|mittel[-\s]?hoch|kritisch|hoch|mittel|niedrig|medium[-\s]?high|critical|high|medium|low)/i);
  if (m) {
    const kw = lcMatch(m[1]); // I-güvenli: "High"->"high" (tr-locale "hıgh" olurdu)
    if (/orta[-\s]?y[uü]ksek|mittel[-\s]?hoch|medium[-\s]?high/.test(kw)) return mk('medium-high');
    if (/kr[iı]t[iı]k|y[uü]ksek|kritisch|hoch|critical|high/.test(kw)) return mk('high');
    if (/^orta$|^mittel$|^medium$/.test(kw)) return mk('medium');
    if (/d[uü][sş][uü]k|niedrig|low/.test(kw)) return mk('low');
  }

  // (2) Acik ifade yoksa (eski/ajan raporu): HTTP baslik tablosundan turet.
  const { present, absent } = parseBasitHeaders(md);
  if (present.size + absent.size === 0) return assessRisk(md, locale); // (3) son care — locale KORUNUR (EN'de 'tr' sızıntısı yoktu)
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
function reportIdentifiers(hostname: string, createdAt: Date, hideDate = false): { reportNo: string; verifyCode: string } {
  const y = createdAt.getUTCFullYear();
  const mo = String(createdAt.getUTCMonth() + 1).padStart(2, '0');
  const d = String(createdAt.getUTCDate()).padStart(2, '0');
  const h = createHash('sha256').update(`${hostname}|${createdAt.toISOString()}`).digest('hex').toUpperCase();
  // (ORNEK PDF) tarih gizliyse Rapor No da tarih icermez -> "CT-ÖRNEK-XXXX".
  const reportNo = hideDate ? `CT-ÖRNEK-${h.slice(0, 4)}` : `CT-${y}${mo}${d}-${h.slice(0, 4)}`;
  return { reportNo, verifyCode: `${h.slice(4, 8)}-${h.slice(8, 12)}` };
}

export type Sev = 'critical' | 'high' | 'medium' | 'low';
export type Finding = { title: string; sev: Sev; type?: FindingType; endpoint?: string; evidence?: string; confidence?: string };
// (TR-I HATASI) Anahtar-kelime eşleştirmede tr-locale küçültme ASCII "I"->"ı" (noktasız) yapar;
// İngilizce başlık/değerler (SEVERITY->severıty, HIGH->hıgh, Critical->crıtıcal, EXECUTIVE->executıve)
// böylece regex'e TAKILMAZ ve EN raporları yapısız yola düşerdi. Bu yardımcı Türkçe İ ile İngilizce I'yı
// birlikte 'i'ye indirger — SALT eşleştirme için güvenli küçültme (görüntülenen metin için KULLANILMAZ).
function lcMatch(s: string): string {
  return s.replace(/[İI]/g, 'i').toLowerCase();
}
function normSev(s: string): Sev | null {
  const x = lcMatch(s);
  if (/krit[iı]k|critical|kritisch/.test(x)) return 'critical';
  if (/y[üu]ksek|high|hoch/.test(x)) return 'high';
  if (/orta|medium|mittel/.test(x)) return 'medium';
  if (/d[üu][şs][üu]k|low|niedrig/.test(x)) return 'low';
  return null;
}
// (TUTARLILIK) Taksonomi etiketi TÜR bazlıdır; aynı türden birden çok örnek (ör. 3 farklı çerez)
// master tabloda BİREBİR aynı başlıkla görünüyordu. Ham satır adında `backtick` içinde SPESİFİK
// tanımlayıcı (çerez adı, yol, politika) varsa onu döndürür → başlık ayırt edilebilir olur ve
// de-dup anahtarı doğru ayrışır. YENİ VERİ TOPLANMAZ; mevcut satırdaki bilgi kullanılır.
function rowDiscriminator(rawCell: string): string {
  const m = rawCell.match(/`([^`]{1,48})`/);
  const id = m?.[1]?.trim() ?? '';
  return id;
}

function stripMd(s: string): string {
  // (BÖLÜM A) Altçizgi düzeltmesi: `_` YALNIZ gerçek markdown italik işareti (kelime-sınırlı `_söz_`)
  // iken temizlenir. Teknik terim/değişken içindeki intra-word `_` (ör. expose_php, X_Frame_Options,
  // snake_case) KORUNUR — aksi halde "exposephp" gibi yanlış render oluşuyordu.
  return s
    .replace(/`([^`]*)`/g, '$1')                                  // inline code
    .replace(/\*\*([^*]*)\*\*/g, '$1')                            // bold
    .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')                      // link -> metin
    .replace(/\*([^*\n]+?)\*/g, '$1')                             // italik *söz*
    .replace(/(^|[^\w`])_([^_\n]+?)_(?=[^\w`]|$)/g, '$1$2')       // italik _söz_ (SADECE kelime-sınırlı)
    .replace(/\*/g, '')                                           // artık * temizle
    .trim();
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

export function parseFindings(md: string, locale: 'tr' | 'en' | 'de'): { rows: Finding[]; counts: Record<Sev, number> } {
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
    const header = cells(block[0]).map((h) => lcMatch(h));
    const sevCol = header.findIndex((h) => /[şs]iddet|severity|ciddiyet|schweregrad/.test(h));
    if (sevCol === -1) continue; // şiddet kolonu yoksa bulgu tablosu değil
    const techCol = header.findIndex((h) => /teknik|technique|technik|t[üu]r\b|tip\b|\btype\b|\btyp\b/.test(h));
    const endpointCol = header.findIndex((h) => /giri[şs]|u[çc] nokta|endpoint|uc nokta|yol\b|path|endpunkt|pfad/.test(h));
    let titleCol = header.findIndex((h) => /bulgu|ba[şs]l[ıi]k|title|finding|befund/.test(h));
    if (titleCol === -1) titleCol = endpointCol;
    if (titleCol === -1) titleCol = header.findIndex((h, idx) => idx !== sevCol && !/^#|^no$|^s[ıi]ra/.test(h));
    if (titleCol === -1) titleCol = 0;
    const nameCol = techCol !== -1 ? techCol : titleCol;
    // Kanıt/açıklama kolonu — kartın "Nasıl Tespit Edildi"/açıklama için GERÇEK veri.
    // (DÜZELTME) İngilizce 'Description' kolonu bu listede YOKTU → EN raporlarda açıklama metni
    // sınıflandırmaya karışıyordu (ör. CSP bulgusunun açıklamasındaki "XSS" yüzünden satır
    // "Reflected XSS indicator" olarak etiketleniyordu). TR 'açıklama' ve DE 'beschreibung' zaten vardı.
    const evidCol = header.findIndex((h) => /kan[ıi]t|evidence|k[ıi]sa a[çc][ıi]klama|a[çc][ıi]klama|description|not\b|nachweis|beschreibung|erl[äa]uterung/.test(h));
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
      const discrim = rowDiscriminator(c[nameCol] ?? c[titleCol] ?? '');
      const labelWithId =
        info && discrim && !info.label.toLocaleLowerCase('tr').includes(discrim.toLocaleLowerCase('tr'))
          ? `${info.label} — ${discrim}`
          : info?.label;
      const title = labelWithId ?? (cleanTitle(rawName) || cleanTitle(curSection) || rawName);
      // Uç nokta: entry kolonundan (nameCol'dan farklıysa). "GET /rest/..." gibi.
      let endpoint = endpointCol !== -1 && endpointCol !== nameCol ? stripMd(c[endpointCol] ?? '') : '';
      // (Faz 4 düzeltme — SALT ETİKET) Uç-nokta kolonu TEK anlamlı kolonsa (endpointCol===nameCol, ör.
      // IDOR "| Uç Nokta | ID | Gözlem | Ciddiyet |") başlık SINIFLAMADAN gelir (info.label; rawName başlık
      // DEĞİL) → o değeri UÇ-NOKTA etiketi yap ki tıpatıp görünen satırlar (CT-8/CT-9) ayrışsın. Yalnız
      // gerçekten uç-nokta GÖRÜNÜMLÜyse (/, ? ya da HTTP fiili). Sayı/severity/de-dup DEĞİŞMEZ (epKey aynı değer).
      if (!endpoint && info && endpointCol !== -1) {
        const epCand = stripMd(c[endpointCol] ?? '');
        if (epCand && /[/?]|^\s*(GET|POST|PUT|DELETE|PATCH|HEAD)\b/i.test(epCand) && epCand.toLocaleLowerCase('tr') !== info.label.toLocaleLowerCase('tr')) endpoint = epCand;
      }
      if (endpoint.length > 60) endpoint = endpoint.slice(0, 60) + '…';
      const evidence = evidCol !== -1 ? stripMd(c[evidCol] ?? '') : '';
      // Güven (varsa) — DÜŞÜK/dolaylı kanıtı master tabloda da görünür kılmak için (yalnız detay kartında değil).
      const confidence = confCol !== -1 ? stripMd(c[confCol] ?? '') : '';
      // DE-DUP (tek bulgu-kaydı): anahtar = TÜR + UÇ NOKTA. Aynı türü AYNI uç noktada iki modül
      // görürse tek CT'de birleşir (çift-sayım yok); FARKLI uç nokta (ör. localStorage['token'] vs
      // localStorage['totp_tmp_token'], ya da /a vs /b) AYRI CT alır — tür-bazlı çökertme distinct
      // bulguları kaybediyordu (client-side statik 2 storage bulgusu master'a hiç girmiyordu).
      // Açık çapraz-referanslar (API F1 BOLA/BFLA → IDOR) zaten Ciddiyet'siz not olarak render edilir,
      // BULGULAR tablosuna satır yazmaz → ikinci CT üretmez.
      const typeKey = (info ? info.type : title.toLocaleLowerCase('tr')).slice(0, 48);
      const epKey = (discrim || endpoint || '').toLocaleLowerCase('tr').replace(/\s+/g, ' ').trim().slice(0, 60);
      const key = `${typeKey}|${epKey}`;
      if (seen.has(key)) continue;
      seen.add(key);
      rows.push({ title, sev, type: info?.type, endpoint: endpoint || undefined, evidence: evidence || undefined, confidence: confidence || undefined });
      counts[sev]++;
    }
  }
  return { rows, counts };
}

const SEV_META: Record<Sev, { tr: string; en: string; de: string; cls: string }> = {
  critical: { tr: 'Kritik', en: 'Critical', de: 'Kritisch', cls: 'sev-critical' },
  high: { tr: 'Yüksek', en: 'High', de: 'Hoch', cls: 'sev-high' },
  medium: { tr: 'Orta', en: 'Medium', de: 'Mittel', cls: 'sev-medium' },
  low: { tr: 'Düşük', en: 'Low', de: 'Niedrig', cls: 'sev-low' },
};
// (Çok-bölge) 3-yönlü seçim: de → Almanca, tr → Türkçe, diğer → İngilizce.
function p3(locale: 'tr' | 'en' | 'de', tr: string, en: string, de: string): string {
  return locale === 'de' ? de : locale === 'tr' ? tr : en;
}
function sevText(s: Sev, locale: 'tr' | 'en' | 'de'): string {
  return locale === 'de' ? SEV_META[s].de : locale === 'tr' ? SEV_META[s].tr : SEV_META[s].en;
}

// 2.1 Zafiyet Dağılımı — gerçek sayılardan bar grafiği + sayı tablosu (0'lar da çizilir, dürüst).
function buildDistribution(counts: Record<Sev, number>, locale: 'tr' | 'en' | 'de', unscannable = false): string {
  const order: Sev[] = ['critical', 'high', 'medium', 'low'];
  const max = Math.max(1, ...order.map((s) => counts[s]));
  const total = order.reduce((a, s) => a + counts[s], 0);
  const bars = order.map((s) => {
    const h = Math.round((counts[s] / max) * 80); // px (maks 80)
    return `<div class="dist-col"><div class="dist-num">${counts[s]}</div><div class="dist-bar ${SEV_META[s].cls}-bg" style="height:${h}px"></div><div class="dist-lbl">${sevText(s, locale)}</div></div>`;
  }).join('');
  // (DÜRÜSTLÜK) Hedefe ulaşılamadıysa 0/0/0/0 "temiz" DEĞİL "incelenemedi"dir — açıkça belirt.
  const intro = unscannable
    ? p3(locale, '⚠️ Kontroller anlamlı şekilde çalıştırılamadı (hedefe ulaşılamadı veya test edilebilir bir yüzey/giriş noktası bulunamadı); aşağıdaki sıfırlar bir güvenlik değerlendirmesi <strong>DEĞİLDİR</strong> (0 = incelenemedi, “temiz” değil).', '⚠️ Checks could not run meaningfully (target unreachable, or no testable surface/entry point found); the zeros below are <strong>NOT</strong> a security assessment (0 = not scanned, not "clean").', '⚠️ Die Prüfungen konnten nicht sinnvoll ausgeführt werden (Ziel nicht erreichbar oder keine testbare Oberfläche/kein Einstiegspunkt gefunden); die Nullen unten sind <strong>KEINE</strong> Sicherheitsbewertung (0 = nicht geprüft, nicht „sauber“).')
    : total === 0
    ? p3(locale, 'Bu taramada açık bir zafiyet göstergesi tespit edilmedi. Çalıştırılan kontroller ve gözlemler aşağıdaki bölümlerde ayrıntılıdır.', 'No open vulnerability indicator was detected in this scan. Executed checks and observations are detailed in the sections below.', 'In diesem Scan wurde kein offener Schwachstellen-Indikator festgestellt. Die ausgeführten Prüfungen und Beobachtungen sind in den folgenden Abschnitten detailliert.')
    : p3(locale, `Bu taramada toplam <strong>${total}</strong> bulgu göstergesi tespit edildi; şiddet dağılımı aşağıdadır.`, `A total of <strong>${total}</strong> finding indicators were detected; the severity distribution is below.`, `In diesem Scan wurden insgesamt <strong>${total}</strong> Befund-Indikatoren festgestellt; die Verteilung nach Schweregrad ist unten dargestellt.`);
  return `<h2 id="s-dist">${p3(locale, '2.1 Zafiyet Dağılımı', '2.1 Vulnerability Distribution', '2.1 Schwachstellenverteilung')}</h2>
  <div class="dist-chart">${bars}</div>
  <p>${intro}</p>`;
}

// ============================================================================
// (A/B TESTİ — YALNIZ KEŞİF PAKETİ / bundle_recon) Okunabilirlik/görsel hiyerarşi.
// Bu blok SADECE meta.packageKey === 'bundle_recon' iken devreye girer; diğer 5 paketin
// çıktısı byte-byte AYNIDIR. Veri/bulgu/metodoloji DEĞİŞMEZ — yalnız sunum.
// ============================================================================
// Zengin (gorsel-hiyerarsili) sablonu KULLANAN paketler. Bu kumede OLMAYAN paketlerin ciktisi
// byte-byte aynidir. A/B: once bundle_recon, simdi basit_tarama da ayni marka dilini kullanir.
const RICH_TEMPLATE_PKGS = new Set(['bundle_recon', 'basit_tarama', 'bundle_surface', 'bundle_active_verify']);
// "Kontrol alanı" dili kullanan paketler (Keşif "keşif yöntemi" der). Pozitif Güvence tablosu
// aynı 2 kolonlu yapıdadır; satır metinlerinde sayı olması/olmaması fark etmez (metin AYNEN taşınır).
const CONTROL_AREA_PKGS = new Set(['basit_tarama', 'bundle_surface']);
// (AKTİF DOĞRULAMA) Kendi dili: "kontrol alanı" değil DOĞRULAMA KATEGORİSİ; "sorun bulunmadı" değil
// "temiz — denendi, kanıt bulunamadı". Tablosu 4 kolonlu ve ÜÇÜNCÜ durum ("İncelenemedi") o pakette
// NORMAL/BEKLENEN bir sonuçtur (kendi metni böyle diyor), bulgu sayılmaz.
const ACTIVE_VERIFY_PKG = 'bundle_active_verify';

/** Güvence satırının üç durumu: temiz / bulgu / incelenemedi (paketlerin kendi metni esas alınır). */
type AssuranceState = 'ok' | 'finding' | 'na';

/** POZİTİF GÜVENCE tablosunun satırlarını ayrıştırır (uydurma YOK — markdown'da ne varsa o). */
function parseReconAssurance(md: string): Array<{ area: string; result: string; ok: boolean; state: AssuranceState }> {
  // Bölüm başlığı 3 dilde. Tablo GENİŞLİĞİ pakete göre DEĞİŞİR:
  //   2 kolon → "| Kontrol Alanı | Sonuç |"                       (Basit Tarama / Dış Yüzey / Keşif)
  //   4 kolon → "| Kontrol | Giriş noktası | İstek | Sonuç |"      (Aktif Doğrulama)
  // Bu yüzden İLK kolon = alan adı, SON kolon = sonuç olarak okunur; ara kolonlar (sayaçlar) yok sayılır
  // — onlar zaten bölümdeki tam tabloda AYNEN duruyor.
  const sec = md.match(/##\s*(?:POZİTİF GÜVENCE|POSITIVE ASSURANCE|POSITIVE ZUSICHERUNG)[^\n]*\n([\s\S]*?)(?=\n##\s|$)/);
  if (!sec) return [];
  const out: Array<{ area: string; result: string; ok: boolean; state: AssuranceState }> = [];
  for (const line of sec[1].split('\n')) {
    if (!/^\s*\|.*\|\s*$/.test(line)) continue;
    const cells = line.trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map((c) => c.trim());
    if (cells.length < 2) continue;
    const area = cells[0];
    const result = cells[cells.length - 1];
    if (/^[-:\s]+$/.test(area) || !result || /^(Sonuç|Result|Ergebnis)$/i.test(result)) continue; // baslik/ayrac satiri
    const ok = result.startsWith('✅');
    // (ÜÇÜNCÜ DURUM) "İncelenemedi / Nicht prüfbar / Not assessable" bir BULGU DEĞİLDİR; paketlerin
    // kendi üç-durum notu bunu açıkça ayırır. Bulgu kutusuna koymak yanıltıcı olurdu.
    // (TR-I TUZAĞI) "İncelenemedi" büyük İ (U+0130) ile başlar; JS'in /i/ bayrağı bunu ASCII 'i' ile
    // EŞLEŞTİRMEZ -> satır yanlışlıkla "bulgu" sayılıyordu. Önce İ/I normalize edilir.
    const norm = result.replace(/[İI]/g, 'i').replace(/\u0307/g, '').toLowerCase();
    // Paketlerin GERÇEKTEN kullandığı tüm "incelenemedi" ifadeleri (kod + örnek fixture'lardan
    // tarandı). DE'de tek bir kalıp YOK: motor "Nicht prüfbar" üretir, örnek fixture "Nicht
    // untersuchbar" der; Dış Yüzey/Basit ayrıca "Nicht ermittelbar"/"Nicht abfragbar" kullanır.
    // AÇIK LİSTE tutulur — "Nicht \w+bar" gibi genel kalıp "Nicht vorhersehbar" (yan-etki riski,
    // BAMBAŞKA bir anlam) satırını da yanlışlıkla yakalardı.
    const na = !ok && /incelenemedi|not assessable|not scanned|nicht (pr[üu]fbar|pruefbar|untersuchbar|ermittelbar|abfragbar)/.test(norm);
    out.push({ area, result, ok, state: ok ? 'ok' : na ? 'na' : 'finding' });
  }
  return out;
}

/** Master tablodaki çıplak "Temiz" yerine geçen KISA özet cümlesi (gerçek sayılardan). */
function reconEmptySummary(rows: Array<{ ok: boolean }>, locale: 'tr' | 'en' | 'de', pkg: string): string {
  if (!rows.length) return '';
  const clean = rows.filter((r) => r.ok).length;
  if (pkg === ACTIVE_VERIFY_PKG) {
    return p3(locale,
      ` <strong>${clean}/${rows.length} aktif doğrulama kategorisi çalıştırıldı; hiçbirinde zafiyet kanıtı bulunamadı</strong> (kategori kategori özet aşağıdadır).`,
      ` <strong>${clean}/${rows.length} active verification categories were run; no evidence of a vulnerability was found in any of them</strong> (category-by-category summary below).`,
      ` <strong>${clean}/${rows.length} aktive Verifizierungskategorien wurden ausgeführt; in keiner wurde ein Schwachstellennachweis gefunden</strong> (Zusammenfassung je Kategorie unten).`);
  }
  if (CONTROL_AREA_PKGS.has(pkg)) {
    return p3(locale,
      ` <strong>${clean}/${rows.length} kontrol alanı çalıştırıldı; hiçbirinde sorun bulunmadı</strong> (alan alan özet aşağıdadır).`,
      ` <strong>${clean}/${rows.length} control areas were run; no issue was found in any of them</strong> (area-by-area summary below).`,
      ` <strong>${clean}/${rows.length} Kontrollbereiche wurden ausgeführt; in keinem wurde ein Problem gefunden</strong> (Zusammenfassung je Bereich unten).`);
  }
  return p3(locale,
    ` <strong>${clean}/${rows.length} keşif yöntemi çalıştırıldı; hiçbirinde gösterge bulunamadı</strong> (yöntem yöntem özet aşağıdadır).`,
    ` <strong>${clean}/${rows.length} reconnaissance methods were executed; no indicator emerged in any of them</strong> (method-by-method summary below).`,
    ` <strong>${clean}/${rows.length} Erkundungsmethoden wurden ausgeführt; in keiner ergab sich ein Indikator</strong> (Zusammenfassung je Methode unten).`);
}

/**
 * Master Bulgu Tablosu'nun HEMEN ALTINA gelen "Ne test edildi / ne çıktı" özeti.
 * İçerik §POZİTİF GÜVENCE tablosundan AYNEN alınır (o bölüm yerinde KALIR) — kullanıcı
 * bilgiyi görmek için raporun sonuna kadar beklemek zorunda kalmasın.
 */
function buildReconAssuranceSummary(md: string, locale: 'tr' | 'en' | 'de', pkg: string): string {
  const rows = parseReconAssurance(md);
  if (!rows.length) return '';
  const okRows = rows.filter((r) => r.state === 'ok');
  const warnRows = rows.filter((r) => r.state === 'finding');
  const naRows = rows.filter((r) => r.state === 'na');
  const strip = (s: string) => s.replace(/^[✅⚠️\s]+/, '').trim();
  // (BASIT TARAMA) Baslik AYNI ZAMANDA ozet cumlesidir: "N/M kontrol alani calistirildi; X'inde
  // gosterge bulundu". Kesif'in mevcut basligi DEGISMEZ (o paket zaten dogrulanmis durumda).
  const naPart = (tr: string, en: string, de: string) => (naRows.length ? p3(locale, tr, en, de) : '');
  const title = pkg === ACTIVE_VERIFY_PKG
    ? p3(locale,
        `${rows.length} doğrulama kategorisi çalıştırıldı — ${okRows.length} temiz, ${warnRows.length} kategoride bulgu var`,
        `${rows.length} verification categories were run — ${okRows.length} clean, ${warnRows.length} produced a finding`,
        `${rows.length} Verifizierungskategorien wurden ausgeführt — ${okRows.length} sauber, ${warnRows.length} mit Befund`)
      + naPart(`, ${naRows.length} incelenemedi`, `, ${naRows.length} not assessable`, `, ${naRows.length} nicht prüfbar`)
    : CONTROL_AREA_PKGS.has(pkg)
    ? p3(locale,
        `${rows.length} kontrol alanı çalıştırıldı — ${okRows.length} alanda sorun bulunmadı, ${warnRows.length} alanda bulgu var`,
        `${rows.length} control areas were run — ${okRows.length} came back clean, ${warnRows.length} produced a finding`,
        `${rows.length} Kontrollbereiche wurden ausgeführt — ${okRows.length} ohne Befund, ${warnRows.length} mit Befund`)
    : p3(locale, 'Ne test edildi, ne çıktı?', 'What was tested, and what came out?', 'Was wurde geprüft, und was kam heraus?');
  const okHead = pkg === ACTIVE_VERIFY_PKG
    ? p3(locale, 'Denendi — zafiyet kanıtı bulunamadı', 'Attempted — no evidence of a vulnerability found', 'Versucht — kein Schwachstellennachweis gefunden')
    : CONTROL_AREA_PKGS.has(pkg)
    ? p3(locale, 'Kontrol edildi — sorun bulunmadı', 'Checked — no issue found', 'Geprüft — kein Problem gefunden')
    : p3(locale, 'Test edildi — gösterge bulunamadı', 'Checked — no indicator found', 'Geprüft — kein Indikator gefunden');
  const warnHead = CONTROL_AREA_PKGS.has(pkg) || pkg === ACTIVE_VERIFY_PKG
    ? p3(locale, 'Bulgu var — ayrıntısı aşağıdaki bölümlerde', 'Finding present — detailed in the sections below', 'Befund vorhanden — Details in den Abschnitten unten')
    : p3(locale, 'Gösterge bulundu — ayrıntısı aşağıdaki bölümlerde', 'Indicator found — detailed in the sections below', 'Indikator gefunden — Details in den Abschnitten unten');
  // (ÜÇÜNCÜ DURUM) "İncelenemedi" ne temiz ne bulgudur — nötr gri kutu; "güvenli" ANLAMINA GELMEZ.
  const naHead = p3(locale,
    'İncelenemedi — “güvenli” anlamına GELMEZ',
    'Not assessable — does NOT mean “secure”',
    'Nicht prüfbar — bedeutet NICHT „sicher“');
  const li = (r: { area: string; result: string }) => `<li><span class="rc-area">${escapeHtml(r.area)}</span> ${escapeHtml(strip(r.result))}</li>`;
  return `<div class="rc-summary">
    <div class="rc-summary-title">${escapeHtml(title)}</div>
    ${okRows.length ? `<div class="rc-ok-box"><div class="rc-box-head">✅ ${escapeHtml(okHead)}</div><ul>${okRows.map(li).join('')}</ul></div>` : ''}
    ${warnRows.length ? `<div class="rc-warn-box"><div class="rc-box-head">⚠️ ${escapeHtml(warnHead)}</div><ul>${warnRows.map(li).join('')}</ul></div>` : ''}
    ${naRows.length ? `<div class="rc-na-box"><div class="rc-box-head">⚠️ ${escapeHtml(naHead)}</div><ul>${naRows.map(li).join('')}</ul></div>` : ''}
  </div>`;
}

/**
 * Rendere edilmiş HTML üzerinde YALNIZ SINIF EKLER (metin/işaret/cümle DEĞİŞMEZ):
 *  - ✅ ile başlayan hücre/madde  -> .rc-ok   (açık yeşil "test + sonuç")
 *  - ⚠️ ile başlayan hücre/madde  -> .rc-warn (amber gösterge)
 *  - DEĞERLENDİRİR / DEĞERLENDİRMEZ paragrafları -> iki ayrı bilgi kutusu
 */
function reconStyleBlocks(html: string): string {
  let out = html
    .replace(/<td>(\s*✅)/g, '<td class="rc-ok">$1')
    .replace(/<td>(\s*⚠️)/g, '<td class="rc-warn">$1')
    .replace(/<li>(\s*✅)/g, '<li class="rc-ok">$1')
    .replace(/<li>(\s*⚠️)/g, '<li class="rc-warn">$1');
  // "NE değerlendirir/EDER — NE değerlendirmez/ETMEZ" — ikisi de BİLGİdir; kırmızı KULLANILMAZ.
  // ÖNEMLİ: OLUMSUZ kalıplar ÖNCE değiştirilir; aksi halde "BEWERTET NICHT"/"DOES NOT" satırı
  // "BEWERTET"/"DOES" ile eşleşip YANLIŞ kutuya (yeşil) düşer. Olumlu kalıplarda ayrıca
  // negatif-ileri-bakış (?!\s+NICHT|\s+NOT) guard'ı var.
  out = out.replace(
    /<p><strong>(DEĞERLENDİRMEZ|DOES NOT ASSESS|DOES NOT|BEWERTET NICHT|PRÜFT NICHT|ETMEZ)\b([\s\S]*?)<\/p>/g,
    '<div class="rc-does-not"><p><strong>$1$2</p></div>',
  );
  out = out.replace(
    /<p><strong>(DEĞERLENDİRİR|ASSESSES|BEWERTET(?!\s+NICHT)|PRÜFT(?!\s+NICHT)|DOES(?!\s+NOT)|EDER)\b([\s\S]*?)<\/p>/g,
    '<div class="rc-does"><p><strong>$1$2</p></div>',
  );
  return out;
}

// 2.2 Master Bulgu Tablosu — ID (CT-N) + Başlık + Durum + Şiddet. Boşsa dürüst "temiz" satırı.
function buildMasterTable(rows: Finding[], locale: 'tr' | 'en' | 'de', unscannable = false, emptyExtra = ''): string {
  const rank: Record<Sev, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  const sorted = [...rows].sort((a, b) => rank[a.sev] - rank[b.sev]);
  const head = locale === 'de' ? ['ID', 'Titel', 'Status', 'Schweregrad'] : locale === 'tr' ? ['ID', 'Başlık', 'Durum', 'Şiddet'] : ['ID', 'Title', 'State', 'Severity'];
  const open = p3(locale, 'Açık', 'Open', 'Offen');
  let body: string;
  if (unscannable) {
    // (DÜRÜSTLÜK) Hedefe ulaşılamadı -> "Temiz" satırı YERİNE açık uyarı; nötr gri "İncelenemedi" (risk rengi YOK).
    body = `<tr><td>—</td><td colspan="2">${p3(locale, 'Kontroller anlamlı şekilde çalıştırılamadı (hedefe ulaşılamadı veya test edilebilir bir yüzey/giriş noktası bulunamadı) — sonuç değerlendirilemez (“güvenli/temiz” anlamına gelmez).', 'Checks could not run meaningfully (target unreachable, or no testable surface/entry point found) — result cannot be assessed (does not mean "safe/clean").', 'Die Prüfungen konnten nicht sinnvoll ausgeführt werden (Ziel nicht erreichbar oder keine testbare Oberfläche/kein Einstiegspunkt gefunden) — das Ergebnis lässt sich nicht bewerten (bedeutet nicht „sicher/sauber“).')}</td><td><span class="sev-badge" style="background:#6B7280">${p3(locale, 'İncelenemedi', 'Not scanned', 'Nicht geprüft')}</span></td></tr>`;
  } else if (sorted.length === 0) {
    // (KEŞİF A/B) emptyExtra YALNIZ bundle_recon'da dolu gelir -> çıplak "Temiz" yerine kısa özet.
    body = `<tr><td>—</td><td colspan="2">${p3(locale, 'Bu taramada açık zafiyet göstergesi tespit edilmedi.', 'No open vulnerability indicator detected in this scan.', 'In diesem Scan wurde kein offener Schwachstellen-Indikator festgestellt.')}${emptyExtra}</td><td><span class="sev-badge" style="background:#1C6B60">${p3(locale, 'Temiz', 'Clean', 'Sauber')}</span></td></tr>`;
  } else {
    body = sorted.map((f, idx) => {
      const sm = SEV_META[f.sev];
      // Başlığa UÇ NOKTA (varsa) — "SQL Enjeksiyon göstergesi — /rest/products/search?q". Payload/teknik master'da DEĞİL.
      // DÜŞÜK/dolaylı güven -> master'da AÇIKÇA işaretle (detay kartıyla sınırlı kalmasın). Hem "Güven"
      // kolonundan hem de kanıt metnindeki "DOLAYLI/ZAYIF GÖSTERGE" ifadesinden tespit et (sağlam).
      const lowConf = /d[üu][şs][üu]k|low/i.test(f.confidence ?? '') || /dolayl[ıi][\s/]*zay[ıi]f g[öo]sterge|zay[ıi]f g[öo]sterge|doğrudan.*kan[ıi]t.*de[ğg]il/i.test(f.evidence ?? '');
      const confTag = lowConf ? ` <span class="mt-ep">· ${p3(locale, 'güven: düşük (dolaylı gösterge)', 'confidence: low (indirect indicator)', 'Konfidenz: niedrig (indirekter Indikator)')}</span>` : '';
      const titleCell = (f.endpoint ? `${escapeHtml(f.title)} <span class="mt-ep">— ${escapeHtml(f.endpoint)}</span>` : escapeHtml(f.title)) + confTag;
      return `<tr><td>CT-${idx + 1}</td><td>${titleCell}</td><td>${open}</td><td class="${sm.cls}"><span class="sev-badge">${sevText(f.sev, locale)}</span></td></tr>`;
    }).join('');
  }
  return `<h2 id="s-master">${p3(locale, '2.2 Master Bulgu Tablosu', '2.2 Master Findings Table', '2.2 Master-Befundtabelle')}</h2>
  <table class="master"><thead><tr>${head.map((h) => `<th>${h}</th>`).join('')}</tr></thead><tbody>${body}</tbody></table>`;
}

// 2.3 Detaylı Bulgular — her GERÇEK bulgu için blok: CT-N + başlık + şiddet + Durum + İŞ ETKİSİ +
// Referans (CWE/OWASP). İş Etkisi/CWE deterministik eşlemeden (findingTaxonomy); eşleme yoksa blok
// ATLANIR (UYDURMA YOK). Sadece GERÇEK raporlarda (örneklerin kendi İş Etkisi bölümleri zaten var).
// (Faz 9 — SUNUM) Yönetim Kararı call-out: master COUNTS'tan türer (yeni veri/severity YOK).
function buildManagementDecision(counts: Record<Sev, number>, locale: 'tr' | 'en' | 'de'): string {
  const hi = counts.critical + counts.high;
  const title = p3(locale, 'Yönetim Kararı', 'Management Decision', 'Management-Entscheidung');
  let body: string;
  if (hi > 0) body = p3(locale,
    `Öncelikli ele alınması gereken <strong>${hi}</strong> yüksek/kritik seviyeli gösterge tespit edildi; bunlar için acil bir düzeltme planı önerilir. Orta/düşük göstergeler planlı iyileştirmeyle giderilebilir.`,
    `<strong>${hi}</strong> high/critical indicator(s) requiring priority attention were found; an urgent remediation plan is recommended. Medium/low items can be addressed via planned improvement.`,
    `Es wurden <strong>${hi}</strong> Indikator(en) mit hohem/kritischem Schweregrad festgestellt, die vorrangig zu behandeln sind; ein dringender Behebungsplan wird empfohlen. Mittlere/geringe Punkte können durch geplante Verbesserung behoben werden.`);
  else if (counts.medium > 0) body = p3(locale,
    'Doğrulanmış kritik/yüksek bir bulgu <strong>öne çıkmadı</strong>; tespit edilen orta/düşük göstergeler planlı bir iyileştirme döngüsüyle giderilebilir.',
    'No confirmed critical/high finding <strong>stood out</strong>; the medium/low indicators can be addressed in a planned improvement cycle.',
    'Kein bestätigter kritischer/hoher Befund ist <strong>hervorgetreten</strong>; die festgestellten mittleren/geringen Indikatoren können in einem geplanten Verbesserungszyklus behoben werden.');
  else body = p3(locale,
    'Bu taramada doğrulanmış kritik/yüksek/orta seviyeli bir gösterge <strong>öne çıkmadı</strong>. Sonuçlar hedefin yüzeyine göre değişir; düzenli tekrar önerilir.',
    'No confirmed critical/high/medium indicator <strong>stood out</strong> in this scan. Results vary by target surface; periodic re-scanning is recommended.',
    'In diesem Scan ist kein bestätigter Indikator mit kritischem/hohem/mittlerem Schweregrad <strong>hervorgetreten</strong>. Die Ergebnisse hängen von der Oberfläche des Ziels ab; regelmäßige Wiederholung wird empfohlen.');
  return `<div class="mgmt-box"><div class="mgmt-t">${hi > 0 ? '⚡ ' : ''}${title}</div><p>${body}</p></div>`;
}

// (Faz 9 — SUNUM) Statik/deterministik Metodoloji + Risk Derecelendirme Kriterleri tabloları (yeni veri YOK).
function buildMethodologyTables(locale: 'tr' | 'en' | 'de'): string {
  const tr = locale === 'tr';
  const de = locale === 'de';
  const mRows = (de
    ? [['Erkundung', 'Die externe Oberfläche, Seiten und (bei SPAs) echte Endpunkte/Parameter aus dem JS-Bundle werden extrahiert.'],
       ['Automatische Erkennung', 'Auf der ermittelten Oberfläche werden deterministische, sichere (read-only) Indikatoren gesucht.'],
       ['Manuell-deterministische Verifizierung', 'Befunde werden mit code-basierten Regeln verifiziert; „nachweisen, nicht ausnutzen“.'],
       ['Autorisierung & Session', 'Im authentifizierten Paket werden Cookie/Session/Autorisierung und die Post-Login-Oberfläche geprüft.'],
       ['Konfiguration', 'Header-, TLS-, E-Mail-/DNS- und Preisgabe-Konfigurationen werden beobachtet.']]
    : tr
    ? [['Keşif', 'Hedefin dış yüzeyi, sayfaları ve (SPA ise) JS bundle\'ından gerçek uç/parametreler çıkarılır.'],
       ['Otomatik tespit', 'Keşfedilen yüzeyde deterministik, güvenli (read-only) göstergeler aranır.'],
       ['Manuel-deterministik doğrulama', 'Bulgular kod-tabanlı kurallarla doğrulanır; “kanıtla, istismar etme”.'],
       ['Yetki & oturum', 'Kimlik-doğrulamalı pakette çerez/oturum/yetki ve login-sonrası yüzey incelenir.'],
       ['Yapılandırma', 'Başlık, TLS, e-posta/DNS ve ifşa yapılandırmaları gözlemlenir.']]
    : [['Discovery', 'The external surface, pages and (for SPAs) real endpoints/params from the JS bundle are extracted.'],
       ['Automated detection', 'Deterministic, safe (read-only) indicators are sought on the discovered surface.'],
       ['Manual-deterministic verification', 'Findings are verified with code-based rules; “prove, don\'t exploit”.'],
       ['Authz & session', 'In the authenticated package, cookie/session/authorization and post-login surface are examined.'],
       ['Configuration', 'Header, TLS, email/DNS and exposure configurations are observed.']]
  ).map((r) => `<tr><td>${escapeHtml(r[0])}</td><td>${escapeHtml(r[1])}</td></tr>`).join('');
  const rRows = (de
    ? [['critical', 'Kritisch', 'Direkt/leicht ausnutzbarer Indikator mit erheblicher Daten-/Zugriffsauswirkung.'],
       ['high', 'Hoch', 'Hervorstechender, vorrangig zu behebender starker Indikator.'],
       ['medium', 'Mittel', 'Erfordert Aufmerksamkeit; kontextabhängige Verifizierung empfohlen.'],
       ['low', 'Niedrig', 'Härtungs-/Reifegrad-Chance; niedrige Priorität.']]
    : tr
    ? [['critical', 'Kritik', 'Doğrudan/kolay istismar edilebilen, ciddi veri/erişim etkisi olan gösterge.'],
       ['high', 'Yüksek', 'Öne çıkan, öncelikli giderilmesi gereken güçlü gösterge.'],
       ['medium', 'Orta', 'Dikkat gerektiren, bağlama göre doğrulanması önerilen gösterge.'],
       ['low', 'Düşük', 'Sertleştirme/olgunluk fırsatı; düşük öncelikli.']]
    : [['critical', 'Critical', 'Directly/easily exploitable indicator with serious data/access impact.'],
       ['high', 'High', 'Prominent, priority-to-fix strong indicator.'],
       ['medium', 'Medium', 'Requires attention; context-dependent verification recommended.'],
       ['low', 'Low', 'Hardening/maturity opportunity; low priority.']]
  ).map((r) => `<tr><td><span class="sev-chip chip-${r[0]}">${escapeHtml(r[1])}</span></td><td>${escapeHtml(r[2])}</td></tr>`).join('');
  return `<h3 class="pres-h3">${p3(locale, 'Metodoloji', 'Methodology', 'Methodik')}</h3>
    <table class="pres-table"><thead><tr><th>${p3(locale, 'Aşama', 'Stage', 'Phase')}</th><th>${p3(locale, 'Açıklama', 'Description', 'Beschreibung')}</th></tr></thead><tbody>${mRows}</tbody></table>
    <h3 class="pres-h3">${p3(locale, 'Risk Derecelendirme Kriterleri', 'Risk Rating Criteria', 'Risikobewertungskriterien')}</h3>
    <table class="pres-table"><thead><tr><th>${p3(locale, 'Şiddet', 'Severity', 'Schweregrad')}</th><th>${p3(locale, 'Tanım', 'Definition', 'Definition')}</th></tr></thead><tbody>${rRows}</tbody></table>
    <p class="pres-note">${p3(locale, 'Şiddet yalnız bant etiketidir (sayısal CVSS skoru kullanılmaz); tüm bulgular “gösterge, doğrulama gerekir” çerçevesindedir.', 'Severity is a band label only (no numeric CVSS score); all findings are framed as “indicator, verification required”.', 'Der Schweregrad ist nur ein Bandlabel (kein numerischer CVSS-Score); alle Befunde sind als „Indikator, Verifizierung erforderlich“ gerahmt.')}</p>`;
}

function buildDetailedFindings(rows: Finding[], locale: 'tr' | 'en' | 'de'): string {
  const rank: Record<Sev, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  const sorted = [...rows].sort((a, b) => rank[a.sev] - rank[b.sev]);
  const blocks: string[] = [];
  const L = locale === 'de'
    ? { state: 'Status: Offen', ep: 'Betroffener Punkt', desc: 'Beschreibung', how: 'Wie es erkannt wurde', impact: 'Geschäftliche Auswirkung', fix: 'Empfohlene Behebung', ref: 'Referenz' }
    : locale === 'tr'
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
    const sevLabel = sevText(f.sev, locale).toLocaleUpperCase(locale === 'de' ? 'de' : locale === 'tr' ? 'tr' : 'en');
    blocks.push(`<div class="finding-block fb-${f.sev}">
      <h3 id="s-fb-${idx + 1}"><span class="sev-chip chip-${f.sev}">[${sevLabel}]</span> CT-${idx + 1} · ${escapeHtml(f.title)}</h3>
      <div class="fb-meta">${L.state}</div>
      ${f.endpoint ? `<p class="fb-row"><strong>${L.ep}:</strong> <code>${escapeHtml(f.endpoint)}</code></p>` : ''}
      <p class="fb-row"><strong>${L.desc}:</strong> ${escapeHtml(det.desc)}</p>
      <p class="fb-row"><strong>${L.how}:</strong> ${escapeHtml(howText)}</p>
      <p class="fb-row"><strong>${L.impact}:</strong> ${escapeHtml(info.impact)}</p>
      <div class="fix-box"><div class="fix-box-t">${p3(locale, 'Önerilen Düzeltme', 'Recommended Fix', 'Empfohlene Behebung')}</div><div class="fix-box-b">${escapeHtml(det.fix)}</div></div>
      <p class="finding-ref"><strong>${L.ref}:</strong> ${escapeHtml(info.cwe)} · OWASP ${escapeHtml(info.owasp)}</p>
    </div>`);
  });
  if (!blocks.length) return '';
  return `<h2 id="s-detail">${p3(locale, '2.3 Detaylı Bulgular', '2.3 Detailed Findings', '2.3 Detaillierte Befunde')}</h2>${blocks.join('')}`;
}

// (YÖNETİCİ ÖZETİ) İyileştirme Öncelikleri — parse edilen GERÇEK bulgulardan DETERMİNİSTİK 3 grup:
// En Acil (yüksek/kritik, config-dışı) · Hızlı Kazanım (sunucu/config, 1-2 gün) · Orta Vadeli (süreç/
// kod/manuel). UYDURMA YOK — bulgu yoksa madde yok. Yönetici "ne yapmalıyım"ı 30 saniyede alır.
const CONFIG_TYPES = new Set<FindingType>(['clickjacking', 'mime_sniffing', 'csp_missing', 'referrer_policy', 'hsts_missing', 'weak_tls', 'weak_key', 'cert', 'version_disclosure', 'spf', 'dmarc', 'dkim', 'dnssec', 'cors', 'cookie_flags', 'exposed_files', 'exposed_api_docs']);
function buildPriorities(rows: Finding[], locale: 'tr' | 'en' | 'de'): string {
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
  const body = grp(p3(locale, '⚡ En Acil / Öncelikli', '⚡ Most Urgent', '⚡ Am dringendsten'), urgent)
    + grp(p3(locale, '🛠 Hızlı Kazanım (sunucu yapılandırması, ~1-2 gün)', '🛠 Quick Wins (~1-2 days)', '🛠 Schnelle Erfolge (Serverkonfiguration, ~1-2 Tage)'), quick)
    + grp(p3(locale, '🗓 Orta Vadeli / Süreç (manuel doğrulama veya kod/mimari)', '🗓 Medium-term / Process', '🗓 Mittelfristig / Prozess (manuelle Verifizierung oder Code/Architektur)'), process);
  if (!body) return '';
  return `<div class="priorities"><h3>${p3(locale, 'İyileştirme Öncelikleri', 'Improvement Priorities', 'Verbesserungsprioritäten')}</h3>${body}</div>`;
}

// (PREMIUM) Pozitif Güvence — "KONTROL ÖZETİ" tablosunda TEMİZ (✓ / kanıt yok / gösterge yok /
// vektör yok) çıkan kontrolleri tek blokta toplar. UYDURMA YOK: yalnız gerçekten çalıştırılıp temiz
// çıkanlar; kapsam-dışı olanlar hariç. Müşteri "neyin GÜVENLİ olduğunu" da görür.
function buildPositiveAssurance(md: string, locale: 'tr' | 'en' | 'de'): string {
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
    const header = cells(block[0]).map((h) => lcMatch(h));
    const kCol = header.findIndex((h) => /kontrol|control/.test(h));
    const sCol = header.findIndex((h) => /sonu[çc]|result/.test(h));
    if (kCol === -1 || sCol === -1) continue; // yalnız KONTROL ÖZETİ tablosu
    for (let r = 1; r < block.length; r++) {
      if (/^\s*\|[\s:|-]+\|\s*$/.test(block[r])) continue;
      const c = cells(block[r]);
      const sonuc = lcMatch(c[sCol] ?? '');
      const isClean = /✓|kan[ıi]t yok|g[öo]sterge yok|vekt[öo]r yok|temiz|no evidence|no indicator|no vector|clean/.test(sonuc);
      const scopeOut = /kapsam d|giri[şs] noktas[ıi] yok|out of scope|no entry point/.test(sonuc);
      if (!isClean || scopeOut) continue;
      const name = stripMd(c[kCol] ?? '');
      const key = name.toLocaleLowerCase('tr');
      if (!name || seen.has(key)) continue;
      seen.add(key);
      clean.push(name);
    }
  }
  if (clean.length < 2) return ''; // tek/hiç temiz kontrolde blok gösterme
  return `<div class="assurance"><h3>${p3(locale, 'Pozitif Güvence', 'Positive Assurance', 'Positive Zusicherung')}</h3>
  <p>${locale === 'tr'
    ? `Şu kontroller çalıştırıldı ve belirgin bir zafiyet göstergesi bulunamadı: ${escapeHtml(clean.join(', '))}. Bu alanlar, tarama anındaki gözlemlerde temiz görünmektedir (kesin güvence için düzenli tekrar önerilir).`
    : `The following controls were executed with no significant vulnerability indicator: ${escapeHtml(clean.join(', '))}.`}</p></div>`;
}

// Ek — Sözlük: yalnız RAPORDA GEÇEN terimler (bloat yok).
const GLOSSARY_TERMS: Array<{ re: RegExp; term: string; tr: string; en: string; de: string }> = [
  { re: /\bSQLi\b|SQL enjeksiyon|SQL Injection/i, term: 'SQL Injection', tr: 'Kullanıcı girdisinin veritabanı sorgusuna karışabildiği bir enjeksiyon zafiyeti.', en: 'An injection flaw where user input reaches a database query.', de: 'Eine Injection-Schwachstelle, bei der Nutzereingaben in eine Datenbankabfrage gelangen.' },
  { re: /\bXSS\b|Cross-Site Scripting|yans[ıi]yan/i, term: 'XSS', tr: 'Cross-Site Scripting — sayfaya kötü amaçlı betik enjekte edilebilmesi.', en: 'Cross-Site Scripting — injection of malicious scripts into pages.', de: 'Cross-Site Scripting — das Einschleusen schädlicher Skripte in Seiten.' },
  { re: /\bIDOR\b/i, term: 'IDOR', tr: 'Yetkisiz Nesne Erişimi — kimlik parametresiyle başka kaydın erişilebilmesi.', en: 'Insecure Direct Object Reference — accessing others’ records via ID manipulation.', de: 'Insecure Direct Object Reference — Zugriff auf fremde Datensätze durch ID-Manipulation.' },
  { re: /\bSSRF\b/i, term: 'SSRF', tr: 'Server-Side Request Forgery — sunucuyu istenmeyen isteklere zorlama.', en: 'Server-Side Request Forgery.', de: 'Server-Side Request Forgery — den Server zu unerwünschten Anfragen zwingen.' },
  { re: /\bCSRF\b/i, term: 'CSRF', tr: 'Cross-Site Request Forgery — kullanıcının istemsiz işlem yapmasını sağlama.', en: 'Cross-Site Request Forgery.', de: 'Cross-Site Request Forgery — den Nutzer zu unbeabsichtigten Aktionen bringen.' },
  { re: /\bCWE\b/i, term: 'CWE', tr: 'Common Weakness Enumeration — zafiyet türleri sınıflandırması.', en: 'Common Weakness Enumeration.', de: 'Common Weakness Enumeration — Klassifizierung von Schwachstellentypen.' },
  { re: /\bOWASP\b/i, term: 'OWASP', tr: 'Açık web uygulama güvenliği topluluğu; Top 10 ve test kılavuzlarıyla bilinir.', en: 'Open Web Application Security Project.', de: 'Open Web Application Security Project; bekannt für die Top 10 und Testleitfäden.' },
  { re: /\bTLS\b|SSL/i, term: 'TLS', tr: 'Taşıma katmanı şifrelemesi (HTTPS’in temeli).', en: 'Transport Layer Security.', de: 'Transport Layer Security (Grundlage von HTTPS).' },
  { re: /\bHSTS\b|Strict-Transport-Security/i, term: 'HSTS', tr: 'Tarayıcıyı yalnız HTTPS kullanmaya zorlayan güvenlik başlığı.', en: 'HTTP Strict Transport Security header.', de: 'Sicherheitsheader, der den Browser zwingt, nur HTTPS zu verwenden.' },
  { re: /\bCSP\b|Content-Security-Policy/i, term: 'CSP', tr: 'İçerik Güvenlik Politikası — XSS/enjeksiyon azaltma başlığı.', en: 'Content Security Policy.', de: 'Content Security Policy — Header zur Minderung von XSS/Injection.' },
  { re: /\bCORS\b/i, term: 'CORS', tr: 'Kaynaklar-arası paylaşım politikası; gevşek yapılandırma risklidir.', en: 'Cross-Origin Resource Sharing.', de: 'Cross-Origin Resource Sharing; eine lockere Konfiguration ist riskant.' },
  { re: /\bJWT\b/i, term: 'JWT', tr: 'JSON Web Token — oturum/yetki taşıyan imzalı belirteç.', en: 'JSON Web Token.', de: 'JSON Web Token — signiertes Token, das Session/Berechtigung trägt.' },
  { re: /\bKVKK\b/i, term: 'KVKK', tr: 'Kişisel Verilerin Korunması Kanunu (Türkiye).', en: 'Turkish Personal Data Protection Law.', de: '' },
  { re: /VERB[İi]S/i, term: 'VERBİS', tr: 'Veri Sorumluları Sicil Bilgi Sistemi (KVKK kayıt sistemi).', en: 'Turkish data controllers’ registry.', de: '' },
  { re: /clickjacking|X-Frame-Options/i, term: 'Clickjacking', tr: 'Sayfanın görünmez iframe içine alınıp kullanıcı tıklamalarının kandırılması.', en: 'Tricking clicks via invisible framing.', de: 'Klicks werden durch unsichtbares Framing getäuscht.' },
  { re: /forced browsing|yetki y[üu]kseltme/i, term: 'Forced Browsing', tr: 'Menüde olmayan (ör. yönetici) uç noktalara URL bilerek erişme.', en: 'Accessing hidden endpoints by guessing URLs.', de: 'Zugriff auf versteckte Endpunkte durch Erraten von URLs.' },
];
function buildGlossary(md: string, locale: 'tr' | 'en' | 'de'): string {
  // (P1/acceptance) /de VE /en'de KVKK/VERBİS gibi Türkiye'ye özel terimler sözlükte GÖSTERİLMEZ
  // (de === '' ile işaretli → hem de hem en'de elenir; UK raporu Türk mevzuat terimi içermemeli).
  const hits = GLOSSARY_TERMS.filter((g) => g.re.test(md)).filter((g) => !((locale === 'de' || locale === 'en') && g.de === ''));
  if (hits.length === 0) return '';
  const rows = hits.map((g) => `<tr><td><strong>${escapeHtml(g.term)}</strong></td><td>${escapeHtml(p3(locale, g.tr, g.en, g.de || g.en))}</td></tr>`).join('');
  return `<h2 id="s-glossary">${p3(locale, 'Ek — Sözlük', 'Appendix — Glossary', 'Anhang — Glossar')}</h2>
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
function buildTocPage(entries: { id: string; text: string }[], locale: 'tr' | 'en' | 'de'): string {
  // TEK numaralandırma: başlık metnindeki manuel "1./2./2.1" ön-eki kullanılır (otomatik <ol> sayacı
  // EKLENMEZ -> "1. 1. Yönetici Özeti" çakışması biter). "N.N" alt bölümler girintili gösterilir.
  const rows = entries.map((e) => {
    const sub = /^\d+\.\d+\s/.test(e.text.trim());
    return `<div class="toc-row${sub ? ' toc-sub' : ''}"><a href="#${e.id}">${escapeHtml(e.text)}</a></div>`;
  }).join('');
  return `<div class="toc-page"><h1>${p3(locale, 'İçindekiler', 'Table of Contents', 'Inhaltsverzeichnis')}</h1>${rows}</div>`;
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


// (TUTARLILIK) KONTROL ÖZETİ tablosunu ayrıştırıp Sonuç sütunu GERÇEKTEN "kapsam dışı" olan kontrol
// adlarını (küçük harf) döndürür. İnceleme Notu + detay-collapse bu TEK kaynaktan üretilir → özet/tablo/
// not asla çelişmez. (buildPositiveAssurance ile AYNI tablo-okuma disiplini.)
function scopeOutControlsFromTable(md: string): Set<string> {
  const out = new Set<string>();
  const lines = md.split('\n');
  for (let i = 0; i < lines.length; ) {
    if (!/^\s*\|.*\|\s*$/.test(lines[i])) { i++; continue; }
    const block: string[] = [];
    while (i < lines.length && /^\s*\|.*\|\s*$/.test(lines[i])) { block.push(lines[i]); i++; }
    if (block.length < 2) continue;
    const cells = (r: string) => r.replace(/^\s*\|/, '').replace(/\|\s*$/, '').split('|').map((c) => c.trim());
    const header = cells(block[0]).map((h) => lcMatch(h));
    const kCol = header.findIndex((h) => /kontrol|control/.test(h));
    const sCol = header.findIndex((h) => /sonu[çc]|result/.test(h));
    if (kCol === -1 || sCol === -1) continue; // yalnız KONTROL ÖZETİ tablosu
    for (let r = 1; r < block.length; r++) {
      if (/^\s*\|[\s:|-]+\|\s*$/.test(block[r])) continue;
      const c = cells(block[r]);
      const sonuc = lcMatch(c[sCol] ?? '');
      if (/kapsam d|giri[şs] noktas[ıi] yok|out of scope|no entry point/.test(sonuc)) {
        const name = stripMd(c[kCol] ?? '').trim();
        if (name) out.add(name.toLocaleLowerCase('tr'));
      }
    }
  }
  return out;
}

export function buildHtml(bodyMd: string, meta: ReportPdfMeta, opts: ReportPdfOptions): string {
  const t = L[meta.locale];
  const dateStr = meta.createdAt.toLocaleDateString(meta.locale === 'tr' ? 'tr-TR' : meta.locale === 'de' ? 'de-DE' : 'en-GB', {
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
    const risk = DETERMINISTIC_PDF_PKGS.has(meta.packageKey ?? '') ? assessBasit(effectiveMd, t, meta.locale) : assessRisk(effectiveMd, meta.locale);
    // (bundle_surface) Ust kutu cumlesi = GENEL DEĞERLENDİRME govde cumlesi (worst-case ALANA
    // ozgu, koddan uretilen) — sabit/gelisiguzel "ör. sertifika/hostname" ornegi YERINE gercek
    // bulgu. Boylece kutu <-> YÖNETİCİ ÖZETİ/GENEL DEĞERLENDİRME HER ZAMAN tutarli. (Yalniz
    // bundle_surface; basit_tarama ve digerleri DEGISMEZ.)
    if (BUNDLE_COMBINED_PKGS.has(meta.packageKey ?? '')) {
      const g = effectiveMd.match(/##\s*(?:GENEL DEĞERLENDİRME|GESAMTBEWERTUNG|OVERALL ASSESSMENT)\s*\n+\*\*(?:Risk Seviyesi|Risikostufe|Risk Level):[^\n]*\*\*\s*\n+([^\n]+)/);
      if (g) risk.sentence = g[1].trim().replace(/\*\*/g, ''); // kutu duz metin — markdown ** temizle
    }
    // (ROZET TUTARLILIĞI) Severity'li AKTİF bulgu YOK (master "Temiz") ama rozet Yüksek diyorsa
    // çelişki doğuyor (config/başlık eksikleri "zafiyet" değildir). 0 bulguda Yüksek'i "İyileştirilebilir"e
    // indir -> rozet ↔ master TUTARLI. (Orta/Düşük dokunulmaz; Basit'in "Temiz+Orta" hali korunur.)
    if (parsed && parsed.rows.length === 0 && (risk.level === 'high' || risk.level === 'medium-high')) {
      risk.level = 'medium';
      risk.label = meta.locale === 'de' ? 'Verbesserungsfähig' : meta.locale === 'tr' ? 'İyileştirilebilir' : 'Improvable';
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
  const { reportNo, verifyCode } = reportIdentifiers(meta.hostname, meta.createdAt, opts.hideDate);
  // (parsed/isCompliance yukarıda hesaplandı — rozet tutarlılığı için.)
  // (DÜRÜSTLÜK) Hedefe ulaşılamadı/tarama yürütülemedi -> master "Temiz" DEĞİL "İncelenemedi",
  // dağılımdaki 0'lar "temiz" değil "incelenemedi" olarak işaretlenir. (assessBasit rozeti zaten nötr yapıyor.)
  const unscannable = /risk\s*seviyesi\s*[:：]\s*\*{0,2}\s*incelenemedi|risikostufe\s*[:：]\s*\*{0,2}\s*nicht\s*pr[üu]fbar|tarama\s*(yap[ıi]lamad|y[uü]r[uü]t[uü]lemed)|ula[şs][ıi]lamad[ıi][ğg][ıi] i[çc]in kontrol/.test(effectiveMd.slice(0, 2000).toLocaleLowerCase('tr'));
  // (KEŞİF A/B — YALNIZ bundle_recon) Master tabloda çıplak "Temiz" yerine kısa özet + tablonun
  // hemen altında "ne test edildi / ne çıktı" kutusu. Diğer paketlerde isRecon=false -> hiçbir fark yok.
  const pkgKey = meta.packageKey ?? '';
  const isRecon = RICH_TEMPLATE_PKGS.has(pkgKey);
  const reconRows = isRecon ? parseReconAssurance(effectiveMd) : [];
  const reconEmpty = isRecon && !unscannable ? reconEmptySummary(reconRows, loc, pkgKey) : '';
  const reconSummaryHtml = isRecon && !unscannable ? buildReconAssuranceSummary(effectiveMd, loc, pkgKey) : '';
  const distMasterHtml = parsed
    ? buildDistribution(parsed.counts, loc, unscannable) + buildMasterTable(parsed.rows, loc, unscannable, reconEmpty) + reconSummaryHtml
    : '';
  // 2.3 Detaylı Bulgular (İş Etkisi + CWE) yalnız GERÇEK raporlarda; örneklerde (assessOverride) kendi var.
  const detailedHtml = parsed && !opts.assessOverride ? buildDetailedFindings(parsed.rows, loc) : '';
  // (PREMIUM) Pozitif Güvence — KONTROL ÖZETİ'ndeki TEMİZ (✓) kontrollerden türetilir (uydurma yok).
  const isPremium = ['bundle_active_verify', 'bundle_full_pentest'].includes(meta.packageKey ?? '');
  const assuranceHtml = isPremium && !opts.assessOverride ? buildPositiveAssurance(effectiveMd, loc) : '';
  const glossaryHtml = buildGlossary(effectiveMd, loc);
  const notCert = p3(loc, 'Bu rapor resmi sızma testi / sertifikasyon değildir.', 'This report is not a formal penetration test / certification.', 'Dieser Bericht ist kein formeller Penetrationstest / keine Zertifizierung.');
  const sealTitle = p3(loc, 'CyberTestify Güvenlik Taraması — Tamamlandı', 'CyberTestify Security Scan — Completed', 'CyberTestify-Sicherheitsscan — Abgeschlossen');

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
    // (TR-I HATASI) tr-locale küçültme ASCII "I" -> "ı" (noktasız) yapar; İngilizce başlık
    // "EXECUTIVE"/"PRIORITY" -> "executıve"/"prıorıty" olur ve anahtar-kelime regex'i TUTMAZ
    // (EN raporları yapısız yola düşer). Türkçe İ eşleşmesini korumak için tt (tr) TUTULUR;
    // İngilizce/Almanca anahtar kelimeleri de yakalamak için varsayılan küçültme EKLENİR.
    const ttx = hm ? `${tt} ${stripMd(hm[1]).toLowerCase()}` : '';
    if (!tt) { if (chunk.trim()) detailParts.push(chunk.replace(/^###\s/gm, '#### ').replace(/^##\s/gm, '### ')); continue; }
    if (/^bulgular$/.test(tt)) continue; // boş "## Bulgular" wrapper
    if (/y[öo]netici [öo]zeti|executive summary|managementzusammenfassung/.test(ttx)) { hasExec = true; summaryParts.push(chunk.replace(/^##[^\n]*\n?/, '').trim()); continue; }
    if (/genel de[ğg]erlendirme|overall assessment|gesamtbewertung/.test(ttx)) continue; // MÜKERRER -> at
    if (/[öo]ncelikli aksiyonlar|priority actions|iyile[şs]tirme [öo]ncelik|priorisierte (aktionen|ma[ßs]nahmen)/.test(ttx)) { summaryParts.push(chunk.replace(/^###\s/gm, '#### ').replace(/^##\s/gm, '### ')); continue; }
    detailParts.push(chunk.replace(/^###\s/gm, '#### ').replace(/^##\s/gm, '### ')); // detay -> H3
  }
  const reorganize = hasExec && !opts.assessOverride;
  // (ORNEK PDF) Uyari afisi — yalnizca sampleNotice verildiginde; belirgin amber kutu, raporun basinda.
  const sampleNoticeHtml = opts.sampleNotice && opts.sampleNotice.trim()
    ? `<div class="sample-notice">⚠️ ${escapeHtml(opts.sampleNotice.trim())}</div>` : '';
  const H2 = (id: string, tr: string, en: string, deS?: string) => `<h2 id="${id}">${escapeHtml(loc === 'de' ? (deS ?? en) : loc === 'tr' ? tr : en)}</h2>`;

  let contentInner0: string;
  if (reorganize) {
    // (KAPSAM-DIŞI SADELEŞTİRME) Hedefin mimarisine UYMAYAN / giriş noktası olmayan kontroller
    // (bulgu YOK) yarım-sayfa "NE KONTROL EDİLDİ/BULGULAR" bloğu olarak açılmasın; TEK "İnceleme
    // Notu" kutusunda toplanır. GERÇEKTEN çalışan (⚠ gösterge/bulgu olan) kontroller TAM blok kalır.
    // (TUTARLILIK — TABLO İLE ÜRET; Sütun 0 / QA) Bir kontrolü "kapsam dışı" saymanın TEK kaynağı
    // KONTROL ÖZETİ tablosunun Sonuç sütunudur. ESKİ HATA: gövde-regex + şiddet-satırı sezgisi, "⚠ Sınırlı
    // gösterge" veren ÇALIŞAN bir bölümü (severity kelimesi satırda yoksa) yanlışlıkla "kapsam dışı" sayıp
    // detayını siliyor ve İnceleme Notu'na yazıyordu (tablo ile ÇELİŞKİ). Artık İnceleme Notu == tablo.
    const tableScopeOut = scopeOutControlsFromTable(effectiveMd);
    const scopeOut: string[] = [];
    const keptDetail = detailParts.filter((chunk) => {
      const hm = chunk.match(/^###\s+(.+?)\s*(?:\n|$)/);
      const name = hm ? stripMd(hm[1]).trim() : '';
      const isControlBlock = /NE KONTROL ED[İi]LD[İi]|####?\s*BULGULAR/i.test(chunk);
      if (name && isControlBlock && tableScopeOut.has(name.toLocaleLowerCase('tr'))) { scopeOut.push(name); return false; }
      return true;
    });
    const scopeNote = scopeOut.length
      ? `<div class="scope-note"><strong>${p3(loc, 'İnceleme Notu', 'Review Note', 'Prüfhinweis')}:</strong> ${loc === 'tr'
          ? `Şu kontroller, hedefin mimarisine uygulanabilir bir giriş noktası bulunmadığından mimari gereği kapsam dışı bırakılmıştır (Kontrol Özeti tablosunda da işaretlidir): ${escapeHtml(scopeOut.join(', '))}.`
          : loc === 'de'
            ? `Die folgenden Kontrollen wurden ausgeschlossen, da für die Zielarchitektur kein anwendbarer Einstiegspunkt existiert (auch in der Kontrollübersicht markiert): ${escapeHtml(scopeOut.join(', '))}.`
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
        // yalnız üst-düzey madde tut (per-kontrol uzun listeyi at). "API saldırı yüzeyi" (Bölüm B —
        // keşfedilen/auth-kilitli API uç sayısı) üst-düzey değer bilgisidir -> korunmalı.
        // (3 BÖLGE) Türkçe + İngilizce + Almanca üst-düzey madde etiketleri. lcMatch: "API"->"api"
        // (tr-locale'de "apı" olurdu; lcMatch I/İ'yi 'i'ye indirger).
        return /genel risk|kapsam|[öo]nerilen|api sald|overall risk|scope|recommended|api attack/.test(lcMatch(bm[1]));
      }).join('\n');
    }
    const summaryBody = dedupeBlockquotes(md.render(execMd)) + (hasVuln ? buildPriorities(parsed!.rows, loc) : '');
    const detailBody0 = scopeNote + dedupeBlockquotes(md.render(keptDetail.join('\n\n')));
    const detailBody = isRecon ? reconStyleBlocks(detailBody0) : detailBody0;
    const hasFindings = !!(distMasterHtml || detailedHtml);
    const findingsSection = hasFindings ? H2('s-findings', '2. Bulgular', '2. Findings', '2. Befunde') + distMasterHtml + detailedHtml + assuranceHtml : '';
    const cn = hasFindings ? 3 : 2; // bulgu bölümü yoksa (uyum) numara boşluğu olmasın
    // AI ve Ekler bölümlerini de numarala (TOC tek-numara okur) — kilit emojisi korunur.
    const fixNum = fixHtml.replace(/<h2 id="s-ai">(🔒 )?/, (_m, lock) => `<h2 id="s-ai">${lock ?? ''}${cn + 1}. `);
    const glossNum = glossaryHtml.replace(/<h2 id="s-glossary">/, `<h2 id="s-glossary">${cn + 2}. `);
    // (TOC HİZASI) "Ek Pasif Kontroller" bölümü §3 (Kontrol Özeti) altında bir alt-bölümdür ->
    // h3'e indir ki TOC'ta ayrı numarasız satır olarak görünüp numaralandırmayı bozmasın.
    const extrasSub = extrasHtml.replace(/<h2\b/g, '<h3').replace(/<\/h2>/g, '</h3>');
    contentInner0 =
      H2('s-summary', '1. Yönetici Özeti', '1. Executive Summary', '1. Managementzusammenfassung') + sampleNoticeHtml + assessBox + (parsed ? buildManagementDecision(parsed.counts, loc) : '') + summaryBody +
      findingsSection +
      H2('s-controls', `${cn}. Kontrol Özeti ve Metodoloji`, `${cn}. Controls & Methodology`, `${cn}. Kontrollübersicht & Methodik`) + detailBody + (parsed ? buildMethodologyTables(loc) : '') +
      extrasSub + fixNum + glossNum;
  } else {
    // Yapısız gövde / örnek PDF: mevcut akış (assessBox + dağılım/master + gövde + AI + sözlük).
    const bodyHtml0 = dedupeBlockquotes(md.render(effectiveMd) + extrasHtml + fixHtml);
    const bodyHtml = isRecon ? reconStyleBlocks(bodyHtml0) : bodyHtml0;
    contentInner0 = `${sampleNoticeHtml}${assessBox}${distMasterHtml}${detailedHtml}${bodyHtml}${glossaryHtml}`;
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
  .sample-notice { border-radius: 8px; padding: 12px 16px; margin: 4px 0 16px; border: 1px solid #F5C77A; border-left: 4px solid #E8912B; background: #FDF5E6; color: #7A4B12; font-size: 12px; font-weight: 600; line-height: 1.5; }
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
  /* ======================================================================
     (A/B TESTİ — ZENGİN ŞABLON: Keşif + Basit Tarama) 4 blok tipi görsel olarak ayrışır.
     Kapsam: .recon-report sınıfı YALNIZ RICH_TEMPLATE_PKGS paketlerine basılır; kalan 3 paketin
     (Uyum / Aktif Doğrulama / Tam Pentest) PDF'i bu kuralların HİÇBİRİNİ almaz.
     Palet marka ile uyumlu: koyu yeşil #123F3A (başlık) + yeşilin açık tonu (test+sonuç)
     + AMBER'in açık tonu (kapsam/dürüstlük notu). Marka turuncusu (#F5A623) ciddi
     bulgu/AI bölümüne ait olduğu için rutin notlarda KULLANILMAZ — karışmasın.
     ====================================================================== */
  /* (1) BAŞLIK — kalın, marka rengi, arka plan YOK */
  .recon-report h2, .recon-report h3, .recon-report h4 { color: #123F3A; background: none; }
  .recon-report h3 { border-left: 3px solid #1C6B60; padding-left: 9px; }
  /* (2) TEST + SONUÇ — açık yeşil, ✅ */
  .recon-report td.rc-ok { background: #EFF8F4; color: #12564C; font-weight: 600; }
  .recon-report li.rc-ok { background: #EFF8F4; color: #12564C; padding: 3px 8px; border-radius: 4px; list-style: none; margin-left: -18px; }
  .rc-summary { margin: 10px 0 18px; }
  .rc-summary-title { font-size: 12.5px; font-weight: 700; color: #123F3A; margin-bottom: 6px; }
  .rc-ok-box { border: 1px solid #BFE3D5; border-left: 4px solid #1C6B60; background: #F1F9F5; border-radius: 0 6px 6px 0; padding: 10px 14px; margin-bottom: 8px; }
  .rc-warn-box { border: 1px solid #F0D9A8; border-left: 4px solid #C98A16; background: #FEF9EE; border-radius: 0 6px 6px 0; padding: 10px 14px; }
  /* (ÜÇÜNCÜ DURUM) "İncelenemedi" — bulgu DEĞİL; nötr gri (rc-does-not ile aynı ton, yeni renk yok) */
  .rc-na-box { border: 1px solid #D9E0DD; border-left: 4px solid #8A9A95; background: #F4F6F5; border-radius: 0 6px 6px 0; padding: 10px 14px; margin-top: 8px; }
  .rc-na-box .rc-box-head { color: #4A5A55; }
  .rc-na-box li { color: #3d4a46; }
  .rc-na-box .rc-area { color: #4A5A55; }
  .rc-box-head { font-size: 11px; font-weight: 800; text-transform: uppercase; letter-spacing: .4px; margin-bottom: 5px; }
  .rc-ok-box .rc-box-head { color: #12564C; }
  .rc-warn-box .rc-box-head { color: #8A5B08; }
  .rc-summary ul { margin: 0; padding-left: 16px; }
  .rc-summary li { font-size: 11.5px; line-height: 1.55; margin: 2px 0; }
  .rc-ok-box li { color: #1b3a34; }
  .rc-warn-box li { color: #5C3D08; }
  .rc-area { font-weight: 700; color: #123F3A; }
  .rc-warn-box .rc-area { color: #7A4B12; }
  /* (3) AÇIKLAMA / METODOLOJİ — nötr, arka plan YOK (varsayılan paragraf) */
  .recon-report p { background: none; color: #1b2b28; }
  /* (4) UYARI / KAPSAM NOTU — amber kutu; CİDDİ BULGU rengiyle (kırmızı/turuncu) KARIŞMAZ */
  .recon-report blockquote { background: #FEF9EE; border-left: 4px solid #C98A16; color: #5C3D08; border-radius: 0 4px 4px 0; }
  .recon-report td.rc-warn { background: #FEF9EE; color: #7A4B12; font-weight: 600; }
  .recon-report li.rc-warn { background: #FEF9EE; color: #7A4B12; padding: 3px 8px; border-radius: 4px; list-style: none; margin-left: -18px; }
  /* Ciddi bulgu göstergeleri (şiddet rozetleri / master tablo) DOKUNULMAZ: kendi kırmızı/turuncu
     renklerini korur -> rutin kapsam notu (amber) ile ASLA aynı görünmez. */
  /* (3.b) "NE değerlendirir / NE değerlendirmez" — ikisi de BİLGİ; kırmızı yok */
  .rc-does, .rc-does-not { border-radius: 6px; padding: 10px 14px; margin: 8px 0; }
  .rc-does { background: #F1F9F5; border: 1px solid #BFE3D5; border-left: 4px solid #1C6B60; }
  .rc-does-not { background: #F4F6F5; border: 1px solid #D9E0DD; border-left: 4px solid #8A9A95; }
  .rc-does p, .rc-does-not p { margin: 0; }
  .rc-does strong { color: #12564C; }
  .rc-does-not strong { color: #4A5A55; }
  /* (4.b) AI ÇÖZÜM ÖNERİLERİ kod blokları — açıklama metninden ayrı görsel kimlik */
  .recon-report .fix-section pre { background: #10221F; color: #DCEFE9; border: 1px solid #23433D; border-radius: 6px; padding: 10px 12px; }
  .recon-report .fix-section pre code { background: none; color: inherit; }
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
  /* (Faz 9 — SUNUM) şiddet chip'i, düzeltme kutusu, yönetim kutusu, sunum tabloları — yalnız görsel */
  .sev-chip { display: inline-block; color: #fff; padding: 1px 7px; border-radius: 4px; font-size: 9.5px; font-weight: 800; letter-spacing: 0.03em; vertical-align: middle; margin-right: 6px; }
  .chip-critical { background: #B3261E; } .chip-high { background: #D64545; }
  .chip-medium { background: #E0940E; } .chip-low { background: #6B7280; }
  .fb-critical { border-left-color: #B3261E !important; } .fb-high { border-left-color: #D64545 !important; }
  .fb-medium { border-left-color: #E0940E !important; } .fb-low { border-left-color: #9AA0A6 !important; }
  .finding-block .fb-row { margin: 4px 0; }
  .fix-box { margin: 8px 0 6px; border: 1px solid #CFE6DE; border-left: 4px solid #1C6B60; background: #F1F8F5; border-radius: 6px; overflow: hidden; }
  .fix-box-t { background: #1C6B60; color: #fff; font-size: 10px; font-weight: 800; letter-spacing: 0.04em; padding: 3px 10px; text-transform: uppercase; }
  .fix-box-b { padding: 7px 10px; font-size: 11px; color: #14403A; }
  .mgmt-box { margin: 8px 0 16px; border: 1px solid #E6C88F; border-left: 4px solid #E0940E; background: #FEF8EC; border-radius: 8px; padding: 10px 14px; }
  .mgmt-box .mgmt-t { font-size: 12px; font-weight: 800; color: #8A5A0B; margin-bottom: 3px; }
  .mgmt-box p { margin: 0; font-size: 11.5px; color: #4a4033; line-height: 1.5; }
  .pres-h3 { color: #123F3A; font-size: 12.5px; margin: 16px 0 6px; }
  .pres-table { width: 100%; border-collapse: collapse; margin: 4px 0 8px; font-size: 11px; }
  .pres-table th { background: #123F3A; color: #EEF5F3; text-align: left; padding: 5px 9px; font-size: 10px; font-weight: 700; }
  .pres-table td { border: 1px solid #E1EAE7; padding: 5px 9px; vertical-align: top; color: #263c38; }
  .pres-table td:first-child { white-space: nowrap; width: 150px; font-weight: 600; }
  .pres-note { font-size: 10px; color: #5b6b67; font-style: italic; margin: 4px 0 0; }
</style></head>
<body>
  <div class="cover">
    <div class="cover-top">${LOGO_SVG}<div class="brand">Cyber<span>Testify</span></div></div>
    <div class="cover-mid">
      ${opts.hideDate ? '' : `<div class="cover-datebadge">${escapeHtml(dateStr)}</div>`}
      <div class="cover-title">${escapeHtml(t.brandTagline)}</div>
      <div class="cover-sub">${escapeHtml(meta.hostname)} &nbsp;·&nbsp; ${escapeHtml(meta.packageName)}</div>
      <div class="cover-seal">
        <div class="seal-title">${escapeHtml(sealTitle)}</div>
        <div class="seal-row">${p3(meta.locale, 'Rapor No', 'Report No', 'Bericht-Nr.')}: <strong>${reportNo}</strong></div>
        <div class="seal-row">${p3(meta.locale, 'Doğrulama Kodu', 'Verification Code', 'Verifizierungscode')}: <strong>${verifyCode}</strong></div>
        ${opts.hideDate ? '' : `<div class="seal-row">${escapeHtml(t.date)}: ${escapeHtml(dateStr)}</div>`}
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
    ${opts.hideDate ? '' : `<div><div class="k">${escapeHtml(t.date)}</div><div class="v">${escapeHtml(dateStr)}</div></div>`}
    <div><div class="k">${p3(meta.locale, 'Rapor No', 'Report No', 'Bericht-Nr.')}</div><div class="v">${reportNo}</div></div>
  </div>
  <div class="content${isRecon ? ' recon-report' : ''}">${contentInner}</div>
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
  const { reportNo } = reportIdentifiers(meta.hostname, meta.createdAt, opts.hideDate);
  const confidential = p3(meta.locale, 'Gizli', 'Confidential', 'Vertraulich');

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

/**
 * (Otonom Red Team) Ham HTML dokümanını PDF'e çevirir — paket rapor şablonundan BAĞIMSIZ (kendi
 * stilini taşır). Mevcut Chromium'u kullanır. renderReportPdf'in paket-özel mantığına dokunmaz.
 */
export async function htmlToPdfBuffer(html: string, footerText = 'CyberTestify · Otonom AI Red Team (deneysel)'): Promise<Buffer> {
  const browser = await puppeteer.launch({
    executablePath: CHROMIUM_PATH,
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--font-render-hinting=none'],
  });
  try {
    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: 'load' });
    const pdf = await page.pdf({
      format: 'A4', printBackground: true,
      margin: { top: '14mm', bottom: '16mm', left: '10mm', right: '10mm' },
      displayHeaderFooter: true, headerTemplate: '<div></div>',
      footerTemplate: `<div style="width:100%;font-size:8px;color:#94a3b8;padding:0 12mm;display:flex;justify-content:space-between;">
        <span>${escapeHtml(footerText)}</span><span>Sayfa <span class="pageNumber"></span>/<span class="totalPages"></span></span></div>`,
    });
    return Buffer.from(pdf);
  } finally {
    await browser.close();
  }
}
