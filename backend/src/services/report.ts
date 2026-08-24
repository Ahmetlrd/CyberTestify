import { prisma } from '../db.js';
import { unscannableReport } from './unscannable.js';
import { config } from '../config.js';
import * as pentagi from '../pentagi/client.js';
import { encryptReport, generateReportAccessSecret } from './crypto.js';
import { redactAll } from './piiRedaction.js';
import { validateAndRepairReport } from './reportValidator.js';
import { logScanStep } from './scanLogger.js';
import { FIX_SUGGESTIONS_DELIM, getPackageDef, securityProfileFor } from './scanPackages.js';
import { hasPassiveExtras, runPassiveExtras, renderPassiveExtrasMarkdown, PASSIVE_EXTRAS_DELIM } from './passiveExtras.js';
import { buildHeaderFixSuggestions } from './fixSuggestions.js';
import { generateBasitReport } from './basitReport.js';
import {
  generateSslTlsReport, generateHeaderLeakReport, generateDnsEmailReport,
  generateCorsCookieReport, generateCspReport, generateBundleSurfaceReport,
} from './surfaceReports.js';
import { generateBundleComplianceReport } from './complianceReports.js';
import { generateBundleReconReport } from './reconReports.js';
import {
  generateInjectionVerifyReport, generateIdorVerifyReport, generateBundleActiveVerifyReport,
  generateSsrfVerifyReport, generateRceVerifyReport, generateFileUploadVerifyReport,
  generateBusinessLogicVerifyReport, generateRaceMassAssignVerifyReport,
} from './activeVerifyReports.js';
import { generateAuthenticatedReport } from './authenticatedReports.js';
import { authenticateOrder } from './authLogin.js';

// (Tam Kapsamlı Pentest) AUTHENTICATED bundle — rapor (host) DEĞİL, ÖNCE login (order kimlik bilgisi)
// gerektirir; DETERMINISTIC_GENERATORS (host-imzalı) yerine generateAndStoreReport'ta özel dallanır.
const AUTH_BUNDLE_KEY = 'bundle_full_pentest';

// Deterministik (kod-yazimi) rapor ureten paketler: key -> uretici(hostname).
// Hepsi { findings, fixText } | null doner (null -> ajan/ham-kanit fallback).
const DETERMINISTIC_GENERATORS: Record<string, ((host: string) => Promise<{ findings: string; fixText: string } | null>) | undefined> = {
  basit_tarama: generateBasitReport,
  ssl_tls: generateSslTlsReport,
  header_leak: generateHeaderLeakReport,
  dns_email: generateDnsEmailReport,
  cors_cookie: generateCorsCookieReport,
  csp_analiz: generateCspReport,
  bundle_surface: generateBundleSurfaceReport, // kombine paket -> 5 alan TEK raporda
  bundle_compliance: generateBundleComplianceReport, // kombine paket -> KVKK+PCI+ISO TEK raporda
  bundle_recon: generateBundleReconReport, // kombine paket -> subdomain+api+cms/cve TEK raporda
  injection_verify: generateInjectionVerifyReport, // aktif-hafif: SQLi/XSS kod-tabanli prob (PentAGI'siz)
  idor_verify: generateIdorVerifyReport, // aktif-hafif: kimlik-dogrulamasiz IDOR gostergesi (PentAGI'siz)
  bundle_active_verify: generateBundleActiveVerifyReport, // kombine: 7 aktif-hafif kontrol (in-band)
  ssrf_verify: generateSsrfVerifyReport,
  rce_verify: generateRceVerifyReport,
  file_upload_verify: generateFileUploadVerifyReport,
  business_logic_verify: generateBusinessLogicVerifyReport,
  race_massassign_verify: generateRaceMassAssignVerifyReport,
};

// Rapor TAMAMEN koddan uretilen (backend collector'lari) paketler -> PentAGI ajani/sandbox'i
// GEREKSIZ. Orchestrator bunlar icin createFlow'u atlar (pentagiFlowId 'deterministic-' sentinel);
// worker + generateAndStoreReport zaten sentinel'e gore PentAGI cagrilarini atliyor. TEK KAYNAK.
export function isDeterministicPackage(key: string): boolean {
  return DETERMINISTIC_GENERATORS[key] !== undefined || key === AUTH_BUNDLE_KEY;
}

type Locale = 'tr' | 'en' | 'de';

/**
 * Ajanin GERCEK bulgularini (tamamlama raporlarini) toplar.
 *
 * KOK DUZELTME (2026-08-02): PentAGI veri modelinde bir gorev/alt-gorev icin ATAMA
 * (talimat) ile TAMAMLAMA (sonuc raporu) AYRI kolonlarda tutulur:
 *   - Task.input / Subtask.description / MessageLog.message  -> ATAMA (talimat)  [KULLANMA]
 *   - Task.result / Subtask.result / MessageLog.result       -> TAMAMLAMA (rapor) [KULLAN]
 * Bir `report`-tipi MessageLog'ta bile `message`=atama, `result`=tamamlamadir.
 * Eski kod tavana carpan (Task.result bos) taramalarda `messageLogs.message`'e
 * dusuyor, yani ajanin gercek son ciktisi yerine ona verilen GOREV TALIMATINI
 * rapora yaziyordu (iso27001/kvkk/header_leak'te ayni sistemik hata). Artik yalniz
 * `result` (tamamlama) alanlarini okuyoruz; uzunluk/sezgi tahmini YOK, resmi alan ayrimi.
 *
 * Oncelik: (1) NIHAI SENTEZ alt-gorevi — result'i ${FIX_SUGGESTIONS_DELIM} iceren
 * subtask musteriye yonelik TEK temiz rapor + cozum onerileridir; VARSA yalniz onu al
 * (ham arastirma subtask'larini ONUNE EKLEME); yoksa (2) task-seviyesi sentez (Task.result,
 * dogal bitiste dolu); yoksa (3) TUM alt-gorev tamamlamalari birlestirilir (tavana carpan
 * taramada bile dolu); yoksa (4) report-msglog.result; yoksa (5) done.result. Hicbir asamada
 * ATAMA metni (message/description) bulgu sayilmaz. Tum ciktilara SUREC-DILI temizligi
 * (stripProcessLanguage) uygulanir — bu bir GUVENLIK AGIDIR; asil cozum promptta (ajan
 * tek temiz rapor yazar). Bkz scanPackages BUDGET_GUARD/FIX_SUGGESTIONS.
 */
function collectFindings(logs: pentagi.FlowLogs): string {
  const join = (parts: string[]) => parts.filter((p) => p.trim().length > 0).join('\n\n---\n\n').trim();
  const subs = logs.tasks.flatMap((t) => t.subtasks ?? []).filter((st) => (st.result ?? '').trim().length > 0);

  // (1) NIHAI SENTEZ alt-gorevi: result'i FIX_SUGGESTIONS delimiter'i iceren subtask, ajanin
  //     yazmaya YONLENDIRILDIGI musteriye-yonelik tek rapor + fix'tir. VARSA yalniz onu al —
  //     boylece ham "arastirma" subtask'lari (surec dili) rapora KARISMAZ + fix bolumu gelir.
  const synth = subs.filter((st) => (st.result ?? '').includes(FIX_SUGGESTIONS_DELIM));
  if (synth.length) return stripProcessLanguage(join(synth.map((st) => (st.result ?? '').trim())));

  // (2) Task-seviyesi tamamlama sentezi (dogal bitiste PentAGI reporter'i doldurur).
  const taskText = join(
    logs.tasks
      .filter((t) => (t.result ?? '').trim().length > 0)
      .map((t) => `### ${t.title}\n\n${(t.result ?? '').trim()}`),
  );
  if (taskText) return stripProcessLanguage(taskText);

  // (3) TUM alt-gorev TAMAMLAMALARI. Tavana carpan taramada sentez subtask'i CALISMAMIS
  //     olabilir; elde ne varsa birlestir (surec-dili temizligiyle).
  const subtaskText = join(subs.map((st) => `### ${st.title}\n\n${(st.result ?? '').trim()}`));
  if (subtaskText) return stripProcessLanguage(subtaskText);

  // (4) report-tipi MessageLog'larin TAMAMLAMASI (message DEGIL, result).
  const reportText = join(
    logs.messageLogs.filter((m) => m.type === 'report').map((m) => (m.result ?? '').trim()),
  );
  if (reportText) return stripProcessLanguage(reportText);

  // (5) Son care: done-tipi MessageLog'un result'i (yoksa message'a dusme — atama olabilir).
  return stripProcessLanguage(join(logs.messageLogs.filter((m) => m.type === 'done').map((m) => (m.result ?? '').trim())));
}

/**
 * GUVENLIK AGI: rapor metninden ic-surec (workflow) dilini temizler. Asil cozum promptta
 * (ajan bunlari hic yazmamali); bu, capped/eski taramalarda kalan kalintilar icin. Yalniz
 * ACIKCA surec-satirlarini duser + baslik "Subtask/Alt-Gorev N ... Raporu" onekini yumusatir;
 * icerigi (teknik bulgu) bozmaz.
 */
export function stripProcessLanguage(md: string): string {
  const dropLine = [
    /^#{1,6}\s*(alt[-\s]?g[oö]rev|subtask)\b/i, // "### Subtask 308 ...", "## Alt-Görev 335"
    /^\s*[*_-]*\s*(✅|✔|☑)?\s*(g[oö]rev\s+(basar|tamamland)|task\s+completed|görev başarıyla)/i,
    /^\s*[*_-]*\s*(ba[sş]ar[iı] durumu|success status)\s*[:：]/i,
    /^\s*#{0,6}\s*[*_-]*\s*(sonraki ad[iı]m|next steps?|siradaki ad[iı]m)\b/i,
    /^\s*[*_-]*\s*(subtask|alt[-\s]?g[oö]rev)\s*\d+.{0,50}(tamamlama raporu|completion report|sonu[cç] raporu)/i,
  ];
  const kept = md
    .split('\n')
    .filter((ln) => !dropLine.some((re) => re.test(ln.trim())));
  return kept
    .join('\n')
    // Baslik/cumle ici "Subtask 308:" / "Alt-Görev 335 -" oneklerini kaldir (baglami koru).
    .replace(/(^|[\s(])(subtask|alt[-\s]?g[oö]rev)\s*\d+\s*[:：\-–—]\s*/gi, '$1')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

// (KVKK GUVENLIK AGI — "UYUM BEYANI YOK" kurali) Asil cozum PROMPTTA (ajan bunlari hic
// yazmamali); bu, ajanin YINE DE urettigi kalintilar icin rapor-finalize SON-KONTROLUdur.
// Kesin uyum hukmu ("uyumlu/uyumsuz/compliant"), "ihlal" iddiasi, durum-ikonu (✓/❌) ve
// ic-surec (Subtask N) ifadelerini NOTR karsiliklariyla degistirir + kaldirir; kalinti
// kalirsa LOGLAR (fark edelim). YALNIZ kvkk_hazirlik'te cagrilir. (Not: madde numaralarina
// "Art. 5" atif SERBEST — yalniz "ihlal edildi" gibi KESIN hukum cumlesi notrlenir.)
const KVKK_FORBIDDEN_SCAN = /\b(uyumlu|uyumsuz|uyumluluk|ihlal|ihlâl|compliant|non-?compliant)\b/i;

export function sanitizeKvkkReport(md: string): string {
  let out = md;
  // 1) Kesin uyum durum degeri -> notr 3-deger. "Uygun" ZATEN notr (uyum kokenli degil), dokunma.
  out = out
    .replace(/uyumsuz(?:luk|dur)?/gi, 'Eksik')
    .replace(/uyumlu(?:luk|dur)?/gi, 'Uygun')
    .replace(/non-?compliant/gi, 'Eksik')
    .replace(/\bcompliant\b/gi, 'Uygun')
    // Buyuk-harf durum degerlerini (ör. ikon-yaninda "✓ UYGUN") Title-case'e normalize et.
    .replace(/\bUYGUN\b/g, 'Uygun')
    .replace(/\bD[İI]KKAT\b/g, 'Dikkat')
    .replace(/\bEKS[İI]K\b/g, 'Eksik');
  // 2) "ihlal" -> notr. Once baslik/kalip ("KVKK İhlali (Listeleri)"), sonra fiil, sonra isim.
  out = out
    .replace(/(?:🚨\s*)?KVKK\s*İhlal(?:i|leri|ler)?(?:\s*Listeler?i)?/gi, 'Gözlemlenen Eksiklikler')
    .replace(/İhlal\s*Listeler?i/gi, 'Gözlemlenen Eksiklikler')
    .replace(/ihlal\s+edil(?:di|iyor|mi[sş]tir|mektedir|ebilir)/gi, 'ile tam örtüşmüyor olabilir')
    .replace(/ihl[aâ]l(?:i|leri|ler|ini|inin)?/gi, 'eksiklik');
  // 3) Durum-ikonlari: tablo hucresi basindaki uyum-ikonunu (✓/✔/❌/✗/🚨) ve prose'daki
  //    "❌ Eksik" gibi kalintilari at ki notr 3-deger + renk-scripti (^eksik$) calissin.
  out = out
    .replace(/\|\s*[✓✔✗✘×❌🚨🔴🟠🟢]\s*/g, '| ')
    .replace(/[✓✔✗✘×❌🚨]\s*(?=(?:Eksik|Dikkat|Uygun)\b)/g, '');
  // 4) IC-SUREC sizintisi: "Subtask 417" / "Alt-Görev 417" iceren satir (Turkce ek dahil:
  //    417'ye/417'nin) + surec basligi/kalinti-cumlesi ("Sonraki Adımlar", "Rapor yazımı
  //    tamamlandı") TAMAMEN atilir — musteri ic gorev/surec referanslarini gormemeli.
  const dropProcessLine = [
    /\b(subtask|alt[-\s]?g[oö]rev)\s*\d+/i,
    /^#{0,6}\s*[*_-]*\s*(sonraki\s*ad[ıi]m|next\s*steps?|sıradaki\s*ad[ıi]m)/i,
    /^\s*[*_>-]*\s*rapor(un)?\s+(yaz[ıi]m[ıi]\s+)?tamamland/i,
  ];
  out = out
    .split('\n')
    .filter((ln) => !dropProcessLine.some((re) => re.test(ln.trim())))
    .join('\n')
    .replace(/\b(subtask|alt[-\s]?g[oö]rev)\s*\d+['’]?\w*/gi, '') // satir-ici kalinti token
    .replace(/\n{3,}/g, '\n\n')
    .trim();

  if (KVKK_FORBIDDEN_SCAN.test(out)) {
    const hit = out.match(KVKK_FORBIDDEN_SCAN)?.[0];
    console.warn(
      `[report][KVKK-GUARD] Yasakli uyum-dili kalintisi finalize sonrasi HALA mevcut: "${hit}" — elle gozden gecir.`,
    );
  }
  return out;
}

// Ayirici YALNIZ KENDI SATIRINDA (opsiyonel markdown baslik "#" + bosluk ile) GERCEK
// ayiricidir. Ajan bazen isareti YONETICI OZETI icinde satir-ici capraz-referans olarak
// yazar (ör. "...icin bkz. ===FIX_SUGGESTIONS===)"); bu GERCEK bolme noktasi DEGILDIR.
// indexOf ile o satir-ici geciste bolunce 3-6. zorunlu bolumler yanlislikla kilitli/paid
// tarafa duser + ")." gibi kalinti sizar (bkz order 8b1c9758 / flow 68 bug'i). Kendi
// satirindaki ILK geciste boluyoruz.
const FIX_DELIM_STANDALONE = new RegExp(`^[ \\t]*#{0,6}[ \\t]*${FIX_SUGGESTIONS_DELIM}[ \\t]*$`, 'm');

/**
 * GUVENLIK AGI: ham ic-format isareti (===FIX_SUGGESTIONS===) render edilen musteri
 * metninde ASLA gorunmemeli. Kendi satirindaki (baslik dahil) kalinti isareti TAMAMEN
 * kaldirir; satir-ici geciste anlamli bir ifadeyle degistirir; yalniz noktalama kalan
 * (")." / "." / ")") artik satirlarini ve fazla bos satirlari temizler.
 */
function stripDelimArtifacts(md: string): string {
  return md
    .replace(new RegExp(`^[ \\t]*#{0,6}[ \\t]*${FIX_SUGGESTIONS_DELIM}[ \\t]*$`, 'gm'), '')
    .replace(new RegExp(FIX_SUGGESTIONS_DELIM, 'g'), 'AI Çözüm Önerileri bölümü')
    .replace(/^[ \t]*[).]+[ \t]*$/gm, '')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

// (BASIT GUVENLIK AGI) basit_tarama raporundan SUREC-DILI ve GOREV-ADI kalintilarini temizler.
// Asil cozum PROMPTTA (ajan bunlari hic yazmamali); bu, ajan yine de uretirse musteriyi koruyan
// SON-KONTROLdur (bkz kvkk sanitizeKvkkReport benzeri). Iki tur kalinti:
//  1) GOREV-ADI gibi duran BASLIKLAR: markdown baslik (#..) VEYA kalin (**..**) satiri, imperative
//     fiil ("topla/analiz et/tespit et/kontrol et/incele/hazirla/cek/getir/belirle/degerlendir/
//     tara/listele/dogrula") ile BITEN -> bu ajanin ic adim adi; TAMAMEN kaldir. (Dogru kanonik
//     basliklar — "HTTP GÜVENLİK BAŞLIKLARI" vb. — fiille bitmez, dokunulmaz.)
//  2) SUREC/BUTCE-MUHASEBESI cumleleri: "hazirlanmistir / istek yapilmamis / kisit korundu /
//     analiz asamasi / adim N / subtask / tool call / butce / tavan" iceren CUMLELER -> at.
// Tabloya (| ... |) ve kanonik basliklara (#) DOKUNMAZ. Her temizligi console.warn ile loglar.
export function sanitizeBasitReport(md: string): string {
  const VERB_HEADING =
    /^\s*(?:#{1,6}\s+|\*\*)\s*.*\b(topla|analiz\s*et|tespit\s*et|kontrol\s*et|incele(?:me|yin)?|haz[ıi]rla|[çc]ek(?:me|in)?|getir|belirle|de[ğg]erlendir|tara(?:ma|yin)?|listele|do[ğg]rula)\w*\**\s*:?\s*$/i;
  const PROC_SENT =
    /(haz[ıi]rlanm[ıi][şs]|istek\s+yap[ıi]lmam|k[ıi]s[ıi]t[ıi]?\s*(?:korun|sa[ğg]lan)|analiz\s+a[şs]amas|a[şs]amas[ıi]\s+i[çc]in|\bad[ıi]m\s*\d+|subtask|alt[\s-]?g[oö]rev|tool[\s-]?call|arac[\s-]?[çc]a[ğg]r|\bbudget\b|b[üu]t[çc]e|\btavan\b)/i;
  let dropped = 0;

  // (1) gorev-adi basliklarini SATIR bazinda ele.
  let lines = md.split('\n').filter((ln) => {
    if (VERB_HEADING.test(ln)) { dropped++; return false; }
    return true;
  });

  // (2) surec/butce cumlelerini CUMLE bazinda ele (tablo/baslik satirlarina dokunma).
  lines = lines.map((ln) => {
    const trimmed = ln.trim();
    if (!trimmed || trimmed.startsWith('|') || trimmed.startsWith('#')) return ln;
    const sentences = ln.split(/(?<=[.!?])\s+/);
    const kept = sentences.filter((s) => {
      if (PROC_SENT.test(s)) { dropped++; return false; }
      return true;
    });
    return kept.join(' ');
  });

  const out = lines.join('\n').replace(/\n{3,}/g, '\n\n').trim();
  if (dropped > 0) {
    console.warn(`[report][BASIT-GUARD] ${dropped} surec-dili/gorev-adi kalintisi temizlendi (basit_tarama).`);
  }
  return out;
}

/** Bulgulardan "cozum onerileri" bolumunu (KENDI SATIRINDAKI delimiter sonrasi) ayirir. */
function splitFixSuggestions(text: string): { findings: string; fixText: string } {
  const m = FIX_DELIM_STANDALONE.exec(text);
  // Gercek (kendi satirinda) ayirici yoksa: hepsi bulgudur, fix bolumu yok. Metinde
  // yalniz satir-ici bir kalinti varsa da onu temizle (ham isaret sizmasin).
  if (!m) return { findings: stripDelimArtifacts(text), fixText: '' };
  return {
    findings: stripDelimArtifacts(text.slice(0, m.index)),
    fixText: stripDelimArtifacts(text.slice(m.index + m[0].length)),
  };
}

/**
 * Flow tamamlandiginda cagrilir (worker.ts). Ham loglari PentAGI'den ceker,
 * okunabilir bir Markdown rapor haline getirir, musteriye ozel bir erisim
 * sifresiyle sifreler ve PentAGI tarafindaki ham veriyi siler.
 */
/**
 * "ELINDEKI HAM VERIYLE": ajan tamamlama yazamadiginda (butce/erken durus), taramada
 * calisan terminal komutlarini + ciktilarini getScopeLogs'tan cekip bir "ham kanit"
 * bolumu olusturur. Ciktilar sonradan redactAll ile maskelenir (PII). Bos donebilir.
 */
async function buildRawEvidenceFallback(pentagiFlowId: string, locale: Locale): Promise<string> {
  try {
    const scope = await pentagi.getScopeLogs(pentagiFlowId);
    const terminals = (scope.toolCallLogs ?? []).filter((t) => t.name == null || t.name === 'terminal');
    if (!terminals.length) return '';
    const items = terminals.slice(0, 40).map((t, i) => {
      const cmd = (t.args ?? '').replace(/\s+/g, ' ').trim().slice(0, 300);
      const out = (t.result ?? '').trim().slice(0, 600);
      return `**${i + 1}.** \`${cmd || '(komut)'}\`\n\n\`\`\`\n${out || '(çıktı yok)'}\n\`\`\``;
    });
    const header =
      locale === 'de'
        ? '## Automatisch zusammengestellte Rohnachweise\n\n> Der Scan erreichte den finalen Berichtsschritt nicht (Budget/vorzeitiger Stopp). Nachfolgend die während des Scans gesammelten Rohnachweise (Befehle und Ausgaben) zu Ihrer Information. **Dies ist kein aufbereiteter Kundenbericht**; da es sich um technische Rohdaten handelt, kann er englische Überschriften/Fragmente enthalten. Für eine abschließende Bewertung wird empfohlen, den Scan erneut auszuführen oder diese Daten von einem Experten auswerten zu lassen.'
        : locale === 'en'
        ? '## Automatically Compiled Raw Evidence\n\n> The scan did not reach the final report-writing step (budget/early stop). Below is the raw evidence (commands and outputs) collected during the scan, for your reference. This is not a polished report; it may contain technical/English fragments.'
        : '## Otomatik Derlenmiş Ham Kanıtlar\n\n> Tarama, nihai rapor-yazma adımına ulaşamadı (bütçe/erken duruş). Aşağıda tarama sırasında toplanan ham kanıtlar (komutlar ve çıktılar) referans için verilmiştir. **Bu, düzenlenmiş bir müşteri raporu değildir**; ham teknik veri olduğu için İngilizce başlıklar/parçalar (ör. HTTP çıktıları, aracın kendi iç notları) içerebilir. Nihai değerlendirme için taramanın yeniden çalıştırılması veya bu verinin bir uzmanca yorumlanması önerilir.';
    return `${header}\n\n${items.join('\n\n')}`;
  } catch (err) {
    console.error('[report] ham kanit fallback uretilemedi:', err);
    return '';
  }
}

export async function generateAndStoreReport(flowId: string) {
  const flow = await prisma.flow.findUniqueOrThrow({
    where: { id: flowId },
    include: { order: { include: { domain: true, package: true } } },
  });

  // (PENTAGI'SIZ) Deterministik flow'da (sentinel 'deterministic-', ör. basit_tarama) PentAGI
  // flow'u YOK -> getFlowLogs cagirma; bulgular zaten backend collector'indan (generateBasitReport)
  // gelir, ajan loglari kullanilmaz. Bos FlowLogs ver.
  const noPentagi = flow.pentagiFlowId.startsWith('deterministic-');
  const logs = noPentagi
    ? ({ tasks: [], messageLogs: [], screenshots: [] } as pentagi.FlowLogs)
    : await pentagi.getFlowLogs(flow.pentagiFlowId);
  const locale: Locale = flow.order.locale === 'de' ? 'de' : flow.order.locale === 'en' ? 'en' : 'tr';

  // (3) Cozum onerilerini bulgulardan AYIR (ayni akista uretildi, ekstra maliyet yok).
  const split = splitFixSuggestions(collectFindings(logs));
  let findings = split.findings;
  let fixText = split.fixText;

  // DETERMINISTIK RAPOR — ajanin ciktisini PARSE ETME. Ajan hem raporu hem komut formatini
  // (curl -I / curl -v / Python script...) ongorulemez uretiyor. Bunun yerine veriyi KENDI
  // KODUMUZLA cek (HTTP/TLS/DNS/CORS/HTML — Ek Pasif Kontroller ile ayni yaklasim) ve raporu
  // KOD yaz. Formattan BAGIMSIZ, her zaman tutarli. Hedefe ulasilamazsa null -> ajan/ham-kanit
  // yoluna dusulur. basit_tarama + bundle_surface uyeleri (ssl_tls/header_leak/dns_email/
  // cors_cookie/csp_analiz) bu yolla uretilir.
  // (Tam Kapsamlı Pentest) AUTHENTICATED bundle: ÖNCE backend deterministik LOGIN (FAZ B), sonra FAZ C/D
  // authenticated rapor. Login başarısız -> authenticateOrder zaten scan_failed + KREDİ + mail yaptı -> çık
  // (rapor üretme, scan_completed'a geçme).
  // (LOGİNSİZ TEST) Müşteri loginsiz seçtiyse (sitede login yok / "loginsiz devam et") login ATLANIR;
  // authenticated rapor üretilmez, tarama unauthenticated yüzey kontrolleriyle TAMAMLANIR (fail DEĞİL).
  if (flow.order.package.key === AUTH_BUNDLE_KEY && flow.order.loginless) {
    console.log(`[report][FULL] ${flow.orderId}: LOGİNSİZ mod — login atlandı, unauthenticated yüzey raporu üretilecek.`);
  } else if (flow.order.package.key === AUTH_BUNDLE_KEY) {
    const authRes = await authenticateOrder(flow.orderId);
    if (!authRes.ok) {
      console.log(`[report][FULL] ${flow.orderId}: login başarısız (${authRes.reason}) -> rapor üretilmedi (kredi tanımlandı, müşteri bilgilendirildi).`);
      return null; // worker: null -> flow'u bitir, rapor-hazır maili GÖNDERME (login-fail maili zaten gitti).
    }
    try {
      const built = await generateAuthenticatedReport(flow.order.domain.hostname, authRes.session);
      if (built) { findings = built.findings; fixText = built.fixText; console.log(`[report][FULL] ${flow.orderId}: authenticated (login'li) rapor DETERMINISTIK üretildi.`); }
      else console.warn(`[report][FULL] ${flow.orderId}: authenticated rapor üretilemedi (hedefe ulaşılamadı).`);
    } catch (err) {
      console.error(`[report][FULL] ${flow.orderId}: authenticated rapor hatası:`, err);
    }
  }

  const detGen = DETERMINISTIC_GENERATORS[flow.order.package.key];
  if (detGen) {
    logScanStep({ step: 'Rapor üretimi', summary: `paket=${flow.order.package.key} · deterministik üretici başladı (hedef=${flow.order.domain.hostname})` });
    const _tGen = Date.now();
    try {
      const built = await detGen(flow.order.domain.hostname);
      if (built) {
        findings = built.findings;
        fixText = built.fixText;
        logScanStep({ step: 'Rapor üretimi', durationMs: Date.now() - _tGen, summary: `bulgu markdown üretildi (${built.findings.length} karakter)` });
        console.log(`[report][DET] ${flow.order.package.key}: rapor KOD-toplanmis kanittan DETERMINISTIK uretildi (ajan ciktisi kullanilmadi).`);
      } else {
        console.warn(`[report][DET] ${flow.order.package.key}: hedefe ulasilamadi (kanit yok) -> ajan/ham-kanit yoluna dusuluyor.`);
      }
    } catch (err) {
      console.error(`[report][DET] ${flow.order.package.key}: deterministik rapor uretilemedi, ajan yoluna dusuluyor:`, err);
    }
  }

  // EKSIK RAPOR TESPITI: ajan hicbir kaynakta (task/subtask/report result) TAMAMLAMA
  // yazmamissa (ör. injection_verify: tavana carparak yazma adimina ulasamadi) findings
  // BOS kalir. Boyle bir durumda BOS/ise-yaramaz rapor vermek yerine "ELINDEKI HAM VERIYLE":
  // taramada calisan terminal komutlarini + ciktilarini (redakte) rapora KANIT olarak koy.
  // Rapor yine 'incomplete' isaretlenir (musteri ajanin tam anlatiyi yazamadigini bilsin)
  // ama artik bos degil — toplanan ham kanitlar gorunur.
  const incomplete = findings.trim().length === 0;
  let incompleteReason: string | null = null;
  if (incomplete) {
    const rawEvidence = await buildRawEvidenceFallback(flow.pentagiFlowId, locale);
    // (GÜVENLİK AĞI — DÜRÜSTLÜK) Rapor boş kaldıysa (generator hiçbir veri toplayamadı / null döndü):
    // ASLA pdf'in varsayılan "Düşük Risk"/"Temiz"ine düşme. "Risk Seviyesi: İncelenemedi" markörünü ÖNE
    // koy -> assessBasit nötr amber rozet + master/dağılım "İncelenemedi" gösterir. Ham kanıt varsa altına ekle.
    const marker = unscannableReport(flow.order.domain.hostname).findings;
    findings = rawEvidence.trim() ? `${marker}\n\n---\n\n${rawEvidence}` : marker;
    incompleteReason =
      'Tarama, tam anlatısal raporu yazma adımına ulaşamadan sonlandı (hedefe ulaşılamadı veya bütçe/erken duruş). ' +
      'Bu rapor bir "temiz/güvenli" sonucu DEĞİLDİR.';
  }

  // (LOGİNSİZ TEST) Kimlik-doğrulamalı paket loginsiz koştuysa raporda DÜRÜST not: oturum-içi kontroller
  // yapılmadı (login sağlanmadı) — bu bir "temiz" sonucu değildir; unauthenticated yüzey kontrolleri geçerlidir.
  if (flow.order.package.key === AUTH_BUNDLE_KEY && flow.order.loginless) {
    const note =
      '> **Not — Loginsiz (kimlik-doğrulamasız) tarama:** Bu tarama test hesabı bilgisi olmadan yapıldı. ' +
      'Oturum-içi (giriş sonrası) yetkilendirme, IDOR ve iş-mantığı kontrolleri **kapsam dışıdır** — bu bir ' +
      '"güvenli/temiz" sonucu değildir. Aşağıdaki bulgular sitenin **herkese açık (login gerektirmeyen)** yüzeyine aittir.';
    findings = findings.trim() ? `${note}\n\n${findings}` : note;
  }

  // (KVKK GUVENLIK AGI) yalniz kvkk_hazirlik: uyum-dili / ihlal iddiasi / Subtask sizintisi /
  // durum-ikonu son-kontrolu (bkz sanitizeKvkkReport). Diger paketler DEGISMEZ.
  const isKvkkPkg = flow.order.package.key === 'kvkk_hazirlik';
  if (isKvkkPkg) findings = sanitizeKvkkReport(findings);

  // (BASIT GUVENLIK AGI) yalniz basit_tarama: gorev-adi gibi baslik + surec/butce-muhasebesi
  // dili son-kontrolu (bkz sanitizeBasitReport). Ajan prompt kurallarina uymasa BILE musteri
  // temiz rapor gorsun. Diger paketler DEGISMEZ.
  if (flow.order.package.key === 'basit_tarama') findings = sanitizeBasitReport(findings);

  // (FIX GARANTISI) Ajan ===FIX_SUGGESTIONS=== bolumunu yazmadiysa fixText BOS kalir ->
  // rapora sifreli fix blogu kaydedilmez -> musteri "AI Çözüm Önerileri satin al/indir"
  // kutusunu HIC goremez. basit_tarama'da eksik guvenlik basliklarindan DETERMINISTIK,
  // somut duzeltme onerileri uret (ek LLM/maliyet YOK) ki bolum HER raporda satin alinip
  // indirilebilsin. Ajan kendi fix'ini yazdiysa ona DOKUNMA.
  if (flow.order.package.key === 'basit_tarama' && !fixText.trim() && findings.trim().length > 0 && !incomplete) {
    fixText = buildHeaderFixSuggestions(findings, flow.order.domain.hostname);
    console.warn('[report][BASIT-FIX] Ajan fix yazmadi -> deterministik baslik-remediation uretildi (satin alinabilir).');
  }

  // KENDI TARAFIMIZDA veri minimizasyonu: sizmis yapisal PII'yi (email/telefon/
  // TCKN/kart/IBAN) sifreli DB'ye yazmadan ONCE maskele (ayni mantik PentAGI Go
  // tarafinda Anthropic'e gitmeden de uygulanir — PATCHES.md).
  // EK PASIF KONTROLLER (deterministik, AGENT'SIZ, LLM'SIZ — sifir ek maliyet).
  // Hedefin kendi DNS/HTTP'sine kod-tabanli sorgular; PDF'te AYRI bir bolume gider.
  // Izole (Promise.allSettled) — hata verse bile raporu/akisi ETKILEMEZ.
  let extrasBlock = '';
  try {
    if (hasPassiveExtras(flow.order.package.key)) {
      const results = await runPassiveExtras(flow.order.domain.hostname, flow.order.package.key);
      const extrasMd = renderPassiveExtrasMarkdown(results);
      if (extrasMd.trim()) extrasBlock = `\n\n${PASSIVE_EXTRAS_DELIM}\n\n${extrasMd}`;
    }
  } catch (err) {
    console.error('[passiveExtras] ek kontroller uretilemedi (rapor yine de olusur):', err);
  }

  const rawMarkdown = redactAll(
    renderReportMarkdown(flow.order.domain.hostname, flow.order.package.displayName, findings, logs.screenshots, locale, flow.order.package.key) +
      extrasBlock,
  );

  // (QA KATMANI) PDF/teslimattan ÖNCE deterministik yapısal bütünlük doğrulaması + onarımı (LLM'siz):
  // yarım/çıplak-URL bulguyu çıkar, devre-kesici şeffaflığını ekle, rozet=master çelişkisini yakala.
  // Onarılmış markdown teslim edilir; kritik tutarsızlıkta (blocked) admin-onay kapısına alarm bırakılır.
  const qa = validateAndRepairReport(rawMarkdown, { packageKey: flow.order.package.key, locale, fixText, hostname: flow.order.domain.hostname });
  for (const issue of qa.issues) {
    logScanStep({ step: 'QA doğrulama', level: issue.level === 'block' ? 'error' : issue.level === 'fix' ? 'warn' : 'info', rule: issue.rule, summary: `${issue.message} -> ${issue.action}` });
  }
  logScanStep({ step: 'QA doğrulama', summary: `tamamlandı (fix=${qa.issues.filter((i) => i.level === 'fix').length} warn=${qa.issues.filter((i) => i.level === 'warn').length} block=${qa.issues.filter((i) => i.level === 'block').length})` });
  if (qa.blocked) {
    console.error(`[report-validator][ALARM] ${flow.orderId} (${flow.order.package.key}): KRİTİK yapısal tutarsızlık — awaiting_admin_review kapısında insan denetimi gerekir.`);
  }
  const markdown = qa.markdown;

  const accessSecret = generateReportAccessSecret();
  const base = encryptReport(Buffer.from(markdown, 'utf-8'), accessSecret);

  // (3) Cozum onerileri varsa AYNI accessSecret ile AYRI sifrele (kilitli alan).
  let fixFields: Record<string, Buffer> = {};
  if (fixText.trim().length > 0) {
    const cleanFix = isKvkkPkg ? sanitizeKvkkReport(fixText) : fixText;
    const fixMd = redactAll(renderFixSuggestionsMarkdown(flow.order.domain.hostname, cleanFix, locale, flow.order.package.key));
    const enc = encryptReport(Buffer.from(fixMd, 'utf-8'), accessSecret);
    fixFields = {
      fixSuggestions: enc.encryptedBlob,
      fixSuggestionsIv: enc.iv,
      fixSuggestionsAuthTag: enc.authTag,
      fixSuggestionsSalt: enc.keyDerivationSalt,
    };
  }

  await prisma.report.create({
    data: {
      orderId: flow.orderId,
      encryptedBlob: base.encryptedBlob,
      iv: base.iv,
      authTag: base.authTag,
      keyDerivationSalt: base.keyDerivationSalt,
      incomplete,
      incompleteReason,
      ...fixFields,
    },
  });

  // (İÇ KALİTE KAPISI) Kapı açıksa rapor müşteriye HEMEN açılmaz: 'awaiting_admin_review'da bekler
  // (admin inceleyip onaylayınca scan_completed + e-posta). Kapı kapalıysa eski davranış (doğrudan teslim).
  await prisma.order.update({
    where: { id: flow.orderId },
    data: { status: config.adminReportGate ? 'awaiting_admin_review' : 'scan_completed' },
  });

  // Ham veriyi PentAGI tarafinda tutmuyoruz — rapor uretildikten hemen sonra sil. (Deterministik
  // flow'da PentAGI ham verisi YOK -> purge cagirma; sadece damgayi at.)
  if (noPentagi) {
    await prisma.flow.update({ where: { id: flow.id }, data: { rawDataPurgedAt: new Date() } });
  } else {
    await pentagi.purgeFlowRawData(flow.pentagiFlowId);
    await prisma.flow.update({ where: { id: flow.id }, data: { rawDataPurgedAt: new Date() } });
  }

  return { accessSecret };
}

const T = {
  tr: {
    title: 'Guvenlik Tarama Raporu', target: 'Hedef', pkg: 'Paket', created: 'Olusturma tarihi',
    findings: 'Bulgular', noFindings: '_Bu taramada raporlanacak bulgu uretilemedi._',
    screenshots: 'Ekran Goruntuleri', none: '_Yok_', legalTitle: 'Yasal Uyari ve Kapsam',
    legal: [
      '**Yapay zeka uretimi:** Bu rapor yapay zeka tabanli otomatik bir ajan tarafindan uretilmistir; olgusal ifadeler bagimsiz dogrulanmadan kullanilmamalidir.',
      '**Kapsam:** Tarama YALNIZCA sahipligi dogrulanmis hedefle ve **pasif** yontemlerle sinirlidir; ic ag, kimlik dogrulamali test ve sizma testi KAPSAM DISIDIR.',
      '**Resmi degildir:** Bu rapor resmi uyumluluk denetimi/sertifikasyon (ASV/QSA vb.) yerine gecmez.',
      '**Sorumluluk:** Bulgularin dogrulanmasi ve giderilmesi musterinin sorumlulugundadir.',
    ],
    fixTitle: 'AI Çözüm Önerileri', fixNote: 'Bu bölüm düzeltme (remediation) içindir; istismar/exploit kodu içermez.',
  },
  en: {
    title: 'Security Scan Report', target: 'Target', pkg: 'Package', created: 'Generated at',
    findings: 'Findings', noFindings: '_No reportable findings could be produced in this scan._',
    screenshots: 'Screenshots', none: '_None_', legalTitle: 'Legal Notice & Scope',
    legal: [
      '**AI-generated:** This report was produced by an autonomous AI agent; factual statements must be independently verified before acting on them.',
      '**Scope:** The scan is limited to the ownership-verified target and **passive** methods only; internal network, authenticated testing and penetration testing are OUT OF SCOPE.',
      '**Not official:** This report is not a substitute for an official compliance audit/certification (ASV/QSA, etc.).',
      '**Responsibility:** Verifying and remediating findings is the customer’s responsibility.',
    ],
    fixTitle: 'AI Fix Suggestions', fixNote: 'This section is remediation guidance only; it contains no exploit code.',
  },
  de: {
    title: 'Sicherheits-Scan-Bericht', target: 'Ziel', pkg: 'Paket', created: 'Erstellt am',
    findings: 'Befunde', noFindings: '_In diesem Scan konnten keine berichtsfähigen Befunde erzeugt werden._',
    screenshots: 'Screenshots', none: '_Keine_', legalTitle: 'Rechtlicher Hinweis & Umfang',
    legal: [
      '**KI-generiert:** Dieser Bericht wurde von einem autonomen KI-Agenten erstellt; sachliche Aussagen müssen vor dem Handeln unabhängig überprüft werden.',
      '**Umfang:** Der Scan ist auf das inhaberschaftsgeprüfte Ziel und ausschließlich **passive** Methoden beschränkt; internes Netzwerk, authentifizierte Tests und Penetrationstests sind AUSSERHALB DES SCOPE.',
      '**Nicht amtlich:** Dieser Bericht ersetzt kein offizielles Compliance-Audit / keine Zertifizierung (ASV/QSA usw.).',
      '**Verantwortung:** Die Überprüfung und Behebung der Befunde liegt in der Verantwortung des Kunden.',
    ],
    fixTitle: 'KI-Lösungsempfehlungen', fixNote: 'Dieser Abschnitt dient nur der Behebung; er enthält keinen Exploit-Code.',
  },
} as const;

// (KVKK PILOTU) KVKK raporunda ajan KENDI yapisini uretir (## Yönetici Özeti + ## Bulgular)
// ve TAM Turkce kullanir; bu yuzden fazladan "## Bulgular" wrapper'i EKLEMEYIZ ve legal
// metni duzeltilmis-Turkce + KISA tutariz (detay son bolumde). Diger paketler DEGISMEDEN kalir.
const KVKK_LEGAL = [
  '**Yapay zeka üretimi:** Bu rapor otonom bir yapay zeka ajanı tarafından üretilmiştir; olgusal ifadeler bağımsız doğrulanmadan kullanılmamalıdır.',
  '**Kapsam:** Kontrol yalnızca dışarıdan gözlemlenebilir, pasif yöntemlerle ve sınırlı sayıda sayfayla yapılmıştır; kapsam dışı sayfalarda farklı bulgular olabilir.',
  '**Resmi değildir:** Bu rapor bir uyum beyanı/denetimi değildir; nihai değerlendirme için KVKK uzmanı/avukat gereklidir.',
];

// (Tam Kapsamlı Pentest) AYRI, DOĞRU disclaimer — bu paket TAM OLARAK kimlik doğrulamalı test yapar;
// diğer 6 paketin "pasif / authenticated KAPSAM DIŞI" cümlesi burada YANLIŞ olurdu. Diğer paketler DEĞİŞMEZ.
const FULL_PENTEST_LEGAL_TR = [
  '**Nasıl üretildi:** Bu rapor **backend deterministik güvenlik kontrolleriyle** üretilmiştir. İki kontrolde (yetki yükseltme + çok-adımlı iş mantığı) isteğe bağlı, **varsayılan olarak kapalı** bir yapay zekâ danışma katmanı vardır; yalnız açıkken ve ek bir doğrulanabilir gösterge bulduğunda devreye girer — kapalıyken sonuçlar tam deterministik kontrollerle üretilir. Olgusal ifadeler bağımsız doğrulanmadan kullanılmamalıdır.',
  '**Kapsam:** Bu tarama, sağladığınız TEST hesabıyla **kimlik doğrulamalı (login’li)** bağlamda yapılmıştır. Gerçek veri değişikliği, hesap durumu değişikliği, ödeme/sipariş tamamlama veya üçüncü taraf hesaplarına erişim **KAPSAM DIŞIDIR ve kod seviyesinde engellenmiştir**.',
  '**Resmi değildir:** Bu rapor resmi bir sızma testi/uyum denetimi (ASV/QSA vb.) yerine geçmez.',
  '**Sorumluluk:** Bulguların doğrulanması ve giderilmesi müşterinin sorumluluğundadır.',
];
const FULL_PENTEST_LEGAL_EN = [
  '**AI-assisted:** This report was produced by backend deterministic checks plus a limited/controlled autonomous agent analysis; factual statements must be independently verified before acting on them.',
  '**Scope:** This scan was performed in an **authenticated (logged-in)** context using the TEST account you provided, with a **limited/controlled autonomous agent** analysis. Real data modification, account-state changes, payment/order completion, and access to third-party accounts are **OUT OF SCOPE and blocked at the code level**.',
  '**Not official:** This report is not a substitute for an official penetration test / compliance audit (ASV/QSA, etc.).',
  '**Responsibility:** Verifying and remediating findings is the customer’s responsibility.',
];
const FULL_PENTEST_LEGAL_DE = [
  '**KI-gestützt:** Dieser Bericht wurde mit deterministischen Backend-Prüfungen plus einer begrenzten/kontrollierten autonomen Agenten-Analyse erstellt; sachliche Aussagen müssen vor dem Handeln unabhängig überprüft werden.',
  '**Umfang:** Dieser Scan wurde in einem **authentifizierten (angemeldeten)** Kontext mit dem von Ihnen bereitgestellten TEST-Konto durchgeführt. Echte Datenänderungen, Kontostatus-Änderungen, Zahlungs-/Bestellabschluss und der Zugriff auf Drittkonten sind **AUSSERHALB DES SCOPE und auf Code-Ebene blockiert**.',
  '**Nicht amtlich:** Dieser Bericht ersetzt keinen offiziellen Penetrationstest / kein Compliance-Audit (ASV/QSA usw.).',
  '**Verantwortung:** Die Überprüfung und Behebung der Befunde liegt in der Verantwortung des Kunden.',
];

// (KALİTE) TÜM raporlara EKLEMELİ (mevcut gövdeyi BOZMADAN) — hiçbir generator'da OLMAYAN iki
// bölüm: "Metodoloji ve Yaklaşım" (yaklaşım+teknik+standart+kısa sınırlama) ve "Sonraki Adımlar"
// (net CTA). Paket PROFİLİNE göre yazılır (pasif/uyum/aktif/authenticated) — dürüst, kısa, uydurma
// sayı YOK, gövdedeki "Ne Kontrol Edildi"/scope notlarını TEKRARLAMAZ (yaklaşım+standart odaklı).
function reportKind(packageKey?: string): 'compliance' | 'authenticated' | 'active' | 'passive' {
  if (!packageKey) return 'passive';
  if (['kvkk_hazirlik', 'bundle_compliance', 'pci_hazirlik', 'iso27001_hazirlik'].includes(packageKey)) return 'compliance';
  if (['bundle_full_pentest', 'authenticated_scan'].includes(packageKey)) return 'authenticated';
  try {
    const prof = securityProfileFor(getPackageDef(packageKey as Parameters<typeof getPackageDef>[0]));
    if (prof === 'active-light' || prof === 'active-verify-only') return 'active';
  } catch { /* bilinmeyen key -> passive */ }
  return 'passive';
}

function buildCommonSections(packageKey: string | undefined, locale: Locale): string {
  const kind = reportKind(packageKey);
  if (locale === 'en') {
    const METH_EN: Record<string, string> = {
      passive: 'This scan uses **passive, low-impact** techniques only: the target’s public responses are retrieved via GET/HEAD/OPTIONS, and TLS handshakes, DNS records and HTTP headers are parsed at the code level. No input is injected, no login is performed and no data is modified. Observed configuration is compared against OWASP/industry best practices.\n\n**Limitations:** No authentication (login-gated areas are out of scope); requests are timeout/rate-limit protected; no out-of-band channels. Findings reflect responses at scan time.',
      compliance: 'This pre-assessment passively reviews the target’s public pages to compile the **externally observable readiness indicators** for the relevant framework. No definitive compliance verdict is made; neutral status labels (Observed / Not observed / Needs review) are used.\n\n**Limitations:** External observation only — internal processes, policies and contracts are out of scope. No authentication. This is not legal advice or an official audit.',
      active: 'Following the **“prove — don’t exploit”** principle, active low-impact verification probes are run: each input point receives a harmless baseline request first, then a single distinguishing indicator probe; a vulnerability **indicator** is derived from the response/timing delta. Vulnerabilities are not exploited and no data is read or changed.\n\n**Limitations:** A circuit breaker halts probing on repeated 5xx/WAF responses. Destructive methods (DELETE/data-writing PUT, real command execution, exfiltration, DoS) are blocked at the code level. No authentication. Absence of findings does not PROVE absence of a vulnerability.',
      authenticated: 'This scan runs in an **authenticated (logged-in)** context using the TEST account you provided. Authorization, session management, forced-browsing and authenticated input checks follow the **“prove — don’t exploit”** principle. Your password is never sent to the agent/PentAGI; it is used only in the backend’s deterministic session.\n\n**Limitations:** Requests are observational/GET-heavy; real data modification, account-state changes, payment/order completion and cross-account access are OUT OF SCOPE and blocked at the code level.',
    };
    const NEXT_EN: Record<string, string> = {
      passive: '1. Remediate the items in **“Findings / Detected Risks”** in order of severity.\n2. Copy-paste-ready fixes for each finding are in the **AI Fix Suggestions** section.\n3. After fixing, re-scan with the same package to verify.',
      compliance: '1. Apply the quick wins in **“Priority Actions”** first.\n2. Engage the relevant specialist (KVKK / PCI QSA / ISO consultant) for the final assessment.\n3. Re-check after remediation.',
      active: '1. Reproduce and remediate the High/Medium indicators in your own environment.\n2. Copy-paste-ready fixes are in the **AI Fix Suggestions** section.\n3. A re-test after remediation is recommended.',
      authenticated: '1. Prioritise High-severity findings first (authorization/session).\n2. Copy-paste-ready fixes are in the **AI Fix Suggestions** section.\n3. A re-test after remediation is recommended.',
    };
    return `\n\n---\n\n## Methodology & Approach\n\n${METH_EN[kind]}\n\n## Next Steps\n\n${NEXT_EN[kind]}`;
  }
  if (locale === 'de') {
    const METH_DE: Record<string, string> = {
      passive: 'Dieser Scan verwendet ausschließlich **passive, wenig-invasive** Techniken: Die öffentlichen Antworten des Ziels werden per GET/HEAD/OPTIONS abgerufen, und TLS-Handshakes, DNS-Einträge und HTTP-Header werden auf Code-Ebene ausgewertet. Es werden keine Eingaben injiziert, keine Anmeldung durchgeführt und keine Daten verändert. Die beobachtete Konfiguration wird mit OWASP-/Branchen-Best-Practices verglichen.\n\n**Einschränkungen:** Keine Authentifizierung (login-geschützte Bereiche sind außerhalb des Scope); Anfragen sind timeout-/ratenbegrenzt geschützt; keine Out-of-Band-Kanäle. Die Befunde spiegeln die Antworten zum Scan-Zeitpunkt wider.',
      compliance: 'Diese Vorabbewertung prüft die öffentlichen Seiten des Ziels passiv, um die **von außen beobachtbaren Bereitschaftsindikatoren** des betreffenden Frameworks zusammenzustellen. Es wird kein endgültiges Compliance-Urteil gefällt; es werden neutrale Statuslabel (Beobachtet / Nicht beobachtet / Zu prüfen) verwendet.\n\n**Einschränkungen:** Nur externe Beobachtung — interne Prozesse, Richtlinien und Verträge sind außerhalb des Scope. Keine Authentifizierung. Dies ist keine Rechtsberatung und kein offizielles Audit.',
      active: 'Nach dem Prinzip **„nachweisen — nicht ausnutzen“** werden aktive, wenig-invasive Verifizierungsprüfungen ausgeführt: Jeder Eingabepunkt erhält zuerst eine harmlose Basisanfrage, dann eine einzelne unterscheidende Indikator-Prüfung; aus der Antwort-/Timing-Differenz wird ein Schwachstellen-**Indikator** abgeleitet. Schwachstellen werden nicht ausgenutzt, und es werden keine Daten gelesen oder verändert.\n\n**Einschränkungen:** Ein Schutzschalter stoppt die Prüfung bei wiederholten 5xx-/WAF-Antworten. Destruktive Methoden (DELETE/datenschreibendes PUT, echte Befehlsausführung, Exfiltration, DoS) sind auf Code-Ebene blockiert. Keine Authentifizierung. Das Fehlen von Befunden BEWEIST nicht das Fehlen einer Schwachstelle.',
      authenticated: 'Dieser Scan läuft in einem **authentifizierten (angemeldeten)** Kontext mit dem von Ihnen bereitgestellten TEST-Konto. Autorisierung, Session-Verwaltung, Forced-Browsing und authentifizierte Eingabeprüfungen folgen dem Prinzip **„nachweisen — nicht ausnutzen“**. Ihr Passwort wird niemals an den Agenten/PentAGI gesendet; es wird nur in der deterministischen Session des Backends verwendet.\n\n**Einschränkungen:** Anfragen sind beobachtend/GET-lastig; echte Datenänderung, Kontostatus-Änderungen, Zahlungs-/Bestellabschluss und Cross-Account-Zugriff sind AUSSERHALB DES SCOPE und auf Code-Ebene blockiert.',
    };
    const NEXT_DE: Record<string, string> = {
      passive: '1. Beheben Sie die Punkte unter **„Befunde / Erkannte Risiken“** nach Schweregrad.\n2. Für jeden Befund finden Sie einsatzbereite Fixes im Abschnitt **KI-Lösungsempfehlungen**.\n3. Scannen Sie nach der Behebung mit demselben Paket erneut zur Überprüfung.',
      compliance: '1. Wenden Sie zuerst die Quick Wins unter **„Prioritäre Maßnahmen“** an.\n2. Ziehen Sie für die abschließende Bewertung den passenden Fachexperten hinzu.\n3. Prüfen Sie nach der Behebung erneut.',
      active: '1. Reproduzieren und beheben Sie die Indikatoren mit hohem/mittlerem Schweregrad in Ihrer eigenen Umgebung.\n2. Einsatzbereite Fixes finden Sie im Abschnitt **KI-Lösungsempfehlungen**.\n3. Ein Retest nach der Behebung wird empfohlen.',
      authenticated: '1. Priorisieren Sie zuerst Befunde mit hohem Schweregrad (Autorisierung/Session).\n2. Einsatzbereite Fixes finden Sie im Abschnitt **KI-Lösungsempfehlungen**.\n3. Ein Retest nach der Behebung wird empfohlen.',
    };
    return `\n\n---\n\n## Methodik & Ansatz\n\n${METH_DE[kind]}\n\n## Nächste Schritte\n\n${NEXT_DE[kind]}`;
  }
  const METH_TR: Record<string, string> = {
    passive: 'Bu tarama YALNIZCA **pasif ve düşük-etkili** tekniklerle yürütülür: hedefin herkese açık yanıtları GET/HEAD/OPTIONS ile alınır; TLS el sıkışması, DNS kayıtları ve HTTP başlıkları kod düzeyinde çözümlenir. Hiçbir girdi enjekte edilmez, oturum açılmaz, veri değiştirilmez. Gözlemlenen yapılandırma OWASP/endüstri en iyi uygulamalarıyla karşılaştırılır.\n\n**Sınırlamalar:** Kimlik doğrulama yapılmadı (giriş gerektiren alanlar kapsam dışı); istekler zaman aşımı/oran sınırıyla korunur; bant-dışı (out-of-band) kanal kullanılmaz. Bulgular tarama anındaki yanıtları yansıtır.',
    compliance: 'Bu ön-değerlendirme, hedefin herkese açık sayfalarını pasif olarak inceleyerek ilgili çerçevenin **dışarıdan gözlemlenebilir hazırlık göstergelerini** derler. Kesin bir uyum hükmü KURULMAZ; nötr durum etiketleri (Gözlemlendi / Gözlemlenmedi / İnceleme gerekli) kullanılır.\n\n**Sınırlamalar:** Yalnız dış gözlem — iç süreç, politika ve sözleşme belgeleri kapsam dışıdır. Kimlik doğrulama yapılmadı. Bu rapor hukuki görüş veya resmî denetim değildir.',
    active: '**“Kanıtla — istismar etme”** ilkesiyle aktif ve düşük-etkili doğrulama probları çalıştırılır: her giriş noktasına önce zararsız bir temel istek, ardından ayırt edici tek bir gösterge probu gönderilir; yanıt/zamanlama farkından zafiyet **göstergesi** türetilir. Zafiyet sömürülmez, veri çekilmez/değiştirilmez.\n\n**Sınırlamalar:** Art arda 5xx/WAF yanıtında devre kesici probları durdurur. Yıkıcı yöntemler (DELETE/veri-yazan PUT, gerçek komut çalıştırma, exfiltrasyon, DoS) kod düzeyinde engellidir. Kimlik doğrulama yapılmadı. Bulgu olmaması, zafiyet olmadığını KANITLAMAZ.',
    authenticated: 'Bu tarama, sağladığınız TEST hesabıyla **kimlik-doğrulamalı (login’li)** bağlamda yürütülür. Yetkilendirme, oturum yönetimi, forced-browsing ve authenticated girdi kontrolleri **“kanıtla — istismar etme”** ilkesiyle çalıştırılır. Şifreniz hiçbir aşamada ajana/PentAGI’ye gönderilmez; yalnız backend’in deterministik oturumunda kullanılır.\n\n**Sınırlamalar:** İstekler gözlemsel/GET-ağırlıklıdır; gerçek veri değişikliği, hesap-durumu değişikliği, ödeme/sipariş tamamlama ve çapraz-hesap erişimi KAPSAM DIŞIDIR ve kod düzeyinde engellidir.',
  };
  const NEXT_TR: Record<string, string> = {
    passive: '1. **“Tespit Edilen Riskler / Bulgular”** bölümündeki bulguları şiddet sırasına göre giderin.\n2. Her bulgu için panoya kopyalanabilir düzeltmeler **AI Çözüm Önerileri** bölümündedir.\n3. Düzeltme sonrası aynı paketle yeniden tarayarak doğrulayın.',
    compliance: '1. **“Öncelikli Aksiyonlar”** bölümündeki hızlı kazanımları önce uygulayın.\n2. Nihai değerlendirme için ilgili uzman (KVKK / PCI QSA / ISO danışmanı) ile çalışın.\n3. Düzeltmeler sonrası yeniden kontrol edin.',
    active: '1. Yüksek/Orta göstergeleri kendi ortamınızda doğrulayıp giderin.\n2. Panoya kopyalanabilir düzeltmeler **AI Çözüm Önerileri** bölümündedir.\n3. Düzeltme sonrası yeniden test önerilir.',
    authenticated: '1. Yüksek şiddetli bulguları öncelikle giderin (yetkilendirme/oturum).\n2. Panoya kopyalanabilir düzeltmeler **AI Çözüm Önerileri** bölümündedir.\n3. Düzeltme sonrası yeniden test önerilir.',
  };
  return `\n\n---\n\n## Metodoloji ve Yaklaşım\n\n${METH_TR[kind]}\n\n## Sonraki Adımlar\n\n${NEXT_TR[kind]}`;
}

export function renderReportMarkdown(
  hostname: string,
  packageName: string,
  findingsMd: string,
  screenshots: pentagi.FlowLogs['screenshots'],
  locale: Locale = 'tr',
  packageKey?: string,
): string {
  const t = T[locale];
  const isKvkk = packageKey === 'kvkk_hazirlik';
  // Ekran goruntusu bolumu YALNIZCA icerik varsa gosterilir — bos "Yok" bolumu koymayiz.
  // KVKK: gercek gorsel gomulmuyor; salt "screenshot-xxxx.png: https://..." dosya-adi
  // listesi musteri icin ANLAMSIZ → kvkk_hazirlik'te bu bolumu TAMAMEN kaldir (sorun 4).
  const screenshotsBlock =
    !isKvkk && screenshots.length > 0
      ? `\n\n---\n\n## ${t.screenshots}\n\n${screenshots.map((s) => `- ${s.name}: ${s.url}`).join('\n')}`
      : '';
  // KVKK: ajanin kendi bolum yapisi (Yönetici Özeti + Bulgular) oldugu gibi; wrapper YOK.
  const bodyBlock = isKvkk
    ? `${findingsMd.trim() || t.noFindings}`
    : `## ${t.findings}\n\n${findingsMd.trim() || t.noFindings}`;
  const isFullPentest = packageKey === 'bundle_full_pentest';
  const legalTitle = isKvkk ? 'Yasal Uyarı ve Kapsam' : t.legalTitle;
  // (Tam Kapsamlı Pentest) AYRI, DOĞRU disclaimer (authenticated); diğer paketlerin metni DEĞİŞMEZ.
  const legal = isFullPentest ? (locale === 'de' ? FULL_PENTEST_LEGAL_DE : locale === 'en' ? FULL_PENTEST_LEGAL_EN : FULL_PENTEST_LEGAL_TR) : isKvkk ? KVKK_LEGAL : t.legal;
  // (KALİTE) Ortak bölümler gövdenin ARKASINA, legal'in ÖNÜNE eklenir; ilk sayfa/özet DEĞİŞMEZ.
  const commonBlock = buildCommonSections(packageKey, locale);
  return `# ${isKvkk ? 'KVKK Ön Uyum Kontrol Raporu' : t.title}

**${t.target}:** ${hostname}
**${t.pkg}:** ${packageName}
**${t.created}:** ${new Date().toISOString()}

---

${bodyBlock}${screenshotsBlock}${commonBlock}

---

## ${legalTitle}

${legal.map((l) => `- ${l}`).join('\n')}
`;
}

// (3) Cozum onerileri bolumu — ayri/kilitli alanda saklanir, odeme sonrasi acilir.
export function renderFixSuggestionsMarkdown(hostname: string, fixText: string, locale: Locale = 'tr', packageKey?: string): string {
  const t = T[locale];
  // KVKK: baslik PDF tarafinda ("Önerilen Aksiyonlar") eklenir + ajan kendi alt-basliklarini
  // (Önerilen Aksiyonlar / Ek-A) yazar; bu yuzden ASCII "# AI Cozum Onerileri" H1'i EKLEMEYIZ.
  if (packageKey === 'kvkk_hazirlik') {
    return `> Bu bölüm düzeltme (remediation) önerileri içindir; istismar/exploit kodu içermez.\n\n${fixText}\n`;
  }
  // PDF tarafi zaten "AI Çözüm Önerileri" baslik (h2) ekliyor (buildHtml fix-section); burada
  // AYRICA "# ... — host" H1'i EKLEMEYIZ (cift baslik/tekrar olurdu). Yalniz not + icerik.
  return `> ${t.fixNote}\n\n${fixText}\n`;
}
