// ============================================================================
// YAPISAL BÜTÜNLÜK DOĞRULAYICI (QA KATMANI) — DETERMİNİSTİK, LLM'SİZ
// ----------------------------------------------------------------------------
// Rapor markdown'ı PDF'e (aslında şifreli DB'ye) yazılmadan HEMEN ÖNCE çağrılır.
// LLM ÇAĞRISI YOK (yeni halüsinasyon kaynağı yaratmaz) — yalnız obje/regex kontrolleri.
// İçeriği YENİDEN YAZMAZ; sadece bulunan yapısal kusurları (a) güvenli şekilde onarır
// (ör. yarım/çıplak-URL bulguyu tablodan çıkarır, eksik şeffaflık notunu ekler),
// (b) onaramadığı kritik tutarsızlıkta 'blocked' bayrağı verir. Sonsuz loop YOK (tek geçiş).
//
// Kurallar (bulduğumuz her hata sınıfı için):
//  R1/R2/R3 Master↔Detay eşleşmesi + çıplak-URL başlık + boş/placeholder alan
//  R4 Rozet = Zafiyet Dağılımı = Master tutarlılığı (regresyon sigortası)
//  R5 Devre kesici / erken durma şeffaflığı (exec-özette görünmeli)
//  R6 Güven/Kapsam tutarlılığı (gerçek bulgusu olan kontrol "Kapsam dışı" olamaz)
//  R7 Platform farkındalığı (IIS/ASP.NET imzası varsa fix'te IIS/web.config bulunmalı)
// ============================================================================
import { parseFindings, assessBasit, type Finding } from './pdf.js';

export type QaIssue = { rule: string; level: 'block' | 'fix' | 'warn'; message: string; action: string };
export type QaResult = { markdown: string; issues: QaIssue[]; blocked: boolean };

// Çıplak URL/path/query başlığı mı? (findingTaxonomy adı DEĞİL — ham URL). ^ / veya http ile başlar,
// yalnız URL karakterleri içerir, boşluk/Türkçe kelime YOK.
function isBareUrl(title: string): boolean {
  const t = title.trim();
  if (!t) return false;
  return /^(https?:\/\/|\/)[\w\-./?=&%:#]+$/i.test(t) && !/\s/.test(t);
}
const PLACEHOLDER_RE = /^(undefined|null|nan|todo|tbd|n\/a|-|—|\{\{.*\}\}|\$\{.*\})$/i;
const SEV_WORD_RE = /^\s*(kritik|y[üu]ksek|orta[-\s]?y[üu]ksek|orta|d[üu][şs][üu]k|critical|high|medium|low)\s*$/i;

// Bir markdown tablo-satırı, verilen (ham) başlığı içeren bir ŞİDDET satırı mı?
function rowLineMatches(line: string, rawTitle: string): boolean {
  if (!/^\s*\|/.test(line)) return false;
  const cells = line.split('|').map((c) => c.trim());
  const hasSev = cells.some((c) => SEV_WORD_RE.test(c));
  if (!hasSev) return false;
  // başlığı sadeleştirip (markdown/backtick) satırda ara
  const needle = rawTitle.replace(/[`*]/g, '').trim();
  return needle.length > 3 && line.replace(/[`*]/g, '').includes(needle);
}

const rank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

export function validateAndRepairReport(
  markdown: string,
  opts: { packageKey?: string; locale?: 'tr' | 'en'; fixText?: string; hostname?: string },
): QaResult {
  const loc = opts.locale ?? 'tr';
  const issues: QaIssue[] = [];
  let md = markdown;
  let blocked = false;
  // KVKK/uyum paketleri severity-master kullanmaz -> R1..R4/R6 atlanır (yanlış-pozitif önle).
  const isCompliance = ['kvkk_hazirlik', 'bundle_compliance', 'pci_hazirlik', 'iso27001_hazirlik'].includes(opts.packageKey ?? '');

  const parsed = parseFindings(md, loc);

  // --- R1/R2/R3: yarım/çıplak-URL/sınıflanamayan bulgu -> master'dan ÇIKAR (yarım bulgu müşteriye gitmesin) ---
  if (!isCompliance) {
    const broken: Finding[] = parsed.rows.filter((r) => {
      // detay kartı SADECE type varsa render edilir -> type yoksa "yarım" (master'da var, kartı yok).
      const noCard = !r.type;
      const urlTitle = isBareUrl(r.title);
      const placeholder = PLACEHOLDER_RE.test(r.title.trim()) || (!!r.evidence && PLACEHOLDER_RE.test(r.evidence.trim()));
      return noCard || urlTitle || placeholder;
    });
    for (const b of broken) {
      const before = md;
      md = md.split('\n').filter((line) => !rowLineMatches(line, b.title)).join('\n');
      if (md !== before) {
        issues.push({ rule: 'R1/R2/R3', level: 'fix', message: `Yarım/çıplak-URL/sınıflanamayan bulgu ("${b.title.slice(0, 50)}") — detay kartı üretilemezdi.`, action: 'master/dağılım/detaydan çıkarıldı' });
      } else {
        issues.push({ rule: 'R1/R2/R3', level: 'warn', message: `Yarım bulgu ("${b.title.slice(0, 50)}") tespit edildi ama kaynak satır bulunamadı.`, action: 'log-only' });
      }
    }
  }

  // parsed'ı onarımdan SONRA yeniden hesapla (R4 için — çıkarılan bulgular sonrası güncel master).
  const parsed2 = parseFindings(md, loc);

  // --- R4: Rozet = Dağılım = Master tutarlılığı (regresyon sigortası) ---
  if (!isCompliance) {
    const t = { riskHigh: 'Yüksek Risk', riskMedium: 'Orta Risk', riskMediumHigh: 'Orta-Yüksek Risk', riskLow: 'Düşük Risk', assessHigh: '', assessMedium: '', assessLow: '' };
    const badge = assessBasit(md, t);
    const isIncelenemedi = /incelenemedi/i.test(badge.label.toLocaleLowerCase('tr'));
    if (!isIncelenemedi) {
      const masterMax = parsed2.rows.reduce((m, r) => Math.max(m, rank[r.sev] ?? 0), 0);
      const badgeRank = badge.level === 'high' ? 3 : badge.level === 'medium-high' ? 2 : badge.level === 'medium' ? 2 : 1;
      // AÇIK çelişki: master'da Yüksek/Kritik bulgu var ama rozet Düşük. (Küçük farkları tolere et.)
      if (masterMax >= 3 && badgeRank <= 1) {
        blocked = true;
        issues.push({ rule: 'R4', level: 'block', message: `Rozet (${badge.label}) ile Master en yüksek şiddet (rank ${masterMax}) çelişiyor.`, action: 'BLOK — rapor teslim edilmemeli (kod hatası sinyali)' });
      }
    }
  }

  // --- R5: Devre kesici / erken durma şeffaflığı (exec-özette görünmeli) ---
  const execSeg = md.split(/##\s*GENEL DE[ĞG]ERLEND[İI]RME/i)[0] ?? md.slice(0, 2500);
  const bodySeg = md.slice(execSeg.length);
  const triggered = /(art arda\s*5xx|devre kesici.*(?:durdu|tetiklendi|nedeniyle)|erken (?:durduruldu|sonland[ıi]r)|WAF.*(?:durdu|engel)|hedef[- ]sa[ğg]l[ıi][ğg][ıi].*durdu|tarama.*erken.*sonland)/i;
  if (triggered.test(bodySeg) && !triggered.test(execSeg)) {
    const note = loc === 'tr'
      ? '\n- ⚠️ **Erken durdurma:** Bir/birkaç kontrol, hedef-sağlığı devre kesici (art arda 5xx / aşırı yavaşlama / WAF) nedeniyle erken sonlandırıldı; ilgili sonuçlar eksik olabilir (aşağıda ilgili kontrolde belirtilmiştir).'
      : '\n- ⚠️ **Early stop:** One or more checks were halted early by the target-health circuit breaker; related results may be incomplete.';
    // YÖNETİCİ ÖZETİ bölümünün sonuna ekle (varsa), yoksa exec segment sonuna.
    if (/##\s*Y[ÖO]NET[İI]C[İI] [ÖO]ZET[İI]/i.test(md)) {
      md = md.replace(/(##\s*Y[ÖO]NET[İI]C[İI] [ÖO]ZET[İI][\s\S]*?)(\n##\s|\n---\n|$)/i, (m, body, tail) => `${body}${note}${tail}`);
      issues.push({ rule: 'R5', level: 'fix', message: 'Devre kesici tetiklendi ama Yönetici Özeti\'nde belirtilmemiş.', action: 'exec-özete şeffaflık notu eklendi' });
    } else {
      issues.push({ rule: 'R5', level: 'warn', message: 'Devre kesici tetiklendi ama Yönetici Özeti bölümü bulunamadı.', action: 'log-only' });
    }
  }

  // --- R6: Güven/Kapsam tutarlılığı (gerçek bulgusu olan kontrol "Kapsam dışı" olamaz) ---
  // KONTROL ÖZETİ tablosunda Sonuç "⚠ ... gösterge/zafiyet" iken Güven "Kapsam dışı" satırı çelişkidir.
  for (const line of md.split('\n')) {
    if (!/^\s*\|/.test(line)) continue;
    const cells = line.split('|').map((c) => c.trim());
    const hasFindingCell = cells.some((c) => /⚠.*g[öo]sterge|⚠.*zafiyet|zafiyet g[öo]stergesi/i.test(c));
    const hasScopeOut = cells.some((c) => /kapsam d[ıi][şs][ıi]/i.test(c));
    if (hasFindingCell && hasScopeOut) {
      issues.push({ rule: 'R6', level: 'warn', message: `Güven/Kapsam çelişkisi: bir kontrol hem "gösterge" hem "Kapsam dışı" işaretli ("${line.slice(0, 60).trim()}").`, action: 'log-only (kaynak generator gözden geçirilmeli)' });
    }
  }

  // --- R7: Platform farkındalığı (IIS/ASP.NET -> fix'te IIS/web.config olmalı) ---
  const iisDetected = /Microsoft-IIS|X-AspNet|ASP\.NET|web\.config/i.test(md);
  const fix = opts.fixText ?? '';
  if (iisDetected && fix && !/web\.config|<system\.webServer>|Microsoft-IIS|IIS/i.test(fix)) {
    issues.push({ rule: 'R7', level: 'warn', message: 'Sunucu imzası IIS/ASP.NET ama AI Çözüm Önerileri yalnız Nginx/Apache içeriyor.', action: 'log-only (IIS/web.config bloğu eklenmeli)' });
  }

  const fixCount = issues.filter((i) => i.level === 'fix').length;
  const warnCount = issues.filter((i) => i.level === 'warn').length;
  const blockCount = issues.filter((i) => i.level === 'block').length;
  console.log(`[report-validator] paket=${opts.packageKey ?? '?'} host=${opts.hostname ?? '?'} -> fix=${fixCount} warn=${warnCount} block=${blockCount}${blocked ? ' BLOCKED' : ''}`);
  for (const i of issues) console.log(`[report-validator]   [${i.level.toUpperCase()}] ${i.rule}: ${i.message} -> ${i.action}`);

  return { markdown: md, issues, blocked };
}
