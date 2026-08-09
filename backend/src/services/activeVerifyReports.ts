/**
 * (Aktif Doğrulama — injection_verify + idor_verify) DETERMINISTIK RAPOR URETICILERI.
 *
 * Prob motoru (activeVerifyEvidence.ts) yalnizca yapisal kanit toplar; Turkce rapor metnini
 * TAMAMEN bu kod yazar (ajan yok). Cikti diger paketlerle ayni bicimde: Yonetici Ozeti + Risk
 * rozeti + "ne kontrol edildi" seffafligi + bulgu tablosu + kilitli "AI Cozum Onerileri".
 * generateXReport { findings, fixText } | null doner (hedefe ulasilamazsa null -> fallback).
 */
import {
  collectInjectionEvidence, collectIdorEvidence, type InjEvidence, type IdorEvidence,
  collectSsrfEvidence, collectRceEvidence, collectFileUploadEvidence, collectBusinessLogicEvidence, collectRaceMassAssignEvidence,
  type ActiveCheckEvidence,
} from './activeVerifyEvidence.js';

const RISK_WORD = { low: 'Düşük', medium: 'Orta', 'medium-high': 'Orta-Yüksek', high: 'Yüksek' } as const;
type Level = 'low' | 'medium' | 'medium-high' | 'high';
function levelRank(l: Level): number { return l === 'high' ? 3 : l === 'medium-high' ? 2 : l === 'medium' ? 1 : 0; }

function assemble(level: Level, summaryBullets: string[], genelSentence: string, sections: string): string {
  return (
    `## YÖNETİCİ ÖZETİ\n\n${summaryBullets.join('\n')}\n\n` +
    `## GENEL DEĞERLENDİRME\n\n**Risk Seviyesi: ${RISK_WORD[level]}**\n\n${genelSentence}\n\n` +
    `${sections}`
  );
}

const SCOPE_NOTE_ACTIVE =
  '> **Kapsam ve yöntem:** Bu paket, "kanıtla — istismar etme" ilkesiyle çalışır. Backend, hedefe ' +
  'sınırlı sayıda **zararsız** doğrulama probu göndermiştir; hiçbir veri çekilmemiş, değiştirilmemiş veya ' +
  'silinmemiştir. İstekler arası bekleme ve hedef-sağlığı devre kesici (art arda 5xx / aşırı yavaşlama / WAF) ' +
  'uygulanır. Kimlik doğrulama gerektiren alanlar ve iç mantık bu paketin kapsamı dışındadır.';

// ======================================================================================
// injection_verify
// ======================================================================================
function injLevel(ev: InjEvidence): Level {
  if (ev.findings.some((f) => f.severity === 'high')) return 'high';
  if (ev.findings.some((f) => f.severity === 'medium')) return 'medium-high';
  if (ev.findings.some((f) => f.severity === 'low')) return 'medium';
  return 'low';
}

export async function generateInjectionVerifyReport(host: string): Promise<{ findings: string; fixText: string } | null> {
  const ev = await collectInjectionEvidence(host);
  return buildInjectionReport(ev);
}

// Saf kurucu (testlenebilir — gercek prob calistirmadan sentetik kanitla dogrulanir).
export function buildInjectionReport(ev: InjEvidence): { findings: string; fixText: string } | null {
  if (!ev.ok) return null;
  const level = injLevel(ev);
  const sqli = ev.findings.filter((f) => f.type === 'SQLi');
  const xss = ev.findings.filter((f) => f.type === 'XSS');

  const bullets = [
    `- **Genel risk seviyesi: ${RISK_WORD[level]}** — ${level === 'high' ? 'aktif doğrulama ile enjeksiyon zafiyeti KANITLANDI.' : level === 'medium-high' || level === 'medium' ? 'olası bir enjeksiyon göstergesi bulundu (bağlama göre doğrulama önerilir).' : ev.inputsFound ? 'test edilen giriş noktalarında enjeksiyon kanıtı bulunamadı.' : 'ana sayfada test edilebilir giriş noktası saptanmadı.'}`,
    `- Kontrol edilen giriş noktası: **${ev.inputsFound}** · Gönderilen probe: **${ev.probesSent}** · SQLi bulgusu: ${sqli.length} · XSS bulgusu: ${xss.length}.`,
    '- **Önerilen ilk adım:** ' + (ev.findings.length ? 'Kanıtlanan giriş noktalarını parametreli sorgu / çıktı kodlaması ile kapatın; hazır adımlar "AI Çözüm Önerileri" bölümünde.' : 'Girdi doğrulama ve çıktı kodlamasını standart hale getirin; hazır sertleştirme adımları "AI Çözüm Önerileri" bölümünde.'),
  ];

  const genel = level === 'high'
    ? 'Aktif-hafif doğrulama ile en az bir giriş noktasında enjeksiyon zafiyeti kanıtlandı; öncelikli olarak giderilmesi önerilir.'
    : level === 'medium-high' || level === 'medium'
      ? 'Olası bir enjeksiyon göstergesi bulundu; bağlama göre manuel doğrulama ve giderme önerilir.'
      : ev.inputsFound
        ? `Test edilen ${ev.inputsFound} giriş noktasında, gönderilen zararsız doğrulama problarına karşı enjeksiyon (SQLi/XSS) kanıtı gözlemlenmedi. Bu, bu giriş noktalarının şu an için dayanıklı göründüğünü gösterir (tüm giriş noktalarının kanıtı değildir).`
        : 'Ana sayfada test edilebilir bir GET parametresi veya form alanı bulunamadı; enjeksiyon doğrulaması için bir giriş noktası saptanmadı.';

  // Ne kontrol edildi — seffaflik (bulgu olsa da olmasa da)
  const method = [
    '## NE KONTROL EDİLDİ\n',
    'Ana sayfadan keşfedilen giriş noktaları (URL query parametreleri + form alanları) üzerinde, giriş noktası başına zararsız doğrulama probları:',
    '',
    '- **SQLi (hata-tabanlı):** Tek tırnak (`\'`) enjekte edilip yanıtta veritabanı hata imzası (MySQL/PostgreSQL/Oracle/MSSQL/SQLite) arandı.',
    `- **SQLi (zaman-tabanlı):** Hata görülmeyen noktalarda tek bir zararsız gecikme probu (SLEEP) ile yanıt süresi baseline’a göre ölçüldü (blind SQLi göstergesi).`,
    '- **XSS (yansıyan):** Benzersiz, zararsız bir işaret dizesi enjekte edilip yanıt HTML’inde **kaçırılmadan (unencoded)** yansıyıp yansımadığı kontrol edildi (JS çalıştırılmadı; stored XSS denenmedi).',
    '',
  ].join('\n');

  const table = ev.findings.length
    ? '## BULGULAR\n\n| Giriş Noktası | Tür | Teknik | Kanıt | Ciddiyet |\n|---------------|-----|--------|-------|----------|\n' +
      ev.findings.map((f) => `| ${f.inputPoint} | ${f.type} | ${f.technique === 'error-based' ? 'hata-tabanlı' : f.technique === 'time-based' ? 'zaman-tabanlı' : 'yansıma'} | ${f.evidence.replace(/\|/g, '\\|')} | ${RISK_WORD[f.severity]} |`).join('\n') + '\n\n'
    : '## BULGULAR\n\nTest edilen giriş noktalarında enjeksiyon kanıtı bulunamadı.\n\n';

  const notes = ev.notes.length ? ev.notes.map((n) => `> ${n}`).join('\n') + '\n\n' : '';
  const findings = assemble(level, bullets, genel, `${method}${table}${notes}${SCOPE_NOTE_ACTIVE}\n`);

  const fixText = ev.findings.length
    ? '### Enjeksiyon (SQLi/XSS) — düzeltme\n\n' + [
        sqli.length ? '- **SQLi:** Tüm veritabanı sorgularını **parametreli sorgu / hazırlanmış ifade (prepared statement)** ile yazın; kullanıcı girdisini asla string olarak sorguya eklemeyin. ORM kullanıyorsanız ham SQL birleştirmeden kaçının. Veritabanı hata mesajlarını son kullanıcıya göstermeyin.' : '',
        xss.length ? '- **XSS:** Kullanıcı girdisini HTML’e basarken **bağlama uygun çıktı kodlaması** (HTML entity encoding) uygulayın; mümkünse otomatik kaçış yapan şablon motoru kullanın. `Content-Security-Policy` başlığı ile satır-içi script’leri kısıtlayın.' : '',
        '- Giderdikten sonra aynı giriş noktalarını yeniden test edin.',
      ].filter(Boolean).join('\n')
    : '### Enjeksiyon — proaktif sertleştirme\n\n' + [
        '- **Girdi doğrulama:** Tüm kullanıcı girdilerini beklenen tip/uzunluk/biçime göre doğrulayın (allowlist yaklaşımı).',
        '- **SQLi’ye karşı:** Her zaman parametreli sorgu / hazırlanmış ifade kullanın; ham SQL string birleştirmeyin.',
        '- **XSS’e karşı:** Çıktı kodlaması (HTML entity) + `Content-Security-Policy` başlığı uygulayın; otomatik kaçış yapan şablon motoru tercih edin.',
        '- Veritabanı ve uygulama hata mesajlarını son kullanıcıdan gizleyin (yığın izi / SQL hatası sızdırmayın).',
      ].join('\n');

  return { findings, fixText };
}

// ======================================================================================
// idor_verify
// ======================================================================================
function idorLevel(ev: IdorEvidence): Level {
  if (ev.findings.some((f) => f.severity === 'medium')) return 'medium-high';
  if (ev.findings.some((f) => f.severity === 'low')) return 'medium';
  return 'low';
}

export async function generateIdorVerifyReport(host: string): Promise<{ findings: string; fixText: string } | null> {
  const ev = await collectIdorEvidence(host);
  return buildIdorReport(ev);
}

// Saf kurucu (testlenebilir).
export function buildIdorReport(ev: IdorEvidence): { findings: string; fixText: string } | null {
  if (!ev.ok) return null;
  const level = idorLevel(ev);

  const bullets = [
    `- **Genel risk seviyesi: ${RISK_WORD[level]}** — ${level === 'medium-high' ? 'kimlik doğrulaması olmadan komşu ID ile farklı kaynağa erişim göstergesi bulundu.' : level === 'medium' ? 'zayıf bir numaralandırma göstergesi bulundu (manuel doğrulama gerekli).' : ev.candidates ? 'test edilen ID’li uç noktalarda yetkisiz erişim göstergesi bulunmadı.' : 'test edilebilir ID’li uç nokta saptanmadı.'}`,
    `- Aday uç nokta: **${ev.candidates}** · Gönderilen probe: **${ev.probesSent}** · Bulgu: ${ev.findings.length}.`,
    '- **Önerilen ilk adım:** ' + (ev.findings.length ? 'Nesne-düzeyi yetkilendirme kontrolü ekleyin; hazır adımlar "AI Çözüm Önerileri" bölümünde.' : 'Nesne-düzeyi yetkilendirmeyi standart hale getirin; hazır adımlar "AI Çözüm Önerileri" bölümünde.'),
  ];

  const genel = level === 'medium-high'
    ? 'Kimlik doğrulaması olmadan, tahmin edilebilir bir ID’yi komşu değere değiştirerek farklı bir kaynağa erişilebildiği gözlemlendi; nesne-düzeyi yetkilendirme kontrolü önerilir.'
    : level === 'medium'
      ? 'Zayıf bir numaralandırma göstergesi bulundu; bağlama göre manuel doğrulama önerilir.'
      : ev.candidates
        ? `Test edilen ${ev.candidates} ID’li uç noktada, kimlik doğrulaması olmadan komşu ID’ye erişim denemesinde yetkisiz erişim göstergesi gözlemlenmedi.`
        : 'Ana sayfada tahmin edilebilir/sayısal ID içeren bir uç nokta bulunamadı.';

  // DURUSTLUK: kapsam sinirini ACIKCA belirt (abartili "IDOR yok" iddiasi YAPMA).
  const scopeLimit =
    '## KAPSAM SINIRI (ÖNEMLİ)\n\n' +
    'Bu paket **kimlik doğrulaması olmadan** çalışır. Bu nedenle yalnızca **herkese açık, numaralandırılabilir kaynaklara** yetkisiz erişimi tespit edebilir. ' +
    'Klasik IDOR (bir kullanıcının, oturum açmış başka bir kullanıcının verisine erişmesi) **iki farklı hesap/oturum** gerektirir ve bu paketin kapsamı dışındadır. ' +
    'Bu bölümde bulgu olmaması, kimlik doğrulamalı akışlarda IDOR olmadığını **kanıtlamaz** — bu, ayrı bir kimlik-doğrulamalı test gerektirir (**İnceleme gerekli / Kapsam Dışı**).\n\n';

  const method = [
    '## NE KONTROL EDİLDİ\n',
    'Ana sayfadan keşfedilen, tahmin edilebilir/sayısal ID içeren uç noktalar (ör. `?id=123`, `/user/45`) üzerinde:',
    '',
    '- ID değeri **komşu bir değere** (N-1 / N+1) değiştirilip, kimlik doğrulaması olmadan **GET** isteği gönderildi.',
    '- Yalnızca yanıt **durumu ve boyutu** karşılaştırıldı; **dönen içerik saklanmadı/alıntılanmadı**.',
    '- Farklı ve geçerli görünen bir kaynak dönmesi, numaralandırılabilir erişim göstergesi sayıldı.',
    '',
  ].join('\n');

  const table = ev.findings.length
    ? '## BULGULAR\n\n| Uç Nokta | ID | Gözlem | Ciddiyet |\n|----------|-----|--------|----------|\n' +
      ev.findings.map((f) => `| ${f.endpoint} | ${f.idParam} | ${f.observation.replace(/\|/g, '\\|')} | ${RISK_WORD[f.severity]} |`).join('\n') + '\n\n'
    : '## BULGULAR\n\nTest edilen ID’li uç noktalarda yetkisiz erişim göstergesi bulunamadı.\n\n';

  const notes = ev.notes.length ? ev.notes.map((n) => `> ${n}`).join('\n') + '\n\n' : '';
  const findings = assemble(level, bullets, genel, `${method}${table}${scopeLimit}${notes}${SCOPE_NOTE_ACTIVE}\n`);

  const fixText = ev.findings.length
    ? '### Yetkisiz Erişim (IDOR) — düzeltme\n\n' + [
        '- **Nesne-düzeyi yetkilendirme:** Her kaynak erişiminde, isteyen kullanıcının o nesneye erişim hakkı olup olmadığını sunucu tarafında doğrulayın (sadece ID’nin geçerli olması yeterli değildir).',
        '- **Tahmin edilemez tanımlayıcılar:** Sıralı sayısal ID yerine UUID/rastgele tanımlayıcı kullanın; numaralandırmayı zorlaştırın.',
        '- Herkese açık olmaması gereken kaynakları kimlik doğrulama arkasına alın.',
      ].join('\n')
    : '### Yetkisiz Erişim (IDOR) — proaktif sertleştirme\n\n' + [
        '- Her kaynak erişiminde **nesne-düzeyi yetkilendirme** kontrolü uygulayın (kullanıcı ↔ nesne sahipliği).',
        '- Sıralı sayısal ID yerine **UUID/rastgele tanımlayıcı** kullanın.',
        '- Kimlik doğrulamalı akışlar için ayrı, oturum-tabanlı bir IDOR testi planlayın (bu paketin kapsamı dışında).',
      ].join('\n');

  return { findings, fixText };
}

// ======================================================================================
// bundle_active_verify — BIRLESIK RAPOR (injection+idor GERCEK + 5 kontrol DURUSTLUK notu)
// ======================================================================================
// injection_verify/idor_verify KENDI rapor mantigini DEGISTIRMEDEN cagirir; ciktilarini birlesik
// rapora yerlestirir. Diger 5 uyenin deterministik generator'i YOK -> sessizce bos/hatali sonuc
// yerine NET "henuz olgunlasmadi" notu basar (Grok/tuketici-durustlugu geregi).
type ActiveMember = { key: string; title: string; gen?: (host: string) => Promise<{ findings: string; fixText: string } | null> };
const ACTIVE_BUNDLE_MEMBERS: ActiveMember[] = [
  { key: 'injection_verify', title: 'Enjeksiyon (SQLi/XSS) Doğrulama', gen: generateInjectionVerifyReport },
  { key: 'idor_verify', title: 'Yetkisiz Erişim (IDOR) Doğrulama', gen: generateIdorVerifyReport },
  { key: 'ssrf_verify', title: 'SSRF Doğrulama', gen: generateSsrfVerifyReport },
  { key: 'file_upload_verify', title: 'Dosya Yükleme Doğrulama', gen: generateFileUploadVerifyReport },
  { key: 'business_logic_verify', title: 'İş Mantığı Doğrulama', gen: generateBusinessLogicVerifyReport },
  { key: 'race_massassign_verify', title: 'Race / Mass-Assignment Doğrulama', gen: generateRaceMassAssignVerifyReport },
  { key: 'rce_verify', title: 'RCE / Komut Enjeksiyonu Doğrulama', gen: generateRceVerifyReport },
];

const PENDING_NOTE =
  '> **Bu kontrol şu anda geliştirme/olgunlaştırma aşamasındadır.** Güvenilir ve doğrulanabilir bir ' +
  'sonuç üretebildiğimizden emin olana kadar bu taramada **çalıştırılmadı** — sessizce boş veya yanlış ' +
  'bir sonuç göstermektense bunu açıkça belirtmeyi tercih ediyoruz. Bu kontrol pakete yakında eklenecektir.';

function extractLevel(findings: string): Level {
  const m = findings.match(/Risk Seviyesi:\s*(Orta[-\s]?Y[uü]ksek|Y[uü]ksek|Orta|D[uü][sş][uü]k)/i);
  if (!m) return 'low';
  const w = m[1].toLocaleLowerCase('tr');
  if (/orta[-\s]?y[uü]ksek/.test(w)) return 'medium-high';
  if (/y[uü]ksek/.test(w)) return 'high';
  if (/orta/.test(w)) return 'medium';
  return 'low';
}
function headlineOf(findings: string): string {
  const m = findings.match(/Genel risk seviyesi:\s*[^\n]+?\s[—–-]\s([^\n]+)/i);
  return m ? m[1].trim().replace(/\*\*/g, '') : '';
}
// YÖNETİCİ ÖZETİ + GENEL DEĞERLENDİRME'yi cikar, detay bolumlerini dondur (## -> ### indir).
function detailOnly(findings: string): string {
  const parts = findings.split(/(?=^## )/m);
  return parts.slice(2).join('').replace(/^## /gm, '### ').trim();
}

export async function generateBundleActiveVerifyReport(host: string): Promise<{ findings: string; fixText: string } | null> {
  // Gercek (deterministik) uyeleri calistir; digerleri stub.
  const results = await Promise.all(
    ACTIVE_BUNDLE_MEMBERS.map(async (m) => (m.gen ? await m.gen(host).catch(() => null) : null)),
  );
  const realIdx = ACTIVE_BUNDLE_MEMBERS.map((m, i) => (m.gen ? i : -1)).filter((i) => i >= 0);
  // Gercek uyelerin hicbiri veri toplayamadiysa (hedefe ulasilamadi) -> fallback.
  if (realIdx.every((i) => !results[i])) return null;

  const levels: Array<Level | null> = ACTIVE_BUNDLE_MEMBERS.map((m, i) => (m.gen && results[i] ? extractLevel(results[i]!.findings) : null));
  const ranked = levels.map((lv, i) => ({ lv, i })).filter((x): x is { lv: Level; i: number } => x.lv !== null).sort((a, b) => levelRank(b.lv) - levelRank(a.lv));
  const worst: Level = ranked.length ? ranked[0].lv : 'low';
  const worstTitle = ranked.length ? ACTIVE_BUNDLE_MEMBERS[ranked[0].i].title : '';
  const worstHl = ranked.length && results[ranked[0].i] ? headlineOf(results[ranked[0].i]!.findings) : '';
  const pendingCount = ACTIVE_BUNDLE_MEMBERS.filter((m) => !m.gen).length;
  const realCount = ACTIVE_BUNDLE_MEMBERS.length - pendingCount;

  // --- YÖNETİCİ ÖZETİ ---
  const summary: string[] = [];
  summary.push(
    worst === 'low'
      ? `- **Genel risk seviyesi: Düşük** — çalıştırılan ${realCount} aktif doğrulama kontrolünde belirgin bir zafiyet kanıtı öne çıkmadı.`
      : `- **Genel risk seviyesi: ${RISK_WORD[worst]}** — çalıştırılan kontrollerde en yüksek risk **${worstTitle}** alanında${worstHl ? ` (${worstHl})` : ''}.`,
  );
  ACTIVE_BUNDLE_MEMBERS.forEach((m, i) => {
    if (m.gen) {
      const lv = levels[i];
      const r = results[i];
      if (!r || !lv) { summary.push(`- **${m.title}:** veri toplanamadı (hedefe ulaşılamadı).`); return; }
      const hl = headlineOf(r.findings);
      summary.push(`- **${m.title}:** ${RISK_WORD[lv]}${hl ? ` — ${hl}` : ''}`);
    } else {
      summary.push(`- **${m.title}:** ⏳ henüz eklenmedi (geliştirme aşamasında).`);
    }
  });
  summary.push(
    pendingCount === 0
      ? `- **Şeffaflık:** Paketteki **${realCount}/${ACTIVE_BUNDLE_MEMBERS.length}** kontrolün tamamı bu taramada çalıştırıldı. SSRF ve RCE tespitleri OOB altyapısı olmadan **zaman-tabanlı/dolaylı (orta güvenilirlik)** yapılır; ilgili bölümlerde belirtilmiştir.`
      : `- **Şeffaflık:** Bu pakette şu an **${realCount}/${ACTIVE_BUNDLE_MEMBERS.length}** kontrol tam işlevseldir; kalan ${pendingCount} kontrol aşamalı olarak devreye alınmaktadır ve bu taramada çalıştırılmamıştır.`,
  );
  summary.push('- **Önerilen ilk adım:** Çalıştırılan kontrollerdeki bulguları giderin; hazır adımlar "AI Çözüm Önerileri" bölümünde.');

  const genel =
    (worst === 'low'
      ? 'Çalıştırılan aktif doğrulama kontrollerinde belirgin bir zafiyet kanıtı öne çıkmadı.'
      : `Çalıştırılan kontrollerde en yüksek risk **${worstTitle}** alanında${worstHl ? ` (${worstHl})` : ''} tespit edildi; öncelikli olarak giderilmesi/doğrulanması önerilir.`) +
    (pendingCount === 0
      ? ' Paketteki 7 kontrolün tamamı çalıştırılmıştır (SSRF/RCE zaman-tabanlı/dolaylı). Aşağıda her kontrol ayrı ayrı raporlanmıştır.'
      : ` Bu paketin ${pendingCount} kontrolü halen olgunlaştırma aşamasındadır ve bu taramada çalıştırılmamıştır — ilgili bölümlerde açıkça belirtilmiştir. Aşağıda her kontrol ayrı ayrı raporlanmıştır.`);

  // --- Bolumler ---
  const sections = ACTIVE_BUNDLE_MEMBERS.map((m, i) => {
    if (m.gen) {
      const r = results[i];
      if (!r) return `## ${m.title}\n\n> Bu kontrol için veri toplanamadı (hedefe ulaşılamadı); diğer kontroller raporlanmıştır.\n`;
      return `## ${m.title}\n\n${detailOnly(r.findings)}\n`;
    }
    return `## ${m.title}\n\n${PENDING_NOTE}\n`;
  }).join('\n');

  const findings =
    `## YÖNETİCİ ÖZETİ\n\n${summary.join('\n')}\n\n` +
    `## GENEL DEĞERLENDİRME\n\n**Risk Seviyesi: ${RISK_WORD[worst]}**\n\n${genel}\n\n` +
    `${sections}`;

  // --- AI ÇÖZÜM ÖNERİLERİ (yalniz gercek uyeler) ---
  const fixParts = ACTIVE_BUNDLE_MEMBERS.map((m, i) => {
    if (!m.gen || !results[i]?.fixText.trim()) return '';
    return `### ${m.title}\n\n${results[i]!.fixText.trim()}`;
  }).filter(Boolean);
  const fixText =
    'Bu bölüm, çalıştırılan aktif doğrulama kontrollerinde tespit edilen bulgular için düzeltme önerileri içerir.\n\n' +
    fixParts.join('\n\n');

  return { findings, fixText };
}

// ======================================================================================
// FAZ B/C/D — SSRF, RCE, Dosya Yükleme, İş Mantığı, Race/Mass-Assignment
// Ortak, VFinding-tabanlı rapor kurucu. Türkçe metni TAMAMEN kod yazar (ajan yok).
// ======================================================================================
type CheckCfg = {
  title: string;
  whatChecked: string[];      // "NE KONTROL EDİLDİ" satırları
  confidenceNote?: string;    // ek dürüstlük/güven notu (ssrf/rce dolaylı vb.)
  fixTitle: string;
  fixFound: string[];
  fixClean: string[];
  cleanGenel: string;
};
function levelFromFindings(fs: ActiveCheckEvidence['findings']): Level {
  if (fs.some((f) => f.severity === 'high')) return 'high';
  if (fs.some((f) => f.severity === 'medium')) return 'medium-high';
  return 'low'; // sadece low-severity gözlem(ler) veya bulgu yok -> rozeti yükseltme
}
const SIDE_EFFECT_WORD: Record<string, string> = { none: 'yok', possible: 'olası', confirmed: 'doğrulandı' };

function buildActiveCheckReport(ev: ActiveCheckEvidence, cfg: CheckCfg): { findings: string; fixText: string } | null {
  if (!ev.ok) return null;
  const level = levelFromFindings(ev.findings);
  const has = ev.findings.length > 0;

  const bullets = [
    `- **Genel risk seviyesi: ${RISK_WORD[level]}** — ${level === 'high' ? 'aktif doğrulama ile zafiyet göstergesi KANITLANDI.' : level === 'medium-high' ? 'dikkat gerektiren bir gösterge bulundu (manuel doğrulama önerilir).' : has ? 'yalnızca düşük-önemli gözlem(ler) bulundu.' : 'belirgin bir zafiyet göstergesi bulunamadı.'}`,
    `- İncelenen giriş/uç nokta: **${ev.inputsFound}** · Gönderilen probe: **${ev.probesSent}** · Bulgu: ${ev.findings.length}.`,
    '- **Önerilen ilk adım:** ' + (has ? 'Bulguları giderin; hazır adımlar "AI Çözüm Önerileri" bölümünde.' : 'Sertleştirme adımları "AI Çözüm Önerileri" bölümünde.'),
  ];
  const genel = has
    ? (level === 'high' ? 'Aktif-hafif doğrulama ile bir zafiyet göstergesi tespit edildi; öncelikli olarak giderilmesi/doğrulanması önerilir.' : 'Dikkat gerektiren bir gösterge bulundu; bağlama göre manuel doğrulama önerilir.')
    : cfg.cleanGenel;

  const method = '## NE KONTROL EDİLDİ\n\n' + cfg.whatChecked.map((l) => `- ${l}`).join('\n') + '\n\n';
  const table = has
    ? '## BULGULAR\n\n| Giriş/Uç Nokta | Teknik | Kanıt | Güven | Yan-etki riski | Ciddiyet |\n|----------------|--------|-------|-------|----------------|----------|\n' +
      ev.findings.map((f) => `| ${f.inputPoint} | ${f.technique} | ${f.evidence.replace(/\|/g, '\\|')} | ${f.confidence === 'high' ? 'Yüksek' : f.confidence === 'medium' ? 'Orta' : 'Düşük'} | ${SIDE_EFFECT_WORD[f.sideEffectRisk]} | ${RISK_WORD[f.severity]} |`).join('\n') + '\n\n'
    : '## BULGULAR\n\nGönderilen zararsız problara karşı belirgin bir zafiyet göstergesi bulunamadı.\n\n';
  const confNote = cfg.confidenceNote ? `> ${cfg.confidenceNote}\n\n` : '';
  const sideEffectNote = ev.findings.some((f) => f.sideEffectRisk !== 'none')
    ? '> **Yan etki uyarısı:** Bu kontroldeki bir/birkaç probe, hedefte bir kayıt/dosya oluşturmuş **olabilir** (yan-etki riski "olası" olarak işaretlenenler). Bu, "kanıtla — istismar etme" ilkesi gereği tek seferlik ve zararsız içerikle yapılmıştır; yine de kontrol edip gerekirse temizlemeniz önerilir.\n\n'
    : '';
  const notes = ev.notes.length ? ev.notes.map((n) => `> ${n}`).join('\n') + '\n\n' : '';
  const findings = assemble(level, bullets, genel, `${method}${table}${confNote}${sideEffectNote}${notes}${SCOPE_NOTE_ACTIVE}\n`);

  const fixText = has
    ? `### ${cfg.fixTitle} — düzeltme\n\n` + cfg.fixFound.map((l) => `- ${l}`).join('\n')
    : `### ${cfg.fixTitle} — proaktif sertleştirme\n\n` + cfg.fixClean.map((l) => `- ${l}`).join('\n');
  return { findings, fixText };
}

const SSRF_CFG: CheckCfg = {
  title: 'SSRF Doğrulama',
  whatChecked: [
    'Sunucu-taraflı fetch tetikleyebilecek parametreler (url/webhook/image/redirect vb.) tespit edildi.',
    'Bu parametrelere, **kontrolümüzdeki** gecikmeli bir echo URL’i verildi; hedefin yanıt süresi baseline ile karşılaştırıldı (sunucu bu URL’i çekerse yanıt gecikir).',
    'İç ağ / bulut-metadata / localhost (169.254.169.254, RFC1918, 127.0.0.1 vb.) **asla** hedeflenmedi (koda gömülü hard-guard).',
  ],
  confidenceNote: 'OOB doğrulama altyapısı kullanılmadığı için bu tespit **zaman-tabanlı, dolaylı ve orta güvenilirliktedir**; kesin doğrulama için ek/manuel test önerilir.',
  fixTitle: 'SSRF',
  fixFound: [
    'Sunucu-taraflı fetch yapan parametreleri bir **allowlist** ile kısıtlayın (yalnızca izin verilen alan adları/şemalar).',
    'İç ağ adreslerine (RFC1918, 169.254.169.254, localhost) giden istekleri sunucu tarafında **engelleyin**; DNS rebinding’e karşı çözümlenen IP’yi de kontrol edin.',
    'Mümkünse dış kaynak çekme işlemlerini izole bir servis/kısıtlı ağ üzerinden yapın.',
  ],
  fixClean: [
    'Kullanıcıdan URL alan tüm alanlarda sunucu-taraflı **allowlist** + iç ağ engellemesi uygulayın (proaktif).',
    'Dış fetch gerektiğinde şema/host doğrulaması + zaman aşımı + boyut limiti koyun.',
  ],
  cleanGenel: 'Tespit edilen fetch-benzeri parametrelerde, kontrolümüzdeki gecikmeli URL’e karşı sunucu-taraflı fetch (SSRF) göstergesi gözlemlenmedi.',
};
const RCE_CFG: CheckCfg = {
  title: 'RCE / Komut Enjeksiyonu Doğrulama',
  whatChecked: [
    'Komuta ulaşabilecek giriş parametreleri tespit edildi.',
    'Yalnızca **zararsız, zaman-tabanlı** gecikme payload’ları (sleep) gönderildi; yanıt süresi baseline ile karşılaştırıldı (blind kanıt).',
    'Gerçek komut çalıştırma (dosya okuma/yazma, ağ bağlantısı, reverse shell) **asla** denenmedi (koda gömülü hard-guard: yalnız sabit sleep payload listesi).',
  ],
  confidenceNote: 'OOB/canary altyapısı kullanılmadığı için bu tespit **zaman-tabanlı, dolaylı ve orta güvenilirliktedir** (ağ gecikmesi yanıltabilir); kesin doğrulama için manuel test önerilir.',
  fixTitle: 'RCE / Komut Enjeksiyonu',
  fixFound: [
    'Kullanıcı girdisini asla doğrudan bir sistem komutuna/shell’e geçirmeyin; mümkünse sistem komutu çağırmaktan tamamen kaçının.',
    'Zorunluysa, komutları argüman dizisi (exec + args) ile çalıştırın; shell birleştirme (string) KULLANMAYIN; girdiyi allowlist ile doğrulayın.',
    'Uygulamayı en düşük yetkiyle çalıştırın; giden ağ bağlantılarını kısıtlayın.',
  ],
  fixClean: [
    'Sistem komutu çağıran kod yollarını gözden geçirin; girdiyi allowlist ile doğrulayın, shell string birleştirmeden kaçının (proaktif).',
    'En düşük yetki + giden ağ kısıtı uygulayın.',
  ],
  cleanGenel: 'Tespit edilen girişlerde, zaman-tabanlı zararsız problara karşı blind komut çalıştırma göstergesi gözlemlenmedi.',
};
const UPLOAD_CFG: CheckCfg = {
  title: 'Dosya Yükleme Doğrulama',
  whatChecked: [
    'Dosya yükleme formu (input type=file) tespit edildi.',
    'Tek seferlik, **zararsız ve çalıştırılamaz (inert)**, çift uzantılı (.php.txt) bir test dosyası gönderildi; yalnızca kabul/red durumu gözlemlendi.',
    'Yüklenen dosya **geri çağrılmadı/çalıştırılmadı** (koda gömülü kural).',
  ],
  fixTitle: 'Dosya Yükleme',
  fixFound: [
    'Dosya tipini **sunucu tarafında** doğrulayın (uzantı + gerçek MIME/işaret baytları); çift uzantı / uzantı hilelerine karşı allowlist kullanın.',
    'Yüklenen dosyaları web köküne KOYMAYIN; çalıştırılamaz bir depoda (veya CDN’de) saklayın; rastgele isim verin.',
    'Yükleme boyutu/tipi limitleri + kimlik doğrulama uygulayın.',
  ],
  fixClean: [
    'Yükleme uç noktalarında sunucu-taraflı tip/MIME doğrulaması + allowlist + web-kökü dışı depolama uygulayın (proaktif).',
  ],
  cleanGenel: 'Tespit edilen yükleme formunda, zararsız test dosyası için belirgin bir zayıf-doğrulama göstergesi gözlemlenmedi (veya yükleme formu bulunamadı).',
};
const BUSINESS_CFG: CheckCfg = {
  title: 'İş Mantığı Doğrulama',
  whatChecked: [
    'Ana sayfa/formlar üzerinde **istemci-tarafında değiştirilebilir** fiyat/miktar alanları (hidden input) gözlemlendi (yalnızca gözlem — istek gönderilmedi).',
    'Bir "başarılı/onay" adımı sayfasına ön koşul olmadan **yalnızca GET** ile erişilip erişilemediği kontrol edildi (adım-atlama göstergesi).',
    '⚠️ Bu kontrol **hiçbir state-değiştiren istek (POST/PUT/…) göndermez** — sepet/ödeme **asla** oluşturulmaz/tamamlanmaz (koda gömülü kural).',
  ],
  confidenceNote: 'İş mantığı zafiyetleri bağlama özeldir; bu kontrol yüzey/gösterge seviyesindedir. Kesin doğrulama kimlik-doğrulamalı manuel test gerektirir.',
  fixTitle: 'İş Mantığı',
  fixFound: [
    'Fiyat/miktar/indirim gibi değerleri **asla** istemciden gelen değerle işlemeyin; sunucu tarafında yeniden hesaplayın/doğrulayın.',
    'Çok adımlı akışlarda her adımın ön koşulunu sunucu tarafında zorunlu kılın (adım-atlamayı engelleyin).',
  ],
  fixClean: [
    'Kritik değerleri (fiyat/miktar) sunucu tarafında doğrulayın; çok adımlı akışlarda adım sırası kontrolü uygulayın (proaktif).',
  ],
  cleanGenel: 'Gözlemlenebilir bir istemci-tarafı fiyat/miktar alanı veya doğrudan erişilebilir "onay" adımı bulunamadı.',
};
const RACE_CFG: CheckCfg = {
  title: 'Race / Mass-Assignment Doğrulama',
  whatChecked: [
    'Kayıt/profil benzeri bir POST formu tespit edildi (ödeme/tamamlama uç noktaları **hariç tutuldu** — koda gömülü blocklist).',
    'Forma fazladan `isAdmin/role` alanları eklenmiş **tek** bir istek gönderildi; yalnızca kabul/red gözlendi (yetki değişikliği **teyit edilmedi**; tekrar/retry **yok**).',
    'Race-condition (eşzamanlılık) testi, tüketilebilir bir kaynağı gerçekten değiştirme riski taşıdığından **otomatik çalıştırılmadı** (aşağıda not).',
  ],
  confidenceNote: 'Mass-assignment göstergesi yalnızca ilk yanıttan çıkarılmıştır (düşük güven). Race-condition için güvenli/test edilebilir bir uç nokta ile manuel doğrulama önerilir.',
  fixTitle: 'Race / Mass-Assignment',
  fixFound: [
    'Sunucu tarafında **allowlist** ile yalnızca izin verilen alanları bağlayın (mass-assignment/over-posting’i engelleyin); `isAdmin/role` gibi alanları asla istemciden almayın.',
    'Kritik işlemlerde (kupon/stok/bakiye) **atomik** işlemler + kilit/idempotency anahtarı kullanarak race-condition’ı engelleyin.',
  ],
  fixClean: [
    'Model bağlamada alan allowlist’i (mass-assignment koruması) uygulayın; kritik işlemlerde atomik/idempotent tasarım kullanın (proaktif).',
  ],
  cleanGenel: 'Uygun (tamamlama/ödeme dışı) bir kayıt/profil formu bulunamadı veya mass-assignment probu kabul edilmedi.',
};

export async function generateSsrfVerifyReport(host: string) { return buildActiveCheckReport(await collectSsrfEvidence(host), SSRF_CFG); }
export async function generateRceVerifyReport(host: string) { return buildActiveCheckReport(await collectRceEvidence(host), RCE_CFG); }
export async function generateFileUploadVerifyReport(host: string) { return buildActiveCheckReport(await collectFileUploadEvidence(host), UPLOAD_CFG); }
export async function generateBusinessLogicVerifyReport(host: string) { return buildActiveCheckReport(await collectBusinessLogicEvidence(host), BUSINESS_CFG); }
export async function generateRaceMassAssignVerifyReport(host: string) { return buildActiveCheckReport(await collectRaceMassAssignEvidence(host), RACE_CFG); }
// Saf kurucu testler icin (sentetik ActiveCheckEvidence ile):
export const _cfg = { SSRF_CFG, RCE_CFG, UPLOAD_CFG, BUSINESS_CFG, RACE_CFG };
export { buildActiveCheckReport };
