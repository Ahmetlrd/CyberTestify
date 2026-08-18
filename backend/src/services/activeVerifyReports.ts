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
  type ActiveCheckEvidence, discoverSurface, spaHint, discoveryMethodNote,
} from './activeVerifyEvidence.js';
import { collectLoginBypassEvidence } from './authExtraChecks.js';
import { collectActiveIndicatorsEvidence } from './activeIndicators.js';
import { resolveOrigin } from './surfaceEvidence.js';
import { unscannableReport } from './unscannable.js';

export const RISK_WORD = { low: 'Düşük', medium: 'Orta', 'medium-high': 'Orta-Yüksek', high: 'Yüksek' } as const;
export type Level = 'low' | 'medium' | 'medium-high' | 'high';
export function levelRank(l: Level): number { return l === 'high' ? 3 : l === 'medium-high' ? 2 : l === 'medium' ? 1 : 0; }

function assemble(level: Level, summaryBullets: string[], genelSentence: string, sections: string, unscannable = false): string {
  return (
    `## YÖNETİCİ ÖZETİ\n\n${summaryBullets.join('\n')}\n\n` +
    `## GENEL DEĞERLENDİRME\n\n**Risk Seviyesi: ${unscannable ? 'İncelenemedi' : RISK_WORD[level]}**\n\n${genelSentence}\n\n` +
    `${sections}`
  );
}

// (DÜRÜSTLIK — tekil aktif-doğrulama paketleri) Hedef erişilebilir ama test edilebilir bir giriş
// noktası (parametre/form/ID) yoksa: sonuç "Düşük/Temiz" DEĞİL, nötr "İncelenemedi"dir. İlk özet
// maddesini de İncelenemedi'ye çevirir ki rozet (assessBasit) + Master aynı işareti okusun.
function noTestableSurfaceBullet(what: string): string {
  return `- **Genel risk seviyesi: İncelenemedi** — hedefe ulaşıldı ancak ${what}; gerçek doğrulama probu çalıştırılamadı. Bu sonuç sitenin **güvenli olduğu anlamına GELMEZ** — yalnızca test edilebilir bir yüzey bulunamadığını gösterir.`;
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
  // (Faz 5) BANT = en yüksek tekil bulgu şiddeti; aşmaz (medium→'medium', low→'low').
  if (ev.findings.some((f) => f.severity === 'high')) return 'high';
  if (ev.findings.some((f) => f.severity === 'medium')) return 'medium';
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
  const noSurface = level === 'low' && !ev.inputsFound;
  const sqli = ev.findings.filter((f) => f.type === 'SQLi');
  const xss = ev.findings.filter((f) => f.type === 'XSS');
  // (İŞ B) Ayrıntılı-hata-sayfası bilgi ifşası (CWE-209) — enjeksiyon DEĞİL, AYRI bir gerçek bulgu.
  // Enjeksiyon güvenini YÜKSELTMEZ; yalnız rapor seviyesini en az Orta yapar ki rozet=master tutarlı olsun.
  const hasVerbose = !!ev.verboseError && !noSurface;
  const reportLevel: Level = levelRank(level) >= levelRank('medium') ? level : hasVerbose ? 'medium' : level;

  const bullets = [
    noSurface
      ? noTestableSurfaceBullet('taranan sayfalarda **test edilebilir bir GET parametresi veya form alanı saptanmadı**')
      : level === 'low' && hasVerbose
      ? `- **Genel risk seviyesi: Orta** — test edilen giriş noktalarında **doğrudan enjeksiyon kanıtı bulunamadı**; ancak hedef, hatalı girdide **ayrıntılı hata sayfası** döndürerek framework sürümü/sunucu dosya yolu ifşa ediyor (bilgi sızıntısı — aşağıda).`
      : `- **Genel risk seviyesi: ${RISK_WORD[level]}** — ${level === 'high' ? 'aktif doğrulama ile enjeksiyon zafiyeti KANITLANDI.' : level === 'medium-high' || level === 'medium' ? 'olası bir enjeksiyon göstergesi bulundu (bağlama göre doğrulama önerilir).' : 'test edilen giriş noktalarında enjeksiyon kanıtı bulunamadı.'}`,
    `- Taranan sayfa/uç nokta: **${ev.pagesScanned}** · Test edilen giriş noktası: **${ev.inputsFound}** · Gönderilen payload: **${ev.payloadsSent}** (toplam ${ev.probesSent} istek) · SQLi bulgusu: ${sqli.length} · XSS bulgusu: ${xss.length}.`,
    '- **Önerilen ilk adım:** ' + (ev.findings.length ? 'Kanıtlanan giriş noktalarını parametreli sorgu / çıktı kodlaması ile kapatın; hazır adımlar "AI Çözüm Önerileri" bölümünde.' : 'Girdi doğrulama ve çıktı kodlamasını standart hale getirin; hazır sertleştirme adımları "AI Çözüm Önerileri" bölümünde.'),
  ];

  const genel = level === 'high'
    ? 'Aktif-hafif doğrulama ile en az bir giriş noktasında enjeksiyon zafiyeti kanıtlandı; öncelikli olarak giderilmesi önerilir.'
    : level === 'medium-high' || level === 'medium'
      ? 'Olası bir enjeksiyon göstergesi bulundu; bağlama göre manuel doğrulama ve giderme önerilir.'
      : ev.inputsFound
        ? `${ev.pagesScanned} sayfa/uç nokta tarandı; ${ev.inputsFound} giriş noktasında toplam **${ev.payloadsSent}** zararsız SQLi/XSS payload'ı denendi ve hiçbiri enjeksiyon kanıtı üretmedi. Bu, test edilen giriş noktalarının şu an için dayanıklı göründüğünü gösterir (tüm giriş noktalarının kanıtı değildir).`
        : `${ev.pagesScanned} sayfa/uç nokta tarandı; test edilebilir bir GET parametresi veya form alanı saptanmadı (enjeksiyon doğrulaması için giriş noktası yok).`;

  // Ne kontrol edildi — seffaflik (bulgu olsa da olmasa da)
  const method = [
    '## NE KONTROL EDİLDİ\n',
    'Taranan sayfalardan (ana sayfa + iç linkler + iyi-bilinen yollar) keşfedilen giriş noktaları (URL query parametreleri + form alanları) üzerinde, giriş noktası başına zararsız doğrulama probları:',
    '',
    '- **SQLi (hata-tabanlı):** Tek tırnak (`\'`) enjekte edilip yanıtta veritabanı hata imzası (MySQL/PostgreSQL/Oracle/MSSQL/SQLite) arandı.',
    `- **SQLi (zaman-tabanlı):** Hata görülmeyen noktalarda tek bir zararsız gecikme probu (SLEEP) ile yanıt süresi baseline’a göre ölçüldü (blind SQLi göstergesi).`,
    `- **SQLi (boolean-tabanlı):** Sayısal/ID-benzeri noktalarda TRUE (\`1=1\`) ve FALSE (\`1=2\`) koşullu iki istek gönderilip yanıtları (status + içerik uzunluğu) karşılaştırıldı; TRUE tekrarında tutarlı ve FALSE'tan KALICI farklıysa boolean-based SQLi göstergesidir (yanlış-pozitife karşı stabilite doğrulaması yapılır).`,
    '- **XSS (yansıyan):** Benzersiz, zararsız bir işaret dizesi enjekte edilip yanıt HTML’inde **kaçırılmadan (unencoded)** yansıyıp yansımadığı kontrol edildi (JS çalıştırılmadı; stored XSS denenmedi).',
    '',
  ].join('\n');

  // (10/10 Bölüm 1.3 + 3) Güven + GEREKÇE ayrı kolonda: yansıma (ham/kodlanmış) ile hata-tabanlı/zaman-tabanlı
  // AYRI güven kategorileri olarak gösterilir — "dolaylı gösterge" ile "doğrudan kanıt" karıştırılmaz.
  const injConf = (f: InjEvidence['findings'][number]): string =>
    f.technique === 'error-based' ? 'Yüksek — yanıtta veritabanı hata imzası (doğrudan kanıt)'
    : f.technique === 'boolean-based' ? 'Yüksek — TRUE/FALSE koşul yanıtları tutarlı ve KALICI biçimde farklı (girdi sorgu mantığını değiştiriyor — doğrudan kanıt)'
    : f.technique === 'time-based' ? 'Orta — zaman-tabanlı/dolaylı; OOB doğrulama altyapısı yok'
    : f.confidence === 'high' ? 'Orta-Yüksek — işaret dizesi HAM (kaçırılmamış) yansıdı; güçlü XSS göstergesi (JS yürütülmediğinden istismar kanıtlanmadı)'
    : 'Düşük — yansıdı ancak kodlanmış/kaçırılmış; bağlama bağlı zayıf gösterge';
  const techLabel = (t: InjEvidence['findings'][number]['technique']): string =>
    t === 'error-based' ? 'hata-tabanlı' : t === 'time-based' ? 'zaman-tabanlı' : t === 'boolean-based' ? 'boolean-tabanlı' : 'yansıma';
  const table = ev.findings.length
    ? '## BULGULAR\n\n| Giriş Noktası | Tür | Teknik | Kanıt | Güven (gerekçe) | Ciddiyet |\n|---------------|-----|--------|-------|-----------------|----------|\n' +
      ev.findings.map((f) => `| ${f.inputPoint} | ${f.type} | ${techLabel(f.technique)} | ${f.evidence.replace(/\|/g, '\\|')} | ${injConf(f)} | ${RISK_WORD[f.severity]} |`).join('\n') + '\n\n'
    : '## BULGULAR\n\nTest edilen giriş noktalarında enjeksiyon kanıtı bulunamadı.\n\n';

  // (İŞ B) GERÇEK yanıt gövdesinden saptanan ayrıntılı-hata-sayfası bilgi ifşası -> ŞİDDET-kolonlu tablo
  // (parseFindings -> master/dağılım/detay kartı). Redakte + kısaltılmış kanıt; UYDURMA YOK.
  const verboseSection = hasVerbose
    ? `## TESPİT EDİLEN RİSKLER\n\n| Bulgu | Şiddet | Açıklama |\n|-------|--------|----------|\n| Ayrıntılı hata sayfası bilgi ifşası | Orta | Doğrulama probu sırasında **${ev.verboseError!.endpoint}** ucundan dönen hata yanıtının GÖVDESİNDE ayrıntılı hata-sayfası imzası saptandı (framework sürümü / sunucu dosya yolu / stack trace). Kanıt (kısaltılmış): \`${ev.verboseError!.sig.replace(/\|/g, '\\|').replace(/`/g, "'")}\` Üretimde ayrıntılı hata sayfaları kapatılmalıdır (CWE-209). |\n\n`
    : '';
  const notes = ev.notes.length ? ev.notes.map((n) => `> ${n}`).join('\n') + '\n\n' : '';
  const findings = assemble(reportLevel, bullets, genel, `${method}${table}${verboseSection}${notes}${SCOPE_NOTE_ACTIVE}\n`, noSurface);

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
  // (Faz 5) BANT = en yüksek tekil bulgu şiddeti; aşmaz. medium (komşu-ID erişim) → 'medium'; low → 'low'.
  if (ev.findings.some((f) => f.severity === 'high')) return 'high';
  if (ev.findings.some((f) => f.severity === 'medium')) return 'medium';
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
  const noSurface = level === 'low' && !ev.candidates;

  const bullets = [
    noSurface
      ? noTestableSurfaceBullet('ana sayfada **tahmin edilebilir/sayısal ID içeren test edilebilir bir uç nokta bulunamadı**')
      : `- **Genel risk seviyesi: ${RISK_WORD[level]}** — ${(level === 'high' || level === 'medium-high' || level === 'medium') ? 'kimlik doğrulaması olmadan komşu ID ile farklı kaynağa erişim göstergesi bulundu.' : ev.findings.length ? 'zayıf bir numaralandırma göstergesi bulundu (manuel doğrulama gerekli).' : 'test edilen ID’li uç noktalarda yetkisiz erişim göstergesi bulunmadı.'}`,
    `- Taranan sayfa/uç nokta: **${ev.pagesScanned}** · Aday ID uç noktası: **${ev.candidates}** · Gönderilen probe: **${ev.probesSent}** · Bulgu: ${ev.findings.length}.`,
    '- **Önerilen ilk adım:** ' + (ev.findings.length ? 'Nesne-düzeyi yetkilendirme kontrolü ekleyin; hazır adımlar "AI Çözüm Önerileri" bölümünde.' : 'Nesne-düzeyi yetkilendirmeyi standart hale getirin; hazır adımlar "AI Çözüm Önerileri" bölümünde.'),
  ];

  const genel = (level === 'high' || level === 'medium-high' || level === 'medium')
    ? 'Kimlik doğrulaması olmadan, tahmin edilebilir bir ID’yi komşu değere değiştirerek farklı bir kaynağa erişilebildiği gözlemlendi; nesne-düzeyi yetkilendirme kontrolü önerilir.'
    : ev.findings.length
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
    'Taranan sayfalardan keşfedilen, tahmin edilebilir/sayısal ID içeren uç noktalar (ör. `?id=123`, `/user/45`) üzerinde:',
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
  const findings = assemble(level, bullets, genel, `${method}${table}${scopeLimit}${notes}${SCOPE_NOTE_ACTIVE}\n`, noSurface);

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
// Her uye: collector'i calistir (sayac icin) + section'i kur. Tumu gercek (7/7).
type MemberRun = { rep: { findings: string; fixText: string } | null; pages: number; inputs: number; probes: number; fc: number; formsTested?: number; formsSkipped?: Array<{ action: string; reason: string }> };
type ActiveMember = { key: string; title: string; conf: 'Yüksek' | 'Orta' | 'Düşük'; run: (host: string) => Promise<MemberRun> };
const ACTIVE_INDICATORS_CFG: CheckCfg = {
  title: 'Güvenli Aktif Göstergeler (LFI/Redirect/HPP/SSTI)',
  whatChecked: [
    'Yalnız hedefte GERÇEKTEN gözlenen GET parametreleri üzerinde, read-only güvenli göstergeler (veri yazma/yükleme/komut YOK).',
    '**A1 LFI / path traversal:** dosya/yol parametrelerinde kademeli, zararsız prob — yalnız bilinen dosya İMZASI (ör. `root:x:0:0:`) eşleşirse bulgu; **içerik REDAKTE** (dosya çekilmez).',
    '**A2 Open redirect:** yönlendirme parametrelerine zararsız harici kanarya; Location/meta-refresh yansıması gözlenir (**redirect TAKİP EDİLMEZ**).',
    '**A3 HTTP Parameter Pollution:** tekrarlı parametrenin işleniş farkı (salt gözlem; veri gönderilmez).',
    '**A5 SSTI:** yansıyan parametrede yalnız aritmetik ifade (`{{1234*3}}`→`3702`) — kod/komut YOK.',
    '**A4 boolean-SQLi** ve **A6 dosya yükleme** ilgili bölümlerde (Enjeksiyon / Dosya Yükleme Doğrulama) değerlendirilir — çift bulgu üretilmez (çapraz-referans).',
  ],
  confidenceNote: 'Hepsi "gösterge, doğrulama gerekir"; yalnız gözlemlenen parametrelerde. LFI-imza Yüksek; open-redirect/SSTI Orta; HPP Düşük. Modern SPA/API sitelerde çoğu zaman "kapsam dışı"/az bulgu çıkması BEKLENEN ve doğru sonuçtur.',
  fixTitle: 'Güvenli Aktif Göstergeler',
  fixFound: [
    'LFI: kullanıcı girdisini dosya yoluna koymayın; allowlist + `basename` + kök-dizin hapsi (realpath/chroot).',
    'Open redirect: yönlendirme hedeflerini sunucuda allowlist ile sınırlayın; harici mutlak URL\'lere yönlendirmeyin.',
    'HPP: parametreleri tek-değere normalize edin; katmanlar arası tutarlı ayrıştırma. SSTI: girdiyi şablona interpolasyonla koymayın (logic-less motor + kaçış + sandbox).',
  ],
  fixClean: ['Girdi dosya-yolu/şablon/yönlendirme hedefine doğrudan konmuyor; parametreler normalize (proaktif).'],
  cleanGenel: 'Gözlemlenen parametrelerde LFI imzası, açık yönlendirme, HTTP parametre kirliliği veya şablon-enjeksiyonu (SSTI) göstergesi bulunamadı.',
};

const ACTIVE_BUNDLE_MEMBERS: ActiveMember[] = [
  { key: 'injection_verify', title: 'Enjeksiyon (SQLi/XSS) Doğrulama', conf: 'Yüksek', run: async (h) => { const ev = await collectInjectionEvidence(h); return { rep: buildInjectionReport(ev), pages: ev.pagesScanned, inputs: ev.inputsFound, probes: ev.probesSent, fc: ev.findings.length, formsTested: ev.formsTested, formsSkipped: ev.formsSkipped }; } },
  { key: 'idor_verify', title: 'Yetkisiz Erişim (IDOR) Doğrulama', conf: 'Orta', run: async (h) => { const ev = await collectIdorEvidence(h); return { rep: buildIdorReport(ev), pages: ev.pagesScanned, inputs: ev.candidates, probes: ev.probesSent, fc: ev.findings.length }; } },
  { key: 'ssrf_verify', title: 'SSRF Doğrulama', conf: 'Orta', run: async (h) => { const ev = await collectSsrfEvidence(h); return { rep: buildActiveCheckReport(ev, SSRF_CFG), pages: ev.pagesScanned, inputs: ev.inputsFound, probes: ev.probesSent, fc: ev.findings.length }; } },
  { key: 'file_upload_verify', title: 'Dosya Yükleme Doğrulama', conf: 'Düşük', run: async (h) => { const ev = await collectFileUploadEvidence(h); return { rep: buildActiveCheckReport(ev, UPLOAD_CFG), pages: ev.pagesScanned, inputs: ev.inputsFound, probes: ev.probesSent, fc: ev.findings.length }; } },
  { key: 'business_logic_verify', title: 'İş Mantığı Doğrulama', conf: 'Düşük', run: async (h) => { const ev = await collectBusinessLogicEvidence(h); return { rep: buildActiveCheckReport(ev, BUSINESS_CFG), pages: ev.pagesScanned, inputs: ev.inputsFound, probes: ev.probesSent, fc: ev.findings.length }; } },
  { key: 'race_massassign_verify', title: 'Race / Mass-Assignment Doğrulama', conf: 'Düşük', run: async (h) => { const ev = await collectRaceMassAssignEvidence(h); return { rep: buildActiveCheckReport(ev, RACE_CFG), pages: ev.pagesScanned, inputs: ev.inputsFound, probes: ev.probesSent, fc: ev.findings.length }; } },
  { key: 'rce_verify', title: 'RCE / Komut Enjeksiyonu Doğrulama', conf: 'Orta', run: async (h) => { const ev = await collectRceEvidence(h); return { rep: buildActiveCheckReport(ev, RCE_CFG), pages: ev.pagesScanned, inputs: ev.inputsFound, probes: ev.probesSent, fc: ev.findings.length }; } },
  // (İŞ 3) Giriş baypası (SQLi göstergesi) — login POST'a kontrol vs SQLi karşılaştırması (gözlemsel).
  { key: 'active_indicators', title: 'Güvenli Aktif Göstergeler (LFI/Redirect/HPP/SSTI)', conf: 'Orta', run: async (h) => { const ev = await collectActiveIndicatorsEvidence(h); return { rep: buildActiveCheckReport(ev, ACTIVE_INDICATORS_CFG), pages: ev.pagesScanned, inputs: ev.inputsFound, probes: ev.probesSent, fc: ev.findings.length }; } },
  { key: 'login_bypass', title: 'Giriş Baypası (SQLi Göstergesi)', conf: 'Yüksek', run: async (h) => { const ev = await collectLoginBypassEvidence(h); return { rep: buildActiveCheckReport(ev, LOGIN_BYPASS_CFG), pages: ev.pagesScanned, inputs: ev.inputsFound, probes: ev.probesSent, fc: ev.findings.length }; } },
];

export function extractLevel(findings: string): Level {
  const m = findings.match(/Risk Seviyesi:\s*(Orta[-\s]?Y[uü]ksek|Y[uü]ksek|Orta|D[uü][sş][uü]k)/i);
  if (!m) return 'low';
  const w = m[1].toLocaleLowerCase('tr');
  if (/orta[-\s]?y[uü]ksek/.test(w)) return 'medium-high';
  if (/y[uü]ksek/.test(w)) return 'high';
  if (/orta/.test(w)) return 'medium';
  return 'low';
}
export function headlineOf(findings: string): string {
  const m = findings.match(/Genel risk seviyesi:\s*[^\n]+?\s[—–-]\s([^\n]+)/i);
  return m ? m[1].trim().replace(/\*\*/g, '') : '';
}
// YÖNETİCİ ÖZETİ + GENEL DEĞERLENDİRME'yi cikar, detay bolumlerini dondur (## -> ### indir).
export function detailOnly(findings: string): string {
  const parts = findings.split(/(?=^## )/m);
  return parts.slice(2).join('').replace(/^## /gm, '### ').trim();
}

export async function generateBundleActiveVerifyReport(host: string): Promise<{ findings: string; fixText: string } | null> {
  // Protokolü ÖNCE çöz: cache'i ısıtır (üye collector'lar cachedOriginUrl ile http-only'de de tarar)
  // + http-only ise https_missing bulgusu üretilir.
  const o = await resolveOrigin(host);
  const httpOnly = o.reachable && !o.httpsWorks;
  // (DÜRÜSTLÜK) Hedefe HİÇ ulaşılamadı -> "İncelenemedi" (ASLA null->Düşük fallback). Headless keşfi de atla.
  if (!o.reachable) return unscannableReport(host, 'aktif doğrulama kontrolleri');
  const runs = await Promise.all(ACTIVE_BUNDLE_MEMBERS.map((m) => m.run(host).catch(() => null)));
  // Hiçbir üye veri toplayamadıysa (hedefe ulaşılamadı) -> "İncelenemedi" (null->Düşük DEĞİL).
  if (runs.every((r) => !r || !r.rep)) return unscannableReport(host, 'aktif doğrulama kontrolleri');
  const surf = await discoverSurface(host); // cache'ten — benzersiz sayfa + SPA bilgisi

  const levels: Array<Level | null> = runs.map((r) => (r?.rep ? extractLevel(r.rep.findings) : null));
  const ranked = levels.map((lv, i) => ({ lv, i })).filter((x): x is { lv: Level; i: number } => x.lv !== null).sort((a, b) => levelRank(b.lv) - levelRank(a.lv));
  const worst: Level = ranked.length ? ranked[0].lv : 'low';
  const worstTitle = ranked.length ? ACTIVE_BUNDLE_MEMBERS[ranked[0].i].title : '';
  const worstHl = ranked.length && runs[ranked[0].i]?.rep ? headlineOf(runs[ranked[0].i]!.rep!.findings) : '';

  // --- Gercek sayaclar (uydurma YOK) ---
  const pagesScanned = surf.pagesScanned;                              // BENZERSIZ icerikli sayfa
  const totalInputs = runs.reduce((s, r) => s + (r?.inputs ?? 0), 0);
  const totalProbes = runs.reduce((s, r) => s + (r?.probes ?? 0), 0);  // baseline + gercek prob
  const confirmedHigh = runs.filter((r, i) => r?.rep && levels[i] === 'high').length;
  const dataOk = runs.filter((r) => r?.rep).length;
  const noInputs = totalInputs === 0;
  // (DÜRÜSTLÜK — "ulaşıldı ama test edilemedi" alt-durumu) Hedef ERİŞİLEBİLİR olsa da
  // kontrollerin çoğu ya veri toplayamadı ya da test edilebilir giriş noktası bulamadıysa,
  // bu "test edildi, temiz çıktı" DEĞİLDİR. Rozet/Master'ı yeşil-Düşük'e DÜŞÜRME; nötr "İncelenemedi".
  // (worst==='low' koşulu: gerçek bir bulgu çıktıysa onu bastırmayız — bulguyu raporlarız.)
  const notTestable = runs.filter((r) => !r || !r.rep || (r.inputs ?? 0) === 0).length;
  const insufficientCoverage = notTestable / ACTIVE_BUNDLE_MEMBERS.length >= 0.7;
  // http-only'de enjekte edilen https_missing GERÇEK bir Yüksek bulgudur -> ASLA "İncelenemedi" deme (guard).
  const noRealTest = !httpOnly && worst === 'low' && (noInputs || insufficientCoverage);
  // Rozet = master'daki en yüksek severity. http-only Yüksek https_missing üretir -> verdict en az Yüksek olmalı
  // (yoksa rozet "Düşük" iken master "Yüksek" çelişir). noRealTest ise nötr "İncelenemedi".
  const verdictLevel: Level = httpOnly && levelRank(worst) < levelRank('high') ? 'high' : worst;
  const verdictWord = noRealTest ? 'İncelenemedi' : RISK_WORD[verdictLevel];

  // --- ÜST ÖZET KUTUSU (ilk sayfa; gerçek N/M/P; input yoksa "gerçek prob yok" netliği) ---
  const box =
    `> ### Değerlendirme Özeti\n` +
    `> **${ACTIVE_BUNDLE_MEMBERS.length} aktif güvenlik kontrol kategorisinin tamamı değerlendirildi.** ` +
    (noInputs
      ? `**${pagesScanned}** benzersiz sayfa/uç nokta tarandı; **test edilebilir giriş noktası (parametre/form/ID) bulunamadı** — bu nedenle gerçek doğrulama probu gönderilmedi (yalnızca ${totalProbes} erişilebilirlik/baseline isteği). Bu **zafiyet olmadığının kanıtı değildir**; kapsam sınırına bakınız.` + spaHint(surf)
      : `**${pagesScanned}** benzersiz sayfa/uç nokta tarandı, **${totalInputs}** giriş noktası test edildi, toplam **${totalProbes}** istek gönderildi. ` +
        (confirmedHigh > 0
          ? `**${confirmedHigh}** kontrolde yüksek/kritik seviyeli zafiyet göstergesi bulundu (aşağıda detaylı).`
          : `Doğrulanmış kritik/yüksek seviyeli bir zafiyet **tespit edilmedi**.`)) +
    `\n>\n> _Keşif yöntemi: ${discoveryMethodNote(surf)}_`;

  // --- KONTROL ÖZETİ TABLOSU (durum + güven) ---
  // Güven: SADECE gerçekten test çalıştıysa (input>0) seviye gösterilir; aksi halde NÖTR "Kapsam dışı"
  // (PDF renklendirme yalnız risk kelimelerini boyar; "Kapsam dışı" nötr kalır — yanıltıcı kırmızı yok).
  const statusOf = (r: MemberRun | null, lv: Level | null): string => {
    if (!r || !r.rep) return 'Veri toplanamadı';
    if (r.fc > 0 && lv === 'high') return '⚠ Zafiyet göstergesi';
    if (r.fc > 0) return '⚠ Sınırlı gösterge';
    if (r.inputs === 0) return 'Giriş noktası yok (Kapsam dışı)';
    return '✓ Zafiyet kanıtı yok';
  };
  // (R6 GÜVEN/KAPSAM TUTARLILIĞI) Kontrol GERÇEK bir bulgu ürettiyse (fc>0) Güven "Kapsam dışı"
  // OLAMAZ — statusOf zaten "⚠ gösterge" der; ikisi çelişmesin. inputs=0 ama gözlemsel bulgu (fc>0)
  // olan İş Mantığı/Race gibi kontroller için de gerçek güven seviyesi gösterilir.
  const confCell = (r: MemberRun | null, conf: string): string => (r && r.rep && (r.inputs > 0 || r.fc > 0) ? conf : 'Kapsam dışı');
  const tableRows = ACTIVE_BUNDLE_MEMBERS.map((m, i) => `| ${m.title} | ${statusOf(runs[i], levels[i])} | ${confCell(runs[i], m.conf)} |`).join('\n');
  const controlTable = `## KONTROL ÖZETİ\n\n| Kontrol | Sonuç | Güven |\n|---------|-------|-------|\n${tableRows}\n\n> Güven yalnızca gerçekten test çalıştırılan (giriş noktası bulunan) kontroller için gösterilir; giriş noktası bulunamayan kontroller **Kapsam dışı**dır. Test edilenlerde: SSRF/RCE dolaylı (zaman-tabanlı, OOB yok) → Orta; gözlemsel (Dosya Yükleme/İş Mantığı/Race) → Düşük; Enjeksiyon hata/yansıma-tabanlı → Yüksek.\n`;

  // --- YÖNETİCİ ÖZETİ ---
  const summary: string[] = [];
  summary.push(
    noRealTest
      ? `- **Genel risk seviyesi: İncelenemedi** — hedefe ulaşıldı ancak ${noInputs ? '**test edilebilir bir giriş noktası (parametre/form/ID) bulunamadı**' : `kontrollerin çoğu (${notTestable}/${ACTIVE_BUNDLE_MEMBERS.length}) veri toplayamadı veya test edilebilir yüzey bulamadı`}; gerçek doğrulama probu çalıştırılamadı. Bu sonuç sitenin **güvenli olduğu anlamına GELMEZ** — yalnızca bu paketin bu hedefte test edilebilir bir yüzey bulamadığını gösterir.`
      : httpOnly && worst === 'low'
      ? `- **Genel risk seviyesi: Yüksek** — hedef HTTPS desteklemiyor (şifresiz iletişim); bu tek başına yüksek riskli bir bulgudur. Aktif kontroller http:// üzerinden yürütüldü ve ek doğrulanmış kritik/yüksek zafiyet öne çıkmadı.`
      : verdictLevel === 'low'
      ? `- **Genel risk seviyesi: Düşük** — ${ACTIVE_BUNDLE_MEMBERS.length} kontrol kategorisinin tamamı değerlendirildi; doğrulanmış kritik/yüksek seviyeli bir zafiyet öne çıkmadı.`
      : `- **Genel risk seviyesi: ${RISK_WORD[verdictLevel]}** — en yüksek risk **${worstTitle || 'HTTPS eksikliği'}** alanında${worstHl ? ` (${worstHl})` : ''}.`,
  );
  // DÜRÜSTLÜK (dinamik — gerçek en yüksek ciddiyetli kontrolden türer): bu paketin kimlik-doğrulamasız
  // kapsam sınırını AÇIKÇA belirt + en güçlü sonucu (bulgu varsa) veya "zafiyet bulunamadı"yı bildir.
  const anyFinding = runs.some((r) => r?.fc && r.fc > 0);
  const strongest = anyFinding && worstTitle
    ? `Bu taramada en güçlü sonuç **${worstTitle}** alanında tespit edilmiştir.`
    : 'Bu taramada doğrulanmış bir zafiyet tespit edilmemiştir.';
  summary.push(
    `- **Kapsam dürüstlüğü:** Bu paket, kimlik doğrulaması **gerektirmeyen dış yüzeye** odaklanır — herkese açık uç noktalar (açık formlar/API'lar, arama, login/kayıt akışının kendisi). IDOR / İş Mantığı / Race-Mass-Assignment kontrolleri **yalnızca login-öncesi erişilebilir yüzeyde** (ör. genel API'lar, herkese açık id-tabanlı uç noktalar) çalışır; bu nedenle bu kategorilerde bazı hedeflerde **sınırlı veya "İncelenemedi"** sonuç normal ve beklenendir (siteye özgü yüzey azlığından; motor eksikliğinden değil). Login-**sonrası** oturum içi derin yetkilendirme/iş mantığı zafiyetleri kapsam dışıdır, **Tam Kapsamlı Pentest**'te ele alınır. ${strongest}`,
  );
  // (BÖLÜM B) API yüzeyi şeffaflığı: spec bulundu mu + keşfedilen ama kimlik-doğrulama-kilitli uç sayısı.
  const apiSpecN = surf.apiSpecFound ? surf.apiSpecPaths ?? 0 : 0;
  const apiGatedN = surf.apiAuthGated ?? 0;
  if (apiSpecN > 0 || apiGatedN > 0) {
    const parts: string[] = [];
    if (apiSpecN > 0) parts.push(`OpenAPI/Swagger şeması bulundu ve **${apiSpecN}** uç noktası keşif kapsamına alındı`);
    if (apiGatedN > 0) parts.push(`**${apiGatedN}** API uç noktası keşfedildi ancak **kimlik doğrulama gerektiriyor** (401/403) — kimlik-doğrulamalı derin test bu paketin kapsamı dışında olduğundan probe edilmedi (Tam Kapsamlı Pentest önerilir)`);
    summary.push(`- **API saldırı yüzeyi:** ${parts.join('; ')}.`);
  }
  ACTIVE_BUNDLE_MEMBERS.forEach((m, i) => {
    const r = runs[i]; const lv = levels[i];
    if (!r || !r.rep || !lv) { summary.push(`- **${m.title}:** veri toplanamadı (hedefe ulaşılamadı).`); return; }
    const hl = headlineOf(r.rep.findings);
    summary.push(`- **${m.title}:** ${RISK_WORD[lv]}${hl ? ` — ${hl}` : ''}`);
  });
  summary.push(
    noInputs
      ? `- **Şeffaflık:** ${dataOk}/${ACTIVE_BUNDLE_MEMBERS.length} kontrol çalıştı; **${pagesScanned}** benzersiz sayfa tarandı ancak **test edilebilir giriş noktası bulunamadı** — gerçek doğrulama probu gönderilmedi (yalnızca ${totalProbes} baseline erişilebilirlik isteği). Bu, zafiyet olmadığının kanıtı değildir.` + spaHint(surf)
      : `- **Şeffaflık:** ${dataOk}/${ACTIVE_BUNDLE_MEMBERS.length} kontrol veri toplayabildi; **${pagesScanned}** benzersiz sayfa, **${totalInputs}** giriş noktası${surf.method === 'headless' ? ' (JS render sırasında gözlemlenen API uçları dâhil)' : ''}, **${totalProbes}** istek.${surf.method === 'headless' && surf.apiWrites.length ? ` Ayrıca **${surf.apiWrites.length}** durum-değiştiren API ucu (ör. login/sepet/sipariş) gözlemlendi ancak güvenlik gereği **probe edilmedi**.` : ''} SSRF/RCE tespitleri OOB altyapısı olmadan zaman-tabanlı/dolaylı (orta güven); gözlemsel kontroller (Dosya Yükleme/İş Mantığı/Race) kesin doğrulama için manuel test gerektirir.`,
  );
  summary.push('- **Önerilen ilk adım:** Çalıştırılan kontrollerdeki bulguları giderin; hazır adımlar "AI Çözüm Önerileri" bölümünde.');

  const genel =
    (noRealTest
      ? `${ACTIVE_BUNDLE_MEMBERS.length} aktif doğrulama kontrol kategorisi denendi ancak bu hedefte **test edilebilir bir yüzey bulunamadığından** gerçek doğrulama probu çalıştırılamadı; sonuç **değerlendirilemedi** ("güvenli/temiz" anlamına gelmez).`
      : worst === 'low'
      ? `${ACTIVE_BUNDLE_MEMBERS.length} aktif doğrulama kontrol kategorisinin tamamı değerlendirildi; doğrulanmış kritik/yüksek seviyeli bir zafiyet öne çıkmadı.`
      : `Çalıştırılan kontrollerde en yüksek risk **${worstTitle}** alanında${worstHl ? ` (${worstHl})` : ''} tespit edildi; öncelikli olarak giderilmesi/doğrulanması önerilir.`) +
    (noInputs
      ? ` ${pagesScanned} benzersiz sayfa/uç nokta tarandı; test edilebilir bir giriş noktası (parametre/form/ID) bulunamadığından gerçek doğrulama probu gönderilmedi (yalnızca baseline istekleri). Aşağıda her kontrol ayrı ayrı raporlanmıştır.`
      : ` ${pagesScanned} benzersiz sayfa/uç nokta tarandı, ${totalInputs} giriş noktasında toplam ${totalProbes} istek gönderildi. SSRF/RCE zaman-tabanlı/dolaylıdır. Aşağıda her kontrol ayrı ayrı raporlanmıştır.`);

  const sections = ACTIVE_BUNDLE_MEMBERS.map((m, i) => {
    const r = runs[i];
    if (!r || !r.rep) return `## ${m.title}\n\n> Bu kontrol için veri toplanamadı (hedefe ulaşılamadı); diğer kontroller raporlanmıştır.\n`;
    return `## ${m.title}\n\n${detailOnly(r.rep.findings)}\n`;
  }).join('\n');

  // (DÜRÜSTLÜK) http-only: HTTPS eksikliği ŞİDDET-kolonlu tabloyla -> Master + Dağılıma girer.
  const httpsFindingSection = httpOnly
    ? `## TESPİT EDİLEN RİSKLER\n\n| Bulgu | Şiddet | Açıklama |\n|-------|--------|----------|\n| HTTPS desteklenmiyor (şifresiz iletişim) | Yüksek | Hedef HTTPS'e yanıt vermiyor; tüm trafik şifresiz (düz metin) taşınıyor — dinlenebilir/değiştirilebilir, oturum/şifre çalınabilir. Aktif kontroller http:// üzerinden yürütüldü. Çözüm: geçerli TLS sertifikası + HTTP→HTTPS yönlendirme + HSTS. |\n\n`
    : '';
  const httpsSummaryNote = httpOnly ? '\n- ⚠️ **HTTPS desteklenmiyor:** Hedef HTTPS (443) üzerinden yanıt vermedi; aktif doğrulama http:// üzerinden yürütüldü. Şifresiz iletişim başlı başına ciddi bir bulgudur.' : '';
  const genelHttps = httpOnly ? 'Bu hedef HTTPS üzerinden yanıt vermiyor; iletişim şifresiz (düz metin) taşınıyor — öncelikli olarak HTTPS’e geçilmelidir. ' : '';

  // (10/10 Bölüm 3 — POZİTİF GÜVENCE) Diğer 4 pakete AYNI üç-durum formatı, Aktif Doğrulama'ya özel:
  // her kontrol türü için "kaç giriş noktası denendi, kaçında kanıt bulunamadı". SADECE gerçek sayaçlardan.
  const assuranceRows = ACTIVE_BUNDLE_MEMBERS.map((m, i) => {
    const r = runs[i]; const lv = levels[i];
    let sonuc: string;
    if (!r || !r.rep) sonuc = '⚠️ İncelenemedi (veri toplanamadı — “temiz” DEĞİL)';
    else if (r.fc > 0 && lv === 'high') sonuc = `⚠️ Bulgu var (${r.fc} — zafiyet göstergesi; yukarıda)`;
    else if (r.fc > 0) sonuc = `⚠️ Bulgu var (${r.fc} — sınırlı/dolaylı gösterge; yukarıda)`;
    else if (r.inputs > 0) sonuc = `✅ Temiz (${r.inputs} giriş noktası denendi, kanıt bulunamadı)`;
    else sonuc = '⚠️ İncelenemedi (test edilebilir giriş noktası bulunamadı — “temiz” DEĞİL)';
    return `| ${m.title} | ${r ? r.inputs : '—'} | ${r ? r.probes : '—'} | ${sonuc} |`;
  }).join('\n');
  // (FORM-POST ŞEFFAFLIĞI) Kaç form gerçek POST ile test edildi, kaçı YASAK listesi gereği atlandı (neden).
  const injRun = runs[0]; // injection_verify = 0. index
  const formsTested = injRun?.formsTested ?? 0;
  const formsSkipped = injRun?.formsSkipped ?? [];
  const formLine =
    (formsTested > 0 || formsSkipped.length > 0)
      ? `\n**Form POST testi:** **${formsTested}** forma (login/arama/filtre vb.) gerçek POST payload’ı gönderildi. ` +
        (formsSkipped.length
          ? `**${formsSkipped.length}** form ise güvenlik gereği (kalıcı/geri-alınamaz yan etki riski) gerçek POST testinden **hariç tutuldu**: ${formsSkipped.map((f) => `\`${f.action}\` (${f.reason})`).join('; ')}. Bu formlar "kanıtla — istismar etme" ilkesi gereği hiç POST edilmez; kimlik-doğrulamalı/kapsam-sözleşmeli test **Tam Kapsamlı Pentest** kapsamındadır.`
          : `YASAK listesine (yorum/iletişim/kayıt/parola-sıfırlama/ödeme/abonelik) giren form saptanmadı.`)
      : '';
  const assuranceSection =
    `## POZİTİF GÜVENCE — DENENEN AKTİF DOĞRULAMA YÖNTEMLERİ\n\n` +
    `Bulgu çıkmayan kontroller de dâhil, ${ACTIVE_BUNDLE_MEMBERS.length} aktif kontrol kategorisinin her biri keşfedilen yüzeyde gerçekten çalıştırıldı (toplam **${totalProbes}** istek, **${pagesScanned}** benzersiz sayfa). Aşağıdaki tablo, "bulgu yok" sonuçlarını da — kaç giriş noktası denendi, kaçında kanıt bulunamadı — şeffaf gösterir:\n\n` +
    `| Kontrol | Denenen giriş noktası | Gönderilen istek | Sonuç |\n|---------|-----------------------|------------------|-------|\n${assuranceRows}\n${formLine}\n\n` +
    `> **Üç-durum ayrımı (dürüstlük):** ✅ *Temiz* = kontrol çalıştı, kanıt bulunamadı · ⚠️ *Bulgu var* = yukarıda detaylı · ⚠️ *İncelenemedi* = test edilebilir giriş noktası bulunamadı (güvenli anlamına GELMEZ).\n\n` +
    `### Bu paket NE değerlendirir, NE değerlendirmez\n\n` +
    `**EDER ("kanıtla — istismar etme" ilkesiyle; zararsız, veri-değiştirmeyen problar):** SQLi/XSS enjeksiyonu, yetkisiz erişim (IDOR), SSRF, dosya yükleme, iş mantığı, race/mass-assignment ve RCE/komut enjeksiyonu göstergeleri — kimlik doğrulaması **gerektirmeyen** yüzeyde, keşfedilen ${pagesScanned} sayfada.\n\n` +
    `**ETMEZ:** Veri değiştiren/silen istismar, ödeme tamamlama veya gerçek RCE çalıştırma **yapılmaz** (yalnızca gösterge/kanıt toplanır). IDOR / İş Mantığı / Race-Mass-Assignment kontrolleri **yalnızca login-öncesi erişilebilir yüzeyde** çalışır; **login-SONRASI** oturum içi derin yetkilendirme/yetki-yükseltme/iş-mantığı zafiyetleri bu paketin **dışındadır** — bunlar **Tam Kapsamlı Pentest** (kimlik-doğrulamalı, kapsam sözleşmeli) kapsamındadır. Bu nedenle bu üç kategoride bazı hedeflerde **sınırlı veya "İncelenemedi"** sonuç normal ve beklenendir (siteye özgü yüzey azlığından; motor eksikliğinden değil). Bir kontrolde "bulgu yok", aktif istismar bilinçli olarak sınırlı/pasif-güvenli tutulduğu için **güvenli olduğunu KANITLAMAZ**.\n\n`;

  const findings =
    `${box}\n\n` +
    `## YÖNETİCİ ÖZETİ\n\n${summary.join('\n')}${httpsSummaryNote}\n\n` +
    `## GENEL DEĞERLENDİRME\n\n**Risk Seviyesi: ${verdictWord}**\n\n${genelHttps}${genel}\n\n` +
    `${httpsFindingSection}${controlTable}\n${assuranceSection}` +
    `${sections}`;

  const fixParts = ACTIVE_BUNDLE_MEMBERS.map((m, i) => {
    const r = runs[i];
    if (!r || !r.rep || !r.rep.fixText.trim()) return '';
    return `### ${m.title}\n\n${r.rep.fixText.trim()}`;
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
export function levelFromFindings(fs: ActiveCheckEvidence['findings']): Level {
  // (Faz 5 düzeltme) BANT = EN YÜKSEK tekil bulgu şiddeti; ASLA aşmaz. medium→'medium' (Orta-Yüksek DEĞİL);
  // hacim (çok sayıda düşük) bandı yukarı itmez. Hibrit 'medium-high' yalnız gerçek köprü-bulguda kullanılır
  // ki bu motorda bulgu şiddeti high|medium|low olduğundan asla üretilmez → tek-yön max-severity eşlemesi.
  if (fs.some((f) => f.severity === 'high')) return 'high';
  if (fs.some((f) => f.severity === 'medium')) return 'medium';
  return 'low';
}
const SIDE_EFFECT_WORD: Record<string, string> = { none: 'yok', possible: 'olası', confirmed: 'doğrulandı' };

function buildActiveCheckReport(ev: ActiveCheckEvidence, cfg: CheckCfg): { findings: string; fixText: string } | null {
  if (!ev.ok) return null;
  const level = levelFromFindings(ev.findings);
  const has = ev.findings.length > 0;
  const noSurface = level === 'low' && !has && ev.inputsFound === 0;

  const bullets = [
    noSurface
      ? noTestableSurfaceBullet('bu kontrol için **test edilebilir bir giriş/uç nokta saptanmadı**')
      : `- **Genel risk seviyesi: ${RISK_WORD[level]}** — ${level === 'high' ? 'aktif doğrulama ile zafiyet göstergesi KANITLANDI.' : (level === 'medium-high' || level === 'medium') ? 'dikkat gerektiren bir gösterge bulundu (manuel doğrulama önerilir).' : has ? 'yalnızca düşük-önemli gözlem(ler) bulundu.' : 'belirgin bir zafiyet göstergesi bulunamadı.'}`,
    `- Taranan sayfa/uç nokta: **${ev.pagesScanned}** · İncelenen giriş/uç nokta: **${ev.inputsFound}** · Gönderilen probe: **${ev.probesSent}** · Bulgu: ${ev.findings.length}.`,
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
  const findings = assemble(level, bullets, genel, `${method}${table}${confNote}${sideEffectNote}${notes}${SCOPE_NOTE_ACTIVE}\n`, noSurface);

  const fixText = has
    ? `### ${cfg.fixTitle} — düzeltme\n\n` + cfg.fixFound.map((l) => `- ${l}`).join('\n')
    : `### ${cfg.fixTitle} — proaktif sertleştirme\n\n` + cfg.fixClean.map((l) => `- ${l}`).join('\n');
  return { findings, fixText };
}

const LOGIN_BYPASS_CFG: CheckCfg = {
  title: 'Giriş Baypası (SQLi Göstergesi)',
  whatChecked: [
    'Giriş (login) ucuna önce **geçersiz kimlik** (kontrol) gönderildi; ardından klasik SQLi payload’ları (`\' OR \'1\'=\'1` vb.) denenip, kontrolün AKSİNE oturum/başarı (token/2xx) dönüp dönmediği gözlemlendi.',
    'Login POST’u zaten izinli bir akıştır; bu, TEK ve zararsız bir gözlemdir.',
    '⚠️ Oturum ele geçirme/istismar YOK — yalnız "kimlik doğrulama atlatma göstergesi var mı" gözlemi.',
  ],
  confidenceNote: 'Gösterge, kontrol denemesiyle karşılaştırmaya dayanır; kesin doğrulama manuel test gerektirir.',
  fixTitle: 'Giriş Baypası / SQL Enjeksiyonu',
  fixFound: [
    'Kimlik doğrulama sorgularında **parametreli sorgu / hazırlanmış ifade (prepared statement)** kullanın; kullanıcı girdisini asla SQL’e doğrudan koymayın.',
    'Girdi doğrulama + ORM güvenli API’leri; hatalı girişte tek-tip hata mesajı döndürün.',
  ],
  fixClean: ['Parametreli sorgu + girdi doğrulama uygulayın (proaktif).'],
  cleanGenel: 'Giriş baypası (SQLi) göstergesi bulunamadı ya da test edilebilir bir login ucu yoktu.',
};

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
