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
export const RISK_WORD_DE = { low: 'Niedrig', medium: 'Mittel', 'medium-high': 'Mittel-Hoch', high: 'Hoch' } as const;
// (Almanca) Türkçe makine-değeri (ev.findings[].severity -> RISK_WORD) DEĞİŞMEZ; yalnız GÖSTERİMDE Almanca kelime.
export const SEV_DISP: Record<string, string> = { 'Kritik': 'Kritisch', 'Yüksek': 'Hoch', 'Orta': 'Mittel', 'Orta-Yüksek': 'Mittel-Hoch', 'Düşük': 'Niedrig', 'Bilgilendirme': 'Hinweis' };
export type Level = 'low' | 'medium' | 'medium-high' | 'high';
export function levelRank(l: Level): number { return l === 'high' ? 3 : l === 'medium-high' ? 2 : l === 'medium' ? 1 : 0; }
const rw = (l: Level, de: boolean) => (de ? RISK_WORD_DE[l] : RISK_WORD[l]);
const sevDisp = (tr: string, de: boolean) => (de ? SEV_DISP[tr] ?? tr : tr);

function assemble(level: Level, summaryBullets: string[], genelSentence: string, sections: string, unscannable = false, de = false): string {
  const t = (tr: string, deS: string) => (de ? deS : tr);
  return (
    `## ${t('YÖNETİCİ ÖZETİ', 'MANAGEMENTZUSAMMENFASSUNG')}\n\n${summaryBullets.join('\n')}\n\n` +
    `## ${t('GENEL DEĞERLENDİRME', 'GESAMTBEWERTUNG')}\n\n**${t('Risk Seviyesi', 'Risikostufe')}: ${unscannable ? t('İncelenemedi', 'Nicht prüfbar') : rw(level, de)}**\n\n${genelSentence}\n\n` +
    `${sections}`
  );
}

// (DÜRÜSTLIK — tekil aktif-doğrulama paketleri) Hedef erişilebilir ama test edilebilir bir giriş
// noktası (parametre/form/ID) yoksa: sonuç "Düşük/Temiz" DEĞİL, nötr "İncelenemedi"dir. İlk özet
// maddesini de İncelenemedi'ye çevirir ki rozet (assessBasit) + Master aynı işareti okusun.
function noTestableSurfaceBullet(what: string, de = false): string {
  return de
    ? `- **Gesamtrisikostufe: Nicht prüfbar** — das Ziel wurde erreicht, jedoch ${what}; es konnte keine echte Verifizierungssonde ausgeführt werden. Dieses Ergebnis bedeutet **NICHT, dass die Website sicher ist** — es zeigt lediglich, dass keine prüfbare Oberfläche gefunden wurde.`
    : `- **Genel risk seviyesi: İncelenemedi** — hedefe ulaşıldı ancak ${what}; gerçek doğrulama probu çalıştırılamadı. Bu sonuç sitenin **güvenli olduğu anlamına GELMEZ** — yalnızca test edilebilir bir yüzey bulunamadığını gösterir.`;
}

const SCOPE_NOTE_ACTIVE =
  '> **Kapsam ve yöntem:** Bu paket, "kanıtla — istismar etme" ilkesiyle çalışır. Backend, hedefe ' +
  'sınırlı sayıda **zararsız** doğrulama probu göndermiştir; hiçbir veri çekilmemiş, değiştirilmemiş veya ' +
  'silinmemiştir. İstekler arası bekleme ve hedef-sağlığı devre kesici (art arda 5xx / aşırı yavaşlama / WAF) ' +
  'uygulanır. Kimlik doğrulama gerektiren alanlar ve iç mantık bu paketin kapsamı dışındadır.';
const SCOPE_NOTE_ACTIVE_DE =
  '> **Geltungsbereich und Methode:** Dieses Paket arbeitet nach dem Prinzip „nachweisen — nicht ausnutzen". Das Backend hat ' +
  'eine begrenzte Anzahl **harmloser** Verifizierungssonden an das Ziel gesendet; es wurden keine Daten abgerufen, verändert oder ' +
  'gelöscht. Wartezeiten zwischen den Anfragen und ein Schutzschalter für die Zielverfügbarkeit (aufeinanderfolgende 5xx / starke Verlangsamung / WAF) ' +
  'werden angewendet. Bereiche, die eine Authentifizierung erfordern, sowie die interne Logik liegen außerhalb des Geltungsbereichs dieses Pakets.';
const scopeNote = (de: boolean) => (de ? SCOPE_NOTE_ACTIVE_DE : SCOPE_NOTE_ACTIVE);

// ======================================================================================
// injection_verify
// ======================================================================================
function injLevel(ev: InjEvidence): Level {
  // (Faz 5) BANT = en yüksek tekil bulgu şiddeti; aşmaz (medium→'medium', low→'low').
  if (ev.findings.some((f) => f.severity === 'high')) return 'high';
  if (ev.findings.some((f) => f.severity === 'medium')) return 'medium';
  return 'low';
}

export async function generateInjectionVerifyReport(host: string, locale: string = 'tr'): Promise<{ findings: string; fixText: string } | null> {
  const ev = await collectInjectionEvidence(host, undefined, locale === 'de');
  return buildInjectionReport(ev, locale === 'de');
}

// Saf kurucu (testlenebilir — gercek prob calistirmadan sentetik kanitla dogrulanir).
export function buildInjectionReport(ev: InjEvidence, de = false): { findings: string; fixText: string } | null {
  if (!ev.ok) return null;
  const t = (tr: string, deS: string) => (de ? deS : tr);
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
      ? noTestableSurfaceBullet(t('taranan sayfalarda **test edilebilir bir GET parametresi veya form alanı saptanmadı**', 'auf den gescannten Seiten **kein prüfbarer GET-Parameter oder Formularfeld festgestellt wurde**'), de)
      : level === 'low' && hasVerbose
      ? t(
          `- **Genel risk seviyesi: Orta** — test edilen giriş noktalarında **doğrudan enjeksiyon kanıtı bulunamadı**; ancak hedef, hatalı girdide **ayrıntılı hata sayfası** döndürerek framework sürümü/sunucu dosya yolu ifşa ediyor (bilgi sızıntısı — aşağıda).`,
          `- **Gesamtrisikostufe: Mittel** — an den getesteten Eingabepunkten wurde **kein direkter Injektionsnachweis gefunden**; jedoch gibt das Ziel bei fehlerhafter Eingabe eine **ausführliche Fehlerseite** zurück und legt damit Framework-Version/Server-Dateipfad offen (Informationsleck — siehe unten).`,
        )
      : t(
          `- **Genel risk seviyesi: ${RISK_WORD[level]}** — ${level === 'high' ? 'aktif doğrulama ile enjeksiyon zafiyeti KANITLANDI.' : level === 'medium-high' || level === 'medium' ? 'olası bir enjeksiyon göstergesi bulundu (bağlama göre doğrulama önerilir).' : 'test edilen giriş noktalarında enjeksiyon kanıtı bulunamadı.'}`,
          `- **Gesamtrisikostufe: ${RISK_WORD_DE[level]}** — ${level === 'high' ? 'mittels aktiver Verifizierung wurde eine Injektionsschwachstelle NACHGEWIESEN.' : level === 'medium-high' || level === 'medium' ? 'ein möglicher Injektionsindikator wurde gefunden (kontextabhängige Verifizierung empfohlen).' : 'an den getesteten Eingabepunkten wurde kein Injektionsnachweis gefunden.'}`,
        ),
    t(
      `- Taranan sayfa/uç nokta: **${ev.pagesScanned}** · Test edilen giriş noktası: **${ev.inputsFound}** · Gönderilen payload: **${ev.payloadsSent}** (toplam ${ev.probesSent} istek) · SQLi bulgusu: ${sqli.length} · XSS bulgusu: ${xss.length}.`,
      `- Gescannte Seiten/Endpunkte: **${ev.pagesScanned}** · Getestete Eingabepunkte: **${ev.inputsFound}** · Gesendete Payloads: **${ev.payloadsSent}** (insgesamt ${ev.probesSent} Anfragen) · SQLi-Befunde: ${sqli.length} · XSS-Befunde: ${xss.length}.`,
    ),
    t('- **Önerilen ilk adım:** ', '- **Empfohlener erster Schritt:** ') + (ev.findings.length ? t('Kanıtlanan giriş noktalarını parametreli sorgu / çıktı kodlaması ile kapatın; hazır adımlar "AI Çözüm Önerileri" bölümünde.', 'Schließen Sie die nachgewiesenen Eingabepunkte mit parametrisierten Abfragen / Ausgabe-Kodierung; fertige Schritte im Abschnitt „KI-Lösungsvorschläge".') : t('Girdi doğrulama ve çıktı kodlamasını standart hale getirin; hazır sertleştirme adımları "AI Çözüm Önerileri" bölümünde.', 'Standardisieren Sie Eingabevalidierung und Ausgabe-Kodierung; fertige Härtungsschritte im Abschnitt „KI-Lösungsvorschläge".')),
  ];

  const genel = level === 'high'
    ? t('Aktif-hafif doğrulama ile en az bir giriş noktasında enjeksiyon zafiyeti kanıtlandı; öncelikli olarak giderilmesi önerilir.', 'Mittels aktiv-leichter Verifizierung wurde an mindestens einem Eingabepunkt eine Injektionsschwachstelle nachgewiesen; eine vorrangige Behebung wird empfohlen.')
    : level === 'medium-high' || level === 'medium'
      ? t('Olası bir enjeksiyon göstergesi bulundu; bağlama göre manuel doğrulama ve giderme önerilir.', 'Ein möglicher Injektionsindikator wurde gefunden; kontextabhängige manuelle Verifizierung und Behebung werden empfohlen.')
      : ev.inputsFound
        ? t(
            `${ev.pagesScanned} sayfa/uç nokta tarandı; ${ev.inputsFound} giriş noktasında toplam **${ev.payloadsSent}** zararsız SQLi/XSS payload'ı denendi ve hiçbiri enjeksiyon kanıtı üretmedi. Bu, test edilen giriş noktalarının şu an için dayanıklı göründüğünü gösterir (tüm giriş noktalarının kanıtı değildir).`,
            `${ev.pagesScanned} Seiten/Endpunkte wurden gescannt; an ${ev.inputsFound} Eingabepunkten wurden insgesamt **${ev.payloadsSent}** harmlose SQLi/XSS-Payloads erprobt, von denen keine einen Injektionsnachweis erbrachte. Dies deutet darauf hin, dass die getesteten Eingabepunkte derzeit widerstandsfähig erscheinen (kein Nachweis für alle Eingabepunkte).`,
          )
        : t(
            `${ev.pagesScanned} sayfa/uç nokta tarandı; test edilebilir bir GET parametresi veya form alanı saptanmadı (enjeksiyon doğrulaması için giriş noktası yok).`,
            `${ev.pagesScanned} Seiten/Endpunkte wurden gescannt; es wurde kein prüfbarer GET-Parameter oder Formularfeld festgestellt (kein Eingabepunkt für die Injektionsverifizierung).`,
          );

  // Ne kontrol edildi — seffaflik (bulgu olsa da olmasa da)
  const method = de
    ? [
        '## WAS WURDE GEPRÜFT\n',
        'Auf den aus den gescannten Seiten (Startseite + interne Links + bekannte Pfade) entdeckten Eingabepunkten (URL-Query-Parameter + Formularfelder) wurden pro Eingabepunkt harmlose Verifizierungssonden ausgeführt:',
        '',
        '- **SQLi (fehlerbasiert):** Ein einfaches Anführungszeichen (`\'`) wurde injiziert und die Antwort auf eine Datenbank-Fehlersignatur (MySQL/PostgreSQL/Oracle/MSSQL/SQLite) untersucht.',
        `- **SQLi (zeitbasiert):** An Punkten ohne Fehler wurde mit einer einzigen harmlosen Verzögerungssonde (SLEEP) die Antwortzeit gegenüber der Baseline gemessen (Blind-SQLi-Indikator).`,
        `- **SQLi (boolean-basiert):** An numerischen/ID-ähnlichen Punkten wurden zwei bedingte Anfragen mit TRUE (\`1=1\`) und FALSE (\`1=2\`) gesendet und ihre Antworten (Status + Inhaltslänge) verglichen; ist die TRUE-Wiederholung konsistent und DAUERHAFT von FALSE verschieden, ist dies ein Boolean-based-SQLi-Indikator (zur Vermeidung von Falsch-Positiven wird eine Stabilitätsprüfung durchgeführt).`,
        '- **XSS (reflektiert):** Eine eindeutige, harmlose Markierungszeichenfolge wurde injiziert und geprüft, ob sie im Antwort-HTML **ohne Kodierung (unencoded)** reflektiert wird (kein JS ausgeführt; kein Stored XSS erprobt).',
        '',
      ].join('\n')
    : [
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
    f.technique === 'error-based' ? t('Yüksek — yanıtta veritabanı hata imzası (doğrudan kanıt)', 'Hoch — Datenbank-Fehlersignatur in der Antwort (direkter Nachweis)')
    : f.technique === 'boolean-based' ? t('Yüksek — TRUE/FALSE koşul yanıtları tutarlı ve KALICI biçimde farklı (girdi sorgu mantığını değiştiriyor — doğrudan kanıt)', 'Hoch — TRUE/FALSE-Bedingungsantworten konsistent und DAUERHAFT verschieden (Eingabe verändert die Abfragelogik — direkter Nachweis)')
    : f.technique === 'time-based' ? t('Orta — zaman-tabanlı/dolaylı; OOB doğrulama altyapısı yok', 'Mittel — zeitbasiert/indirekt; keine OOB-Verifizierungsinfrastruktur')
    : f.confidence === 'high' ? t('Orta-Yüksek — işaret dizesi HAM (kaçırılmamış) yansıdı; güçlü XSS göstergesi (JS yürütülmediğinden istismar kanıtlanmadı)', 'Mittel-Hoch — Markierungszeichenfolge ROH (unkodiert) reflektiert; starker XSS-Indikator (da kein JS ausgeführt wurde, keine Ausnutzung nachgewiesen)')
    : t('Düşük — yansıdı ancak kodlanmış/kaçırılmış; bağlama bağlı zayıf gösterge', 'Niedrig — reflektiert, jedoch kodiert/escaped; kontextabhängiger schwacher Indikator');
  const techLabel = (tech: InjEvidence['findings'][number]['technique']): string =>
    tech === 'error-based' ? t('hata-tabanlı', 'fehlerbasiert') : tech === 'time-based' ? t('zaman-tabanlı', 'zeitbasiert') : tech === 'boolean-based' ? t('boolean-tabanlı', 'boolean-basiert') : t('yansıma', 'Reflexion');
  const table = ev.findings.length
    ? t('## BULGULAR\n\n| Giriş Noktası | Tür | Teknik | Kanıt | Güven (gerekçe) | Ciddiyet |\n|---------------|-----|--------|-------|-----------------|----------|\n', '## BEFUNDE\n\n| Eingabepunkt | Typ | Technik | Nachweis | Konfidenz (Begründung) | Schweregrad |\n|---------------|-----|--------|-------|-----------------|----------|\n') +
      ev.findings.map((f) => `| ${f.inputPoint} | ${f.type} | ${techLabel(f.technique)} | ${f.evidence.replace(/\|/g, '\\|')} | ${injConf(f)} | ${sevDisp(RISK_WORD[f.severity], de)} |`).join('\n') + '\n\n'
    : t('## BULGULAR\n\nTest edilen giriş noktalarında enjeksiyon kanıtı bulunamadı.\n\n', '## BEFUNDE\n\nAn den getesteten Eingabepunkten wurde kein Injektionsnachweis gefunden.\n\n');

  // (İŞ B) GERÇEK yanıt gövdesinden saptanan ayrıntılı-hata-sayfası bilgi ifşası -> ŞİDDET-kolonlu tablo
  // (parseFindings -> master/dağılım/detay kartı). Redakte + kısaltılmış kanıt; UYDURMA YOK.
  const verboseSection = hasVerbose
    ? (de
        ? `## FESTGESTELLTE RISIKEN\n\n| Befund | Schweregrad | Beschreibung |\n|-------|--------|----------|\n| Informationsleck durch ausführliche Fehlerseite | Mittel | Während der Verifizierungssonde wurde im KÖRPER der vom Endpunkt **${ev.verboseError!.endpoint}** zurückgegebenen Fehlerantwort eine ausführliche Fehlerseiten-Signatur festgestellt (Framework-Version / Server-Dateipfad / Stack-Trace). Nachweis (gekürzt): \`${ev.verboseError!.sig.replace(/\|/g, '\\|').replace(/`/g, "'")}\` In der Produktion sollten ausführliche Fehlerseiten deaktiviert werden (CWE-209). |\n\n`
        : `## TESPİT EDİLEN RİSKLER\n\n| Bulgu | Şiddet | Açıklama |\n|-------|--------|----------|\n| Ayrıntılı hata sayfası bilgi ifşası | Orta | Doğrulama probu sırasında **${ev.verboseError!.endpoint}** ucundan dönen hata yanıtının GÖVDESİNDE ayrıntılı hata-sayfası imzası saptandı (framework sürümü / sunucu dosya yolu / stack trace). Kanıt (kısaltılmış): \`${ev.verboseError!.sig.replace(/\|/g, '\\|').replace(/`/g, "'")}\` Üretimde ayrıntılı hata sayfaları kapatılmalıdır (CWE-209). |\n\n`)
    : '';
  const notes = ev.notes.length ? ev.notes.map((n) => `> ${n}`).join('\n') + '\n\n' : '';
  const findings = assemble(reportLevel, bullets, genel, `${method}${table}${verboseSection}${notes}${scopeNote(de)}\n`, noSurface, de);

  const fixText = ev.findings.length
    ? t('### Enjeksiyon (SQLi/XSS) — düzeltme\n\n', '### Injektion (SQLi/XSS) — Behebung\n\n') + [
        sqli.length ? t('- **SQLi:** Tüm veritabanı sorgularını **parametreli sorgu / hazırlanmış ifade (prepared statement)** ile yazın; kullanıcı girdisini asla string olarak sorguya eklemeyin. ORM kullanıyorsanız ham SQL birleştirmeden kaçının. Veritabanı hata mesajlarını son kullanıcıya göstermeyin.', '- **SQLi:** Schreiben Sie alle Datenbankabfragen mit **parametrisierten Abfragen / Prepared Statements**; fügen Sie Benutzereingaben niemals als String in die Abfrage ein. Bei Verwendung eines ORM vermeiden Sie rohe SQL-Verkettung. Zeigen Sie Datenbank-Fehlermeldungen nicht dem Endbenutzer.') : '',
        xss.length ? t('- **XSS:** Kullanıcı girdisini HTML’e basarken **bağlama uygun çıktı kodlaması** (HTML entity encoding) uygulayın; mümkünse otomatik kaçış yapan şablon motoru kullanın. `Content-Security-Policy` başlığı ile satır-içi script’leri kısıtlayın.', '- **XSS:** Wenden Sie beim Ausgeben von Benutzereingaben in HTML eine **kontextgerechte Ausgabe-Kodierung** (HTML-Entity-Encoding) an; verwenden Sie nach Möglichkeit eine automatisch escapende Template-Engine. Beschränken Sie Inline-Skripte mit dem `Content-Security-Policy`-Header.') : '',
        t('- Giderdikten sonra aynı giriş noktalarını yeniden test edin.', '- Testen Sie nach der Behebung dieselben Eingabepunkte erneut.'),
      ].filter(Boolean).join('\n')
    : t('### Enjeksiyon — proaktif sertleştirme\n\n', '### Injektion — proaktive Härtung\n\n') + [
        t('- **Girdi doğrulama:** Tüm kullanıcı girdilerini beklenen tip/uzunluk/biçime göre doğrulayın (allowlist yaklaşımı).', '- **Eingabevalidierung:** Validieren Sie alle Benutzereingaben nach erwartetem Typ/Länge/Format (Allowlist-Ansatz).'),
        t('- **SQLi’ye karşı:** Her zaman parametreli sorgu / hazırlanmış ifade kullanın; ham SQL string birleştirmeyin.', '- **Gegen SQLi:** Verwenden Sie stets parametrisierte Abfragen / Prepared Statements; keine rohe SQL-String-Verkettung.'),
        t('- **XSS’e karşı:** Çıktı kodlaması (HTML entity) + `Content-Security-Policy` başlığı uygulayın; otomatik kaçış yapan şablon motoru tercih edin.', '- **Gegen XSS:** Wenden Sie Ausgabe-Kodierung (HTML-Entity) + `Content-Security-Policy`-Header an; bevorzugen Sie eine automatisch escapende Template-Engine.'),
        t('- Veritabanı ve uygulama hata mesajlarını son kullanıcıdan gizleyin (yığın izi / SQL hatası sızdırmayın).', '- Verbergen Sie Datenbank- und Anwendungsfehlermeldungen vor dem Endbenutzer (keine Stack-Traces / SQL-Fehler preisgeben).'),
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

export async function generateIdorVerifyReport(host: string, locale: string = 'tr'): Promise<{ findings: string; fixText: string } | null> {
  const ev = await collectIdorEvidence(host, undefined, locale === 'de');
  return buildIdorReport(ev, locale === 'de');
}

// Saf kurucu (testlenebilir).
export function buildIdorReport(ev: IdorEvidence, de = false): { findings: string; fixText: string } | null {
  if (!ev.ok) return null;
  const t = (tr: string, deS: string) => (de ? deS : tr);
  const level = idorLevel(ev);
  const noSurface = level === 'low' && !ev.candidates;

  const bullets = [
    noSurface
      ? noTestableSurfaceBullet(t('ana sayfada **tahmin edilebilir/sayısal ID içeren test edilebilir bir uç nokta bulunamadı**', 'auf der Startseite **kein prüfbarer Endpunkt mit vorhersehbarer/numerischer ID gefunden wurde**'), de)
      : t(
          `- **Genel risk seviyesi: ${RISK_WORD[level]}** — ${(level === 'high' || level === 'medium-high' || level === 'medium') ? 'kimlik doğrulaması olmadan komşu ID ile farklı kaynağa erişim göstergesi bulundu.' : ev.findings.length ? 'zayıf bir numaralandırma göstergesi bulundu (manuel doğrulama gerekli).' : 'test edilen ID’li uç noktalarda yetkisiz erişim göstergesi bulunmadı.'}`,
          `- **Gesamtrisikostufe: ${RISK_WORD_DE[level]}** — ${(level === 'high' || level === 'medium-high' || level === 'medium') ? 'ein Indikator für den Zugriff auf eine andere Ressource über eine benachbarte ID ohne Authentifizierung wurde gefunden.' : ev.findings.length ? 'ein schwacher Enumerationsindikator wurde gefunden (manuelle Verifizierung erforderlich).' : 'an den getesteten ID-Endpunkten wurde kein Indikator für unbefugten Zugriff gefunden.'}`,
        ),
    t(
      `- Taranan sayfa/uç nokta: **${ev.pagesScanned}** · Aday ID uç noktası: **${ev.candidates}** · Gönderilen probe: **${ev.probesSent}** · Bulgu: ${ev.findings.length}.`,
      `- Gescannte Seiten/Endpunkte: **${ev.pagesScanned}** · Kandidaten-ID-Endpunkte: **${ev.candidates}** · Gesendete Sonden: **${ev.probesSent}** · Befunde: ${ev.findings.length}.`,
    ),
    t('- **Önerilen ilk adım:** ', '- **Empfohlener erster Schritt:** ') + (ev.findings.length ? t('Nesne-düzeyi yetkilendirme kontrolü ekleyin; hazır adımlar "AI Çözüm Önerileri" bölümünde.', 'Fügen Sie eine Objekt-Ebenen-Autorisierungsprüfung hinzu; fertige Schritte im Abschnitt „KI-Lösungsvorschläge".') : t('Nesne-düzeyi yetkilendirmeyi standart hale getirin; hazır adımlar "AI Çözüm Önerileri" bölümünde.', 'Standardisieren Sie die Objekt-Ebenen-Autorisierung; fertige Schritte im Abschnitt „KI-Lösungsvorschläge".')),
  ];

  const genel = (level === 'high' || level === 'medium-high' || level === 'medium')
    ? t('Kimlik doğrulaması olmadan, tahmin edilebilir bir ID’yi komşu değere değiştirerek farklı bir kaynağa erişilebildiği gözlemlendi; nesne-düzeyi yetkilendirme kontrolü önerilir.', 'Es wurde beobachtet, dass ohne Authentifizierung durch Ändern einer vorhersehbaren ID auf einen benachbarten Wert auf eine andere Ressource zugegriffen werden konnte; eine Objekt-Ebenen-Autorisierungsprüfung wird empfohlen.')
    : ev.findings.length
      ? t('Zayıf bir numaralandırma göstergesi bulundu; bağlama göre manuel doğrulama önerilir.', 'Ein schwacher Enumerationsindikator wurde gefunden; kontextabhängige manuelle Verifizierung wird empfohlen.')
      : ev.candidates
        ? t(
            `Test edilen ${ev.candidates} ID’li uç noktada, kimlik doğrulaması olmadan komşu ID’ye erişim denemesinde yetkisiz erişim göstergesi gözlemlenmedi.`,
            `An den ${ev.candidates} getesteten ID-Endpunkten wurde beim Zugriffsversuch auf eine benachbarte ID ohne Authentifizierung kein Indikator für unbefugten Zugriff beobachtet.`,
          )
        : t('Ana sayfada tahmin edilebilir/sayısal ID içeren bir uç nokta bulunamadı.', 'Auf der Startseite wurde kein Endpunkt mit vorhersehbarer/numerischer ID gefunden.');

  // DURUSTLUK: kapsam sinirini ACIKCA belirt (abartili "IDOR yok" iddiasi YAPMA).
  const scopeLimit = de
    ? '## GELTUNGSBEREICH (WICHTIG)\n\n' +
      'Dieses Paket arbeitet **ohne Authentifizierung**. Daher kann es nur unbefugten Zugriff auf **öffentlich zugängliche, enumerierbare Ressourcen** erkennen. ' +
      'Klassisches IDOR (ein Benutzer greift auf die Daten eines anderen angemeldeten Benutzers zu) erfordert **zwei verschiedene Konten/Sitzungen** und liegt außerhalb des Geltungsbereichs dieses Pakets. ' +
      'Das Fehlen von Befunden in diesem Abschnitt **beweist nicht**, dass in authentifizierten Abläufen kein IDOR vorliegt — dies erfordert einen separaten authentifizierten Test (**Prüfung erforderlich / Außerhalb des Umfangs**).\n\n'
    : '## KAPSAM SINIRI (ÖNEMLİ)\n\n' +
      'Bu paket **kimlik doğrulaması olmadan** çalışır. Bu nedenle yalnızca **herkese açık, numaralandırılabilir kaynaklara** yetkisiz erişimi tespit edebilir. ' +
      'Klasik IDOR (bir kullanıcının, oturum açmış başka bir kullanıcının verisine erişmesi) **iki farklı hesap/oturum** gerektirir ve bu paketin kapsamı dışındadır. ' +
      'Bu bölümde bulgu olmaması, kimlik doğrulamalı akışlarda IDOR olmadığını **kanıtlamaz** — bu, ayrı bir kimlik-doğrulamalı test gerektirir (**İnceleme gerekli / Kapsam Dışı**).\n\n';

  const method = de
    ? [
        '## WAS WURDE GEPRÜFT\n',
        'Auf den aus den gescannten Seiten entdeckten Endpunkten mit vorhersehbarer/numerischer ID (z. B. `?id=123`, `/user/45`):',
        '',
        '- Der ID-Wert wurde **auf einen benachbarten Wert** (N-1 / N+1) geändert und ohne Authentifizierung eine **GET**-Anfrage gesendet.',
        '- Es wurden nur **Status und Größe** der Antwort verglichen; **der zurückgegebene Inhalt wurde nicht gespeichert/zitiert**.',
        '- Die Rückgabe einer anderen, gültig erscheinenden Ressource wurde als Indikator für enumerierbaren Zugriff gewertet.',
        '',
      ].join('\n')
    : [
        '## NE KONTROL EDİLDİ\n',
        'Taranan sayfalardan keşfedilen, tahmin edilebilir/sayısal ID içeren uç noktalar (ör. `?id=123`, `/user/45`) üzerinde:',
        '',
        '- ID değeri **komşu bir değere** (N-1 / N+1) değiştirilip, kimlik doğrulaması olmadan **GET** isteği gönderildi.',
        '- Yalnızca yanıt **durumu ve boyutu** karşılaştırıldı; **dönen içerik saklanmadı/alıntılanmadı**.',
        '- Farklı ve geçerli görünen bir kaynak dönmesi, numaralandırılabilir erişim göstergesi sayıldı.',
        '',
      ].join('\n');

  const table = ev.findings.length
    ? t('## BULGULAR\n\n| Uç Nokta | ID | Gözlem | Ciddiyet |\n|----------|-----|--------|----------|\n', '## BEFUNDE\n\n| Endpunkt | ID | Beobachtung | Schweregrad |\n|----------|-----|--------|----------|\n') +
      ev.findings.map((f) => `| ${f.endpoint} | ${f.idParam} | ${f.observation.replace(/\|/g, '\\|')} | ${sevDisp(RISK_WORD[f.severity], de)} |`).join('\n') + '\n\n'
    : t('## BULGULAR\n\nTest edilen ID’li uç noktalarda yetkisiz erişim göstergesi bulunamadı.\n\n', '## BEFUNDE\n\nAn den getesteten ID-Endpunkten wurde kein Indikator für unbefugten Zugriff gefunden.\n\n');

  const notes = ev.notes.length ? ev.notes.map((n) => `> ${n}`).join('\n') + '\n\n' : '';
  const findings = assemble(level, bullets, genel, `${method}${table}${scopeLimit}${notes}${scopeNote(de)}\n`, noSurface, de);

  const fixText = ev.findings.length
    ? t('### Yetkisiz Erişim (IDOR) — düzeltme\n\n', '### Unbefugter Zugriff (IDOR) — Behebung\n\n') + [
        t('- **Nesne-düzeyi yetkilendirme:** Her kaynak erişiminde, isteyen kullanıcının o nesneye erişim hakkı olup olmadığını sunucu tarafında doğrulayın (sadece ID’nin geçerli olması yeterli değildir).', '- **Objekt-Ebenen-Autorisierung:** Prüfen Sie bei jedem Ressourcenzugriff serverseitig, ob der anfragende Benutzer zum Zugriff auf dieses Objekt berechtigt ist (die bloße Gültigkeit der ID genügt nicht).'),
        t('- **Tahmin edilemez tanımlayıcılar:** Sıralı sayısal ID yerine UUID/rastgele tanımlayıcı kullanın; numaralandırmayı zorlaştırın.', '- **Nicht vorhersehbare Bezeichner:** Verwenden Sie statt sequenzieller numerischer IDs UUIDs/zufällige Bezeichner; erschweren Sie die Enumeration.'),
        t('- Herkese açık olmaması gereken kaynakları kimlik doğrulama arkasına alın.', '- Stellen Sie Ressourcen, die nicht öffentlich sein sollten, hinter eine Authentifizierung.'),
      ].join('\n')
    : t('### Yetkisiz Erişim (IDOR) — proaktif sertleştirme\n\n', '### Unbefugter Zugriff (IDOR) — proaktive Härtung\n\n') + [
        t('- Her kaynak erişiminde **nesne-düzeyi yetkilendirme** kontrolü uygulayın (kullanıcı ↔ nesne sahipliği).', '- Wenden Sie bei jedem Ressourcenzugriff eine **Objekt-Ebenen-Autorisierungsprüfung** an (Benutzer ↔ Objekteigentum).'),
        t('- Sıralı sayısal ID yerine **UUID/rastgele tanımlayıcı** kullanın.', '- Verwenden Sie statt sequenzieller numerischer IDs **UUIDs/zufällige Bezeichner**.'),
        t('- Kimlik doğrulamalı akışlar için ayrı, oturum-tabanlı bir IDOR testi planlayın (bu paketin kapsamı dışında).', '- Planen Sie für authentifizierte Abläufe einen separaten, sitzungsbasierten IDOR-Test (außerhalb des Umfangs dieses Pakets).'),
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
type ActiveMember = { key: string; title: string; titleDe: string; conf: 'Yüksek' | 'Orta' | 'Düşük'; run: (host: string, de: boolean) => Promise<MemberRun> };
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
  whatCheckedDe: [
    'Nur auf am Ziel TATSÄCHLICH beobachteten GET-Parametern, schreibgeschützte sichere Indikatoren (KEIN Schreiben/Hochladen/Befehl).',
    '**A1 LFI / Path Traversal:** abgestufte, harmlose Sonde in Datei-/Pfadparametern — Befund nur bei Übereinstimmung einer bekannten Datei-SIGNATUR (z. B. `root:x:0:0:`); **Inhalt REDIGIERT** (keine Datei abgerufen).',
    '**A2 Open Redirect:** harmloser externer Canary in Weiterleitungsparametern; Location/meta-refresh-Reflexion beobachtet (**Redirect wird NICHT verfolgt**).',
    '**A3 HTTP Parameter Pollution:** Verarbeitungsunterschied eines wiederholten Parameters (reine Beobachtung; keine Daten gesendet).',
    '**A5 SSTI:** nur arithmetischer Ausdruck im reflektierten Parameter (`{{1234*3}}`→`3702`) — KEIN Code/Befehl.',
    '**A4 boolean-SQLi** und **A6 Datei-Upload** werden in den zugehörigen Abschnitten (Injektion / Datei-Upload-Verifizierung) bewertet — keine Doppelbefunde (Querverweis).',
  ],
  confidenceNoteDe: 'Alle sind „Indikator, Verifizierung erforderlich"; nur auf beobachteten Parametern. LFI-Signatur Hoch; Open-Redirect/SSTI Mittel; HPP Niedrig. Bei modernen SPA-/API-Seiten ist ein „außerhalb des Umfangs"/geringer Befund oft das ERWARTETE und richtige Ergebnis.',
  fixTitleDe: 'Sichere aktive Indikatoren',
  fixFoundDe: [
    'LFI: Legen Sie Benutzereingaben nicht in den Dateipfad; Allowlist + `basename` + Wurzelverzeichnis-Beschränkung (realpath/chroot).',
    'Open Redirect: Beschränken Sie Weiterleitungsziele serverseitig per Allowlist; leiten Sie nicht auf externe absolute URLs weiter.',
    'HPP: Normalisieren Sie Parameter auf einen Einzelwert; konsistentes Parsen über Schichten hinweg. SSTI: Interpolieren Sie Eingaben nicht in Templates (logikfreie Engine + Escaping + Sandbox).',
  ],
  fixCleanDe: ['Eingaben werden nicht direkt in Dateipfad/Template/Weiterleitungsziel gelegt; Parameter normalisiert (proaktiv).'],
  cleanGenelDe: 'In den beobachteten Parametern wurde kein Indikator für LFI-Signatur, Open Redirect, HTTP Parameter Pollution oder Template-Injektion (SSTI) gefunden.',
};

const ACTIVE_BUNDLE_MEMBERS: ActiveMember[] = [
  { key: 'injection_verify', title: 'Enjeksiyon (SQLi/XSS) Doğrulama', titleDe: 'Injektion (SQLi/XSS) Verifizierung', conf: 'Yüksek', run: async (h, de) => { const ev = await collectInjectionEvidence(h, undefined, de); return { rep: buildInjectionReport(ev, de), pages: ev.pagesScanned, inputs: ev.inputsFound, probes: ev.probesSent, fc: ev.findings.length, formsTested: ev.formsTested, formsSkipped: ev.formsSkipped }; } },
  { key: 'idor_verify', title: 'Yetkisiz Erişim (IDOR) Doğrulama', titleDe: 'Unbefugter Zugriff (IDOR) Verifizierung', conf: 'Orta', run: async (h, de) => { const ev = await collectIdorEvidence(h, undefined, de); return { rep: buildIdorReport(ev, de), pages: ev.pagesScanned, inputs: ev.candidates, probes: ev.probesSent, fc: ev.findings.length }; } },
  { key: 'ssrf_verify', title: 'SSRF Doğrulama', titleDe: 'SSRF Verifizierung', conf: 'Orta', run: async (h, de) => { const ev = await collectSsrfEvidence(h, undefined, de); return { rep: buildActiveCheckReport(ev, SSRF_CFG, de), pages: ev.pagesScanned, inputs: ev.inputsFound, probes: ev.probesSent, fc: ev.findings.length }; } },
  { key: 'file_upload_verify', title: 'Dosya Yükleme Doğrulama', titleDe: 'Datei-Upload-Verifizierung', conf: 'Düşük', run: async (h, de) => { const ev = await collectFileUploadEvidence(h, de); return { rep: buildActiveCheckReport(ev, UPLOAD_CFG, de), pages: ev.pagesScanned, inputs: ev.inputsFound, probes: ev.probesSent, fc: ev.findings.length }; } },
  { key: 'business_logic_verify', title: 'İş Mantığı Doğrulama', titleDe: 'Geschäftslogik-Verifizierung', conf: 'Düşük', run: async (h, de) => { const ev = await collectBusinessLogicEvidence(h, de); return { rep: buildActiveCheckReport(ev, BUSINESS_CFG, de), pages: ev.pagesScanned, inputs: ev.inputsFound, probes: ev.probesSent, fc: ev.findings.length }; } },
  { key: 'race_massassign_verify', title: 'Race / Mass-Assignment Doğrulama', titleDe: 'Race / Mass-Assignment Verifizierung', conf: 'Düşük', run: async (h, de) => { const ev = await collectRaceMassAssignEvidence(h, de); return { rep: buildActiveCheckReport(ev, RACE_CFG, de), pages: ev.pagesScanned, inputs: ev.inputsFound, probes: ev.probesSent, fc: ev.findings.length }; } },
  { key: 'rce_verify', title: 'RCE / Komut Enjeksiyonu Doğrulama', titleDe: 'RCE / Befehlsinjektion Verifizierung', conf: 'Orta', run: async (h, de) => { const ev = await collectRceEvidence(h, undefined, de); return { rep: buildActiveCheckReport(ev, RCE_CFG, de), pages: ev.pagesScanned, inputs: ev.inputsFound, probes: ev.probesSent, fc: ev.findings.length }; } },
  // (İŞ 3) Giriş baypası (SQLi göstergesi) — login POST'a kontrol vs SQLi karşılaştırması (gözlemsel).
  { key: 'active_indicators', title: 'Güvenli Aktif Göstergeler (LFI/Redirect/HPP/SSTI)', titleDe: 'Sichere aktive Indikatoren (LFI/Redirect/HPP/SSTI)', conf: 'Orta', run: async (h, de) => { const ev = await collectActiveIndicatorsEvidence(h); return { rep: buildActiveCheckReport(ev, ACTIVE_INDICATORS_CFG, de), pages: ev.pagesScanned, inputs: ev.inputsFound, probes: ev.probesSent, fc: ev.findings.length }; } },
  { key: 'login_bypass', title: 'Giriş Baypası (SQLi Göstergesi)', titleDe: 'Login-Bypass (SQLi-Indikator)', conf: 'Yüksek', run: async (h, de) => { const ev = await collectLoginBypassEvidence(h); return { rep: buildActiveCheckReport(ev, LOGIN_BYPASS_CFG, de), pages: ev.pagesScanned, inputs: ev.inputsFound, probes: ev.probesSent, fc: ev.findings.length }; } },
];

export function extractLevel(findings: string): Level {
  // (Çok-bölge) TR "Risk Seviyesi:" + DE "Risikostufe:"; risk kelimeleri iki dilde de tanınır.
  const m = findings.match(/(?:Risk Seviyesi|Risikostufe):\s*(Orta[-\s]?Y[uü]ksek|Y[uü]ksek|Orta|D[uü][sş][uü]k|Mittel[-\s]?Hoch|Hoch|Mittel|Niedrig)/i);
  if (!m) return 'low';
  const w = m[1].toLocaleLowerCase('tr');
  if (/orta[-\s]?y[uü]ksek|mittel[-\s]?hoch/.test(w)) return 'medium-high';
  if (/y[uü]ksek|hoch/.test(w)) return 'high';
  if (/orta|mittel/.test(w)) return 'medium';
  return 'low';
}
export function headlineOf(findings: string): string {
  const m = findings.match(/(?:Genel risk seviyesi|Gesamtrisikostufe):\s*[^\n]+?\s[—–-]\s([^\n]+)/i);
  return m ? m[1].trim().replace(/\*\*/g, '') : '';
}
// YÖNETİCİ ÖZETİ + GENEL DEĞERLENDİRME'yi cikar, detay bolumlerini dondur (## -> ### indir).
export function detailOnly(findings: string): string {
  const parts = findings.split(/(?=^## )/m);
  return parts.slice(2).join('').replace(/^## /gm, '### ').trim();
}

export async function generateBundleActiveVerifyReport(host: string, locale: string = 'tr'): Promise<{ findings: string; fixText: string } | null> {
  const de = locale === 'de';
  const t = (tr: string, deS: string) => (de ? deS : tr);
  const mt = (m: ActiveMember) => (de ? m.titleDe : m.title); // üye başlığı (locale'e göre)
  // Protokolü ÖNCE çöz: cache'i ısıtır (üye collector'lar cachedOriginUrl ile http-only'de de tarar)
  // + http-only ise https_missing bulgusu üretilir.
  const o = await resolveOrigin(host);
  const httpOnly = o.reachable && !o.httpsWorks;
  // (DÜRÜSTLÜK) Hedefe HİÇ ulaşılamadı -> "İncelenemedi" (ASLA null->Düşük fallback). Headless keşfi de atla.
  if (!o.reachable) return unscannableReport(host, t('aktif doğrulama kontrolleri', 'aktiven Verifizierungsprüfungen'), de);
  const runs = await Promise.all(ACTIVE_BUNDLE_MEMBERS.map((m) => m.run(host, de).catch(() => null)));
  // Hiçbir üye veri toplayamadıysa (hedefe ulaşılamadı) -> "İncelenemedi" (null->Düşük DEĞİL).
  if (runs.every((r) => !r || !r.rep)) return unscannableReport(host, t('aktif doğrulama kontrolleri', 'aktiven Verifizierungsprüfungen'), de);
  const surf = await discoverSurface(host); // cache'ten — benzersiz sayfa + SPA bilgisi

  const levels: Array<Level | null> = runs.map((r) => (r?.rep ? extractLevel(r.rep.findings) : null));
  const ranked = levels.map((lv, i) => ({ lv, i })).filter((x): x is { lv: Level; i: number } => x.lv !== null).sort((a, b) => levelRank(b.lv) - levelRank(a.lv));
  const worst: Level = ranked.length ? ranked[0].lv : 'low';
  const worstTitle = ranked.length ? mt(ACTIVE_BUNDLE_MEMBERS[ranked[0].i]) : '';
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
  const verdictWord = noRealTest ? t('İncelenemedi', 'Nicht prüfbar') : rw(verdictLevel, de);

  // --- ÜST ÖZET KUTUSU (ilk sayfa; gerçek N/M/P; input yoksa "gerçek prob yok" netliği) ---
  const box =
    t(`> ### Değerlendirme Özeti\n`, `> ### Bewertungsübersicht\n`) +
    t(`> **${ACTIVE_BUNDLE_MEMBERS.length} aktif güvenlik kontrol kategorisinin tamamı değerlendirildi.** `, `> **Alle ${ACTIVE_BUNDLE_MEMBERS.length} aktiven Sicherheitskontrollkategorien wurden bewertet.** `) +
    (noInputs
      ? t(`**${pagesScanned}** benzersiz sayfa/uç nokta tarandı; **test edilebilir giriş noktası (parametre/form/ID) bulunamadı** — bu nedenle gerçek doğrulama probu gönderilmedi (yalnızca ${totalProbes} erişilebilirlik/baseline isteği). Bu **zafiyet olmadığının kanıtı değildir**; kapsam sınırına bakınız.`, `**${pagesScanned}** einzigartige Seiten/Endpunkte wurden gescannt; **es wurde kein prüfbarer Eingabepunkt (Parameter/Formular/ID) gefunden** — daher wurde keine echte Verifizierungssonde gesendet (nur ${totalProbes} Erreichbarkeits-/Baseline-Anfragen). Dies **ist kein Beweis für das Fehlen von Schwachstellen**; siehe Geltungsbereichsgrenze.`) + spaHint(surf, de)
      : t(`**${pagesScanned}** benzersiz sayfa/uç nokta tarandı, **${totalInputs}** giriş noktası test edildi, toplam **${totalProbes}** istek gönderildi. `, `**${pagesScanned}** einzigartige Seiten/Endpunkte wurden gescannt, **${totalInputs}** Eingabepunkte getestet, insgesamt **${totalProbes}** Anfragen gesendet. `) +
        (confirmedHigh > 0
          ? t(`**${confirmedHigh}** kontrolde yüksek/kritik seviyeli zafiyet göstergesi bulundu (aşağıda detaylı).`, `In **${confirmedHigh}** Prüfungen wurde ein Schwachstellenindikator hoher/kritischer Stufe gefunden (unten im Detail).`)
          : t(`Doğrulanmış kritik/yüksek seviyeli bir zafiyet **tespit edilmedi**.`, `Es wurde **keine** verifizierte Schwachstelle kritischer/hoher Stufe festgestellt.`))) +
    t(`\n>\n> _Keşif yöntemi: ${discoveryMethodNote(surf, de)}_`, `\n>\n> _Entdeckungsmethode: ${discoveryMethodNote(surf, de)}_`);

  // --- KONTROL ÖZETİ TABLOSU (durum + güven) ---
  // Güven: SADECE gerçekten test çalıştıysa (input>0) seviye gösterilir; aksi halde NÖTR "Kapsam dışı"
  // (PDF renklendirme yalnız risk kelimelerini boyar; "Kapsam dışı" nötr kalır — yanıltıcı kırmızı yok).
  const statusOf = (r: MemberRun | null, lv: Level | null): string => {
    if (!r || !r.rep) return t('Veri toplanamadı', 'Keine Daten erhoben');
    if (r.fc > 0 && lv === 'high') return t('⚠ Zafiyet göstergesi', '⚠ Schwachstellenindikator');
    if (r.fc > 0) return t('⚠ Sınırlı gösterge', '⚠ Begrenzter Indikator');
    if (r.inputs === 0) return t('Giriş noktası yok (Kapsam dışı)', 'Kein Eingabepunkt (außerhalb des Umfangs)');
    return t('✓ Zafiyet kanıtı yok', '✓ Kein Schwachstellennachweis');
  };
  // (R6 GÜVEN/KAPSAM TUTARLILIĞI) Kontrol GERÇEK bir bulgu ürettiyse (fc>0) Güven "Kapsam dışı"
  // OLAMAZ — statusOf zaten "⚠ gösterge" der; ikisi çelişmesin. inputs=0 ama gözlemsel bulgu (fc>0)
  // olan İş Mantığı/Race gibi kontroller için de gerçek güven seviyesi gösterilir.
  const confCell = (r: MemberRun | null, conf: string): string => (r && r.rep && (r.inputs > 0 || r.fc > 0) ? sevDisp(conf, de) : t('Kapsam dışı', 'Außerhalb des Umfangs'));
  const tableRows = ACTIVE_BUNDLE_MEMBERS.map((m, i) => `| ${mt(m)} | ${statusOf(runs[i], levels[i])} | ${confCell(runs[i], m.conf)} |`).join('\n');
  const controlTable = t(`## KONTROL ÖZETİ\n\n| Kontrol | Sonuç | Güven |\n|---------|-------|-------|\n${tableRows}\n\n> Güven yalnızca gerçekten test çalıştırılan (giriş noktası bulunan) kontroller için gösterilir; giriş noktası bulunamayan kontroller **Kapsam dışı**dır. Test edilenlerde: SSRF/RCE dolaylı (zaman-tabanlı, OOB yok) → Orta; gözlemsel (Dosya Yükleme/İş Mantığı/Race) → Düşük; Enjeksiyon hata/yansıma-tabanlı → Yüksek.\n`, `## KONTROLLÜBERSICHT\n\n| Prüfung | Ergebnis | Konfidenz |\n|---------|-------|-------|\n${tableRows}\n\n> Die Konfidenz wird nur für tatsächlich ausgeführte Prüfungen (mit gefundenem Eingabepunkt) angezeigt; Prüfungen ohne Eingabepunkt sind **außerhalb des Umfangs**. Bei den getesteten: SSRF/RCE indirekt (zeitbasiert, kein OOB) → Mittel; beobachtend (Datei-Upload/Geschäftslogik/Race) → Niedrig; Injektion fehler-/reflexionsbasiert → Hoch.\n`);

  // --- YÖNETİCİ ÖZETİ ---
  const summary: string[] = [];
  summary.push(
    noRealTest
      ? t(`- **Genel risk seviyesi: İncelenemedi** — hedefe ulaşıldı ancak ${noInputs ? '**test edilebilir bir giriş noktası (parametre/form/ID) bulunamadı**' : `kontrollerin çoğu (${notTestable}/${ACTIVE_BUNDLE_MEMBERS.length}) veri toplayamadı veya test edilebilir yüzey bulamadı`}; gerçek doğrulama probu çalıştırılamadı. Bu sonuç sitenin **güvenli olduğu anlamına GELMEZ** — yalnızca bu paketin bu hedefte test edilebilir bir yüzey bulamadığını gösterir.`, `- **Gesamtrisikostufe: Nicht prüfbar** — das Ziel wurde erreicht, jedoch ${noInputs ? '**wurde kein prüfbarer Eingabepunkt (Parameter/Formular/ID) gefunden**' : `konnten die meisten Prüfungen (${notTestable}/${ACTIVE_BUNDLE_MEMBERS.length}) keine Daten erheben oder keine prüfbare Oberfläche finden`}; es konnte keine echte Verifizierungssonde ausgeführt werden. Dieses Ergebnis bedeutet **NICHT, dass die Website sicher ist** — es zeigt lediglich, dass dieses Paket auf diesem Ziel keine prüfbare Oberfläche gefunden hat.`)
      : httpOnly && worst === 'low'
      ? t(`- **Genel risk seviyesi: Yüksek** — hedef HTTPS desteklemiyor (şifresiz iletişim); bu tek başına yüksek riskli bir bulgudur. Aktif kontroller http:// üzerinden yürütüldü ve ek doğrulanmış kritik/yüksek zafiyet öne çıkmadı.`, `- **Gesamtrisikostufe: Hoch** — das Ziel unterstützt kein HTTPS (unverschlüsselte Kommunikation); dies ist für sich genommen ein Befund mit hohem Risiko. Die aktiven Prüfungen wurden über http:// durchgeführt und es trat keine weitere verifizierte kritische/hohe Schwachstelle hervor.`)
      : verdictLevel === 'low'
      ? t(`- **Genel risk seviyesi: Düşük** — ${ACTIVE_BUNDLE_MEMBERS.length} kontrol kategorisinin tamamı değerlendirildi; doğrulanmış kritik/yüksek seviyeli bir zafiyet öne çıkmadı.`, `- **Gesamtrisikostufe: Niedrig** — alle ${ACTIVE_BUNDLE_MEMBERS.length} Kontrollkategorien wurden bewertet; es trat keine verifizierte Schwachstelle kritischer/hoher Stufe hervor.`)
      : t(`- **Genel risk seviyesi: ${RISK_WORD[verdictLevel]}** — en yüksek risk **${worstTitle || 'HTTPS eksikliği'}** alanında${worstHl ? ` (${worstHl})` : ''}.`, `- **Gesamtrisikostufe: ${RISK_WORD_DE[verdictLevel]}** — das höchste Risiko liegt im Bereich **${worstTitle || 'HTTPS-Mangel'}**${worstHl ? ` (${worstHl})` : ''}.`),
  );
  // DÜRÜSTLÜK (dinamik — gerçek en yüksek ciddiyetli kontrolden türer): bu paketin kimlik-doğrulamasız
  // kapsam sınırını AÇIKÇA belirt + en güçlü sonucu (bulgu varsa) veya "zafiyet bulunamadı"yı bildir.
  const anyFinding = runs.some((r) => r?.fc && r.fc > 0);
  const strongest = anyFinding && worstTitle
    ? t(`Bu taramada en güçlü sonuç **${worstTitle}** alanında tespit edilmiştir.`, `Das stärkste Ergebnis dieses Scans wurde im Bereich **${worstTitle}** festgestellt.`)
    : t('Bu taramada doğrulanmış bir zafiyet tespit edilmemiştir.', 'In diesem Scan wurde keine verifizierte Schwachstelle festgestellt.');
  summary.push(
    t(`- **Kapsam dürüstlüğü:** Bu paket, kimlik doğrulaması **gerektirmeyen dış yüzeye** odaklanır — herkese açık uç noktalar (açık formlar/API'lar, arama, login/kayıt akışının kendisi). IDOR / İş Mantığı / Race-Mass-Assignment kontrolleri **yalnızca login-öncesi erişilebilir yüzeyde** (ör. genel API'lar, herkese açık id-tabanlı uç noktalar) çalışır; bu nedenle bu kategorilerde bazı hedeflerde **sınırlı veya "İncelenemedi"** sonuç normal ve beklenendir (siteye özgü yüzey azlığından; motor eksikliğinden değil). Login-**sonrası** oturum içi derin yetkilendirme/iş mantığı zafiyetleri kapsam dışıdır, **Tam Kapsamlı Pentest**'te ele alınır. ${strongest}`, `- **Geltungsbereich-Ehrlichkeit:** Dieses Paket konzentriert sich auf die **externe Oberfläche ohne Authentifizierung** — öffentlich zugängliche Endpunkte (offene Formulare/APIs, Suche, der Login-/Registrierungsablauf selbst). Die Prüfungen IDOR / Geschäftslogik / Race-Mass-Assignment laufen **nur auf der vor dem Login erreichbaren Oberfläche** (z. B. öffentliche APIs, öffentlich zugängliche ID-basierte Endpunkte); daher sind in diesen Kategorien bei manchen Zielen **begrenzte oder „Nicht prüfbar"**-Ergebnisse normal und zu erwarten (wegen der zielspezifisch geringen Oberfläche; nicht wegen fehlender Engine). Tiefe Autorisierungs-/Geschäftslogik-Schwachstellen innerhalb der Sitzung **nach** dem Login sind außerhalb des Umfangs und werden im **Umfassenden Pentest** behandelt. ${strongest}`),
  );
  // (BÖLÜM B) API yüzeyi şeffaflığı: spec bulundu mu + keşfedilen ama kimlik-doğrulama-kilitli uç sayısı.
  const apiSpecN = surf.apiSpecFound ? surf.apiSpecPaths ?? 0 : 0;
  const apiGatedN = surf.apiAuthGated ?? 0;
  if (apiSpecN > 0 || apiGatedN > 0) {
    const parts: string[] = [];
    if (apiSpecN > 0) parts.push(t(`OpenAPI/Swagger şeması bulundu ve **${apiSpecN}** uç noktası keşif kapsamına alındı`, `Ein OpenAPI/Swagger-Schema wurde gefunden und **${apiSpecN}** Endpunkte in den Entdeckungsumfang aufgenommen`));
    if (apiGatedN > 0) parts.push(t(`**${apiGatedN}** API uç noktası keşfedildi ancak **kimlik doğrulama gerektiriyor** (401/403) — kimlik-doğrulamalı derin test bu paketin kapsamı dışında olduğundan probe edilmedi (Tam Kapsamlı Pentest önerilir)`, `**${apiGatedN}** API-Endpunkte wurden entdeckt, erfordern aber **eine Authentifizierung** (401/403) — da der authentifizierte Tiefentest außerhalb des Umfangs dieses Pakets liegt, wurden sie nicht sondiert (Umfassender Pentest empfohlen)`));
    summary.push(t(`- **API saldırı yüzeyi:** ${parts.join('; ')}.`, `- **API-Angriffsfläche:** ${parts.join('; ')}.`));
  }
  ACTIVE_BUNDLE_MEMBERS.forEach((m, i) => {
    const r = runs[i]; const lv = levels[i];
    if (!r || !r.rep || !lv) { summary.push(t(`- **${mt(m)}:** veri toplanamadı (hedefe ulaşılamadı).`, `- **${mt(m)}:** keine Daten erhoben (Ziel nicht erreichbar).`)); return; }
    const hl = headlineOf(r.rep.findings);
    summary.push(`- **${mt(m)}:** ${rw(lv, de)}${hl ? ` — ${hl}` : ''}`);
  });
  summary.push(
    noInputs
      ? t(`- **Şeffaflık:** ${dataOk}/${ACTIVE_BUNDLE_MEMBERS.length} kontrol çalıştı; **${pagesScanned}** benzersiz sayfa tarandı ancak **test edilebilir giriş noktası bulunamadı** — gerçek doğrulama probu gönderilmedi (yalnızca ${totalProbes} baseline erişilebilirlik isteği). Bu, zafiyet olmadığının kanıtı değildir.`, `- **Transparenz:** ${dataOk}/${ACTIVE_BUNDLE_MEMBERS.length} Prüfungen liefen; **${pagesScanned}** einzigartige Seiten wurden gescannt, aber **es wurde kein prüfbarer Eingabepunkt gefunden** — es wurde keine echte Verifizierungssonde gesendet (nur ${totalProbes} Baseline-Erreichbarkeitsanfragen). Dies ist kein Beweis für das Fehlen von Schwachstellen.`) + spaHint(surf, de)
      : t(`- **Şeffaflık:** ${dataOk}/${ACTIVE_BUNDLE_MEMBERS.length} kontrol veri toplayabildi; **${pagesScanned}** benzersiz sayfa, **${totalInputs}** giriş noktası${surf.method === 'headless' ? ' (JS render sırasında gözlemlenen API uçları dâhil)' : ''}, **${totalProbes}** istek.${surf.method === 'headless' && surf.apiWrites.length ? ` Ayrıca **${surf.apiWrites.length}** durum-değiştiren API ucu (ör. login/sepet/sipariş) gözlemlendi ancak güvenlik gereği **probe edilmedi**.` : ''} SSRF/RCE tespitleri OOB altyapısı olmadan zaman-tabanlı/dolaylı (orta güven); gözlemsel kontroller (Dosya Yükleme/İş Mantığı/Race) kesin doğrulama için manuel test gerektirir.`, `- **Transparenz:** ${dataOk}/${ACTIVE_BUNDLE_MEMBERS.length} Prüfungen konnten Daten erheben; **${pagesScanned}** einzigartige Seiten, **${totalInputs}** Eingabepunkte${surf.method === 'headless' ? ' (einschließlich der beim JS-Rendering beobachteten API-Endpunkte)' : ''}, **${totalProbes}** Anfragen.${surf.method === 'headless' && surf.apiWrites.length ? ` Zudem wurden **${surf.apiWrites.length}** zustandsändernde API-Endpunkte (z. B. Login/Warenkorb/Bestellung) beobachtet, aber aus Sicherheitsgründen **nicht sondiert**.` : ''} SSRF/RCE-Erkennungen sind ohne OOB-Infrastruktur zeitbasiert/indirekt (mittlere Konfidenz); beobachtende Prüfungen (Datei-Upload/Geschäftslogik/Race) erfordern für eine sichere Verifizierung einen manuellen Test.`),
  );
  summary.push(t('- **Önerilen ilk adım:** Çalıştırılan kontrollerdeki bulguları giderin; hazır adımlar "AI Çözüm Önerileri" bölümünde.', '- **Empfohlener erster Schritt:** Beheben Sie die Befunde der ausgeführten Prüfungen; fertige Schritte im Abschnitt „KI-Lösungsvorschläge".'));

  const genel =
    (noRealTest
      ? t(`${ACTIVE_BUNDLE_MEMBERS.length} aktif doğrulama kontrol kategorisi denendi ancak bu hedefte **test edilebilir bir yüzey bulunamadığından** gerçek doğrulama probu çalıştırılamadı; sonuç **değerlendirilemedi** ("güvenli/temiz" anlamına gelmez).`, `${ACTIVE_BUNDLE_MEMBERS.length} aktive Verifizierungskontrollkategorien wurden versucht, aber da auf diesem Ziel **keine prüfbare Oberfläche gefunden wurde**, konnte keine echte Verifizierungssonde ausgeführt werden; das Ergebnis konnte **nicht bewertet werden** (bedeutet nicht „sicher/sauber").`)
      : worst === 'low'
      ? t(`${ACTIVE_BUNDLE_MEMBERS.length} aktif doğrulama kontrol kategorisinin tamamı değerlendirildi; doğrulanmış kritik/yüksek seviyeli bir zafiyet öne çıkmadı.`, `Alle ${ACTIVE_BUNDLE_MEMBERS.length} aktiven Verifizierungskontrollkategorien wurden bewertet; es trat keine verifizierte Schwachstelle kritischer/hoher Stufe hervor.`)
      : t(`Çalıştırılan kontrollerde en yüksek risk **${worstTitle}** alanında${worstHl ? ` (${worstHl})` : ''} tespit edildi; öncelikli olarak giderilmesi/doğrulanması önerilir.`, `Bei den ausgeführten Prüfungen wurde das höchste Risiko im Bereich **${worstTitle}**${worstHl ? ` (${worstHl})` : ''} festgestellt; eine vorrangige Behebung/Verifizierung wird empfohlen.`)) +
    (noInputs
      ? t(` ${pagesScanned} benzersiz sayfa/uç nokta tarandı; test edilebilir bir giriş noktası (parametre/form/ID) bulunamadığından gerçek doğrulama probu gönderilmedi (yalnızca baseline istekleri). Aşağıda her kontrol ayrı ayrı raporlanmıştır.`, ` ${pagesScanned} einzigartige Seiten/Endpunkte wurden gescannt; da kein prüfbarer Eingabepunkt (Parameter/Formular/ID) gefunden wurde, wurde keine echte Verifizierungssonde gesendet (nur Baseline-Anfragen). Nachfolgend ist jede Prüfung einzeln aufgeführt.`)
      : t(` ${pagesScanned} benzersiz sayfa/uç nokta tarandı, ${totalInputs} giriş noktasında toplam ${totalProbes} istek gönderildi. SSRF/RCE zaman-tabanlı/dolaylıdır. Aşağıda her kontrol ayrı ayrı raporlanmıştır.`, ` ${pagesScanned} einzigartige Seiten/Endpunkte wurden gescannt, an ${totalInputs} Eingabepunkten wurden insgesamt ${totalProbes} Anfragen gesendet. SSRF/RCE sind zeitbasiert/indirekt. Nachfolgend ist jede Prüfung einzeln aufgeführt.`));

  const sections = ACTIVE_BUNDLE_MEMBERS.map((m, i) => {
    const r = runs[i];
    if (!r || !r.rep) return t(`## ${mt(m)}\n\n> Bu kontrol için veri toplanamadı (hedefe ulaşılamadı); diğer kontroller raporlanmıştır.\n`, `## ${mt(m)}\n\n> Für diese Prüfung konnten keine Daten erhoben werden (Ziel nicht erreichbar); die übrigen Prüfungen wurden aufgeführt.\n`);
    return `## ${mt(m)}\n\n${detailOnly(r.rep.findings)}\n`;
  }).join('\n');

  // (DÜRÜSTLÜK) http-only: HTTPS eksikliği ŞİDDET-kolonlu tabloyla -> Master + Dağılıma girer.
  const httpsFindingSection = httpOnly
    ? t(`## TESPİT EDİLEN RİSKLER\n\n| Bulgu | Şiddet | Açıklama |\n|-------|--------|----------|\n| HTTPS desteklenmiyor (şifresiz iletişim) | Yüksek | Hedef HTTPS'e yanıt vermiyor; tüm trafik şifresiz (düz metin) taşınıyor — dinlenebilir/değiştirilebilir, oturum/şifre çalınabilir. Aktif kontroller http:// üzerinden yürütüldü. Çözüm: geçerli TLS sertifikası + HTTP→HTTPS yönlendirme + HSTS. |\n\n`, `## FESTGESTELLTE RISIKEN\n\n| Befund | Schweregrad | Beschreibung |\n|-------|--------|----------|\n| HTTPS wird nicht unterstützt (unverschlüsselte Kommunikation) | Hoch | Das Ziel antwortet nicht über HTTPS; der gesamte Verkehr wird unverschlüsselt (Klartext) übertragen — mitlesbar/veränderbar, Sitzungen/Passwörter können gestohlen werden. Die aktiven Prüfungen wurden über http:// durchgeführt. Lösung: gültiges TLS-Zertifikat + HTTP→HTTPS-Umleitung + HSTS. |\n\n`)
    : '';
  const httpsSummaryNote = httpOnly ? t('\n- ⚠️ **HTTPS desteklenmiyor:** Hedef HTTPS (443) üzerinden yanıt vermedi; aktif doğrulama http:// üzerinden yürütüldü. Şifresiz iletişim başlı başına ciddi bir bulgudur.', '\n- ⚠️ **HTTPS wird nicht unterstützt:** Das Ziel hat nicht über HTTPS (443) geantwortet; die aktive Verifizierung wurde über http:// durchgeführt. Unverschlüsselte Kommunikation ist für sich genommen ein ernster Befund.') : '';
  const genelHttps = httpOnly ? t('Bu hedef HTTPS üzerinden yanıt vermiyor; iletişim şifresiz (düz metin) taşınıyor — öncelikli olarak HTTPS’e geçilmelidir. ', 'Dieses Ziel antwortet nicht über HTTPS; die Kommunikation wird unverschlüsselt (Klartext) übertragen — vorrangig sollte auf HTTPS umgestellt werden. ') : '';

  // (10/10 Bölüm 3 — POZİTİF GÜVENCE) Diğer 4 pakete AYNI üç-durum formatı, Aktif Doğrulama'ya özel:
  // her kontrol türü için "kaç giriş noktası denendi, kaçında kanıt bulunamadı". SADECE gerçek sayaçlardan.
  const assuranceRows = ACTIVE_BUNDLE_MEMBERS.map((m, i) => {
    const r = runs[i]; const lv = levels[i];
    let sonuc: string;
    if (!r || !r.rep) sonuc = t('⚠️ İncelenemedi (veri toplanamadı — “temiz” DEĞİL)', '⚠️ Nicht prüfbar (keine Daten erhoben — NICHT „sauber")');
    else if (r.fc > 0 && lv === 'high') sonuc = t(`⚠️ Bulgu var (${r.fc} — zafiyet göstergesi; yukarıda)`, `⚠️ Befund vorhanden (${r.fc} — Schwachstellenindikator; oben)`);
    else if (r.fc > 0) sonuc = t(`⚠️ Bulgu var (${r.fc} — sınırlı/dolaylı gösterge; yukarıda)`, `⚠️ Befund vorhanden (${r.fc} — begrenzter/indirekter Indikator; oben)`);
    else if (r.inputs > 0) sonuc = t(`✅ Temiz (${r.inputs} giriş noktası denendi, kanıt bulunamadı)`, `✅ Sauber (${r.inputs} Eingabepunkte versucht, kein Nachweis gefunden)`);
    else sonuc = t('⚠️ İncelenemedi (test edilebilir giriş noktası bulunamadı — “temiz” DEĞİL)', '⚠️ Nicht prüfbar (kein prüfbarer Eingabepunkt gefunden — NICHT „sauber")');
    return `| ${mt(m)} | ${r ? r.inputs : '—'} | ${r ? r.probes : '—'} | ${sonuc} |`;
  }).join('\n');
  // (FORM-POST ŞEFFAFLIĞI) Kaç form gerçek POST ile test edildi, kaçı YASAK listesi gereği atlandı (neden).
  const injRun = runs[0]; // injection_verify = 0. index
  const formsTested = injRun?.formsTested ?? 0;
  const formsSkipped = injRun?.formsSkipped ?? [];
  const formLine =
    (formsTested > 0 || formsSkipped.length > 0)
      ? t(`\n**Form POST testi:** **${formsTested}** forma (login/arama/filtre vb.) gerçek POST payload’ı gönderildi. `, `\n**Formular-POST-Test:** An **${formsTested}** Formulare (Login/Suche/Filter usw.) wurde eine echte POST-Payload gesendet. `) +
        (formsSkipped.length
          ? t(`**${formsSkipped.length}** form ise güvenlik gereği (kalıcı/geri-alınamaz yan etki riski) gerçek POST testinden **hariç tutuldu**: ${formsSkipped.map((f) => `\`${f.action}\` (${f.reason})`).join('; ')}. Bu formlar "kanıtla — istismar etme" ilkesi gereği hiç POST edilmez; kimlik-doğrulamalı/kapsam-sözleşmeli test **Tam Kapsamlı Pentest** kapsamındadır.`, `**${formsSkipped.length}** Formulare wurden aus Sicherheitsgründen (Risiko dauerhafter/nicht rückgängig zu machender Nebenwirkungen) vom echten POST-Test **ausgeschlossen**: ${formsSkipped.map((f) => `\`${f.action}\` (${f.reason})`).join('; ')}. Diese Formulare werden gemäß dem Prinzip „nachweisen — nicht ausnutzen" nie per POST angesprochen; der authentifizierte/vertraglich abgesteckte Test gehört zum **Umfassenden Pentest**.`)
          : t(`YASAK listesine (yorum/iletişim/kayıt/parola-sıfırlama/ödeme/abonelik) giren form saptanmadı.`, `Es wurde kein Formular festgestellt, das auf der Sperrliste steht (Kommentar/Kontakt/Registrierung/Passwort-Reset/Zahlung/Abonnement).`))
      : '';
  const assuranceSection =
    t(`## POZİTİF GÜVENCE — DENENEN AKTİF DOĞRULAMA YÖNTEMLERİ\n\n`, `## POSITIVE ZUSICHERUNG — VERSUCHTE AKTIVE VERIFIZIERUNGSMETHODEN\n\n`) +
    t(`Bulgu çıkmayan kontroller de dâhil, ${ACTIVE_BUNDLE_MEMBERS.length} aktif kontrol kategorisinin her biri keşfedilen yüzeyde gerçekten çalıştırıldı (toplam **${totalProbes}** istek, **${pagesScanned}** benzersiz sayfa). Aşağıdaki tablo, "bulgu yok" sonuçlarını da — kaç giriş noktası denendi, kaçında kanıt bulunamadı — şeffaf gösterir:\n\n`, `Einschließlich der Prüfungen ohne Befund wurde jede der ${ACTIVE_BUNDLE_MEMBERS.length} aktiven Kontrollkategorien tatsächlich auf der entdeckten Oberfläche ausgeführt (insgesamt **${totalProbes}** Anfragen, **${pagesScanned}** einzigartige Seiten). Die folgende Tabelle zeigt auch die „kein Befund"-Ergebnisse transparent — wie viele Eingabepunkte versucht wurden und bei wie vielen kein Nachweis gefunden wurde:\n\n`) +
    t(`| Kontrol | Denenen giriş noktası | Gönderilen istek | Sonuç |\n|---------|-----------------------|------------------|-------|\n${assuranceRows}\n${formLine}\n\n`, `| Prüfung | Versuchte Eingabepunkte | Gesendete Anfragen | Ergebnis |\n|---------|-----------------------|------------------|-------|\n${assuranceRows}\n${formLine}\n\n`) +
    t(`> **Üç-durum ayrımı (dürüstlük):** ✅ *Temiz* = kontrol çalıştı, kanıt bulunamadı · ⚠️ *Bulgu var* = yukarıda detaylı · ⚠️ *İncelenemedi* = test edilebilir giriş noktası bulunamadı (güvenli anlamına GELMEZ).\n\n`, `> **Drei-Zustands-Unterscheidung (Ehrlichkeit):** ✅ *Sauber* = Prüfung lief, kein Nachweis gefunden · ⚠️ *Befund vorhanden* = oben im Detail · ⚠️ *Nicht prüfbar* = kein prüfbarer Eingabepunkt gefunden (bedeutet NICHT sicher).\n\n`) +
    t(`### Bu paket NE değerlendirir, NE değerlendirmez\n\n`, `### Was dieses Paket bewertet — und was NICHT\n\n`) +
    t(`**EDER ("kanıtla — istismar etme" ilkesiyle; zararsız, veri-değiştirmeyen problar):** SQLi/XSS enjeksiyonu, yetkisiz erişim (IDOR), SSRF, dosya yükleme, iş mantığı, race/mass-assignment ve RCE/komut enjeksiyonu göstergeleri — kimlik doğrulaması **gerektirmeyen** yüzeyde, keşfedilen ${pagesScanned} sayfada.\n\n`, `**BEWERTET (nach dem Prinzip „nachweisen — nicht ausnutzen"; harmlose, nicht datenverändernde Sonden):** Indikatoren für SQLi/XSS-Injektion, unbefugten Zugriff (IDOR), SSRF, Datei-Upload, Geschäftslogik, Race/Mass-Assignment und RCE/Befehlsinjektion — auf der Oberfläche **ohne** Authentifizierung, auf den entdeckten ${pagesScanned} Seiten.\n\n`) +
    t(`**ETMEZ:** Veri değiştiren/silen istismar, ödeme tamamlama veya gerçek RCE çalıştırma **yapılmaz** (yalnızca gösterge/kanıt toplanır). IDOR / İş Mantığı / Race-Mass-Assignment kontrolleri **yalnızca login-öncesi erişilebilir yüzeyde** çalışır; **login-SONRASI** oturum içi derin yetkilendirme/yetki-yükseltme/iş-mantığı zafiyetleri bu paketin **dışındadır** — bunlar **Tam Kapsamlı Pentest** (kimlik-doğrulamalı, kapsam sözleşmeli) kapsamındadır. Bu nedenle bu üç kategoride bazı hedeflerde **sınırlı veya "İncelenemedi"** sonuç normal ve beklenendir (siteye özgü yüzey azlığından; motor eksikliğinden değil). Bir kontrolde "bulgu yok", aktif istismar bilinçli olarak sınırlı/pasif-güvenli tutulduğu için **güvenli olduğunu KANITLAMAZ**.\n\n`, `**BEWERTET NICHT:** Datenverändernde/-löschende Ausnutzung, Zahlungsabschluss oder echte RCE-Ausführung werden **nicht** durchgeführt (nur Indikatoren/Nachweise werden gesammelt). Die Prüfungen IDOR / Geschäftslogik / Race-Mass-Assignment laufen **nur auf der vor dem Login erreichbaren Oberfläche**; tiefe Autorisierungs-/Rechteausweitungs-/Geschäftslogik-Schwachstellen innerhalb der Sitzung **nach** dem Login liegen **außerhalb** dieses Pakets — sie gehören zum **Umfassenden Pentest** (authentifiziert, vertraglich abgesteckt). Daher sind in diesen drei Kategorien bei manchen Zielen **begrenzte oder „Nicht prüfbar"**-Ergebnisse normal und zu erwarten (wegen der zielspezifisch geringen Oberfläche; nicht wegen fehlender Engine). „Kein Befund" in einer Prüfung **BEWEIST NICHT**, dass sie sicher ist, da die aktive Ausnutzung bewusst begrenzt/passiv-sicher gehalten wird.\n\n`);

  const findings =
    `${box}\n\n` +
    `## ${t('YÖNETİCİ ÖZETİ', 'MANAGEMENTZUSAMMENFASSUNG')}\n\n${summary.join('\n')}${httpsSummaryNote}\n\n` +
    `## ${t('GENEL DEĞERLENDİRME', 'GESAMTBEWERTUNG')}\n\n**${t('Risk Seviyesi', 'Risikostufe')}: ${verdictWord}**\n\n${genelHttps}${genel}\n\n` +
    `${httpsFindingSection}${controlTable}\n${assuranceSection}` +
    `${sections}`;

  const fixParts = ACTIVE_BUNDLE_MEMBERS.map((m, i) => {
    const r = runs[i];
    if (!r || !r.rep || !r.rep.fixText.trim()) return '';
    return `### ${mt(m)}\n\n${r.rep.fixText.trim()}`;
  }).filter(Boolean);
  const fixText =
    t('Bu bölüm, çalıştırılan aktif doğrulama kontrollerinde tespit edilen bulgular için düzeltme önerileri içerir.\n\n', 'Dieser Abschnitt enthält Behebungsempfehlungen für die in den ausgeführten aktiven Verifizierungsprüfungen festgestellten Befunde.\n\n') +
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
  // (Çok-bölge) Opsiyonel Almanca karşılıklar — yalnız de=true iken OKUNUR; yoksa TR'ye düşer (TR byte-aynı kalır).
  whatCheckedDe?: string[];
  confidenceNoteDe?: string;
  fixTitleDe?: string;
  fixFoundDe?: string[];
  fixCleanDe?: string[];
  cleanGenelDe?: string;
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
const SIDE_EFFECT_WORD_DE: Record<string, string> = { none: 'keine', possible: 'möglich', confirmed: 'bestätigt' };

function buildActiveCheckReport(ev: ActiveCheckEvidence, cfg: CheckCfg, de = false): { findings: string; fixText: string } | null {
  if (!ev.ok) return null;
  const t = (tr: string, deS: string) => (de ? deS : tr);
  // (Çok-bölge) CFG'de Almanca alan varsa onu, yoksa TR'ye düş (Almanca eksik parça sadece TR basar).
  const wc = de ? (cfg.whatCheckedDe ?? cfg.whatChecked) : cfg.whatChecked;
  const confNoteStr = de ? (cfg.confidenceNoteDe ?? cfg.confidenceNote) : cfg.confidenceNote;
  const fixTitle = de ? (cfg.fixTitleDe ?? cfg.fixTitle) : cfg.fixTitle;
  const fixFound = de ? (cfg.fixFoundDe ?? cfg.fixFound) : cfg.fixFound;
  const fixClean = de ? (cfg.fixCleanDe ?? cfg.fixClean) : cfg.fixClean;
  const cleanGenel = de ? (cfg.cleanGenelDe ?? cfg.cleanGenel) : cfg.cleanGenel;
  const level = levelFromFindings(ev.findings);
  const has = ev.findings.length > 0;
  const noSurface = level === 'low' && !has && ev.inputsFound === 0;

  const bullets = [
    noSurface
      ? noTestableSurfaceBullet(t('bu kontrol için **test edilebilir bir giriş/uç nokta saptanmadı**', 'für diese Prüfung **kein prüfbarer Eingabe-/Endpunkt festgestellt wurde**'), de)
      : t(
          `- **Genel risk seviyesi: ${RISK_WORD[level]}** — ${level === 'high' ? 'aktif doğrulama ile zafiyet göstergesi KANITLANDI.' : (level === 'medium-high' || level === 'medium') ? 'dikkat gerektiren bir gösterge bulundu (manuel doğrulama önerilir).' : has ? 'yalnızca düşük-önemli gözlem(ler) bulundu.' : 'belirgin bir zafiyet göstergesi bulunamadı.'}`,
          `- **Gesamtrisikostufe: ${RISK_WORD_DE[level]}** — ${level === 'high' ? 'mittels aktiver Verifizierung wurde ein Schwachstellenindikator NACHGEWIESEN.' : (level === 'medium-high' || level === 'medium') ? 'ein aufmerksamkeitsbedürftiger Indikator wurde gefunden (manuelle Verifizierung empfohlen).' : has ? 'es wurden nur geringfügige Beobachtung(en) gefunden.' : 'es wurde kein eindeutiger Schwachstellenindikator gefunden.'}`,
        ),
    t(
      `- Taranan sayfa/uç nokta: **${ev.pagesScanned}** · İncelenen giriş/uç nokta: **${ev.inputsFound}** · Gönderilen probe: **${ev.probesSent}** · Bulgu: ${ev.findings.length}.`,
      `- Gescannte Seiten/Endpunkte: **${ev.pagesScanned}** · Untersuchte Eingabe-/Endpunkte: **${ev.inputsFound}** · Gesendete Sonden: **${ev.probesSent}** · Befunde: ${ev.findings.length}.`,
    ),
    t('- **Önerilen ilk adım:** ', '- **Empfohlener erster Schritt:** ') + (has ? t('Bulguları giderin; hazır adımlar "AI Çözüm Önerileri" bölümünde.', 'Beheben Sie die Befunde; fertige Schritte im Abschnitt „KI-Lösungsvorschläge".') : t('Sertleştirme adımları "AI Çözüm Önerileri" bölümünde.', 'Härtungsschritte im Abschnitt „KI-Lösungsvorschläge".')),
  ];
  const genel = has
    ? (level === 'high' ? t('Aktif-hafif doğrulama ile bir zafiyet göstergesi tespit edildi; öncelikli olarak giderilmesi/doğrulanması önerilir.', 'Mittels aktiv-leichter Verifizierung wurde ein Schwachstellenindikator festgestellt; eine vorrangige Behebung/Verifizierung wird empfohlen.') : t('Dikkat gerektiren bir gösterge bulundu; bağlama göre manuel doğrulama önerilir.', 'Ein aufmerksamkeitsbedürftiger Indikator wurde gefunden; kontextabhängige manuelle Verifizierung wird empfohlen.'))
    : cleanGenel;

  const method = `## ${t('NE KONTROL EDİLDİ', 'WAS WURDE GEPRÜFT')}\n\n` + wc.map((l) => `- ${l}`).join('\n') + '\n\n';
  const table = has
    ? t('## BULGULAR\n\n| Giriş/Uç Nokta | Teknik | Kanıt | Güven | Yan-etki riski | Ciddiyet |\n|----------------|--------|-------|-------|----------------|----------|\n', '## BEFUNDE\n\n| Eingabe-/Endpunkt | Technik | Nachweis | Konfidenz | Nebenwirkungsrisiko | Schweregrad |\n|----------------|--------|-------|-------|----------------|----------|\n') +
      ev.findings.map((f) => `| ${f.inputPoint} | ${f.technique} | ${f.evidence.replace(/\|/g, '\\|')} | ${f.confidence === 'high' ? t('Yüksek', 'Hoch') : f.confidence === 'medium' ? t('Orta', 'Mittel') : t('Düşük', 'Niedrig')} | ${de ? SIDE_EFFECT_WORD_DE[f.sideEffectRisk] : SIDE_EFFECT_WORD[f.sideEffectRisk]} | ${sevDisp(RISK_WORD[f.severity], de)} |`).join('\n') + '\n\n'
    : t('## BULGULAR\n\nGönderilen zararsız problara karşı belirgin bir zafiyet göstergesi bulunamadı.\n\n', '## BEFUNDE\n\nGegen die gesendeten harmlosen Sonden wurde kein eindeutiger Schwachstellenindikator gefunden.\n\n');
  const confNote = confNoteStr ? `> ${confNoteStr}\n\n` : '';
  const sideEffectNote = ev.findings.some((f) => f.sideEffectRisk !== 'none')
    ? t('> **Yan etki uyarısı:** Bu kontroldeki bir/birkaç probe, hedefte bir kayıt/dosya oluşturmuş **olabilir** (yan-etki riski "olası" olarak işaretlenenler). Bu, "kanıtla — istismar etme" ilkesi gereği tek seferlik ve zararsız içerikle yapılmıştır; yine de kontrol edip gerekirse temizlemeniz önerilir.\n\n', '> **Nebenwirkungshinweis:** Eine/mehrere Sonden dieser Prüfung **könnten** am Ziel einen Datensatz/eine Datei erzeugt haben (die mit Nebenwirkungsrisiko „möglich" markierten). Dies erfolgte nach dem Prinzip „nachweisen — nicht ausnutzen" einmalig und mit harmlosem Inhalt; dennoch wird empfohlen, dies zu prüfen und bei Bedarf zu bereinigen.\n\n')
    : '';
  const notes = ev.notes.length ? ev.notes.map((n) => `> ${n}`).join('\n') + '\n\n' : '';
  const findings = assemble(level, bullets, genel, `${method}${table}${confNote}${sideEffectNote}${notes}${scopeNote(de)}\n`, noSurface, de);

  const fixText = has
    ? `### ${fixTitle} — ${t('düzeltme', 'Behebung')}\n\n` + fixFound.map((l) => `- ${l}`).join('\n')
    : `### ${fixTitle} — ${t('proaktif sertleştirme', 'proaktive Härtung')}\n\n` + fixClean.map((l) => `- ${l}`).join('\n');
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
  whatCheckedDe: [
    'An den Login-Endpunkt wurden zuerst **ungültige Zugangsdaten** (Kontrolle) gesendet; anschließend wurden klassische SQLi-Payloads (`\' OR \'1\'=\'1` usw.) erprobt und beobachtet, ob — im Gegensatz zur Kontrolle — eine Sitzung/ein Erfolg (Token/2xx) zurückkam.',
    'Der Login-POST ist bereits ein erlaubter Ablauf; dies ist eine EINZIGE, harmlose Beobachtung.',
    '⚠️ KEINE Sitzungsübernahme/Ausnutzung — nur die Beobachtung, „ob ein Indikator für eine Authentifizierungsumgehung vorliegt".',
  ],
  confidenceNoteDe: 'Der Indikator beruht auf dem Vergleich mit dem Kontrollversuch; eine sichere Verifizierung erfordert einen manuellen Test.',
  fixTitleDe: 'Login-Bypass / SQL-Injektion',
  fixFoundDe: [
    'Verwenden Sie in Authentifizierungsabfragen **parametrisierte Abfragen / Prepared Statements**; fügen Sie Benutzereingaben niemals direkt in SQL ein.',
    'Eingabevalidierung + sichere ORM-APIs; geben Sie bei fehlerhaftem Login eine einheitliche Fehlermeldung zurück.',
  ],
  fixCleanDe: ['Wenden Sie parametrisierte Abfragen + Eingabevalidierung an (proaktiv).'],
  cleanGenelDe: 'Es wurde kein Login-Bypass-(SQLi-)Indikator gefunden oder es gab keinen prüfbaren Login-Endpunkt.',
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
  whatCheckedDe: [
    'Parameter, die einen serverseitigen Fetch auslösen können (url/webhook/image/redirect usw.), wurden identifiziert.',
    'Diesen Parametern wurde eine **in unserer Kontrolle** befindliche, verzögerte Echo-URL übergeben; die Antwortzeit des Ziels wurde mit der Baseline verglichen (ruft der Server diese URL ab, verzögert sich die Antwort).',
    'Internes Netzwerk / Cloud-Metadaten / localhost (169.254.169.254, RFC1918, 127.0.0.1 usw.) wurden **niemals** angesteuert (im Code fest verankerter Hard-Guard).',
  ],
  confidenceNoteDe: 'Da keine OOB-Verifizierungsinfrastruktur verwendet wurde, ist diese Erkennung **zeitbasiert, indirekt und von mittlerer Zuverlässigkeit**; zur sicheren Verifizierung wird ein zusätzlicher/manueller Test empfohlen.',
  fixTitleDe: 'SSRF',
  fixFoundDe: [
    'Beschränken Sie Parameter, die serverseitige Fetches auslösen, per **Allowlist** (nur erlaubte Domains/Schemata).',
    'Blockieren Sie serverseitig Anfragen an interne Netzwerkadressen (RFC1918, 169.254.169.254, localhost); prüfen Sie gegen DNS-Rebinding auch die aufgelöste IP.',
    'Führen Sie das Abrufen externer Ressourcen nach Möglichkeit über einen isolierten Dienst / ein eingeschränktes Netzwerk durch.',
  ],
  fixCleanDe: [
    'Wenden Sie in allen Feldern, die eine URL vom Benutzer entgegennehmen, serverseitig **Allowlist** + Sperre interner Netzwerke an (proaktiv).',
    'Setzen Sie bei erforderlichem externen Fetch Schema-/Host-Validierung + Timeout + Größenlimit.',
  ],
  cleanGenelDe: 'In den erkannten Fetch-ähnlichen Parametern wurde gegenüber der von uns kontrollierten verzögerten URL kein Indikator für serverseitigen Fetch (SSRF) beobachtet.',
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
  whatCheckedDe: [
    'Eingabeparameter, die einen Befehl erreichen könnten, wurden identifiziert.',
    'Es wurden nur **harmlose, zeitbasierte** Verzögerungs-Payloads (sleep) gesendet; die Antwortzeit wurde mit der Baseline verglichen (Blind-Nachweis).',
    'Tatsächliche Befehlsausführung (Datei lesen/schreiben, Netzwerkverbindung, Reverse Shell) wurde **niemals** versucht (im Code fest verankerter Hard-Guard: nur feste sleep-Payload-Liste).',
  ],
  confidenceNoteDe: 'Da keine OOB-/Canary-Infrastruktur verwendet wurde, ist diese Erkennung **zeitbasiert, indirekt und von mittlerer Zuverlässigkeit** (Netzwerklatenz kann täuschen); zur sicheren Verifizierung wird ein manueller Test empfohlen.',
  fixTitleDe: 'RCE / Befehlsinjektion',
  fixFoundDe: [
    'Übergeben Sie Benutzereingaben niemals direkt an einen Systembefehl/eine Shell; vermeiden Sie nach Möglichkeit den Aufruf von Systembefehlen vollständig.',
    'Falls unvermeidbar, führen Sie Befehle als Argument-Array (exec + args) aus; verwenden Sie KEINE Shell-Verkettung (String); validieren Sie die Eingabe per Allowlist.',
    'Betreiben Sie die Anwendung mit minimalen Rechten; beschränken Sie ausgehende Netzwerkverbindungen.',
  ],
  fixCleanDe: [
    'Überprüfen Sie Codepfade, die Systembefehle aufrufen; validieren Sie die Eingabe per Allowlist, vermeiden Sie Shell-String-Verkettung (proaktiv).',
    'Wenden Sie minimale Rechte + Beschränkung ausgehender Netzwerkverbindungen an.',
  ],
  cleanGenelDe: 'In den erkannten Eingaben wurde gegenüber den zeitbasierten harmlosen Sonden kein Indikator für blinde Befehlsausführung beobachtet.',
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
  whatCheckedDe: [
    'Ein Datei-Upload-Formular (input type=file) wurde identifiziert.',
    'Eine einmalige, **harmlose und nicht ausführbare (inerte)**, doppelt erweiterte (.php.txt) Testdatei wurde gesendet; es wurde nur der Annahme-/Ablehnungsstatus beobachtet.',
    'Die hochgeladene Datei wurde **nicht abgerufen/ausgeführt** (im Code verankerte Regel).',
  ],
  fixTitleDe: 'Datei-Upload',
  fixFoundDe: [
    'Validieren Sie den Dateityp **serverseitig** (Erweiterung + tatsächliche MIME/Magic Bytes); verwenden Sie gegen doppelte Erweiterungen / Erweiterungstricks eine Allowlist.',
    'Legen Sie hochgeladene Dateien NICHT in das Web-Root; speichern Sie sie in einem nicht ausführbaren Speicher (oder CDN); vergeben Sie zufällige Namen.',
    'Wenden Sie Größen-/Typlimits + Authentifizierung an.',
  ],
  fixCleanDe: [
    'Wenden Sie an Upload-Endpunkten serverseitige Typ-/MIME-Validierung + Allowlist + Speicherung außerhalb des Web-Root an (proaktiv).',
  ],
  cleanGenelDe: 'Im erkannten Upload-Formular wurde für die harmlose Testdatei kein eindeutiger Indikator für schwache Validierung beobachtet (oder es wurde kein Upload-Formular gefunden).',
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
  whatCheckedDe: [
    'Auf der Startseite/in Formularen wurden **clientseitig veränderbare** Preis-/Mengenfelder (hidden input) beobachtet (nur Beobachtung — keine Anfrage gesendet).',
    'Es wurde geprüft, ob eine „Erfolg-/Bestätigungs"-Schrittseite ohne Vorbedingung **nur per GET** erreichbar ist (Indikator für Schrittüberspringen).',
    '⚠️ Diese Prüfung sendet **keine zustandsändernde Anfrage (POST/PUT/…)** — Warenkorb/Zahlung werden **niemals** erstellt/abgeschlossen (im Code verankerte Regel).',
  ],
  confidenceNoteDe: 'Geschäftslogik-Schwachstellen sind kontextspezifisch; diese Prüfung ist auf Oberflächen-/Indikatorebene. Eine sichere Verifizierung erfordert einen authentifizierten manuellen Test.',
  fixTitleDe: 'Geschäftslogik',
  fixFoundDe: [
    'Verarbeiten Sie Werte wie Preis/Menge/Rabatt **niemals** mit dem vom Client gelieferten Wert; berechnen/validieren Sie sie serverseitig neu.',
    'Erzwingen Sie in mehrstufigen Abläufen die Vorbedingung jedes Schritts serverseitig (verhindern Sie Schrittüberspringen).',
  ],
  fixCleanDe: [
    'Validieren Sie kritische Werte (Preis/Menge) serverseitig; wenden Sie in mehrstufigen Abläufen eine Schrittreihenfolge-Prüfung an (proaktiv).',
  ],
  cleanGenelDe: 'Es wurde kein beobachtbares clientseitiges Preis-/Mengenfeld oder ein direkt erreichbarer „Bestätigungs"-Schritt gefunden.',
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
  whatCheckedDe: [
    'Ein registrierungs-/profilähnliches POST-Formular wurde identifiziert (Zahlungs-/Abschluss-Endpunkte **ausgeschlossen** — im Code verankerte Blocklist).',
    'Es wurde **eine einzige** Anfrage mit zusätzlichen Feldern `isAdmin/role` gesendet; nur Annahme/Ablehnung wurde beobachtet (eine Rechteänderung wurde **nicht bestätigt**; **kein** Retry).',
    'Der Race-Condition-Test (Nebenläufigkeit) wurde **nicht automatisch ausgeführt**, da er das Risiko birgt, eine verbrauchbare Ressource tatsächlich zu verändern (Hinweis unten).',
  ],
  confidenceNoteDe: 'Der Mass-Assignment-Indikator wurde nur aus der ersten Antwort abgeleitet (geringe Konfidenz). Für Race-Conditions wird eine manuelle Verifizierung mit einem sicheren/prüfbaren Endpunkt empfohlen.',
  fixTitleDe: 'Race / Mass-Assignment',
  fixFoundDe: [
    'Binden Sie serverseitig per **Allowlist** nur erlaubte Felder (verhindern Sie Mass-Assignment/Over-Posting); nehmen Sie Felder wie `isAdmin/role` niemals vom Client entgegen.',
    'Verhindern Sie bei kritischen Operationen (Coupon/Bestand/Guthaben) Race-Conditions durch **atomare** Operationen + Sperre/Idempotenzschlüssel.',
  ],
  fixCleanDe: [
    'Wenden Sie bei der Modellbindung eine Feld-Allowlist (Mass-Assignment-Schutz) an; nutzen Sie bei kritischen Operationen ein atomares/idempotentes Design (proaktiv).',
  ],
  cleanGenelDe: 'Es wurde kein geeignetes (nicht abschluss-/zahlungsbezogenes) Registrierungs-/Profilformular gefunden oder die Mass-Assignment-Sonde wurde nicht akzeptiert.',
};

export async function generateSsrfVerifyReport(host: string, locale: string = 'tr') { return buildActiveCheckReport(await collectSsrfEvidence(host, undefined, locale === 'de'), SSRF_CFG, locale === 'de'); }
export async function generateRceVerifyReport(host: string, locale: string = 'tr') { return buildActiveCheckReport(await collectRceEvidence(host, undefined, locale === 'de'), RCE_CFG, locale === 'de'); }
export async function generateFileUploadVerifyReport(host: string, locale: string = 'tr') { return buildActiveCheckReport(await collectFileUploadEvidence(host, locale === 'de'), UPLOAD_CFG, locale === 'de'); }
export async function generateBusinessLogicVerifyReport(host: string, locale: string = 'tr') { return buildActiveCheckReport(await collectBusinessLogicEvidence(host, locale === 'de'), BUSINESS_CFG, locale === 'de'); }
export async function generateRaceMassAssignVerifyReport(host: string, locale: string = 'tr') { return buildActiveCheckReport(await collectRaceMassAssignEvidence(host, locale === 'de'), RACE_CFG, locale === 'de'); }
// Saf kurucu testler icin (sentetik ActiveCheckEvidence ile):
export const _cfg = { SSRF_CFG, RCE_CFG, UPLOAD_CFG, BUSINESS_CFG, RACE_CFG };
export { buildActiveCheckReport };
