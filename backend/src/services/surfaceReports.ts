/**
 * (Dış Yüzey & Yapılandırma bundle üyeleri) DETERMINISTIK RAPOR URETICILERI.
 *
 * ssl_tls / header_leak / dns_email / cors_cookie / csp_analiz — her biri KOD-toplanmis
 * kanittan (surfaceEvidence.ts) kendi odakli raporunu uretir. Ajan ciktisina bakilmaz.
 * Her fonksiyon { findings, fixText } | null doner (hedefe ulasilamazsa null -> fallback).
 * Risk hesabi TAMAMEN kod; GENEL DEĞERLENDİRME'ye acik "Risk Seviyesi: X" yazilir (pdf.ts
 * assessBasit bunu okuyup rozeti tutarli gosterir).
 *
 * P2: locale='de' desteği (uykuda) — çıktı 'de' değilse BYTE-AYNI Türkçe kalır.
 */
import {
  collectHttp, collectTls, collectCors, collectCorsForUrl, collectDns, collectExposedFiles, collectSurfaceLeakExtras, resolveOrigin,
  collectPages, type PageEvidence, type CorsEvidence, type TlsEvidence, type DnsEvidence,
} from './surfaceEvidence.js';
import { buildHeaderFixSuggestions } from './fixSuggestions.js';
import { detectOutdatedSoftware } from './techEol.js';

const RISK_WORD = { low: 'Düşük', medium: 'Orta', 'medium-high': 'Orta-Yüksek', high: 'Yüksek' } as const;
const RISK_WORD_DE = { low: 'Niedrig', medium: 'Mittel', 'medium-high': 'Mittel-Hoch', high: 'Hoch' } as const;
const RISK_WORD_EN = { low: 'Low', medium: 'Medium', 'medium-high': 'Medium-High', high: 'High' } as const;
// Bulgu tablosundaki şiddet kelimesini locale'e çevir (makine-değer TR kalır; yalnız görüntü).
const SEV_DE: Record<string, string> = { 'Kritik': 'Kritisch', 'Yüksek': 'Hoch', 'Orta': 'Mittel', 'Düşük': 'Niedrig', 'Bilgilendirme': 'Hinweis' };
const SEV_EN: Record<string, string> = { 'Kritik': 'Critical', 'Yüksek': 'High', 'Orta': 'Medium', 'Düşük': 'Low', 'Bilgilendirme': 'Informational' };
type Level = 'low' | 'medium' | 'medium-high' | 'high';

function assemble(_title: string, level: Level, summaryBullets: string[], genelSentence: string, sections: string, locale: string = 'tr'): string {
  const de = locale === 'de';
  const en = locale === 'en';
  const RW = en ? RISK_WORD_EN : de ? RISK_WORD_DE : RISK_WORD;
  const execHdr = en ? 'EXECUTIVE SUMMARY' : de ? 'MANAGEMENTZUSAMMENFASSUNG' : 'YÖNETİCİ ÖZETİ';
  const overallHdr = en ? 'OVERALL ASSESSMENT' : de ? 'GESAMTBEWERTUNG' : 'GENEL DEĞERLENDİRME';
  const riskLbl = en ? 'Risk Level' : de ? 'Risikostufe' : 'Risk Seviyesi';
  return (
    `## ${execHdr}\n\n${summaryBullets.join('\n')}\n\n` +
    `## ${overallHdr}\n\n**${riskLbl}: ${RW[level]}**\n\n${genelSentence}\n\n` +
    `${sections}`
  );
}

// (MERKEZİ FINDINGS) Alt-kontrol "TESPİT EDİLEN RİSKLER" maddelerini ŞİDDET-kolonlu tabloya çevirir.
// Neden: pdf.parseFindings YALNIZ şiddet-kolonlu tabloları toplar; bullet listesi 2.1 Dağılım / 2.2
// Master'a GİRMEZ (rozet Yüksek der ama master "Temiz" gösterirdi — tutarsızlık). Tabloya çevirince
// her alanın bulgusu tek merkezi master tabloda toplanır; rozet=dağılım=master aynı kaynaktan gelir.
// Bullet formatı: "- **Yüksek — Başlık:** açıklama". Parse edilemeyen (temiz) satırlar metin kalır.
// NOT: bullet içindeki şiddet TOKEN'ı (Kritik|Yüksek|…) locale'den BAĞIMSIZ TR kalır (regex + makine
// değeri); yalnız GÖRÜNTÜLENEN şiddet de'de çevrilir.
function risksTable(risks: string[], locale: string = 'tr'): string {
  const de = locale === 'de';
  const en = locale === 'en';
  const sevMap = (s: string) => en ? (SEV_EN[s] ?? s) : de ? (SEV_DE[s] ?? s) : s;
  const rows: string[] = [];
  for (const r of risks) {
    const m = r.match(/^-\s*\*\*\s*(Kritik|Yüksek|Orta|Düşük|Bilgilendirme)\s*[—–-]\s*([^:]+?)\s*:\s*\*\*\s*([\s\S]*)$/);
    if (m) rows.push(`| ${m[2].trim()} | ${sevMap(m[1])} | ${m[3].trim().replace(/\|/g, '\\|').replace(/\n+/g, ' ')} |`);
  }
  // Parse edilebilir hiç risk yoksa (temiz alan) eski metni koru -> parseFindings 0 sayar (doğru "temiz").
  if (!rows.length) return risks.join('\n');
  const hdr = en ? `| Finding | Severity | Description |` : de ? `| Befund | Schweregrad | Beschreibung |` : `| Bulgu | Şiddet | Açıklama |`;
  return `${hdr}\n|-------|--------|----------|\n${rows.join('\n')}`;
}

// ======================================================================================
// 1) ssl_tls — SSL/TLS Yapılandırma Denetimi
// ======================================================================================
export async function generateSslTlsReport(host: string, locale: string = 'tr'): Promise<{ findings: string; fixText: string } | null> {
  const de = locale === 'de';
  const t = (trS: string, deS: string, enS?: string) => (locale === 'de' ? deS : locale === 'en' ? (enS ?? trS) : trS);
  const RW = locale === 'en' ? RISK_WORD_EN : de ? RISK_WORD_DE : RISK_WORD;
  const [http, tls] = await Promise.all([collectHttp(host), collectTls(host)]);
  if (!tls.found && !http.ok) return null;

  const httpOnly = http.reachable && !http.httpsWorks; // HTTPS(443) yok, http var -> https_missing
  const hstsPresent = http.headers.has('strict-transport-security');
  const expired = tls.daysLeft != null && tls.daysLeft < 0;
  const veryClose = tls.daysLeft != null && tls.daysLeft >= 0 && tls.daysLeft < 15; // ESKALASYON
  const expiringSoon = tls.daysLeft != null && tls.daysLeft >= 15 && tls.daysLeft < 45;
  const mismatch = tls.hostnameMatch === false;
  const weak = tls.weakProtocols.length > 0;

  let level: Level = 'low';
  if (httpOnly || expired || mismatch || weak || veryClose) level = 'high'; // http-only (şifresiz) = Yüksek
  else if (expiringSoon || !hstsPresent) level = 'medium';

  const tlsSection = httpOnly
    ? `## ${t('TLS SERTİFİKA DURUMU', 'TLS-ZERTIFIKATSSTATUS', 'TLS CERTIFICATE STATUS')}\n\n` + t(
        `⚠️ Bu hedef **HTTPS (443) üzerinden yanıt vermedi**; geçerli bir TLS sertifikası bulunamadı. Site yalnızca **şifresiz HTTP** üzerinden yayında.\n\n`,
        `⚠️ Dieses Ziel **hat nicht über HTTPS (443) geantwortet**; es wurde kein gültiges TLS-Zertifikat gefunden. Die Website ist nur über **unverschlüsseltes HTTP** erreichbar.\n\n`,
        `⚠️ This target **did not respond over HTTPS (443)**; no valid TLS certificate was found. The site is served only over **unencrypted HTTP**.\n\n`,
      )
    : tlsBlock(host, tls, locale);
  const protoSection =
    `## ${t('TLS PROTOKOL & CIPHER', 'TLS-PROTOKOLL & CIPHER', 'TLS PROTOCOL & CIPHER')}\n\n` +
    `- **${t('Aktif protokol', 'Aktives Protokoll', 'Active protocol')}:** ${tls.protocol ?? t('tespit edilemedi', 'nicht ermittelbar', 'not detectable')}${tls.protocol && /TLSv1\.[01]$/.test(tls.protocol) ? t(' — ⚠️ zayıf', ' — ⚠️ schwach', ' — ⚠️ weak') : ''}\n` +
    `- **Cipher:** ${tls.cipher ?? t('tespit edilemedi', 'nicht ermittelbar', 'not detectable')}\n` +
    `- **${t('Eski/zayıf sürüm desteği', 'Unterstützung veralteter/schwacher Versionen', 'Legacy/weak version support')}:** ${weak ? t(`⚠️ ${tls.weakProtocols.join(', ')} hâlâ kabul ediliyor — kapatılması önerilir`, `⚠️ ${tls.weakProtocols.join(', ')} wird weiterhin akzeptiert — Deaktivierung empfohlen`, `⚠️ ${tls.weakProtocols.join(', ')} is still accepted — disabling is recommended`) : t('Gözlemlenmedi (yalnızca TLS 1.2+ görüldü)', 'Nicht beobachtet (nur TLS 1.2+ gesehen)', 'Not observed (only TLS 1.2+ seen)')}\n\n`;
  const hstsSection =
    `## HSTS (HTTP Strict Transport Security)\n\n` +
    (hstsPresent
      ? `- **${t('Durum', 'Status', 'Status')}:** ` + t(`Var — \`${http.headers.get('strict-transport-security')}\`. Tarayıcıya HTTPS zorunluluğu bildiriliyor.\n\n`, `Vorhanden — \`${http.headers.get('strict-transport-security')}\`. Dem Browser wird die HTTPS-Pflicht mitgeteilt.\n\n`, `Present — \`${http.headers.get('strict-transport-security')}\`. The browser is instructed to enforce HTTPS.\n\n`)
      : `- **${t('Durum', 'Status', 'Status')}:** ` + t(`Yok — Tarayıcıya HTTPS zorunluluğu bildirilmiyor; ilk isteklerde SSL-stripping/downgrade saldırısı riski var.\n\n`, `Fehlt — Dem Browser wird die HTTPS-Pflicht nicht mitgeteilt; bei Erstanfragen besteht das Risiko von SSL-Stripping-/Downgrade-Angriffen.\n\n`, `Absent — The browser is not instructed to enforce HTTPS; there is a risk of SSL-stripping/downgrade attacks on initial requests.\n\n`));

  const risks: string[] = [];
  if (httpOnly) risks.push(t(`- **Yüksek — HTTPS desteklenmiyor (şifresiz iletişim):** Site HTTPS'e yanıt vermiyor; tüm trafik şifresiz (düz metin) taşınıyor. Aynı ağdaki bir saldırgan dinleyebilir, oturum/şifre çalabilir veya içeriği değiştirebilir. Çözüm: geçerli TLS sertifikası + HTTP→HTTPS yönlendirme + HSTS.`, `- **Yüksek — HTTPS wird nicht unterstützt (unverschlüsselte Kommunikation):** Die Website antwortet nicht über HTTPS; der gesamte Datenverkehr wird unverschlüsselt (Klartext) übertragen. Ein Angreifer im selben Netzwerk kann mithören, Sitzungen/Passwörter stehlen oder Inhalte verändern. Lösung: gültiges TLS-Zertifikat + HTTP→HTTPS-Umleitung + HSTS.`, `- **Yüksek — HTTPS not supported (unencrypted communication):** The site does not respond over HTTPS; all traffic is carried in the clear (plaintext). An attacker on the same network can eavesdrop, steal sessions/passwords or alter content. Fix: valid TLS certificate + HTTP→HTTPS redirect + HSTS.`));
  if (mismatch) risks.push(t(`- **Yüksek — Sertifika hostname uyuşmazlığı:** Sertifika ${host} adına düzenlenmemiş; ziyaretçiler tarayıcı güvenlik uyarısıyla karşılaşır.`, `- **Yüksek — Zertifikat-Hostname-Abweichung:** Das Zertifikat ist nicht auf ${host} ausgestellt; Besucher erhalten eine Browser-Sicherheitswarnung.`, `- **Yüksek — Certificate hostname mismatch:** The certificate is not issued for ${host}; visitors will encounter a browser security warning.`));
  if (expired) risks.push(t('- **Yüksek — Sertifika süresi dolmuş:** Site tarayıcılarca güvensiz kabul edilir.', '- **Yüksek — Zertifikat abgelaufen:** Die Website wird von Browsern als unsicher eingestuft.', '- **Yüksek — Certificate expired:** The site is treated as insecure by browsers.'));
  if (weak) risks.push(t(`- **Yüksek — Zayıf TLS sürümü:** ${tls.weakProtocols.join(', ')} destekleniyor. Bu sürümlerde bilinen zayıflıklar (POODLE/BEAST vb.) vardır; devre dışı bırakılmalı.`, `- **Yüksek — Schwache TLS-Version:** ${tls.weakProtocols.join(', ')} wird unterstützt. Diese Versionen weisen bekannte Schwächen auf (POODLE/BEAST usw.); sie sollten deaktiviert werden.`, `- **Yüksek — Weak TLS version:** ${tls.weakProtocols.join(', ')} is supported. These versions have known weaknesses (POODLE/BEAST etc.); they should be disabled.`));
  if (veryClose) risks.push(t(`- **Yüksek — Sertifika çok yakında sona eriyor:** yalnızca ${tls.daysLeft} gün kaldı; acilen yenilenmeli (aksi halde site erişilemez/güvensiz olur).`, `- **Yüksek — Zertifikat läuft sehr bald ab:** nur noch ${tls.daysLeft} Tage; umgehende Erneuerung erforderlich (andernfalls wird die Website nicht erreichbar/unsicher).`, `- **Yüksek — Certificate expiring very soon:** only ${tls.daysLeft} days left; renew urgently (otherwise the site becomes unreachable/insecure).`));
  if (expiringSoon) risks.push(t(`- **Orta — Sertifika yakında sona eriyor:** ${tls.daysLeft} gün kaldı; kesinti yaşamamak için yenileme planlanmalı.`, `- **Orta — Zertifikat läuft bald ab:** noch ${tls.daysLeft} Tage; planen Sie die Erneuerung, um Ausfälle zu vermeiden.`, `- **Orta — Certificate expiring soon:** ${tls.daysLeft} days left; plan the renewal to avoid downtime.`));
  if (!hstsPresent) risks.push(t('- **Orta — HSTS eksik:** HTTPS zorunluluğu tarayıcıya bildirilmiyor; downgrade saldırılarına açık.', '- **Orta — HSTS fehlt:** Die HTTPS-Pflicht wird dem Browser nicht mitgeteilt; anfällig für Downgrade-Angriffe.', '- **Orta — HSTS missing:** HTTPS enforcement is not signalled to the browser; open to downgrade attacks.'));
  if (!risks.length) risks.push(t('- Belirgin bir TLS yapılandırma sorunu öne çıkmadı; şifreleme yapılandırması güncel.', '- Es wurde kein deutliches TLS-Konfigurationsproblem festgestellt; die Verschlüsselungskonfiguration ist aktuell.', '- No notable TLS configuration issue stood out; the encryption configuration is up to date.'));

  const bullets: string[] = [];
  bullets.push(`- **${t('Genel risk seviyesi', 'Gesamtrisikostufe', 'Overall risk level')}: ${RW[level]}** — ${level === 'high' ? t('sertifika ve/veya protokol düzeyinde acil ele alınması gereken bir sorun tespit edildi.', 'auf Zertifikats- und/oder Protokollebene wurde ein dringend zu behebendes Problem festgestellt.', 'an issue requiring urgent attention was detected at the certificate and/or protocol level.') : level === 'medium' ? t('şifreleme temelde sağlam; kısa vadede giderilecek eksikler var.', 'die Verschlüsselung ist grundsätzlich solide; kurzfristig zu behebende Lücken bestehen.', 'encryption is fundamentally sound; there are gaps to be addressed in the short term.') : t('şifreleme yapılandırması güncel ve sağlam.', 'die Verschlüsselungskonfiguration ist aktuell und solide.', 'the encryption configuration is up to date and sound.')}`);
  bullets.push(`- ${t('Sertifika', 'Zertifikat', 'Certificate')}: ${tls.found ? (mismatch ? t('⚠️ hostname uyuşmazlığı', '⚠️ Hostname-Abweichung', '⚠️ hostname mismatch') : expired ? t('⚠️ süresi dolmuş', '⚠️ abgelaufen', '⚠️ expired') : t(`geçerli (${tls.daysLeft} gün)`, `gültig (${tls.daysLeft} Tage)`, `valid (${tls.daysLeft} days)`)) : t('tespit edilemedi', 'nicht ermittelbar', 'not detectable')}${tls.protocol ? `, ${tls.protocol}` : ''}.`);
  bullets.push(`- HSTS: ${hstsPresent ? t('var', 'vorhanden', 'present') : t('yok', 'fehlt', 'absent')}; ${t('Eski TLS desteği', 'Veraltete TLS-Unterstützung', 'Legacy TLS support')}: ${weak ? tls.weakProtocols.join(', ') : t('gözlemlenmedi', 'nicht beobachtet', 'not observed')}.`);
  bullets.push(`- **${t('Önerilen ilk adım', 'Empfohlener erster Schritt', 'Recommended first step')}:** ` + (weak ? t('Eski TLS sürümlerini kapatın ve ', 'Deaktivieren Sie veraltete TLS-Versionen und ', 'Disable legacy TLS versions and ') : '') + (hstsPresent ? t('sertifika yenilemeyi takip edin.', 'verfolgen Sie die Zertifikatserneuerung.', 'keep track of certificate renewal.') : t('HSTS başlığını ekleyin (hazır komutlar "AI Çözüm Önerileri" eklentisinde).', 'ergänzen Sie den HSTS-Header (fertige Befehle im Add-on „KI-Lösungsvorschläge").', 'add the HSTS header (ready-made commands in the "AI Remediation Suggestions" add-on).')));

  const genel =
    level === 'high'
      ? t('Şifreleme katmanında ziyaretçileri doğrudan etkileyebilecek (sertifika/protokol) acil bir sorun tespit edildi; öncelikli giderilmesi önerilir.', 'In der Verschlüsselungsschicht wurde ein dringendes Problem (Zertifikat/Protokoll) festgestellt, das Besucher direkt betreffen kann; eine vorrangige Behebung wird empfohlen.', 'An urgent issue (certificate/protocol) that can directly affect visitors was detected in the encryption layer; priority remediation is recommended.')
      : level === 'medium'
        ? t('Taşıma güvenliği temelde sağlam; kısa vadede giderilmesi önerilen eksikler (ör. HSTS / yaklaşan yenileme) var.', 'Die Transportsicherheit ist grundsätzlich solide; es bestehen kurzfristig zu behebende Lücken (z. B. HSTS / bevorstehende Erneuerung).', 'Transport security is fundamentally sound; there are gaps recommended for short-term remediation (e.g. HSTS / upcoming renewal).')
        : t('TLS/SSL yapılandırması güncel ve sağlam; rapor yalnızca küçük iyileştirme fırsatlarını listeler.', 'Die TLS/SSL-Konfiguration ist aktuell und solide; der Bericht listet nur kleine Verbesserungsmöglichkeiten auf.', 'The TLS/SSL configuration is up to date and sound; the report lists only minor improvement opportunities.');

  const findings = assemble('SSL/TLS', level, bullets, genel, `${tlsSection}${protoSection}${hstsSection}## ${t('TESPİT EDİLEN RİSKLER', 'FESTGESTELLTE RISIKEN', 'IDENTIFIED RISKS')}\n\n${risksTable(risks, locale)}\n`, locale);
  const fixText = buildTlsFix(host, { hstsMissing: !hstsPresent, weak: tls.weakProtocols }, locale);
  return { findings, fixText };
}

function tlsBlock(host: string, tls: TlsEvidence, locale: string = 'tr'): string {
  const de = locale === 'de';
  const t = (trS: string, deS: string, enS?: string) => (locale === 'de' ? deS : locale === 'en' ? (enS ?? trS) : trS);
  const heading = `## ${t('TLS SERTİFİKA DURUMU', 'TLS-ZERTIFIKATSSTATUS', 'TLS CERTIFICATE STATUS')}`;
  if (!tls.found) return `${heading}\n\n` + t('TLS sertifika bilgisi elde edilemedi (443 portuna güvenli bağlantı kurulamadı).\n\n', 'Es konnten keine TLS-Zertifikatsinformationen ermittelt werden (keine sichere Verbindung zu Port 443 möglich).\n\n', 'TLS certificate information could not be obtained (no secure connection to port 443 could be established).\n\n');
  const l: string[] = [];
  l.push(`- **${t('Geçerlilik', 'Gültigkeit', 'Validity')}:** ${tls.daysLeft != null ? (tls.daysLeft >= 0 ? t(`Geçerli, ${tls.daysLeft} gün kaldı`, `Gültig, noch ${tls.daysLeft} Tage`, `Valid, ${tls.daysLeft} days remaining`) : t(`SÜRESİ DOLMUŞ (${Math.abs(tls.daysLeft)} gün önce)`, `ABGELAUFEN (vor ${Math.abs(tls.daysLeft)} Tagen)`, `EXPIRED (${Math.abs(tls.daysLeft)} days ago)`)) : t('Belirlenemedi', 'Nicht ermittelbar', 'Not determinable')}${tls.notAfter ? t(` (bitiş: ${tls.notAfter})`, ` (Ablauf: ${tls.notAfter})`, ` (expiry: ${tls.notAfter})`) : ''}`);
  if (tls.hostnameMatch === false) l.push(t(`- **Hostname eşleşmesi:** ⚠️ Sertifika ${host} ile eşleşmiyor${tls.cn ? ` (sahibi: ${tls.cn})` : ''}${tls.san.length ? `; kapsanan: ${tls.san.slice(0, 6).join(', ')}` : ''}.`, `- **Hostname-Abgleich:** ⚠️ Das Zertifikat stimmt nicht mit ${host} überein${tls.cn ? ` (Inhaber: ${tls.cn})` : ''}${tls.san.length ? `; abgedeckt: ${tls.san.slice(0, 6).join(', ')}` : ''}.`, `- **Hostname match:** ⚠️ The certificate does not match ${host}${tls.cn ? ` (owner: ${tls.cn})` : ''}${tls.san.length ? `; covered: ${tls.san.slice(0, 6).join(', ')}` : ''}.`));
  else if (tls.hostnameMatch === true) { const multi = tls.cn && tls.cn.toLowerCase() !== host.toLowerCase(); l.push(t(`- **Hostname eşleşmesi:** Uyumlu${multi ? ` (çok alanlı sertifika; ${host} kapsanıyor)` : ''}.`, `- **Hostname-Abgleich:** Übereinstimmend${multi ? ` (Multi-Domain-Zertifikat; ${host} ist abgedeckt)` : ''}.`, `- **Hostname match:** Matching${multi ? ` (multi-domain certificate; ${host} is covered)` : ''}.`)); }
  if (tls.issuer) l.push(`- **${t('Veren (issuer)', 'Aussteller (Issuer)', 'Issuer')}:** ${tls.issuer}`);
  return `${heading}\n\n${l.join('\n')}\n\n`;
}

// ======================================================================================
// 2) header_leak — Güvenlik Başlıkları & Bilgi Sızıntısı
// ======================================================================================
const SEC_HDRS: Array<{ hdr: string; name: string; absent: string; absentDe: string; absentEn: string }> = [
  { hdr: 'strict-transport-security', name: 'Strict-Transport-Security', absent: 'HTTPS zorunluluğu bildirilmiyor; SSL-stripping riski.', absentDe: 'Die HTTPS-Pflicht wird nicht mitgeteilt; SSL-Stripping-Risiko.', absentEn: 'HTTPS enforcement is not signalled; SSL-stripping risk.' },
  { hdr: 'content-security-policy', name: 'Content-Security-Policy', absent: 'XSS/enjeksiyona karşı tarayıcı savunması yok.', absentDe: 'Keine Browser-Verteidigung gegen XSS/Injection.', absentEn: 'No browser defence against XSS/injection.' },
  { hdr: 'x-frame-options', name: 'X-Frame-Options', absent: 'Clickjacking’e açık; iframe’e gömülebilir.', absentDe: 'Anfällig für Clickjacking; kann in ein iframe eingebettet werden.', absentEn: 'Open to clickjacking; can be embedded in an iframe.' },
  { hdr: 'x-content-type-options', name: 'X-Content-Type-Options', absent: 'MIME-sniffing mümkün.', absentDe: 'MIME-Sniffing möglich.', absentEn: 'MIME-sniffing is possible.' },
  { hdr: 'referrer-policy', name: 'Referrer-Policy', absent: 'Referrer bilgisi dış kaynaklara sızabilir.', absentDe: 'Referrer-Informationen können an externe Quellen abfließen.', absentEn: 'Referrer information may leak to external sources.' },
  { hdr: 'permissions-policy', name: 'Permissions-Policy', absent: 'Hassas tarayıcı API’leri kısıtlanmamış.', absentDe: 'Sensible Browser-APIs sind nicht eingeschränkt.', absentEn: 'Sensitive browser APIs are not restricted.' },
  { hdr: 'x-xss-protection', name: 'X-XSS-Protection', absent: 'Eski tarayıcı XSS filtresi ayarlı değil (modernlerde kritik değil).', absentDe: 'Der Legacy-XSS-Filter älterer Browser ist nicht gesetzt (in modernen Browsern unkritisch).', absentEn: 'The legacy browser XSS filter is not set (not critical in modern browsers).' },
];

export async function generateHeaderLeakReport(host: string, locale: string = 'tr'): Promise<{ findings: string; fixText: string } | null> {
  const de = locale === 'de';
  const t = (trS: string, deS: string, enS?: string) => (locale === 'de' ? deS : locale === 'en' ? (enS ?? trS) : trS);
  const RW = locale === 'en' ? RISK_WORD_EN : de ? RISK_WORD_DE : RISK_WORD;
  const http = await collectHttp(host);
  if (!http.ok) return null;
  const exposed = await collectExposedFiles(host, http.html, locale);
  // (Genişletme A.2/A.3/A.4) ek pasif bilgi-sızıntısı gözlemleri — dizin listeleme / verbose-error
  // yol ifşası / parola-autocomplete. GET-only; içerik REDAKTE. Mevcut bulgular DEĞİŞMEZ.
  const leakX = await collectSurfaceLeakExtras(host, http.html, locale);
  const dirHits = leakX.dirListings;
  const errLeaked = leakX.errorDisclosure.leaked;
  const acObserved = leakX.autocomplete.observed;

  const missing = SEC_HDRS.filter((h) => !http.headers.has(h.hdr));
  const missingCrit = missing.filter((h) => h.hdr === 'content-security-policy' || h.hdr === 'x-frame-options');
  const exposedHits = exposed.filter((e) => e.exposed);

  // (BÖLÜM 1 — ÇOK SAYFA) Güvenlik başlığı varlığı + sürüm imzası, keşfedilen sayfaların BİRLEŞİMİNDEN
  // değerlendirilir (PASİF, paylaşılan crawl'dan; ek prob YOK). EOL için sürüm alt sayfada da çıkabilir.
  const hlPages = await collectPages(host);
  const hlPageCount = Math.max(1, hlPages.length);
  const hdrAbsentCount = new Map<string, number>();
  for (const pg of hlPages) for (const h of SEC_HDRS) if (!pg.headers.has(h.hdr)) hdrAbsentCount.set(h.hdr, (hdrAbsentCount.get(h.hdr) ?? 0) + 1);
  const hdrCov = (hdrs: { hdr: string }[]) => (hlPageCount > 1 ? t(` (${Math.max(...hdrs.map((h) => hdrAbsentCount.get(h.hdr) ?? hlPageCount))}/${hlPageCount} sayfada eksik)`, ` (fehlt auf ${Math.max(...hdrs.map((h) => hdrAbsentCount.get(h.hdr) ?? hlPageCount))}/${hlPageCount} Seiten)`, ` (missing on ${Math.max(...hdrs.map((h) => hdrAbsentCount.get(h.hdr) ?? hlPageCount))}/${hlPageCount} pages)`) : '');

  // (HATA 4) EOL/eski yazılım imzası -> GERÇEK bulgu (sunucu/X-Powered-By/generator sürümünden).
  const techStrings: string[] = [];
  const srvHdr = http.headers.get('server'); if (srvHdr) techStrings.push(`Sunucu: ${srvHdr}`);
  const xpbHdr = http.headers.get('x-powered-by'); if (xpbHdr) techStrings.push(`X-Powered-By: ${xpbHdr}`);
  const genMeta = http.html?.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)/i)?.[1];
  if (genMeta) techStrings.push(genMeta);
  for (const pg of hlPages) { const s = pg.headers.get('server'); if (s) techStrings.push(`Sunucu: ${s}`); const x = pg.headers.get('x-powered-by'); if (x) techStrings.push(`X-Powered-By: ${x}`); }
  const eolRisks = detectOutdatedSoftware(techStrings, locale);
  const eolHigh = eolRisks.some((r) => r.sev === 'Yüksek');
  const eolMed = eolRisks.some((r) => r.sev === 'Orta');

  let level: Level = 'low';
  if (exposedHits.length || eolHigh) level = 'high';
  else if (missingCrit.length || missing.length >= 3 || eolMed || dirHits.length || errLeaked) level = 'medium';

  const table =
    `## ${t('HTTP GÜVENLİK BAŞLIKLARI', 'HTTP-SICHERHEITS-HEADER', 'HTTP SECURITY HEADERS')}\n\n| ${t('Başlık', 'Header', 'Header')} | ${t('Durum', 'Status', 'Status')} | ${t('Açıklama', 'Beschreibung', 'Description')} |\n|--------|-------|----------|\n` +
    SEC_HDRS.map((h) => {
      const present = http.headers.has(h.hdr);
      return `| ${h.name} | ${present ? t('Var', 'Vorhanden', 'Present') : t('Yok', 'Fehlt', 'Absent')} | ${present ? t('Mevcut ve yapılandırılmış.', 'Vorhanden und konfiguriert.', 'Present and configured.') : t(h.absent, h.absentDe, h.absentEn)} |`;
    }).join('\n') + '\n\n';

  const leakSection =
    `## ${t('BİLGİ SIZINTISI / AÇIKTA DOSYALAR', 'INFORMATIONSLECKS / OFFENLIEGENDE DATEIEN', 'INFORMATION LEAKAGE / EXPOSED FILES')}\n\n` +
    t(`Yaygın hassas yollar tek GET ile kontrol edildi (içerik doğrulandı — yalnız HTTP 200 kanıt sayılmaz):\n\n`, `Häufige sensible Pfade wurden mit einem einzigen GET geprüft (Inhalt verifiziert — allein HTTP 200 gilt nicht als Nachweis):\n\n`, `Common sensitive paths were checked with a single GET (content verified — HTTP 200 alone is not treated as evidence):\n\n`) +
    `| ${t('Yol', 'Pfad', 'Path')} | ${t('Durum', 'Status', 'Status')} | ${t('Not', 'Hinweis', 'Note')} |\n|-----|-------|-----|\n` +
    exposed.map((e) => `| \`${e.path}\` | ${e.exposed ? t('⚠️ AÇIK', '⚠️ OFFEN', '⚠️ EXPOSED') : t('Kapalı', 'Geschlossen', 'Closed')} | ${e.reason} |`).join('\n') + '\n\n';

  // (A.2/A.3/A.4 şeffaflık) Üç ek pasif gözlem — bulgu çıkmasa da "denendi, gösterge yok" olarak
  // ŞEFFAF listelenir (üç-durum: ✅ temiz / ⚠️ gösterge / ⚠️ İncelenemedi).
  const S_CLEAN = t('✅ Gösterge bulunamadı', '✅ Kein Indikator gefunden', '✅ No indicator found');
  const S_NA = t('⚠️ İncelenemedi (hedefe ulaşılamadı — “temiz” DEĞİL)', '⚠️ Nicht prüfbar (Ziel nicht erreichbar — NICHT „sauber")', '⚠️ Not assessable (target unreachable — NOT "clean")');
  const dirCell = !leakX.reachable ? S_NA : dirHits.length ? t(`⚠️ Listeleme açık (${dirHits.map((d) => d.path).join(', ')})`, `⚠️ Auflistung aktiv (${dirHits.map((d) => d.path).join(', ')})`, `⚠️ Listing enabled (${dirHits.map((d) => d.path).join(', ')})`) : t(`✅ ${leakX.dirsTried} dizin denendi, listeleme yok`, `✅ ${leakX.dirsTried} Verzeichnisse geprüft, keine Auflistung`, `✅ ${leakX.dirsTried} directories tried, no listing`);
  const errCell = !leakX.reachable ? S_NA : errLeaked ? t(`⚠️ Yol/stack sızıyor (REDAKTE)`, `⚠️ Pfad/Stack lecken (REDIGIERT)`, `⚠️ Path/stack leaking (REDACTED)`) : S_CLEAN;
  const acCell = !leakX.reachable ? S_NA : acObserved ? t(`⚠️ Politika yok (${leakX.autocomplete.count} alan)`, `⚠️ Keine Richtlinie (${leakX.autocomplete.count} Feld(er))`, `⚠️ No policy (${leakX.autocomplete.count} field(s))`) : t('✅ Uygun / parola alanı gözlenmedi', '✅ Angemessen / kein Passwortfeld beobachtet', '✅ Appropriate / no password field observed');
  const leakExtrasSection =
    `## ${t('EK BİLGİ-SIZINTISI GÖZLEMLERİ', 'ZUSÄTZLICHE INFORMATIONSLECK-BEOBACHTUNGEN', 'ADDITIONAL INFORMATION-LEAKAGE OBSERVATIONS')}\n\n` +
    `| ${t('Kontrol', 'Prüfung', 'Control')} | ${t('Sonuç', 'Ergebnis', 'Result')} |\n|-----|-------|\n` +
    `| ${t('Dizin listeleme (autoindex / “Index of /”)', 'Verzeichnisauflistung (autoindex / „Index of /")', 'Directory listing (autoindex / "Index of /")')} · CWE-548 | ${dirCell} |\n` +
    `| ${t('Ayrıntılı hata / sunucu-yol ifşası', 'Ausführlicher Fehler / Serverpfad-Offenlegung', 'Verbose error / server-path disclosure')} · CWE-209 | ${errCell} |\n` +
    `| ${t('Parola alanı autocomplete politikası', 'autocomplete-Richtlinie im Passwortfeld', 'Password-field autocomplete policy')} · CWE-522 | ${acCell} |\n\n` +
    `> ${t('Hepsi GET-only/pasif gözlemdir — içerik ÇEKİLMEZ/gösterilmez; sızan yol REDAKTE edilir. “Gösterge bulunamadı” güvenli olduğunu KANITLAMAZ; yalnız denenen pasif yöntemlerle gösterge çıkmadığını gösterir.', 'Alles GET-only/passive Beobachtung — Inhalte werden NICHT abgerufen/angezeigt; ein geleakter Pfad wird REDIGIERT. „Kein Indikator gefunden" BEWEIST NICHT, dass es sicher ist; es zeigt nur, dass mit den passiven Methoden kein Indikator auftrat.', 'All GET-only/passive observation — content is NOT fetched/shown; a leaked path is REDACTED. "No indicator found" does NOT PROVE it is secure; it only shows that no indicator emerged from the passive methods attempted.')}\n\n`;

  const risks: string[] = [];
  for (const e of exposedHits) risks.push(t(`- **Yüksek — Hassas dosya erişilebilir (\`${e.path}\`):** İçerik doğrulandı; yapılandırma/kaynak sızıntısı riski. Erişim derhal engellenmeli.`, `- **Yüksek — Sensible Datei erreichbar (\`${e.path}\`):** Inhalt verifiziert; Risiko eines Konfigurations-/Quellcode-Lecks. Der Zugriff muss umgehend gesperrt werden.`, `- **Yüksek — Sensitive file accessible (\`${e.path}\`):** Content verified; risk of configuration/source-code leakage. Access must be blocked immediately.`));
  for (const e of eolRisks) risks.push(`- **${e.sev} — ${e.bulgu}:** ${e.aciklama}`);
  // (A.2) Dizin listeleme (autoindex) — CWE-548 / OWASP A05. İçerik dökülmez, yalnız listelenen dizin yolu.
  if (dirHits.length) risks.push(t(
    `- **Orta — Dizin listeleme açık (${dirHits.map((d) => `\`${d.path}\``).join(', ')}):** Sunucu dizin içeriğini listeliyor (autoindex/“Index of /”); dosya envanteri dışarıya sızabilir. Dizin listelemeyi kapatın (Nginx \`autoindex off\`, Apache \`Options -Indexes\`). CWE-548 · OWASP A05.`,
    `- **Orta — Verzeichnisauflistung aktiv (${dirHits.map((d) => `\`${d.path}\``).join(', ')}):** Der Server listet den Verzeichnisinhalt auf (autoindex/„Index of /"); ein Dateiinventar kann nach außen abfließen. Deaktivieren Sie die Verzeichnisauflistung (Nginx \`autoindex off\`, Apache \`Options -Indexes\`). CWE-548 · OWASP A05.`,
    `- **Orta — Directory listing enabled (${dirHits.map((d) => `\`${d.path}\``).join(', ')}):** The server lists the directory contents (autoindex/"Index of /"); a file inventory can leak externally. Disable directory listing (Nginx \`autoindex off\`, Apache \`Options -Indexes\`). CWE-548 · OWASP A05.`));
  // (A.3) Verbose error / sunucu-yol ifşası — CWE-209 / OWASP A05. Sızan yol REDAKTE.
  if (errLeaked) risks.push(t(
    `- **Orta — Ayrıntılı hata / sunucu yolu ifşası (${leakX.errorDisclosure.kind === 'stack_trace' ? 'stack izi' : 'sunucu-içi yol'} \`${leakX.errorDisclosure.redacted}\`):** Hata yanıtında iç dizin yapısı/yığın izi sızıyor (yol REDAKTE) — saldırgana teknoloji/dizin ipucu verir. Üretimde genel (generic) hata sayfası kullanın; hata detaylarını/izleri gizleyin. CWE-209 · OWASP A05.`,
    `- **Orta — Ausführlicher Fehler / Serverpfad-Offenlegung (${leakX.errorDisclosure.kind === 'stack_trace' ? 'Stack-Trace' : 'serverinterner Pfad'} \`${leakX.errorDisclosure.redacted}\`):** In der Fehlerantwort werden interne Verzeichnisstruktur/Stack-Trace offengelegt (Pfad REDIGIERT) — gibt einem Angreifer Hinweise auf Technologie/Verzeichnisse. Verwenden Sie in der Produktion eine generische Fehlerseite; verbergen Sie Fehlerdetails/Traces. CWE-209 · OWASP A05.`,
    `- **Orta — Verbose error / server path disclosure (${leakX.errorDisclosure.kind === 'stack_trace' ? 'stack trace' : 'server-internal path'} \`${leakX.errorDisclosure.redacted}\`):** The error response leaks internal directory structure/stack trace (path REDACTED) — gives an attacker technology/directory hints. Use a generic error page in production; hide error details/traces. CWE-209 · OWASP A05.`));
  // (A.4) Parola autocomplete politikası yok — CWE-522 / OWASP A04. Düşük/bilgilendirici sertleştirme.
  if (acObserved) risks.push(t(
    `- **Düşük — Parola alanında autocomplete politikası belirtilmemiş (${leakX.autocomplete.count}):** Paylaşılan/ortak cihaz bağlamında tarayıcı parolayı saklayabilir. Tehdit modelinize göre parola alanlarında \`autocomplete\` politikasını (ör. paylaşılan terminal için \`off\`) değerlendirin. Bilgilendirici sertleştirme. CWE-522 · OWASP A04.`,
    `- **Düşük — Keine autocomplete-Richtlinie im Passwortfeld (${leakX.autocomplete.count}):** In einem geteilten/öffentlichen Gerätekontext kann der Browser das Passwort speichern. Bewerten Sie je nach Bedrohungsmodell die \`autocomplete\`-Richtlinie der Passwortfelder (z. B. \`off\` für geteilte Terminals). Informative Härtung. CWE-522 · OWASP A04.`,
    `- **Düşük — No autocomplete policy on the password field (${leakX.autocomplete.count}):** In a shared/public-device context the browser may store the password. Depending on your threat model, evaluate the \`autocomplete\` policy of the password fields (e.g. \`off\` for shared terminals). Informative hardening. CWE-522 · OWASP A04.`));
  if (missingCrit.length) risks.push(t(`- **Orta — Kritik güvenlik başlıkları eksik (${missingCrit.map((h) => h.name).join(', ')}):** XSS/clickjacking’e karşı tarayıcı savunması zayıf.${hdrCov(missingCrit)}`, `- **Orta — Kritische Sicherheits-Header fehlen (${missingCrit.map((h) => h.name).join(', ')}):** Die Browser-Verteidigung gegen XSS/Clickjacking ist schwach.${hdrCov(missingCrit)}`, `- **Orta — Critical security headers missing (${missingCrit.map((h) => h.name).join(', ')}):** Browser defence against XSS/clickjacking is weak.${hdrCov(missingCrit)}`));
  const otherMissing = missing.filter((h) => !missingCrit.includes(h));
  if (otherMissing.length) risks.push(t(`- **Orta — Ek başlıklar eksik (${otherMissing.map((h) => h.name).join(', ')}):** Savunma derinliği zayıf.${hdrCov(otherMissing)}`, `- **Orta — Weitere Header fehlen (${otherMissing.map((h) => h.name).join(', ')}):** Die Verteidigungstiefe ist schwach.${hdrCov(otherMissing)}`, `- **Orta — Additional headers missing (${otherMissing.map((h) => h.name).join(', ')}):** Defence in depth is weak.${hdrCov(otherMissing)}`));
  if (!risks.length) risks.push(t('- Belirgin bir başlık/sızıntı sorunu öne çıkmadı.', '- Es wurde kein deutliches Header-/Leck-Problem festgestellt.', '- No notable header/leakage issue stood out.'));

  const highReason = exposedHits.length ? t('dışarıdan erişilebilir hassas dosya tespit edildi.', 'eine von außen erreichbare sensible Datei wurde festgestellt.', 'an externally accessible sensitive file was detected.') : t('eski/desteksiz yazılım sürümü ifşa ediliyor (aşağıda).', 'eine veraltete/nicht unterstützte Softwareversion wird offengelegt (siehe unten).', 'an outdated/unsupported software version is being disclosed (below).');
  const medReason = (missingCrit.length || missing.length >= 3) ? t('önemli güvenlik başlığı eksiklikleri var.', 'es bestehen wichtige Lücken bei Sicherheits-Headern.', 'there are significant security-header gaps.') : t('güncel olmayan yazılım sürümü ifşa ediliyor (aşağıda).', 'eine nicht aktuelle Softwareversion wird offengelegt (siehe unten).', 'a non-current software version is being disclosed (below).');
  const bullets: string[] = [];
  bullets.push(`- **${t('Genel risk seviyesi', 'Gesamtrisikostufe', 'Overall risk level')}: ${RW[level]}** — ${level === 'high' ? highReason : level === 'medium' ? medReason : t('ciddi bir sorun öne çıkmadı.', 'es wurde kein ernstes Problem festgestellt.', 'no serious issue stood out.')}`);
  bullets.push(t(`- ${missing.length}/${SEC_HDRS.length} güvenlik başlığı eksik${missing.length ? `: ${missing.map((h) => h.name).join(', ')}` : ''}.`, `- ${missing.length}/${SEC_HDRS.length} Sicherheits-Header fehlen${missing.length ? `: ${missing.map((h) => h.name).join(', ')}` : ''}.`, `- ${missing.length}/${SEC_HDRS.length} security headers missing${missing.length ? `: ${missing.map((h) => h.name).join(', ')}` : ''}.`));
  bullets.push(t(`- Açıkta dosya: ${exposedHits.length ? `⚠️ ${exposedHits.map((e) => e.path).join(', ')}` : 'tespit edilmedi'}.`, `- Offenliegende Datei: ${exposedHits.length ? `⚠️ ${exposedHits.map((e) => e.path).join(', ')}` : 'keine festgestellt'}.`, `- Exposed file: ${exposedHits.length ? `⚠️ ${exposedHits.map((e) => e.path).join(', ')}` : 'none detected'}.`));
  if (eolRisks.length) bullets.push(t(`- ⚠️ Eski/desteksiz yazılım sürümü ifşası: ${eolRisks.map((e) => e.bulgu.replace(/^.*\(/, '(')).join(', ')}.`, `- ⚠️ Offenlegung einer veralteten/nicht unterstützten Softwareversion: ${eolRisks.map((e) => e.bulgu.replace(/^.*\(/, '(')).join(', ')}.`, `- ⚠️ Disclosure of an outdated/unsupported software version: ${eolRisks.map((e) => e.bulgu.replace(/^.*\(/, '(')).join(', ')}.`));
  bullets.push(`- **${t('Önerilen ilk adım', 'Empfohlener erster Schritt', 'Recommended first step')}:** ` + (exposedHits.length ? t('Açıkta kalan dosyalara erişimi engelleyin ve ', 'Sperren Sie den Zugriff auf die offenliegenden Dateien und ', 'Block access to the exposed files and ') : eolRisks.length ? t('İfşa edilen eski yazılımı güncel sürüme yükseltin ve ', 'Aktualisieren Sie die offengelegte veraltete Software auf eine aktuelle Version und ', 'Upgrade the disclosed outdated software to a current version and ') : '') + t('eksik güvenlik başlıklarını ekleyin (hazır komutlar "AI Çözüm Önerileri" eklentisinde).', 'ergänzen Sie die fehlenden Sicherheits-Header (fertige Befehle im Add-on „KI-Lösungsvorschläge").', 'add the missing security headers (ready-made commands in the "AI Remediation Suggestions" add-on).'));

  const eolClause = eolRisks.length ? t(` Ayrıca eski/desteksiz yazılım sürümü ifşa ediliyor (${eolRisks.map((e) => e.bulgu.replace(/^.*\(/, '(')).join(', ')}); güncel sürüme yükseltilmelidir.`, ` Zudem wird eine veraltete/nicht unterstützte Softwareversion offengelegt (${eolRisks.map((e) => e.bulgu.replace(/^.*\(/, '(')).join(', ')}); sie sollte auf eine aktuelle Version aktualisiert werden.`, ` In addition, an outdated/unsupported software version is being disclosed (${eolRisks.map((e) => e.bulgu.replace(/^.*\(/, '(')).join(', ')}); it should be upgraded to a current version.`) : '';
  const genel =
    level === 'high'
      ? (exposedHits.length
          ? t(`Dışarıdan erişilebilen hassas bir dosya tespit edildi (içerik doğrulandı); öncelikli olarak erişimin engellenmesi gerekir.${eolClause} Ayrıca eksik güvenlik başlıkları savunmayı zayıflatıyor.`, `Eine von außen erreichbare sensible Datei wurde festgestellt (Inhalt verifiziert); der Zugriff muss vorrangig gesperrt werden.${eolClause} Zudem schwächen fehlende Sicherheits-Header die Verteidigung.`, `An externally accessible sensitive file was detected (content verified); access must be blocked as a priority.${eolClause} Missing security headers also weaken the defence.`)
          : t(`Eski/desteksiz yazılım sürümü ifşa ediliyor; bilinen güvenlik açıkları yamasız kalabilir — öncelikli olarak güncel, desteklenen sürüme yükseltilmelidir.`, `Eine veraltete/nicht unterstützte Softwareversion wird offengelegt; bekannte Sicherheitslücken können ungepatcht bleiben — vorrangig sollte auf eine aktuelle, unterstützte Version aktualisiert werden.`, `An outdated/unsupported software version is being disclosed; known vulnerabilities may remain unpatched — it should be upgraded to a current, supported version as a priority.`))
      : level === 'medium'
        ? t(`${(missingCrit.length || missing.length >= 3) ? 'Önemli güvenlik başlığı eksiklikleri var; hassas dosya sızıntısı tespit edilmedi. Eksik başlıklar düşük maliyetli sunucu ayarlarıyla kapatılabilir.' : 'Güncel olmayan bir yazılım sürümü ifşa ediliyor; desteklenen sürüme yükseltilmesi önerilir.'}${(missingCrit.length || missing.length >= 3) ? eolClause : ''}`, `${(missingCrit.length || missing.length >= 3) ? 'Es bestehen wichtige Lücken bei Sicherheits-Headern; kein Datei-Leck festgestellt. Fehlende Header lassen sich mit kostengünstigen Servereinstellungen schließen.' : 'Eine nicht aktuelle Softwareversion wird offengelegt; ein Upgrade auf eine unterstützte Version wird empfohlen.'}${(missingCrit.length || missing.length >= 3) ? eolClause : ''}`, `${(missingCrit.length || missing.length >= 3) ? 'There are significant security-header gaps; no sensitive-file leakage was detected. Missing headers can be closed with low-cost server settings.' : 'A non-current software version is being disclosed; upgrading to a supported version is recommended.'}${(missingCrit.length || missing.length >= 3) ? eolClause : ''}`)
        : t('Güvenlik başlıkları büyük ölçüde mevcut ve dışarıdan erişilebilen hassas dosya bulunmadı.', 'Die Sicherheits-Header sind weitgehend vorhanden und es wurde keine von außen erreichbare sensible Datei gefunden.', 'Security headers are largely present and no externally accessible sensitive file was found.');

  const findings = assemble('Başlıklar', level, bullets, genel, `${table}${leakSection}${leakExtrasSection}## ${t('TESPİT EDİLEN RİSKLER', 'FESTGESTELLTE RISIKEN', 'IDENTIFIED RISKS')}\n\n${risksTable(risks, locale)}\n`, locale);
  const fixText = buildHeaderFixSuggestions(findings, host, locale) + (exposedHits.length ? '\n\n' + buildExposedFileFix(exposedHits.map((e) => e.path), locale) : '');
  return { findings, fixText };
}

// ======================================================================================
// 3) dns_email — DNS & E-posta Güvenliği
// ======================================================================================
export async function generateDnsEmailReport(host: string, locale: string = 'tr'): Promise<{ findings: string; fixText: string } | null> {
  const de = locale === 'de';
  const t = (trS: string, deS: string, enS?: string) => (locale === 'de' ? deS : locale === 'en' ? (enS ?? trS) : trS);
  const RW = locale === 'en' ? RISK_WORD_EN : de ? RISK_WORD_DE : RISK_WORD;
  const dns = await collectDns(host);
  if (!dns.ok) return null;

  // (İŞ 2) SORGULANAMADI (geçici DNS hatası) != KAYIT YOK. Sorgu başarısızsa "eksik/Yüksek" TETİKLENMEZ.
  const spfQueried = dns.spf?.queried !== false;
  const dmarcQueried = dns.dmarc?.queried !== false;
  const spfWeak = spfQueried && (!dns.spf || dns.spf.all === 'yok' || dns.spf.all === '+all' || dns.spf.all === '?all');
  const spfMissing = spfQueried && (!dns.spf || dns.spf.all === 'yok');
  const dmarcMissing = dmarcQueried && (!dns.dmarc || dns.dmarc.policy === 'yok');
  const dmarcWeak = dns.dmarc?.policy === 'none';
  const dkimMissing = !dns.dkim?.found;
  const dnsInconclusive = !spfQueried || !dmarcQueried;

  let level: Level = 'low';
  if (spfMissing && dmarcMissing) level = 'high'; // spoofing sonuna kadar acik
  else {
    const authWeak = [spfMissing || spfWeak, dmarcMissing || dmarcWeak].filter(Boolean).length;
    if (authWeak >= 2) level = 'high';
    else if (authWeak >= 1) level = 'medium';
  }

  const checked = dns.checkedDomain;
  const spfSection =
    `## ${t('SPF (Gönderen Politikası) — kontrol edilen alan', 'SPF (Sender-Richtlinie) — geprüfte Domain', 'SPF (Sender Policy) — checked domain')}: \`${checked}\`\n\n` +
    (!spfQueried
      ? `- **${t('Durum', 'Status', 'Status')}:** ` + t(`Sorgulanamadı — geçici bir DNS hatası nedeniyle SPF kaydı bu taramada okunamadı. Bu **"kayıt yok" anlamına gelmez**; lütfen taramayı tekrarlayın.\n\n`, `Nicht abfragbar — aufgrund eines temporären DNS-Fehlers konnte der SPF-Eintrag in dieser Prüfung nicht gelesen werden. Das bedeutet **NICHT „kein Eintrag"**; bitte wiederholen Sie die Prüfung.\n\n`, `Not queryable — due to a temporary DNS error the SPF record could not be read in this scan. This does **NOT mean "no record"**; please repeat the scan.\n\n`)
      : dns.spf && dns.spf.all !== 'yok'
        ? `- **${t('Durum', 'Status', 'Status')}:** ` + t(`Var — \`${dns.spf.record}\`\n- **Sertlik:** \`${dns.spf.all}\` — ${dns.spf.all === '-all' ? 'katı (hardfail; en güvenli).' : dns.spf.all === '~all' ? 'yumuşak (softfail; kabul edilebilir, ideal değil).' : dns.spf.all === '+all' || dns.spf.all === '?all' ? '⚠️ zayıf/etkisiz — herkesin sizin adınıza mail göndermesine izin verir.' : 'belirsiz.'}\n\n`, `Vorhanden — \`${dns.spf.record}\`\n- **Härte:** \`${dns.spf.all}\` — ${dns.spf.all === '-all' ? 'streng (hardfail; am sichersten).' : dns.spf.all === '~all' ? 'weich (softfail; akzeptabel, nicht ideal).' : dns.spf.all === '+all' || dns.spf.all === '?all' ? '⚠️ schwach/wirkungslos — erlaubt jedem, in Ihrem Namen E-Mails zu senden.' : 'unklar.'}\n\n`, `Present — \`${dns.spf.record}\`\n- **Strictness:** \`${dns.spf.all}\` — ${dns.spf.all === '-all' ? 'strict (hardfail; most secure).' : dns.spf.all === '~all' ? 'soft (softfail; acceptable, not ideal).' : dns.spf.all === '+all' || dns.spf.all === '?all' ? '⚠️ weak/ineffective — allows anyone to send mail in your name.' : 'unclear.'}\n\n`)
        : `- **${t('Durum', 'Status', 'Status')}:** ` + t(`Yok — SPF kaydı bulunamadı. Alan adınız adına sahte e-posta gönderimi (spoofing) kolaylaşır.\n\n`, `Fehlt — Es wurde kein SPF-Eintrag gefunden. Das Versenden gefälschter E-Mails (Spoofing) in Ihrem Domain-Namen wird erleichtert.\n\n`, `Absent — No SPF record was found. Sending forged email (spoofing) in your domain's name becomes easier.\n\n`));
  const dmarcSection =
    `## ${t('DMARC (Kimlik Doğrulama Politikası) — kontrol edilen alan', 'DMARC (Authentifizierungsrichtlinie) — geprüfte Domain', 'DMARC (Authentication Policy) — checked domain')}: \`${checked}\`\n\n` +
    (!dmarcQueried
      ? `- **${t('Durum', 'Status', 'Status')}:** ` + t(`Sorgulanamadı — geçici bir DNS hatası nedeniyle DMARC kaydı bu taramada okunamadı. Bu **"kayıt yok" anlamına gelmez**; lütfen taramayı tekrarlayın.\n\n`, `Nicht abfragbar — aufgrund eines temporären DNS-Fehlers konnte der DMARC-Eintrag in dieser Prüfung nicht gelesen werden. Das bedeutet **NICHT „kein Eintrag"**; bitte wiederholen Sie die Prüfung.\n\n`, `Not queryable — due to a temporary DNS error the DMARC record could not be read in this scan. This does **NOT mean "no record"**; please repeat the scan.\n\n`)
      : dns.dmarc && dns.dmarc.policy !== 'yok'
        ? `- **${t('Durum', 'Status', 'Status')}:** ` + t(`Var — \`${dns.dmarc.record}\`\n- **Politika:** \`p=${dns.dmarc.policy}\` — ${dns.dmarc.policy === 'reject' ? 'güçlü (sahte mailler reddedilir).' : dns.dmarc.policy === 'quarantine' ? 'orta (sahte mailler spam’e düşer).' : '⚠️ zayıf (p=none; yalnızca izler, engellemez).'}\n\n`, `Vorhanden — \`${dns.dmarc.record}\`\n- **Richtlinie:** \`p=${dns.dmarc.policy}\` — ${dns.dmarc.policy === 'reject' ? 'stark (gefälschte Mails werden abgelehnt).' : dns.dmarc.policy === 'quarantine' ? 'mittel (gefälschte Mails landen im Spam).' : '⚠️ schwach (p=none; überwacht nur, blockiert nicht).'}\n\n`, `Present — \`${dns.dmarc.record}\`\n- **Policy:** \`p=${dns.dmarc.policy}\` — ${dns.dmarc.policy === 'reject' ? 'strong (forged mail is rejected).' : dns.dmarc.policy === 'quarantine' ? 'medium (forged mail lands in spam).' : '⚠️ weak (p=none; monitors only, does not block).'}\n\n`)
        : `- **${t('Durum', 'Status', 'Status')}:** ` + t(`Yok — DMARC kaydı bulunamadı. SPF/DKIM sonuçlarına göre uygulama yapılmıyor; spoofing’e karşı koruma zayıf.\n\n`, `Fehlt — Es wurde kein DMARC-Eintrag gefunden. Es erfolgt keine Durchsetzung anhand der SPF/DKIM-Ergebnisse; der Schutz vor Spoofing ist schwach.\n\n`, `Absent — No DMARC record was found. No enforcement is applied based on SPF/DKIM results; protection against spoofing is weak.\n\n`));
  const dkimSection =
    `## ${t('DKIM (İmza)', 'DKIM (Signatur)', 'DKIM (Signature)')}\n\n` +
    (dns.dkim?.found
      ? `- **${t('Durum', 'Status', 'Status')}:** ` + t(`Tespit edildi (\`${dns.dkim.selector}._domainkey\` seçicisi). E-postalar kriptografik olarak imzalanıyor.\n\n`, `Erkannt (Selektor \`${dns.dkim.selector}._domainkey\`). E-Mails werden kryptografisch signiert.\n\n`, `Detected (selector \`${dns.dkim.selector}._domainkey\`). Emails are cryptographically signed.\n\n`)
      : `- **${t('Durum', 'Status', 'Status')}:** ` + t(`Tespit edilemedi — Yaygın seçicilerde (default/google/selector1…) DKIM kaydı bulunamadı. Farklı bir seçici kullanıyor olabilirsiniz; bu kesin “yok” anlamına gelmez.\n\n`, `Nicht erkannt — Bei gängigen Selektoren (default/google/selector1…) wurde kein DKIM-Eintrag gefunden. Möglicherweise verwenden Sie einen anderen Selektor; dies bedeutet nicht sicher „kein Eintrag".\n\n`, `Not detected — No DKIM record was found at common selectors (default/google/selector1…). You may be using a different selector; this does not definitely mean "no record".\n\n`));
  const dnssecSection =
    `## DNSSEC\n\n- **${t('Durum', 'Status', 'Status')}:** ${dns.dnssec ? t('Aktif — DNS yanıtları kriptografik olarak imzalı (DNS zehirlenmesine karşı koruma).', 'Aktiv — DNS-Antworten sind kryptografisch signiert (Schutz gegen DNS-Poisoning).', 'Active — DNS responses are cryptographically signed (protection against DNS poisoning).') : t('Pasif/yok — DNS yanıtları imzalı değil; DNS spoofing/cache-poisoning riskine daha açık.', 'Passiv/fehlt — DNS-Antworten sind nicht signiert; erhöhtes Risiko für DNS-Spoofing/Cache-Poisoning.', 'Passive/absent — DNS responses are not signed; more exposed to DNS spoofing/cache-poisoning risk.')}\n\n`;

  const risks: string[] = [];
  if (spfMissing && dmarcMissing) risks.push(t('- **Yüksek — Alan adınız e-posta sahteciliğine (spoofing) tamamen açık:** Ne SPF ne DMARC var. Saldırgan sizin adınıza sahte e-posta gönderebilir.', '- **Yüksek — Ihre Domain ist vollständig anfällig für E-Mail-Spoofing:** Weder SPF noch DMARC vorhanden. Ein Angreifer kann in Ihrem Namen gefälschte E-Mails senden.', '- **Yüksek — Your domain is fully exposed to email spoofing:** Neither SPF nor DMARC is present. An attacker can send forged email in your name.'));
  else {
    if (spfMissing) risks.push(t('- **Orta — SPF eksik:** Yetkili gönderen sunucular tanımlı değil.', '- **Orta — SPF fehlt:** Es sind keine autorisierten sendenden Server definiert.', '- **Orta — SPF missing:** No authorised sending servers are defined.'));
    else if (spfWeak) risks.push(t(`- **Orta — SPF zayıf (\`${dns.spf?.all}\`):** Sahte gönderimi etkili biçimde engellemiyor.`, `- **Orta — SPF schwach (\`${dns.spf?.all}\`):** Verhindert gefälschten Versand nicht wirksam.`, `- **Orta — SPF weak (\`${dns.spf?.all}\`):** Does not effectively prevent forged sending.`));
    if (dmarcMissing) risks.push(t('- **Orta — DMARC eksik:** SPF/DKIM sonuçları uygulanmıyor.', '- **Orta — DMARC fehlt:** Die SPF/DKIM-Ergebnisse werden nicht durchgesetzt.', '- **Orta — DMARC missing:** SPF/DKIM results are not enforced.'));
    else if (dmarcWeak) risks.push(t('- **Orta — DMARC zayıf (`p=none`):** Yalnızca raporlama; sahte mailler yine de teslim edilir.', '- **Orta — DMARC schwach (`p=none`):** Nur Berichterstattung; gefälschte Mails werden dennoch zugestellt.', '- **Orta — DMARC weak (`p=none`):** Reporting only; forged mail is still delivered.'));
  }
  if (dnsInconclusive) risks.push(t(`- **Bilgilendirme — ${!spfQueried && !dmarcQueried ? 'SPF ve DMARC' : !spfQueried ? 'SPF' : 'DMARC'} sorgulanamadı:** Geçici DNS hatası; "kayıt yok" olarak değerlendirilMEDİ. Kesin sonuç için taramayı tekrarlayın.`, `- **Bilgilendirme — ${!spfQueried && !dmarcQueried ? 'SPF und DMARC' : !spfQueried ? 'SPF' : 'DMARC'} nicht abfragbar:** Temporärer DNS-Fehler; wurde NICHT als „kein Eintrag" gewertet. Für ein sicheres Ergebnis wiederholen Sie die Prüfung.`, `- **Bilgilendirme — ${!spfQueried && !dmarcQueried ? 'SPF and DMARC' : !spfQueried ? 'SPF' : 'DMARC'} not queryable:** Temporary DNS error; was NOT treated as "no record". Repeat the scan for a definitive result.`));
  if (dkimMissing) risks.push(t('- **Bilgilendirme — DKIM tespit edilemedi:** Yaygın seçicilerde bulunamadı (farklı seçici olabilir).', '- **Bilgilendirme — DKIM nicht erkannt:** Bei gängigen Selektoren nicht gefunden (möglicherweise anderer Selektor).', '- **Bilgilendirme — DKIM not detected:** Not found at common selectors (may be a different selector).'));
  if (!dns.dnssec) risks.push(t('- **Bilgilendirme — DNSSEC pasif:** DNS yanıtları imzalı değil.', '- **Bilgilendirme — DNSSEC passiv:** Die DNS-Antworten sind nicht signiert.', '- **Bilgilendirme — DNSSEC passive:** DNS responses are not signed.'));
  if (!risks.length) risks.push(t('- E-posta kimlik doğrulama kayıtları (SPF/DMARC/DKIM) düzgün yapılandırılmış.', '- Die E-Mail-Authentifizierungseinträge (SPF/DMARC/DKIM) sind ordnungsgemäß konfiguriert.', '- Email authentication records (SPF/DMARC/DKIM) are properly configured.'));

  const bullets: string[] = [];
  bullets.push(`- **${t('Genel risk seviyesi', 'Gesamtrisikostufe', 'Overall risk level')}: ${RW[level]}** — ${level === 'high' ? t('e-posta sahteciliğine karşı koruma kritik seviyede zayıf.', 'der Schutz vor E-Mail-Spoofing ist kritisch schwach.', 'protection against email spoofing is critically weak.') : level === 'medium' ? t('e-posta kimlik doğrulamasında giderilmesi gereken eksikler var.', 'bei der E-Mail-Authentifizierung bestehen zu behebende Lücken.', 'there are gaps to be addressed in email authentication.') : t('e-posta kimlik doğrulama kayıtları büyük ölçüde sağlam.', 'die E-Mail-Authentifizierungseinträge sind weitgehend solide.', 'email authentication records are largely sound.')}`);
  const spfSummary = !spfQueried ? t('sorgulanamadı', 'nicht abfragbar', 'not queryable') : dns.spf && dns.spf.all !== 'yok' ? t(`var (${dns.spf.all})`, `vorhanden (${dns.spf.all})`, `present (${dns.spf.all})`) : t('yok', 'fehlt', 'absent');
  const dmarcSummary = !dmarcQueried ? t('sorgulanamadı', 'nicht abfragbar', 'not queryable') : dns.dmarc && dns.dmarc.policy !== 'yok' ? `p=${dns.dmarc.policy}` : t('yok', 'fehlt', 'absent');
  bullets.push(`- SPF: ${spfSummary} · DMARC: ${dmarcSummary} · DKIM: ${dns.dkim?.found ? t('var', 'vorhanden', 'present') : t('tespit edilemedi', 'nicht erkannt', 'not detected')} · DNSSEC: ${dns.dnssec ? t('aktif', 'aktiv', 'active') : t('yok', 'fehlt', 'absent')}.`);
  bullets.push(`- **${t('Önerilen ilk adım', 'Empfohlener erster Schritt', 'Recommended first step')}:** ` + (spfMissing || dmarcMissing ? t('SPF ve DMARC kayıtlarını ekleyin (örnek TXT kayıtları "AI Çözüm Önerileri" eklentisinde).', 'Ergänzen Sie SPF- und DMARC-Einträge (Beispiel-TXT-Einträge im Add-on „KI-Lösungsvorschläge").', 'Add SPF and DMARC records (example TXT records in the "AI Remediation Suggestions" add-on).') : t('DMARC politikasını kademeli sıkılaştırın (none → quarantine → reject).', 'Verschärfen Sie die DMARC-Richtlinie schrittweise (none → quarantine → reject).', 'Tighten the DMARC policy gradually (none → quarantine → reject).')));

  const genel =
    level === 'high'
      ? t('Alan adınız e-posta sahteciliğine (spoofing/phishing) karşı yetersiz korunuyor; SPF/DMARC eksik veya etkisiz. Öncelikli olarak ele alınması önerilir.', 'Ihre Domain ist unzureichend gegen E-Mail-Spoofing/Phishing geschützt; SPF/DMARC fehlen oder sind wirkungslos. Eine vorrangige Behandlung wird empfohlen.', 'Your domain is inadequately protected against email spoofing/phishing; SPF/DMARC are missing or ineffective. Priority attention is recommended.')
      : level === 'medium'
        ? t('E-posta kimlik doğrulama kayıtlarında (SPF/DMARC/DKIM) giderilmesi önerilen eksikler var. Bunlar kademeli olarak sıkılaştırılabilir.', 'Bei den E-Mail-Authentifizierungseinträgen (SPF/DMARC/DKIM) bestehen zu behebende Lücken. Diese können schrittweise verschärft werden.', 'There are gaps recommended for remediation in the email authentication records (SPF/DMARC/DKIM). These can be tightened gradually.')
        : t('E-posta kimlik doğrulama kayıtları büyük ölçüde sağlam; rapor yalnızca küçük iyileştirmeleri listeler.', 'Die E-Mail-Authentifizierungseinträge sind weitgehend solide; der Bericht listet nur kleine Verbesserungen auf.', 'Email authentication records are largely sound; the report lists only minor improvements.');

  const findings = assemble('DNS/E-posta', level, bullets, genel, `${spfSection}${dmarcSection}${dkimSection}${dnssecSection}## ${t('TESPİT EDİLEN RİSKLER', 'FESTGESTELLTE RISIKEN', 'IDENTIFIED RISKS')}\n\n${risksTable(risks, locale)}\n`, locale);
  const fixText = buildDnsFix(host, dns, locale);
  return { findings, fixText };
}

// ======================================================================================
// 4) cors_cookie — CORS & Çerez Güvenliği
// ======================================================================================
const CORS_SEV = (c: CorsEvidence): number => ((c.wildcard || c.reflected) && /true/i.test(c.acac ?? '') ? 3 : c.wildcard || c.reflected ? 2 : c.acao ? 1 : 0);

export async function generateCorsCookieReport(host: string, locale: string = 'tr'): Promise<{ findings: string; fixText: string } | null> {
  const de = locale === 'de';
  const t = (trS: string, deS: string, enS?: string) => (locale === 'de' ? deS : locale === 'en' ? (enS ?? trS) : trS);
  const RW = locale === 'en' ? RISK_WORD_EN : de ? RISK_WORD_DE : RISK_WORD;
  // (BÖLÜM 1 — ÇOK SAYFA) CORS ve çerez politikaları PATH-BAZLI değişebilir (/api altında farklı,
  // statik sayfada farklı). Keşfedilen sayfaların HER BİRİNDE çerez bayraklarını + CORS'u değerlendir.
  // PASİF: yalnız GET (+ zararsız Origin request-header'ı); prob/payload YOK.
  const pages = await collectPages(host);
  if (!pages.length) return null; // hedefe ulaşılamadı -> alan null; bundle "İncelenemedi"e düşer
  const pageCount = pages.length;
  const pathOf = (u: string) => { try { return new URL(u).pathname + (new URL(u).search || ''); } catch { return u; } };

  // --- ÇEREZLER: tüm sayfalardaki Set-Cookie'leri çerez ADINA göre birleştir; en GÜVENSİZ hâli tut,
  //     hangi sayfalarda set edildiğini kaydet. (Grok kritiği: her çerez ayrı ayrı, hangi bayrak eksik.)
  const cookieMap = new Map<string, { c: Cookie; onPages: Set<string> }>();
  for (const pg of pages) for (const raw of pg.setCookies) {
    const c = parseCookie(raw, locale);
    const e = cookieMap.get(c.name);
    if (!e) cookieMap.set(c.name, { c, onPages: new Set([pathOf(pg.url)]) });
    else { e.onPages.add(pathOf(pg.url)); e.c = { name: c.name, secure: e.c.secure && c.secure, httpOnly: e.c.httpOnly && c.httpOnly, sameSite: e.c.sameSite ?? c.sameSite }; }
  }
  const cookieEntries = [...cookieMap.values()];
  const insecureCookies = cookieEntries.filter((e) => !e.c.secure || !e.c.httpOnly);
  const sameSiteNone = cookieEntries.filter((e) => e.c.sameSite === 'None' && !e.c.secure);

  // --- CORS: her sayfada zararsız Origin probe (en fazla 10 sayfa). En kötü + sayfa-özel sapma.
  const corsPer: Array<{ path: string; cors: CorsEvidence }> = [];
  for (const pg of pages.slice(0, 10)) corsPer.push({ path: pathOf(pg.url), cors: await collectCorsForUrl(pg.url) });
  const corsOkList = corsPer.filter((x) => x.cors.ok);
  const worst = corsOkList.reduce<{ path: string; cors: CorsEvidence } | null>((w, x) => (!w || CORS_SEV(x.cors) > CORS_SEV(w.cors) ? x : w), null);
  const worstCors = worst?.cors ?? { ok: false, testedOrigin: '', reflected: false, wildcard: false };
  const credsWildcardDanger = CORS_SEV(worstCors) >= 3;
  // sayfaya-özgü: CORS en kötüsü home'dan FARKLI bir path'te mi (bazı sayfalar açık, diğerleri kapalı)
  const corsVariance = worst && CORS_SEV(worstCors) >= 2 && corsOkList.some((x) => CORS_SEV(x.cors) < CORS_SEV(worstCors));

  let level: Level = 'low';
  if (credsWildcardDanger) level = 'high';
  else if (CORS_SEV(worstCors) >= 2 || insecureCookies.length) level = 'medium';

  const covPages = (paths: Set<string>) => t(`${paths.size}/${pageCount} sayfada`, `auf ${paths.size}/${pageCount} Seiten`, `on ${paths.size}/${pageCount} pages`);
  const corsSection =
    `## ${t('CORS YAPILANDIRMASI', 'CORS-KONFIGURATION', 'CORS CONFIGURATION')} (${t(`${corsOkList.length}/${pageCount} sayfada test edildi`, `auf ${corsOkList.length}/${pageCount} Seiten getestet`, `tested on ${corsOkList.length}/${pageCount} pages`)})\n\n` +
    (!worst
      ? t('- CORS yanıtı elde edilemedi.\n\n', '- Es konnte keine CORS-Antwort ermittelt werden.\n\n', '- No CORS response could be obtained.\n\n')
      : t(`- **Test Origin:** \`${worstCors.testedOrigin}\` — her sayfaya zararsız bir Origin başlığı gönderilip yanıt değerlendirildi.\n`, `- **Test-Origin:** \`${worstCors.testedOrigin}\` — an jede Seite wurde ein harmloser Origin-Header gesendet und die Antwort ausgewertet.\n`, `- **Test Origin:** \`${worstCors.testedOrigin}\` — a harmless Origin header was sent to each page and the response evaluated.\n`) +
        t(`- **En açık gözlemlenen politika** (\`${worst.path}\`): Access-Control-Allow-Origin: ${worstCors.acao ? `\`${worstCors.acao}\`` : 'gönderilmiyor (kapalı — güvenli varsayılan)'}${worstCors.wildcard ? ' — ⚠️ wildcard (`*`)' : worstCors.reflected ? ' — ⚠️ Origin yansıtma' : ''}; Allow-Credentials: ${worstCors.acac ? `\`${worstCors.acac}\`` : 'gönderilmiyor'}.\n`, `- **Offenste beobachtete Richtlinie** (\`${worst.path}\`): Access-Control-Allow-Origin: ${worstCors.acao ? `\`${worstCors.acao}\`` : 'wird nicht gesendet (geschlossen — sichere Voreinstellung)'}${worstCors.wildcard ? ' — ⚠️ Wildcard (`*`)' : worstCors.reflected ? ' — ⚠️ Origin-Spiegelung' : ''}; Allow-Credentials: ${worstCors.acac ? `\`${worstCors.acac}\`` : 'wird nicht gesendet'}.\n`, `- **Most permissive observed policy** (\`${worst.path}\`): Access-Control-Allow-Origin: ${worstCors.acao ? `\`${worstCors.acao}\`` : 'not sent (closed — secure default)'}${worstCors.wildcard ? ' — ⚠️ wildcard (`*`)' : worstCors.reflected ? ' — ⚠️ Origin reflection' : ''}; Allow-Credentials: ${worstCors.acac ? `\`${worstCors.acac}\`` : 'not sent'}.\n`) +
        (credsWildcardDanger ? t(`- ⚠️ **TEHLİKELİ KOMBİNASYON:** Kimlik bilgisi (credentials) + açık/yansıtılan origin — başka sitelerin kullanıcı oturumuyla veri okumasına yol açabilir.\n`, `- ⚠️ **GEFÄHRLICHE KOMBINATION:** Anmeldeinformationen (Credentials) + offener/gespiegelter Origin — kann dazu führen, dass andere Websites mit der Nutzersitzung Daten auslesen.\n`, `- ⚠️ **DANGEROUS COMBINATION:** Credentials + open/reflected origin — can allow other sites to read data using the user's session.\n`) : '') +
        (corsVariance ? t(`- ℹ️ CORS politikası sayfaya göre DEĞİŞİYOR (bazı yollar açık, bazıları kapalı) — en açık yol yukarıda.\n`, `- ℹ️ Die CORS-Richtlinie VARIIERT je Seite (einige Pfade offen, andere geschlossen) — der offenste Pfad oben.\n`, `- ℹ️ The CORS policy VARIES by page (some paths open, others closed) — the most permissive path above.\n`) : '') +
        '\n');

  const cookieSection =
    `## ${t('ÇEREZ BAYRAKLARI', 'COOKIE-FLAGS', 'COOKIE FLAGS')} (${t(`${pageCount} sayfada gözlemlenen tüm çerezler`, `alle auf ${pageCount} Seiten beobachteten Cookies`, `all cookies observed across ${pageCount} pages`)})\n\n` +
    (cookieEntries.length === 0
      ? t(`- Taranan ${pageCount} sayfanın hiçbirinde Set-Cookie gözlemlenmedi.\n\n`, `- Auf keiner der ${pageCount} geprüften Seiten wurde ein Set-Cookie beobachtet.\n\n`, `- No Set-Cookie was observed on any of the ${pageCount} scanned pages.\n\n`)
      : `| ${t('Çerez', 'Cookie', 'Cookie')} | Secure | HttpOnly | SameSite | ${t('Gözlemlendiği yer', 'Beobachtet auf', 'Observed on')} | ${t('Not', 'Hinweis', 'Note')} |\n|-------|--------|----------|----------|------------------|-----|\n` +
        cookieEntries.map((e) => `| \`${e.c.name}\` | ${e.c.secure ? '✅' : '❌'} | ${e.c.httpOnly ? '✅' : '❌'} | ${e.c.sameSite ?? '—'} | ${covPages(e.onPages)} | ${cookieNote(e.c, locale)} |`).join('\n') + '\n\n');

  const risks: string[] = [];
  if (credsWildcardDanger) risks.push(t(`- **Yüksek — Tehlikeli CORS kombinasyonu (\`${worst!.path}\`):** \`Allow-Credentials: true\` ile açık/yansıtılan \`Allow-Origin\`. Kötü niyetli bir site, kurbanın oturum çerezleriyle bu uç noktadan veri çekip saldırgana gönderebilir (hesap verisi sızıntısı).`, `- **Yüksek — Gefährliche CORS-Kombination (\`${worst!.path}\`):** \`Allow-Credentials: true\` mit offenem/gespiegeltem \`Allow-Origin\`. Eine bösartige Website kann mit den Sitzungscookies des Opfers Daten von diesem Endpunkt abrufen und an den Angreifer senden (Leck von Kontodaten).`, `- **Yüksek — Dangerous CORS combination (\`${worst!.path}\`):** \`Allow-Credentials: true\` with an open/reflected \`Allow-Origin\`. A malicious site could pull data from this endpoint using the victim's session cookies and send it to the attacker (account-data leakage).`));
  else if (worstCors.wildcard) risks.push(t(`- **Orta — CORS wildcard (\`*\`, \`${worst!.path}\`):** Tüm kökenlere açık. Kimlik bilgisi olmayan uç noktalarda kabul edilebilir; hassas API'lerde origin allowlist önerilir.`, `- **Orta — CORS-Wildcard (\`*\`, \`${worst!.path}\`):** Für alle Origins offen. Bei Endpunkten ohne Anmeldeinformationen akzeptabel; bei sensiblen APIs wird eine Origin-Allowlist empfohlen.`, `- **Orta — CORS wildcard (\`*\`, \`${worst!.path}\`):** Open to all origins. Acceptable on endpoints without credentials; an origin allowlist is recommended for sensitive APIs.`));
  else if (worstCors.reflected) risks.push(t(`- **Orta — CORS Origin yansıtması (\`${worst!.path}\`):** Gelen Origin doğrulanmadan yansıtılıyor; bir allowlist ile sınırlanmalı.`, `- **Orta — CORS-Origin-Spiegelung (\`${worst!.path}\`):** Der eingehende Origin wird ohne Prüfung gespiegelt; er sollte mit einer Allowlist eingeschränkt werden.`, `- **Orta — CORS Origin reflection (\`${worst!.path}\`):** The incoming Origin is reflected without validation; it should be constrained with an allowlist.`));
  for (const e of insecureCookies) risks.push(t(`- **Orta — Çerez bayrağı eksik (\`${e.c.name}\`, ${covPages(e.onPages)}):** ${!e.c.secure ? '**Secure yok** — çerez HTTP üzerinden düz metin gidebilir, ağ dinleyen bir saldırgan oturum çerezini çalabilir. ' : ''}${!e.c.httpOnly ? '**HttpOnly yok** — bir XSS açığı olması hâlinde JavaScript çerezi okuyup oturumu ele geçirebilir.' : ''}`, `- **Orta — Fehlendes Cookie-Flag (\`${e.c.name}\`, ${covPages(e.onPages)}):** ${!e.c.secure ? '**Kein Secure** — das Cookie kann im Klartext über HTTP übertragen werden; ein Angreifer, der das Netzwerk mithört, kann das Sitzungscookie stehlen. ' : ''}${!e.c.httpOnly ? '**Kein HttpOnly** — bei einer XSS-Schwachstelle kann JavaScript das Cookie auslesen und die Sitzung übernehmen.' : ''}`, `- **Orta — Missing cookie flag (\`${e.c.name}\`, ${covPages(e.onPages)}):** ${!e.c.secure ? '**No Secure** — the cookie may be sent in the clear over HTTP; an attacker eavesdropping on the network could steal the session cookie. ' : ''}${!e.c.httpOnly ? '**No HttpOnly** — if an XSS flaw exists, JavaScript can read the cookie and hijack the session.' : ''}`));
  for (const e of sameSiteNone) risks.push(t(`- **Orta — \`${e.c.name}\` SameSite=None ama Secure yok (${covPages(e.onPages)}):** Modern tarayıcılar reddeder; ayrıca CSRF yüzeyini artırır.`, `- **Orta — \`${e.c.name}\` SameSite=None, aber kein Secure (${covPages(e.onPages)}):** Moderne Browser lehnen es ab; erhöht zudem die CSRF-Fläche.`, `- **Orta — \`${e.c.name}\` SameSite=None but no Secure (${covPages(e.onPages)}):** Modern browsers reject it; it also increases the CSRF surface.`));
  if (!risks.length) risks.push(t('- CORS ve çerez yapılandırmasında belirgin bir risk öne çıkmadı.', '- Bei der CORS- und Cookie-Konfiguration wurde kein deutliches Risiko festgestellt.', '- No notable risk stood out in the CORS and cookie configuration.'));

  const bullets: string[] = [];
  bullets.push(`- **${t('Genel risk seviyesi', 'Gesamtrisikostufe', 'Overall risk level')}: ${RW[level]}** — ${level === 'high' ? t('kimlik bilgisiyle birlikte tehlikeli bir CORS yapılandırması tespit edildi.', 'eine gefährliche CORS-Konfiguration in Verbindung mit Anmeldeinformationen wurde festgestellt.', 'a dangerous CORS configuration combined with credentials was detected.') : level === 'medium' ? t('CORS ve/veya çerez bayraklarında giderilmesi önerilen eksikler var.', 'bei CORS und/oder Cookie-Flags bestehen zu behebende Lücken.', 'there are gaps recommended for remediation in CORS and/or cookie flags.') : t('belirgin bir CORS/çerez sorunu öne çıkmadı.', 'es wurde kein deutliches CORS-/Cookie-Problem festgestellt.', 'no notable CORS/cookie issue stood out.')}`);
  bullets.push(`- **${t('Kapsam', 'Umfang', 'Scope')}:** ${t(`${pageCount} benzersiz sayfada değerlendirildi. CORS: ${worstCors.wildcard ? 'wildcard (*)' : worstCors.reflected ? 'origin yansıtma' : worstCors.acao ? 'sınırlı' : 'kapalı'}${credsWildcardDanger ? ' + credentials ⚠️' : ''}. Çerez: ${cookieEntries.length} benzersiz, ${insecureCookies.length} eksik bayraklı.`, `Auf ${pageCount} einzigartigen Seiten ausgewertet. CORS: ${worstCors.wildcard ? 'Wildcard (*)' : worstCors.reflected ? 'Origin-Spiegelung' : worstCors.acao ? 'eingeschränkt' : 'geschlossen'}${credsWildcardDanger ? ' + Credentials ⚠️' : ''}. Cookies: ${cookieEntries.length} einzigartige, ${insecureCookies.length} mit fehlenden Flags.`, `Evaluated across ${pageCount} unique pages. CORS: ${worstCors.wildcard ? 'wildcard (*)' : worstCors.reflected ? 'origin reflection' : worstCors.acao ? 'restricted' : 'closed'}${credsWildcardDanger ? ' + credentials ⚠️' : ''}. Cookies: ${cookieEntries.length} unique, ${insecureCookies.length} with missing flags.`)}`);
  bullets.push(`- **${t('Önerilen ilk adım', 'Empfohlener erster Schritt', 'Recommended first step')}:** ` + (credsWildcardDanger ? t('CORS’u origin allowlist’e çekin; credentials ile wildcard/yansıtmayı kaldırın.', 'Stellen Sie CORS auf eine Origin-Allowlist um; entfernen Sie Wildcard/Spiegelung in Verbindung mit Credentials.', 'Move CORS to an origin allowlist; remove wildcard/reflection in combination with credentials.') : t('Çerezlere Secure + HttpOnly + uygun SameSite ekleyin (hazır örnekler "AI Çözüm Önerileri" eklentisinde).', 'Ergänzen Sie bei Cookies Secure + HttpOnly + passendes SameSite (fertige Beispiele im Add-on „KI-Lösungsvorschläge").', 'Add Secure + HttpOnly + an appropriate SameSite to cookies (ready-made examples in the "AI Remediation Suggestions" add-on).')));

  const genel =
    level === 'high'
      ? t('Kimlik bilgisiyle (credentials) birlikte açık/yansıtılan bir CORS politikası tespit edildi; bu, çapraz-köken veri sızıntısına yol açabilir ve öncelikli giderilmelidir.', 'Es wurde eine offene/gespiegelte CORS-Richtlinie in Verbindung mit Anmeldeinformationen (Credentials) festgestellt; dies kann zu einem Cross-Origin-Datenleck führen und sollte vorrangig behoben werden.', 'An open/reflected CORS policy combined with credentials was detected; this can lead to cross-origin data leakage and should be remediated as a priority.')
      : level === 'medium'
        ? t('CORS ve/veya çerez bayraklarında giderilmesi önerilen eksikler var; taşıma güvenliği açısından kritik değil ancak saldırı yüzeyini artırıyor.', 'Bei CORS und/oder Cookie-Flags bestehen zu behebende Lücken; für die Transportsicherheit nicht kritisch, aber sie vergrößern die Angriffsfläche.', 'There are gaps recommended for remediation in CORS and/or cookie flags; not critical to transport security but they increase the attack surface.')
        : t('CORS ve çerez yapılandırması güvenli varsayılanlara yakın; rapor yalnızca küçük iyileştirmeleri listeler.', 'Die CORS- und Cookie-Konfiguration ist nahe an sicheren Voreinstellungen; der Bericht listet nur kleine Verbesserungen auf.', 'The CORS and cookie configuration is close to secure defaults; the report lists only minor improvements.');

  const findings = assemble('CORS/Çerez', level, bullets, genel, `${corsSection}${cookieSection}## ${t('TESPİT EDİLEN RİSKLER', 'FESTGESTELLTE RISIKEN', 'IDENTIFIED RISKS')}\n\n${risksTable(risks, locale)}\n`, locale);
  const fixText = buildCorsCookieFix(host, { credsWildcardDanger, wildcard: worstCors.wildcard, reflected: worstCors.reflected, insecure: insecureCookies.length > 0 }, locale);
  return { findings, fixText };
}

type Cookie = { name: string; secure: boolean; httpOnly: boolean; sameSite?: string };
function parseCookie(raw: string, locale: string = 'tr'): Cookie {
  const de = locale === 'de';
  const name = raw.split('=')[0]?.trim() || (locale === 'en' ? '(cookie)' : de ? '(Cookie)' : '(çerez)');
  const ss = raw.match(/;\s*samesite\s*=\s*(strict|lax|none)/i)?.[1];
  return { name, secure: /;\s*secure/i.test(raw), httpOnly: /;\s*httponly/i.test(raw), sameSite: ss ? ss[0].toUpperCase() + ss.slice(1).toLowerCase() : undefined };
}
function cookieNote(c: Cookie, locale: string = 'tr'): string {
  const de = locale === 'de';
  const t = (trS: string, deS: string, enS?: string) => (locale === 'de' ? deS : locale === 'en' ? (enS ?? trS) : trS);
  const p: string[] = [];
  if (!c.secure) p.push(t('Secure eksik', 'Secure fehlt', 'Secure missing'));
  if (!c.httpOnly) p.push(t('HttpOnly eksik', 'HttpOnly fehlt', 'HttpOnly missing'));
  if (c.sameSite === 'None' && !c.secure) p.push(t('SameSite=None+Secure yok', 'SameSite=None+kein Secure', 'SameSite=None+no Secure'));
  return p.length ? p.join('; ') : t('Bayraklar uygun', 'Flags in Ordnung', 'Flags OK');
}

// ======================================================================================
// 5) csp_analiz — CSP Analizi
// ======================================================================================
export async function generateCspReport(host: string, locale: string = 'tr'): Promise<{ findings: string; fixText: string } | null> {
  const de = locale === 'de';
  const t = (trS: string, deS: string, enS?: string) => (locale === 'de' ? deS : locale === 'en' ? (enS ?? trS) : trS);
  const RW = locale === 'en' ? RISK_WORD_EN : de ? RISK_WORD_DE : RISK_WORD;
  const http = await collectHttp(host);
  if (!http.ok) return null;
  const csp = http.headers.get('content-security-policy') ?? '';
  const cspRO = http.headers.get('content-security-policy-report-only') ?? '';
  const isSpa = /\/assets\/index-[\w-]+\.js|data-reactroot|id="root"/i.test(http.html);

  const present = !!csp.trim();
  const directives = present ? parseCsp(csp) : null;
  const weakFindings: string[] = [];
  if (directives) {
    if (directives.unsafeInline) weakFindings.push(t("`'unsafe-inline'` kullanılıyor — inline script/style’a izin verir, XSS korumasını büyük ölçüde zayıflatır.", "`'unsafe-inline'` wird verwendet — erlaubt Inline-Script/Style und schwächt den XSS-Schutz erheblich.", "`'unsafe-inline'` is used — allows inline script/style and substantially weakens XSS protection."));
    if (directives.unsafeEval) weakFindings.push(t("`'unsafe-eval'` kullanılıyor — eval() benzeri dinamik kod yürütmeye izin verir.", "`'unsafe-eval'` wird verwendet — erlaubt dynamische Codeausführung ähnlich wie eval().", "`'unsafe-eval'` is used — allows dynamic code execution similar to eval()."));
    if (directives.wildcard) weakFindings.push(t('Kaynak olarak wildcard (`*`) var — herhangi bir kökeni yükleyebilir, politikayı etkisizleştirir.', 'Als Quelle ist ein Wildcard (`*`) vorhanden — es kann jeden Origin laden und macht die Richtlinie wirkungslos.', 'A wildcard (`*`) source is present — it can load any origin and renders the policy ineffective.'));
    if (!directives.hasDefaultSrc) weakFindings.push(t('`default-src` tanımlı değil — kapsanmayan kaynak türleri için yedek politika yok.', '`default-src` ist nicht definiert — keine Fallback-Richtlinie für nicht abgedeckte Ressourcentypen.', '`default-src` is not defined — no fallback policy for uncovered resource types.'));
    if (!directives.hasFrameAncestors) weakFindings.push(t('`frame-ancestors` yok — clickjacking için ek koruma sağlanmıyor.', '`frame-ancestors` fehlt — kein zusätzlicher Schutz gegen Clickjacking.', '`frame-ancestors` is missing — no additional protection against clickjacking.'));
  }

  let level: Level = 'low';
  if (!present && !cspRO) level = 'medium';
  else if (present && (directives?.unsafeInline || directives?.unsafeEval || directives?.wildcard)) level = 'medium';
  else if (!present && cspRO) level = 'medium';

  // (BÖLÜM 1 — ÇOK SAYFA) CSP başlığı path-bazlı değişebilir (bir sayfada var, diğerinde yok).
  const cspPages = await collectPages(host);
  const cspPageCount = Math.max(1, cspPages.length);
  const cspAbsentPaths = cspPages.filter((pg) => !(pg.headers.get('content-security-policy') ?? '').trim()).map((pg) => { try { return new URL(pg.url).pathname; } catch { return pg.url; } });
  const cspVariance = present && cspAbsentPaths.length > 0; // home'da var ama bazı sayfalarda YOK
  const cspCov = cspPageCount > 1 ? t(` Taranan ${cspPageCount} sayfanın ${cspAbsentPaths.length === cspPageCount ? 'TAMAMINDA' : `${cspAbsentPaths.length}/${cspPageCount}'sinde`} CSP başlığı yok.`, ` Auf ${cspAbsentPaths.length === cspPageCount ? `ALLEN ${cspPageCount}` : `${cspAbsentPaths.length}/${cspPageCount}`} geprüften Seiten fehlt der CSP-Header.`, ` The CSP header is missing on ${cspAbsentPaths.length === cspPageCount ? `ALL ${cspPageCount}` : `${cspAbsentPaths.length}/${cspPageCount}`} of the scanned pages.`) : '';

  const statusSection =
    `## ${t('CSP DURUMU', 'CSP-STATUS', 'CSP STATUS')}\n\n` +
    (present
      ? `- **${t('Durum', 'Status', 'Status')}:** ${t('Var (uygulanıyor).', 'Vorhanden (wird durchgesetzt).', 'Present (enforced).')}\n- **${t('Politika', 'Richtlinie', 'Policy')}:** \`${csp.slice(0, 400)}${csp.length > 400 ? '…' : ''}\`\n\n`
      : cspRO
        ? `- **${t('Durum', 'Status', 'Status')}:** ` + t(`Yalnızca Report-Only modda (\`Content-Security-Policy-Report-Only\`) — ihlaller raporlanıyor ama ENGELLENMİYOR. Gerçek koruma için uygulanan (enforce) moda geçilmeli.\n\n`, `Nur im Report-Only-Modus (\`Content-Security-Policy-Report-Only\`) — Verstöße werden gemeldet, aber NICHT blockiert. Für echten Schutz sollte in den durchsetzenden (enforce) Modus gewechselt werden.\n\n`, `Report-Only mode only (\`Content-Security-Policy-Report-Only\`) — violations are reported but NOT blocked. For real protection it should be switched to enforce mode.\n\n`)
        : `- **${t('Durum', 'Status', 'Status')}:** ` + t(`Yok — Content-Security-Policy başlığı hiç gönderilmiyor.${isSpa ? ' Site JavaScript ağırlıklı bir SPA olduğundan CSP eksikliği XSS etkisini belirgin şekilde büyütür.' : ''}\n\n`, `Fehlt — Es wird kein Content-Security-Policy-Header gesendet.${isSpa ? ' Da die Website eine JavaScript-lastige SPA ist, vergrößert das Fehlen einer CSP die XSS-Auswirkung deutlich.' : ''}\n\n`, `Absent — No Content-Security-Policy header is sent at all.${isSpa ? ' As the site is a JavaScript-heavy SPA, the absence of a CSP markedly amplifies the XSS impact.' : ''}\n\n`));

  const analysisSection =
    `## ${t('CSP DİREKTİF ANALİZİ', 'CSP-DIREKTIVENANALYSE', 'CSP DIRECTIVE ANALYSIS')}\n\n` +
    (present
      ? (weakFindings.length ? weakFindings.map((w) => `- ⚠️ ${w}`).join('\n') + '\n\n' : t('- Politika temel zayıflatıcı direktifler (unsafe-inline/unsafe-eval/wildcard) içermiyor; sağlam görünüyor.\n\n', '- Die Richtlinie enthält keine grundlegend schwächenden Direktiven (unsafe-inline/unsafe-eval/wildcard); sie wirkt solide.\n\n', '- The policy contains no fundamentally weakening directives (unsafe-inline/unsafe-eval/wildcard); it appears sound.\n\n'))
      : t('- Uygulanan bir CSP olmadığından direktif analizi yapılamadı.\n\n', '- Da keine durchgesetzte CSP vorhanden ist, konnte keine Direktivenanalyse durchgeführt werden.\n\n', '- As there is no enforced CSP, no directive analysis could be performed.\n\n'));

  const risks: string[] = [];
  if (!present && !cspRO) risks.push(t(`- **${isSpa ? 'Orta-Yüksek' : 'Orta'} — CSP tamamen eksik:** XSS ve içerik enjeksiyonuna karşı tarayıcı seviyesinde savunma yok.${isSpa ? ' SPA olduğu için XSS etkisi belirgindir.' : ''}${cspCov}`, `- **${isSpa ? 'Orta-Yüksek' : 'Orta'} — CSP vollständig fehlend:** Keine Verteidigung auf Browser-Ebene gegen XSS und Content-Injection.${isSpa ? ' Da es sich um eine SPA handelt, ist die XSS-Auswirkung ausgeprägt.' : ''}${cspCov}`, `- **${isSpa ? 'Orta-Yüksek' : 'Orta'} — CSP entirely missing:** No browser-level defence against XSS and content injection.${isSpa ? ' Being a SPA, the XSS impact is pronounced.' : ''}${cspCov}`));
  if (!present && cspRO) risks.push(t('- **Orta — CSP yalnızca Report-Only:** İhlaller engellenmiyor; enforce moda geçilmeli.', '- **Orta — CSP nur Report-Only:** Verstöße werden nicht blockiert; ein Wechsel in den Enforce-Modus ist erforderlich.', '- **Orta — CSP is Report-Only:** Violations are not blocked; switch to enforce mode.'));
  if (present) for (const w of weakFindings.filter((x) => /unsafe|wildcard/.test(x))) risks.push(t(`- **Orta — Zayıf CSP direktifi:** ${w}`, `- **Orta — Schwache CSP-Direktive:** ${w}`, `- **Orta — Weak CSP directive:** ${w}`));
  if (cspVariance) risks.push(t(`- **Orta — Sayfaya özgü CSP tutarsızlığı:** CSP ana sayfada mevcut ancak ${cspAbsentPaths.length}/${cspPageCount} iç sayfada gönderilmiyor (ör. ${cspAbsentPaths.slice(0, 3).join(', ')}). Politika tüm yollarda tutarlı uygulanmalı.`, `- **Orta — Seitenspezifische CSP-Inkonsistenz:** CSP ist auf der Startseite vorhanden, wird aber auf ${cspAbsentPaths.length}/${cspPageCount} Unterseiten nicht gesendet (z. B. ${cspAbsentPaths.slice(0, 3).join(', ')}). Die Richtlinie sollte auf allen Pfaden konsistent angewendet werden.`, `- **Orta — Page-specific CSP inconsistency:** CSP is present on the home page but is not sent on ${cspAbsentPaths.length}/${cspPageCount} inner pages (e.g. ${cspAbsentPaths.slice(0, 3).join(', ')}). The policy should be applied consistently across all paths.`));
  if (!risks.length) risks.push(t('- CSP mevcut ve belirgin bir zayıflatıcı direktif içermiyor.', '- CSP ist vorhanden und enthält keine deutlich schwächende Direktive.', '- CSP is present and contains no clearly weakening directive.'));

  const bullets: string[] = [];
  bullets.push(`- **${t('Genel risk seviyesi', 'Gesamtrisikostufe', 'Overall risk level')}: ${RW[level]}** — ${level === 'medium' ? (present ? t('CSP var ama zayıflatıcı direktifler içeriyor.', 'CSP ist vorhanden, enthält aber schwächende Direktiven.', 'CSP is present but contains weakening directives.') : t('CSP eksik/enforce edilmiyor.', 'CSP fehlt/wird nicht durchgesetzt.', 'CSP is missing/not enforced.')) : t('CSP mevcut ve makul yapılandırılmış.', 'CSP ist vorhanden und sinnvoll konfiguriert.', 'CSP is present and reasonably configured.')}`);
  bullets.push(`- CSP: ${present ? t('uygulanıyor', 'wird durchgesetzt', 'enforced') : cspRO ? t('yalnızca Report-Only', 'nur Report-Only', 'Report-Only only') : t('yok', 'fehlt', 'missing')}${directives && weakFindings.length ? t(`, ${weakFindings.length} zayıf nokta`, `, ${weakFindings.length} Schwachstelle(n)`, `, ${weakFindings.length} weak point(s)`) : ''}.`);
  bullets.push(`- **${t('Önerilen ilk adım', 'Empfohlener erster Schritt', 'Recommended first step')}:** ` + (present ? t("unsafe-inline/unsafe-eval/wildcard direktiflerini kaldırın.", 'Entfernen Sie die Direktiven unsafe-inline/unsafe-eval/wildcard.', 'Remove the unsafe-inline/unsafe-eval/wildcard directives.') : t('Önce Report-Only modda test edip ardından uygulanan CSP ekleyin (hazır örnekler "AI Çözüm Önerileri" eklentisinde).', 'Testen Sie zunächst im Report-Only-Modus und ergänzen Sie dann eine durchgesetzte CSP (fertige Beispiele im Add-on „KI-Lösungsvorschläge").', 'Test in Report-Only mode first, then add an enforced CSP (ready-made examples in the "AI Fix Suggestions" add-on).')));

  const genel =
    level === 'medium'
        ? (present ? t('CSP mevcut ancak koruma değerini düşüren direktifler (unsafe-inline/unsafe-eval/wildcard) içeriyor; sıkılaştırılması önerilir.', 'CSP ist vorhanden, enthält aber Direktiven (unsafe-inline/unsafe-eval/wildcard), die den Schutzwert mindern; eine Verschärfung wird empfohlen.', 'CSP is present but contains directives (unsafe-inline/unsafe-eval/wildcard) that reduce its protective value; tightening is recommended.') : t('Uygulanan bir CSP yok (yok veya yalnızca Report-Only). XSS azaltması için enforce edilen bir politika önerilir.', 'Es gibt keine durchgesetzte CSP (fehlt oder nur Report-Only). Zur XSS-Minderung wird eine durchgesetzte Richtlinie empfohlen.', 'There is no enforced CSP (missing or Report-Only only). An enforced policy is recommended to mitigate XSS.'))
        : t('Content-Security-Policy mevcut ve makul yapılandırılmış; rapor yalnızca küçük iyileştirmeleri listeler.', 'Die Content-Security-Policy ist vorhanden und sinnvoll konfiguriert; der Bericht listet nur kleine Verbesserungen auf.', 'The Content-Security-Policy is present and reasonably configured; the report lists only minor improvements.');

  const findings = assemble('CSP', level, bullets, genel, `${statusSection}${analysisSection}## ${t('TESPİT EDİLEN RİSKLER', 'FESTGESTELLTE RISIKEN', 'IDENTIFIED RISKS')}\n\n${risksTable(risks, locale)}\n`, locale);
  const fixText = buildCspFix(host, { present, weak: weakFindings.length > 0 }, locale);
  return { findings, fixText };
}

type CspInfo = { unsafeInline: boolean; unsafeEval: boolean; wildcard: boolean; hasDefaultSrc: boolean; hasFrameAncestors: boolean };
function parseCsp(csp: string): CspInfo {
  const lc = csp.toLowerCase();
  return {
    unsafeInline: /'unsafe-inline'/.test(lc),
    unsafeEval: /'unsafe-eval'/.test(lc),
    wildcard: /(^|[\s;])\*($|[\s;])/.test(lc) || /src\s+[^;]*\s\*(\s|;|$)/.test(lc),
    hasDefaultSrc: /default-src/.test(lc),
    hasFrameAncestors: /frame-ancestors/.test(lc),
  };
}

// ======================================================================================
// FIX URETICILERI (kod-gomulu remediation sablonlari; coklu platform)
// ======================================================================================
function platformHeaderBlock(entries: Array<{ name: string; value: string }>, locale: string = 'tr'): string {
  const de = locale === 'de';
  const t = (trS: string, deS: string, enS?: string) => (locale === 'de' ? deS : locale === 'en' ? (enS ?? trS) : trS);
  const nginx = entries.map((e) => `add_header ${e.name} "${e.value}" always;`).join('\n');
  const json = entries.map((e) => `          { "key": "${e.name}", "value": "${e.value}" }`).join(',\n');
  const apache = entries.map((e) => `Header always set ${e.name} "${e.value}"`).join('\n');
  return (
    '**Nginx:**\n\n```nginx\n' + nginx + '\n```\n\n' +
    t('**Firebase Hosting — `firebase.json`:**\n\n```json\n', '**Firebase Hosting — `firebase.json`:**\n\n```json\n', '**Firebase Hosting — `firebase.json`:**\n\n```json\n') +
    `{\n  "hosting": {\n    "headers": [\n      {\n        "source": "**",\n        "headers": [\n${json}\n        ]\n      }\n    ]\n  }\n}\n` + '```\n\n' +
    '**Apache — `.htaccess`:**\n\n```apache\n' + apache + '\n```'
  );
}

function buildTlsFix(host: string, o: { hstsMissing: boolean; weak: string[] }, locale: string = 'tr'): string {
  const de = locale === 'de';
  const t = (trS: string, deS: string, enS?: string) => (locale === 'de' ? deS : locale === 'en' ? (enS ?? trS) : trS);
  const parts: string[] = [t(`Aşağıdaki öneriler ${host} için TLS/şifreleme yapılandırmasını güçlendirir.`, `Die folgenden Empfehlungen stärken die TLS-/Verschlüsselungskonfiguration für ${host}.`, `The following recommendations strengthen the TLS/encryption configuration for ${host}.`)];
  if (o.hstsMissing) {
    parts.push(t('### 1. HSTS başlığını ekleyin\n\nTarayıcıya siteye yalnızca HTTPS ile bağlanmasını söyler (yalnızca siteniz tamamen HTTPS ise uygulayın):\n\n', '### 1. HSTS-Header ergänzen\n\nWeist den Browser an, die Website nur über HTTPS aufzurufen (nur anwenden, wenn Ihre Website vollständig auf HTTPS läuft):\n\n', '### 1. Add the HSTS header\n\nTells the browser to connect to the site only over HTTPS (apply only if your site runs entirely over HTTPS):\n\n') +
      platformHeaderBlock([{ name: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' }], locale));
  }
  if (o.weak.length) {
    parts.push(t(`### ${o.hstsMissing ? 2 : 1}. Eski TLS sürümlerini kapatın (${o.weak.join(', ')})\n\n`, `### ${o.hstsMissing ? 2 : 1}. Veraltete TLS-Versionen deaktivieren (${o.weak.join(', ')})\n\n`, `### ${o.hstsMissing ? 2 : 1}. Disable outdated TLS versions (${o.weak.join(', ')})\n\n`) +
      '**Nginx:**\n\n```nginx\nssl_protocols TLSv1.2 TLSv1.3;\nssl_prefer_server_ciphers on;\n```\n\n' +
      '**Cloudflare:** SSL/TLS → Edge Certificates → **Minimum TLS Version = 1.2**.\n\n' +
      '**Apache:**\n\n```apache\nSSLProtocol -all +TLSv1.2 +TLSv1.3\n```');
  }
  if (parts.length === 1) parts.push(t('TLS yapılandırmanız güncel görünüyor. Sürekli güvence için sertifika yenilemenizi otomatik (ör. certbot/ACME) tutun ve yalnızca TLS 1.2+ kabul edin.', 'Ihre TLS-Konfiguration wirkt aktuell. Halten Sie zur dauerhaften Absicherung die Zertifikatserneuerung automatisch (z. B. certbot/ACME) und akzeptieren Sie nur TLS 1.2+.', 'Your TLS configuration appears current. For ongoing assurance, keep certificate renewal automated (e.g. certbot/ACME) and accept only TLS 1.2+.'));
  return parts.join('\n\n');
}

function buildExposedFileFix(paths: string[], locale: string = 'tr'): string {
  const de = locale === 'de';
  const t = (trS: string, deS: string, enS?: string) => (locale === 'de' ? deS : locale === 'en' ? (enS ?? trS) : trS);
  return (
    t(`### Açıkta kalan dosyalara erişimi engelleyin\n\n`, `### Zugriff auf offenliegende Dateien sperren\n\n`, `### Block access to exposed files\n\n`) +
    t(`Tespit edilen yollar: ${paths.map((p) => `\`${p}\``).join(', ')}. Sunucu seviyesinde erişimi kapatın:\n\n`, `Festgestellte Pfade: ${paths.map((p) => `\`${p}\``).join(', ')}. Sperren Sie den Zugriff auf Serverebene:\n\n`, `Detected paths: ${paths.map((p) => `\`${p}\``).join(', ')}. Block access at the server level:\n\n`) +
    '**Nginx:**\n\n```nginx\nlocation ~ /\\.(git|env|ht) { deny all; return 404; }\nlocation ~* \\.(bak|old|zip|sql)$ { deny all; return 404; }\n```\n\n' +
    '**Apache — `.htaccess`:**\n\n```apache\nRedirectMatch 404 /\\.git\nRedirectMatch 404 /\\.env\n<FilesMatch "\\.(bak|old|zip|sql)$">\n  Require all denied\n</FilesMatch>\n```\n\n' +
    t('Ayrıca bu dosyaların web köküne (public) hiç konmaması en sağlıklısıdır.', 'Am besten legen Sie diese Dateien zudem gar nicht erst in das Web-Root (public).', 'It is also best not to place these files in the web root (public) at all.')
  );
}

function buildDnsFix(host: string, dns: DnsEvidence, locale: string = 'tr'): string {
  const de = locale === 'de';
  const t = (trS: string, deS: string, enS?: string) => (locale === 'de' ? deS : locale === 'en' ? (enS ?? trS) : trS);
  const apex = host.split('.').slice(-2).join('.');
  const parts: string[] = [t(`Aşağıdaki öneriler ${apex} alan adının e-posta kimlik doğrulamasını güçlendirir. Kayıtları DNS sağlayıcınızın (Cloudflare/GoDaddy/…) TXT arayüzünden ekleyin.`, `Die folgenden Empfehlungen stärken die E-Mail-Authentifizierung der Domain ${apex}. Fügen Sie die Einträge über die TXT-Oberfläche Ihres DNS-Anbieters (Cloudflare/GoDaddy/…) hinzu.`, `The following recommendations strengthen email authentication for the domain ${apex}. Add the records via your DNS provider's (Cloudflare/GoDaddy/…) TXT interface.`)];
  if (!dns.spf || dns.spf.all === 'yok' || dns.spf.all === '+all' || dns.spf.all === '?all') {
    parts.push(t('### SPF kaydı ekleyin/sertleştirin\n\nYalnızca yetkili sunucuların sizin adınıza mail göndermesine izin verir. Kendi gönderen servislerinizi (`include:`) ekleyin:\n\n', '### SPF-Eintrag hinzufügen/verschärfen\n\nErlaubt nur autorisierten Servern, in Ihrem Namen E-Mails zu senden. Fügen Sie Ihre eigenen sendenden Dienste (`include:`) hinzu:\n\n', '### Add/harden an SPF record\n\nAllows only authorised servers to send mail on your behalf. Add your own sending services (`include:`):\n\n') + '```dns\n' +
      `${apex}.  TXT  "v=spf1 include:_spf.google.com -all"\n` +
      '```\n\n' + t('`-all` (hardfail) en güvenlidir; geçiş sırasında `~all` (softfail) ile başlayabilirsiniz.', '`-all` (hardfail) ist am sichersten; für die Umstellung können Sie mit `~all` (softfail) beginnen.', '`-all` (hardfail) is the most secure; during migration you can start with `~all` (softfail).'));
  }
  if (!dns.dmarc || dns.dmarc.policy === 'yok' || dns.dmarc.policy === 'none') {
    parts.push(t('### DMARC kaydı ekleyin/sıkılaştırın\n\nÖnce `p=none` ile izleyin, raporları inceleyip yanlış-pozitif olmadığından emin olunca `quarantine` → `reject` yapın:\n\n', '### DMARC-Eintrag hinzufügen/verschärfen\n\nÜberwachen Sie zunächst mit `p=none`; sobald Sie die Berichte geprüft und Fehlalarme ausgeschlossen haben, wechseln Sie zu `quarantine` → `reject`:\n\n', '### Add/harden a DMARC record\n\nFirst monitor with `p=none`; once you have reviewed the reports and ruled out false positives, move to `quarantine` → `reject`:\n\n') + '```dns\n' +
      `_dmarc.${apex}.  TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@${apex}; fo=1"\n` +
      '```');
  }
  if (!dns.dkim?.found) {
    parts.push(t('### DKIM imzalamayı etkinleştirin\n\nE-posta sağlayıcınızın (Google Workspace/Microsoft 365/gönderim servisi) panelinden DKIM üretin ve verdiği TXT kaydını `seçici._domainkey` altına ekleyin:\n\n', '### DKIM-Signierung aktivieren\n\nErzeugen Sie DKIM über das Panel Ihres E-Mail-Anbieters (Google Workspace/Microsoft 365/Versanddienst) und fügen Sie den bereitgestellten TXT-Eintrag unter `selektor._domainkey` hinzu:\n\n', '### Enable DKIM signing\n\nGenerate DKIM from your email provider\'s panel (Google Workspace/Microsoft 365/sending service) and add the TXT record it provides under `selector._domainkey`:\n\n') + '```dns\n' +
      `google._domainkey.${apex}.  TXT  "v=DKIM1; k=rsa; p=${t('<sağlayıcının-verdiği-anahtar>', '<vom-Anbieter-bereitgestellter-Schlüssel>', '<key-provided-by-your-provider>')}"\n` +
      '```');
  }
  if (!dns.dnssec) {
    parts.push(t('### DNSSEC’i etkinleştirin\n\nDNS sağlayıcınızın panelinden **DNSSEC**’i açın; sağlayıcı DS kaydını üretir, bunu alan adı kayıt operatörünüze (registrar) girin. DNS yanıtlarını imzalayarak cache-poisoning’i zorlaştırır.', '### DNSSEC aktivieren\n\nAktivieren Sie **DNSSEC** im Panel Ihres DNS-Anbieters; der Anbieter erzeugt den DS-Eintrag, den Sie bei Ihrem Domain-Registrar eintragen. Es signiert die DNS-Antworten und erschwert Cache-Poisoning.', '### Enable DNSSEC\n\nTurn on **DNSSEC** in your DNS provider\'s panel; the provider generates the DS record, which you enter at your domain registrar. It signs DNS responses and makes cache poisoning harder.'));
  }
  if (parts.length === 1) parts.push(t('E-posta kimlik doğrulama kayıtlarınız (SPF/DMARC/DKIM) sağlam görünüyor. DMARC politikanızı zamanla `reject`’e çekmeyi ve raporları (rua) izlemeyi sürdürün.', 'Ihre E-Mail-Authentifizierungseinträge (SPF/DMARC/DKIM) wirken solide. Ziehen Sie Ihre DMARC-Richtlinie mit der Zeit auf `reject` und überwachen Sie weiterhin die Berichte (rua).', 'Your email authentication records (SPF/DMARC/DKIM) appear solid. Continue moving your DMARC policy towards `reject` over time and keep monitoring the reports (rua).'));
  return parts.join('\n\n');
}

function buildCorsCookieFix(host: string, o: { credsWildcardDanger: boolean; wildcard: boolean; reflected: boolean; insecure: boolean }, locale: string = 'tr'): string {
  const de = locale === 'de';
  const t = (trS: string, deS: string, enS?: string) => (locale === 'de' ? deS : locale === 'en' ? (enS ?? trS) : trS);
  const parts: string[] = [t(`Aşağıdaki öneriler ${host} için CORS ve çerez güvenliğini güçlendirir.`, `Die folgenden Empfehlungen stärken die CORS- und Cookie-Sicherheit für ${host}.`, `The following recommendations strengthen CORS and cookie security for ${host}.`)];
  if (o.credsWildcardDanger || o.wildcard || o.reflected) {
    parts.push(t('### CORS’u origin allowlist’e çekin\n\nGelen Origin’i doğrulamadan yansıtmayın ve kimlik bilgisi (credentials) ile wildcard’ı ASLA birlikte kullanmayın. Yalnızca bilinen kökenlere izin verin:\n\n', '### CORS auf eine Origin-Allowlist umstellen\n\nSpiegeln Sie den eingehenden Origin nicht ungeprüft und verwenden Sie Wildcard NIEMALS zusammen mit Anmeldeinformationen (Credentials). Erlauben Sie nur bekannte Origins:\n\n', '### Move CORS to an origin allowlist\n\nDo not reflect the incoming Origin without validation, and NEVER use wildcard together with credentials. Allow only known origins:\n\n') +
      t('**Nginx (örnek allowlist):**\n\n', '**Nginx (Beispiel-Allowlist):**\n\n', '**Nginx (example allowlist):**\n\n') + '```nginx\nset $cors "";\nif ($http_origin ~* "^https://(app\\.example\\.com|www\\.example\\.com)$") { set $cors $http_origin; }\nadd_header Access-Control-Allow-Origin $cors always;\nadd_header Vary Origin always;\n' + t('# credentials gerekmiyorsa Allow-Credentials göndermeyin', '# Senden Sie Allow-Credentials nicht, wenn keine Credentials benötigt werden', '# do not send Allow-Credentials if credentials are not needed') + '\n```\n\n' +
      '**Express/Node:**\n\n```js\nconst allow = new Set([\'https://app.example.com\']);\napp.use((req,res,next)=>{ const o=req.headers.origin; if(o&&allow.has(o)){ res.set(\'Access-Control-Allow-Origin\',o); res.set(\'Vary\',\'Origin\'); } next(); });\n```');
  }
  if (o.insecure) {
    parts.push(t('### Çerez bayraklarını tamamlayın\n\nOturum çerezlerine `Secure` (yalnız HTTPS), `HttpOnly` (JS erişimini engeller) ve uygun `SameSite` ekleyin:\n\n', '### Cookie-Flags vervollständigen\n\nErgänzen Sie bei Sitzungscookies `Secure` (nur HTTPS), `HttpOnly` (verhindert JS-Zugriff) und ein passendes `SameSite`:\n\n', '### Complete the cookie flags\n\nAdd `Secure` (HTTPS only), `HttpOnly` (blocks JS access) and an appropriate `SameSite` to session cookies:\n\n') +
      '```\nSet-Cookie: session=...; Secure; HttpOnly; SameSite=Lax; Path=/\n```\n\n' +
      t('Çapraz-site gönderim gerekiyorsa `SameSite=None` kullanın ama mutlaka `Secure` ile birlikte.', 'Wenn seitenübergreifender Versand erforderlich ist, verwenden Sie `SameSite=None`, aber stets zusammen mit `Secure`.', 'If cross-site sending is required, use `SameSite=None`, but always together with `Secure`.'));
  }
  if (parts.length === 1) parts.push(t('CORS ve çerez yapılandırmanız güvenli varsayılanlara yakın. Yeni uç noktalar eklerken origin allowlist ve çerez bayrakları (Secure/HttpOnly/SameSite) prensibini koruyun.', 'Ihre CORS- und Cookie-Konfiguration ist nahe an sicheren Voreinstellungen. Behalten Sie beim Hinzufügen neuer Endpunkte das Prinzip der Origin-Allowlist und der Cookie-Flags (Secure/HttpOnly/SameSite) bei.', 'Your CORS and cookie configuration is close to secure defaults. When adding new endpoints, keep the origin-allowlist and cookie-flag (Secure/HttpOnly/SameSite) principle.'));
  return parts.join('\n\n');
}

function buildCspFix(host: string, o: { present: boolean; weak: boolean }, locale: string = 'tr'): string {
  const de = locale === 'de';
  const t = (trS: string, deS: string, enS?: string) => (locale === 'de' ? deS : locale === 'en' ? (enS ?? trS) : trS);
  const parts: string[] = [t(`Aşağıdaki öneriler ${host} için Content-Security-Policy’yi güçlendirir. CSP’yi önce \`Content-Security-Policy-Report-Only\` başlığıyla test edip, siteyi bozmadığından emin olduktan sonra uygulanan (enforce) başlığa geçin.`, `Die folgenden Empfehlungen stärken die Content-Security-Policy für ${host}. Testen Sie die CSP zunächst mit dem Header \`Content-Security-Policy-Report-Only\` und wechseln Sie erst dann zum durchgesetzten (enforce) Header, wenn Sie sicher sind, dass die Website nicht beeinträchtigt wird.`, `The following recommendations strengthen the Content-Security-Policy for ${host}. Test the CSP first with the \`Content-Security-Policy-Report-Only\` header, and only switch to the enforced header once you are sure the site is not broken.`)];
  parts.push(t('### Temel (başlangıç) CSP\n\nKendi üçüncü taraf alan adlarınızı (analytics, CDN, font) `script-src`/`connect-src`/`img-src`’ye ekleyerek genişletin:\n\n', '### Basis-CSP (Einstieg)\n\nErweitern Sie sie, indem Sie Ihre eigenen Drittanbieter-Domains (Analytics, CDN, Schriftarten) zu `script-src`/`connect-src`/`img-src` hinzufügen:\n\n', '### Baseline (starter) CSP\n\nExtend it by adding your own third-party domains (analytics, CDN, fonts) to `script-src`/`connect-src`/`img-src`:\n\n') +
    platformHeaderBlock([{ name: 'Content-Security-Policy', value: "default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'self'; object-src 'none'; base-uri 'self'" }], locale));
  if (o.weak) {
    parts.push(t("### Zayıflatıcı direktifleri kaldırın\n\n`'unsafe-inline'` ve `'unsafe-eval'` XSS korumasını büyük ölçüde etkisizleştirir. Inline script’leri harici dosyalara taşıyın veya **nonce/hash** kullanın:\n\n```\nscript-src 'self' 'nonce-<rastgele-üretilen>';\n```\n\nWildcard (`*`) kaynakları yerine spesifik alan adları tanımlayın.", "### Schwächende Direktiven entfernen\n\n`'unsafe-inline'` und `'unsafe-eval'` machen den XSS-Schutz weitgehend wirkungslos. Verlagern Sie Inline-Skripte in externe Dateien oder verwenden Sie **Nonce/Hash**:\n\n```\nscript-src 'self' 'nonce-<zufällig-generiert>';\n```\n\nDefinieren Sie spezifische Domains statt Wildcard-Quellen (`*`).", "### Remove weakening directives\n\n`'unsafe-inline'` and `'unsafe-eval'` largely neutralise XSS protection. Move inline scripts to external files or use a **nonce/hash**:\n\n```\nscript-src 'self' 'nonce-<randomly-generated>';\n```\n\nDefine specific domains instead of wildcard (`*`) sources."));
  }
  parts.push(t('### Report-Only ile test\n\n', '### Test mit Report-Only\n\n', '### Test with Report-Only\n\n') + '```\nContent-Security-Policy-Report-Only: default-src \'self\'; report-uri /csp-report\n```\n\n' + t('Raporları izleyip yanlış-pozitifleri giderdikten sonra başlığı `Content-Security-Policy` olarak yayınlayın.', 'Nachdem Sie die Berichte überwacht und Fehlalarme beseitigt haben, veröffentlichen Sie den Header als `Content-Security-Policy`.', 'After monitoring the reports and clearing false positives, publish the header as `Content-Security-Policy`.'));
  return parts.join('\n\n');
}

// ======================================================================================
// BUNDLE: Dış Yüzey & Yapılandırma — 5 alani TEK raporda birlestir (worst-case rozet)
// ======================================================================================
const BUNDLE_AREAS: Array<{ title: string; titleDe: string; titleEn: string; gen: (h: string, locale: string) => Promise<{ findings: string; fixText: string } | null> }> = [
  { title: 'SSL/TLS Yapılandırma Denetimi', titleDe: 'SSL/TLS-Konfigurationsaudit', titleEn: 'SSL/TLS Configuration Audit', gen: generateSslTlsReport },
  { title: 'Güvenlik Başlıkları & Bilgi Sızıntısı', titleDe: 'Sicherheits-Header & Informationslecks', titleEn: 'Security Headers & Information Leakage', gen: generateHeaderLeakReport },
  { title: 'DNS & E-posta Güvenliği', titleDe: 'DNS- & E-Mail-Sicherheit', titleEn: 'DNS & Email Security', gen: generateDnsEmailReport },
  { title: 'CORS & Çerez Güvenliği', titleDe: 'CORS- & Cookie-Sicherheit', titleEn: 'CORS & Cookie Security', gen: generateCorsCookieReport },
  { title: 'CSP (İçerik Güvenlik Politikası) Analizi', titleDe: 'CSP-Analyse (Content Security Policy)', titleEn: 'CSP (Content Security Policy) Analysis', gen: generateCspReport },
];

// (TUTARLILIK — "özet ≠ tablo" hatası) Pozitif Güvence satırı ESKİDEN alanın kendi risk SEVİYESİNDEN
// (extractLevel) türetiliyordu. Alan seviyesi 'low' olsa bile o alanın "TESPİT EDİLEN RİSKLER"
// tablosunda ŞİDDET'li satır bulunabiliyor (ör. yalnız Referrer/Permissions eksik ya da sayfaya-özel
// CSP tutarsızlığı) — bu satırlar Master Bulgu Tablosu'na DÜŞÜYOR ama güvence tablosu "Sorun
// bulunmadı" diyordu. Artık güvence, master'ın SAYDIĞI satırların AYNISINDAN türetilir.
//
// Şiddet sözlüğü pdf.ts:normSev ile BİREBİR aynıdır ("Bilgilendirme/Informational" SAYILMAZ —
// master da saymaz). Eşdeğerlik testi: scripts yok; bkz. commit mesajındaki doğrulama.
type CountedSev = 'critical' | 'high' | 'medium' | 'low';
function normSevLocal(x: string): CountedSev | null {
  const v = x.toLocaleLowerCase('tr').replace(/i̇/g, 'i');
  if (/krit[iı]k|critical|kritisch/.test(v)) return 'critical';
  if (/y[üu]ksek|high|hoch/.test(v)) return 'high';
  if (/orta|medium|mittel/.test(v)) return 'medium';
  if (/d[üu][şs][üu]k|low|niedrig/.test(v)) return 'low';
  return null;
}
/** Alanın markdown'ındaki ŞİDDET-kolonlu tablolarda sayılan en yüksek şiddet (yoksa null). */
export function worstCountedSeverity(md: string): CountedSev | null {
  const rank: Record<CountedSev, number> = { critical: 3, high: 2, medium: 1, low: 0 };
  let best: CountedSev | null = null;
  const lines = md.split('\n');
  let i = 0;
  while (i < lines.length) {
    if (!/^\s*\|.*\|\s*$/.test(lines[i])) { i++; continue; }
    const block: string[] = [];
    while (i < lines.length && /^\s*\|.*\|\s*$/.test(lines[i])) { block.push(lines[i]); i++; }
    if (block.length < 2) continue;
    const cells = (r: string) => r.replace(/^\s*\|/, '').replace(/\|\s*$/, '').split('|').map((c) => c.trim());
    const header = cells(block[0]).map((h) => h.toLocaleLowerCase('tr'));
    const sevCol = header.findIndex((h) => /[şs]iddet|severity|ciddiyet|schweregrad/.test(h));
    if (sevCol === -1) continue; // şiddet kolonu yoksa bulgu tablosu değil (pdf.ts ile aynı kural)
    for (let r = 1; r < block.length; r++) {
      if (/^\s*\|[\s:|-]+\|\s*$/.test(block[r])) continue;
      const sev = normSevLocal(cells(block[r])[sevCol] ?? '');
      if (sev && (best === null || rank[sev] > rank[best])) best = sev;
    }
  }
  return best;
}

function areaTitle(i: number, locale: string): string { return locale === 'en' ? BUNDLE_AREAS[i].titleEn : locale === 'de' ? BUNDLE_AREAS[i].titleDe : BUNDLE_AREAS[i].title; }

function levelRank(l: Level): number { return l === 'high' ? 3 : l === 'medium-high' ? 2 : l === 'medium' ? 1 : 0; }
function extractLevel(findings: string): Level | null {
  // "Orta-Yüksek"/"Mittel-Hoch" ONCE eslesmeli (yoksa "Orta"/"Yüksek"/"Mittel"/"Hoch" yanlis yakalar).
  const m = findings.match(/(?:Risk Seviyesi|Risikostufe|Risk Level):\s*(Orta[-\s]?Y[uü]ksek|Y[uü]ksek|Orta|D[uü][sş][uü]k|Mittel[-\s]?Hoch|Hoch|Mittel|Niedrig|Medium[-\s]?High|High|Medium|Low)/i);
  if (!m) return null;
  const w = m[1].toLocaleLowerCase('tr');
  if (/orta[-\s]?y[uü]ksek/.test(w) || /mittel[-\s]?hoch/.test(w) || /medium[-\s]?high/.test(w)) return 'medium-high';
  if (/y[uü]ksek/.test(w) || /hoch/.test(w) || /high/.test(w)) return 'high';
  if (/orta/.test(w) || /mittel/.test(w) || /medium/.test(w)) return 'medium';
  return 'low';
}
function areaHeadline(findings: string): string {
  // "... : <seviye> — <gerekce>" — ayirici YALNIZ BOSLUKLA cevrili tire ( — / – / - ).
  const m = findings.match(/(?:Genel risk seviyesi|Gesamtrisikostufe|Overall risk level):\s*[^\n]+?\s[—–-]\s([^\n]+)/i);
  return m ? m[1].trim().replace(/\*\*/g, '') : '';
}
// YÖNETİCİ ÖZETİ + GENEL DEĞERLENDİRME'yi cikar, detay bolumlerini dondur (## -> ### indir).
function detailOnly(findings: string): string {
  const parts = findings.split(/(?=^## )/m); // [0]=YÖNETİCİ, [1]=GENEL, geri kalan = detay
  return parts.slice(2).join('').replace(/^## /gm, '### ').trim();
}

export async function generateBundleSurfaceReport(host: string, locale: string = 'tr'): Promise<{ findings: string; fixText: string } | null> {
  const o = await resolveOrigin(host);
  // (DÜRÜSTLÜK — c durumu) HEDEFE HİÇ ULAŞILAMADI -> "İncelenemedi" raporu (ASLA "temiz"/"düşük").
  if (!o.reachable) return unscannableSurfaceReport(host, locale);
  // Her alan kendi kanitini toplar (bagimsiz, saf); paralel calistir, biri patlarsa null.
  // (BÖLÜM 1) Alanlar collectPages'i PAYLAŞIR (in-flight cache) -> hedefe tek crawl gider.
  const [results, pages] = await Promise.all([
    Promise.all(BUNDLE_AREAS.map((a) => a.gen(host, locale).catch(() => null))),
    collectPages(host).catch(() => [] as PageEvidence[]),
  ]);
  // Hiçbir alan veri toplayamadıysa (reachable ama tüm sorgular başarısız) -> "İncelenemedi".
  return combineSurfaceAreas(results, { httpOnly: o.reachable && !o.httpsWorks, pageCount: pages.length, locale }) ?? unscannableSurfaceReport(host, locale);
}

// Hedefe ulaşılamadığında dürüst "İncelenemedi" raporu (pdf.ts assessBasit nötr amber rozet basar).
function unscannableSurfaceReport(host: string, locale: string = 'tr'): { findings: string; fixText: string } {
  const de = locale === 'de';
  const en = locale === 'en';
  const findings = en
    ? `## EXECUTIVE SUMMARY\n\n` +
      `- **Overall risk level: Not assessable** — the external-surface scan could not be carried out because no connection to the target (${host}) could be established.\n` +
      `- This result does NOT mean the website is SECURE; it only shows that the checks could not be run.\n` +
      `- **Recommended first step:** Confirm that the domain is live and reachable from the outside, then repeat the scan.\n\n` +
      `## OVERALL ASSESSMENT\n\n**Risk Level: Not assessable**\n\n` +
      `No connection could be established to the target's ports 443 (HTTPS) and 80 (HTTP). None of the 5 external-surface areas (TLS, security headers, DNS/email, CORS/cookie, CSP) could collect data. This report is NOT a "clean/secure" result; it should be re-scanned once access is possible.\n`
    : de
    ? `## MANAGEMENTZUSAMMENFASSUNG\n\n` +
      `- **Gesamtrisikostufe: Nicht prüfbar** — die Prüfung der externen Angriffsfläche konnte nicht durchgeführt werden, da keine Verbindung zum Ziel (${host}) hergestellt werden konnte.\n` +
      `- Dieses Ergebnis bedeutet NICHT, dass die Website SICHER ist; es zeigt lediglich, dass die Kontrollen nicht ausgeführt werden konnten.\n` +
      `- **Empfohlener erster Schritt:** Prüfen Sie, ob die Domain online und von außen erreichbar ist, und wiederholen Sie die Prüfung.\n\n` +
      `## GESAMTBEWERTUNG\n\n**Risikostufe: Nicht prüfbar**\n\n` +
      `Zu den Ports 443 (HTTPS) und 80 (HTTP) des Ziels konnte keine Verbindung hergestellt werden. Keiner der 5 Bereiche der externen Angriffsfläche (TLS, Sicherheits-Header, DNS/E-Mail, CORS/Cookie, CSP) konnte Daten erheben. Dieser Bericht ist KEIN „sauberes/sicheres" Ergebnis; sobald der Zugriff möglich ist, sollte erneut geprüft werden.\n`
    : `## YÖNETİCİ ÖZETİ\n\n` +
      `- **Genel risk seviyesi: İncelenemedi** — hedefe (${host}) bağlanılamadığı için dış yüzey taraması yürütülemedi.\n` +
      `- Bu sonuç sitenin GÜVENLİ olduğu anlamına GELMEZ; yalnızca kontrollerin çalıştırılamadığını gösterir.\n` +
      `- **Önerilen ilk adım:** Alan adının yayında ve dışarıdan erişilebilir olduğunu doğrulayıp taramayı tekrarlayın.\n\n` +
      `## GENEL DEĞERLENDİRME\n\n**Risk Seviyesi: İncelenemedi**\n\n` +
      `Hedefin 443 (HTTPS) ve 80 (HTTP) portlarına bağlantı kurulamadı. 5 dış-yüzey alanının (TLS, güvenlik başlıkları, DNS/e-posta, CORS/çerez, CSP) hiçbiri veri toplayamadı. Bu rapor bir "temiz/güvenli" sonucu DEĞİLDİR; erişim sağlanınca yeniden taranmalıdır.\n`;
  return { findings, fixText: '' };
}

// 5 alan sonucunu (bazilari null olabilir) TEK rapora birlestirir. Ayri fonksiyon: sentetik
// verilerle (null-alan / worst-case) test edilebilsin diye. Hepsi null ise -> null (fallback).
export function combineSurfaceAreas(
  results: Array<{ findings: string; fixText: string } | null>,
  opts?: { httpOnly?: boolean; pageCount?: number; locale?: string },
): { findings: string; fixText: string } | null {
  if (results.every((r) => r === null)) return null; // hicbir alan veri toplayamadi -> fallback
  const locale = opts?.locale ?? 'tr';
  const de = locale === 'de';
  const en = locale === 'en';
  const t = (trS: string, deS: string, enS?: string) => (locale === 'de' ? deS : locale === 'en' ? (enS ?? trS) : trS);
  const RW = en ? RISK_WORD_EN : de ? RISK_WORD_DE : RISK_WORD;
  const httpOnly = opts?.httpOnly ?? false;
  const pageCount = Math.max(1, opts?.pageCount ?? 1);

  const levels: Array<Level | null> = results.map((r) => (r ? extractLevel(r.findings) : null));
  // WORST-CASE ALAN: en yuksek seviyeli alanin indexini bul — genel rozet + kutu/genel cumle
  // O ALANIN GERCEK bulgusuna dayanir (sabit/gelisiguzel ornek YOK). Esitlikte ilk alan (stable
  // sort). Fonksiyonel hesap: TS closure-mutasyonunu daraltamadigi icin.
  const ranked = levels
    .map((lv, i) => ({ lv, i }))
    .filter((x): x is { lv: Level; i: number } => x.lv !== null)
    .sort((a, b) => levelRank(b.lv) - levelRank(a.lv));
  const worstIdx = ranked.length ? ranked[0].i : -1;
  const baseWorst: Level = worstIdx >= 0 ? (levels[worstIdx] as Level) : 'low';
  const worstTitle = worstIdx >= 0 ? areaTitle(worstIdx, locale) : '';
  const worstHl = worstIdx >= 0 && results[worstIdx] ? areaHeadline(results[worstIdx]!.findings) : '';

  const nullCount = results.filter((r) => r === null).length;
  const partial = nullCount >= 2;
  let worst: Level = baseWorst;
  if (httpOnly && levelRank(worst) < levelRank('high')) worst = 'high';
  if (partial && worst === 'low') worst = 'medium';

  // --- YÖNETİCİ ÖZETİ (TEK, birlesik) ---
  const summary: string[] = [];
  summary.push(
    worst === 'low'
      ? t(`- **Genel risk seviyesi: Düşük** — dış yüzey yapılandırmanız 5 alanda incelendi; belirgin bir sorun öne çıkmadı.`, `- **Gesamtrisikostufe: Niedrig** — Ihre externe Angriffsfläche wurde in 5 Bereichen geprüft; es wurde kein deutliches Problem festgestellt.`, `- **Overall risk level: Low** — your external surface configuration was examined across 5 areas; no significant issue stood out.`)
      : t(`- **Genel risk seviyesi: ${RW[worst]}** — 5 alan incelendi; en yüksek risk **${worstTitle}** alanında${worstHl ? ` (${worstHl})` : ''}.`, `- **Gesamtrisikostufe: ${RW[worst]}** — 5 Bereiche wurden geprüft; das höchste Risiko liegt im Bereich **${worstTitle}**${worstHl ? ` (${worstHl})` : ''}.`, `- **Overall risk level: ${RW[worst]}** — 5 areas were examined; the highest risk is in the **${worstTitle}** area${worstHl ? ` (${worstHl})` : ''}.`),
  );
  if (httpOnly) summary.push(t('- ⚠️ **HTTPS desteklenmiyor:** Hedef HTTPS (443) üzerinden yanıt vermedi; iletişim şifresiz (düz metin) taşınıyor. Tarama http:// üzerinden yürütüldü. Bu başlı başına ciddi bir bulgudur (aşağıda).', '- ⚠️ **HTTPS wird nicht unterstützt:** Das Ziel hat nicht über HTTPS (443) geantwortet; die Kommunikation läuft unverschlüsselt (Klartext). Die Prüfung wurde über http:// durchgeführt. Das ist für sich genommen ein ernster Befund (siehe unten).', '- ⚠️ **HTTPS is not supported:** The target did not respond over HTTPS (443); communication is carried in plaintext. The scan was run over http://. This is a serious finding in itself (below).'));
  BUNDLE_AREAS.forEach((a, i) => {
    const r = results[i];
    const lv = levels[i];
    const title = areaTitle(i, locale);
    // (c durumu) "veri toplanamadı" DÜRÜSTÇE ayrı: bu "temiz" DEĞİL, o alan İNCELENEMEDİ demektir.
    if (!r || !lv) { summary.push(t(`- **${title}:** ⚠️ incelenemedi (bağlantı/sorgu başarısız) — "temiz" anlamına gelmez.`, `- **${title}:** ⚠️ nicht prüfbar (Verbindung/Abfrage fehlgeschlagen) — bedeutet nicht „sauber".`, `- **${title}:** ⚠️ not assessable (connection/query failed) — does not mean "clean".`)); return; }
    const hl = areaHeadline(r.findings);
    summary.push(`- **${title}:** ${RW[lv]}${hl ? ` — ${hl}` : ''}`);
  });
  if (partial) summary.push(t(`- ⚠️ **Kısmi tarama:** ${nullCount}/5 alan incelenemedi; sonuç eksiktir, tam güvence vermez.`, `- ⚠️ **Teilweise Prüfung:** ${nullCount}/5 Bereiche konnten nicht geprüft werden; das Ergebnis ist unvollständig und bietet keine vollständige Zusicherung.`, `- ⚠️ **Partial scan:** ${nullCount}/5 areas could not be assessed; the result is incomplete and does not give full assurance.`));
  summary.push(t('- **Önerilen ilk adım:** En yüksek riskli alandan başlayın; her bulgu için adım adım hazır komutlar "AI Çözüm Önerileri" bölümünde sunulur.', '- **Empfohlener erster Schritt:** Beginnen Sie mit dem Bereich mit dem höchsten Risiko; für jeden Befund werden schrittweise fertige Befehle im Abschnitt „KI-Lösungsvorschläge" bereitgestellt.', '- **Recommended first step:** Start with the highest-risk area; for each finding, ready-made step-by-step commands are provided in the "AI Fix Suggestions" section.'));

  // GENEL DEĞERLENDİRME cumlesi worst-case ALANA ozgu (pdf.ts bunu ust kutuda da kullanir).
  const genelSentence =
    worst === 'high'
        ? t(`En yüksek risk **${worstTitle}** alanında${worstHl ? ` (${worstHl})` : ''} tespit edildi; öncelikli olarak giderilmesi önerilir. Aşağıda her alan ayrı ayrı raporlanmıştır.`, `Das höchste Risiko wurde im Bereich **${worstTitle}**${worstHl ? ` (${worstHl})` : ''} festgestellt; eine vorrangige Behebung wird empfohlen. Nachfolgend wird jeder Bereich einzeln berichtet.`, `The highest risk was detected in the **${worstTitle}** area${worstHl ? ` (${worstHl})` : ''}; priority remediation is recommended. Each area is reported separately below.`)
        : worst === 'medium-high'
          ? t(`Öne çıkan alan **${worstTitle}**${worstHl ? ` (${worstHl})` : ''}; tek başına yüksek etkili ancak başka ciddi alan yok. Öncelikli olarak giderilmesi önerilir. Aşağıda her alan ayrı ayrı raporlanmıştır.`, `Der hervorstechende Bereich ist **${worstTitle}**${worstHl ? ` (${worstHl})` : ''}; für sich genommen hochwirksam, aber kein weiterer ernster Bereich. Eine vorrangige Behebung wird empfohlen. Nachfolgend wird jeder Bereich einzeln berichtet.`, `The standout area is **${worstTitle}**${worstHl ? ` (${worstHl})` : ''}; high-impact on its own but no other serious area. Priority remediation is recommended. Each area is reported separately below.`)
          : worst === 'medium'
            ? t(`Öne çıkan alan **${worstTitle}**${worstHl ? ` (${worstHl})` : ''}; kısa vadede giderilmesi önerilir. Kritik/acil bir sorun öne çıkmadı. Aşağıda her alan ayrı ayrı raporlanmıştır.`, `Der hervorstechende Bereich ist **${worstTitle}**${worstHl ? ` (${worstHl})` : ''}; eine kurzfristige Behebung wird empfohlen. Kein kritisches/dringendes Problem festgestellt. Nachfolgend wird jeder Bereich einzeln berichtet.`, `The standout area is **${worstTitle}**${worstHl ? ` (${worstHl})` : ''}; short-term remediation is recommended. No critical/urgent issue stood out. Each area is reported separately below.`)
            : t('Dış yüzey yapılandırmanız genel olarak sağlam; rapor yalnızca küçük iyileştirme fırsatlarını listeler. Aşağıda her alan ayrı ayrı raporlanmıştır.', 'Ihre externe Angriffsfläche ist insgesamt solide konfiguriert; der Bericht listet nur kleine Verbesserungsmöglichkeiten auf. Nachfolgend wird jeder Bereich einzeln berichtet.', 'Your external surface configuration is generally sound; the report lists only minor improvement opportunities. Each area is reported separately below.');

  // --- Alan bolumleri (exec/genel cikarilmis, ## -> ### indirilmis) ---
  const areaSections = BUNDLE_AREAS.map((a, i) => {
    const r = results[i];
    const title = areaTitle(i, locale);
    if (!r) return `## ${title}\n\n> ${t('Bu alan için veri toplanamadı (bağlantı/sorgu başarısız); diğer alanlar tam olarak raporlanmıştır.', 'Für diesen Bereich konnten keine Daten erhoben werden (Verbindung/Abfrage fehlgeschlagen); die übrigen Bereiche wurden vollständig berichtet.', 'No data could be collected for this area (connection/query failed); the other areas were reported in full.')}\n`;
    return `## ${title}\n\n${detailOnly(r.findings)}\n`;
  }).join('\n');

  // (MASTER TABLO + ZAFİYET DAĞILIMI) https_missing ŞİDDET-KOLONLU tablo -> parseFindings sayar
  const httpsFindingSection = httpOnly
    ? `## ${t('TESPİT EDİLEN RİSKLER', 'FESTGESTELLTE RISIKEN', 'IDENTIFIED RISKS')}\n\n| ${t('Bulgu', 'Befund', 'Finding')} | ${t('Şiddet', 'Schweregrad', 'Severity')} | ${t('Açıklama', 'Beschreibung', 'Description')} |\n|-------|--------|----------|\n| ${t('HTTPS desteklenmiyor (şifresiz iletişim)', 'HTTPS wird nicht unterstützt (unverschlüsselte Kommunikation)', 'HTTPS is not supported (unencrypted communication)')} | ${en ? 'High' : de ? 'Hoch' : 'Yüksek'} | ${t(`Site HTTPS'e yanıt vermiyor; tüm trafik şifresiz (düz metin) taşınıyor — dinlenebilir/değiştirilebilir, oturum/şifre çalınabilir. Çözüm: geçerli TLS sertifikası + HTTP→HTTPS yönlendirme + HSTS.`, `Die Website antwortet nicht über HTTPS; der gesamte Verkehr wird unverschlüsselt (Klartext) übertragen — mitlesbar/veränderbar, Sitzungen/Passwörter können gestohlen werden. Lösung: gültiges TLS-Zertifikat + HTTP→HTTPS-Umleitung + HSTS.`, `The site does not respond over HTTPS; all traffic is carried in plaintext — it can be intercepted/modified and sessions/passwords stolen. Fix: valid TLS certificate + HTTP→HTTPS redirect + HSTS.`)} |\n\n`
    : '';

  // (BÖLÜM 2 — POZİTİF GÜVENCE) "Sorun bulunamadı"yı da ŞEFFAF kıl.
  const assuranceRows = BUNDLE_AREAS.map((a, i) => {
    const r = results[i]; const lv = levels[i];
    const title = areaTitle(i, locale);
    // Master tabloya DÜŞEN satırlar burada da esas alınır (özet ↔ tablo çelişkisi imkânsız).
    const counted = r ? worstCountedSeverity(r.findings) : null;
    const sevWord = counted ? RW[counted === 'critical' ? 'high' : counted] : '';
    const state = !r || !lv
      ? t('⚠️ İncelenemedi (veri toplanamadı — “temiz” DEĞİL)', '⚠️ Nicht prüfbar (keine Daten erhebbar — NICHT „sauber")', '⚠️ Not assessable (no data collected — NOT "clean")')
      : counted
        ? t(`⚠️ Bulgu var (${sevWord} — yukarıda ayrıntılı)`, `⚠️ Befund vorhanden (${sevWord} — oben im Detail)`, `⚠️ Finding present (${sevWord} — detailed above)`)
        : t('✅ Sorun bulunmadı', '✅ Kein Problem gefunden', '✅ No issue found');
    return `| ${title} | ${state} |`;
  }).join('\n');
  // (Faz 4 — DÜRÜSTLÜK) Ek pasif alt-kontroller (dizin listeleme/hata ifşası/autocomplete, CWE-548/209/522)
  // pozitif güvence tablosunda da AÇIKÇA görünsün — TEMİZKEN BİLE "denendi". State, header alanının
  // "EK BİLGİ-SIZINTISI GÖZLEMLERİ" üç-durum tablosundaki HÜCRENİN AYNISIDIR (uydurma yok).
  const extraAssurance: string[] = [];
  for (const r of results) {
    if (!r) continue;
    for (const line of r.findings.split('\n')) {
      if (/^\|.*CWE-(?:548|209|522).*\|.*\|\s*$/.test(line)) extraAssurance.push(line.trim());
    }
  }
  const assuranceRowsAll = extraAssurance.length ? `${assuranceRows}\n${extraAssurance.join('\n')}` : assuranceRows;
  const assuranceSection = en
    ? `## POSITIVE ASSURANCE — AREAS CHECKED\n\n` +
      `Including the areas with no finding, the external-surface checks were genuinely run across **${pageCount} unique pages** including the home page. The table below also shows the "no issue found" results transparently:\n\n` +
      `| Control area | Result |\n|---------------|-------|\n${assuranceRowsAll}\n\n` +
      `> **Three-state distinction (honesty):** ✅ *No issue found* = the check ran and came back clean · ⚠️ *Finding present* = detailed above · ⚠️ *Not assessable* = no data could be collected (does NOT mean secure).\n\n` +
      `### What this package DOES and DOES NOT check\n\n` +
      `**DOES (passive — only page retrieval via GET + harmless Origin/DNS query):** TLS/certificate, HTTP security headers, CORS policy, cookie flags (Secure/HttpOnly/SameSite), Content-Security-Policy, DNS/email records (SPF/DKIM/DMARC/DNSSEC), exposed sensitive files (incl. common backup patterns), directory listing (autoindex), verbose-error/server-path disclosure (redacted), password-field autocomplete policy, outdated/unsupported software versions — across the ${pageCount} discovered pages.\n\n` +
      `**DOES NOT:** Active vulnerability verification (payload/probe attempts such as SQLi/XSS/IDOR), authenticated flow testing, business-logic abuse. These are within the scope of the **Active Verification** and **Full-Scope Pentest** packages. This report relies on passive observation; "no finding" in an area **does NOT PROVE** it is secure, because no active exploit was attempted — it only shows that the externally observed configuration is clean.\n\n`
    : de
    ? `## POSITIVE ZUSICHERUNG — GEPRÜFTE BEREICHE\n\n` +
      `Auch die Bereiche ohne Befund eingeschlossen, wurden die Kontrollen der externen Angriffsfläche tatsächlich auf **${pageCount} einzigartigen Seiten** einschließlich der Startseite ausgeführt. Die folgende Tabelle zeigt auch die „kein Problem gefunden"-Ergebnisse transparent:\n\n` +
      `| Kontrollbereich | Ergebnis |\n|---------------|-------|\n${assuranceRowsAll}\n\n` +
      `> **Drei-Zustands-Unterscheidung (Ehrlichkeit):** ✅ *Kein Problem gefunden* = Kontrolle lief, Ergebnis sauber · ⚠️ *Befund vorhanden* = oben im Detail · ⚠️ *Nicht prüfbar* = keine Daten erhebbar (bedeutet NICHT sicher).\n\n` +
      `### Was dieses Paket prüft — und was NICHT\n\n` +
      `**PRÜFT (passiv — nur Seitenabruf per GET + harmlose Origin-/DNS-Abfrage):** TLS/Zertifikat, HTTP-Sicherheits-Header, CORS-Richtlinie, Cookie-Flags (Secure/HttpOnly/SameSite), Content-Security-Policy, DNS-/E-Mail-Einträge (SPF/DKIM/DMARC/DNSSEC), offenliegende sensible Dateien (inkl. gängiger Backup-Muster), Verzeichnisauflistung (autoindex), ausführliche-Fehler-/Serverpfad-Offenlegung (redigiert), autocomplete-Richtlinie im Passwortfeld, veraltete/nicht unterstützte Softwareversionen — auf den ${pageCount} entdeckten Seiten.\n\n` +
      `**PRÜFT NICHT:** Aktive Schwachstellenverifikation (Payload-/Probe-Versuche wie SQLi/XSS/IDOR), authentifizierte Ablauftests, Missbrauch der Geschäftslogik. Diese gehören zum Umfang der Pakete **Aktive Verifikation** und **Umfassender Pentest**. Dieser Bericht beruht auf passiver Beobachtung; die Aussage „kein Befund" in einem Bereich **BEWEIST NICHT**, dass er sicher ist, da kein aktiver Exploit versucht wurde — sie zeigt lediglich, dass die von außen beobachtete Konfiguration sauber ist.\n\n`
    : `## POZİTİF GÜVENCE — KONTROL EDİLEN ALANLAR\n\n` +
      `Bulgu çıkmayan alanlar da dâhil, dış-yüzey kontrolleri ana sayfa dâhil **${pageCount} benzersiz sayfada** gerçekten çalıştırıldı. Aşağıdaki tablo, "sorun bulunamadı" sonuçlarını da şeffaf biçimde gösterir:\n\n` +
      `| Kontrol Alanı | Sonuç |\n|---------------|-------|\n${assuranceRowsAll}\n\n` +
      `> **Üç-durum ayrımı (dürüstlük):** ✅ *Sorun bulunmadı* = kontrol çalıştı, temiz çıktı · ⚠️ *Bulgu var* = yukarıda detaylı · ⚠️ *İncelenemedi* = veri toplanamadı (güvenli anlamına GELMEZ).\n\n` +
      `### Bu paket NE kontrol EDER, NE ETMEZ\n\n` +
      `**EDER (pasif — yalnız GET ile sayfa çekme + zararsız Origin/DNS sorgusu):** TLS/sertifika, HTTP güvenlik başlıkları, CORS politikası, çerez bayrakları (Secure/HttpOnly/SameSite), Content-Security-Policy, DNS/e-posta kayıtları (SPF/DKIM/DMARC/DNSSEC), açıkta hassas dosya (yaygın yedek kalıpları dâhil), dizin listeleme (autoindex), ayrıntılı-hata/sunucu-yol ifşası (redakte), parola alanı autocomplete politikası, eski/desteksiz yazılım sürümü — keşfedilen ${pageCount} sayfada.\n\n` +
      `**ETMEZ:** Aktif zafiyet doğrulaması (SQLi/XSS/IDOR gibi payload/prob denemesi), kimlik-doğrulamalı akış testi, iş-mantığı istismarı. Bunlar **Aktif Doğrulama** ve **Tam Kapsamlı Pentest** paketlerinin kapsamındadır. Bu rapor pasif gözleme dayanır; bir alanda "bulgu yok" ifadesi, aktif istismar denenmediği için **güvenli olduğunu KANITLAMAZ** — yalnız dışarıdan gözlemlenen yapılandırmanın temiz olduğunu gösterir.\n\n`;

  const findings =
    `## ${t('YÖNETİCİ ÖZETİ', 'MANAGEMENTZUSAMMENFASSUNG', 'EXECUTIVE SUMMARY')}\n\n${summary.join('\n')}\n\n` +
    `## ${t('GENEL DEĞERLENDİRME', 'GESAMTBEWERTUNG', 'OVERALL ASSESSMENT')}\n\n**${t('Risk Seviyesi', 'Risikostufe', 'Risk Level')}: ${RW[worst]}**\n\n${httpOnly ? t('Bu hedef HTTPS üzerinden yanıt vermiyor; iletişim şifresiz (düz metin) taşınıyor — öncelikli olarak geçerli bir TLS sertifikasıyla HTTPS’e geçilmelidir. Diğer alanlar http:// üzerinden incelenmiştir. ', 'Dieses Ziel antwortet nicht über HTTPS; die Kommunikation läuft unverschlüsselt (Klartext) — vorrangig sollte mit einem gültigen TLS-Zertifikat auf HTTPS umgestellt werden. Die übrigen Bereiche wurden über http:// geprüft. ', 'This target does not respond over HTTPS; communication is carried in plaintext — the priority is to move to HTTPS with a valid TLS certificate. The other areas were examined over http://. ') : ''}${genelSentence}\n\n` +
    `${httpsFindingSection}${areaSections}\n${assuranceSection}`;

  // --- AI ÇÖZÜM ÖNERİLERİ (5 alan TEK bolumde, alt-basliklarla) ---
  const fixParts = BUNDLE_AREAS.map((a, i) => {
    const r = results[i];
    if (!r || !r.fixText.trim()) return '';
    return `### ${areaTitle(i, locale)}\n\n${r.fixText.trim()}`;
  }).filter(Boolean);
  const fixText =
    t('Bu bölüm, dış yüzey taramanızda tespit edilen tüm eksiklikler için alan alan düzeltme önerileri içerir. Sunucunuza uygun örnekleri (Nginx/Firebase/Apache/DNS) kopyalayın.', 'Dieser Abschnitt enthält bereichsweise Korrekturvorschläge für alle in Ihrer Prüfung der externen Angriffsfläche festgestellten Lücken. Kopieren Sie die für Ihren Server passenden Beispiele (Nginx/Firebase/Apache/DNS).', 'This section contains area-by-area remediation suggestions for all the gaps detected in your external-surface scan. Copy the examples that suit your server (Nginx/Firebase/Apache/DNS).') + '\n\n' +
    fixParts.join('\n\n');

  return { findings, fixText };
}
