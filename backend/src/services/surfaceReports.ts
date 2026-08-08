/**
 * (Dış Yüzey & Yapılandırma bundle üyeleri) DETERMINISTIK RAPOR URETICILERI.
 *
 * ssl_tls / header_leak / dns_email / cors_cookie / csp_analiz — her biri KOD-toplanmis
 * kanittan (surfaceEvidence.ts) kendi odakli raporunu uretir. Ajan ciktisina bakilmaz.
 * Her fonksiyon { findings, fixText } | null doner (hedefe ulasilamazsa null -> fallback).
 * Risk hesabi TAMAMEN kod; GENEL DEĞERLENDİRME'ye acik "Risk Seviyesi: X" yazilir (pdf.ts
 * assessBasit bunu okuyup rozeti tutarli gosterir).
 */
import {
  collectHttp, collectTls, collectCors, collectDns, collectExposedFiles,
  type TlsEvidence, type DnsEvidence,
} from './surfaceEvidence.js';
import { buildHeaderFixSuggestions } from './fixSuggestions.js';

const RISK_WORD = { low: 'Düşük', medium: 'Orta', high: 'Yüksek' } as const;
type Level = 'low' | 'medium' | 'high';

function assemble(_title: string, level: Level, summaryBullets: string[], genelSentence: string, sections: string): string {
  return (
    `## YÖNETİCİ ÖZETİ\n\n${summaryBullets.join('\n')}\n\n` +
    `## GENEL DEĞERLENDİRME\n\n**Risk Seviyesi: ${RISK_WORD[level]}**\n\n${genelSentence}\n\n` +
    `${sections}`
  );
}

// ======================================================================================
// 1) ssl_tls — SSL/TLS Yapılandırma Denetimi
// ======================================================================================
export async function generateSslTlsReport(host: string): Promise<{ findings: string; fixText: string } | null> {
  const [http, tls] = await Promise.all([collectHttp(host), collectTls(host)]);
  if (!tls.found && !http.ok) return null;

  const hstsPresent = http.headers.has('strict-transport-security');
  const expired = tls.daysLeft != null && tls.daysLeft < 0;
  const veryClose = tls.daysLeft != null && tls.daysLeft >= 0 && tls.daysLeft < 15; // ESKALASYON
  const expiringSoon = tls.daysLeft != null && tls.daysLeft >= 15 && tls.daysLeft < 45;
  const mismatch = tls.hostnameMatch === false;
  const weak = tls.weakProtocols.length > 0;

  let level: Level = 'low';
  if (expired || mismatch || weak || veryClose) level = 'high'; // <15 gun -> bir kademe YUKARI
  else if (expiringSoon || !hstsPresent) level = 'medium';

  const tlsSection = tlsBlock(host, tls);
  const protoSection =
    `## TLS PROTOKOL & CIPHER\n\n` +
    `- **Aktif protokol:** ${tls.protocol ?? 'tespit edilemedi'}${tls.protocol && /TLSv1\.[01]$/.test(tls.protocol) ? ' — ⚠️ zayıf' : ''}\n` +
    `- **Cipher:** ${tls.cipher ?? 'tespit edilemedi'}\n` +
    `- **Eski/zayıf sürüm desteği:** ${weak ? `⚠️ ${tls.weakProtocols.join(', ')} hâlâ kabul ediliyor — kapatılması önerilir` : 'Gözlemlenmedi (yalnızca TLS 1.2+ görüldü)'}\n\n`;
  const hstsSection =
    `## HSTS (HTTP Strict Transport Security)\n\n` +
    (hstsPresent
      ? `- **Durum:** Var — \`${http.headers.get('strict-transport-security')}\`. Tarayıcıya HTTPS zorunluluğu bildiriliyor.\n\n`
      : `- **Durum:** Yok — Tarayıcıya HTTPS zorunluluğu bildirilmiyor; ilk isteklerde SSL-stripping/downgrade saldırısı riski var.\n\n`);

  const risks: string[] = [];
  if (mismatch) risks.push(`- **Yüksek — Sertifika hostname uyuşmazlığı:** Sertifika ${host} adına düzenlenmemiş; ziyaretçiler tarayıcı güvenlik uyarısıyla karşılaşır.`);
  if (expired) risks.push('- **Yüksek — Sertifika süresi dolmuş:** Site tarayıcılarca güvensiz kabul edilir.');
  if (weak) risks.push(`- **Yüksek — Zayıf TLS sürümü:** ${tls.weakProtocols.join(', ')} destekleniyor. Bu sürümlerde bilinen zayıflıklar (POODLE/BEAST vb.) vardır; devre dışı bırakılmalı.`);
  if (veryClose) risks.push(`- **Yüksek — Sertifika çok yakında sona eriyor:** yalnızca ${tls.daysLeft} gün kaldı; acilen yenilenmeli (aksi halde site erişilemez/güvensiz olur).`);
  if (expiringSoon) risks.push(`- **Orta — Sertifika yakında sona eriyor:** ${tls.daysLeft} gün kaldı; kesinti yaşamamak için yenileme planlanmalı.`);
  if (!hstsPresent) risks.push('- **Orta — HSTS eksik:** HTTPS zorunluluğu tarayıcıya bildirilmiyor; downgrade saldırılarına açık.');
  if (!risks.length) risks.push('- Belirgin bir TLS yapılandırma sorunu öne çıkmadı; şifreleme yapılandırması güncel.');

  const bullets: string[] = [];
  bullets.push(`- **Genel risk seviyesi: ${RISK_WORD[level]}** — ${level === 'high' ? 'sertifika ve/veya protokol düzeyinde acil ele alınması gereken bir sorun tespit edildi.' : level === 'medium' ? 'şifreleme temelde sağlam; kısa vadede giderilecek eksikler var.' : 'şifreleme yapılandırması güncel ve sağlam.'}`);
  bullets.push(`- Sertifika: ${tls.found ? (mismatch ? '⚠️ hostname uyuşmazlığı' : expired ? '⚠️ süresi dolmuş' : `geçerli (${tls.daysLeft} gün)`) : 'tespit edilemedi'}${tls.protocol ? `, ${tls.protocol}` : ''}.`);
  bullets.push(`- HSTS: ${hstsPresent ? 'var' : 'yok'}; Eski TLS desteği: ${weak ? tls.weakProtocols.join(', ') : 'gözlemlenmedi'}.`);
  bullets.push('- **Önerilen ilk adım:** ' + (weak ? 'Eski TLS sürümlerini kapatın ve ' : '') + (hstsPresent ? 'sertifika yenilemeyi takip edin.' : 'HSTS başlığını ekleyin (hazır komutlar "AI Çözüm Önerileri" eklentisinde).'));

  const genel =
    level === 'high'
      ? 'Şifreleme katmanında ziyaretçileri doğrudan etkileyebilecek (sertifika/protokol) acil bir sorun tespit edildi; öncelikli giderilmesi önerilir.'
      : level === 'medium'
        ? 'Taşıma güvenliği temelde sağlam; kısa vadede giderilmesi önerilen eksikler (ör. HSTS / yaklaşan yenileme) var.'
        : 'TLS/SSL yapılandırması güncel ve sağlam; rapor yalnızca küçük iyileştirme fırsatlarını listeler.';

  const findings = assemble('SSL/TLS', level, bullets, genel, `${tlsSection}${protoSection}${hstsSection}## TESPİT EDİLEN RİSKLER\n\n${risks.join('\n')}\n`);
  const fixText = buildTlsFix(host, { hstsMissing: !hstsPresent, weak: tls.weakProtocols });
  return { findings, fixText };
}

function tlsBlock(host: string, tls: TlsEvidence): string {
  if (!tls.found) return '## TLS SERTİFİKA DURUMU\n\nTLS sertifika bilgisi elde edilemedi (443 portuna güvenli bağlantı kurulamadı).\n\n';
  const l: string[] = [];
  l.push(`- **Geçerlilik:** ${tls.daysLeft != null ? (tls.daysLeft >= 0 ? `Geçerli, ${tls.daysLeft} gün kaldı` : `SÜRESİ DOLMUŞ (${Math.abs(tls.daysLeft)} gün önce)`) : 'Belirlenemedi'}${tls.notAfter ? ` (bitiş: ${tls.notAfter})` : ''}`);
  if (tls.hostnameMatch === false) l.push(`- **Hostname eşleşmesi:** ⚠️ Sertifika ${host} ile eşleşmiyor${tls.cn ? ` (sahibi: ${tls.cn})` : ''}${tls.san.length ? `; kapsanan: ${tls.san.slice(0, 6).join(', ')}` : ''}.`);
  else if (tls.hostnameMatch === true) { const multi = tls.cn && tls.cn.toLowerCase() !== host.toLowerCase(); l.push(`- **Hostname eşleşmesi:** Uyumlu${multi ? ` (çok alanlı sertifika; ${host} kapsanıyor)` : ''}.`); }
  if (tls.issuer) l.push(`- **Veren (issuer):** ${tls.issuer}`);
  return `## TLS SERTİFİKA DURUMU\n\n${l.join('\n')}\n\n`;
}

// ======================================================================================
// 2) header_leak — Güvenlik Başlıkları & Bilgi Sızıntısı
// ======================================================================================
const SEC_HDRS: Array<{ hdr: string; name: string; absent: string }> = [
  { hdr: 'strict-transport-security', name: 'Strict-Transport-Security', absent: 'HTTPS zorunluluğu bildirilmiyor; SSL-stripping riski.' },
  { hdr: 'content-security-policy', name: 'Content-Security-Policy', absent: 'XSS/enjeksiyona karşı tarayıcı savunması yok.' },
  { hdr: 'x-frame-options', name: 'X-Frame-Options', absent: 'Clickjacking’e açık; iframe’e gömülebilir.' },
  { hdr: 'x-content-type-options', name: 'X-Content-Type-Options', absent: 'MIME-sniffing mümkün.' },
  { hdr: 'referrer-policy', name: 'Referrer-Policy', absent: 'Referrer bilgisi dış kaynaklara sızabilir.' },
  { hdr: 'permissions-policy', name: 'Permissions-Policy', absent: 'Hassas tarayıcı API’leri kısıtlanmamış.' },
  { hdr: 'x-xss-protection', name: 'X-XSS-Protection', absent: 'Eski tarayıcı XSS filtresi ayarlı değil (modernlerde kritik değil).' },
];

export async function generateHeaderLeakReport(host: string): Promise<{ findings: string; fixText: string } | null> {
  const http = await collectHttp(host);
  if (!http.ok) return null;
  const exposed = await collectExposedFiles(host, http.html);

  const missing = SEC_HDRS.filter((h) => !http.headers.has(h.hdr));
  const missingCrit = missing.filter((h) => h.hdr === 'content-security-policy' || h.hdr === 'x-frame-options');
  const exposedHits = exposed.filter((e) => e.exposed);

  let level: Level = 'low';
  if (exposedHits.length) level = 'high';
  else if (missingCrit.length || missing.length >= 3) level = 'medium';

  const table =
    `## HTTP GÜVENLİK BAŞLIKLARI\n\n| Başlık | Durum | Açıklama |\n|--------|-------|----------|\n` +
    SEC_HDRS.map((h) => {
      const present = http.headers.has(h.hdr);
      return `| ${h.name} | ${present ? 'Var' : 'Yok'} | ${present ? 'Mevcut ve yapılandırılmış.' : h.absent} |`;
    }).join('\n') + '\n\n';

  const leakSection =
    `## BİLGİ SIZINTISI / AÇIKTA DOSYALAR\n\n` +
    `Yaygın hassas yollar tek GET ile kontrol edildi (içerik doğrulandı — yalnız HTTP 200 kanıt sayılmaz):\n\n` +
    `| Yol | Durum | Not |\n|-----|-------|-----|\n` +
    exposed.map((e) => `| \`${e.path}\` | ${e.exposed ? '⚠️ AÇIK' : 'Kapalı'} | ${e.reason} |`).join('\n') + '\n\n';

  const risks: string[] = [];
  for (const e of exposedHits) risks.push(`- **Yüksek — Hassas dosya erişilebilir (\`${e.path}\`):** İçerik doğrulandı; yapılandırma/kaynak sızıntısı riski. Erişim derhal engellenmeli.`);
  if (missingCrit.length) risks.push(`- **Orta — Kritik güvenlik başlıkları eksik (${missingCrit.map((h) => h.name).join(', ')}):** XSS/clickjacking’e karşı tarayıcı savunması zayıf.`);
  const otherMissing = missing.filter((h) => !missingCrit.includes(h));
  if (otherMissing.length) risks.push(`- **Orta — Ek başlıklar eksik (${otherMissing.map((h) => h.name).join(', ')}):** Savunma derinliği zayıf.`);
  if (!risks.length) risks.push('- Belirgin bir başlık/sızıntı sorunu öne çıkmadı.');

  const bullets: string[] = [];
  bullets.push(`- **Genel risk seviyesi: ${RISK_WORD[level]}** — ${level === 'high' ? 'dışarıdan erişilebilir hassas dosya tespit edildi.' : level === 'medium' ? 'önemli güvenlik başlığı eksiklikleri var.' : 'ciddi bir sorun öne çıkmadı.'}`);
  bullets.push(`- ${missing.length}/${SEC_HDRS.length} güvenlik başlığı eksik${missing.length ? `: ${missing.map((h) => h.name).join(', ')}` : ''}.`);
  bullets.push(`- Açıkta dosya: ${exposedHits.length ? `⚠️ ${exposedHits.map((e) => e.path).join(', ')}` : 'tespit edilmedi'}.`);
  bullets.push('- **Önerilen ilk adım:** ' + (exposedHits.length ? 'Açıkta kalan dosyalara erişimi engelleyin ve ' : '') + 'eksik güvenlik başlıklarını ekleyin (hazır komutlar "AI Çözüm Önerileri" eklentisinde).');

  const genel =
    level === 'high'
      ? 'Dışarıdan erişilebilen hassas bir dosya tespit edildi (içerik doğrulandı); öncelikli olarak erişimin engellenmesi gerekir. Ayrıca eksik güvenlik başlıkları savunmayı zayıflatıyor.'
      : level === 'medium'
        ? 'Önemli güvenlik başlığı eksiklikleri var; hassas dosya sızıntısı tespit edilmedi. Eksik başlıklar düşük maliyetli sunucu ayarlarıyla kapatılabilir.'
        : 'Güvenlik başlıkları büyük ölçüde mevcut ve dışarıdan erişilebilen hassas dosya bulunmadı.';

  const findings = assemble('Başlıklar', level, bullets, genel, `${table}${leakSection}## TESPİT EDİLEN RİSKLER\n\n${risks.join('\n')}\n`);
  const fixText = buildHeaderFixSuggestions(findings, host) + (exposedHits.length ? '\n\n' + buildExposedFileFix(exposedHits.map((e) => e.path)) : '');
  return { findings, fixText };
}

// ======================================================================================
// 3) dns_email — DNS & E-posta Güvenliği
// ======================================================================================
export async function generateDnsEmailReport(host: string): Promise<{ findings: string; fixText: string } | null> {
  const dns = await collectDns(host);
  if (!dns.ok) return null;

  const spfWeak = !dns.spf || dns.spf.all === 'yok' || dns.spf.all === '+all' || dns.spf.all === '?all';
  const spfMissing = !dns.spf || dns.spf.all === 'yok';
  const dmarcMissing = !dns.dmarc || dns.dmarc.policy === 'yok';
  const dmarcWeak = dns.dmarc?.policy === 'none';
  const dkimMissing = !dns.dkim?.found;

  // Risk YALNIZ SPF/DMARC'a (yetkili/kesin sinyaller) gore. DKIM "tespit edilemedi" belirsizdir
  // (seçici bilinmiyor) ve DNSSEC yoklugu tek basina — ikisi de LEVEL'i YUKSELTMEZ, yalniz
  // bilgilendirme olarak listelenir. Aksi halde guclu bir alan (ör. google.com) yanlislikla
  // "Orta" cikar.
  let level: Level = 'low';
  if (spfMissing && dmarcMissing) level = 'high'; // spoofing sonuna kadar acik
  else {
    const authWeak = [spfMissing || spfWeak, dmarcMissing || dmarcWeak].filter(Boolean).length;
    if (authWeak >= 2) level = 'high';
    else if (authWeak >= 1) level = 'medium';
  }

  const spfSection =
    `## SPF (Gönderen Politikası)\n\n` +
    (dns.spf && dns.spf.all !== 'yok'
      ? `- **Durum:** Var — \`${dns.spf.record}\`\n- **Sertlik:** \`${dns.spf.all}\` — ${dns.spf.all === '-all' ? 'katı (hardfail; en güvenli).' : dns.spf.all === '~all' ? 'yumuşak (softfail; kabul edilebilir, ideal değil).' : dns.spf.all === '+all' || dns.spf.all === '?all' ? '⚠️ zayıf/etkisiz — herkesin sizin adınıza mail göndermesine izin verir.' : 'belirsiz.'}\n\n`
      : `- **Durum:** Yok — SPF kaydı bulunamadı. Alan adınız adına sahte e-posta gönderimi (spoofing) kolaylaşır.\n\n`);
  const dmarcSection =
    `## DMARC (Kimlik Doğrulama Politikası)\n\n` +
    (dns.dmarc && dns.dmarc.policy !== 'yok'
      ? `- **Durum:** Var — \`${dns.dmarc.record}\`\n- **Politika:** \`p=${dns.dmarc.policy}\` — ${dns.dmarc.policy === 'reject' ? 'güçlü (sahte mailler reddedilir).' : dns.dmarc.policy === 'quarantine' ? 'orta (sahte mailler spam’e düşer).' : '⚠️ zayıf (p=none; yalnızca izler, engellemez).'}\n\n`
      : `- **Durum:** Yok — DMARC kaydı bulunamadı. SPF/DKIM sonuçlarına göre uygulama yapılmıyor; spoofing’e karşı koruma zayıf.\n\n`);
  const dkimSection =
    `## DKIM (İmza)\n\n` +
    (dns.dkim?.found
      ? `- **Durum:** Tespit edildi (\`${dns.dkim.selector}._domainkey\` seçicisi). E-postalar kriptografik olarak imzalanıyor.\n\n`
      : `- **Durum:** Tespit edilemedi — Yaygın seçicilerde (default/google/selector1…) DKIM kaydı bulunamadı. Farklı bir seçici kullanıyor olabilirsiniz; bu kesin “yok” anlamına gelmez.\n\n`);
  const dnssecSection =
    `## DNSSEC\n\n- **Durum:** ${dns.dnssec ? 'Aktif — DNS yanıtları kriptografik olarak imzalı (DNS zehirlenmesine karşı koruma).' : 'Pasif/yok — DNS yanıtları imzalı değil; DNS spoofing/cache-poisoning riskine daha açık.'}\n\n`;

  const risks: string[] = [];
  if (spfMissing && dmarcMissing) risks.push('- **Yüksek — Alan adınız e-posta sahteciliğine (spoofing) tamamen açık:** Ne SPF ne DMARC var. Saldırgan sizin adınıza sahte e-posta gönderebilir.');
  else {
    if (spfMissing) risks.push('- **Orta — SPF eksik:** Yetkili gönderen sunucular tanımlı değil.');
    else if (spfWeak) risks.push(`- **Orta — SPF zayıf (\`${dns.spf?.all}\`):** Sahte gönderimi etkili biçimde engellemiyor.`);
    if (dmarcMissing) risks.push('- **Orta — DMARC eksik:** SPF/DKIM sonuçları uygulanmıyor.');
    else if (dmarcWeak) risks.push('- **Orta — DMARC zayıf (`p=none`):** Yalnızca raporlama; sahte mailler yine de teslim edilir.');
  }
  if (dkimMissing) risks.push('- **Bilgilendirme — DKIM tespit edilemedi:** Yaygın seçicilerde bulunamadı (farklı seçici olabilir).');
  if (!dns.dnssec) risks.push('- **Bilgilendirme — DNSSEC pasif:** DNS yanıtları imzalı değil.');
  if (!risks.length) risks.push('- E-posta kimlik doğrulama kayıtları (SPF/DMARC/DKIM) düzgün yapılandırılmış.');

  const bullets: string[] = [];
  bullets.push(`- **Genel risk seviyesi: ${RISK_WORD[level]}** — ${level === 'high' ? 'e-posta sahteciliğine karşı koruma kritik seviyede zayıf.' : level === 'medium' ? 'e-posta kimlik doğrulamasında giderilmesi gereken eksikler var.' : 'e-posta kimlik doğrulama kayıtları büyük ölçüde sağlam.'}`);
  bullets.push(`- SPF: ${dns.spf && dns.spf.all !== 'yok' ? `var (${dns.spf.all})` : 'yok'} · DMARC: ${dns.dmarc && dns.dmarc.policy !== 'yok' ? `p=${dns.dmarc.policy}` : 'yok'} · DKIM: ${dns.dkim?.found ? 'var' : 'tespit edilemedi'} · DNSSEC: ${dns.dnssec ? 'aktif' : 'yok'}.`);
  bullets.push('- **Önerilen ilk adım:** ' + (spfMissing || dmarcMissing ? 'SPF ve DMARC kayıtlarını ekleyin (örnek TXT kayıtları "AI Çözüm Önerileri" eklentisinde).' : 'DMARC politikasını kademeli sıkılaştırın (none → quarantine → reject).'));

  const genel =
    level === 'high'
      ? 'Alan adınız e-posta sahteciliğine (spoofing/phishing) karşı yetersiz korunuyor; SPF/DMARC eksik veya etkisiz. Öncelikli olarak ele alınması önerilir.'
      : level === 'medium'
        ? 'E-posta kimlik doğrulama kayıtlarında (SPF/DMARC/DKIM) giderilmesi önerilen eksikler var. Bunlar kademeli olarak sıkılaştırılabilir.'
        : 'E-posta kimlik doğrulama kayıtları büyük ölçüde sağlam; rapor yalnızca küçük iyileştirmeleri listeler.';

  const findings = assemble('DNS/E-posta', level, bullets, genel, `${spfSection}${dmarcSection}${dkimSection}${dnssecSection}## TESPİT EDİLEN RİSKLER\n\n${risks.join('\n')}\n`);
  const fixText = buildDnsFix(host, dns);
  return { findings, fixText };
}

// ======================================================================================
// 4) cors_cookie — CORS & Çerez Güvenliği
// ======================================================================================
export async function generateCorsCookieReport(host: string): Promise<{ findings: string; fixText: string } | null> {
  const [http, cors] = await Promise.all([collectHttp(host), collectCors(host)]);
  if (!http.ok && !cors.ok) return null;

  const credsWildcardDanger = (cors.wildcard || cors.reflected) && /true/i.test(cors.acac ?? '');
  const cookies = http.setCookies.map(parseCookie);
  const insecureCookies = cookies.filter((c) => !c.secure || !c.httpOnly);
  const sameSiteNone = cookies.filter((c) => c.sameSite === 'none' && !c.secure);

  let level: Level = 'low';
  if (credsWildcardDanger) level = 'high';
  else if (cors.wildcard || cors.reflected || insecureCookies.length) level = 'medium';

  const corsSection =
    `## CORS YAPILANDIRMASI\n\n` +
    (!cors.ok
      ? '- CORS yanıtı elde edilemedi.\n\n'
      : `- **Test Origin:** \`${cors.testedOrigin}\`\n` +
        `- **Access-Control-Allow-Origin:** ${cors.acao ? `\`${cors.acao}\`` : 'gönderilmiyor (CORS kapalı — güvenli varsayılan)'}${cors.wildcard ? ' — ⚠️ wildcard (`*`)' : cors.reflected ? ' — ⚠️ Origin’i yansıtıyor' : ''}\n` +
        `- **Access-Control-Allow-Credentials:** ${cors.acac ? `\`${cors.acac}\`` : 'gönderilmiyor'}\n` +
        (credsWildcardDanger ? `- ⚠️ **TEHLİKELİ KOMBİNASYON:** Kimlik bilgisi (credentials) + açık/yansıtılan origin — başka sitelerin kullanıcı oturumuyla veri okumasına yol açabilir.\n` : '') +
        '\n');

  const cookieSection =
    `## ÇEREZ BAYRAKLARI\n\n` +
    (cookies.length === 0
      ? '- Ana sayfa yanıtında Set-Cookie gözlemlenmedi.\n\n'
      : `| Çerez | Secure | HttpOnly | SameSite | Not |\n|-------|--------|----------|----------|-----|\n` +
        cookies.map((c) => `| \`${c.name}\` | ${c.secure ? '✅' : '❌'} | ${c.httpOnly ? '✅' : '❌'} | ${c.sameSite ?? '—'} | ${cookieNote(c)} |`).join('\n') + '\n\n');

  const risks: string[] = [];
  if (credsWildcardDanger) risks.push('- **Yüksek — Tehlikeli CORS kombinasyonu:** `Allow-Credentials: true` ile açık/yansıtılan `Allow-Origin`. Kötü niyetli bir site, giriş yapmış kullanıcının oturumuyla API’nizden veri çekebilir.');
  else if (cors.wildcard) risks.push('- **Orta — CORS wildcard (`*`):** Tüm kökenlere açık. Kimlik bilgisi olmayan uç noktalar için kabul edilebilir olsa da, hassas API’lerde origin allowlist önerilir.');
  else if (cors.reflected) risks.push('- **Orta — CORS Origin yansıtması:** Gelen Origin doğrulanmadan yansıtılıyor; allowlist’e geçilmeli.');
  for (const c of insecureCookies) risks.push(`- **Orta — Çerez bayrağı eksik (\`${c.name}\`):** ${!c.secure ? 'Secure yok (HTTP üzerinden sızabilir). ' : ''}${!c.httpOnly ? 'HttpOnly yok (JavaScript/XSS ile okunabilir).' : ''}`);
  for (const c of sameSiteNone) risks.push(`- **Orta — \`${c.name}\` SameSite=None ama Secure yok:** Modern tarayıcılar reddeder; CSRF yüzeyi artar.`);
  if (!risks.length) risks.push('- CORS ve çerez yapılandırmasında belirgin bir risk öne çıkmadı.');

  const bullets: string[] = [];
  bullets.push(`- **Genel risk seviyesi: ${RISK_WORD[level]}** — ${level === 'high' ? 'kimlik bilgisiyle birlikte tehlikeli bir CORS yapılandırması tespit edildi.' : level === 'medium' ? 'CORS ve/veya çerez bayraklarında giderilmesi önerilen eksikler var.' : 'belirgin bir CORS/çerez sorunu öne çıkmadı.'}`);
  bullets.push(`- CORS: ${cors.wildcard ? 'wildcard (*)' : cors.reflected ? 'origin yansıtma' : cors.acao ? 'sınırlı' : 'kapalı'}${credsWildcardDanger ? ' + credentials ⚠️' : ''}. Çerez: ${cookies.length} adet, ${insecureCookies.length} eksik bayraklı.`);
  bullets.push('- **Önerilen ilk adım:** ' + (credsWildcardDanger ? 'CORS’u origin allowlist’e çekin; credentials ile wildcard/yansıtmayı kaldırın.' : 'Çerezlere Secure + HttpOnly + uygun SameSite ekleyin (hazır örnekler "AI Çözüm Önerileri" eklentisinde).'));

  const genel =
    level === 'high'
      ? 'Kimlik bilgisiyle (credentials) birlikte açık/yansıtılan bir CORS politikası tespit edildi; bu, çapraz-köken veri sızıntısına yol açabilir ve öncelikli giderilmelidir.'
      : level === 'medium'
        ? 'CORS ve/veya çerez bayraklarında giderilmesi önerilen eksikler var; taşıma güvenliği açısından kritik değil ancak saldırı yüzeyini artırıyor.'
        : 'CORS ve çerez yapılandırması güvenli varsayılanlara yakın; rapor yalnızca küçük iyileştirmeleri listeler.';

  const findings = assemble('CORS/Çerez', level, bullets, genel, `${corsSection}${cookieSection}## TESPİT EDİLEN RİSKLER\n\n${risks.join('\n')}\n`);
  const fixText = buildCorsCookieFix(host, { credsWildcardDanger, wildcard: cors.wildcard, reflected: cors.reflected, insecure: insecureCookies.length > 0 });
  return { findings, fixText };
}

type Cookie = { name: string; secure: boolean; httpOnly: boolean; sameSite?: string };
function parseCookie(raw: string): Cookie {
  const name = raw.split('=')[0]?.trim() || '(çerez)';
  const ss = raw.match(/;\s*samesite\s*=\s*(strict|lax|none)/i)?.[1];
  return { name, secure: /;\s*secure/i.test(raw), httpOnly: /;\s*httponly/i.test(raw), sameSite: ss ? ss[0].toUpperCase() + ss.slice(1).toLowerCase() : undefined };
}
function cookieNote(c: Cookie): string {
  const p: string[] = [];
  if (!c.secure) p.push('Secure eksik');
  if (!c.httpOnly) p.push('HttpOnly eksik');
  if (c.sameSite === 'None' && !c.secure) p.push('SameSite=None+Secure yok');
  return p.length ? p.join('; ') : 'Bayraklar uygun';
}

// ======================================================================================
// 5) csp_analiz — CSP Analizi
// ======================================================================================
export async function generateCspReport(host: string): Promise<{ findings: string; fixText: string } | null> {
  const http = await collectHttp(host);
  if (!http.ok) return null;
  const csp = http.headers.get('content-security-policy') ?? '';
  const cspRO = http.headers.get('content-security-policy-report-only') ?? '';
  const isSpa = /\/assets\/index-[\w-]+\.js|data-reactroot|id="root"/i.test(http.html);

  const present = !!csp.trim();
  const directives = present ? parseCsp(csp) : null;
  const weakFindings: string[] = [];
  if (directives) {
    if (directives.unsafeInline) weakFindings.push("`'unsafe-inline'` kullanılıyor — inline script/style’a izin verir, XSS korumasını büyük ölçüde zayıflatır.");
    if (directives.unsafeEval) weakFindings.push("`'unsafe-eval'` kullanılıyor — eval() benzeri dinamik kod yürütmeye izin verir.");
    if (directives.wildcard) weakFindings.push('Kaynak olarak wildcard (`*`) var — herhangi bir kökeni yükleyebilir, politikayı etkisizleştirir.');
    if (!directives.hasDefaultSrc) weakFindings.push('`default-src` tanımlı değil — kapsanmayan kaynak türleri için yedek politika yok.');
    if (!directives.hasFrameAncestors) weakFindings.push('`frame-ancestors` yok — clickjacking için ek koruma sağlanmıyor.');
  }

  let level: Level = 'low';
  if (!present && !cspRO) level = isSpa ? 'high' : 'medium';
  else if (present && (directives?.unsafeInline || directives?.unsafeEval || directives?.wildcard)) level = 'medium';
  else if (!present && cspRO) level = 'medium';

  const statusSection =
    `## CSP DURUMU\n\n` +
    (present
      ? `- **Durum:** Var (uygulanıyor).\n- **Politika:** \`${csp.slice(0, 400)}${csp.length > 400 ? '…' : ''}\`\n\n`
      : cspRO
        ? `- **Durum:** Yalnızca Report-Only modda (\`Content-Security-Policy-Report-Only\`) — ihlaller raporlanıyor ama ENGELLENMİYOR. Gerçek koruma için uygulanan (enforce) moda geçilmeli.\n\n`
        : `- **Durum:** Yok — Content-Security-Policy başlığı hiç gönderilmiyor.${isSpa ? ' Site JavaScript ağırlıklı bir SPA olduğundan CSP eksikliği XSS etkisini belirgin şekilde büyütür.' : ''}\n\n`);

  const analysisSection =
    `## CSP DİREKTİF ANALİZİ\n\n` +
    (present
      ? (weakFindings.length ? weakFindings.map((w) => `- ⚠️ ${w}`).join('\n') + '\n\n' : '- Politika temel zayıflatıcı direktifler (unsafe-inline/unsafe-eval/wildcard) içermiyor; sağlam görünüyor.\n\n')
      : '- Uygulanan bir CSP olmadığından direktif analizi yapılamadı.\n\n');

  const risks: string[] = [];
  if (!present && !cspRO) risks.push(`- **${isSpa ? 'Yüksek' : 'Orta'} — CSP tamamen eksik:** XSS ve içerik enjeksiyonuna karşı tarayıcı seviyesinde savunma yok.${isSpa ? ' SPA olduğu için XSS etkisi kritiktir.' : ''}`);
  if (!present && cspRO) risks.push('- **Orta — CSP yalnızca Report-Only:** İhlaller engellenmiyor; enforce moda geçilmeli.');
  if (present) for (const w of weakFindings.filter((x) => /unsafe|wildcard/.test(x))) risks.push(`- **Orta — Zayıf CSP direktifi:** ${w}`);
  if (!risks.length) risks.push('- CSP mevcut ve belirgin bir zayıflatıcı direktif içermiyor.');

  const bullets: string[] = [];
  bullets.push(`- **Genel risk seviyesi: ${RISK_WORD[level]}** — ${level === 'high' ? 'SPA’da CSP tamamen eksik; XSS etkisi büyük.' : level === 'medium' ? (present ? 'CSP var ama zayıflatıcı direktifler içeriyor.' : 'CSP eksik/enforce edilmiyor.') : 'CSP mevcut ve makul yapılandırılmış.'}`);
  bullets.push(`- CSP: ${present ? 'uygulanıyor' : cspRO ? 'yalnızca Report-Only' : 'yok'}${directives && weakFindings.length ? `, ${weakFindings.length} zayıf nokta` : ''}.`);
  bullets.push('- **Önerilen ilk adım:** ' + (present ? "unsafe-inline/unsafe-eval/wildcard direktiflerini kaldırın." : 'Önce Report-Only modda test edip ardından uygulanan CSP ekleyin (hazır örnekler "AI Çözüm Önerileri" eklentisinde).'));

  const genel =
    level === 'high'
      ? 'JavaScript ağırlıklı bir uygulamada Content-Security-Policy tamamen eksik; XSS ve içerik enjeksiyonu etkisi yüksek. Öncelikli olarak (önce Report-Only modda test ederek) eklenmesi önerilir.'
      : level === 'medium'
        ? (present ? 'CSP mevcut ancak koruma değerini düşüren direktifler (unsafe-inline/unsafe-eval/wildcard) içeriyor; sıkılaştırılması önerilir.' : 'Uygulanan bir CSP yok (yok veya yalnızca Report-Only). XSS azaltması için enforce edilen bir politika önerilir.')
        : 'Content-Security-Policy mevcut ve makul yapılandırılmış; rapor yalnızca küçük iyileştirmeleri listeler.';

  const findings = assemble('CSP', level, bullets, genel, `${statusSection}${analysisSection}## TESPİT EDİLEN RİSKLER\n\n${risks.join('\n')}\n`);
  const fixText = buildCspFix(host, { present, weak: weakFindings.length > 0 });
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
function platformHeaderBlock(entries: Array<{ name: string; value: string }>): string {
  const nginx = entries.map((e) => `add_header ${e.name} "${e.value}" always;`).join('\n');
  const json = entries.map((e) => `          { "key": "${e.name}", "value": "${e.value}" }`).join(',\n');
  const apache = entries.map((e) => `Header always set ${e.name} "${e.value}"`).join('\n');
  return (
    '**Nginx:**\n\n```nginx\n' + nginx + '\n```\n\n' +
    '**Firebase Hosting — `firebase.json`:**\n\n```json\n' +
    `{\n  "hosting": {\n    "headers": [\n      {\n        "source": "**",\n        "headers": [\n${json}\n        ]\n      }\n    ]\n  }\n}\n` + '```\n\n' +
    '**Apache — `.htaccess`:**\n\n```apache\n' + apache + '\n```'
  );
}

function buildTlsFix(host: string, o: { hstsMissing: boolean; weak: string[] }): string {
  const parts: string[] = [`Aşağıdaki öneriler ${host} için TLS/şifreleme yapılandırmasını güçlendirir.`];
  if (o.hstsMissing) {
    parts.push('### 1. HSTS başlığını ekleyin\n\nTarayıcıya siteye yalnızca HTTPS ile bağlanmasını söyler (yalnızca siteniz tamamen HTTPS ise uygulayın):\n\n' +
      platformHeaderBlock([{ name: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' }]));
  }
  if (o.weak.length) {
    parts.push(`### ${o.hstsMissing ? 2 : 1}. Eski TLS sürümlerini kapatın (${o.weak.join(', ')})\n\n` +
      '**Nginx:**\n\n```nginx\nssl_protocols TLSv1.2 TLSv1.3;\nssl_prefer_server_ciphers on;\n```\n\n' +
      '**Cloudflare:** SSL/TLS → Edge Certificates → **Minimum TLS Version = 1.2**.\n\n' +
      '**Apache:**\n\n```apache\nSSLProtocol -all +TLSv1.2 +TLSv1.3\n```');
  }
  if (parts.length === 1) parts.push('TLS yapılandırmanız güncel görünüyor. Sürekli güvence için sertifika yenilemenizi otomatik (ör. certbot/ACME) tutun ve yalnızca TLS 1.2+ kabul edin.');
  return parts.join('\n\n');
}

function buildExposedFileFix(paths: string[]): string {
  return (
    `### Açıkta kalan dosyalara erişimi engelleyin\n\n` +
    `Tespit edilen yollar: ${paths.map((p) => `\`${p}\``).join(', ')}. Sunucu seviyesinde erişimi kapatın:\n\n` +
    '**Nginx:**\n\n```nginx\nlocation ~ /\\.(git|env|ht) { deny all; return 404; }\nlocation ~* \\.(bak|old|zip|sql)$ { deny all; return 404; }\n```\n\n' +
    '**Apache — `.htaccess`:**\n\n```apache\nRedirectMatch 404 /\\.git\nRedirectMatch 404 /\\.env\n<FilesMatch "\\.(bak|old|zip|sql)$">\n  Require all denied\n</FilesMatch>\n```\n\n' +
    'Ayrıca bu dosyaların web köküne (public) hiç konmaması en sağlıklısıdır.'
  );
}

function buildDnsFix(host: string, dns: DnsEvidence): string {
  const apex = host.split('.').slice(-2).join('.');
  const parts: string[] = [`Aşağıdaki öneriler ${apex} alan adının e-posta kimlik doğrulamasını güçlendirir. Kayıtları DNS sağlayıcınızın (Cloudflare/GoDaddy/…) TXT arayüzünden ekleyin.`];
  if (!dns.spf || dns.spf.all === 'yok' || dns.spf.all === '+all' || dns.spf.all === '?all') {
    parts.push('### SPF kaydı ekleyin/sertleştirin\n\nYalnızca yetkili sunucuların sizin adınıza mail göndermesine izin verir. Kendi gönderen servislerinizi (`include:`) ekleyin:\n\n```dns\n' +
      `${apex}.  TXT  "v=spf1 include:_spf.google.com -all"\n` +
      '```\n\n`-all` (hardfail) en güvenlidir; geçiş sırasında `~all` (softfail) ile başlayabilirsiniz.');
  }
  if (!dns.dmarc || dns.dmarc.policy === 'yok' || dns.dmarc.policy === 'none') {
    parts.push('### DMARC kaydı ekleyin/sıkılaştırın\n\nÖnce `p=none` ile izleyin, raporları inceleyip yanlış-pozitif olmadığından emin olunca `quarantine` → `reject` yapın:\n\n```dns\n' +
      `_dmarc.${apex}.  TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@${apex}; fo=1"\n` +
      '```');
  }
  if (!dns.dkim?.found) {
    parts.push('### DKIM imzalamayı etkinleştirin\n\nE-posta sağlayıcınızın (Google Workspace/Microsoft 365/gönderim servisi) panelinden DKIM üretin ve verdiği TXT kaydını `seçici._domainkey` altına ekleyin:\n\n```dns\n' +
      `google._domainkey.${apex}.  TXT  "v=DKIM1; k=rsa; p=<sağlayıcının-verdiği-anahtar>"\n` +
      '```');
  }
  if (!dns.dnssec) {
    parts.push('### DNSSEC’i etkinleştirin\n\nDNS sağlayıcınızın panelinden **DNSSEC**’i açın; sağlayıcı DS kaydını üretir, bunu alan adı kayıt operatörünüze (registrar) girin. DNS yanıtlarını imzalayarak cache-poisoning’i zorlaştırır.');
  }
  if (parts.length === 1) parts.push('E-posta kimlik doğrulama kayıtlarınız (SPF/DMARC/DKIM) sağlam görünüyor. DMARC politikanızı zamanla `reject`’e çekmeyi ve raporları (rua) izlemeyi sürdürün.');
  return parts.join('\n\n');
}

function buildCorsCookieFix(host: string, o: { credsWildcardDanger: boolean; wildcard: boolean; reflected: boolean; insecure: boolean }): string {
  const parts: string[] = [`Aşağıdaki öneriler ${host} için CORS ve çerez güvenliğini güçlendirir.`];
  if (o.credsWildcardDanger || o.wildcard || o.reflected) {
    parts.push('### CORS’u origin allowlist’e çekin\n\nGelen Origin’i doğrulamadan yansıtmayın ve kimlik bilgisi (credentials) ile wildcard’ı ASLA birlikte kullanmayın. Yalnızca bilinen kökenlere izin verin:\n\n' +
      '**Nginx (örnek allowlist):**\n\n```nginx\nset $cors "";\nif ($http_origin ~* "^https://(app\\.example\\.com|www\\.example\\.com)$") { set $cors $http_origin; }\nadd_header Access-Control-Allow-Origin $cors always;\nadd_header Vary Origin always;\n# credentials gerekmiyorsa Allow-Credentials göndermeyin\n```\n\n' +
      '**Express/Node:**\n\n```js\nconst allow = new Set([\'https://app.example.com\']);\napp.use((req,res,next)=>{ const o=req.headers.origin; if(o&&allow.has(o)){ res.set(\'Access-Control-Allow-Origin\',o); res.set(\'Vary\',\'Origin\'); } next(); });\n```');
  }
  if (o.insecure) {
    parts.push('### Çerez bayraklarını tamamlayın\n\nOturum çerezlerine `Secure` (yalnız HTTPS), `HttpOnly` (JS erişimini engeller) ve uygun `SameSite` ekleyin:\n\n' +
      '```\nSet-Cookie: session=...; Secure; HttpOnly; SameSite=Lax; Path=/\n```\n\n' +
      'Çapraz-site gönderim gerekiyorsa `SameSite=None` kullanın ama mutlaka `Secure` ile birlikte.');
  }
  if (parts.length === 1) parts.push('CORS ve çerez yapılandırmanız güvenli varsayılanlara yakın. Yeni uç noktalar eklerken origin allowlist ve çerez bayrakları (Secure/HttpOnly/SameSite) prensibini koruyun.');
  return parts.join('\n\n');
}

function buildCspFix(host: string, o: { present: boolean; weak: boolean }): string {
  const parts: string[] = [`Aşağıdaki öneriler ${host} için Content-Security-Policy’yi güçlendirir. CSP’yi önce \`Content-Security-Policy-Report-Only\` başlığıyla test edip, siteyi bozmadığından emin olduktan sonra uygulanan (enforce) başlığa geçin.`];
  parts.push('### Temel (başlangıç) CSP\n\nKendi üçüncü taraf alan adlarınızı (analytics, CDN, font) `script-src`/`connect-src`/`img-src`’ye ekleyerek genişletin:\n\n' +
    platformHeaderBlock([{ name: 'Content-Security-Policy', value: "default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'self'; object-src 'none'; base-uri 'self'" }]));
  if (o.weak) {
    parts.push("### Zayıflatıcı direktifleri kaldırın\n\n`'unsafe-inline'` ve `'unsafe-eval'` XSS korumasını büyük ölçüde etkisizleştirir. Inline script’leri harici dosyalara taşıyın veya **nonce/hash** kullanın:\n\n```\nscript-src 'self' 'nonce-<rastgele-üretilen>';\n```\n\nWildcard (`*`) kaynakları yerine spesifik alan adları tanımlayın.");
  }
  parts.push('### Report-Only ile test\n\n```\nContent-Security-Policy-Report-Only: default-src \'self\'; report-uri /csp-report\n```\n\nRaporları izleyip yanlış-pozitifleri giderdikten sonra başlığı `Content-Security-Policy` olarak yayınlayın.');
  return parts.join('\n\n');
}

// ======================================================================================
// BUNDLE: Dış Yüzey & Yapılandırma — 5 alani TEK raporda birlestir (worst-case rozet)
// ======================================================================================
const BUNDLE_AREAS: Array<{ title: string; gen: (h: string) => Promise<{ findings: string; fixText: string } | null> }> = [
  { title: 'SSL/TLS Yapılandırma Denetimi', gen: generateSslTlsReport },
  { title: 'Güvenlik Başlıkları & Bilgi Sızıntısı', gen: generateHeaderLeakReport },
  { title: 'DNS & E-posta Güvenliği', gen: generateDnsEmailReport },
  { title: 'CORS & Çerez Güvenliği', gen: generateCorsCookieReport },
  { title: 'CSP (İçerik Güvenlik Politikası) Analizi', gen: generateCspReport },
];

function levelRank(l: Level): number { return l === 'high' ? 2 : l === 'medium' ? 1 : 0; }
function extractLevel(findings: string): Level | null {
  const m = findings.match(/Risk Seviyesi:\s*(Y[uü]ksek|Orta|D[uü][sş][uü]k)/i);
  if (!m) return null;
  const w = m[1].toLocaleLowerCase('tr');
  return /y[uü]ksek/.test(w) ? 'high' : /orta/.test(w) ? 'medium' : 'low';
}
function areaHeadline(findings: string): string {
  const m = findings.match(/Genel risk seviyesi:\s*[^\n—-]+[—-]\s*([^\n]+)/i);
  return m ? m[1].trim().replace(/\*\*/g, '') : '';
}
// YÖNETİCİ ÖZETİ + GENEL DEĞERLENDİRME'yi cikar, detay bolumlerini dondur (## -> ### indir).
function detailOnly(findings: string): string {
  const parts = findings.split(/(?=^## )/m); // [0]=YÖNETİCİ, [1]=GENEL, geri kalan = detay
  return parts.slice(2).join('').replace(/^## /gm, '### ').trim();
}

export async function generateBundleSurfaceReport(host: string): Promise<{ findings: string; fixText: string } | null> {
  // Her alan kendi kanitini toplar (bagimsiz, saf); paralel calistir, biri patlarsa null.
  const results = await Promise.all(BUNDLE_AREAS.map((a) => a.gen(host).catch(() => null)));
  return combineSurfaceAreas(results);
}

// 5 alan sonucunu (bazilari null olabilir) TEK rapora birlestirir. Ayri fonksiyon: sentetik
// verilerle (null-alan / worst-case) test edilebilsin diye. Hepsi null ise -> null (fallback).
export function combineSurfaceAreas(results: Array<{ findings: string; fixText: string } | null>): { findings: string; fixText: string } | null {
  if (results.every((r) => r === null)) return null; // hicbir alan veri toplayamadi -> fallback

  const levels: Array<Level | null> = results.map((r) => (r ? extractLevel(r.findings) : null));
  // WORST-CASE ALAN: en yuksek seviyeli alanin indexini bul — genel rozet + kutu/genel cumle
  // O ALANIN GERCEK bulgusuna dayanir (sabit/gelisiguzel ornek YOK). Esitlikte ilk alan (stable
  // sort). Fonksiyonel hesap: TS closure-mutasyonunu daraltamadigi icin.
  const ranked = levels
    .map((lv, i) => ({ lv, i }))
    .filter((x): x is { lv: Level; i: number } => x.lv !== null)
    .sort((a, b) => levelRank(b.lv) - levelRank(a.lv));
  const worstIdx = ranked.length ? ranked[0].i : -1;
  const worst: Level = worstIdx >= 0 ? (levels[worstIdx] as Level) : 'low';
  const worstTitle = worstIdx >= 0 ? BUNDLE_AREAS[worstIdx].title : '';
  const worstHl = worstIdx >= 0 && results[worstIdx] ? areaHeadline(results[worstIdx]!.findings) : '';

  // --- YÖNETİCİ ÖZETİ (TEK, birlesik) ---
  const summary: string[] = [];
  summary.push(
    worst === 'low'
      ? `- **Genel risk seviyesi: Düşük** — dış yüzey yapılandırmanız 5 alanda incelendi; belirgin bir sorun öne çıkmadı.`
      : `- **Genel risk seviyesi: ${RISK_WORD[worst]}** — 5 alan incelendi; en yüksek risk **${worstTitle}** alanında${worstHl ? ` (${worstHl})` : ''}.`,
  );
  BUNDLE_AREAS.forEach((a, i) => {
    const r = results[i];
    const lv = levels[i];
    if (!r || !lv) { summary.push(`- **${a.title}:** veri toplanamadı.`); return; }
    const hl = areaHeadline(r.findings);
    summary.push(`- **${a.title}:** ${RISK_WORD[lv]}${hl ? ` — ${hl}` : ''}`);
  });
  summary.push('- **Önerilen ilk adım:** En yüksek riskli alandan başlayın; her bulgu için adım adım hazır komutlar "AI Çözüm Önerileri" bölümünde sunulur.');

  // GENEL DEĞERLENDİRME cumlesi worst-case ALANA ozgu (pdf.ts bunu ust kutuda da kullanir).
  const genelSentence =
    worst === 'high'
      ? `En yüksek risk **${worstTitle}** alanında${worstHl ? ` (${worstHl})` : ''} tespit edildi; öncelikli olarak giderilmesi önerilir. Aşağıda her alan ayrı ayrı raporlanmıştır.`
      : worst === 'medium'
        ? `Öne çıkan alan **${worstTitle}**${worstHl ? ` (${worstHl})` : ''}; kısa vadede giderilmesi önerilir. Kritik/acil bir sorun öne çıkmadı. Aşağıda her alan ayrı ayrı raporlanmıştır.`
        : 'Dış yüzey yapılandırmanız genel olarak sağlam; rapor yalnızca küçük iyileştirme fırsatlarını listeler. Aşağıda her alan ayrı ayrı raporlanmıştır.';

  // --- Alan bolumleri (exec/genel cikarilmis, ## -> ### indirilmis) ---
  const areaSections = BUNDLE_AREAS.map((a, i) => {
    const r = results[i];
    if (!r) return `## ${a.title}\n\n> Bu alan için veri toplanamadı (bağlantı/sorgu başarısız); diğer alanlar tam olarak raporlanmıştır.\n`;
    return `## ${a.title}\n\n${detailOnly(r.findings)}\n`;
  }).join('\n');

  const findings =
    `## YÖNETİCİ ÖZETİ\n\n${summary.join('\n')}\n\n` +
    `## GENEL DEĞERLENDİRME\n\n**Risk Seviyesi: ${RISK_WORD[worst]}**\n\n${genelSentence}\n\n` +
    `${areaSections}`;

  // --- AI ÇÖZÜM ÖNERİLERİ (5 alan TEK bolumde, alt-basliklarla) ---
  const fixParts = BUNDLE_AREAS.map((a, i) => {
    const r = results[i];
    if (!r || !r.fixText.trim()) return '';
    return `### ${a.title}\n\n${r.fixText.trim()}`;
  }).filter(Boolean);
  const fixText =
    'Bu bölüm, dış yüzey taramanızda tespit edilen tüm eksiklikler için alan alan düzeltme önerileri içerir. Sunucunuza uygun örnekleri (Nginx/Firebase/Apache/DNS) kopyalayın.\n\n' +
    fixParts.join('\n\n');

  return { findings, fixText };
}
