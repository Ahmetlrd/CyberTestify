/**
 * (PROFESYONEL RAPOR — bulgu-başı derinlik) ORTAK EŞLEME MODÜLÜ.
 *
 * Bulgu TÜRÜ -> { İş Etkisi (business impact, iş diline çevrilmiş), CWE, OWASP }.
 * Tek kaynak: pdf.ts bunu 2.3 Detaylı Bulgular bloklarında kullanır; gelecekte generator'lar
 * da buradan çekebilir. DETERMİNİSTİK (LLM YOK). UYDURMA YOK: eşleme yoksa satır ATLANIR
 * (yanlış CWE / dolgu İş Etkisi yazılmaz). İş Etkisi/"nasıl tespit edildi" İSTİSMAR TARİFİ DEĞİL.
 */

export type FindingType =
  | 'clickjacking' | 'mime_sniffing' | 'csp_missing' | 'referrer_policy' | 'hsts_missing'
  | 'weak_tls' | 'weak_key' | 'cert' | 'version_disclosure' | 'exposed_files'
  | 'spf' | 'dmarc' | 'dkim' | 'dnssec'
  | 'cors' | 'cookie_flags'
  | 'sqli' | 'xss' | 'idor' | 'ssrf' | 'open_redirect' | 'rce' | 'file_upload'
  | 'business_logic' | 'race'
  | 'forced_browsing' | 'weak_logout' | 'session_fixation' | 'jwt' | 'privilege_escalation' | 'login_bypass'
  | 'exposed_api_docs' | 'staging_exposure' | 'stale_subdomain' | 'outdated_component' | 'subdomain_takeover';

type Entry = { tr: string; en: string; cwe: string; owasp: string };

// İş Etkisi metinleri O BULGU TÜRÜNE ÖZGÜ ve SOMUT — genel-geçer "güvenlik önemlidir" YOK.
export const FINDING_TAXONOMY: Record<FindingType, Entry> = {
  clickjacking: { cwe: 'CWE-1021', owasp: 'A05:2021 Security Misconfiguration',
    tr: 'Sayfa görünmez bir çerçeveye alınıp kullanıcılar istemeden işlem yapmaya kandırılabilir (clickjacking); hesap ve işlem güvenliğini zayıflatır.',
    en: 'The page can be framed invisibly to trick users into unintended actions (clickjacking), weakening account and transaction safety.' },
  mime_sniffing: { cwe: 'CWE-693', owasp: 'A05:2021 Security Misconfiguration',
    tr: 'Tarayıcı içerik türünü tahmin edip zararlı içeriği çalıştırabilir; XSS/enjeksiyon saldırı yüzeyini genişletir.',
    en: 'The browser may sniff content types and execute malicious content, widening the XSS/injection surface.' },
  csp_missing: { cwe: 'CWE-693', owasp: 'A05:2021 Security Misconfiguration',
    tr: 'İçerik enjeksiyonu ve XSS için tarayıcı-taraflı azaltma katmanı yok; enjekte edilen betikler çalışabilir.',
    en: 'No browser-side mitigation against content injection/XSS; injected scripts can execute.' },
  referrer_policy: { cwe: 'CWE-200', owasp: 'A05:2021 Security Misconfiguration',
    tr: 'Dış bağlantılara adres/oturum bilgisi sızabilir; düşük etkili bilgi ifşası riski.',
    en: 'Address/session info may leak to external links; low-impact information exposure.' },
  hsts_missing: { cwe: 'CWE-319', owasp: 'A05:2021 Security Misconfiguration',
    tr: 'İlk bağlantı HTTPS’e zorlanmadığından araya-girme (MITM) saldırısıyla trafik dinlenebilir/yönlendirilebilir.',
    en: 'Without forced HTTPS, traffic can be intercepted/redirected via man-in-the-middle.' },
  weak_tls: { cwe: 'CWE-326', owasp: 'A02:2021 Cryptographic Failures',
    tr: 'Zayıf şifre paketleri trafik gizliliğini ve ileri gizliliği zayıflatır; protokol-düşürme saldırılarına açar.',
    en: 'Weak cipher suites weaken confidentiality and forward secrecy, enabling downgrade attacks.' },
  weak_key: { cwe: 'CWE-326', owasp: 'A02:2021 Cryptographic Failures',
    tr: 'Anahtar boyutu uzun vadede kriptografik dayanıklılığı sınırlar (kısa vadede kabul edilebilir); yenilemede güçlendirilmeli.',
    en: 'Key size limits long-term cryptographic strength (acceptable short-term); strengthen at renewal.' },
  cert: { cwe: 'CWE-295', owasp: 'A02:2021 Cryptographic Failures',
    tr: 'Sertifika sorunları güven zincirini bozar; tarayıcı uyarıları ve araya-girme (MITM) riskini artırır.',
    en: 'Certificate issues break the trust chain, causing browser warnings and MITM risk.' },
  version_disclosure: { cwe: 'CWE-200', owasp: 'A05:2021 Security Misconfiguration',
    tr: 'Sürüm/teknoloji ifşası, saldırganın o bileşene ait bilinen açıkları doğrudan hedeflemesini kolaylaştırır.',
    en: 'Version/tech disclosure helps attackers target known vulnerabilities of that component.' },
  exposed_files: { cwe: 'CWE-538', owasp: 'A05:2021 Security Misconfiguration',
    tr: 'Kaynak kodu, yedek veya gizli anahtar gibi hassas dosyalar dışa açık; kimlik bilgisi/sistem sırrı sızıntısı riski.',
    en: 'Sensitive files (source, backups, secrets) are exposed; risk of credential/secret leakage.' },
  spf: { cwe: 'CWE-290', owasp: 'A07:2021 Identification & Authentication Failures',
    tr: 'SPF eksik/gevşek olduğundan alan adınızdan sahte e-posta (spoofing/phishing) gönderilebilir; marka itibarı ve dolandırıcılık riski.',
    en: 'Missing/loose SPF lets attackers send spoofed email from your domain; brand and fraud risk.' },
  dmarc: { cwe: 'CWE-290', owasp: 'A07:2021 Identification & Authentication Failures',
    tr: 'DMARC politikası olmadan sahte e-postalar engellenmez; phishing ve marka itibarı riski.',
    en: 'Without a DMARC policy, spoofed emails are not blocked; phishing and brand-reputation risk.' },
  dkim: { cwe: 'CWE-290', owasp: 'A07:2021 Identification & Authentication Failures',
    tr: 'DKIM imzası yoksa giden e-postaların bütünlüğü doğrulanamaz; spoofing kolaylaşır.',
    en: 'Without DKIM signing, outgoing email integrity cannot be verified; spoofing becomes easier.' },
  dnssec: { cwe: 'CWE-350', owasp: 'A05:2021 Security Misconfiguration',
    tr: 'DNSSEC yoksa DNS yanıtları taklit edilerek kullanıcılar sahte sunuculara yönlendirilebilir.',
    en: 'Without DNSSEC, DNS responses can be spoofed to redirect users to malicious servers.' },
  cors: { cwe: 'CWE-942', owasp: 'A05:2021 Security Misconfiguration',
    tr: 'Gevşek CORS politikası, başka kökenlerin oturumlu isteklerle kullanıcı verisini okumasına yol açabilir; oturum ve veri güvenliğini zayıflatır.',
    en: 'A loose CORS policy may let other origins read user data via credentialed requests, weakening session/data security.' },
  cookie_flags: { cwe: 'CWE-1004', owasp: 'A05:2021 Security Misconfiguration',
    tr: 'Çerez bayrakları (HttpOnly/Secure/SameSite) eksikse oturum çerezi XSS ile çalınabilir veya şifresiz kanaldan sızabilir; hesap ele geçirme riski.',
    en: 'Missing cookie flags (HttpOnly/Secure/SameSite) allow session theft via XSS or plaintext leakage; account takeover risk.' },
  sqli: { cwe: 'CWE-89', owasp: 'A03:2021 Injection',
    tr: 'Veritabanındaki müşteri/hesap kayıtlarına yetkisiz erişim veya değişiklik olabilir; veri sızıntısı, KVKK ihlali ve müşteri güveni kaybı riski.',
    en: 'Unauthorized access/modification of customer/account records is possible; data breach, compliance violation and loss of trust.' },
  xss: { cwe: 'CWE-79', owasp: 'A03:2021 Injection',
    tr: 'Kullanıcının tarayıcısında betik çalıştırılarak oturum çalma/kimlik taklidi ve hesap ele geçirme mümkün olabilir.',
    en: 'Running script in the victim’s browser enables session theft/impersonation and account takeover.' },
  idor: { cwe: 'CWE-639', owasp: 'A01:2021 Broken Access Control',
    tr: 'Kimlik parametresi değiştirilerek başka kullanıcıların kayıtlarına erişilebilir; toplu veri sızıntısı ve KVKK ihlali riski.',
    en: 'Manipulating an ID parameter can access other users’ records; mass data exposure and compliance risk.' },
  ssrf: { cwe: 'CWE-918', owasp: 'A10:2021 Server-Side Request Forgery',
    tr: 'Sunucu, iç ağdaki servislere veya bulut metadata uçlarına istek yapmaya zorlanabilir; iç sistem ifşası ve yanal hareket riski.',
    en: 'The server can be coerced into requesting internal services or cloud metadata; internal exposure and lateral-movement risk.' },
  open_redirect: { cwe: 'CWE-601', owasp: 'A01:2021 Broken Access Control',
    tr: 'Güvenilir alan adınız üzerinden kullanıcılar zararlı sitelere yönlendirilebilir; phishing ve itibar riski.',
    en: 'Users can be redirected to malicious sites via your trusted domain; phishing and reputation risk.' },
  rce: { cwe: 'CWE-94', owasp: 'A03:2021 Injection',
    tr: 'Sunucuda komut/kod çalıştırma göstergesi — en yüksek etki: tam sistem ele geçirme ve veri kaybı riski.',
    en: 'Indicator of command/code execution on the server — highest impact: full system compromise and data loss risk.' },
  file_upload: { cwe: 'CWE-434', owasp: 'A05:2021 Security Misconfiguration',
    tr: 'Kısıtsız dosya yükleme ile zararlı dosya sunucuya yerleştirilip çalıştırılabilir; sistem ele geçirme riski.',
    en: 'Unrestricted upload can place and execute a malicious file on the server; system compromise risk.' },
  business_logic: { cwe: 'CWE-840', owasp: 'A04:2021 Insecure Design',
    tr: 'İş mantığı manipülasyonu (ör. negatif miktar, çift indirim) finansal kayba ve muhasebe tutarsızlığına yol açabilir.',
    en: 'Business-logic manipulation (e.g., negative quantity, double discount) can cause financial loss and accounting inconsistency.' },
  race: { cwe: 'CWE-362', owasp: 'A04:2021 Insecure Design',
    tr: 'Yarış durumu ile tek-kullanımlık işlemler (kupon/kredi) çift işlenebilir; doğrudan finansal kayıp riski.',
    en: 'A race condition can double-process single-use operations (coupons/credits); direct financial loss risk.' },
  forced_browsing: { cwe: 'CWE-284', owasp: 'A01:2021 Broken Access Control',
    tr: 'Yetkisiz kullanıcı yönetim/gizli uç noktalara erişebilir; yetkisiz veri görüntüleme/değiştirme ve iç suistimal riski.',
    en: 'An unauthorized user can reach admin/hidden endpoints; unauthorized data view/modify and insider-abuse risk.' },
  weak_logout: { cwe: 'CWE-613', owasp: 'A07:2021 Identification & Authentication Failures',
    tr: 'Çıkıştan sonra oturum geçerli kaldığından çalınan/paylaşılan bir oturum yeniden kullanılabilir; ortak cihazlarda hesap ele geçirme riski.',
    en: 'If the session stays valid after logout, a stolen/shared session can be reused; account takeover on shared devices.' },
  session_fixation: { cwe: 'CWE-384', owasp: 'A07:2021 Identification & Authentication Failures',
    tr: 'Saldırgan oturum kimliğini sabitleyip kurbanın oturumunu ele geçirebilir.',
    en: 'An attacker can fixate the session ID and hijack the victim’s session.' },
  jwt: { cwe: 'CWE-347', owasp: 'A02:2021 Cryptographic Failures',
    tr: 'Zayıf/imzasız (alg=none) JWT ile yetki yükseltme veya kimlik taklidi mümkün olabilir.',
    en: 'Weak/unsigned (alg=none) JWT may enable privilege escalation or impersonation.' },
  privilege_escalation: { cwe: 'CWE-269', owasp: 'A01:2021 Broken Access Control',
    tr: 'Standart kullanıcı yetkilerini aşarak ayrıcalıklı işlemler yapabilir; iç suistimal ve veri güvenliği riski.',
    en: 'A standard user can exceed privileges to perform privileged actions; insider-abuse and data risk.' },
  login_bypass: { cwe: 'CWE-287', owasp: 'A07:2021 Identification & Authentication Failures',
    tr: 'Kimlik doğrulama atlatılarak yetkisiz erişim mümkün olabilir; hesap ve veri güvenliği doğrudan tehlikede.',
    en: 'Authentication bypass may allow unauthorized access; account and data security directly at risk.' },
  exposed_api_docs: { cwe: 'CWE-200', owasp: 'A05:2021 Security Misconfiguration',
    tr: 'Açık API dokümantasyonu saldırı yüzeyini ve uç nokta şemasını ifşa eder; hedefli saldırıları kolaylaştırır.',
    en: 'Exposed API docs reveal the attack surface and endpoint schema, easing targeted attacks.' },
  staging_exposure: { cwe: 'CWE-668', owasp: 'A05:2021 Security Misconfiguration',
    tr: 'İnternete açık hazırlık/eski ortam üretim kadar korunmadığından veri sızıntısı ve saldırı sıçrama noktası olabilir.',
    en: 'An internet-exposed staging/old environment is less protected, risking data leakage and a foothold.' },
  stale_subdomain: { cwe: 'CWE-1104', owasp: 'A06:2021 Vulnerable & Outdated Components',
    tr: 'Bakım-dışı/unutulmuş varlık yama almadığından bilinen açıklara maruz kalabilir.',
    en: 'An unmaintained/forgotten asset may be exposed to known vulnerabilities due to missing patches.' },
  outdated_component: { cwe: 'CWE-1104', owasp: 'A06:2021 Vulnerable & Outdated Components',
    tr: 'Güncel olmayan bileşen bilinen CVE’lerle istismara açıktır; hedefli saldırı riski.',
    en: 'An outdated component is exposed to known CVEs; targeted-attack risk.' },
  subdomain_takeover: { cwe: 'CWE-284', owasp: 'A05:2021 Security Misconfiguration',
    tr: 'Sahipsiz/dangling kaynağa işaret eden alt alan adı saldırganca devralınabilir; phishing ve itibar riski.',
    en: 'A subdomain pointing to a dangling resource can be taken over by an attacker; phishing and reputation risk.' },
};

// Başlıktan bulgu türü sınıflandırıcı — SPESİFİK önce (ör. authenticated SQLi -> sqli; forced browsing).
const CLASSIFIERS: Array<{ re: RegExp; type: FindingType }> = [
  { re: /forced.?browsing|zorla gezinme|admin u[çc]|fonksiyon seviyesi|y[öo]netici u[çc]/i, type: 'forced_browsing' },
  { re: /privilege|yetki y[üu]kseltme|dikey yetki/i, type: 'privilege_escalation' },
  { re: /login.?bypass|kimlik do[ğg]rulama (atlat|baypas)|giri[şs] baypas|baypas g[öo]sterge/i, type: 'login_bypass' },
  { re: /logout|[çc]ık[ıi][şs].*oturum|oturum ge[çc]ersiz/i, type: 'weak_logout' },
  { re: /session.?fixation|oturum sabit/i, type: 'session_fixation' },
  { re: /\bjwt\b|token b[üu]t[üu]nl[üu]k|alg\s*=\s*none/i, type: 'jwt' },
  { re: /sql|sqli/i, type: 'sqli' },
  { re: /\bxss\b|cross.?site scripting|yans[ıi]yan/i, type: 'xss' },
  { re: /\bidor\b|yetkisiz nesne|nesne eri[şs]im|do[ğg]rudan nesne/i, type: 'idor' },
  { re: /\bssrf\b|sunucu.?tarafl[ıi] istek/i, type: 'ssrf' },
  { re: /a[çc][ıi]k y[öo]nlendirme|open.?redirect/i, type: 'open_redirect' },
  { re: /\brce\b|uzaktan kod|komut [çc]al[ıi][şs]t[ıi]r/i, type: 'rce' },
  { re: /dosya y[üu]kleme|file.?upload/i, type: 'file_upload' },
  { re: /yar[ıi][şs]|race.?condition/i, type: 'race' },
  { re: /i[şs] mant[ıi][ğg]|business.?logic|negatif|kupon|indirim/i, type: 'business_logic' },
  { re: /cors/i, type: 'cors' },
  { re: /[çc]erez|cookie|httponly|samesite|secure bayrak/i, type: 'cookie_flags' },
  { re: /x-frame-options|clickjacking|[çc]er[çc]eve/i, type: 'clickjacking' },
  { re: /x-content-type-options|mime/i, type: 'mime_sniffing' },
  { re: /content-security-policy|\bcsp\b/i, type: 'csp_missing' },
  { re: /referrer-policy/i, type: 'referrer_policy' },
  { re: /hsts|strict-transport/i, type: 'hsts_missing' },
  { re: /swagger|openapi|api dok[üu]|a[çc][ıi]k.*api/i, type: 'exposed_api_docs' },
  { re: /staging|hazırlık ortam|test ortam/i, type: 'staging_exposure' },
  { re: /takeover|devral|dangling/i, type: 'subdomain_takeover' },
  { re: /bak[ıi]m.?d[ıi][şs][ıi]|eski.*alt alan|unutulmu[şs]|\bold\b.*alt/i, type: 'stale_subdomain' },
  { re: /cms|wordpress|eklenti|\bcve\b|s[üu]r[üu]m.*eski|outdated|g[üu]ncel olmayan/i, type: 'outdated_component' },
  { re: /hassas dosya|a[çc][ıi]kta.*dosya|\.git|\.env|exposed file/i, type: 'exposed_files' },
  { re: /\bspf\b/i, type: 'spf' },
  { re: /\bdmarc\b/i, type: 'dmarc' },
  { re: /\bdkim\b/i, type: 'dkim' },
  { re: /\bdnssec\b/i, type: 'dnssec' },
  { re: /zay[ıi]f.*cipher|cipher.*zay[ıi]f|weak.*tls|weak.*cipher|zay[ıi]f.*tls|3des|\brc4\b/i, type: 'weak_tls' },
  { re: /rsa.*(1024|2048)|anahtar boyut|key size/i, type: 'weak_key' },
  { re: /sertifika|certificate|hostname e[şs]le|son kullanma|expir/i, type: 'cert' },
  { re: /s[üu]r[üu]m if[şs]a|version disclosure|server.*banner|server_tokens|banner/i, type: 'version_disclosure' },
];

export function classifyFinding(title: string): FindingType | null {
  // Türkçe "İ" problemi: JS'te /i flag'i "İ"yi "i"ye eşlemez -> önce tr-locale ile küçült.
  const t = title.toLocaleLowerCase('tr');
  for (const c of CLASSIFIERS) if (c.re.test(t)) return c.type;
  return null;
}

// Master tablo / bulgu başlığı için MÜŞTERİ-DOSTU, jargonsuz ad (PentAGI/iç-jargon YOK; payload/
// teknik detay master'da DEĞİL, 2.3 Detaylı Bulgular'da kalır).
const FRIENDLY_LABEL: Record<FindingType, { tr: string; en: string }> = {
  clickjacking: { tr: 'X-Frame-Options eksik (clickjacking)', en: 'Missing X-Frame-Options (clickjacking)' },
  mime_sniffing: { tr: 'X-Content-Type-Options eksik (MIME-sniffing)', en: 'Missing X-Content-Type-Options' },
  csp_missing: { tr: 'Content-Security-Policy eksik', en: 'Missing Content-Security-Policy' },
  referrer_policy: { tr: 'Referrer-Policy eksik', en: 'Missing Referrer-Policy' },
  hsts_missing: { tr: 'HSTS (Strict-Transport-Security) eksik', en: 'Missing HSTS' },
  weak_tls: { tr: 'Zayıf TLS şifre yapılandırması', en: 'Weak TLS cipher configuration' },
  weak_key: { tr: 'Zayıf sertifika anahtar boyutu', en: 'Weak certificate key size' },
  cert: { tr: 'Sertifika yapılandırma sorunu', en: 'Certificate configuration issue' },
  version_disclosure: { tr: 'Sürüm/teknoloji ifşası', en: 'Version/technology disclosure' },
  exposed_files: { tr: 'Açıkta hassas dosya', en: 'Exposed sensitive file' },
  spf: { tr: 'SPF kaydı eksik/zayıf', en: 'Missing/weak SPF record' },
  dmarc: { tr: 'DMARC kaydı eksik', en: 'Missing DMARC record' },
  dkim: { tr: 'DKIM imzası eksik', en: 'Missing DKIM signing' },
  dnssec: { tr: 'DNSSEC pasif', en: 'DNSSEC not enabled' },
  cors: { tr: 'Gevşek CORS yapılandırması', en: 'Loose CORS configuration' },
  cookie_flags: { tr: 'Eksik çerez güvenlik bayrakları', en: 'Missing cookie security flags' },
  sqli: { tr: 'SQL Enjeksiyon göstergesi', en: 'SQL Injection indicator' },
  xss: { tr: 'Yansıyan XSS göstergesi', en: 'Reflected XSS indicator' },
  idor: { tr: 'Yetkisiz nesne erişimi (IDOR) göstergesi', en: 'IDOR indicator' },
  ssrf: { tr: 'SSRF göstergesi', en: 'SSRF indicator' },
  open_redirect: { tr: 'Açık yönlendirme (open redirect)', en: 'Open redirect' },
  rce: { tr: 'Komut/kod çalıştırma göstergesi', en: 'Command/code execution indicator' },
  file_upload: { tr: 'Kısıtsız dosya yükleme göstergesi', en: 'Unrestricted file upload indicator' },
  business_logic: { tr: 'İş mantığı / yetki göstergesi (ileri analiz)', en: 'Business-logic / authorization indicator (advanced analysis)' },
  race: { tr: 'Yarış durumu (race condition) göstergesi', en: 'Race condition indicator' },
  forced_browsing: { tr: 'Yetkisiz uç nokta erişimi (forced browsing)', en: 'Unauthorized endpoint access (forced browsing)' },
  weak_logout: { tr: 'Oturum geçersizleştirme zayıflığı', en: 'Weak session invalidation' },
  session_fixation: { tr: 'Oturum sabitleme (session fixation)', en: 'Session fixation' },
  jwt: { tr: 'JWT/Token güvenlik göstergesi', en: 'JWT/Token security indicator' },
  privilege_escalation: { tr: 'Yetki yükseltme göstergesi', en: 'Privilege escalation indicator' },
  login_bypass: { tr: 'Kimlik doğrulama baypas göstergesi', en: 'Authentication bypass indicator' },
  exposed_api_docs: { tr: 'Açık API dokümantasyonu', en: 'Exposed API documentation' },
  staging_exposure: { tr: 'İnternete açık hazırlık ortamı', en: 'Internet-exposed staging environment' },
  stale_subdomain: { tr: 'Bakım-dışı alt alan adı', en: 'Stale subdomain' },
  outdated_component: { tr: 'Güncel olmayan bileşen (CVE)', en: 'Outdated component (CVE)' },
  subdomain_takeover: { tr: 'Alt alan adı devralma riski', en: 'Subdomain takeover risk' },
};
export function friendlyLabel(type: FindingType, locale: 'tr' | 'en'): string {
  return locale === 'tr' ? FRIENDLY_LABEL[type].tr : FRIENDLY_LABEL[type].en;
}

// Başlık -> { İş Etkisi, CWE, OWASP } (locale). Eşleme yoksa null (UYDURMA YOK).
export function lookupByType(type: FindingType, locale: 'tr' | 'en'): { impact: string; cwe: string; owasp: string; type: FindingType; label: string } {
  const e = FINDING_TAXONOMY[type];
  return { impact: locale === 'tr' ? e.tr : e.en, cwe: e.cwe, owasp: e.owasp, type, label: friendlyLabel(type, locale) };
}
export function lookupFinding(title: string, locale: 'tr' | 'en'): { impact: string; cwe: string; owasp: string; type: FindingType; label: string } | null {
  const type = classifyFinding(title);
  if (!type) return null;
  return lookupByType(type, locale);
}
