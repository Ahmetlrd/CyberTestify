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
  | 'https_missing'
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
  https_missing: { cwe: 'CWE-319', owasp: 'A02:2021 Cryptographic Failures',
    tr: 'Site HTTPS üzerinden yanıt vermiyor; sayfaya gelen/giden tüm trafik ŞİFRESİZ (düz metin) taşınıyor. Aynı ağdaki bir saldırgan trafiği dinleyebilir, oturum/şifre çalabilir veya içeriği değiştirebilir; modern tarayıcılar sayfayı "Güvenli değil" olarak işaretler.',
    en: 'The site does not respond over HTTPS; all traffic is transmitted in CLEARTEXT. An attacker on the same network can eavesdrop, steal sessions/passwords, or tamper with content; modern browsers flag the page as "Not secure".' },
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
    // (BAĞLAM-NÖTR) Hedef türü bilinmediğinden e-ticarete özgü örnek (negatif miktar/indirim) yerine
    // genel iş-akışı/yetki dili; maddi kayıp yalnız finansal akış VARSA koşullu belirtilir.
    tr: 'İş akışı/yetki manipülasyonu (ör. adım atlama, istemci-tarafı değer değişikliği, yetkisiz işlem) iş sürecine veya veri bütünlüğüne zarar verebilir; finansal/işlemsel bir akış varsa maddi kayba yol açabilir.',
    en: 'Workflow/authorization manipulation (e.g., step-skipping, client-side value tampering, unauthorized action) can harm the business process or data integrity; where a financial/transactional flow exists, it may cause monetary loss.' },
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
  // (HALÜSİNASYON GUARD) Açıkta dosya/kaynak (db.sql, dump.sql, .git, .env...) PASİF bir sızıntıdır;
  // aktif-istismar imalı 'sqli/rce' kategorilerinden ÖNCE eşleşmeli. Yoksa dosya yolundaki "sql"
  // kelimesi sqli'ye düşer ("SQL Enjeksiyon göstergesi" halüsinasyonu). CWE-538/200 ailesi.
  { re: /hassas dosya|a[çc][ıi]kta.*dosya|eri[şs]ilebilir.*dosya|exposed file|\.git\b|\.env\b|\.sql\b|\.bak\b|\.old\b|\.zip\b|\bdump\b|\byedek\b|backup/i, type: 'exposed_files' },
  // sqli SADECE gerçek enjeksiyon dili ile (aktif prob) — bare "sql" (dosya adı, mysql/postgresql,
  // "db.sql") ASLA eşleşmesin. Aktif Doğrulama'nın "SQLi" (Tür kolonu) bulguları \bsqli\b ile geçer.
  { re: /\bsqli\b|sql\s*enjeksiyon|sql\s*injection|sorguya\s*s[ıi]z|veritaban[ıi].*sorgu.*s[ıi]z/i, type: 'sqli' },
  // "X-XSS-Protection" bir GÜVENLİK BAŞLIĞI adıdır, XSS zafiyeti DEĞİL -> xss'e eşleşmesin
  // (negatif lookahead: xss'ten hemen sonra "-protection" gelirse eşleşme). "yansıyan XSS" eşleşir.
  { re: /\bxss\b(?!\s*[-–]?\s*protection)|cross.?site scripting|yans[ıi]yan/i, type: 'xss' },
  // NOT: "IDOR" tr-locale'de "ıdor" (noktasız ı) olur -> \b[iı]dor. "Yetkisiz erişim" (IDOR bölüm
  // adı) + "numaralandırılabilir" (IDOR gözlem dili) de eşleşmeli; aksi halde /Comments.aspx?id=0
  // gibi bulgular sınıflanamayıp ÇIPLAK URL başlık + detay kartı EKSİK kalıyordu.
  { re: /\b[iı]dor\b|yetkisiz (nesne|eri[şs]im)|nesne eri[şs]im|numaraland[ıi]r[ıi]labilir|do[ğg]rudan nesne/i, type: 'idor' },
  { re: /\bssrf\b|sunucu.?tarafl[ıi] istek/i, type: 'ssrf' },
  { re: /a[çc][ıi]k y[öo]nlendirme|open.?redirect/i, type: 'open_redirect' },
  { re: /\brce\b|uzaktan kod|komut [çc]al[ıi][şs]t[ıi]r/i, type: 'rce' },
  { re: /dosya y[üu]kleme|file.?upload/i, type: 'file_upload' },
  { re: /yar[ıi][şs]|race[- ]?condition|\brace\b|mass.?assign|over.?post/i, type: 'race' },
  { re: /i[şs] mant[ıi][ğg]|business.?logic|negatif|kupon|indirim/i, type: 'business_logic' },
  { re: /cors/i, type: 'cors' },
  { re: /[çc]erez|cookie|httponly|samesite|secure bayrak/i, type: 'cookie_flags' },
  { re: /x-frame-options|clickjacking|[çc]er[çc]eve/i, type: 'clickjacking' },
  { re: /x-content-type-options|mime/i, type: 'mime_sniffing' },
  { re: /content-security-policy|\bcsp\b/i, type: 'csp_missing' },
  { re: /referrer-policy/i, type: 'referrer_policy' },
  // https_missing hsts'ten ÖNCE: "HTTPS yok/desteklenmiyor/şifresiz/düz metin/http üzerinden".
  { re: /https\s*(deste[ğg]i\s*)?(yok|eksik|desteklenm|zorlan|kurul)|[şs]ifresiz|d[üu]z\s*metin|cleartext|clear.?text|http\s*[- ]?only|yaln[ıi]z.*http\b/i, type: 'https_missing' },
  { re: /hsts|strict-transport/i, type: 'hsts_missing' },
  { re: /swagger|openapi|api dok[üu]|a[çc][ıi]k.*api/i, type: 'exposed_api_docs' },
  { re: /staging|hazırlık ortam|test ortam/i, type: 'staging_exposure' },
  { re: /takeover|devral|dangling/i, type: 'subdomain_takeover' },
  { re: /bak[ıi]m.?d[ıi][şs][ıi]|eski.*alt alan|unutulmu[şs]|\bold\b.*alt/i, type: 'stale_subdomain' },
  { re: /cms|wordpress|eklenti|\bcve\b|s[üu]r[üu]m.*eski|outdated|g[üu]ncel olmayan|eol\b|desteksiz|desteklenmeyen/i, type: 'outdated_component' },
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
  https_missing: { tr: 'HTTPS desteklenmiyor (şifresiz iletişim)', en: 'HTTPS not supported (cleartext transmission)' },
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
  race: { tr: 'Race / Mass-Assignment göstergesi', en: 'Race / Mass-Assignment indicator' },
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

// Bulgu kartı derinliği: her tür için Açıklama (ne/nerede), Nasıl Tespit Edildi (ZARARSIZ gösterge
// probu + gözlem — İSTİSMAR TARİFİ DEĞİL) ve Çözüm (somut, o türe özgü). "howDetected" gerçek Kanıt
// bulunmadığında yedek olarak kullanılır (pdf.ts önce gerçek kanıtı yazar). TÜM 36 tür DOLU (TODO yok).
type Detail = { desc: string; how: string; fix: string };
const D = (tr: Detail, en: Detail) => ({ tr, en });
const FINDING_DETAIL: Record<FindingType, { tr: Detail; en: Detail }> = {
  clickjacking: D(
    { desc: 'Sayfa, X-Frame-Options / CSP frame-ancestors olmadığından başka bir sitenin iframe’ine gömülebilir.', how: 'Yanıt başlıkları incelendi; X-Frame-Options ve CSP frame-ancestors gözlenmedi.', fix: '`X-Frame-Options: SAMEORIGIN` ekleyin veya CSP’ye `frame-ancestors \'self\'` koyun.' },
    { desc: 'The page can be framed by other sites (no X-Frame-Options / CSP frame-ancestors).', how: 'Response headers inspected; no X-Frame-Options or CSP frame-ancestors observed.', fix: 'Add `X-Frame-Options: SAMEORIGIN` or CSP `frame-ancestors \'self\'`.' }),
  mime_sniffing: D(
    { desc: 'X-Content-Type-Options yok; tarayıcı içerik türünü tahmin edebilir (MIME-sniffing).', how: 'Yanıt başlıklarında `nosniff` gözlenmedi.', fix: '`X-Content-Type-Options: nosniff` başlığını ekleyin.' },
    { desc: 'No X-Content-Type-Options; browser may MIME-sniff.', how: 'No `nosniff` observed in headers.', fix: 'Add `X-Content-Type-Options: nosniff`.' }),
  csp_missing: D(
    { desc: 'Content-Security-Policy gönderilmiyor; tarayıcı-taraflı XSS azaltma katmanı yok.', how: 'Yanıt başlıklarında Content-Security-Policy gözlenmedi.', fix: 'Sıkı bir CSP tanımlayın (`default-src \'self\'`); üçüncü taraf kaynakları allowlist’leyin.' },
    { desc: 'No Content-Security-Policy; no browser-side XSS mitigation.', how: 'No CSP header observed.', fix: 'Define a strict CSP (`default-src \'self\'`) and allowlist third-party sources.' }),
  referrer_policy: D(
    { desc: 'Referrer-Policy yok; dış bağlantılara tam adres sızabilir.', how: 'Yanıt başlıklarında Referrer-Policy gözlenmedi.', fix: '`Referrer-Policy: strict-origin-when-cross-origin` ekleyin.' },
    { desc: 'No Referrer-Policy; full URL may leak to external links.', how: 'No Referrer-Policy observed.', fix: 'Add `Referrer-Policy: strict-origin-when-cross-origin`.' }),
  hsts_missing: D(
    { desc: 'HSTS (Strict-Transport-Security) yok; tarayıcı HTTPS’e zorlanmıyor.', how: 'Yanıt başlıklarında Strict-Transport-Security gözlenmedi.', fix: '`Strict-Transport-Security: max-age=31536000; includeSubDomains` ekleyin (site tamamen HTTPS ise).' },
    { desc: 'No HSTS; browser not forced to HTTPS.', how: 'No Strict-Transport-Security observed.', fix: 'Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` (if fully HTTPS).' }),
  https_missing: D(
    { desc: 'Site HTTPS üzerinden yanıt vermiyor; iletişim şifresiz (düz metin) HTTP ile yürüyor.', how: 'Hedefin 443 (HTTPS) portuna güvenli bağlantı kurulamadı; yalnızca 80 (HTTP) yanıt verdi. Tarama http:// üzerinden yürütüldü.', fix: 'Geçerli bir TLS sertifikası kurun (ücretsiz: Let’s Encrypt), tüm HTTP isteklerini kalıcı olarak (301) HTTPS’e yönlendirin ve HSTS başlığını ekleyin.' },
    { desc: 'The site does not respond over HTTPS; communication runs over cleartext HTTP.', how: 'No secure connection could be established to port 443 (HTTPS); only port 80 (HTTP) responded. The scan was performed over http://.', fix: 'Install a valid TLS certificate (free: Let’s Encrypt), permanently redirect (301) all HTTP to HTTPS, and add the HSTS header.' }),
  weak_tls: D(
    { desc: 'Sunucu zayıf/eski TLS şifre paketlerini kabul ediyor.', how: 'TLS el sıkışması incelendi; zayıf cipher/eski protokol desteği gözlendi.', fix: 'Yalnız TLS 1.2+ ve ileri-gizlilikli AEAD (ECDHE+AES-GCM/ChaCha20) bırakın; CBC/3DES/RSA-kex kapatın.' },
    { desc: 'Server accepts weak/legacy TLS ciphers.', how: 'TLS handshake inspected; weak cipher/legacy protocol observed.', fix: 'Allow only TLS 1.2+ forward-secret AEAD suites; disable CBC/3DES/RSA-kex.' }),
  weak_key: D(
    { desc: 'Sertifika anahtar boyutu uzun-vade için sınırlı.', how: 'Sertifika incelendi; anahtar boyutu kaydedildi.', fix: 'Yenilemede en az 2048-bit RSA veya ECDSA P-256 kullanın.' },
    { desc: 'Certificate key size is limited for the long term.', how: 'Certificate inspected; key size recorded.', fix: 'Use ≥2048-bit RSA or ECDSA P-256 at renewal.' }),
  cert: D(
    { desc: 'TLS sertifikasında yapılandırma sorunu (süre/hostname/zincir).', how: 'Sertifika geçerlilik, hostname eşleşmesi ve zincir gözlendi.', fix: 'Geçerli, hostname’i kapsayan, tam zincirli sertifika kullanın; otomatik yenileme (ACME) kurun.' },
    { desc: 'Certificate configuration issue (validity/hostname/chain).', how: 'Validity, hostname match and chain observed.', fix: 'Use a valid, hostname-covering, full-chain certificate; automate renewal (ACME).' }),
  version_disclosure: D(
    { desc: 'Sunucu/teknoloji sürümü başlık veya sayfada ifşa oluyor.', how: 'Server / X-Powered-By başlıkları ve sayfa imzaları incelendi.', fix: 'Sürüm başlıklarını gizleyin (`server_tokens off`, X-Powered-By kaldır).' },
    { desc: 'Server/tech version disclosed via header or page.', how: 'Server / X-Powered-By headers and page signatures inspected.', fix: 'Hide version headers (`server_tokens off`, remove X-Powered-By).' }),
  exposed_files: D(
    { desc: 'Hassas dosya (.git/.env/yedek) dışarıya açık.', how: 'Yaygın hassas yollar tek GET ile denendi; içerik ana sayfadan farklı/gerçek dosya gözlendi.', fix: 'Bu yolları engelleyin; kaynak/yedek/sır dosyalarını web-kökünden çıkarın.' },
    { desc: 'Sensitive file (.git/.env/backup) exposed.', how: 'Common sensitive paths probed with a single GET; a real file distinct from the homepage was observed.', fix: 'Block these paths; move source/backup/secret files out of web root.' }),
  spf: D(
    { desc: 'SPF kaydı eksik veya gevşek (~all/?all).', how: 'Alan adının TXT/SPF kaydı sorgulandı.', fix: '`v=spf1 … -all` ile sıkı bir SPF yayınlayın.' },
    { desc: 'SPF record missing or lax (~all/?all).', how: 'Domain TXT/SPF record queried.', fix: 'Publish a strict SPF with `-all`.' }),
  dmarc: D(
    { desc: 'DMARC kaydı yok; SPF/DKIM uygulanmıyor.', how: '`_dmarc` TXT kaydı sorgulandı; bulunamadı.', fix: '`_dmarc` altına `v=DMARC1; p=quarantine` (izlemeyle başlayıp reject’e yükseltin).' },
    { desc: 'No DMARC; SPF/DKIM not enforced.', how: '`_dmarc` TXT record queried; not found.', fix: 'Publish `_dmarc` `v=DMARC1; p=quarantine` (start monitoring, then reject).' }),
  dkim: D(
    { desc: 'Yaygın seçicilerde DKIM imzası bulunamadı.', how: 'Yaygın DKIM seçicileri (default/google/selector1…) sorgulandı.', fix: 'Sağlayıcınızda DKIM üretip `seçici._domainkey` TXT kaydını ekleyin.' },
    { desc: 'No DKIM found on common selectors.', how: 'Common DKIM selectors queried.', fix: 'Generate DKIM at your provider and add the `selector._domainkey` TXT record.' }),
  dnssec: D(
    { desc: 'DNSSEC pasif; DNS yanıtları imzalı değil.', how: 'Alan adının DNSSEC/DS durumu sorgulandı.', fix: 'DNS sağlayıcınızda DNSSEC’i açıp DS kaydını registrar’a girin.' },
    { desc: 'DNSSEC not enabled; DNS responses unsigned.', how: 'Domain DNSSEC/DS status queried.', fix: 'Enable DNSSEC and add the DS record at your registrar.' }),
  cors: D(
    { desc: 'CORS politikası gevşek; başka kökenlere oturumlu erişim açabilir.', how: 'Bir test Origin’iyle istek gönderildi; Access-Control-Allow-Origin/Credentials yanıtı gözlendi.', fix: 'Origin’i allowlist’leyin; kimlik bilgili isteklerde wildcard kullanmayın.' },
    { desc: 'Loose CORS may allow credentialed cross-origin access.', how: 'Request sent with a test Origin; Access-Control-Allow-Origin/Credentials observed.', fix: 'Allowlist origins; never use wildcard with credentials.' }),
  cookie_flags: D(
    { desc: 'Oturum çerezinde Secure/HttpOnly/SameSite bayrakları eksik.', how: 'Set-Cookie başlıkları toplanıp bayrakları incelendi.', fix: 'Oturum çerezlerine `HttpOnly; Secure; SameSite=Lax/Strict` ekleyin.' },
    { desc: 'Session cookie missing Secure/HttpOnly/SameSite flags.', how: 'Set-Cookie headers collected and flags inspected.', fix: 'Add `HttpOnly; Secure; SameSite` to session cookies.' }),
  sqli: D(
    { desc: 'Bir giriş noktası, girdiyi veritabanı sorgusuna süzebiliyor (enjeksiyon göstergesi).', how: 'Giriş noktasına tek bir zararsız işaret (tek tırnak / zaman-tabanlı sonda) gönderildi; yanıtta veritabanı hata imzası veya süre sapması gözlendi. Veri çekme/istismar YAPILMADI.', fix: 'Tüm sorguları parametreli sorgu / hazırlanmış ifade ile yazın; veritabanı hata mesajlarını son kullanıcıya göstermeyin.' },
    { desc: 'An input reaches a DB query (injection indicator).', how: 'A single harmless marker (single quote / time-based probe) was sent; a DB error signature or timing deviation was observed. No data extracted/exploited.', fix: 'Use parameterized queries/prepared statements; hide DB error messages.' }),
  xss: D(
    { desc: 'Kullanıcı girdisi yanıt HTML’ine kodlanmadan yansıyor (yansıyan XSS göstergesi).', how: 'Benzersiz, zararsız bir işaret dizesi enjekte edildi; yanıtta kaçırılmadan yansıdığı gözlendi (JS çalıştırılmadı).', fix: 'Çıktıyı bağlama uygun kodlayın (HTML entity encoding); CSP ile satır-içi script’i kısıtlayın.' },
    { desc: 'User input reflects unencoded in HTML (reflected XSS indicator).', how: 'A unique harmless marker was injected and observed reflected unescaped (no JS executed).', fix: 'Context-encode output (HTML entity encoding); restrict inline script via CSP.' }),
  idor: D(
    { desc: 'Kimlik parametresi değiştirilerek başka bir kaydın erişilebildiğine dair sinyal.', how: 'ID değeri komşu bir değere değiştirilip istek gönderildi; farklı/geçerli kaynak dönüşü gözlendi (içerik saklanmadı).', fix: 'Her erişimde nesne-düzeyi yetki kontrolü uygulayın; tahmin edilebilir ID yerine UUID kullanın.' },
    { desc: 'Signal that changing an ID reaches another record.', how: 'ID changed to a neighbor and requested; a different/valid resource was observed (content not stored).', fix: 'Enforce object-level authorization; use UUIDs instead of predictable IDs.' }),
  ssrf: D(
    { desc: 'Sunucu-taraflı fetch parametresi iç kaynaklara istek yaptırabilir (gösterge).', how: 'Kontrollü, gecikmeli bir echo URL’i verildi; yanıt süresi sapması gözlendi. İç ağ/metadata ASLA hedeflenmedi.', fix: 'URL alanlarında sunucu-taraflı allowlist + iç-ağ engelleme; şema/host doğrulama uygulayın.' },
    { desc: 'A server-side fetch parameter may reach internal resources (indicator).', how: 'A controlled delayed echo URL was supplied; a timing deviation was observed. Internal/metadata never targeted.', fix: 'Apply server-side allowlist + internal-network blocking; validate scheme/host.' }),
  open_redirect: D(
    { desc: 'Yönlendirme parametresi dış adrese yönlendirebiliyor.', how: 'Yönlendirme parametresine kontrollü bir işaret verildi; dış hedefe yönlendirme göstergesi gözlendi.', fix: 'Yönlendirmeleri iç allowlist ile sınırlayın; kullanıcı-girdili tam URL’e yönlendirmeyin.' },
    { desc: 'A redirect parameter can send users to external addresses.', how: 'A controlled marker was supplied; redirection to an external target was indicated.', fix: 'Restrict redirects to an internal allowlist; never redirect to a user-supplied full URL.' }),
  rce: D(
    { desc: 'Bir parametre komut/kod yürütmeye ulaşabiliyor (zaman-tabanlı gösterge).', how: 'Yalnız zararsız, zaman-tabanlı gecikme sondası (sleep) gönderildi; süre sapması gözlendi. Gerçek komut YÜRÜTÜLMEDİ.', fix: 'Sistem-komutu çağıran yolları gözden geçirin; girdiyi allowlist’leyin, shell birleştirmeden kaçının; en düşük yetki uygulayın.' },
    { desc: 'A parameter may reach command/code execution (time-based indicator).', how: 'Only a harmless time-based delay probe (sleep) was sent; a timing deviation was observed. No real command executed.', fix: 'Review command-invoking paths; allowlist input, avoid shell concatenation; least privilege.' }),
  file_upload: D(
    { desc: 'Dosya yükleme kısıtsız görünüyor (gösterge).', how: 'Tek, zararsız ve çalıştırılamaz bir test dosyası gönderildi; yalnız kabul/red gözlendi (dosya geri çağrılmadı).', fix: 'Sunucu-taraflı tip/MIME doğrulaması + allowlist + web-kökü dışı depolama uygulayın.' },
    { desc: 'File upload appears unrestricted (indicator).', how: 'A single harmless, non-executable test file was sent; only accept/reject observed (file not retrieved).', fix: 'Apply server-side type/MIME validation + allowlist + storage outside web root.' }),
  business_logic: D(
    { desc: 'İş akışı/yetki alanında incelenmesi gereken bir gösterge (ör. istemci-değiştirilebilir fiyat/adım-atlama).', how: 'Yüzey gözlemsel olarak incelendi (yalnız GET); state-değiştiren istek gönderilmedi.', fix: 'Kritik değerleri (fiyat/miktar/rol) sunucuda doğrulayın; adım ön-koşullarını sunucuda zorunlu kılın.' },
    { desc: 'A workflow/authorization indicator to review (e.g., client-editable price/step-skipping).', how: 'Surface reviewed observationally (GET only); no state-changing request sent.', fix: 'Validate critical values (price/qty/role) server-side; enforce step preconditions server-side.' }),
  race: D(
    { desc: 'Eşzamanlılık/mass-assignment göstergesi (düşük güven).', how: 'Tek gözlemsel istek yapıldı; tüketilebilir kaynağı değiştiren tekrar/yarış testi ÇALIŞTIRILMADI.', fix: 'Kritik işlemleri atomik/idempotent tasarlayın; model bağlamada alan allowlist’i uygulayın.' },
    { desc: 'Concurrency/mass-assignment indicator (low confidence).', how: 'A single observational request was made; no repeated/race test against consumable resources was run.', fix: 'Design critical operations atomic/idempotent; apply field allowlist on model binding.' }),
  forced_browsing: D(
    { desc: 'Menüde olmayan bir yönetim/gizli uç noktaya, düşük yetkili oturumla erişilebiliyor.', how: 'Yaygın yönetim uç noktalarına eldeki oturumla GET yapıldı; ana-sayfadan FARKLI 200/JSON dönüşü gözlendi (dönen veri raporlanmadı).', fix: 'Her hassas uç noktada sunucu-taraflı rol/yetki kontrolü uygulayın; UI’da gizlemek yetmez.' },
    { desc: 'An admin/hidden endpoint is reachable with a low-privileged session.', how: 'Common admin endpoints were GET-requested with the session; a 200/JSON distinct from the homepage was observed (returned data not reported).', fix: 'Enforce server-side role/authorization on every sensitive endpoint; UI hiding is insufficient.' }),
  weak_logout: D(
    { desc: 'Çıkıştan sonra oturum sunucu tarafında geçersizleştirilmiyor.', how: 'Logout sonrası AYNI oturumla korumalı bir uca erişim denendi; erişim sürdüğü gözlendi.', fix: 'Logout’ta oturumu sunucu tarafında iptal edin (revocation/expiry); istemci-tarafı silme yetmez.' },
    { desc: 'Session not invalidated server-side after logout.', how: 'After logout, access to a protected endpoint with the SAME session was attempted and still succeeded.', fix: 'Invalidate the session server-side on logout (revocation/expiry).' }),
  session_fixation: D(
    { desc: 'Girişte oturum kimliği yenilenmiyor (fixation göstergesi).', how: 'Login öncesi/sonrası oturum çerezi değeri karşılaştırıldı.', fix: 'Girişte oturum id’sini yenileyin (session regeneration).' },
    { desc: 'Session ID not regenerated on login (fixation indicator).', how: 'Session cookie value compared before/after login.', fix: 'Regenerate the session ID on login.' }),
  jwt: D(
    { desc: 'JWT/token yapılandırmasında güvenlik göstergesi (alg=none / zayıf sır / aşırı claim).', how: 'Token OFFLINE çözülüp imza algoritması, sır dayanıklılığı ve claim’ler incelendi.', fix: 'İmza algoritmasını sabitleyin, güçlü sır kullanın, `exp` ekleyin, hassas claim taşımayın.' },
    { desc: 'JWT/token security indicator (alg=none / weak secret / excessive claims).', how: 'Token decoded OFFLINE; algorithm, secret strength and claims inspected.', fix: 'Pin the signing algorithm, use a strong secret, add `exp`, avoid sensitive claims.' }),
  privilege_escalation: D(
    { desc: 'Standart kullanıcının yetkisini aşabileceğine dair gösterge (mass-assignment vb.).', how: 'Yüzey Otonom Analiz Motoru ile değerlendirildi; backend güvenli, gözlemsel bir prob uyguladı (gerçek yükseltme yapılmadı).', fix: 'Rol/yetki alanlarını istemciden kabul etmeyin; alan allowlist’i uygulayın.' },
    { desc: 'Indicator a standard user could exceed privileges (mass-assignment etc.).', how: 'Surface evaluated by the Autonomous Analysis Engine; the backend applied a safe observational probe (no real escalation).', fix: 'Do not accept role/authorization fields from the client; apply a field allowlist.' }),
  login_bypass: D(
    { desc: 'Giriş formuna klasik SQLi payload’ı ile kimlik doğrulama atlatma göstergesi.', how: 'Önce geçersiz kimlik, sonra `\' OR 1=1--` benzeri bir işaret denendi; kontrolün AKSİNE oturum/başarı yanıtı gözlendi. Oturum ele geçirilmedi.', fix: 'Kimlik sorgularında parametreli sorgu kullanın; girdi doğrulama + hatalı girişte tek-tip hata mesajı.' },
    { desc: 'Auth-bypass indicator via a classic SQLi payload on the login form.', how: 'Invalid credentials first, then a `\' OR 1=1--`-style marker; contrary to the control, a success/session response was observed. No session hijacked.', fix: 'Use parameterized queries in auth; validate input; return uniform error messages.' }),
  exposed_api_docs: D(
    { desc: 'Herkese açık API dokümantasyonu (Swagger/OpenAPI) bulundu.', how: 'Yaygın dokümantasyon yolları GET ile denendi; şema/arayüz dönüşü gözlendi (uç noktalar çağrılmadı).', fix: 'Şema uçlarını üretimde kimlik doğrulama/IP kısıtı arkasına alın; GraphQL introspection’ı kapatın.' },
    { desc: 'Public API documentation (Swagger/OpenAPI) found.', how: 'Common doc paths GET-probed; a schema/UI response observed (endpoints not called).', fix: 'Put schema endpoints behind auth/IP restriction in production; disable GraphQL introspection.' }),
  staging_exposure: D(
    { desc: 'İnternete açık hazırlık/test ortamı gözlendi.', how: 'Alt alan/uç gözlemlendi; üretim-dışı ortam göstergesi kaydedildi.', fix: 'Hazırlık ortamlarını IP/kimlik ile kısıtlayın veya internete kapatın.' },
    { desc: 'Internet-exposed staging/test environment observed.', how: 'Subdomain/endpoint observed; non-production indicator recorded.', fix: 'Restrict staging by IP/auth or take it off the internet.' }),
  stale_subdomain: D(
    { desc: 'Bakım-dışı/unutulmuş bir alt alan adı gözlendi.', how: 'Certificate Transparency + DNS kayıtları pasif toplandı.', fix: 'Kullanılmayan CNAME/kayıtları temizleyin; alt alan envanteri tutun.' },
    { desc: 'A stale/forgotten subdomain observed.', how: 'Certificate Transparency + DNS records collected passively.', fix: 'Clean up unused CNAME/records; keep a subdomain inventory.' }),
  outdated_component: D(
    { desc: 'Güncel olmayan bir bileşen/CMS parmak izi ve olası bilinen CVE.', how: 'HTTP başlıkları / meta generator / HTML izleri pasif incelendi; sürüm NVD ile eşlendi (CVE istismar edilmedi).', fix: 'Bileşen/eklenti/tema sürümlerini güncel tutun; otomatik güncelleme + bağımlılık taraması kurun.' },
    { desc: 'Outdated component/CMS fingerprint and possible known CVE.', how: 'HTTP headers / meta generator / HTML traces inspected passively; version matched against NVD (no CVE exploited).', fix: 'Keep components/plugins/themes updated; add auto-update + dependency scanning.' }),
  subdomain_takeover: D(
    { desc: 'Devralınabilir (dangling) alt alan göstergesi.', how: 'Alt alan CNAME kayıtları çözümlenip terk-edilmiş bulut imzalarıyla karşılaştırıldı.', fix: 'Bulut kaynağını silmeden önce DNS kaydını kaldırın; sahipsiz CNAME’leri temizleyin.' },
    { desc: 'Dangling subdomain takeover indicator.', how: 'Subdomain CNAMEs resolved and compared against abandoned-cloud signatures.', fix: 'Remove the DNS record before deleting the cloud resource; clean dangling CNAMEs.' }),
};
export function findingDetail(type: FindingType, locale: 'tr' | 'en'): Detail {
  return locale === 'tr' ? FINDING_DETAIL[type].tr : FINDING_DETAIL[type].en;
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
