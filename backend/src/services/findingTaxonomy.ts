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
  | 'weak_tls' | 'weak_key' | 'cert' | 'version_disclosure' | 'verbose_error' | 'exposed_files'
  | 'spf' | 'dmarc' | 'dkim' | 'dnssec'
  | 'cors' | 'cookie_flags'
  | 'sqli' | 'xss' | 'idor' | 'ssrf' | 'open_redirect' | 'rce' | 'file_upload'
  | 'business_logic' | 'race'
  | 'forced_browsing' | 'weak_logout' | 'session_fixation' | 'jwt' | 'privilege_escalation' | 'login_bypass'
  | 'exposed_api_docs' | 'staging_exposure' | 'stale_subdomain' | 'outdated_component' | 'subdomain_takeover'
  // (Faz 4) Derinlik modüllerinin somut bulguları — master'a girebilmesi için taksonomi türü ŞART.
  | 'csrf' | 'session_in_url' | 'weak_session' | 'user_enum' | 'default_creds' | 'no_lockout'
  | 'weak_pw_policy' | 'weak_pw_reset' | 'host_header' | 'http_method' | 'web_cache' | 'comment_leak'
  | 'mixed_content' | 'cloud_exposure' | 'caa' | 'mta_sts' | 'client_storage' | 'postmessage'
  | 'sri' | 'tabnabbing' | 'excessive_data' | 'rate_limit' | 'shadow_api' | 'graphql_introspection'
  // (Faz 5) Taşıma katmanı & başlık derinliği
  | 'csp_weak' | 'permissions_policy'
  // (Faz 6) Güvenli aktif göstergeler (login'siz)
  | 'lfi' | 'ssti' | 'hpp';

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
  verbose_error: { cwe: 'CWE-209', owasp: 'A05:2021 Security Misconfiguration',
    tr: 'Ayrıntılı hata sayfası (stack trace / framework sürümü / sunucu dosya yolu) saldırgana iç yapı hakkında bilgi verir ve sonraki saldırıları kolaylaştırır.',
    en: 'A verbose error page (stack trace / framework version / server file path) reveals internal structure to attackers and eases follow-up attacks.' },
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
    en: 'Unauthorized access/modification of customer/account records is possible; data breach, breach of UK GDPR / Data Protection Act 2018 and loss of trust.' },
  xss: { cwe: 'CWE-79', owasp: 'A03:2021 Injection',
    tr: 'Kullanıcının tarayıcısında betik çalıştırılarak oturum çalma/kimlik taklidi ve hesap ele geçirme mümkün olabilir.',
    en: 'Running script in the victim’s browser enables session theft/impersonation and account takeover.' },
  idor: { cwe: 'CWE-639', owasp: 'A01:2021 Broken Access Control',
    tr: 'Kimlik parametresi değiştirilerek başka kullanıcıların kayıtlarına erişilebilir; toplu veri sızıntısı ve KVKK ihlali riski.',
    en: 'Manipulating an ID parameter can access other users’ records; mass data exposure and breach of UK GDPR / Data Protection Act 2018.' },
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
  csrf: { cwe: 'CWE-352', owasp: 'A01:2021 Broken Access Control',
    tr: 'Anti-CSRF token / SameSite eksikliği; kullanıcı oturumu üzerinden istem-dışı işlem (CSRF) tetiklenebilir.',
    en: 'Missing anti-CSRF token / SameSite; unintended actions can be triggered on the user session (CSRF).' },
  session_in_url: { cwe: 'CWE-598', owasp: 'A07:2021 Identification & Authentication Failures',
    tr: 'Oturum kimliği URL’de taşınıyor; tarayıcı geçmişi, referrer ve loglara sızarak oturum çalınabilir.',
    en: 'Session id carried in the URL; leaks via history, referrer and logs, enabling session theft.' },
  weak_session: { cwe: 'CWE-331', owasp: 'A07:2021 Identification & Authentication Failures',
    tr: 'Oturum kimliği düşük entropili/tahmin edilebilir görünüyor; oturum ele geçirme riskini artırır.',
    en: 'Session id appears low-entropy/predictable, increasing session-hijacking risk.' },
  user_enum: { cwe: 'CWE-204', owasp: 'A07:2021 Identification & Authentication Failures',
    tr: 'Uygulama, geçerli/geçersiz kullanıcıyı farklı yanıtla ayırt ediyor; hesap numaralandırma ve hedefli saldırıya zemin.',
    en: 'The app distinguishes valid/invalid users via differing responses; enables account enumeration and targeting.' },
  default_creds: { cwe: 'CWE-1392', owasp: 'A07:2021 Identification & Authentication Failures',
    tr: 'Varsayılan/zayıf kimlik bilgileri kabul ediliyor göstergesi; doğrudan yetkisiz erişime yol açabilir.',
    en: 'Indicator that default/weak credentials are accepted; can lead to direct unauthorized access.' },
  no_lockout: { cwe: 'CWE-307', owasp: 'A07:2021 Identification & Authentication Failures',
    tr: 'Ardışık başarısız girişte kilitleme/kısıtlama gözlenmedi; kaba-kuvvet (brute-force) saldırısına açık.',
    en: 'No lockout/throttling observed after repeated failed logins; open to brute-force.' },
  weak_pw_policy: { cwe: 'CWE-521', owasp: 'A07:2021 Identification & Authentication Failures',
    tr: 'Zayıf parola politikası göstergesi (kısa/yaygın parolalar kabul); hesap ele geçirme riskini artırır.',
    en: 'Weak password-policy indicator (short/common passwords accepted); raises account-takeover risk.' },
  weak_pw_reset: { cwe: 'CWE-640', owasp: 'A07:2021 Identification & Authentication Failures',
    tr: 'Parola sıfırlama akışında zayıflık göstergesi (tahmin edilebilir token / kullanıcı ifşası); hesap ele geçirme riski.',
    en: 'Weakness indicator in password-reset flow (guessable token / user disclosure); account-takeover risk.' },
  host_header: { cwe: 'CWE-644', owasp: 'A05:2021 Security Misconfiguration',
    tr: 'Host başlığı yanıta/mantığa yansıyor göstergesi; parola-sıfırlama zehirleme ve cache poisoning’e zemin olabilir.',
    en: 'Indicator that the Host header reflects into responses/logic; can enable reset poisoning and cache poisoning.' },
  http_method: { cwe: 'CWE-650', owasp: 'A05:2021 Security Misconfiguration',
    tr: 'Gereksiz/tehlikeli HTTP metodu (TRACE/PUT/DELETE vb.) açık göstergesi; saldırı yüzeyini genişletir.',
    en: 'Indicator of unnecessary/dangerous HTTP methods (TRACE/PUT/DELETE) enabled; widens attack surface.' },
  web_cache: { cwe: 'CWE-525', owasp: 'A05:2021 Security Misconfiguration',
    tr: 'Hassas yanıt önbelleğe alınabiliyor / unkeyed başlık yansıması göstergesi; cache poisoning veya hassas veri sızıntısı.',
    en: 'Indicator that sensitive responses are cacheable / unkeyed header reflection; cache poisoning or data leak.' },
  comment_leak: { cwe: 'CWE-615', owasp: 'A05:2021 Security Misconfiguration',
    tr: 'HTML/JS yorum veya metadata’sında iç bilgi (TODO, iç IP, yol) sızıntısı; saldırgana keşif kolaylığı.',
    en: 'Internal info (TODO, internal IP, paths) leaks via HTML/JS comments or metadata; aids attacker recon.' },
  mixed_content: { cwe: 'CWE-311', owasp: 'A02:2021 Cryptographic Failures',
    tr: 'HTTPS sayfada HTTP kaynak yükleniyor (karışık içerik); MITM ile enjeksiyon/dinleme ve tarayıcı uyarısı.',
    en: 'HTTP resources loaded on an HTTPS page (mixed content); MITM injection/eavesdropping and browser warnings.' },
  cloud_exposure: { cwe: 'CWE-732', owasp: 'A05:2021 Security Misconfiguration',
    tr: 'Public cloud storage (S3/GCS/Azure) referansı listelenebilir görünüyor; nesne envanteri/veri sızıntısı riski.',
    en: 'Referenced public cloud storage (S3/GCS/Azure) appears listable; object-inventory/data-leak risk.' },
  caa: { cwe: 'CWE-295', owasp: 'A05:2021 Security Misconfiguration',
    tr: 'CAA kaydı yok; herhangi bir CA alan için sertifika verebilir — yanlış/kötü-amaçlı sertifika verme riski.',
    en: 'No CAA record; any CA can issue certificates for the domain — mis-issuance risk.' },
  mta_sts: { cwe: 'CWE-319', owasp: 'A02:2021 Cryptographic Failures',
    tr: 'MTA-STS zorlayıcı değil (enforce yok); SMTP teslimi downgrade/MITM ile şifresiz taşınabilir.',
    en: 'MTA-STS not enforcing; SMTP delivery can be downgraded/MITM to cleartext.' },
  client_storage: { cwe: 'CWE-922', owasp: 'A04:2021 Insecure Design',
    tr: 'Hassas veri (token/oturum) localStorage/sessionStorage’a yazılıyor; XSS ile okunabilir — HttpOnly çerez tercih edilmeli.',
    en: 'Sensitive data (token/session) written to localStorage/sessionStorage; readable via XSS — prefer HttpOnly cookies.' },
  postmessage: { cwe: 'CWE-346', owasp: 'A05:2021 Security Misconfiguration',
    tr: 'postMessage origin doğrulaması eksik göstergesi; kötü-amaçlı sayfa mesaj enjekte edip veri sızdırabilir.',
    en: 'Indicator of missing postMessage origin validation; a malicious page can inject messages/exfiltrate data.' },
  sri: { cwe: 'CWE-353', owasp: 'A08:2021 Software & Data Integrity Failures',
    tr: 'Harici script’te Subresource Integrity (SRI) yok; kaynak/CDN ele geçirilirse zararlı kod çalışabilir.',
    en: 'External script lacks Subresource Integrity (SRI); if the source/CDN is compromised, malicious code can run.' },
  tabnabbing: { cwe: 'CWE-1022', owasp: 'A01:2021 Broken Access Control',
    tr: 'target=_blank bağlantılarda rel=noopener yok (reverse tabnabbing); açılan sayfa kaynak sekmeyi phishing’e yönlendirebilir.',
    en: 'target=_blank links lack rel=noopener (reverse tabnabbing); the opened page can redirect the source tab to phishing.' },
  excessive_data: { cwe: 'CWE-213', owasp: 'API3:2023 Broken Object Property Level Authorization',
    tr: 'API yanıtı gerekenden fazla/hassas alan (parola-hash/rol/iç-ID) döndürüyor; veri sızıntısı ve yetki haritalama.',
    en: 'API response returns excessive/sensitive fields (password-hash/role/internal-id); data leak and authz mapping.' },
  rate_limit: { cwe: 'CWE-770', owasp: 'API4:2023 Unrestricted Resource Consumption',
    tr: 'API ucunda rate-limit/kota gözlenmedi; brute-force, scraping ve kaynak tüketimi (DoS) riskine açık.',
    en: 'No rate-limit/quota observed on the API endpoint; open to brute-force, scraping and resource exhaustion (DoS).' },
  shadow_api: { cwe: 'CWE-1059', owasp: 'API9:2023 Improper Inventory Management',
    tr: 'Eski/gölge API sürümleri (v1/v2) erişilebilir; yamasız kalıp saldırı yüzeyini genişletebilir.',
    en: 'Old/shadow API versions (v1/v2) reachable; may stay unpatched and widen the attack surface.' },
  graphql_introspection: { cwe: 'CWE-200', owasp: 'API9:2023 Improper Inventory Management',
    tr: 'GraphQL introspection açık; tüm şema (tipler/mutasyonlar) ifşa olur ve saldırı yüzeyini haritalar.',
    en: 'GraphQL introspection is open; the full schema (types/mutations) is exposed and maps the attack surface.' },
  csp_weak: { cwe: 'CWE-693', owasp: 'A05:2021 Security Misconfiguration',
    tr: 'CSP mevcut ama `unsafe-inline`/`unsafe-eval`/`*` içeriyor; XSS azaltması büyük ölçüde etkisiz kalır (sertleştirme boşluğu).',
    en: 'CSP is present but includes `unsafe-inline`/`unsafe-eval`/`*`; its XSS mitigation is largely ineffective (hardening gap).' },
  permissions_policy: { cwe: 'CWE-693', owasp: 'A05:2021 Security Misconfiguration',
    tr: 'Permissions-Policy yok; tarayıcı özellik erişimi (kamera/mikrofon/konum vb.) kısıtlanmıyor (bilgilendirici sertleştirme).',
    en: 'No Permissions-Policy; browser feature access (camera/mic/geolocation) is unrestricted (informational hardening).' },
  lfi: { cwe: 'CWE-22', owasp: 'A01:2021 Broken Access Control',
    tr: 'Dosya/yol parametresi sunucu dosya sistemine yol geçişi (path traversal / LFI) yapabiliyor göstergesi; hassas dosya okuma/kaynak sızıntısı riski.',
    en: 'A file/path parameter appears to allow path traversal / LFI into the server filesystem; risk of sensitive file read/source leakage.' },
  ssti: { cwe: 'CWE-1336', owasp: 'A03:2021 Injection',
    tr: 'Girdi bir şablon motorunda değerlendiriliyor göstergesi (SSTI — aritmetik ifade sonuca yansıdı); sunucu-taraflı kod/veri ifşası riski.',
    en: 'Indicator that input is evaluated by a template engine (SSTI — arithmetic reflected in output); risk of server-side code/data exposure.' },
  hpp: { cwe: 'CWE-235', owasp: 'A05:2021 Security Misconfiguration',
    tr: 'HTTP Parametre Kirliliği (HPP) göstergesi — tekrarlanan parametrenin işlenişi tutarsız; filtre atlatma/mantık sapması yüzeyi.',
    en: 'HTTP Parameter Pollution (HPP) indicator — duplicated parameter is parsed inconsistently; filter-bypass/logic-deviation surface.' },
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
  { re: /\blfi\b|yol ge[çc]i[şs]i|path.?traversal|dizin ge[çc]i[şs]i|dosya ok(u|uma).*ge[çc]|root:x:0:0/i, type: 'lfi' },
  { re: /\bssti\b|[şs]ablon enjeksiyon|template injection|server.?side template/i, type: 'ssti' },
  { re: /\bhpp\b|parametre kirlili|parameter pollution/i, type: 'hpp' },
  { re: /\brce\b|uzaktan kod|komut [çc]al[ıi][şs]t[ıi]r/i, type: 'rce' },
  { re: /dosya y[üu]kleme|file.?upload/i, type: 'file_upload' },
  { re: /yar[ıi][şs]|race[- ]?condition|\brace\b|mass.?assign|over.?post/i, type: 'race' },
  { re: /i[şs] mant[ıi][ğg]|business.?logic|negatif|kupon|indirim/i, type: 'business_logic' },
  { re: /cors/i, type: 'cors' },
  // csrf, cookie_flags'tan ÖNCE: CSRF tekniği "SameSite" içerir; yoksa cookie_flags'a düşer (yanlış tür).
  { re: /\bcsrf\b|anti-csrf|siteler.?aras[ıi] istek|cross.?site request/i, type: 'csrf' },
  { re: /[çc]erez|cookie|httponly|samesite|secure bayrak/i, type: 'cookie_flags' },
  { re: /x-frame-options|clickjacking|[çc]er[çc]eve/i, type: 'clickjacking' },
  { re: /x-content-type-options|mime/i, type: 'mime_sniffing' },
  // csp_weak, csp_missing'ten ÖNCE: mevcut-ama-zayıf CSP "eksik" sayılmamalı.
  { re: /unsafe-inline|unsafe-eval|csp.*(zay[ıi]f|unsafe|\*)|zay[ıi]f.*csp/i, type: 'csp_weak' },
  { re: /content-security-policy|\bcsp\b/i, type: 'csp_missing' },
  { re: /permissions-policy|izin politikas[ıi]/i, type: 'permissions_policy' },
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
  { re: /\bdk[iı]m\b/i, type: 'dkim' },
  { re: /\bdnssec\b/i, type: 'dnssec' },
  { re: /zay[ıi]f.*cipher|cipher.*zay[ıi]f|weak.*tls|weak.*cipher|zay[ıi]f.*tls|3des|\brc4\b|sslv3|\bexport\b.*cipher|null.*cipher|tls\s*1\.[01]\b|eski protokol|deprecated.*(tls|protokol)/i, type: 'weak_tls' },
  { re: /rsa.*(1024|2048)|anahtar boyut|key size/i, type: 'weak_key' },
  // caa, cert'ten ÖNCE: CAA bulgusunun kanıtı "…CA sertifika verebilir" içerir; yoksa cert'e düşer (yanlış tür).
  { re: /\bcaa\b|sertifika verme|certificate authority auth/i, type: 'caa' },
  { re: /sertifika|certificate|hostname e[şs]le|son kullanma|expir/i, type: 'cert' },
  { re: /ayr[ıi]nt[ıi]l[ıi] hata|hata sayfas[ıi].*if[şs]a|verbose error|stack trace|error page/i, type: 'verbose_error' },
  { re: /s[üu]r[üu]m if[şs]a|version disclosure|server.*banner|server_tokens|banner/i, type: 'version_disclosure' },
  // ——— (Faz 4) Derinlik modülleri: teknik/kanıt metnindeki AYIRT EDİCİ sözcüklere göre sınıflama.
  // En sona eklendi: mevcut bulgular önce eşleşir; yalnız daha önce sınıflanamayanlar buraya düşer.
  { re: /graphql|introspection|__schema/i, type: 'graphql_introspection' },
  { re: /a[şs][ıi]r[ıi] veri|\bbopla\b|excessive data|hassas alan.*yan[ıi]t|yan[ıi]t.*hassas alan/i, type: 'excessive_data' },
  { re: /rate.?limit|k[ıi]s[ıi]tlanmam[ıi][şs] t[üu]ketim|\b429\b|kota\b/i, type: 'rate_limit' },
  { re: /shadow|g[öo]lge s[üu]r[üu]m|deprecated api|api s[üu]r[üu]m ucu|\/api\/v\d|sürüm ucu/i, type: 'shadow_api' },
  { re: /subresource [iı]ntegr[iı]ty|\bsr[iı]\b/i, type: 'sri' },
  { re: /tabnabbing|target=_blank|rel=.{0,4}noopener/i, type: 'tabnabbing' },
  { re: /postmessage|web messaging|message handler/i, type: 'postmessage' },
  { re: /istemci depolama|localstorage|sessionstorage|browser storage|taray[ıi]c[ıi] depolama|storage statik|storage\.setitem/i, type: 'client_storage' },
  { re: /kar[ıi][şs][ıi]k i[çc]erik|mixed content/i, type: 'mixed_content' },
  { re: /cloud storage|\bbucket\b|amazonaws|storage\.googleapis|blob\.core|listelenebilir.*depo|public.*depo/i, type: 'cloud_exposure' },
  { re: /mta-sts|smtp.*downgrade|smtp tls zorla/i, type: 'mta_sts' },
  { re: /oturum kimli[ğg]i.*url|session id.*url|url'?de oturum|url.*oturum kimli/i, type: 'session_in_url' },
  { re: /oturum.*entropi|zay[ıi]f oturum kimli|session.*entropy|tahmin edilebilir oturum/i, type: 'weak_session' },
  { re: /kullan[ıi]c[ıi] numaraland[ıi]|user enumeration|enumerasyon|kullan[ıi]c[ıi] say[ıi]m|hesap varl[ıi][ğg][ıi] if[şs]a|ge[çc]erli vs ge[çc]ersiz/i, type: 'user_enum' },
  { re: /varsay[ıi]lan kimlik|default credential|varsay[ıi]lan parola|admin\/admin/i, type: 'default_creds' },
  { re: /kilitleme|lockout|kaba.?kuvvet|brute.?force|deneme s[ıi]n[ıi]rlama/i, type: 'no_lockout' },
  { re: /parola politikas[ıi]|password policy|zay[ıi]f parola politika/i, type: 'weak_pw_policy' },
  { re: /parola s[ıi]f[ıi]rlama|password reset|[şs]ifre s[ıi]f[ıi]rlama/i, type: 'weak_pw_reset' },
  { re: /host header|host ba[şs]l[ıi][ğg][ıi]|host.?header injection|x-forwarded-host|host.*yans[ıi]/i, type: 'host_header' },
  { re: /trace metodu|http method|tehlikeli.*metod|put\/delete|webdav|options allow/i, type: 'http_method' },
  { re: /cache poison|[öo]nbellek zehir|cacheable|[öo]nbelle[ğg]e al[ıi]n|unkeyed|cache ba[şs]l|cache-control|yan[ıi]t cache/i, type: 'web_cache' },
  { re: /yorum.*s[ıi]z|comment.*leak|metadata s[ıi]z|html yorum|yorum\/metadata/i, type: 'comment_leak' },
  { re: /y[öo]netici aray[üu]z|admin aray[üu]z|admin panel|y[öo]netici aray/i, type: 'forced_browsing' },
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
  verbose_error: { tr: 'Ayrıntılı hata sayfası bilgi ifşası', en: 'Verbose error page information disclosure' },
  exposed_files: { tr: 'Açıkta hassas dosya', en: 'Exposed sensitive file' },
  spf: { tr: 'SPF kaydı eksik/zayıf', en: 'Missing/weak SPF record' },
  dmarc: { tr: 'DMARC politikası yetersiz (eksik veya zayıf)', en: 'Insufficient DMARC policy (missing or weak)' },
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
  csrf: { tr: 'CSRF koruması eksik', en: 'Missing CSRF protection' },
  session_in_url: { tr: 'Oturum kimliği URL’de', en: 'Session id in URL' },
  weak_session: { tr: 'Zayıf oturum kimliği entropisi', en: 'Weak session id entropy' },
  user_enum: { tr: 'Kullanıcı numaralandırma göstergesi', en: 'User enumeration indicator' },
  default_creds: { tr: 'Varsayılan kimlik bilgileri göstergesi', en: 'Default credentials indicator' },
  no_lockout: { tr: 'Hesap kilitleme / brute-force koruması yok', en: 'No account lockout / brute-force protection' },
  weak_pw_policy: { tr: 'Zayıf parola politikası', en: 'Weak password policy' },
  weak_pw_reset: { tr: 'Zayıf parola sıfırlama akışı', en: 'Weak password-reset flow' },
  host_header: { tr: 'Host header injection göstergesi', en: 'Host header injection indicator' },
  http_method: { tr: 'Tehlikeli HTTP metodu açık', en: 'Dangerous HTTP method enabled' },
  web_cache: { tr: 'Web cache / hassas önbellekleme göstergesi', en: 'Web cache / sensitive caching indicator' },
  comment_leak: { tr: 'Yorum/metadata bilgi sızıntısı', en: 'Comment/metadata information leak' },
  mixed_content: { tr: 'Karışık içerik (HTTP kaynak)', en: 'Mixed content (HTTP resource)' },
  cloud_exposure: { tr: 'Listelenebilir cloud storage bucket', en: 'Listable cloud storage bucket' },
  caa: { tr: 'CAA kaydı eksik', en: 'Missing CAA record' },
  mta_sts: { tr: 'MTA-STS zorlayıcı değil', en: 'MTA-STS not enforcing' },
  client_storage: { tr: 'Hassas veri istemci depolamasında', en: 'Sensitive data in client storage' },
  postmessage: { tr: 'Güvensiz postMessage origin', en: 'Insecure postMessage origin' },
  sri: { tr: 'Subresource Integrity (SRI) eksik', en: 'Missing Subresource Integrity (SRI)' },
  tabnabbing: { tr: 'Reverse tabnabbing (rel=noopener yok)', en: 'Reverse tabnabbing (no rel=noopener)' },
  excessive_data: { tr: 'Aşırı veri ifşası (API/BOPLA)', en: 'Excessive data exposure (API/BOPLA)' },
  rate_limit: { tr: 'API rate-limit yok', en: 'No API rate-limit' },
  shadow_api: { tr: 'Gölge/deprecated API sürümü', en: 'Shadow/deprecated API version' },
  graphql_introspection: { tr: 'GraphQL introspection açık', en: 'GraphQL introspection enabled' },
  csp_weak: { tr: 'CSP zayıf (unsafe-inline/eval)', en: 'Weak CSP (unsafe-inline/eval)' },
  permissions_policy: { tr: 'Permissions-Policy eksik', en: 'Missing Permissions-Policy' },
  lfi: { tr: 'Yol geçişi / LFI göstergesi', en: 'Path traversal / LFI indicator' },
  ssti: { tr: 'Şablon enjeksiyonu (SSTI) göstergesi', en: 'Template injection (SSTI) indicator' },
  hpp: { tr: 'HTTP Parametre Kirliliği (HPP)', en: 'HTTP Parameter Pollution (HPP)' },
};
export function friendlyLabel(type: FindingType, locale: 'tr' | 'en' | 'de'): string {
  if (locale === 'de') return FRIENDLY_LABEL_DE[type] ?? FRIENDLY_LABEL[type].en;
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
  verbose_error: D(
    { desc: 'Uygulama, hatalı/beklenmedik girdide ayrıntılı bir hata sayfası döndürüyor; framework sürümü, sunucu dosya yolu veya stack trace ifşa oluyor.', how: 'Doğrulama probları sırasında dönen hata yanıtının GÖVDESİ, framework hata-sayfası imzaları (ör. "Server Error in", ".NET Framework Version", fiziksel dosya yolu, stack trace) için tarandı — GERÇEK yanıttan.', fix: 'Üretimde ayrıntılı hata sayfalarını kapatın (ör. ASP.NET `<customErrors mode="On" />` / `<httpErrors errorMode="Custom" />`; PHP `display_errors=Off`); son kullanıcıya jenerik hata sayfası gösterin, ayrıntıyı yalnız sunucu loguna yazın.' },
    { desc: 'On malformed/unexpected input the app returns a verbose error page leaking framework version, server file path, or stack trace.', how: 'The error response BODY collected during verification probes was scanned for framework error-page signatures (e.g., "Server Error in", ".NET Framework Version", physical file path, stack trace) — from the REAL response.', fix: 'Disable verbose errors in production (e.g., ASP.NET `<customErrors mode="On" />`; PHP `display_errors=Off`); show a generic error page and log details server-side only.' }),
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
    { desc: 'Oturum çerezinde Secure/HttpOnly/SameSite bayrakları eksik.', how: 'Gerçek oturum çerezlerinin güvenlik bayrakları incelendi (analitik çerezler hariç).', fix: 'Oturum çerezlerine `HttpOnly; Secure; SameSite=Lax/Strict` ekleyin.' },
    { desc: 'Session cookie missing Secure/HttpOnly/SameSite flags.', how: 'Security flags of genuine session cookies inspected (analytics cookies excluded).', fix: 'Add `HttpOnly; Secure; SameSite` to session cookies.' }),
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
    { desc: 'Standart kullanıcının yetkisini aşabileceğine dair gösterge (mass-assignment vb.).', how: 'Keşfedilen authenticated yüzeyde yetki-alanı içeren form/API üzerinde backend güvenli, gözlemsel bir prob uyguladı (gerçek yükseltme yapılmadı).', fix: 'Rol/yetki alanlarını istemciden kabul etmeyin; alan allowlist’i uygulayın.' },
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
  csrf: D(
    { desc: 'Durum-değiştiren istekte anti-CSRF token yok ve/veya çerez SameSite değil.', how: 'POST formları ve oturum çerezleri incelendi; anti-CSRF token / SameSite gözlenmedi (istismar yapılmadı).', fix: 'Durum-değiştiren isteklere anti-CSRF token ekleyin; oturum çerezine `SameSite=Lax/Strict`.' },
    { desc: 'No anti-CSRF token on a state-changing request and/or cookie is not SameSite.', how: 'POST forms and session cookies inspected; no anti-CSRF token / SameSite observed (not exploited).', fix: 'Add anti-CSRF tokens to state-changing requests; set `SameSite=Lax/Strict` on session cookies.' }),
  session_in_url: D(
    { desc: 'Oturum kimliği URL parametresinde taşınıyor.', how: 'URL/bağlantılarda oturum kimliği kalıbı gözlendi (değer gösterilmez).', fix: 'Oturum kimliğini yalnız HttpOnly çerezde taşıyın; URL’den kaldırın.' },
    { desc: 'Session id carried in a URL parameter.', how: 'A session-id pattern observed in URLs/links (value redacted).', fix: 'Carry the session id only in an HttpOnly cookie; remove it from URLs.' }),
  weak_session: D(
    { desc: 'Oturum kimliği düşük entropili/tahmin edilebilir görünüyor.', how: 'Oturum kimliğinin uzunluk/karakter-uzayı gözlendi (JWT hariç); düşük entropi göstergesi.', fix: 'Kriptografik olarak güçlü, ≥128-bit rastgele oturum kimliği üretin.' },
    { desc: 'Session id appears low-entropy/predictable.', how: 'Length/char-space of the session id observed (JWT excluded); low-entropy indicator.', fix: 'Generate cryptographically strong, ≥128-bit random session ids.' }),
  user_enum: D(
    { desc: 'Geçerli/geçersiz kullanıcı farklı yanıtla ayırt edilebiliyor.', how: 'Var-olmayan ve olası bir kullanıcıyla (throwaway) yanıt/zaman farkı gözlendi; hesap kilitlenmedi.', fix: 'Giriş/sıfırlama/kayıt akışlarında tek-tip yanıt ve süre döndürün.' },
    { desc: 'Valid/invalid users can be distinguished by differing responses.', how: 'Response/timing difference observed with a non-existent vs. a likely (throwaway) user; no account locked.', fix: 'Return uniform responses and timing across login/reset/registration.' }),
  default_creds: D(
    { desc: 'Varsayılan/zayıf kimlik bilgisi kabul ediliyor göstergesi.', how: 'Küçük, throwaway bir varsayılan-çift denendi; başarı göstergesi gözlendi (istismar edilmedi).', fix: 'Varsayılan hesapları kaldırın/kilitleyin; ilk açılışta güçlü parola zorunlu kılın.' },
    { desc: 'Indicator that default/weak credentials are accepted.', how: 'A small, throwaway default pair was tried; a success indicator was observed (not exploited).', fix: 'Remove/disable default accounts; force a strong password at first setup.' }),
  no_lockout: D(
    { desc: 'Ardışık başarısız girişte kilitleme/kısıtlama gözlenmedi.', how: 'Throwaway bir kullanıcıyla düşük hacimli başarısız giriş denendi; kilitleme/gecikme gözlenmedi (gerçek hesap kilitlenmedi).', fix: 'Hesap+IP bazlı kademeli gecikme/kilitleme ve CAPTCHA ekleyin.' },
    { desc: 'No lockout/throttling observed after repeated failed logins.', how: 'Low-volume failed logins with a throwaway user; no lockout/delay observed (no real account locked).', fix: 'Add per-account+IP progressive delay/lockout and CAPTCHA.' }),
  weak_pw_policy: D(
    { desc: 'Zayıf parola politikası göstergesi (kısa/yaygın parola kabul).', how: 'Kayıt/parola akışında politika sinyalleri gözlendi (gerçek hesap oluşturulmadı).', fix: 'Minimum uzunluk + yaygın-parola engeli (NIST 800-63B) uygulayın.' },
    { desc: 'Weak password-policy indicator (short/common passwords accepted).', how: 'Policy signals observed in the registration/password flow (no real account created).', fix: 'Enforce minimum length + common-password blocklist (NIST 800-63B).' }),
  weak_pw_reset: D(
    { desc: 'Parola sıfırlama akışında zayıflık göstergesi (kullanıcı ifşası / tahmin edilebilir token).', how: 'Sıfırlama akışı GET/gözlem ile incelendi; gerçek sıfırlama e-postası tetiklenmedi.', fix: 'Tek-tip yanıt + yüksek-entropili, kısa ömürlü, tek-kullanımlık token kullanın.' },
    { desc: 'Weakness indicator in password-reset (user disclosure / guessable token).', how: 'Reset flow inspected via GET/observation; no real reset email triggered.', fix: 'Uniform responses + high-entropy, short-lived, single-use tokens.' }),
  host_header: D(
    { desc: 'Host başlığı yanıta/mantığa yansıyor göstergesi.', how: 'Alternatif Host başlığıyla tek güvenli istek gönderildi; yansıma gözlendi (zehirleme yapılmadı).', fix: 'Host’u allowlist ile doğrulayın; mutlak URL üretiminde güvenilen sabit alan kullanın.' },
    { desc: 'Indicator that the Host header reflects into responses/logic.', how: 'A single safe request with an alternate Host header; reflection observed (no poisoning).', fix: 'Validate Host against an allowlist; use a trusted fixed domain for absolute URLs.' }),
  http_method: D(
    { desc: 'Gereksiz/tehlikeli HTTP metodu (TRACE/PUT/DELETE) açık göstergesi.', how: 'OPTIONS ile izin verilen metodlar listelendi / TRACE gözlendi (durum-değiştiren metod ÇAĞRILMADI).', fix: 'Yalnız gerekli metodlara izin verin; TRACE ve kullanılmayan WebDAV metodlarını kapatın.' },
    { desc: 'Indicator of unnecessary/dangerous HTTP methods (TRACE/PUT/DELETE) enabled.', how: 'Allowed methods enumerated via OPTIONS / TRACE observed (no state-changing method called).', fix: 'Allow only required methods; disable TRACE and unused WebDAV methods.' }),
  web_cache: D(
    { desc: 'Hassas yanıt önbelleğe alınabiliyor veya unkeyed başlık yansıması var.', how: 'Cache-Control/response gözlendi; unkeyed başlık yansıması için tek güvenli prob (zehirleme yapılmadı).', fix: 'Hassas yanıtlara `Cache-Control: no-store`; cache anahtarına ilgili başlıkları dahil edin.' },
    { desc: 'Sensitive responses are cacheable or there is unkeyed header reflection.', how: 'Cache-Control/response observed; a single safe probe for unkeyed reflection (no poisoning).', fix: 'Set `Cache-Control: no-store` on sensitive responses; include relevant headers in the cache key.' }),
  comment_leak: D(
    { desc: 'HTML/JS yorum veya metadata’sında iç bilgi (TODO/iç IP/yol) sızıntısı.', how: 'Sayfa/JS yorumları pasif tarandı; iç bilgi kalıpları gözlendi.', fix: 'Üretim çıktısından yorumları/metadata’yı temizleyin (minify + comment strip).' },
    { desc: 'Internal info (TODO/internal IP/path) leaks via HTML/JS comments or metadata.', how: 'Page/JS comments passively scanned; internal-info patterns observed.', fix: 'Strip comments/metadata from production output (minify + comment strip).' }),
  mixed_content: D(
    { desc: 'HTTPS sayfada HTTP üzerinden kaynak yükleniyor (karışık içerik).', how: 'HTTPS sayfanın kaynakları pasif incelendi; `http://` alt-kaynak gözlendi.', fix: 'Tüm alt-kaynakları HTTPS’e taşıyın; `upgrade-insecure-requests` CSP direktifi ekleyin.' },
    { desc: 'Resources loaded over HTTP on an HTTPS page (mixed content).', how: 'The HTTPS page resources inspected passively; an `http://` sub-resource observed.', fix: 'Move all sub-resources to HTTPS; add the `upgrade-insecure-requests` CSP directive.' }),
  cloud_exposure: D(
    { desc: 'Referans verilen public cloud storage (S3/GCS/Azure) listelenebilir görünüyor.', how: 'Kaynaklardaki bucket referansına güvenli GET; dizin listeleme yanıtı gözlendi.', fix: 'Bucket liste iznini kapatın; nesneleri private yapın; gereksiz public erişimi kaldırın.' },
    { desc: 'Referenced public cloud storage (S3/GCS/Azure) appears listable.', how: 'Safe GET to the referenced bucket; a directory-listing response observed.', fix: 'Disable bucket listing; make objects private; remove unnecessary public access.' }),
  caa: D(
    { desc: 'CAA kaydı yok; herhangi bir CA sertifika verebilir.', how: 'Org-alanın CAA kaydı sorgulandı; bulunamadı.', fix: 'Yetkili CA’ları `CAA` kaydıyla kısıtlayın (ör. `0 issue "letsencrypt.org"`).' },
    { desc: 'No CAA record; any CA can issue certificates.', how: 'The org-domain CAA record queried; not found.', fix: 'Restrict authorized CAs with a `CAA` record (e.g. `0 issue "letsencrypt.org"`).' }),
  mta_sts: D(
    { desc: 'MTA-STS zorlayıcı değil (enforce yok); SMTP downgrade’e açık.', how: '`_mta-sts` TXT + politika dosyası (tek güvenli GET) okundu; mode enforce değil.', fix: 'MTA-STS politikasını `mode: enforce` yapın; TLS-RPT ile raporlamayı açın.' },
    { desc: 'MTA-STS not enforcing; open to SMTP downgrade.', how: '`_mta-sts` TXT + policy file (single safe GET) read; mode not enforce.', fix: 'Set the MTA-STS policy to `mode: enforce`; enable reporting via TLS-RPT.' }),
  client_storage: D(
    { desc: 'Hassas veri (token/oturum) localStorage/sessionStorage’a yazılıyor.', how: 'İstemci JS statik olarak tarandı; `storage.setItem` ile hassas anahtar yazımı gözlendi (değer REDAKTE).', fix: 'Oturum token’ını localStorage yerine `HttpOnly + Secure` çerezde tutun.' },
    { desc: 'Sensitive data (token/session) written to localStorage/sessionStorage.', how: 'Client JS scanned statically; a sensitive-key `storage.setItem` write observed (value redacted).', fix: 'Keep the session token in an `HttpOnly + Secure` cookie instead of localStorage.' }),
  postmessage: D(
    { desc: 'postMessage mesaj işleyicisinde origin doğrulaması eksik göstergesi.', how: 'İstemci JS statik tarandı; origin kontrolü olmayan `message` handler gözlendi.', fix: '`message` işleyicilerinde `event.origin`’i katı allowlist ile doğrulayın.' },
    { desc: 'Indicator of missing origin validation in a postMessage handler.', how: 'Client JS scanned statically; a `message` handler without origin checks observed.', fix: 'Validate `event.origin` against a strict allowlist in `message` handlers.' }),
  sri: D(
    { desc: 'Harici script Subresource Integrity (SRI) olmadan yükleniyor.', how: 'Sayfadaki harici `<script>` etiketleri incelendi; `integrity` özniteliği gözlenmedi.', fix: 'Harici script/stil için `integrity` + `crossorigin` (SRI) hash’i ekleyin.' },
    { desc: 'External script loaded without Subresource Integrity (SRI).', how: 'External `<script>` tags inspected; no `integrity` attribute observed.', fix: 'Add `integrity` + `crossorigin` (SRI) hashes to external scripts/styles.' }),
  tabnabbing: D(
    { desc: '`target=_blank` bağlantıda `rel=noopener` yok (reverse tabnabbing).', how: 'Dış bağlantılar statik incelendi; `noopener/noreferrer` olmayan `_blank` gözlendi.', fix: '`target=_blank` bağlantılara `rel="noopener noreferrer"` ekleyin.' },
    { desc: '`target=_blank` link lacks `rel=noopener` (reverse tabnabbing).', how: 'External links inspected statically; a `_blank` without `noopener/noreferrer` observed.', fix: 'Add `rel="noopener noreferrer"` to `target=_blank` links.' }),
  excessive_data: D(
    { desc: 'API yanıtı gerekenden fazla/hassas alan (parola-hash/rol/iç-ID) döndürüyor.', how: 'Gerçek API yanıtında hassas/aşırı alan adı gözlendi (değer REDAKTE).', fix: 'Yanıtları alan-allowlist (response DTO) ile sınırlayın; hassas alanları hiç göndermeyin.' },
    { desc: 'API response returns excessive/sensitive fields (password-hash/role/internal-id).', how: 'A sensitive/excessive field name observed in a real API response (value redacted).', fix: 'Constrain responses with a field allowlist (response DTO); never send sensitive fields.' }),
  rate_limit: D(
    { desc: 'API ucunda rate-limit/kota gözlenmedi.', how: 'Bir API ucuna MODEST burst (DoS değil) sonrası 429/rate-limit başlığı gözlenmedi; hedef yorulmadı.', fix: 'Hesap+IP+endpoint bazlı rate-limit + kota; ağır uçlara maliyet-tabanlı sınır ekleyin.' },
    { desc: 'No rate-limit/quota observed on the API endpoint.', how: 'After a MODEST burst (not DoS) no 429/rate-limit header observed; target not stressed.', fix: 'Add per-account+IP+endpoint rate-limit + quota; cost-based limits on heavy endpoints.' }),
  shadow_api: D(
    { desc: 'Eski/gölge API sürümleri (v1/v2) aynı anda erişilebilir.', how: 'Sürüm uçlarına güvenli GET; SPA-shell olmayan, JSON dönen birden fazla sürüm gözlendi.', fix: 'Kullanılmayan/eski API sürümlerini kapatın veya kaldırın; sürüm envanteri tutun.' },
    { desc: 'Old/shadow API versions (v1/v2) reachable simultaneously.', how: 'Safe GET to version endpoints; multiple non-shell JSON versions observed.', fix: 'Disable/remove unused/old API versions; maintain a version inventory.' }),
  graphql_introspection: D(
    { desc: 'GraphQL ucunda introspection açık; tüm şema ifşa oluyor.', how: 'GraphQL ucuna read-only introspection sorgusu; şema döndü (veri değiştirilmedi).', fix: 'Üretimde introspection’ı kapatın; sorgu derinliği/karmaşıklık limiti ekleyin.' },
    { desc: 'GraphQL introspection is open; the full schema is exposed.', how: 'A read-only introspection query to the GraphQL endpoint returned the schema (no data changed).', fix: 'Disable introspection in production; add query depth/complexity limits.' }),
  csp_weak: D(
    { desc: 'Content-Security-Policy mevcut ancak `unsafe-inline`/`unsafe-eval`/`*` gibi izinler taşıyor.', how: 'CSP başlığı ayrıştırıldı; zayıflatıcı direktif(ler) gözlendi.', fix: 'unsafe-inline/unsafe-eval kaldırın; nonce/hash tabanlı script politikası kullanın; kaynakları allowlist’leyin.' },
    { desc: 'Content-Security-Policy is present but carries permissive directives like `unsafe-inline`/`unsafe-eval`/`*`.', how: 'CSP header parsed; weakening directive(s) observed.', fix: 'Remove unsafe-inline/unsafe-eval; use nonce/hash-based script policy; allowlist sources.' }),
  permissions_policy: D(
    { desc: 'Permissions-Policy başlığı yok; tarayıcı özellik erişimi kısıtlanmıyor.', how: 'HTTPS yanıt başlıkları incelendi; Permissions-Policy gözlenmedi.', fix: 'Kullanılmayan özellikleri kapatan bir `Permissions-Policy` ekleyin (ör. `geolocation=(), camera=(), microphone=()`).' },
    { desc: 'No Permissions-Policy header; browser feature access is unrestricted.', how: 'HTTPS response headers inspected; no Permissions-Policy observed.', fix: 'Add a `Permissions-Policy` disabling unused features (e.g. `geolocation=(), camera=(), microphone=()`).' }),
  lfi: D(
    { desc: 'Bir dosya/yol parametresi sunucu dosya sistemine yol geçişine (../) izin veriyor göstergesi.', how: 'Kademeli, zararsız probla (önce tek `../`, sinyal varsa derin) yanıtta bilinen dosya İMZASI (ör. `root:x:0:0:`) arandı — içerik DÖKÜLMEZ, dosya çekilmez/saklanmaz; yalnız imza gözlemi.', fix: 'Kullanıcı girdisini dosya yoluna koymayın; allowlist + `basename` + kök-dizin hapsi (chroot/realpath) uygulayın.' },
    { desc: 'Indicator that a file/path parameter allows filesystem path traversal (../).', how: 'A staged, harmless probe (single `../` first, deeper only if a signal appears) looked for a known file SIGNATURE (e.g. `root:x:0:0:`) in the response — content is NOT dumped, no file retrieved/stored; signature observation only.', fix: 'Never place user input in file paths; use an allowlist + `basename` + root-dir confinement (chroot/realpath).' }),
  ssti: D(
    { desc: 'Girdi bir şablon motorunda değerlendiriliyor göstergesi (SSTI).', how: 'Yansıyan parametreye yalnız aritmetik ifade (`{{7*7}}`/`${7*7}`/`#{7*7}`) gönderildi; çıktıda `49` belirdi — kod/komut ÇALIŞTIRILMADI (yalnız aritmetik gösterge).', fix: 'Kullanıcı girdisini şablona interpolasyonla koymayın; mantıksız-şablon (logic-less) motoru + otomatik kaçış kullanın; sandbox uygulayın.' },
    { desc: 'Indicator that input is evaluated by a template engine (SSTI).', how: 'Only an arithmetic expression (`{{7*7}}`/`${7*7}`/`#{7*7}`) was sent to a reflected parameter and `49` appeared in the output — no code/command executed (arithmetic indicator only).', fix: 'Do not interpolate user input into templates; use a logic-less engine + auto-escaping; apply a sandbox.' }),
  hpp: D(
    { desc: 'Tekrarlanan aynı parametre sunucuda tutarsız işleniyor (HTTP Parameter Pollution).', how: 'Aynı parametre iki kez (`?p=A&p=B`) gönderilip tekil isteklerle karşılaştırıldı; işleniş farkı gözlendi — veri gönderilmedi, salt gözlem.', fix: 'Parametreleri tek-değer olarak normalize edin; sunucu/framework katmanları arası tutarlı ayrıştırma sağlayın.' },
    { desc: 'A duplicated parameter is parsed inconsistently on the server (HTTP Parameter Pollution).', how: 'The same parameter was sent twice (`?p=A&p=B`) and compared with single requests; a parsing difference was observed — no data submitted, observation only.', fix: 'Normalize parameters to a single value; ensure consistent parsing across server/framework layers.' }),
};
// ————— (Almanya /de) Almanca ADDITIVE map'ler — mevcut tr/en tabloları DEĞİŞMEZ; eksikte en fallback.
// P1: sqli/idor İş Etkisi'nde KVKK yerine DSGVO. Profesyonel Almanca güvenlik-rapor terminolojisi.
const FINDING_IMPACT_DE: Partial<Record<FindingType, string>> = {
  clickjacking: 'Die Seite kann unsichtbar in einen Frame eingebettet werden, um Nutzer zu unbeabsichtigten Aktionen zu verleiten (Clickjacking); schwächt Konto- und Transaktionssicherheit.',
  mime_sniffing: 'Der Browser kann Inhaltstypen erraten und schädliche Inhalte ausführen, was die XSS-/Injection-Angriffsfläche vergrößert.',
  csp_missing: 'Keine browserseitige Minderung gegen Content-Injection/XSS; injizierte Skripte können ausgeführt werden.',
  referrer_policy: 'Adress-/Session-Informationen können an externe Links durchsickern; geringfügige Informationspreisgabe.',
  hsts_missing: 'Ohne erzwungenes HTTPS kann der Verkehr per Man-in-the-Middle abgehört/umgeleitet werden.',
  https_missing: 'Die Website antwortet nicht über HTTPS; der gesamte Verkehr wird im KLARTEXT übertragen. Ein Angreifer im selben Netzwerk kann mithören, Sessions/Passwörter stehlen oder Inhalte manipulieren; moderne Browser markieren die Seite als „Nicht sicher“.',
  weak_tls: 'Schwache Cipher-Suites schwächen Vertraulichkeit und Forward Secrecy und ermöglichen Downgrade-Angriffe.',
  weak_key: 'Die Schlüsselgröße begrenzt die langfristige kryptografische Stärke (kurzfristig akzeptabel); bei der Erneuerung verstärken.',
  cert: 'Zertifikatsprobleme brechen die Vertrauenskette und verursachen Browser-Warnungen sowie MITM-Risiko.',
  version_disclosure: 'Versions-/Technologie-Preisgabe hilft Angreifern, bekannte Schwachstellen dieser Komponente gezielt anzugreifen.',
  verbose_error: 'Eine ausführliche Fehlerseite (Stacktrace / Framework-Version / Serverpfad) offenbart die interne Struktur und erleichtert Folgeangriffe.',
  exposed_files: 'Sensible Dateien (Quellcode, Backups, Secrets) sind offengelegt; Risiko der Preisgabe von Zugangsdaten/Geheimnissen.',
  spf: 'Fehlendes/lockeres SPF ermöglicht gefälschte E-Mails von Ihrer Domain (Spoofing/Phishing); Marken- und Betrugsrisiko.',
  dmarc: 'Ohne DMARC-Richtlinie werden gefälschte E-Mails nicht blockiert; Phishing- und Reputationsrisiko.',
  dkim: 'Ohne DKIM-Signatur kann die Integrität ausgehender E-Mails nicht überprüft werden; Spoofing wird erleichtert.',
  dnssec: 'Ohne DNSSEC können DNS-Antworten gefälscht werden, um Nutzer auf schädliche Server umzuleiten.',
  cors: 'Eine lockere CORS-Richtlinie kann anderen Ursprüngen erlauben, Nutzerdaten über credentialisierte Anfragen zu lesen; schwächt Session-/Datensicherheit.',
  cookie_flags: 'Fehlende Cookie-Flags (HttpOnly/Secure/SameSite) ermöglichen Session-Diebstahl per XSS oder Klartext-Leck; Risiko der Kontoübernahme.',
  sqli: 'Unbefugter Zugriff/Änderung von Kunden-/Kontodatensätzen in der Datenbank möglich; Risiko von Datenpanne, **Verstoß gegen die DSGVO** und Vertrauensverlust.',
  xss: 'Durch Ausführen von Skript im Browser des Opfers sind Session-Diebstahl/Identitätsvortäuschung und Kontoübernahme möglich.',
  idor: 'Durch Manipulation eines ID-Parameters kann auf Datensätze anderer Nutzer zugegriffen werden; Risiko massenhafter Datenpreisgabe und eines **Verstoßes gegen die DSGVO**.',
  ssrf: 'Der Server kann gezwungen werden, interne Dienste oder Cloud-Metadaten anzufragen; Risiko interner Preisgabe und lateraler Bewegung.',
  open_redirect: 'Nutzer können über Ihre vertrauenswürdige Domain auf schädliche Seiten umgeleitet werden; Phishing- und Reputationsrisiko.',
  rce: 'Indikator für Befehls-/Codeausführung auf dem Server — höchste Auswirkung: Risiko der vollständigen Systemübernahme und des Datenverlusts.',
  file_upload: 'Uneingeschränkter Upload kann eine schädliche Datei auf dem Server platzieren und ausführen; Risiko der Systemübernahme.',
  business_logic: 'Manipulation von Workflow/Autorisierung (z. B. Schritt-Überspringen, clientseitige Wert-Manipulation, unbefugte Aktion) kann den Geschäftsprozess oder die Datenintegrität schädigen; bei einem Finanz-/Transaktionsfluss kann ein finanzieller Verlust entstehen.',
  race: 'Eine Race Condition kann Einmal-Vorgänge (Gutscheine/Guthaben) doppelt verarbeiten; direktes Risiko finanziellen Verlusts.',
  forced_browsing: 'Ein unbefugter Nutzer kann Admin-/versteckte Endpunkte erreichen; Risiko unbefugter Datenansicht/-änderung und Insider-Missbrauch.',
  weak_logout: 'Bleibt die Session nach dem Logout gültig, kann eine gestohlene/geteilte Session wiederverwendet werden; Kontoübernahme auf gemeinsam genutzten Geräten.',
  session_fixation: 'Ein Angreifer kann die Session-ID fixieren und die Session des Opfers übernehmen.',
  jwt: 'Ein schwaches/unsigniertes (alg=none) JWT kann Rechteausweitung oder Identitätsvortäuschung ermöglichen.',
  privilege_escalation: 'Ein Standardnutzer kann seine Rechte überschreiten und privilegierte Aktionen ausführen; Risiko von Insider-Missbrauch und Datengefährdung.',
  login_bypass: 'Eine Umgehung der Authentifizierung kann unbefugten Zugriff ermöglichen; Konto- und Datensicherheit direkt gefährdet.',
  exposed_api_docs: 'Offengelegte API-Dokumentation zeigt die Angriffsfläche und das Endpunkt-Schema und erleichtert gezielte Angriffe.',
  staging_exposure: 'Eine im Internet erreichbare Staging-/Altumgebung ist weniger geschützt und birgt Risiken der Datenpreisgabe und eines Brückenkopfs.',
  stale_subdomain: 'Ein nicht gewartetes/vergessenes Asset kann mangels Patches bekannten Schwachstellen ausgesetzt sein.',
  outdated_component: 'Eine veraltete Komponente ist bekannten CVEs ausgesetzt; Risiko gezielter Angriffe.',
  subdomain_takeover: 'Eine auf eine „dangling“ Ressource zeigende Subdomain kann von einem Angreifer übernommen werden; Phishing- und Reputationsrisiko.',
  csrf: 'Fehlendes Anti-CSRF-Token / SameSite; über die Nutzer-Session können unbeabsichtigte Aktionen ausgelöst werden (CSRF).',
  session_in_url: 'Die Session-ID wird in der URL übertragen; sie kann über Verlauf, Referrer und Logs durchsickern und Session-Diebstahl ermöglichen.',
  weak_session: 'Die Session-ID erscheint schwach/vorhersehbar, was das Risiko der Session-Übernahme erhöht.',
  user_enum: 'Die Anwendung unterscheidet gültige/ungültige Nutzer durch abweichende Antworten; ermöglicht Konto-Enumeration und gezielte Angriffe.',
  default_creds: 'Indikator, dass Standard-/schwache Zugangsdaten akzeptiert werden; kann zu direktem unbefugtem Zugriff führen.',
  no_lockout: 'Keine Sperrung/Drosselung nach wiederholt fehlgeschlagenen Anmeldungen beobachtet; anfällig für Brute-Force.',
  weak_pw_policy: 'Indikator für schwache Passwortrichtlinie (kurze/gängige Passwörter akzeptiert); erhöht das Risiko der Kontoübernahme.',
  weak_pw_reset: 'Schwäche-Indikator im Passwort-Reset-Flow (erratbares Token / Nutzerpreisgabe); Risiko der Kontoübernahme.',
  host_header: 'Indikator, dass der Host-Header in Antworten/Logik reflektiert wird; kann Reset-Poisoning und Cache-Poisoning ermöglichen.',
  http_method: 'Indikator für unnötige/gefährliche HTTP-Methoden (TRACE/PUT/DELETE); vergrößert die Angriffsfläche.',
  web_cache: 'Indikator, dass sensible Antworten cachebar sind / unkeyed Header-Reflexion; Cache-Poisoning oder Datenleck.',
  comment_leak: 'Interne Informationen (TODO, interne IP, Pfade) durchsickern über HTML-/JS-Kommentare oder Metadaten; erleichtert die Angreifer-Aufklärung.',
  mixed_content: 'HTTP-Ressourcen auf einer HTTPS-Seite geladen (Mixed Content); MITM-Injection/-Abhören und Browser-Warnungen.',
  cloud_exposure: 'Ein auflistbarer Cloud-Storage-Bucket kann sensible Dateien offenlegen; Risiko der Datenpreisgabe.',
  caa: 'Ohne CAA-Eintrag kann jede beliebige Zertifizierungsstelle ein Zertifikat für Ihre Domain ausstellen; erhöht das Missbrauchsrisiko.',
  mta_sts: 'Ohne durchgesetztes MTA-STS kann die E-Mail-Übertragung auf unverschlüsselte Verbindungen herabgestuft werden.',
  client_storage: 'Sensible Daten im Client-Storage (localStorage/sessionStorage) sind per XSS/geteiltem Gerät zugänglich; Risiko der Datenpreisgabe.',
  postmessage: 'Unsicherer postMessage-Origin (Wildcard) kann das Lesen/Einschleusen von Daten durch andere Ursprünge ermöglichen.',
  sri: 'Fehlende Subresource Integrity (SRI); ein kompromittiertes Drittanbieter-Skript kann unbemerkt schädlichen Code ausführen.',
  tabnabbing: 'Reverse Tabnabbing (kein rel=noopener); die geöffnete Seite kann die ursprüngliche Registerkarte auf eine Phishing-Seite umleiten.',
  excessive_data: 'Übermäßige Datenpreisgabe über die API (BOPLA); mehr Felder als nötig werden zurückgegeben, was das Datenleck-Risiko erhöht.',
  rate_limit: 'Kein API-Rate-Limit; anfällig für Brute-Force, Enumeration und Ressourcenerschöpfung.',
  shadow_api: 'Eine Shadow-/veraltete API-Version kann ungepatchte Schwachstellen enthalten; erweitert die Angriffsfläche.',
  graphql_introspection: 'Aktivierte GraphQL-Introspection legt das gesamte Schema offen und erleichtert gezielte Angriffe.',
  csp_weak: 'Schwache CSP (unsafe-inline/eval); die XSS-Minderung ist wirkungslos, injizierte Skripte können ausgeführt werden.',
  permissions_policy: 'Fehlende Permissions-Policy; Browser-Funktionen (Kamera/Mikrofon/Geolokalisierung) sind nicht eingeschränkt.',
  lfi: 'Path-Traversal-/LFI-Indikator; es kann auf Dateien außerhalb des vorgesehenen Verzeichnisses zugegriffen werden (Serverdateien/Secrets).',
  ssti: 'Template-Injection-(SSTI)-Indikator; kann bis zu serverseitiger Codeausführung eskalieren.',
  hpp: 'HTTP Parameter Pollution (HPP); doppelte Parameter werden inkonsistent geparst und können Sicherheitskontrollen umgehen.',
};
const FRIENDLY_LABEL_DE: Partial<Record<FindingType, string>> = {
  clickjacking: 'Fehlendes X-Frame-Options (Clickjacking)', mime_sniffing: 'Fehlendes X-Content-Type-Options', csp_missing: 'Fehlende Content-Security-Policy',
  referrer_policy: 'Fehlende Referrer-Policy', hsts_missing: 'Fehlendes HSTS', https_missing: 'HTTPS nicht unterstützt (Klartext-Übertragung)',
  weak_tls: 'Schwache TLS-Cipher-Konfiguration', weak_key: 'Schwache Zertifikat-Schlüsselgröße', cert: 'Zertifikat-Konfigurationsproblem',
  version_disclosure: 'Versions-/Technologie-Preisgabe', verbose_error: 'Informationspreisgabe durch ausführliche Fehlerseite', exposed_files: 'Offengelegte sensible Datei',
  spf: 'Fehlender/schwacher SPF-Eintrag', dmarc: 'Unzureichende DMARC-Richtlinie (fehlend oder schwach)', dkim: 'Fehlende DKIM-Signatur', dnssec: 'DNSSEC nicht aktiviert',
  cors: 'Lockere CORS-Konfiguration', cookie_flags: 'Fehlende Cookie-Sicherheits-Flags', sqli: 'SQL-Injection-Indikator', xss: 'Reflected-XSS-Indikator',
  idor: 'IDOR-Indikator', ssrf: 'SSRF-Indikator', open_redirect: 'Open Redirect', rce: 'Befehls-/Codeausführungs-Indikator', file_upload: 'Indikator für uneingeschränkten Datei-Upload',
  business_logic: 'Geschäftslogik-/Autorisierungs-Indikator (erweiterte Analyse)', race: 'Race-/Mass-Assignment-Indikator', forced_browsing: 'Unbefugter Endpunkt-Zugriff (Forced Browsing)',
  weak_logout: 'Schwache Session-Invalidierung', session_fixation: 'Session Fixation', jwt: 'JWT-/Token-Sicherheitsindikator', privilege_escalation: 'Rechteausweitungs-Indikator',
  login_bypass: 'Authentifizierungs-Bypass-Indikator', exposed_api_docs: 'Offengelegte API-Dokumentation', staging_exposure: 'Im Internet erreichbare Staging-Umgebung',
  stale_subdomain: 'Nicht gewartete Subdomain', outdated_component: 'Veraltete Komponente (CVE)', subdomain_takeover: 'Subdomain-Takeover-Risiko',
  csrf: 'Fehlender CSRF-Schutz', session_in_url: 'Session-ID in der URL', weak_session: 'Schwache Session-ID-Entropie', user_enum: 'Nutzer-Enumeration-Indikator',
  default_creds: 'Standard-Zugangsdaten-Indikator', no_lockout: 'Keine Kontosperrung / kein Brute-Force-Schutz', weak_pw_policy: 'Schwache Passwortrichtlinie', weak_pw_reset: 'Schwacher Passwort-Reset-Flow',
  host_header: 'Host-Header-Injection-Indikator', http_method: 'Gefährliche HTTP-Methode aktiviert', web_cache: 'Web-Cache-/sensibles Caching-Indikator', comment_leak: 'Informationsleck durch Kommentar/Metadaten',
  mixed_content: 'Mixed Content (HTTP-Ressource)', cloud_exposure: 'Auflistbarer Cloud-Storage-Bucket', caa: 'Fehlender CAA-Eintrag', mta_sts: 'MTA-STS nicht durchgesetzt',
  client_storage: 'Sensible Daten im Client-Storage', postmessage: 'Unsicherer postMessage-Origin', sri: 'Fehlende Subresource Integrity (SRI)', tabnabbing: 'Reverse Tabnabbing (kein rel=noopener)',
  excessive_data: 'Übermäßige Datenpreisgabe (API/BOPLA)', rate_limit: 'Kein API-Rate-Limit', shadow_api: 'Shadow-/veraltete API-Version', graphql_introspection: 'GraphQL-Introspection aktiviert',
  csp_weak: 'Schwache CSP (unsafe-inline/eval)', permissions_policy: 'Fehlende Permissions-Policy', lfi: 'Path-Traversal-/LFI-Indikator', ssti: 'Template-Injection-(SSTI)-Indikator', hpp: 'HTTP Parameter Pollution (HPP)',
};
const FINDING_DETAIL_DE: Partial<Record<FindingType, Detail>> = {
  clickjacking: { desc: 'Die Seite kann in einen iframe einer anderen Website eingebettet werden (kein X-Frame-Options / CSP frame-ancestors).', how: 'Antwort-Header geprüft; weder X-Frame-Options noch CSP frame-ancestors beobachtet.', fix: 'Fügen Sie `X-Frame-Options: SAMEORIGIN` hinzu oder setzen Sie CSP `frame-ancestors \'self\'`.' },
  mime_sniffing: { desc: 'Kein X-Content-Type-Options; der Browser kann den Inhaltstyp erraten (MIME-Sniffing).', how: 'Kein `nosniff` in den Headern beobachtet.', fix: 'Fügen Sie `X-Content-Type-Options: nosniff` hinzu.' },
  csp_missing: { desc: 'Keine Content-Security-Policy; keine browserseitige XSS-Minderung.', how: 'Kein CSP-Header beobachtet.', fix: 'Definieren Sie eine strikte CSP (`default-src \'self\'`) und setzen Sie Drittanbieter-Quellen auf eine Allowlist.' },
  referrer_policy: { desc: 'Keine Referrer-Policy; die vollständige URL kann an externe Links durchsickern.', how: 'Keine Referrer-Policy beobachtet.', fix: 'Fügen Sie `Referrer-Policy: strict-origin-when-cross-origin` hinzu.' },
  hsts_missing: { desc: 'Kein HSTS; der Browser wird nicht auf HTTPS gezwungen.', how: 'Kein Strict-Transport-Security beobachtet.', fix: 'Fügen Sie `Strict-Transport-Security: max-age=31536000; includeSubDomains` hinzu (wenn vollständig HTTPS).' },
  https_missing: { desc: 'Die Website antwortet nicht über HTTPS; die Kommunikation läuft über unverschlüsseltes HTTP.', how: 'Zu Port 443 (HTTPS) konnte keine sichere Verbindung aufgebaut werden; nur Port 80 (HTTP) antwortete. Der Scan erfolgte über http://.', fix: 'Installieren Sie ein gültiges TLS-Zertifikat (kostenlos: Let’s Encrypt), leiten Sie allen HTTP-Verkehr dauerhaft (301) auf HTTPS um und fügen Sie den HSTS-Header hinzu.' },
  weak_tls: { desc: 'Der Server akzeptiert schwache/veraltete TLS-Cipher.', how: 'TLS-Handshake geprüft; schwache Cipher / veraltetes Protokoll beobachtet.', fix: 'Lassen Sie nur TLS 1.2+ Forward-Secret-AEAD-Suites zu; deaktivieren Sie CBC/3DES/RSA-kex.' },
  weak_key: { desc: 'Die Zertifikat-Schlüsselgröße ist für die lange Frist begrenzt.', how: 'Zertifikat geprüft; Schlüsselgröße erfasst.', fix: 'Verwenden Sie bei der Erneuerung ≥2048-Bit-RSA oder ECDSA P-256.' },
  cert: { desc: 'Zertifikat-Konfigurationsproblem (Gültigkeit/Hostname/Kette).', how: 'Gültigkeit, Hostname-Übereinstimmung und Kette beobachtet.', fix: 'Verwenden Sie ein gültiges, den Hostnamen abdeckendes Zertifikat mit vollständiger Kette; automatisieren Sie die Erneuerung (ACME).' },
  version_disclosure: { desc: 'Server-/Technologie-Version wird über Header oder Seite preisgegeben.', how: 'Server- / X-Powered-By-Header und Seitensignaturen geprüft.', fix: 'Verbergen Sie Versions-Header (`server_tokens off`, X-Powered-By entfernen).' },
  verbose_error: { desc: 'Bei fehlerhafter/unerwarteter Eingabe liefert die App eine ausführliche Fehlerseite, die Framework-Version, Serverpfad oder Stacktrace preisgibt.', how: 'Der bei Verifizierungsprüfungen zurückgegebene Fehlerantwort-KÖRPER wurde auf Framework-Fehlerseiten-Signaturen (z. B. „Server Error in“, „.NET Framework Version“, physischer Pfad, Stacktrace) durchsucht — aus der ECHTEN Antwort.', fix: 'Deaktivieren Sie ausführliche Fehler in Produktion (z. B. ASP.NET `<customErrors mode="On" />`; PHP `display_errors=Off`); zeigen Sie eine generische Fehlerseite und protokollieren Sie Details nur serverseitig.' },
  exposed_files: { desc: 'Eine sensible Datei (.git/.env/Backup) ist offengelegt.', how: 'Gängige sensible Pfade mit einem einzigen GET geprüft; eine echte, von der Startseite abweichende Datei beobachtet.', fix: 'Blockieren Sie diese Pfade; verschieben Sie Quell-/Backup-/Secret-Dateien aus dem Web-Root.' },
  spf: { desc: 'SPF-Eintrag fehlt oder ist locker (~all/?all).', how: 'TXT/SPF-Eintrag der Domain abgefragt.', fix: 'Veröffentlichen Sie ein striktes SPF mit `-all`.' },
  dmarc: { desc: 'Kein DMARC; SPF/DKIM werden nicht durchgesetzt.', how: '`_dmarc` TXT-Eintrag abgefragt; nicht gefunden.', fix: 'Veröffentlichen Sie `_dmarc` `v=DMARC1; p=quarantine` (mit Monitoring beginnen, dann auf reject erhöhen).' },
  dkim: { desc: 'Auf gängigen Selektoren kein DKIM gefunden.', how: 'Gängige DKIM-Selektoren abgefragt.', fix: 'Erzeugen Sie DKIM bei Ihrem Anbieter und fügen Sie den `selector._domainkey` TXT-Eintrag hinzu.' },
  dnssec: { desc: 'DNSSEC nicht aktiviert; DNS-Antworten unsigniert.', how: 'DNSSEC/DS-Status der Domain abgefragt.', fix: 'Aktivieren Sie DNSSEC und fügen Sie den DS-Eintrag beim Registrar hinzu.' },
  cors: { desc: 'Lockeres CORS kann credentialisierten Cross-Origin-Zugriff erlauben.', how: 'Anfrage mit einem Test-Origin gesendet; Access-Control-Allow-Origin/Credentials beobachtet.', fix: 'Setzen Sie Ursprünge auf eine Allowlist; verwenden Sie mit Credentials niemals Wildcards.' },
  cookie_flags: { desc: 'Dem Session-Cookie fehlen die Flags Secure/HttpOnly/SameSite.', how: 'Sicherheits-Flags echter Session-Cookies geprüft (Analyse-Cookies ausgeschlossen).', fix: 'Fügen Sie Session-Cookies `HttpOnly; Secure; SameSite` hinzu.' },
  sqli: { desc: 'Eine Eingabe erreicht eine DB-Abfrage (Injection-Indikator).', how: 'Ein einziger harmloser Marker (einfaches Anführungszeichen / zeitbasierte Prüfung) wurde gesendet; eine DB-Fehlersignatur oder Timing-Abweichung wurde beobachtet. Keine Daten extrahiert/ausgenutzt.', fix: 'Verwenden Sie parametrisierte Abfragen / Prepared Statements; verbergen Sie DB-Fehlermeldungen.' },
  xss: { desc: 'Nutzereingabe wird unkodiert im HTML reflektiert (Reflected-XSS-Indikator).', how: 'Ein eindeutiger harmloser Marker wurde injiziert und unescaped reflektiert beobachtet (kein JS ausgeführt).', fix: 'Kodieren Sie die Ausgabe kontextabhängig (HTML-Entity-Encoding); beschränken Sie Inline-Skripte per CSP.' },
  idor: { desc: 'Signal, dass das Ändern einer ID einen anderen Datensatz erreicht.', how: 'ID auf einen Nachbarwert geändert und angefragt; eine andere/gültige Ressource wurde beobachtet (Inhalt nicht gespeichert).', fix: 'Erzwingen Sie Autorisierung auf Objektebene; verwenden Sie UUIDs statt vorhersehbarer IDs.' },
  ssrf: { desc: 'Ein serverseitiger Fetch-Parameter kann interne Ressourcen erreichen (Indikator).', how: 'Eine kontrollierte, verzögerte Echo-URL wurde bereitgestellt; eine Timing-Abweichung wurde beobachtet. Internes/Metadaten wurden nie angesprochen.', fix: 'Wenden Sie serverseitige Allowlist + Blockierung interner Netze an; validieren Sie Schema/Host.' },
  open_redirect: { desc: 'Ein Redirect-Parameter kann Nutzer auf externe Adressen senden.', how: 'Ein kontrollierter Marker wurde bereitgestellt; eine Umleitung auf ein externes Ziel wurde angezeigt.', fix: 'Beschränken Sie Weiterleitungen auf eine interne Allowlist; leiten Sie niemals auf eine vom Nutzer angegebene vollständige URL um.' },
  rce: { desc: 'Ein Parameter kann Befehls-/Codeausführung erreichen (zeitbasierter Indikator).', how: 'Nur eine harmlose zeitbasierte Verzögerungsprüfung (sleep) wurde gesendet; eine Timing-Abweichung wurde beobachtet. Kein echter Befehl ausgeführt.', fix: 'Überprüfen Sie befehlsaufrufende Pfade; setzen Sie Eingaben auf eine Allowlist, vermeiden Sie Shell-Verkettung; minimale Rechte.' },
  file_upload: { desc: 'Der Datei-Upload erscheint uneingeschränkt (Indikator).', how: 'Eine einzelne harmlose, nicht ausführbare Testdatei wurde gesendet; nur Annahme/Ablehnung beobachtet (Datei nicht abgerufen).', fix: 'Wenden Sie serverseitige Typ-/MIME-Validierung + Allowlist + Speicherung außerhalb des Web-Roots an.' },
  business_logic: { desc: 'Ein zu prüfender Workflow-/Autorisierungs-Indikator (z. B. clientseitig editierbarer Preis / Schritt-Überspringen).', how: 'Oberfläche beobachtend geprüft (nur GET); keine zustandsändernde Anfrage gesendet.', fix: 'Validieren Sie kritische Werte (Preis/Menge/Rolle) serverseitig; erzwingen Sie Schritt-Vorbedingungen serverseitig.' },
  race: { desc: 'Concurrency-/Mass-Assignment-Indikator (geringe Konfidenz).', how: 'Eine einzelne beobachtende Anfrage wurde gestellt; kein wiederholter/Race-Test gegen verbrauchbare Ressourcen ausgeführt.', fix: 'Gestalten Sie kritische Operationen atomar/idempotent; wenden Sie beim Model-Binding eine Feld-Allowlist an.' },
  forced_browsing: { desc: 'Ein Admin-/versteckter Endpunkt ist mit einer niedrig privilegierten Session erreichbar.', how: 'Gängige Admin-Endpunkte wurden mit der Session per GET angefragt; eine von der Startseite abweichende 200/JSON wurde beobachtet (zurückgegebene Daten nicht berichtet).', fix: 'Erzwingen Sie serverseitige Rollen-/Autorisierungsprüfung an jedem sensiblen Endpunkt; UI-Verbergen genügt nicht.' },
  weak_logout: { desc: 'Die Session wird nach dem Logout serverseitig nicht invalidiert.', how: 'Nach dem Logout wurde mit DERSELBEN Session der Zugriff auf einen geschützten Endpunkt versucht und war weiterhin erfolgreich.', fix: 'Invalidieren Sie die Session beim Logout serverseitig (Revocation/Ablauf).' },
  session_fixation: { desc: 'Die Session-ID wird beim Login nicht erneuert (Fixation-Indikator).', how: 'Session-Cookie-Wert vor/nach dem Login verglichen.', fix: 'Erneuern Sie die Session-ID beim Login (Session-Regeneration).' },
  jwt: { desc: 'Sicherheitsindikator in der JWT-/Token-Konfiguration (alg=none / schwaches Secret / übermäßige Claims).', how: 'Token OFFLINE dekodiert; Algorithmus, Secret-Stärke und Claims geprüft.', fix: 'Fixieren Sie den Signaturalgorithmus, verwenden Sie ein starkes Secret, fügen Sie `exp` hinzu, vermeiden Sie sensible Claims.' },
  privilege_escalation: { desc: 'Indikator, dass ein Standardnutzer seine Rechte überschreiten könnte (Mass-Assignment usw.).', how: 'Die authentifizierte Oberfläche wurde geprüft; das Backend wendete eine sichere, beobachtende Prüfung an (keine echte Ausweitung).', fix: 'Akzeptieren Sie Rollen-/Autorisierungsfelder nicht vom Client; wenden Sie eine Feld-Allowlist an.' },
  login_bypass: { desc: 'Auth-Bypass-Indikator über einen klassischen SQLi-Payload im Login-Formular.', how: 'Zuerst ungültige Zugangsdaten, dann ein `\' OR 1=1--`-artiger Marker; entgegen der Kontrolle wurde eine Erfolgs-/Session-Antwort beobachtet. Keine Session gekapert.', fix: 'Verwenden Sie in der Authentifizierung parametrisierte Abfragen; validieren Sie Eingaben; geben Sie einheitliche Fehlermeldungen zurück.' },
  exposed_api_docs: { desc: 'Öffentliche API-Dokumentation (Swagger/OpenAPI) gefunden.', how: 'Gängige Doku-Pfade per GET geprüft; eine Schema-/UI-Antwort beobachtet (Endpunkte nicht aufgerufen).', fix: 'Stellen Sie Schema-Endpunkte in Produktion hinter Auth/IP-Beschränkung; deaktivieren Sie GraphQL-Introspection.' },
  staging_exposure: { desc: 'Eine im Internet erreichbare Staging-/Testumgebung wurde beobachtet.', how: 'Subdomain/Endpunkt beobachtet; Nicht-Produktions-Indikator erfasst.', fix: 'Beschränken Sie Staging per IP/Auth oder nehmen Sie es aus dem Internet.' },
  stale_subdomain: { desc: 'Eine nicht gewartete/vergessene Subdomain wurde beobachtet.', how: 'Certificate Transparency + DNS-Einträge passiv gesammelt.', fix: 'Bereinigen Sie ungenutzte CNAME-/Einträge; führen Sie ein Subdomain-Inventar.' },
  outdated_component: { desc: 'Fingerabdruck einer veralteten Komponente/eines CMS und mögliche bekannte CVE.', how: 'HTTP-Header / Meta-Generator / HTML-Spuren passiv geprüft; Version mit NVD abgeglichen (keine CVE ausgenutzt).', fix: 'Halten Sie Komponenten/Plugins/Themes aktuell; ergänzen Sie Auto-Update + Dependency-Scanning.' },
  subdomain_takeover: { desc: 'Indikator für eine übernehmbare (dangling) Subdomain.', how: 'Subdomain-CNAMEs aufgelöst und mit Signaturen aufgegebener Cloud-Ressourcen verglichen.', fix: 'Entfernen Sie den DNS-Eintrag, bevor Sie die Cloud-Ressource löschen; bereinigen Sie dangling CNAMEs.' },
  csrf: { desc: 'Kein Anti-CSRF-Token bei einer zustandsändernden Anfrage und/oder Cookie ist nicht SameSite.', how: 'POST-Formulare und Session-Cookies geprüft; kein Anti-CSRF-Token / SameSite beobachtet (nicht ausgenutzt).', fix: 'Fügen Sie zustandsändernden Anfragen Anti-CSRF-Tokens hinzu; setzen Sie `SameSite=Lax/Strict` auf Session-Cookies.' },
  session_in_url: { desc: 'Die Session-ID wird in einem URL-Parameter übertragen.', how: 'Ein Session-ID-Muster in URLs/Links beobachtet (Wert geschwärzt).', fix: 'Übertragen Sie die Session-ID nur in einem HttpOnly-Cookie; entfernen Sie sie aus URLs.' },
  weak_session: { desc: 'Die Session-ID erscheint schwach/vorhersehbar.', how: 'Länge/Zeichenraum der Session-ID beobachtet (JWT ausgeschlossen); Niedrig-Entropie-Indikator.', fix: 'Erzeugen Sie kryptografisch starke, ≥128-Bit zufällige Session-IDs.' },
  user_enum: { desc: 'Gültige/ungültige Nutzer lassen sich durch abweichende Antworten unterscheiden.', how: 'Antwort-/Timing-Unterschied mit einem nicht existierenden vs. einem wahrscheinlichen (Wegwerf-)Nutzer beobachtet; kein Konto gesperrt.', fix: 'Geben Sie über Login/Reset/Registrierung einheitliche Antworten und Timings zurück.' },
  default_creds: { desc: 'Indikator, dass Standard-/schwache Zugangsdaten akzeptiert werden.', how: 'Ein kleines Wegwerf-Standardpaar wurde probiert; ein Erfolgsindikator wurde beobachtet (nicht ausgenutzt).', fix: 'Entfernen/deaktivieren Sie Standardkonten; erzwingen Sie beim ersten Setup ein starkes Passwort.' },
  no_lockout: { desc: 'Nach wiederholt fehlgeschlagenen Anmeldungen keine Sperrung/Drosselung beobachtet.', how: 'Geringvolumige fehlgeschlagene Anmeldungen mit einem Wegwerf-Nutzer; keine Sperrung/Verzögerung beobachtet (kein echtes Konto gesperrt).', fix: 'Fügen Sie pro Konto+IP progressive Verzögerung/Sperrung und CAPTCHA hinzu.' },
  weak_pw_policy: { desc: 'Indikator für schwache Passwortrichtlinie (kurze/gängige Passwörter akzeptiert).', how: 'Richtliniensignale im Registrierungs-/Passwort-Flow beobachtet (kein echtes Konto erstellt).', fix: 'Erzwingen Sie Mindestlänge + Sperrliste gängiger Passwörter (NIST 800-63B).' },
  weak_pw_reset: { desc: 'Schwäche-Indikator im Passwort-Reset (Nutzerpreisgabe / erratbares Token).', how: 'Reset-Flow per GET/Beobachtung geprüft; keine echte Reset-E-Mail ausgelöst.', fix: 'Einheitliche Antworten + Token mit hoher Entropie, kurzer Lebensdauer und Einmalgebrauch.' },
  host_header: { desc: 'Indikator, dass der Host-Header in Antworten/Logik reflektiert wird.', how: 'Eine einzelne sichere Anfrage mit alternativem Host-Header; Reflexion beobachtet (kein Poisoning).', fix: 'Validieren Sie den Host gegen eine Allowlist; verwenden Sie für absolute URLs eine vertrauenswürdige feste Domain.' },
  http_method: { desc: 'Indikator für aktivierte unnötige/gefährliche HTTP-Methoden (TRACE/PUT/DELETE).', how: 'Erlaubte Methoden per OPTIONS aufgezählt / TRACE beobachtet (keine zustandsändernde Methode aufgerufen).', fix: 'Erlauben Sie nur benötigte Methoden; deaktivieren Sie TRACE und ungenutzte WebDAV-Methoden.' },
  web_cache: { desc: 'Sensible Antworten sind cachebar oder es gibt unkeyed Header-Reflexion.', how: 'Cache-Control/Antwort beobachtet; eine einzelne sichere Prüfung auf unkeyed Reflexion (kein Poisoning).', fix: 'Setzen Sie `Cache-Control: no-store` auf sensible Antworten; nehmen Sie relevante Header in den Cache-Key auf.' },
  comment_leak: { desc: 'Interne Informationen (TODO/interne IP/Pfad) durchsickern über HTML-/JS-Kommentare oder Metadaten.', how: 'Seiten-/JS-Kommentare passiv gescannt; Muster interner Informationen beobachtet.', fix: 'Entfernen Sie Kommentare/Metadaten aus der Produktionsausgabe (Minify + Comment-Strip).' },
  mixed_content: { desc: 'Ressourcen werden auf einer HTTPS-Seite über HTTP geladen (Mixed Content).', how: 'Ressourcen der HTTPS-Seite passiv geprüft; eine `http://`-Unterressource beobachtet.', fix: 'Verschieben Sie alle Unterressourcen auf HTTPS; fügen Sie die CSP-Direktive `upgrade-insecure-requests` hinzu.' },
  cloud_exposure: { desc: 'Referenzierter öffentlicher Cloud-Storage (S3/GCS/Azure) erscheint auflistbar.', how: 'Sicherer GET auf den referenzierten Bucket; eine Directory-Listing-Antwort beobachtet.', fix: 'Deaktivieren Sie das Bucket-Listing; machen Sie Objekte privat; entfernen Sie unnötigen öffentlichen Zugriff.' },
  caa: { desc: 'Kein CAA-Eintrag; jede beliebige CA kann Zertifikate ausstellen.', how: 'CAA-Eintrag der Org-Domain abgefragt; nicht gefunden.', fix: 'Beschränken Sie autorisierte CAs mit einem `CAA`-Eintrag (z. B. `0 issue "letsencrypt.org"`).' },
  mta_sts: { desc: 'MTA-STS wird nicht durchgesetzt; anfällig für SMTP-Downgrade.', how: '`_mta-sts` TXT + Policy-Datei (einzelner sicherer GET) gelesen; Modus nicht enforce.', fix: 'Setzen Sie die MTA-STS-Policy auf `mode: enforce`; aktivieren Sie Reporting via TLS-RPT.' },
  client_storage: { desc: 'Sensible Daten (Token/Session) werden in localStorage/sessionStorage geschrieben.', how: 'Client-JS statisch gescannt; ein `storage.setItem`-Schreibvorgang mit sensiblem Schlüssel beobachtet (Wert geschwärzt).', fix: 'Bewahren Sie das Session-Token in einem `HttpOnly + Secure`-Cookie statt in localStorage auf.' },
  postmessage: { desc: 'Indikator für fehlende Origin-Validierung in einem postMessage-Handler.', how: 'Client-JS statisch gescannt; ein `message`-Handler ohne Origin-Prüfung beobachtet.', fix: 'Validieren Sie `event.origin` in `message`-Handlern gegen eine strikte Allowlist.' },
  sri: { desc: 'Externes Skript wird ohne Subresource Integrity (SRI) geladen.', how: 'Externe `<script>`-Tags geprüft; kein `integrity`-Attribut beobachtet.', fix: 'Fügen Sie externen Skripten/Styles `integrity` + `crossorigin` (SRI)-Hashes hinzu.' },
  tabnabbing: { desc: 'Einem `target=_blank`-Link fehlt `rel=noopener` (Reverse Tabnabbing).', how: 'Externe Links statisch geprüft; ein `_blank` ohne `noopener/noreferrer` beobachtet.', fix: 'Fügen Sie `target=_blank`-Links `rel="noopener noreferrer"` hinzu.' },
  excessive_data: { desc: 'Die API-Antwort gibt übermäßige/sensible Felder zurück (Passwort-Hash/Rolle/interne ID).', how: 'Ein sensibler/übermäßiger Feldname wurde in einer echten API-Antwort beobachtet (Wert geschwärzt).', fix: 'Begrenzen Sie Antworten mit einer Feld-Allowlist (Response-DTO); senden Sie sensible Felder niemals.' },
  rate_limit: { desc: 'Kein Rate-Limit/Kontingent am API-Endpunkt beobachtet.', how: 'Nach einem MODERATEN Burst (kein DoS) kein 429/Rate-Limit-Header beobachtet; Ziel nicht belastet.', fix: 'Fügen Sie Rate-Limit + Kontingent pro Konto+IP+Endpunkt hinzu; kostenbasierte Limits auf schweren Endpunkten.' },
  shadow_api: { desc: 'Alte/Shadow-API-Versionen (v1/v2) gleichzeitig erreichbar.', how: 'Sicherer GET auf Versions-Endpunkte; mehrere Nicht-Shell-JSON-Versionen beobachtet.', fix: 'Deaktivieren/entfernen Sie ungenutzte/alte API-Versionen; führen Sie ein Versions-Inventar.' },
  graphql_introspection: { desc: 'GraphQL-Introspection ist offen; das vollständige Schema wird preisgegeben.', how: 'Eine schreibgeschützte Introspection-Abfrage an den GraphQL-Endpunkt gab das Schema zurück (keine Daten geändert).', fix: 'Deaktivieren Sie Introspection in Produktion; fügen Sie Query-Tiefen-/Komplexitätslimits hinzu.' },
  csp_weak: { desc: 'Eine Content-Security-Policy ist vorhanden, trägt aber permissive Direktiven wie `unsafe-inline`/`unsafe-eval`/`*`.', how: 'CSP-Header geparst; schwächende Direktive(n) beobachtet.', fix: 'Entfernen Sie unsafe-inline/unsafe-eval; verwenden Sie eine nonce-/hash-basierte Skript-Policy; setzen Sie Quellen auf eine Allowlist.' },
  permissions_policy: { desc: 'Kein Permissions-Policy-Header; der Browser-Feature-Zugriff ist unbeschränkt.', how: 'HTTPS-Antwort-Header geprüft; keine Permissions-Policy beobachtet.', fix: 'Fügen Sie eine `Permissions-Policy` hinzu, die ungenutzte Funktionen deaktiviert (z. B. `geolocation=(), camera=(), microphone=()`).' },
  lfi: { desc: 'Indikator, dass ein Datei-/Pfadparameter Path-Traversal (../) im Dateisystem erlaubt.', how: 'Eine gestufte, harmlose Prüfung (zuerst einzelnes `../`, tiefer nur bei einem Signal) suchte im Response nach einer bekannten Datei-SIGNATUR (z. B. `root:x:0:0:`) — Inhalt wird NICHT ausgegeben, keine Datei abgerufen/gespeichert; nur Signaturbeobachtung.', fix: 'Fügen Sie Nutzereingaben niemals in Dateipfade ein; verwenden Sie eine Allowlist + `basename` + Wurzelverzeichnis-Einschluss (chroot/realpath).' },
  ssti: { desc: 'Indikator, dass Eingaben von einer Template-Engine ausgewertet werden (SSTI).', how: 'Nur ein arithmetischer Ausdruck (`{{7*7}}`/`${7*7}`/`#{7*7}`) wurde an einen reflektierten Parameter gesendet und `49` erschien in der Ausgabe — kein Code/Befehl ausgeführt (nur arithmetischer Indikator).', fix: 'Interpolieren Sie Nutzereingaben nicht in Templates; verwenden Sie eine logikfreie Engine + Auto-Escaping; wenden Sie eine Sandbox an.' },
  hpp: { desc: 'Ein doppelter Parameter wird auf dem Server inkonsistent geparst (HTTP Parameter Pollution).', how: 'Derselbe Parameter wurde zweimal gesendet (`?p=A&p=B`) und mit Einzelanfragen verglichen; ein Parsing-Unterschied wurde beobachtet — keine Daten übermittelt, nur Beobachtung.', fix: 'Normalisieren Sie Parameter auf einen einzigen Wert; sorgen Sie über Server-/Framework-Schichten für konsistentes Parsing.' },
};

export function findingDetail(type: FindingType, locale: 'tr' | 'en' | 'de'): Detail {
  if (locale === 'de') return FINDING_DETAIL_DE[type] ?? FINDING_DETAIL[type].en;
  return locale === 'tr' ? FINDING_DETAIL[type].tr : FINDING_DETAIL[type].en;
}

// Başlık -> { İş Etkisi, CWE, OWASP } (locale). Eşleme yoksa null (UYDURMA YOK).
export function lookupByType(type: FindingType, locale: 'tr' | 'en' | 'de'): { impact: string; cwe: string; owasp: string; type: FindingType; label: string } {
  const e = FINDING_TAXONOMY[type];
  const impact = locale === 'de' ? (FINDING_IMPACT_DE[type] ?? e.en) : locale === 'tr' ? e.tr : e.en;
  return { impact, cwe: e.cwe, owasp: e.owasp, type, label: friendlyLabel(type, locale) };
}
export function lookupFinding(title: string, locale: 'tr' | 'en' | 'de'): { impact: string; cwe: string; owasp: string; type: FindingType; label: string } | null {
  const type = classifyFinding(title);
  if (!type) return null;
  return lookupByType(type, locale);
}
