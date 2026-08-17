/**
 * (Tam Kapsamlı Pentest — FAZ C) AUTHENTICATED DETERMİNİSTİK RAPOR ÜRETİCİSİ.
 *
 * FAZ B oturumunu (AuthSession) kullanan 6 kontrolü (çerez bayrakları, session fixation, logout,
 * forced browsing + authenticated injection + authenticated IDOR) çalıştırır ve Aktif Doğrulama
 * raporuyla TUTARLI (NE KONTROL EDİLDİ / BULGULAR / Kapsam kutuları) TEK dokümana birleştirir.
 * Tüm Türkçe metin KOD tarafından yazılır (ajan yok).
 */
import { collectInjectionEvidence, collectIdorEvidence } from './activeVerifyEvidence.js';
import { unscannableReport } from './unscannable.js';
import {
  collectCookieFlagsEvidence, collectSessionFixationEvidence, collectLogoutEvidence, collectForcedBrowsingEvidence,
} from './authenticatedChecks.js';
import { collectPrivilegeEscalationEvidence, collectMultiStepBusinessLogicEvidence } from './authAgentChecks.js';
import { collectJwtAnalysis, collectLoginBypassEvidence } from './authExtraChecks.js';
import { collectJsAnalysisEvidence } from './jsAnalysis.js';
import { collectClientSideEvidence } from './clientSideChecks.js';
import { collectAuthDepthEvidence } from './authDepthChecks.js';
import { collectSessionDepthEvidence } from './sessionDepthChecks.js';
import { collectInputHeaderEvidence, collectConfigExposureEvidence } from './configExposureChecks.js';
import { collectApiSecurityEvidence } from './apiSecurityChecks.js';
import { collectEmailDnsEvidence } from './emailDnsChecks.js';
import {
  buildActiveCheckReport, buildInjectionReport, buildIdorReport,
  RISK_WORD, levelRank, extractLevel, headlineOf, detailOnly, type Level,
} from './activeVerifyReports.js';
import type { AuthSession } from './authSession.js';

const COOKIE_CFG = {
  title: 'Oturum Çerezi Bayrakları', whatChecked: [
    'Login sonrası gözlemlenen çerezler arasından yalnızca gerçek **sunucu oturum çerezleri** değerlendirildi.',
    'Her oturum çerezi için **Secure / HttpOnly / SameSite** güvenlik bayrakları kontrol edildi.',
    'Analitik/3rd-party çerezler (_ga, _fbp, _clck vb.) oturum çerezi sayılmaz (HttpOnly bunlarda imkânsız) — değerlendirmeye alınmaz.',
  ],
  fixTitle: 'Çerez Güvenliği',
  fixFound: ['Oturum çerezlerine **Secure + HttpOnly + SameSite=Strict/Lax** bayraklarını ekleyin.', 'HttpOnly, çerezin JavaScript ile (XSS) okunmasını engeller; Secure, düz HTTP’de sızmasını önler; SameSite CSRF’i azaltır.'],
  fixClean: ['Oturum çerezlerinde Secure/HttpOnly/SameSite bayraklarını proaktif olarak zorunlu kılın.'],
  cleanGenel: 'Oturum çerezlerinde eksik güvenlik bayrağı gözlemlenmedi (veya oturum çerez-tabanlı değil).',
};
const FIXATION_CFG = {
  title: 'Session Fixation', whatChecked: [
    'Login ÖNCESİ (kimlik-doğrulamasız) ana sayfadan alınan oturum çerezi değeri gözlemlendi.',
    'Login SONRASI oturum çerezi değeriyle **karşılaştırıldı** (aynıysa sunucu oturumu yenilemiyor).',
    'Yalnız tek GET; hiçbir state değiştirilmedi.',
  ],
  fixTitle: 'Session Fixation',
  fixFound: ['Başarılı girişte oturum tanımlayıcısını **mutlaka yenileyin** (session regeneration); login öncesi verilen id’yi geçersiz kılın.'],
  fixClean: ['Girişte oturum id yenilemeyi (session regeneration) standart hale getirin.'],
  cleanGenel: 'Login sonrası oturum çerezi yenilendiği (veya oturum çerez-tabanlı olmadığı) için fixation göstergesi gözlemlenmedi.',
};
const LOGOUT_CFG = {
  title: 'Logout / Oturum Geçersizleştirme', whatChecked: [
    'Oturumla 200 dönen korumalı bir uç (whoami/profil) tespit edildi.',
    'GET ile çağrılabilen bir logout uç noktası denendi (**POST yok** — state değişmez).',
    'Logout SONRASI AYNI token ile korumalı uca tekrar erişilebiliyor mu kontrol edildi.',
  ],
  fixTitle: 'Oturum Geçersizleştirme',
  fixFound: ['Logout’ta oturum token’ını **sunucu tarafında geçersiz kılın** (revocation/expiry); istemci-tarafı token silme tek başına yeterli değildir.'],
  fixClean: ['Sunucu-taraflı oturum geçersizleştirme (revocation) uygulayın.'],
  cleanGenel: 'Logout sonrası oturum geçersizleştirildiği (veya sunucu-taraflı logout uç noktası olmadığı) için bulgu gözlemlenmedi.',
};
const FORCED_CFG = {
  title: 'Forced Browsing / Fonksiyon-Seviye Yetki', whatChecked: [
    'Yaygın admin/yönetim uç noktalarına ELDEKİ (muhtemelen düşük yetkili) test hesabının oturumuyla **GET** isteği atıldı.',
    'Yanlış-pozitifi önlemek için yalnız ana-sayfa shell’inden **FARKLI** içerik/JSON dönen 200’ler bulgu sayıldı.',
    'Tek deneme, GET-only, devre kesiciye tabi.',
  ],
  fixTitle: 'Fonksiyon-Seviye Yetkilendirme',
  fixFound: ['Her yönetim/hassas uç noktasında **sunucu-taraflı rol/yetki kontrolü** uygulayın; yalnız UI’da gizlemek yeterli değildir.'],
  fixClean: ['Yönetim uç noktalarını sunucu-taraflı rol kontrolüyle koruyun (proaktif).'],
  cleanGenel: 'Düşük yetkili oturumla erişilebilen bir admin/yönetim uç noktası gözlemlenmedi.',
};

// (İş A) NE KONTROL EDİLDİ ilk satırı advisor durumuna göre koşullu: KAPALI (varsayılan) -> deterministik dil;
// AÇIK (AUTH_ADVISOR_HOSTS) -> AI-danışma dili. Tek 'agentStatus' bayrağından türer (rapor kendiyle çelişmez).
const PRIVESC_WC_DET = 'Keşfedilen authenticated yüzeyde **deterministik olarak** yetki-alanı içeren form/API (kayıt/profil/ayar tipi) arandı.';
const PRIVESC_WC_AI = 'Keşfedilen authenticated yüzeyden **Otonom Analiz Motoru** (yalnız JSON öneri; doğrudan HTTP atmaz) yetki-alanı içeren form/API seçti.';
const MULTISTEP_WC_DET = '**Deterministik olarak** çok-adımlı akış/fiyat-kupon alanı arandı; backend YALNIZ **GET-gözlem** yaptı.';
const MULTISTEP_WC_AI = '**Otonom Analiz Motoru** (yalnız JSON öneri) çok-adımlı akış/fiyat-kupon alanı seçti; backend YALNIZ **GET-gözlem** yaptı.';
const PRIVESC_CFG = {
  title: 'Yetki Yükseltme (Privilege Escalation)', whatChecked: [
    PRIVESC_WC_DET,
    'Güvenli test edilebilir bir yüzey bulunduysa **güvenli, authenticated-light** fonksiyonla TEK gözlemsel mass-assignment probu (`role/isAdmin` ek alan) uygulandı.',
    '⚠️ Gerçek yükseltme TAMAMLANMADI; yükseltilmiş yetkiyle tekrar giriş yapılmadı; oturum dışına çıkılmadı; hesap-değiştiren/checkout hedeflerine **yazılmadı** (kod-seviyesi blocklist).',
  ],
  confidenceNote: 'Mass-assignment göstergesi yalnızca ilk yanıttan çıkarılmıştır (düşük güven); kesin doğrulama manuel test gerektirir.',
  fixTitle: 'Yetki Yükseltme / Mass-Assignment',
  fixFound: ['Model bağlamada **allowlist** ile yalnız izin verilen alanları bağlayın; `role/isAdmin` gibi alanları ASLA istemciden almayın.', 'Sunucu tarafında rol atamasını yalnız yetkili akışlarda yapın.'],
  fixClean: ['Mass-assignment koruması (alan allowlist) uygulayın; rol/yetki alanlarını istemciden kabul etmeyin (proaktif).'],
  cleanGenel: 'Uygun bir kayıt/profil formu bulunamadı veya `role/isAdmin` mass-assignment probu kabul edilmedi.',
};
const MULTISTEP_CFG = {
  title: 'Çok-Adımlı İş Mantığı', whatChecked: [
    MULTISTEP_WC_DET,
    'İstemci-değiştirilebilir gizli fiyat/miktar/kupon alanı + ön koşulsuz erişilebilen "onay" adımı gözlemlendi.',
    '⚠️ Yalnız sepete/forma kadar; **ödeme/checkout TAMAMLANMADI** (kod-seviyesi blocklist); hiçbir kaynak tüketilmedi.',
  ],
  confidenceNote: 'İş mantığı zafiyetleri bağlama özeldir; bu kontrol yüzey/gösterge seviyesindedir.',
  fixTitle: 'Çok-Adımlı İş Mantığı',
  fixFound: ['Fiyat/miktar/indirim/kupon değerlerini **asla** istemciden gelenle işlemeyin; sunucuda yeniden hesaplayın/doğrulayın.', 'Çok-adımlı akışlarda her adımın ön koşulunu sunucu tarafında zorunlu kılın; kuponu tek-kullanımlık atomik tüketin.'],
  fixClean: ['Kritik değerleri sunucuda doğrulayın; adım sırası + kupon tekrar-kullanım kontrolü uygulayın (proaktif).'],
  cleanGenel: 'Gözlemlenebilir bir istemci-tarafı fiyat/kupon alanı veya doğrudan erişilebilir "onay" adımı bulunamadı.',
};

const JWT_CFG = {
  title: 'JWT / Token Güvenliği', whatChecked: [
    'Oturum bir **JWT bearer** taşıyorsa token OFFLINE çözülüp analiz edildi: imza algoritması (**alg=none / imzasız**), imza sırrının **zayıf/yaygın** olup olmadığı (yaygın sırlarla OFFLINE doğrulama), ve token gövdesindeki **hassas/aşırı claim** (parola/sır, rol/yetki).',
    'Ek olarak TEK, zararsız gözlem: imzasız (alg=none) forge edilmiş bir token korumalı bir uçta KABUL ediliyor mu (yalnız gözlem; erişim kullanılmadı).',
    '⚠️ Gerçek istismar YOK — token ele geçirme/yetki yükseltme yapılmadı; yalnız güvenlik göstergesi raporlandı.',
  ],
  confidenceNote: 'Zayıf-sır ve alg=none KABUL göstergeleri kesindir (yüksek güven); claim gözlemleri bilgilendirmedir.',
  fixTitle: 'JWT / Token Güvenliği',
  fixFound: ['İmza algoritmasını sunucuda **sabitleyin** (ör. yalnız RS256/HS256); `alg=none` ve istemci-seçimli alg’i REDDEDİN.', 'JWT imza sırrını **güçlü/rastgele** (256-bit+) yapın; sır/parola gibi hassas veriyi token gövdesine KOYMAYIN (JWT gövdesi şifreli değildir).', 'Token’a `exp` (kısa ömür) ekleyin; kritik yetki/rol kararlarını istemci claim’ine değil sunucu doğrulamasına dayandırın.'],
  fixClean: ['İmza algoritmasını sabitleyin, güçlü sır kullanın, `exp` ekleyin ve hassas claim taşımayın (proaktif).'],
  cleanGenel: 'JWT/token güvenlik göstergesi bulunamadı ya da oturum JWT taşımıyor.',
};

const LOGIN_BYPASS_CFG = {
  title: 'Giriş Baypası (SQLi Göstergesi)', whatChecked: [
    'Giriş (login) ucuna önce **geçersiz kimlik** (kontrol) gönderildi; ardından klasik SQLi payload’ları (`\' OR \'1\'=\'1` vb.) denenip, kontrolün AKSİNE oturum/başarı (token/2xx) dönüp dönmediği gözlemlendi.',
    'Login POST’u zaten izinli akıştır; TEK, zararsız gözlemdir.',
    '⚠️ Oturum ele geçirme/istismar YOK — yalnız "kimlik doğrulama atlatma göstergesi var mı" gözlemi.',
  ],
  confidenceNote: 'Gösterge, kontrol denemesiyle karşılaştırmaya dayanır; kesin doğrulama manuel test gerektirir.',
  fixTitle: 'Giriş Baypası / SQL Enjeksiyonu',
  fixFound: ['Kimlik doğrulama sorgularında **parametreli sorgu / hazırlanmış ifade (prepared statement)** kullanın; kullanıcı girdisini asla SQL’e doğrudan koymayın.', 'Girdi doğrulama + ORM güvenli API’leri; hatalı girişte tek-tip hata mesajı döndürün.'],
  fixClean: ['Parametreli sorgu + girdi doğrulama uygulayın (proaktif); kimlik doğrulama akışını SQLi’ye kapatın.'],
  cleanGenel: 'Giriş baypası (SQLi) göstergesi bulunamadı ya da test edilebilir bir login ucu yoktu.',
};

// (blocker fix — part 2) Aktif Doğrulama'nın (login'siz) şablonundan MİRAS kalan "kimlik doğrulaması
// olmadan / kapsam dışı" cümlelerini authenticated bağlama çevirir. buildInjection/Idor/ActiveCheckReport
// DİĞER paketlerde AYNEN kalır — bu yalnız authenticated raporu POST-İŞLER (kaynak şablonlara dokunmaz).
function toAuthenticatedContext(md: string): string {
  return md
    .replace(
      /(#{2,3}) KAPSAM SINIRI \(ÖNEMLİ\)[\s\S]*?\(\*\*İnceleme gerekli \/ Kapsam Dışı\*\*\)\.\n\n/,
      '$1 KAPSAM SINIRI (ÖNEMLİ)\n\nBu bölüm, sağladığınız TEST hesabının **oturumuyla (login’li)** çalıştırılmıştır ve hesabın **kendi** numaralandırılabilir kaynaklarına yetkisiz erişimi test eder. **Cross-account** (başka bir kullanıcının verisine erişim) testi bu sürümün kapsamı dışındadır (iki ayrı hesap gerektirir). Bulgu olmaması, tüm kimlik-doğrulamalı akışlarda IDOR olmadığını kanıtlamaz.\n\n',
    )
    .replace(
      /Kimlik doğrulama gerektiren alanlar ve iç mantık bu paketin kapsamı dışındadır\./g,
      'Bu bölüm, sağladığınız TEST hesabının oturumuyla kimlik-doğrulamalı (login’li) bağlamda çalıştırılmıştır; ödeme/hesap-durumu değişikliği tamamlama kod seviyesinde engellidir.',
    )
    .replace(/kimlik doğrulaması olmadan/g, 'kimlik-doğrulamalı oturumla');
}

// (Client-Side / JS Analizi) PASİF JS bundle analizi — 6. pakete özel bölüm. Sütun 0: public-by-design
// anahtarlar bulgu değildir; sürüm okunamayan kütüphaneye CVE atanmaz.
const JS_ANALYSIS_CFG = {
  title: 'Client-Side / JS Analizi',
  whatChecked: [
    'Sayfanın yüklediği JS bundle’ları (script src’leri + inline) çekilip **statik** analiz edildi — aktif istismar YOK, yalnız indir + oku.',
    '**A) Sır taraması:** özel anahtar, AWS/GCP kimliği, Stripe **sk_live_**, GitHub/GitLab/Slack token, DB bağlantı dizesi gibi GERÇEK sırlar arandı (değerler REDAKTE).',
    '**Public-by-design ayrımı:** Firebase apiKey, GTM/GA ölçüm ID, Google Maps browser key, Stripe **pk_**, reCAPTCHA site key tasarım gereği herkese açıktır → "ifşa/sır" SAYILMAZ, yalnız bilgilendirici listelenir.',
    '**B) Source-map ifşası:** `//# sourceMappingURL` yorumları + `.js.map` adayları denendi; erişilebilir `.map` → orijinal kaynak kod/ağaç sızıntısı.',
    '**C) Bilinen-zafiyetli kütüphane:** yüklenen kütüphaneler + SÜRÜMLERİ tespit edilip bilinen CVE’lerle MUHAFAZAKÂR eşlendi; sürüm güvenle okunamazsa CVE eşleme YAPILMADI ("yama teyidi gerekir" dili; "istismar edilebilir" denmez).',
  ],
  confidenceNote: 'Tümü pasif/statiktir; kütüphane bulguları sürüm-tabanlı göstergedir (dağıtımınız yamalı/backport’lu olabilir — teyit önerilir).',
  fixTitle: 'Client-Side / JS Güvenliği',
  fixFound: [
    'İstemci JS’ine GERÇEK sır koymayın; tespit edilenleri **derhal döndürün/geçersizleştirin** ve sunucu-taraflı proxy + gizli-yönetimi (secret manager) kullanın.',
    'Üretimde source-map yayımlamayın (veya erişimi kısıtlayın); public dizinden `.map` dosyalarını kaldırın.',
    'Zafiyetli kütüphaneleri güncel/yamalı sürüme çıkarın; SRI + bağımlılık taraması (retire.js/Dependabot) ekleyin.',
  ],
  fixClean: ['İstemci JS’inde sır bulundurmayın; source-map’leri üretimde yayımlamayın; kütüphaneleri güncel tutup bağımlılık taraması uygulayın (proaktif).'],
  cleanGenel: 'Çekilen JS bundle’larında gerçek sır, erişilebilir source-map veya bilinen-zafiyetli (sürümü okunabilen) kütüphane gözlemlenmedi. Public-by-design anahtarlar (varsa) yukarıda bilgilendirici olarak ayrılmıştır.',
};

// (Faz 1-B) Client-Side Statik Analiz — 6 pasif kontrol (DOM-XSS gösterge / postMessage / storage /
// SRI / tabnabbing / open-redirect). Sütun 0: DOM-XSS "gösterge", kanıtlanmış XSS değil.
const CLIENT_SIDE_CFG = {
  title: 'Client-Side Statik Analiz',
  whatChecked: [
    'Aynı JS/HTML corpus’u üzerinde **statik** olarak (aktif istismar YOK) 6 istemci-tarafı kontrol yapıldı.',
    '**1) DOM-based XSS (gösterge):** tehlikeli sink (innerHTML/document.write/eval/.html()/location=) ile kullanıcı-kontrollü kaynak (location.hash/search, referrer, window.name) AYNI ifadede mi — **kanıtlanmış XSS DEĞİL**, düşük güvenli gösterge (dinamik doğrulama gerekir).',
    '**2) postMessage:** `message` olay dinleyicilerinde **event.origin doğrulaması** var mı.',
    '**3) Browser storage:** localStorage/sessionStorage’a **hassas veri** (token/JWT/oturum) yazımı (statik; değer REDAKTE).',
    '**4) Eksik SRI:** harici script/style’larda `integrity` attribute’u var mı (tedarik-zinciri).',
    '**5) Reverse tabnabbing:** `target="_blank"` linklerinde `rel="noopener/noreferrer"` var mı.',
    '**6) Open redirect:** HTML’de GÖZLENEN yönlendirme parametrelerine **tek güvenli prob** — zararsız harici URL gönderilip Location gözlendi; **redirect TAKİP EDİLMEDİ**.',
  ],
  confidenceNote: 'DOM-XSS bulguları STATİK göstergedir (yanlış-pozitif potansiyeli yüksek; dinamik doğrulama gerekir). Diğerleri deterministik gözlemdir.',
  fixTitle: 'Client-Side Statik Güvenlik',
  fixFound: [
    'DOM-XSS: kullanıcı-kontrollü veriyi innerHTML/eval/document.write yerine textContent + güvenli API ile işleyin; gerekiyorsa DOMPurify ile sanitize edin.',
    'postMessage: her `message` handler’ında `event.origin`’i allowlist ile doğrulayın.',
    'Storage: oturum token’ını localStorage yerine **HttpOnly + Secure çerezde** tutun.',
    'SRI: harici script/style’lara `integrity` + `crossorigin` ekleyin. Tabnabbing: `target="_blank"` linklere `rel="noopener noreferrer"`.',
    'Open redirect: yönlendirme hedeflerini sunucuda **allowlist** ile sınırlayın; harici mutlak URL’lere yönlendirmeyin.',
  ],
  fixClean: ['DOM sink’lerini güvenli API + sanitizasyonla kullanın; postMessage origin doğrulayın; token’ı HttpOnly çerezde tutun; SRI + rel=noopener + redirect allowlist uygulayın (proaktif).'],
  cleanGenel: 'Statik ayrıştırmada belirgin bir DOM-XSS göstergesi, güvensiz message handler, hassas storage yazımı, eksik SRI, tabnabbing veya açık yönlendirme gözlemlenmedi.',
};

// (Faz 2-A) Kimlik-Doğrulama Derinliği — 9 kontrol. Güvenlik kuralları kod-seviyesinde (gerçek hesap
// kilitlenmez / reset e-postası gitmez / kayıt yapılmaz). Enumerasyon/lockout/reset = "gösterge" dili.
const AUTH_DEPTH_CFG = {
  title: 'Kimlik-Doğrulama Derinliği',
  whatChecked: [
    '9 kimlik-doğrulama derinlik kontrolü (WSTG-ATHN/IDNT) — **güvenli, düşük hacim**; brute-force/DoS YOK.',
    '**1) Hesap enumerasyonu:** geçerli (test hesabı) vs geçersiz (rastgele) kullanıcıda yanıt farkı — birer BAŞARISIZ deneme; hesap oluşturmaz.',
    '**2) Varsayılan kimlik:** küçük sabit liste (admin/admin vb.) — yalnız başarısız login; kabul edilirse oturum KULLANILMAZ.',
    '**3) Zayıf lockout/rate-limit:** THROWAWAY (rastgele) kullanıcıyla birkaç hatalı deneme — **gerçek hesap ASLA kilitlenmez**.',
    '**4) Parola sıfırlama:** mekanizma gözlemi (güvenlik sorusu/token) — **GERÇEK sıfırlama e-postası TETİKLENMEZ** (var-olmayan e-posta).',
    '**5) Parola/kayıt politikası:** yalnız client-side gözlem — **GERÇEK kayıt YAPILMAZ**.',
    '**6) "Beni hatırla" çerezi · 7) Authenticated sayfa cache (Cache-Control) · 8) MFA varlığı (bilgilendirici) · 9) Kimlik şifresiz kanalda (HTTP).**',
  ],
  confidenceNote: 'Enumerasyon/lockout/reset bulguları "gösterge"dir (doğrulama gerekir). Güvenlik: gerçek hesap kilitlenmedi, reset e-postası gitmedi, kayıt yapılmadı, başarılı giriş bulunsa bile oturum kullanılmadı.',
  fixTitle: 'Kimlik-Doğrulama Sertleştirme',
  fixFound: [
    'Enumerasyon: login/reset/register’da **tek-tip** yanıt/mesaj/süre döndürün (kullanıcı var/yok sızdırmayın).',
    'Varsayılan kimlik: tüm varsayılan hesapları kaldırın/parolalarını zorunlu değiştirin.',
    'Lockout: art arda hatalı denemede **hesap+IP bazlı hız-sınırı / geçici kilit** uygulayın; CAPTCHA ekleyin.',
    'Parola sıfırlama: **token-tabanlı** (tek-kullanımlık, kısa ömür), güvenlik-sorusundan kaçının; Host header’ı reset linkinde kullanmayın.',
    'Parola politikası: sunucuda **min 8+ / karmaşıklık**; şifresiz kanal: login’i **yalnız HTTPS**’te yapın; hassas sayfalara `Cache-Control: no-store`; **MFA** sunun.',
  ],
  fixClean: ['Tek-tip auth yanıtları, varsayılan-hesap yok, lockout/rate-limit + CAPTCHA, token-tabanlı reset, güçlü parola politikası, HTTPS-only login, no-store cache, MFA (proaktif).'],
  cleanGenel: 'Kimlik-doğrulama derinlik kontrollerinde belirgin bir enumerasyon, varsayılan-kimlik, zayıf-lockout, zayıf-reset veya şifresiz-kanal göstergesi gözlemlenmedi.',
};

// (Faz 2-B) Oturum Güvenliği Derinliği — 5 kontrol (CSRF/SameSite, session-id entropi, oturum-URL,
// zaman-aşımı gözlemi, __Host-/__Secure- prefix). Sunucu oturum çerezi yoksa (Bearer/SPA) KAPSAM DIŞI.
const SESSION_DEPTH_CFG = {
  title: 'Oturum Güvenliği Derinliği',
  whatChecked: [
    'GERÇEK sunucu-taraflı oturum çerezi (Set-Cookie session) VARSA 5 oturum-yönetimi kontrolü — hepsi **read-only/gözlemsel** (durum-değiştiren gönderim / gerçek CSRF saldırısı YOK). Bearer/JWT/token-tabanlı hedefte bu bölüm **kapsam dışıdır**.',
    '**1) CSRF (SESS-05):** oturum çerezinde SameSite + durum-değiştiren POST formunda anti-CSRF token gözlemi (statik; form GÖNDERİLMEDİ).',
    '**2) Session-id entropi (SESS-01):** oturum kimliğinin yapısal analizi (uzunluk/charset/entropi) — brute YOK; JWT ise ayrı bölüme bırakılır.',
    '**3) Oturum URL\'de (SESS-04):** session id URL/query\'de (jsessionid/sid vb.) ifşa mı.',
    '**4) Zaman aşımı / eş-zamanlı oturum (SESS-07/11):** gözlemsel gösterge (kesin test manuel).',
    '**5) Çerez prefix (SESS-02):** oturum çerezinde __Host-/__Secure- prefix eksik mi.',
  ],
  confidenceNote: 'Bulgular "gösterge"dir (gerçek CSRF saldırısı/brute yapılmadı; token/oturum REDAKTE). Sunucu oturum çerezi yoksa kontroller kapsam dışıdır (token/JWT güvenliği ayrı bölümde).',
  fixTitle: 'Oturum Güvenliği Sertleştirme',
  fixFound: [
    'CSRF: oturum çerezine **SameSite=Lax/Strict** ekleyin; durum-değiştiren isteklerde **anti-CSRF token** (double-submit / synchronizer) zorunlu kılın.',
    'Session-id: en az **128-bit rastgele** (CSPRNG) oturum kimliği kullanın; tahmin-edilebilir/sıralı değer kullanmayın.',
    'Oturum URL\'de: session id\'yi **asla URL/query\'de taşımayın** — yalnız HttpOnly + Secure çerezde.',
    'Prefix: oturum çerezini **`__Host-`** prefix\'iyle (Secure + Path=/ + Domain yok) ayarlayın. Zaman aşımı: makul idle/absolute timeout + sunucu-taraflı geçersizleştirme.',
  ],
  fixClean: ['Oturum çerezine SameSite + __Host- prefix, 128-bit rastgele session-id, URL\'de oturum taşımama, anti-CSRF token, makul timeout (proaktif).'],
  cleanGenel: 'Sunucu oturum çerezi gözlemlendi ancak belirgin bir CSRF/SameSite eksiği, zayıf session-id, URL-ifşa veya prefix eksikliği göstergesi bulunamadı.',
};

// (Faz 3-A) Girdi & Header + Yapılandırma & İfşa derinliği — 10 kontrol (güvenli GET/OPTIONS/TRACE +
// statik). SPA catch-all shell 200'ler bulgu sayılmaz (Faz 0 provenance); PUT/DELETE atılmaz; D5 gönderim yok.
const INPUT_HEADER_CFG = {
  title: 'Girdi & Header Derinliği',
  whatChecked: [
    'Güvenli/read-only girdi & header kontrolleri (yalnız GET/OPTIONS/TRACE — durum-değiştiren/yıkıcı istek YOK).',
    '**D1 Host header injection:** sahte `X-Forwarded-Host` gönderilip yanıtta yansıma gözlendi (gösterge).',
    '**D2 HTTP parameter pollution:** aynı parametre tekrarlanıp işleniş farkı gözlendi (gözlemsel).',
    '**D3 HTTP methods / TRACE:** OPTIONS ile izinli method keşfi + TRACE gözlemi — **PUT/DELETE GÖNDERİLMEDİ**.',
    '**D4 Mixed content:** HTTPS sayfada HTTP kaynak (script/img/iframe) statik tespit.',
    '**D5 Stored-XSS giriş noktası:** kalıcı bağlama yansıyabilecek ADAY alanlar işaretlendi — **hiçbir veri GÖNDERİLMEDİ/kaydedilmedi** (düşük güven, dinamik doğrulama gerekir).',
  ],
  confidenceNote: 'Host-injection/HPP/D5 "gösterge/aday"dır (gerçek saldırı/gönderim yapılmadı). TRACE/mixed-content deterministik gözlemdir.',
  fixTitle: 'Girdi & Header Sertleştirme',
  fixFound: [
    'Host header: uygulamada Host/X-Forwarded-Host değerini **allowlist** ile sabitleyin; mutlak URL üretiminde kullanmayın.',
    'HTTP methods: **TRACE**\'i kapatın; durum-değiştiren method\'larda sunucu-taraflı yetkilendirme zorunlu.',
    'Mixed content: tüm kaynakları **HTTPS**\'e taşıyın (upgrade-insecure-requests / CSP).',
    'Stored-XSS: kalıcı alanlarda çıktı-kodlaması + sanitizasyon (DOMPurify) uygulayın; HPP\'ye karşı parametreleri tek-değer olarak işleyin.',
  ],
  fixClean: ['Host allowlist, TRACE kapalı, tüm kaynaklar HTTPS, kalıcı girdilerde çıktı-kodlama/sanitizasyon, parametre tekilleştirme (proaktif).'],
  cleanGenel: 'Girdi/header kontrollerinde belirgin bir Host-injection, açık TRACE, mixed-content veya HPP göstergesi bulunamadı.',
};
const CONFIG_EXPOSURE_CFG = {
  title: 'Yapılandırma & İfşa Derinliği',
  whatChecked: [
    'Güvenli GET + statik yapılandırma/ifşa kontrolleri. **SPA catch-all 200 (ana sayfa shell)** dönen tahmin edilen yollar GERÇEK sayılmaz — yalnız gerçekten erişilebilen, AYIRT EDİCİ yanıt bulgu üretir (Sütun 0 provenance).',
    '**E1 Yedek/eski dosya:** `.env/.bak/.sql/.git/config` vb. güvenli GET (shell 200 elendi).',
    '**E2 Admin arayüz:** yaygın yönetim yolları dışarıdan erişilebilir mi (aynı provenance).',
    '**E3 Cloud storage:** HTML/JS\'te public S3/GCS/Azure bucket referansı + **listelenebilir** mi.',
    '**E4 Cache / poisoning göstergesi:** Cache-Control/Vary + unkeyed-header yansıması (zehirleme YAPILMADI).',
    '**E5 Yorum & metadata sızıntısı:** dev yorumu / iç IP-hostname / sunucu dosya yolu (statik).',
  ],
  confidenceNote: 'Yedek/admin bulguları yalnız GERÇEKTEN erişilebilen, SPA-shell OLMAYAN yanıtlar için üretilir. Cache/host göstergeleri "gösterge"dir; içerik/hassas veri REDAKTE.',
  fixTitle: 'Yapılandırma & İfşa Sertleştirme',
  fixFound: [
    'Yedek/eski/`.git`/`.env` dosyalarını public dizinden kaldırın; web sunucusunda erişimi engelleyin.',
    'Yönetim arayüzlerini ağ (IP allowlist/VPN) + kimlik-doğrulama arkasına alın; dışarı açmayın.',
    'Cloud bucket: **liste iznini kapatın**, hassas nesneleri private yapın (public yalnız gerçekten public asset için).',
    'Cache: unkeyed girdiyi yansıtmayın veya `Vary`\'e ekleyin. Yorumlar: üretim build\'inde dev yorumu/iç bilgi bırakmayın.',
  ],
  fixClean: ['Yedek/.git/.env dizin dışında, admin arayüzü kimlik/ağ arkasında, bucket private/list-kapalı, cache Vary doğru, üretimde yorum/metadata temiz (proaktif).'],
  cleanGenel: 'Erişilebilir yedek/eski dosya, açık admin arayüzü, listelenebilir bucket, cache-poisoning göstergesi veya belirgin yorum/metadata sızıntısı gözlemlenmedi.',
};

// (Faz 3-B) API Güvenliği Derinliği — OWASP API Top 10. Yalnız GERÇEK keşfedilmiş (JSON, SPA-shell
// olmayan) REST/GraphQL API'de çalışır; yoksa Kapsam dışı. Read-only; mutasyon/DoS yok.
const API_SECURITY_CFG = {
  title: 'API Güvenliği Derinliği (OWASP API Top 10)',
  whatChecked: [
    'Aynı-origin JS/HTML\'den keşfedilen, JSON dönen (SPA catch-all shell OLMAYAN) GERÇEK API uçlarında 5 kontrol — hepsi read-only. Gerçek API yoksa (Firebase/istemci-SDK/SPA) bu bölüm **kapsam dışıdır**.',
    '**F1 BOLA/BFLA (API1/API5):** nesne/fonksiyon-seviyesi yetki — **Authenticated IDOR** + **Forced Browsing** bölümlerinde değerlendirildi (çift bulgu önlemek için burada tekrar probe edilmedi).',
    '**F2 Aşırı veri ifşası / BOPLA (API3):** API yanıtında hassas/aşırı alan (parola-hash/rol/iç-ID) — değer REDAKTE.',
    '**F3 Rate-limit (API4):** MODEST burst (DoS DEĞİL) sonrası 429/rate-limit başlığı çıkıyor mu — hedef yorulmadı.',
    '**F4 Shadow/deprecated sürüm (API9):** /v1,/v2,/api/v1 gibi sürüm uçları erişilebilir mi (SPA-shell elendi).',
    '**F5 GraphQL introspection (APIT-99):** GraphQL ucu varsa introspection açık mı — **read-only sorgu; mutasyon YOK**.',
  ],
  confidenceNote: 'Bulgular "gösterge"dir; yalnız GERÇEKTEN gözlemlenen (JSON, SPA-shell olmayan) uçlarda. Hassas veri REDAKTE; mutasyon/veri-değiştirme/DoS yapılmadı.',
  fixTitle: 'API Güvenliği Sertleştirme',
  fixFound: [
    'BOLA/BFLA: her API isteğinde nesne-sahipliği + fonksiyon-rol kontrolünü sunucuda zorunlu kılın (ID geçerliliği yetmez).',
    'Aşırı veri: yanıtları **alan-allowlist (DTO)** ile sınırlayın; parola-hash/sır/iç-ID/rol\'ü istemciye göndermeyin.',
    'Rate-limit: hesap+IP+endpoint bazlı **rate-limit + kota**; ağır uçlara maliyet-tabanlı sınır.',
    'Sürüm: kullanılmayan/eski API sürümlerini kapatın. GraphQL: üretimde **introspection\'ı kapatın**; sorgu derinliği/karmaşıklık limiti ekleyin.',
  ],
  fixClean: ['Nesne/fonksiyon yetkisi sunucuda, yanıt DTO-allowlist, rate-limit+kota, eski sürümler kapalı, GraphQL introspection kapalı (proaktif).'],
  cleanGenel: 'Keşfedilen API uçlarında belirgin bir aşırı-veri ifşası, rate-limit eksikliği, gölge-sürüm veya açık GraphQL introspection göstergesi bulunamadı.',
};

// (Faz 3-C) E-posta & DNS Derinliği — anti-spoofing + DNS bütünlüğü. Pasif DNS/TXT + tek MTA-STS GET.
const EMAIL_DNS_CFG = {
  title: 'E-posta & DNS Derinliği (Anti-Spoofing)',
  whatChecked: [
    'Yalnız GERÇEK org-alandan okunan DNS kayıtları; hepsi PASİF DNS/TXT + tek güvenli MTA-STS GET (saldırı/state-değişimi yok). Alt-alan için DMARC **organizasyonel alan** seviyesinde değerlendirilir.',
    '**G1 DMARC** politika gücü (p=none/quarantine/reject, pct, sp alt-alan, adkim/aspf, rua).',
    '**G2 SPF** derinliği (-all/~all/?all/+all + üst-seviye DNS-arama sayısı, RFC 7208).',
    '**G3 DKIM** yaygın seçici keşfi (default/google/selector1…) + anahtar uzunluğu (~1024/2048) + iptal (p= boş).',
    '**G4 MTA-STS** (_mta-sts TXT + politika: enforce/testing/none) · **G5 TLS-RPT** raporlama.',
    '**G6 DNSSEC** (imza/doğrulama — AD bayrağı, yalnız gözlem) · **G7 CAA** (sertifika-verme kısıtı) + **BIMI** (bilgilendirici).',
  ],
  confidenceNote: 'Kanıt = DNS\'in gerçekten döndürdüğü public kayıt (redaksiyon gereksiz). "gösterge" dili; e-posta göndermeyen alanda (MX yok) eksik DMARC/SPF şiddeti düşürülür. Uydurma/tahmin kayıt yok.',
  fixTitle: 'E-posta & DNS Sertleştirme',
  fixFound: [
    'DMARC: \`p=none\`→\`quarantine\`→\`reject\` (pct=100) kademeli sıkılaştırın; \`rua=\` ile raporlamayı açın; alt-alanlar için \`sp=reject\`.',
    'SPF: \`-all\` (hardfail) kullanın; \`+all\`/\`?all\`\'dan kaçının; DNS-arama sayısını ≤10 tutun (PermError).',
    'DKIM: 2048-bit anahtar, iptal edilen seçicileri kaldırın. MTA-STS: \`mode=enforce\`. TLS-RPT ekleyin.',
    'DNSSEC\'i etkinleştirin (DS+RRSIG). CAA ile yetkili CA\'ları kısıtlayın.',
  ],
  fixClean: ['DMARC p=reject, SPF -all, DKIM 2048-bit, MTA-STS enforce, TLS-RPT, DNSSEC, CAA — anti-spoofing/DNS bütünlüğü güçlü (proaktif).'],
  cleanGenel: 'Sorgulanan org-alanın e-posta/DNS kayıtlarında belirgin bir anti-spoofing zayıflığı (eksik/gevşek DMARC-SPF, açık +all, imzasız DNSSEC vb.) göstergesi bulunamadı.',
};

type Run = { title: string; conf: 'Yüksek' | 'Orta' | 'Düşük'; rep: { findings: string; fixText: string } | null; inputs: number; probes: number; fc: number; agentCheck?: boolean; agentUsed?: boolean; agentStatus?: 'analyzed' | 'no_candidate' | 'unavailable' | 'disabled'; enumerableSurface?: { param: string; count: number } | null };

/** 6 authenticated kontrolü çalıştır + TEK rapora birleştir. Hedefe ulaşılamazsa null. */
export async function generateAuthenticatedReport(host: string, session: AuthSession): Promise<{ findings: string; fixText: string } | null> {
  const runs: Run[] = [];
  const cookieEv = collectCookieFlagsEvidence(session);
  runs.push({ title: 'Oturum Çerezi Bayrakları', conf: 'Yüksek', rep: buildActiveCheckReport(cookieEv, COOKIE_CFG), inputs: cookieEv.inputsFound, probes: cookieEv.probesSent, fc: cookieEv.findings.length });
  const fixEv = await collectSessionFixationEvidence(host, session).catch(() => null);
  runs.push({ title: 'Session Fixation', conf: 'Orta', rep: fixEv ? buildActiveCheckReport(fixEv, FIXATION_CFG) : null, inputs: fixEv?.inputsFound ?? 0, probes: fixEv?.probesSent ?? 0, fc: fixEv?.findings.length ?? 0 });
  const logoutEv = await collectLogoutEvidence(host, session).catch(() => null);
  runs.push({ title: 'Logout / Oturum Geçersizleştirme', conf: 'Orta', rep: logoutEv ? buildActiveCheckReport(logoutEv, LOGOUT_CFG) : null, inputs: logoutEv?.inputsFound ?? 0, probes: logoutEv?.probesSent ?? 0, fc: logoutEv?.findings.length ?? 0 });
  const forcedEv = await collectForcedBrowsingEvidence(host, session).catch(() => null);
  runs.push({ title: 'Forced Browsing / Fonksiyon-Seviye Yetki', conf: 'Orta', rep: forcedEv ? buildActiveCheckReport(forcedEv, FORCED_CFG) : null, inputs: forcedEv?.inputsFound ?? 0, probes: forcedEv?.probesSent ?? 0, fc: forcedEv?.findings.length ?? 0 });
  const injEv = await collectInjectionEvidence(host, session).catch(() => null);
  runs.push({ title: 'Authenticated Enjeksiyon (SQLi/XSS)', conf: 'Yüksek', rep: injEv ? buildInjectionReport(injEv) : null, inputs: injEv?.inputsFound ?? 0, probes: injEv?.probesSent ?? 0, fc: injEv?.findings.length ?? 0 });
  const idorEv = await collectIdorEvidence(host, session).catch(() => null);
  runs.push({ title: 'Authenticated IDOR (kendi kaynakları)', conf: 'Orta', rep: idorEv ? buildIdorReport(idorEv) : null, inputs: idorEv?.candidates ?? 0, probes: idorEv?.probesSent ?? 0, fc: idorEv?.findings.length ?? 0, enumerableSurface: idorEv?.enumerableSurface ?? null });
  // (FAZ D) SINIRLI/KONTROLLÜ AJAN KATMANI — priv-esc + çok-adımlı iş mantığı (ajan öneri, backend uygular).
  const privEv = await collectPrivilegeEscalationEvidence(host, session).catch(() => null);
  // (İş A) advisor AÇIK (analyzed) ise AI-danışma dili; KAPALI (varsayılan) ise deterministik dil.
  const privCfg = privEv?.agentStatus === 'analyzed' ? { ...PRIVESC_CFG, whatChecked: [PRIVESC_WC_AI, ...PRIVESC_CFG.whatChecked.slice(1)] } : PRIVESC_CFG;
  runs.push({ title: 'Yetki Yükseltme (Privilege Escalation)', conf: 'Orta', rep: privEv ? buildActiveCheckReport(privEv, privCfg) : null, inputs: privEv?.inputsFound ?? 0, probes: privEv?.probesSent ?? 0, fc: privEv?.findings.length ?? 0, agentCheck: true, agentUsed: privEv?.agentUsed ?? false, agentStatus: privEv?.agentStatus });
  const multiEv = await collectMultiStepBusinessLogicEvidence(host, session).catch(() => null);
  const multiCfg = multiEv?.agentStatus === 'analyzed' ? { ...MULTISTEP_CFG, whatChecked: [MULTISTEP_WC_AI, ...MULTISTEP_CFG.whatChecked.slice(1)] } : MULTISTEP_CFG;
  runs.push({ title: 'Çok-Adımlı İş Mantığı', conf: 'Düşük', rep: multiEv ? buildActiveCheckReport(multiEv, multiCfg) : null, inputs: multiEv?.inputsFound ?? 0, probes: multiEv?.probesSent ?? 0, fc: multiEv?.findings.length ?? 0, agentCheck: true, agentUsed: multiEv?.agentUsed ?? false, agentStatus: multiEv?.agentStatus });
  const advisorActive = privEv?.agentStatus === 'analyzed' || multiEv?.agentStatus === 'analyzed'; // (İş A) tek bayrak
  // (İŞ 3) JWT/token güvenliği + giriş baypası (SQLi göstergesi) — deterministik, gözlemsel.
  const jwtEv = await collectJwtAnalysis(host, session).catch(() => null);
  runs.push({ title: 'JWT / Token Güvenliği', conf: 'Yüksek', rep: jwtEv ? buildActiveCheckReport(jwtEv, JWT_CFG) : null, inputs: jwtEv?.inputsFound ?? 0, probes: jwtEv?.probesSent ?? 0, fc: jwtEv?.findings.length ?? 0 });
  const loginBypassEv = await collectLoginBypassEvidence(host, session.loginUrl).catch(() => null);
  runs.push({ title: 'Giriş Baypası (SQLi Göstergesi)', conf: 'Yüksek', rep: loginBypassEv ? buildActiveCheckReport(loginBypassEv, LOGIN_BYPASS_CFG) : null, inputs: loginBypassEv?.inputsFound ?? 0, probes: loginBypassEv?.probesSent ?? 0, fc: loginBypassEv?.findings.length ?? 0 });

  // (YENİ — 6. pakete özel) Client-Side / JS Analizi: pasif JS bundle sır + source-map + zafiyetli-kütüphane.
  const jsEv = await collectJsAnalysisEvidence(host).catch(() => null);
  runs.push({ title: 'Client-Side / JS Analizi', conf: 'Yüksek', rep: jsEv ? buildActiveCheckReport(jsEv, JS_ANALYSIS_CFG) : null, inputs: jsEv?.inputsFound ?? 0, probes: jsEv?.probesSent ?? 0, fc: jsEv?.findings.length ?? 0 });

  // (YENİ — Faz 1-B) Client-Side Statik Analiz: DOM-XSS gösterge / postMessage / storage / SRI / tabnabbing / open-redirect.
  const csEv = await collectClientSideEvidence(host).catch(() => null);
  runs.push({ title: 'Client-Side Statik Analiz', conf: 'Orta', rep: csEv ? buildActiveCheckReport(csEv, CLIENT_SIDE_CFG) : null, inputs: csEv?.inputsFound ?? 0, probes: csEv?.probesSent ?? 0, fc: csEv?.findings.length ?? 0 });

  // (YENİ — Faz 2-A) Kimlik-Doğrulama Derinliği: enum/varsayılan-kimlik/lockout/reset/politika/cache/MFA/HTTP.
  const adEv = await collectAuthDepthEvidence(host, session).catch(() => null);
  runs.push({ title: 'Kimlik-Doğrulama Derinliği', conf: 'Yüksek', rep: adEv ? buildActiveCheckReport(adEv, AUTH_DEPTH_CFG) : null, inputs: adEv?.inputsFound ?? 0, probes: adEv?.probesSent ?? 0, fc: adEv?.findings.length ?? 0 });

  // (YENİ — Faz 2-B) Oturum Güvenliği Derinliği: CSRF/SameSite, session-id entropi, oturum-URL, prefix, timeout.
  const sdEv = await collectSessionDepthEvidence(host, session).catch(() => null);
  runs.push({ title: 'Oturum Güvenliği Derinliği', conf: 'Orta', rep: sdEv ? buildActiveCheckReport(sdEv, SESSION_DEPTH_CFG) : null, inputs: sdEv?.inputsFound ?? 0, probes: sdEv?.probesSent ?? 0, fc: sdEv?.findings.length ?? 0 });

  // (YENİ — Faz 3-A) Girdi & Header + Yapılandırma & İfşa derinliği (güvenli GET/OPTIONS/TRACE + statik).
  const ihEv = await collectInputHeaderEvidence(host, session).catch(() => null);
  runs.push({ title: 'Girdi & Header Derinliği', conf: 'Orta', rep: ihEv ? buildActiveCheckReport(ihEv, INPUT_HEADER_CFG) : null, inputs: ihEv?.inputsFound ?? 0, probes: ihEv?.probesSent ?? 0, fc: ihEv?.findings.length ?? 0 });
  const ceEv = await collectConfigExposureEvidence(host, session).catch(() => null);
  runs.push({ title: 'Yapılandırma & İfşa Derinliği', conf: 'Yüksek', rep: ceEv ? buildActiveCheckReport(ceEv, CONFIG_EXPOSURE_CFG) : null, inputs: ceEv?.inputsFound ?? 0, probes: ceEv?.probesSent ?? 0, fc: ceEv?.findings.length ?? 0 });
  const apiEv = await collectApiSecurityEvidence(host, session).catch(() => null);
  runs.push({ title: 'API Güvenliği Derinliği (OWASP API Top 10)', conf: 'Orta', rep: apiEv ? buildActiveCheckReport(apiEv, API_SECURITY_CFG) : null, inputs: apiEv?.inputsFound ?? 0, probes: apiEv?.probesSent ?? 0, fc: apiEv?.findings.length ?? 0 });
  const edEv = await collectEmailDnsEvidence(host).catch(() => null);
  runs.push({ title: 'E-posta & DNS Derinliği (Anti-Spoofing)', conf: 'Orta', rep: edEv ? buildActiveCheckReport(edEv, EMAIL_DNS_CFG) : null, inputs: edEv?.inputsFound ?? 0, probes: edEv?.probesSent ?? 0, fc: edEv?.findings.length ?? 0 });

  // (DÜRÜSTLÜK) Hiçbir kontrol veri toplayamadıysa (hedefe ulaşılamadı) -> "İncelenemedi" (null->Düşük DEĞİL).
  if (runs.every((r) => !r.rep)) return unscannableReport(host, 'kimlik-doğrulamalı kontroller');

  const levels: Array<Level | null> = runs.map((r) => (r.rep ? extractLevel(r.rep.findings) : null));
  const ranked = levels.map((lv, i) => ({ lv, i })).filter((x): x is { lv: Level; i: number } => x.lv !== null).sort((a, b) => levelRank(b.lv) - levelRank(a.lv));
  const worst: Level = ranked.length ? ranked[0].lv : 'low';
  const worstTitle = ranked.length ? runs[ranked[0].i].title : '';
  const anyFinding = runs.some((r) => r.fc > 0);
  const totalProbes = runs.reduce((s, r) => s + r.probes, 0);
  const dataOk = runs.filter((r) => r.rep).length;

  const box =
    `> ### Değerlendirme Özeti (Authenticated)\n` +
    `> **Bu tarama, verilen TEST hesabının oturumuyla KİMLİK-DOĞRULAMALI (login’li) bağlamda yapılmıştır.** ` +
    `${runs.length} authenticated kontrol değerlendirildi; toplam **${totalProbes}** istek. ` +
    (anyFinding ? `En yüksek risk **${worstTitle}** alanında (aşağıda detaylı).` : `Doğrulanmış kritik/yüksek seviyeli bir zafiyet öne çıkmadı.`) +
    `\n>\n> _Şifre hiçbir aşamada dışarı/üçüncü bir servise gönderilmedi; backend deterministik login yapıp yalnız oturumu (cookie/token) kullandı._`;

  // AJAN kontrolleri için 3 durum NET ayrılır (dürüstlük): 'unavailable' = advisory tamamlanamadı;
  // 'analyzed' = advisory GERÇEKTEN çalıştı (bulgu varsa gösterge, yoksa "AI analiz etti, vektör yok");
  // 'no_candidate' = pasif keşifle aday yoktu, advisory çağrılmadı (gerçek "kapsam dışı"). Böylece
  // "AI çalıştı ama temiz" ile "hiç uygulanamadı" birbirine KARIŞMAZ.
  const statusOf = (r: Run, lv: Level | null): string => {
    if (!r.rep) return 'Veri toplanamadı';
    if (r.fc > 0 && lv === 'high') return '⚠ Zafiyet göstergesi';
    if (r.fc > 0) return '⚠ Sınırlı gösterge';
    if (r.agentCheck) {
      // (Deney) advisory VARSAYILAN KAPALI -> bu kontrol deterministik çalışır; sonucu deterministik durumdan türet.
      if (r.agentStatus === 'disabled') return r.inputs === 0 ? 'İncelenemedi — güvenli test edilebilir yüzey yok' : '✓ Zafiyet kanıtı yok';
      if (r.agentStatus === 'unavailable' || r.agentUsed === false) return 'Ajan analizi tamamlanamadı (deterministik göstergeyle sınırlı)';
      if (r.agentStatus === 'analyzed') return '✓ AI advisory analiz etti — vektör yok';
      return 'Uygulanabilir giriş noktası yok (advisory çalıştırılmadı)'; // no_candidate
    }
    // (İş 2 tutarlılık) Numaralandırılabilir yüzey BULUNDU ama cross-account testi kapsam dışı olduğundan
    // komşu-ID probu BİLİNÇLİ çalıştırılmadı -> "temiz" DEĞİL; detay bölümüyle tutarlı ayrı durum.
    if (r.enumerableSurface && r.fc === 0) return '⚠ Yüzey bulundu — cross-account testi kapsam dışı';
    if (r.inputs === 0) return 'Uygulanabilir giriş noktası yok (Kapsam dışı)';
    return '✓ Zafiyet kanıtı yok';
  };
  const confCell = (r: Run): string => {
    if (!r.rep) return 'Kapsam dışı';
    if (r.agentCheck) {
      if (r.agentStatus === 'disabled') return r.inputs > 0 || r.fc > 0 ? r.conf : 'Kapsam dışı';
      if (r.agentStatus === 'unavailable' || r.agentUsed === false) return 'Sınırlı';
      if (r.agentStatus === 'analyzed') return r.conf; // AI gerçekten çalıştı -> güven göster
      return 'Kapsam dışı'; // no_candidate
    }
    if (r.enumerableSurface && r.fc === 0) return 'Kapsam dışı'; // yüzey var ama test çalıştırılmadı -> güven yok
    return r.inputs > 0 ? r.conf : 'Kapsam dışı';
  };
  // (blocker fix) YÖNETİCİ ÖZETİ satırı, KONTROL ÖZETİ tablosuyla AYNI kaynaktan/mantıktan türer —
  // ayrı statik "Düşük — bulunamadı" şablonu YOK. statusOf ile birebir tutarlı (her satır tek doğru durum).
  const statusSummary = (r: Run, lv: Level | null): string => {
    if (!r.rep || !lv) return 'veri toplanamadı';
    const hl = headlineOf(r.rep.findings);
    if (r.fc > 0) return `${RISK_WORD[lv]}${hl ? ` — ${hl}` : ''}`;                       // bulgu var -> seviye + başlık
    if (r.agentCheck) {
      if (r.agentStatus === 'disabled') return r.inputs === 0 ? 'İncelenemedi — güvenle test edilebilir yüzey bulunamadı (deterministik kontrol)' : `${RISK_WORD[lv]} — deterministik kontrol, göstergesi yok`;
      if (r.agentStatus === 'unavailable' || r.agentUsed === false) return 'Ajan analizi tamamlanamadı — deterministik göstergeyle sınırlı';
      if (r.agentStatus === 'analyzed') return 'Yapay zekâ destekli advisory analiz etti — uygulanabilir vektör tespit edilmedi';
      return 'Kapsam dışı — pasif keşifle uygulanabilir giriş noktası yok (advisory çalıştırılmadı)'; // no_candidate
    }
    if (r.enumerableSurface && r.fc === 0) return `Numaralandırılabilir yüzey bulundu (${r.enumerableSurface.count} değer) — kendi kaynağına erişim yetkili; cross-account IDOR kapsam dışı (komşu-ID bilinçli çalıştırılmadı)`;
    if (r.inputs === 0) return 'Kapsam dışı — uygulanabilir giriş noktası yok';
    return `${RISK_WORD[lv]}${hl ? ` — ${hl}` : ''}`;                                      // temiz çalıştı -> seviye + başlık
  };
  const tableRows = runs.map((r, i) => `| ${r.title} | ${statusOf(r, levels[i])} | ${confCell(r)} |`).join('\n');
  const controlTable = `## KONTROL ÖZETİ\n\n| Kontrol | Sonuç | Güven |\n|---------|-------|-------|\n${tableRows}\n\n> Güven yalnızca gerçekten uygulanabilen (giriş/çerez/uç bulunan) kontroller için gösterilir; uygulanamayan kontroller **Kapsam dışı**dır (ör. çerez yerine token kullanan oturumda çerez-bayrağı/fixation).\n`;

  const summary: string[] = [];
  summary.push(
    worst === 'low'
      ? `- **Genel risk seviyesi: Düşük** — ${runs.length} authenticated kontrol değerlendirildi; doğrulanmış kritik/yüksek seviyeli bir zafiyet öne çıkmadı.`
      : `- **Genel risk seviyesi: ${RISK_WORD[worst]}** — en yüksek risk **${worstTitle}** alanında.`,
  );
  summary.push(
    `- **Kapsam:** Bu bölüm **kimlik-doğrulamalı (login’li)** bağlamda çalışır; çerez/oturum/yetki, authenticated enjeksiyon/IDOR ve ${advisorActive ? 'isteğe bağlı bir **yapay zekâ danışma katmanı** destekli' : '**deterministik güvenlik kontrolleriyle**'} yetki yükseltme + çok-adımlı iş mantığı göstergelerini kapsar (backend güvenli uygular; ödeme/hesap-değişikliği tamamlama YOK). Cross-account (başka kullanıcının verisi) IDOR bu sürümün kapsamı dışındadır.`,
  );
  runs.forEach((r, i) => {
    summary.push(`- **${r.title}:** ${statusSummary(r, levels[i])}`);
  });
  summary.push('- **Önerilen ilk adım:** Çalıştırılan kontrollerdeki bulguları giderin; hazır adımlar "AI Çözüm Önerileri" bölümünde.');

  const genel =
    (worst === 'low'
      ? `${runs.length} authenticated doğrulama kontrolü değerlendirildi; doğrulanmış kritik/yüksek seviyeli bir zafiyet öne çıkmadı.`
      : `Çalıştırılan authenticated kontrollerde en yüksek risk **${worstTitle}** alanında tespit edildi; öncelikli olarak giderilmesi/doğrulanması önerilir.`) +
    ` Tüm kontroller GET-only/gözlemseldir; state-değiştiren istek gönderilmemiştir. Şifre dışarı/üçüncü bir servise gönderilmemiş, backend login yapıp yalnız oturumu kullanmıştır.`;

  const sections = runs.map((r) => {
    if (!r.rep) return `## ${r.title}\n\n> Bu kontrol için veri toplanamadı.\n`;
    return `## ${r.title}\n\n${detailOnly(r.rep.findings)}\n`;
  }).join('\n');

  const findingsRaw =
    `${box}\n\n` +
    `## YÖNETİCİ ÖZETİ\n\n${summary.join('\n')}\n\n` +
    `## GENEL DEĞERLENDİRME\n\n**Risk Seviyesi: ${RISK_WORD[worst]}**\n\n${genel}\n\n` +
    `${controlTable}\n${sections}`;

  const fixParts = runs.map((r) => (r.rep && r.rep.fixText.trim() ? `### ${r.title}\n\n${r.rep.fixText.trim()}` : '')).filter(Boolean);
  const fixTextRaw = `Bu bölüm, çalıştırılan authenticated kontrollerde tespit edilen bulgular için düzeltme önerileri içerir.\n\n${fixParts.join('\n\n')}`;

  void dataOk;
  // (part 2) MİRAS login'siz cümleleri authenticated bağlama çevir (kaynak şablonlara dokunmadan).
  return { findings: toAuthenticatedContext(findingsRaw), fixText: toAuthenticatedContext(fixTextRaw) };
}
