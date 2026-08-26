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
import { collectTransportSecurityEvidence, collectSubdomainTakeoverEvidence } from './transportSecurityChecks.js';
import { collectActiveIndicatorsEvidence } from './activeIndicators.js';
import { suggestPricingForHost } from './pricingModel.js';
import { logScanStep } from './scanLogger.js';
import {
  buildActiveCheckReport, buildInjectionReport, buildIdorReport, generateBundleActiveVerifyReport,
  RISK_WORD, RISK_WORD_DE, RISK_WORD_EN, SEV_DISP, levelRank, extractLevel, headlineOf, detailOnly, type Level,
} from './activeVerifyReports.js';
import { resolveOrigin } from './surfaceEvidence.js';
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
  whatCheckedDe: [
    'Aus den nach dem Login beobachteten Cookies wurden nur echte **Server-Sitzungscookies** bewertet.',
    'Für jedes Sitzungscookie wurden die Sicherheits-Flags **Secure / HttpOnly / SameSite** geprüft.',
    'Analyse-/Drittanbieter-Cookies (_ga, _fbp, _clck usw.) gelten nicht als Sitzungscookies (HttpOnly ist bei ihnen unmöglich) — sie werden nicht bewertet.',
  ],
  fixTitleDe: 'Cookie-Sicherheit',
  fixFoundDe: ['Fügen Sie Sitzungscookies die Flags **Secure + HttpOnly + SameSite=Strict/Lax** hinzu.', 'HttpOnly verhindert das Auslesen des Cookies per JavaScript (XSS); Secure verhindert die Preisgabe über einfaches HTTP; SameSite reduziert CSRF.'],
  fixCleanDe: ['Erzwingen Sie bei Sitzungscookies proaktiv die Flags Secure/HttpOnly/SameSite.'],
  cleanGenelDe: 'Bei den Sitzungscookies wurde kein fehlendes Sicherheits-Flag beobachtet (oder die Sitzung ist nicht cookie-basiert).',
  whatCheckedEn: [
    'Among the cookies observed after login, only real **server session cookies** were assessed.',
    'For each session cookie, the **Secure / HttpOnly / SameSite** security flags were checked.',
    'Analytics/3rd-party cookies (_ga, _fbp, _clck etc.) are not counted as session cookies (HttpOnly is impossible on them) — they are not assessed.',
  ],
  fixTitleEn: 'Cookie Security',
  fixFoundEn: ['Add the **Secure + HttpOnly + SameSite=Strict/Lax** flags to session cookies.', 'HttpOnly prevents the cookie being read via JavaScript (XSS); Secure prevents leakage over plain HTTP; SameSite reduces CSRF.'],
  fixCleanEn: ['Proactively enforce Secure/HttpOnly/SameSite flags on session cookies.'],
  cleanGenelEn: 'No missing security flag was observed on the session cookies (or the session is not cookie-based).',
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
  whatCheckedDe: [
    'Der VOR dem Login (unauthentifiziert) von der Startseite bezogene Sitzungscookie-Wert wurde beobachtet.',
    'Er wurde mit dem Sitzungscookie-Wert NACH dem Login **verglichen** (bei Gleichheit erneuert der Server die Sitzung nicht).',
    'Nur ein einziges GET; es wurde kein Zustand geändert.',
  ],
  fixTitleDe: 'Session Fixation',
  fixFoundDe: ['**Erneuern Sie** bei erfolgreichem Login unbedingt den Sitzungsbezeichner (Session Regeneration); machen Sie die vor dem Login vergebene ID ungültig.'],
  fixCleanDe: ['Standardisieren Sie die Erneuerung der Sitzungs-ID beim Login (Session Regeneration).'],
  cleanGenelDe: 'Da das Sitzungscookie nach dem Login erneuert wurde (oder die Sitzung nicht cookie-basiert ist), wurde kein Fixation-Indikator beobachtet.',
  whatCheckedEn: [
    'The session cookie value taken from the home page BEFORE login (unauthenticated) was observed.',
    'It was **compared** with the session cookie value AFTER login (if equal, the server does not renew the session).',
    'A single GET only; no state was changed.',
  ],
  fixTitleEn: 'Session Fixation',
  fixFoundEn: ['**Always renew** the session identifier on successful login (session regeneration); invalidate the id issued before login.'],
  fixCleanEn: ['Make session-id renewal (session regeneration) standard on login.'],
  cleanGenelEn: 'Because the session cookie was renewed after login (or the session is not cookie-based), no fixation indicator was observed.',
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
  whatCheckedDe: [
    'Ein geschützter Endpunkt (whoami/Profil), der mit der Sitzung 200 zurückgibt, wurde identifiziert.',
    'Ein per GET aufrufbarer Logout-Endpunkt wurde erprobt (**kein POST** — kein Zustandswechsel).',
    'Es wurde geprüft, ob NACH dem Logout mit DEMSELBEN Token erneut auf den geschützten Endpunkt zugegriffen werden kann.',
  ],
  fixTitleDe: 'Sitzungsinvalidierung',
  fixFoundDe: ['**Machen Sie** das Sitzungs-Token beim Logout **serverseitig ungültig** (Revocation/Expiry); das clientseitige Löschen des Tokens allein genügt nicht.'],
  fixCleanDe: ['Wenden Sie eine serverseitige Sitzungsinvalidierung (Revocation) an.'],
  cleanGenelDe: 'Da die Sitzung nach dem Logout ungültig gemacht wurde (oder kein serverseitiger Logout-Endpunkt vorhanden ist), wurde kein Befund beobachtet.',
  whatCheckedEn: [
    'A protected endpoint (whoami/profile) that returns 200 with the session was identified.',
    'A logout endpoint callable via GET was tried (**no POST** — no state change).',
    'It was checked whether the protected endpoint can be accessed again with the SAME token AFTER logout.',
  ],
  fixTitleEn: 'Session Invalidation',
  fixFoundEn: ['**Invalidate the session token server-side** on logout (revocation/expiry); client-side token deletion alone is not enough.'],
  fixCleanEn: ['Apply server-side session invalidation (revocation).'],
  cleanGenelEn: 'Because the session was invalidated after logout (or there is no server-side logout endpoint), no finding was observed.',
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
  whatCheckedDe: [
    'An gängige Admin-/Verwaltungs-Endpunkte wurde mit der Sitzung des VORHANDENEN (vermutlich niedrig privilegierten) Testkontos eine **GET**-Anfrage gesendet.',
    'Zur Vermeidung von Falsch-Positiven wurden nur 200er als Befund gewertet, die **ABWEICHENDEN** Inhalt/JSON gegenüber der Startseiten-Shell zurückgaben.',
    'Ein einziger Versuch, nur GET, dem Schutzschalter unterworfen.',
  ],
  fixTitleDe: 'Funktionsebenen-Autorisierung',
  fixFoundDe: ['Wenden Sie an jedem Verwaltungs-/sensiblen Endpunkt eine **serverseitige Rollen-/Berechtigungsprüfung** an; ein bloßes Ausblenden in der UI genügt nicht.'],
  fixCleanDe: ['Schützen Sie Verwaltungs-Endpunkte durch serverseitige Rollenprüfung (proaktiv).'],
  cleanGenelDe: 'Es wurde kein Admin-/Verwaltungs-Endpunkt beobachtet, der mit einer niedrig privilegierten Sitzung erreichbar war.',
  whatCheckedEn: [
    'A **GET** request was sent to common admin/management endpoints with the session of the AVAILABLE (presumably low-privilege) test account.',
    'To avoid false positives, only 200s returning content/JSON **DIFFERENT** from the home-page shell were counted as a finding.',
    'A single attempt, GET-only, subject to the circuit breaker.',
  ],
  fixTitleEn: 'Function-Level Authorization',
  fixFoundEn: ['Apply a **server-side role/permission check** on every management/sensitive endpoint; hiding in the UI alone is not enough.'],
  fixCleanEn: ['Protect management endpoints with a server-side role check (proactive).'],
  cleanGenelEn: 'No admin/management endpoint reachable with a low-privilege session was observed.',
};

// (İş A) NE KONTROL EDİLDİ ilk satırı advisor durumuna göre koşullu: KAPALI (varsayılan) -> deterministik dil;
// AÇIK (AUTH_ADVISOR_HOSTS) -> AI-danışma dili. Tek 'agentStatus' bayrağından türer (rapor kendiyle çelişmez).
const PRIVESC_WC_DET = 'Keşfedilen authenticated yüzeyde **deterministik olarak** yetki-alanı içeren form/API (kayıt/profil/ayar tipi) arandı.';
const PRIVESC_WC_AI = 'Keşfedilen authenticated yüzeyden **Otonom Analiz Motoru** (yalnız JSON öneri; doğrudan HTTP atmaz) yetki-alanı içeren form/API seçti.';
const PRIVESC_WC_DET_DE = 'Auf der entdeckten authentifizierten Oberfläche wurde **deterministisch** nach Formularen/APIs mit Berechtigungsbezug (Registrierung/Profil/Einstellung) gesucht.';
const PRIVESC_WC_AI_DE = 'Aus der entdeckten authentifizierten Oberfläche wählte die **autonome Analyse-Engine** (nur JSON-Vorschlag; sendet keine direkten HTTP-Anfragen) Formulare/APIs mit Berechtigungsbezug aus.';
const MULTISTEP_WC_DET = '**Deterministik olarak** çok-adımlı akış/fiyat-kupon alanı arandı; backend YALNIZ **GET-gözlem** yaptı.';
const MULTISTEP_WC_AI = '**Otonom Analiz Motoru** (yalnız JSON öneri) çok-adımlı akış/fiyat-kupon alanı seçti; backend YALNIZ **GET-gözlem** yaptı.';
const MULTISTEP_WC_DET_DE = '**Deterministisch** wurde nach mehrstufigen Abläufen/Preis-Coupon-Feldern gesucht; das Backend führte NUR **GET-Beobachtung** durch.';
const MULTISTEP_WC_AI_DE = 'Die **autonome Analyse-Engine** (nur JSON-Vorschlag) wählte mehrstufige Abläufe/Preis-Coupon-Felder aus; das Backend führte NUR **GET-Beobachtung** durch.';
const PRIVESC_WC_DET_EN = 'The discovered authenticated surface was searched **deterministically** for forms/APIs with a privilege field (registration/profile/settings type).';
const PRIVESC_WC_AI_EN = 'The **Autonomous Analysis Engine** (JSON suggestion only; sends no direct HTTP) selected forms/APIs with a privilege field from the discovered authenticated surface.';
const MULTISTEP_WC_DET_EN = 'Multi-step flows/price-coupon fields were searched for **deterministically**; the backend performed **GET observation** ONLY.';
const MULTISTEP_WC_AI_EN = 'The **Autonomous Analysis Engine** (JSON suggestion only) selected multi-step flows/price-coupon fields; the backend performed **GET observation** ONLY.';
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
  whatCheckedDe: [
    PRIVESC_WC_DET_DE,
    'Falls eine sicher prüfbare Oberfläche gefunden wurde, wurde mit einer **sicheren, authenticated-light** Funktion EINE beobachtende Mass-Assignment-Sonde (`role/isAdmin`-Zusatzfeld) angewendet.',
    '⚠️ Es wurde KEINE echte Ausweitung durchgeführt; es wurde nicht mit erhöhten Rechten erneut angemeldet; die Sitzung wurde nicht verlassen; auf konten-ändernde/Checkout-Ziele wurde **nicht geschrieben** (Blocklist auf Codeebene).',
  ],
  confidenceNoteDe: 'Der Mass-Assignment-Indikator wurde nur aus der ersten Antwort abgeleitet (geringe Konfidenz); eine sichere Verifizierung erfordert einen manuellen Test.',
  fixTitleDe: 'Rechteausweitung / Mass-Assignment',
  fixFoundDe: ['Binden Sie bei der Modellbindung per **Allowlist** nur erlaubte Felder; nehmen Sie Felder wie `role/isAdmin` NIEMALS vom Client entgegen.', 'Nehmen Sie die Rollenzuweisung serverseitig nur in autorisierten Abläufen vor.'],
  fixCleanDe: ['Wenden Sie Mass-Assignment-Schutz (Feld-Allowlist) an; akzeptieren Sie Rollen-/Berechtigungsfelder nicht vom Client (proaktiv).'],
  cleanGenelDe: 'Es wurde kein geeignetes Registrierungs-/Profilformular gefunden oder die `role/isAdmin`-Mass-Assignment-Sonde wurde nicht akzeptiert.',
  whatCheckedEn: [
    PRIVESC_WC_DET_EN,
    'If a safely testable surface was found, ONE observational mass-assignment probe (`role/isAdmin` extra field) was applied with a **safe, authenticated-light** function.',
    '⚠️ No real escalation was COMPLETED; no re-login with elevated privilege; the session was not left; account-changing/checkout targets were **not written to** (code-level blocklist).',
  ],
  confidenceNoteEn: 'The mass-assignment indicator was derived only from the first response (low confidence); definitive verification requires a manual test.',
  fixTitleEn: 'Privilege Escalation / Mass-Assignment',
  fixFoundEn: ['Bind only permitted fields with an **allowlist** in model binding; NEVER accept fields like `role/isAdmin` from the client.', 'Perform role assignment server-side only in authorized flows.'],
  fixCleanEn: ['Apply mass-assignment protection (field allowlist); do not accept role/privilege fields from the client (proactive).'],
  cleanGenelEn: 'No suitable registration/profile form was found, or the `role/isAdmin` mass-assignment probe was not accepted.',
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
  whatCheckedDe: [
    MULTISTEP_WC_DET_DE,
    'Ein clientseitig veränderbares verstecktes Preis-/Mengen-/Coupon-Feld + ein ohne Vorbedingung erreichbarer „Bestätigungs"-Schritt wurden beobachtet.',
    '⚠️ Nur bis zum Warenkorb/Formular; **Zahlung/Checkout NICHT abgeschlossen** (Blocklist auf Codeebene); es wurde keine Ressource verbraucht.',
  ],
  confidenceNoteDe: 'Geschäftslogik-Schwachstellen sind kontextspezifisch; diese Prüfung ist auf Oberflächen-/Indikatorebene.',
  fixTitleDe: 'Mehrstufige Geschäftslogik',
  fixFoundDe: ['Verarbeiten Sie Preis-/Mengen-/Rabatt-/Coupon-Werte **niemals** mit dem vom Client gelieferten Wert; berechnen/validieren Sie sie serverseitig neu.', 'Erzwingen Sie in mehrstufigen Abläufen die Vorbedingung jedes Schritts serverseitig; verbrauchen Sie Coupons atomar als Einmal-Gebrauch.'],
  fixCleanDe: ['Validieren Sie kritische Werte serverseitig; wenden Sie eine Schrittreihenfolge- + Coupon-Wiederverwendungsprüfung an (proaktiv).'],
  cleanGenelDe: 'Es wurde kein beobachtbares clientseitiges Preis-/Coupon-Feld oder ein direkt erreichbarer „Bestätigungs"-Schritt gefunden.',
  whatCheckedEn: [
    MULTISTEP_WC_DET_EN,
    'A client-modifiable hidden price/quantity/coupon field + a "confirmation" step reachable without a precondition were observed.',
    '⚠️ Only up to the cart/form; **payment/checkout NOT completed** (code-level blocklist); no resource was consumed.',
  ],
  confidenceNoteEn: 'Business-logic vulnerabilities are context-specific; this check is at the surface/indicator level.',
  fixTitleEn: 'Multi-Step Business Logic',
  fixFoundEn: ['**Never** process price/quantity/discount/coupon values with the value coming from the client; recompute/validate them server-side.', 'Enforce the precondition of each step server-side in multi-step flows; consume coupons atomically as single-use.'],
  fixCleanEn: ['Validate critical values server-side; apply step-order + coupon-reuse control (proactive).'],
  cleanGenelEn: 'No observable client-side price/coupon field or directly reachable "confirmation" step was found.',
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
  whatCheckedDe: [
    'Trägt die Sitzung ein **JWT-Bearer**, wurde das Token OFFLINE dekodiert und analysiert: Signaturalgorithmus (**alg=none / unsigniert**), ob das Signaturgeheimnis **schwach/verbreitet** ist (OFFLINE-Verifizierung mit gängigen Geheimnissen) und **sensible/übermäßige Claims** im Token-Körper (Passwort/Geheimnis, Rolle/Berechtigung).',
    'Zusätzlich eine EINZIGE, harmlose Beobachtung: Wird ein unsigniertes (alg=none) gefälschtes Token an einem geschützten Endpunkt AKZEPTIERT (nur Beobachtung; der Zugriff wurde nicht genutzt).',
    '⚠️ KEINE echte Ausnutzung — keine Token-Übernahme/Rechteausweitung; nur der Sicherheitsindikator wurde berichtet.',
  ],
  confidenceNoteDe: 'Schwaches-Geheimnis- und alg=none-AKZEPTANZ-Indikatoren sind eindeutig (hohe Konfidenz); Claim-Beobachtungen sind informativ.',
  fixTitleDe: 'JWT / Token-Sicherheit',
  fixFoundDe: ['**Fixieren Sie** den Signaturalgorithmus serverseitig (z. B. nur RS256/HS256); LEHNEN Sie `alg=none` und clientseitig gewählte Algorithmen AB.', 'Machen Sie das JWT-Signaturgeheimnis **stark/zufällig** (256-Bit+); legen Sie sensible Daten wie Geheimnis/Passwort NICHT in den Token-Körper (der JWT-Körper ist nicht verschlüsselt).', 'Fügen Sie dem Token `exp` (kurze Lebensdauer) hinzu; stützen Sie kritische Berechtigungs-/Rollenentscheidungen auf serverseitige Validierung statt auf Client-Claims.'],
  fixCleanDe: ['Fixieren Sie den Signaturalgorithmus, verwenden Sie ein starkes Geheimnis, fügen Sie `exp` hinzu und tragen Sie keine sensiblen Claims (proaktiv).'],
  cleanGenelDe: 'Es wurde kein JWT/Token-Sicherheitsindikator gefunden oder die Sitzung trägt kein JWT.',
  whatCheckedEn: [
    'If the session carries a **JWT bearer**, the token was decoded and analysed OFFLINE: the signature algorithm (**alg=none / unsigned**), whether the signing secret is **weak/common** (OFFLINE verification with common secrets), and **sensitive/excessive claims** in the token body (password/secret, role/privilege).',
    'In addition, a SINGLE harmless observation: whether an unsigned (alg=none) forged token is ACCEPTED at a protected endpoint (observation only; the access was not used).',
    '⚠️ No real exploitation — no token takeover/privilege escalation; only the security indicator was reported.',
  ],
  confidenceNoteEn: 'Weak-secret and alg=none ACCEPTANCE indicators are definitive (high confidence); claim observations are informational.',
  fixTitleEn: 'JWT / Token Security',
  fixFoundEn: ['**Pin** the signature algorithm server-side (e.g. RS256/HS256 only); REJECT `alg=none` and client-chosen alg.', 'Make the JWT signing secret **strong/random** (256-bit+); do NOT place sensitive data such as a secret/password in the token body (the JWT body is not encrypted).', 'Add `exp` (short-lived) to the token; base critical privilege/role decisions on server-side validation, not on client claims.'],
  fixCleanEn: ['Pin the signature algorithm, use a strong secret, add `exp` and carry no sensitive claims (proactive).'],
  cleanGenelEn: 'No JWT/token security indicator was found, or the session does not carry a JWT.',
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
  whatCheckedDe: [
    'An den Login-Endpunkt wurden zuerst **ungültige Zugangsdaten** (Kontrolle) gesendet; anschließend wurden klassische SQLi-Payloads (`\' OR \'1\'=\'1` usw.) erprobt und beobachtet, ob — im Gegensatz zur Kontrolle — eine Sitzung/ein Erfolg (Token/2xx) zurückkam.',
    'Der Login-POST ist bereits ein erlaubter Ablauf; es handelt sich um eine EINZIGE, harmlose Beobachtung.',
    '⚠️ KEINE Sitzungsübernahme/Ausnutzung — nur die Beobachtung, „ob ein Indikator für eine Authentifizierungsumgehung vorliegt".',
  ],
  confidenceNoteDe: 'Der Indikator beruht auf dem Vergleich mit dem Kontrollversuch; eine sichere Verifizierung erfordert einen manuellen Test.',
  fixTitleDe: 'Login-Bypass / SQL-Injektion',
  fixFoundDe: ['Verwenden Sie in Authentifizierungsabfragen **parametrisierte Abfragen / Prepared Statements**; fügen Sie Benutzereingaben niemals direkt in SQL ein.', 'Eingabevalidierung + sichere ORM-APIs; geben Sie bei fehlerhaftem Login eine einheitliche Fehlermeldung zurück.'],
  fixCleanDe: ['Wenden Sie parametrisierte Abfragen + Eingabevalidierung an (proaktiv); sichern Sie den Authentifizierungsablauf gegen SQLi ab.'],
  cleanGenelDe: 'Es wurde kein Login-Bypass-(SQLi-)Indikator gefunden oder es gab keinen prüfbaren Login-Endpunkt.',
  whatCheckedEn: [
    'The login endpoint was first sent **invalid credentials** (control); then classic SQLi payloads (`\' OR \'1\'=\'1` etc.) were tried and it was observed whether — contrary to the control — a session/success (token/2xx) was returned.',
    'The login POST is already a permitted flow; it is a SINGLE, harmless observation.',
    '⚠️ No session takeover/exploitation — only the observation of "whether an authentication-bypass indicator is present".',
  ],
  confidenceNoteEn: 'The indicator is based on comparison with the control attempt; definitive verification requires a manual test.',
  fixTitleEn: 'Login Bypass / SQL Injection',
  fixFoundEn: ['Use **parameterised queries / prepared statements** in authentication queries; never place user input directly into SQL.', 'Input validation + safe ORM APIs; return a uniform error message on failed login.'],
  fixCleanEn: ['Apply parameterised queries + input validation (proactive); close the authentication flow to SQLi.'],
  cleanGenelEn: 'No login-bypass (SQLi) indicator was found, or there was no testable login endpoint.',
};

// (blocker fix — part 2) Aktif Doğrulama'nın (login'siz) şablonundan MİRAS kalan "kimlik doğrulaması
// olmadan / kapsam dışı" cümlelerini authenticated bağlama çevirir. buildInjection/Idor/ActiveCheckReport
// DİĞER paketlerde AYNEN kalır — bu yalnız authenticated raporu POST-İŞLER (kaynak şablonlara dokunmaz).
function toAuthenticatedContext(md: string, locale: string | boolean = false): string {
  const de = locale === true || locale === 'de', en = locale === 'en';
  if (en) {
    return md
      .replace(
        /(#{2,3}) SCOPE \(IMPORTANT\)[\s\S]*?\(\*\*Review required \/ Out of scope\*\*\)\.\n\n/,
        '$1 SCOPE (IMPORTANT)\n\nThis section was run with the **session (logged in)** of the TEST account you provided and tests unauthorized access to the account\'s **own** enumerable resources. A **cross-account** test (accessing another user\'s data) is outside the scope of this version (it requires two separate accounts). The absence of findings does not prove that there is no IDOR in all authenticated flows.\n\n',
      )
      .replace(
        /Areas that require authentication and internal logic are outside the scope of this package\./g,
        'This section was run with the session of the TEST account you provided in an authenticated (logged-in) context; completion of payment/account-status change is blocked at the code level.',
      )
      .replace(/without authentication/g, 'with an authenticated session');
  }
  if (de) {
    return md
      .replace(
        /(#{2,3}) GELTUNGSBEREICH \(WICHTIG\)[\s\S]*?\(\*\*Prüfung erforderlich \/ Außerhalb des Umfangs\*\*\)\.\n\n/,
        '$1 GELTUNGSBEREICH (WICHTIG)\n\nDieser Abschnitt wurde mit der **Sitzung (angemeldet)** des von Ihnen bereitgestellten TEST-Kontos ausgeführt und prüft den unbefugten Zugriff auf die **eigenen** enumerierbaren Ressourcen des Kontos. Ein **Cross-Account**-Test (Zugriff auf die Daten eines anderen Benutzers) liegt außerhalb des Umfangs dieser Version (erfordert zwei separate Konten). Das Fehlen von Befunden beweist nicht, dass in allen authentifizierten Abläufen kein IDOR vorliegt.\n\n',
      )
      .replace(
        /Bereiche, die eine Authentifizierung erfordern, sowie die interne Logik liegen außerhalb des Geltungsbereichs dieses Pakets\./g,
        'Dieser Abschnitt wurde mit der Sitzung des von Ihnen bereitgestellten TEST-Kontos in einem authentifizierten (angemeldeten) Kontext ausgeführt; der Abschluss von Zahlung/Kontostatusänderung ist auf Codeebene gesperrt.',
      )
      .replace(/ohne Authentifizierung/g, 'mit authentifizierter Sitzung');
  }
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
  whatCheckedDe: [
    'Die von der Seite geladenen JS-Bundles (script-src + inline) wurden abgerufen und **statisch** analysiert — KEINE aktive Ausnutzung, nur Herunterladen + Lesen.',
    '**A) Geheimnis-Scan:** Es wurde nach ECHTEN Geheimnissen wie privaten Schlüsseln, AWS/GCP-Anmeldedaten, Stripe **sk_live_**, GitHub/GitLab/Slack-Token, DB-Verbindungszeichenfolgen gesucht (Werte REDIGIERT).',
    '**Public-by-Design-Unterscheidung:** Firebase apiKey, GTM/GA-Mess-ID, Google-Maps-Browser-Key, Stripe **pk_**, reCAPTCHA-Site-Key sind konstruktionsbedingt öffentlich → gelten NICHT als „Offenlegung/Geheimnis", werden nur informativ gelistet.',
    '**B) Source-Map-Offenlegung:** `//# sourceMappingURL`-Kommentare + `.js.map`-Kandidaten wurden erprobt; eine erreichbare `.map` → Leck des Original-Quellcodes/-Baums.',
    '**C) Bekannt anfällige Bibliothek:** Geladene Bibliotheken + VERSIONEN wurden erkannt und KONSERVATIV mit bekannten CVEs abgeglichen; ist die Version nicht sicher lesbar, wurde KEIN CVE-Abgleich vorgenommen (Sprache „Patch-Bestätigung erforderlich"; nicht „ausnutzbar").',
  ],
  confidenceNoteDe: 'Alles ist passiv/statisch; Bibliotheksbefunde sind versionsbasierte Indikatoren (Ihre Distribution könnte gepatcht/backportiert sein — Bestätigung empfohlen).',
  fixTitleDe: 'Client-Side / JS-Sicherheit',
  fixFoundDe: [
    'Legen Sie KEINE echten Geheimnisse in Client-JS; **widerrufen/invalidieren** Sie erkannte sofort und nutzen Sie einen serverseitigen Proxy + Secret-Management (Secret Manager).',
    'Veröffentlichen Sie in der Produktion keine Source-Maps (oder beschränken Sie den Zugriff); entfernen Sie `.map`-Dateien aus dem öffentlichen Verzeichnis.',
    'Bringen Sie anfällige Bibliotheken auf eine aktuelle/gepatchte Version; ergänzen Sie SRI + Abhängigkeitsscans (retire.js/Dependabot).',
  ],
  fixCleanDe: ['Bewahren Sie keine Geheimnisse in Client-JS auf; veröffentlichen Sie keine Source-Maps in der Produktion; halten Sie Bibliotheken aktuell und wenden Sie Abhängigkeitsscans an (proaktiv).'],
  cleanGenelDe: 'In den abgerufenen JS-Bundles wurde kein echtes Geheimnis, keine erreichbare Source-Map und keine bekannt anfällige (versionslesbare) Bibliothek beobachtet. Public-by-Design-Schlüssel (falls vorhanden) wurden oben informativ ausgewiesen.',
  whatCheckedEn: [
    'The JS bundles the page loads (script srcs + inline) were fetched and analysed **statically** — NO active exploitation, only download + read.',
    '**A) Secret scan:** REAL secrets such as private keys, AWS/GCP credentials, Stripe **sk_live_**, GitHub/GitLab/Slack tokens, DB connection strings were searched for (values REDACTED).',
    '**Public-by-design distinction:** Firebase apiKey, GTM/GA measurement id, Google Maps browser key, Stripe **pk_**, reCAPTCHA site key are public by design → NOT counted as "exposure/secret", listed only informationally.',
    '**B) Source-map exposure:** `//# sourceMappingURL` comments + `.js.map` candidates were tried; a reachable `.map` → leakage of the original source code/tree.',
    '**C) Known-vulnerable library:** loaded libraries + their VERSIONS were detected and CONSERVATIVELY matched against known CVEs; if the version could not be read safely, NO CVE match was made ("patch confirmation required" language; not "exploitable").',
  ],
  confidenceNoteEn: 'Everything is passive/static; library findings are version-based indicators (your distribution may be patched/backported — confirmation recommended).',
  fixTitleEn: 'Client-Side / JS Security',
  fixFoundEn: [
    'Do not place REAL secrets in client JS; **rotate/invalidate** any detected immediately and use a server-side proxy + secret management (secret manager).',
    'Do not publish source-maps in production (or restrict access); remove `.map` files from the public directory.',
    'Upgrade vulnerable libraries to a current/patched version; add SRI + dependency scanning (retire.js/Dependabot).',
  ],
  fixCleanEn: ['Keep no secrets in client JS; do not publish source-maps in production; keep libraries current and apply dependency scanning (proactive).'],
  cleanGenelEn: 'No real secret, reachable source-map or known-vulnerable (version-readable) library was observed in the fetched JS bundles. Public-by-design keys (if any) are separated informationally above.',
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
  whatCheckedDe: [
    'Auf demselben JS/HTML-Corpus wurden **statisch** (KEINE aktive Ausnutzung) 6 clientseitige Prüfungen durchgeführt.',
    '**1) DOM-based XSS (Indikator):** Steht eine gefährliche Sink (innerHTML/document.write/eval/.html()/location=) mit einer benutzergesteuerten Quelle (location.hash/search, referrer, window.name) im SELBEN Ausdruck — **KEIN nachgewiesenes XSS**, ein Indikator geringer Konfidenz (dynamische Verifizierung erforderlich).',
    '**2) postMessage:** Erfolgt in `message`-Event-Listenern eine **event.origin-Prüfung**.',
    '**3) Browser-Storage:** Schreiben **sensibler Daten** (Token/JWT/Sitzung) in localStorage/sessionStorage (statisch; Wert REDIGIERT).',
    '**4) Fehlendes SRI:** Haben externe script/style ein `integrity`-Attribut (Lieferkette).',
    '**5) Reverse Tabnabbing:** Haben `target="_blank"`-Links `rel="noopener/noreferrer"`.',
    '**6) Open Redirect:** **eine einzige sichere Sonde** an im HTML BEOBACHTETE Weiterleitungsparameter — eine harmlose externe URL wurde gesendet und Location beobachtet; **Redirect wurde NICHT verfolgt**.',
  ],
  confidenceNoteDe: 'DOM-XSS-Befunde sind STATISCHE Indikatoren (hohes Falsch-Positiv-Potenzial; dynamische Verifizierung erforderlich). Die übrigen sind deterministische Beobachtungen.',
  fixTitleDe: 'Client-Side-Statiksicherheit',
  fixFoundDe: [
    'DOM-XSS: Verarbeiten Sie benutzergesteuerte Daten statt mit innerHTML/eval/document.write mit textContent + sicherer API; sanitisieren Sie bei Bedarf mit DOMPurify.',
    'postMessage: Validieren Sie in jedem `message`-Handler `event.origin` per Allowlist.',
    'Storage: Bewahren Sie das Sitzungs-Token statt im localStorage in einem **HttpOnly + Secure Cookie** auf.',
    'SRI: Fügen Sie externen script/style `integrity` + `crossorigin` hinzu. Tabnabbing: `rel="noopener noreferrer"` an `target="_blank"`-Links.',
    'Open Redirect: Beschränken Sie Weiterleitungsziele serverseitig per **Allowlist**; leiten Sie nicht auf externe absolute URLs weiter.',
  ],
  fixCleanDe: ['Verwenden Sie DOM-Sinks mit sicherer API + Sanitisierung; validieren Sie postMessage-Origin; bewahren Sie das Token in einem HttpOnly-Cookie auf; wenden Sie SRI + rel=noopener + Redirect-Allowlist an (proaktiv).'],
  cleanGenelDe: 'Bei der statischen Analyse wurde kein eindeutiger DOM-XSS-Indikator, kein unsicherer Message-Handler, kein Schreiben sensibler Daten in Storage, kein fehlendes SRI, kein Tabnabbing und keine offene Weiterleitung beobachtet.',
  whatCheckedEn: [
    '6 client-side checks were performed **statically** (NO active exploitation) on the same JS/HTML corpus.',
    '**1) DOM-based XSS (indicator):** whether a dangerous sink (innerHTML/document.write/eval/.html()/location=) and a user-controlled source (location.hash/search, referrer, window.name) are in the SAME expression — **NOT proven XSS**, a low-confidence indicator (dynamic verification required).',
    '**2) postMessage:** whether `message` event listeners perform an **event.origin check**.',
    '**3) Browser storage:** writing of **sensitive data** (token/JWT/session) to localStorage/sessionStorage (static; value REDACTED).',
    '**4) Missing SRI:** whether external script/style has an `integrity` attribute (supply chain).',
    '**5) Reverse tabnabbing:** whether `target="_blank"` links have `rel="noopener/noreferrer"`.',
    '**6) Open redirect:** a **single safe probe** to redirect parameters OBSERVED in the HTML — a harmless external URL was sent and Location observed; **the redirect was NOT followed**.',
  ],
  confidenceNoteEn: 'DOM-XSS findings are STATIC indicators (high false-positive potential; dynamic verification required). The others are deterministic observations.',
  fixTitleEn: 'Client-Side Static Security',
  fixFoundEn: [
    'DOM-XSS: process user-controlled data with textContent + a safe API instead of innerHTML/eval/document.write; sanitise with DOMPurify if needed.',
    'postMessage: validate `event.origin` with an allowlist in every `message` handler.',
    'Storage: keep the session token in an **HttpOnly + Secure cookie** rather than localStorage.',
    'SRI: add `integrity` + `crossorigin` to external script/style. Tabnabbing: `rel="noopener noreferrer"` on `target="_blank"` links.',
    'Open redirect: restrict redirect targets server-side with an **allowlist**; do not redirect to external absolute URLs.',
  ],
  fixCleanEn: ['Use DOM sinks with a safe API + sanitisation; validate postMessage origin; keep the token in an HttpOnly cookie; apply SRI + rel=noopener + redirect allowlist (proactive).'],
  cleanGenelEn: 'Static analysis observed no clear DOM-XSS indicator, insecure message handler, sensitive storage write, missing SRI, tabnabbing or open redirect.',
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
  whatCheckedDe: [
    '9 Authentifizierungstiefen-Prüfungen (WSTG-ATHN/IDNT) — **sicher, geringes Volumen**; KEIN Brute-Force/DoS.',
    '**1) Konto-Enumeration:** Antwortunterschied bei gültigem (Testkonto) vs. ungültigem (zufälligem) Benutzer — je ein FEHLGESCHLAGENER Versuch; erstellt kein Konto.',
    '**2) Standard-Zugangsdaten:** kleine feste Liste (admin/admin usw.) — nur fehlgeschlagener Login; bei Annahme wird die Sitzung NICHT genutzt.',
    '**3) Schwaches Lockout/Rate-Limit:** einige Fehlversuche mit einem THROWAWAY-(zufälligen)-Benutzer — **ein echtes Konto wird NIEMALS gesperrt**.',
    '**4) Passwort-Reset:** Mechanismus-Beobachtung (Sicherheitsfrage/Token) — **es wird KEINE echte Reset-E-Mail AUSGELÖST** (nicht existierende E-Mail).',
    '**5) Passwort-/Registrierungsrichtlinie:** nur clientseitige Beobachtung — **es wird KEINE echte Registrierung durchgeführt**.',
    '**6) „Angemeldet bleiben"-Cookie · 7) Cache authentifizierter Seiten (Cache-Control) · 8) MFA-Vorhandensein (informativ) · 9) Anmeldedaten über unverschlüsselten Kanal (HTTP).**',
  ],
  confidenceNoteDe: 'Enumeration/Lockout/Reset-Befunde sind „Indikatoren" (Verifizierung erforderlich). Sicherheit: kein echtes Konto gesperrt, keine Reset-E-Mail gesendet, keine Registrierung durchgeführt, selbst bei erfolgreichem Login wurde die Sitzung nicht genutzt.',
  fixTitleDe: 'Authentifizierungs-Härtung',
  fixFoundDe: [
    'Enumeration: Geben Sie bei login/reset/register **einheitliche** Antwort/Nachricht/Zeit zurück (verraten Sie nicht, ob ein Benutzer existiert).',
    'Standard-Zugangsdaten: Entfernen Sie alle Standardkonten / erzwingen Sie eine Passwortänderung.',
    'Lockout: Wenden Sie bei aufeinanderfolgenden Fehlversuchen ein **konto- + IP-basiertes Rate-Limit / eine temporäre Sperre** an; fügen Sie CAPTCHA hinzu.',
    'Passwort-Reset: **Token-basiert** (Einmal-Gebrauch, kurze Lebensdauer), vermeiden Sie Sicherheitsfragen; verwenden Sie den Host-Header nicht im Reset-Link.',
    'Passwortrichtlinie: serverseitig **min. 8+ / Komplexität**; unverschlüsselter Kanal: führen Sie den Login **nur über HTTPS** durch; `Cache-Control: no-store` für sensible Seiten; bieten Sie **MFA** an.',
  ],
  fixCleanDe: ['Einheitliche Auth-Antworten, keine Standardkonten, Lockout/Rate-Limit + CAPTCHA, token-basierter Reset, starke Passwortrichtlinie, HTTPS-only-Login, no-store-Cache, MFA (proaktiv).'],
  cleanGenelDe: 'In den Authentifizierungstiefen-Prüfungen wurde kein eindeutiger Indikator für Enumeration, Standard-Zugangsdaten, schwaches Lockout, schwachen Reset oder unverschlüsselten Kanal beobachtet.',
  whatCheckedEn: [
    '9 authentication-depth checks (WSTG-ATHN/IDNT) — **safe, low volume**; NO brute-force/DoS.',
    '**1) Account enumeration:** response difference for a valid (test account) vs invalid (random) user — one FAILED attempt each; creates no account.',
    '**2) Default credentials:** a small fixed list (admin/admin etc.) — only a failed login; if accepted, the session is NOT used.',
    '**3) Weak lockout/rate-limit:** a few failed attempts with a THROWAWAY (random) user — **a real account is NEVER locked**.',
    '**4) Password reset:** mechanism observation (security question/token) — **NO real reset e-mail is TRIGGERED** (non-existent e-mail).',
    '**5) Password/registration policy:** client-side observation only — **NO real registration is performed**.',
    '**6) "Remember me" cookie · 7) Authenticated page cache (Cache-Control) · 8) MFA presence (informational) · 9) Credentials over an unencrypted channel (HTTP).**',
  ],
  confidenceNoteEn: 'Enumeration/lockout/reset findings are "indicators" (verification required). Safety: no real account was locked, no reset e-mail was sent, no registration was performed, and even if a successful login was found the session was not used.',
  fixTitleEn: 'Authentication Hardening',
  fixFoundEn: [
    'Enumeration: return a **uniform** response/message/timing on login/reset/register (do not leak whether a user exists).',
    'Default credentials: remove all default accounts / force a password change.',
    'Lockout: apply an **account + IP-based rate-limit / temporary lock** on consecutive failed attempts; add CAPTCHA.',
    'Password reset: **token-based** (single-use, short-lived), avoid security questions; do not use the Host header in the reset link.',
    'Password policy: **min 8+ / complexity** server-side; unencrypted channel: perform login **over HTTPS only**; `Cache-Control: no-store` for sensitive pages; offer **MFA**.',
  ],
  fixCleanEn: ['Uniform auth responses, no default accounts, lockout/rate-limit + CAPTCHA, token-based reset, strong password policy, HTTPS-only login, no-store cache, MFA (proactive).'],
  cleanGenelEn: 'The authentication-depth checks observed no clear indicator of enumeration, default credentials, weak lockout, weak reset or an unencrypted channel.',
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
  whatCheckedDe: [
    'FALLS ein ECHTES serverseitiges Sitzungscookie (Set-Cookie session) vorhanden ist, 5 Sitzungsverwaltungsprüfungen — alle **read-only/beobachtend** (KEINE zustandsändernde Übermittlung / kein echter CSRF-Angriff). Bei Bearer/JWT/token-basierten Zielen liegt dieser Abschnitt **außerhalb des Umfangs**.',
    '**1) CSRF (SESS-05):** Beobachtung von SameSite im Sitzungscookie + Anti-CSRF-Token im zustandsändernden POST-Formular (statisch; Formular NICHT abgesendet).',
    '**2) Session-ID-Entropie (SESS-01):** strukturelle Analyse der Sitzungs-ID (Länge/Charset/Entropie) — KEIN Brute; bei JWT einem separaten Abschnitt überlassen.',
    '**3) Sitzung in URL (SESS-04):** Wird die Session-ID in URL/Query (jsessionid/sid usw.) offengelegt.',
    '**4) Timeout / gleichzeitige Sitzungen (SESS-07/11):** beobachtender Indikator (sicherer Test manuell).',
    '**5) Cookie-Prefix (SESS-02):** Fehlt dem Sitzungscookie ein __Host-/__Secure--Prefix.',
  ],
  confidenceNoteDe: 'Die Befunde sind „Indikatoren" (kein echter CSRF-Angriff/Brute durchgeführt; Token/Sitzung REDIGIERT). Ohne serverseitiges Sitzungscookie liegen die Prüfungen außerhalb des Umfangs (Token/JWT-Sicherheit in separatem Abschnitt).',
  fixTitleDe: 'Sitzungssicherheits-Härtung',
  fixFoundDe: [
    'CSRF: Fügen Sie dem Sitzungscookie **SameSite=Lax/Strict** hinzu; erzwingen Sie bei zustandsändernden Anfragen ein **Anti-CSRF-Token** (Double-Submit / Synchronizer).',
    'Session-ID: Verwenden Sie eine mindestens **128-Bit zufällige** (CSPRNG) Sitzungs-ID; keine vorhersehbaren/sequenziellen Werte.',
    'Sitzung in URL: Tragen Sie die Session-ID **niemals in URL/Query** — nur im HttpOnly + Secure Cookie.',
    'Prefix: Setzen Sie das Sitzungscookie mit dem **`__Host-`**-Prefix (Secure + Path=/ + kein Domain). Timeout: angemessenes Idle-/Absolute-Timeout + serverseitige Invalidierung.',
  ],
  fixCleanDe: ['Sitzungscookie mit SameSite + __Host--Prefix, 128-Bit zufällige Session-ID, keine Sitzung in der URL, Anti-CSRF-Token, angemessenes Timeout (proaktiv).'],
  cleanGenelDe: 'Ein serverseitiges Sitzungscookie wurde beobachtet, jedoch kein eindeutiger Indikator für fehlendes CSRF/SameSite, schwache Session-ID, URL-Offenlegung oder fehlenden Prefix gefunden.',
  whatCheckedEn: [
    'IF a REAL server-side session cookie (Set-Cookie session) is present, 5 session-management checks — all **read-only/observational** (NO state-changing submission / no real CSRF attack). On a bearer/JWT/token-based target this section is **out of scope**.',
    '**1) CSRF (SESS-05):** observation of SameSite on the session cookie + anti-CSRF token in a state-changing POST form (static; form NOT submitted).',
    '**2) Session-id entropy (SESS-01):** structural analysis of the session id (length/charset/entropy) — NO brute; if a JWT, left to a separate section.',
    '**3) Session in URL (SESS-04):** whether the session id is exposed in the URL/query (jsessionid/sid etc.).',
    '**4) Timeout / concurrent sessions (SESS-07/11):** an observational indicator (definitive test is manual).',
    '**5) Cookie prefix (SESS-02):** whether the session cookie lacks a __Host-/__Secure- prefix.',
  ],
  confidenceNoteEn: 'Findings are "indicators" (no real CSRF attack/brute performed; token/session REDACTED). Without a server-side session cookie the checks are out of scope (token/JWT security in a separate section).',
  fixTitleEn: 'Session Security Hardening',
  fixFoundEn: [
    'CSRF: add **SameSite=Lax/Strict** to the session cookie; require an **anti-CSRF token** (double-submit / synchronizer) on state-changing requests.',
    'Session-id: use at least a **128-bit random** (CSPRNG) session id; do not use predictable/sequential values.',
    'Session in URL: **never carry the session id in the URL/query** — only in an HttpOnly + Secure cookie.',
    'Prefix: set the session cookie with the **`__Host-`** prefix (Secure + Path=/ + no Domain). Timeout: reasonable idle/absolute timeout + server-side invalidation.',
  ],
  fixCleanEn: ['Session cookie with SameSite + __Host- prefix, 128-bit random session id, no session in the URL, anti-CSRF token, reasonable timeout (proactive).'],
  cleanGenelEn: 'A server-side session cookie was observed, but no clear indicator of missing CSRF/SameSite, a weak session-id, URL exposure or a missing prefix was found.',
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
  whatCheckedDe: [
    'Sichere/read-only Eingabe- & Header-Prüfungen (nur GET/OPTIONS/TRACE — KEINE zustandsändernde/destruktive Anfrage).',
    '**D1 Host-Header-Injection:** Ein gefälschter `X-Forwarded-Host` wurde gesendet und die Reflexion in der Antwort beobachtet (Indikator).',
    '**D2 HTTP Parameter Pollution:** Derselbe Parameter wurde wiederholt und der Verarbeitungsunterschied beobachtet (beobachtend).',
    '**D3 HTTP-Methoden / TRACE:** Erkennung erlaubter Methoden per OPTIONS + TRACE-Beobachtung — **kein PUT/DELETE GESENDET**.',
    '**D4 Mixed Content:** statische Erkennung von HTTP-Ressourcen (script/img/iframe) auf einer HTTPS-Seite.',
    '**D5 Stored-XSS-Eingabepunkt:** KANDIDATEN-Felder, die in einen persistenten Kontext reflektiert werden könnten, wurden markiert — **es wurden KEINE Daten GESENDET/gespeichert** (geringe Konfidenz, dynamische Verifizierung erforderlich).',
  ],
  confidenceNoteDe: 'Host-Injection/HPP/D5 sind „Indikator/Kandidat" (kein echter Angriff/keine Übermittlung durchgeführt). TRACE/Mixed-Content sind deterministische Beobachtungen.',
  fixTitleDe: 'Eingabe- & Header-Härtung',
  fixFoundDe: [
    'Host-Header: Fixieren Sie in der Anwendung den Host/X-Forwarded-Host-Wert per **Allowlist**; verwenden Sie ihn nicht zur Erzeugung absoluter URLs.',
    'HTTP-Methoden: Deaktivieren Sie **TRACE**; erzwingen Sie bei zustandsändernden Methoden serverseitige Autorisierung.',
    'Mixed Content: Verlagern Sie alle Ressourcen auf **HTTPS** (upgrade-insecure-requests / CSP).',
    'Stored-XSS: Wenden Sie in persistenten Feldern Ausgabe-Kodierung + Sanitisierung (DOMPurify) an; verarbeiten Sie Parameter gegen HPP als Einzelwert.',
  ],
  fixCleanDe: ['Host-Allowlist, TRACE deaktiviert, alle Ressourcen HTTPS, Ausgabe-Kodierung/Sanitisierung bei persistenten Eingaben, Parameter-Deduplizierung (proaktiv).'],
  cleanGenelDe: 'In den Eingabe-/Header-Prüfungen wurde kein eindeutiger Indikator für Host-Injection, offenes TRACE, Mixed Content oder HPP gefunden.',
  whatCheckedEn: [
    'Safe/read-only input & header checks (GET/OPTIONS/TRACE only — NO state-changing/destructive request).',
    '**D1 Host header injection:** a spoofed `X-Forwarded-Host` was sent and reflection in the response observed (indicator).',
    '**D2 HTTP parameter pollution:** the same parameter was repeated and the processing difference observed (observational).',
    '**D3 HTTP methods / TRACE:** allowed-method discovery via OPTIONS + TRACE observation — **no PUT/DELETE SENT**.',
    '**D4 Mixed content:** static detection of HTTP resources (script/img/iframe) on an HTTPS page.',
    '**D5 Stored-XSS entry point:** CANDIDATE fields that could be reflected into a persistent context were flagged — **NO data was SENT/saved** (low confidence, dynamic verification required).',
  ],
  confidenceNoteEn: 'Host-injection/HPP/D5 are "indicator/candidate" (no real attack/submission performed). TRACE/mixed-content are deterministic observations.',
  fixTitleEn: 'Input & Header Hardening',
  fixFoundEn: [
    'Host header: pin the Host/X-Forwarded-Host value with an **allowlist** in the application; do not use it to build absolute URLs.',
    'HTTP methods: disable **TRACE**; enforce server-side authorization on state-changing methods.',
    'Mixed content: move all resources to **HTTPS** (upgrade-insecure-requests / CSP).',
    'Stored-XSS: apply output-encoding + sanitisation (DOMPurify) on persistent fields; process parameters as a single value against HPP.',
  ],
  fixCleanEn: ['Host allowlist, TRACE disabled, all resources HTTPS, output-encoding/sanitisation on persistent inputs, parameter de-duplication (proactive).'],
  cleanGenelEn: 'The input/header checks found no clear indicator of Host injection, open TRACE, mixed content or HPP.',
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
  whatCheckedDe: [
    'Sichere GET + statische Konfigurations-/Expositionsprüfungen. Als **SPA-catch-all 200 (Startseiten-Shell)** zurückgegebene erratene Pfade gelten NICHT als echt — nur tatsächlich erreichbare, UNTERSCHEIDBARE Antworten erzeugen einen Befund (Provenienz Spalte 0).',
    '**E1 Backup-/Altdatei:** `.env/.bak/.sql/.git/config` usw. per sicherem GET (Shell-200 herausgefiltert).',
    '**E2 Admin-Oberfläche:** Sind gängige Verwaltungspfade von außen erreichbar (gleiche Provenienz).',
    '**E3 Cloud-Storage:** Public-S3/GCS/Azure-Bucket-Referenz in HTML/JS + ist sie **auflistbar**.',
    '**E4 Cache-/Poisoning-Indikator:** Cache-Control/Vary + Reflexion ungekeyter Header (KEIN Poisoning durchgeführt).',
    '**E5 Kommentar- & Metadaten-Leck:** Dev-Kommentar / interne IP-Hostname / Server-Dateipfad (statisch).',
  ],
  confidenceNoteDe: 'Backup-/Admin-Befunde werden nur für tatsächlich erreichbare, NICHT-SPA-Shell-Antworten erzeugt. Cache-/Host-Indikatoren sind „Indikatoren"; Inhalt/sensible Daten REDIGIERT.',
  fixTitleDe: 'Konfigurations- & Expositions-Härtung',
  fixFoundDe: [
    'Entfernen Sie Backup-/Alt-/`.git`/`.env`-Dateien aus dem öffentlichen Verzeichnis; sperren Sie den Zugriff am Webserver.',
    'Stellen Sie Verwaltungsoberflächen hinter Netzwerk (IP-Allowlist/VPN) + Authentifizierung; öffnen Sie sie nicht nach außen.',
    'Cloud-Bucket: **Deaktivieren Sie die Auflistungsberechtigung**, machen Sie sensible Objekte privat (public nur für tatsächlich öffentliche Assets).',
    'Cache: Reflektieren Sie ungekeyte Eingaben nicht oder fügen Sie sie `Vary` hinzu. Kommentare: Belassen Sie im Produktions-Build keine Dev-Kommentare/internen Informationen.',
  ],
  fixCleanDe: ['Backup/.git/.env außerhalb des Verzeichnisses, Admin-Oberfläche hinter Auth/Netzwerk, Bucket privat/Auflistung deaktiviert, Cache Vary korrekt, in der Produktion Kommentar/Metadaten sauber (proaktiv).'],
  cleanGenelDe: 'Es wurde keine erreichbare Backup-/Altdatei, keine offene Admin-Oberfläche, kein auflistbarer Bucket, kein Cache-Poisoning-Indikator und kein eindeutiges Kommentar-/Metadaten-Leck beobachtet.',
  whatCheckedEn: [
    'Safe GET + static configuration/exposure checks. Guessed paths that return an **SPA catch-all 200 (home-page shell)** are NOT counted as real — only genuinely reachable, DISTINCTIVE responses produce a finding (Column 0 provenance).',
    '**E1 Backup/old file:** `.env/.bak/.sql/.git/config` etc. via safe GET (shell 200 filtered out).',
    '**E2 Admin interface:** whether common management paths are externally reachable (same provenance).',
    '**E3 Cloud storage:** public S3/GCS/Azure bucket reference in HTML/JS + whether it is **listable**.',
    '**E4 Cache / poisoning indicator:** Cache-Control/Vary + unkeyed-header reflection (NO poisoning performed).',
    '**E5 Comment & metadata leak:** dev comment / internal IP-hostname / server file path (static).',
  ],
  confidenceNoteEn: 'Backup/admin findings are produced only for genuinely reachable, NON-SPA-shell responses. Cache/host indicators are "indicators"; content/sensitive data REDACTED.',
  fixTitleEn: 'Configuration & Exposure Hardening',
  fixFoundEn: [
    'Remove backup/old/`.git`/`.env` files from the public directory; block access at the web server.',
    'Place management interfaces behind the network (IP allowlist/VPN) + authentication; do not expose them externally.',
    'Cloud bucket: **disable list permission**, make sensitive objects private (public only for genuinely public assets).',
    'Cache: do not reflect unkeyed input or add it to `Vary`. Comments: leave no dev comments/internal information in the production build.',
  ],
  fixCleanEn: ['Backup/.git/.env outside the directory, admin interface behind auth/network, bucket private/listing disabled, correct cache Vary, clean comments/metadata in production (proactive).'],
  cleanGenelEn: 'No reachable backup/old file, open admin interface, listable bucket, cache-poisoning indicator or clear comment/metadata leak was observed.',
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
  whatCheckedDe: [
    'An ECHTEN, aus Same-Origin-JS/HTML entdeckten API-Endpunkten, die JSON (NICHT SPA-catch-all-Shell) zurückgeben, 5 Prüfungen — alle read-only. Ohne echte API (Firebase/Client-SDK/SPA) liegt dieser Abschnitt **außerhalb des Umfangs**.',
    '**F1 BOLA/BFLA (API1/API5):** Objekt-/Funktionsebenen-Autorisierung — in den Abschnitten **Authentifizierte IDOR** + **Forced Browsing** bewertet (zur Vermeidung von Doppelbefunden hier nicht erneut sondiert).',
    '**F2 Übermäßige Datenoffenlegung / BOPLA (API3):** sensibles/übermäßiges Feld in der API-Antwort (Passwort-Hash/Rolle/interne ID) — Wert REDIGIERT.',
    '**F3 Rate-Limit (API4):** Erscheint nach einem MODERATEN Burst (KEIN DoS) ein 429/Rate-Limit-Header — das Ziel wurde nicht ermüdet.',
    '**F4 Shadow/veraltete Version (API9):** Sind Versions-Endpunkte wie /v1,/v2,/api/v1 erreichbar (SPA-Shell herausgefiltert).',
    '**F5 GraphQL-Introspection (APIT-99):** Ist bei vorhandenem GraphQL-Endpunkt die Introspection aktiv — **read-only-Abfrage; KEINE Mutation**.',
  ],
  confidenceNoteDe: 'Die Befunde sind „Indikatoren"; nur an tatsächlich beobachteten (JSON, NICHT-SPA-Shell) Endpunkten. Sensible Daten REDIGIERT; keine Mutation/Datenänderung/DoS durchgeführt.',
  fixTitleDe: 'API-Sicherheits-Härtung',
  fixFoundDe: [
    'BOLA/BFLA: Erzwingen Sie bei jeder API-Anfrage serverseitig die Objekteigentums- + Funktionsrollenprüfung (ID-Gültigkeit genügt nicht).',
    'Übermäßige Daten: Beschränken Sie Antworten per **Feld-Allowlist (DTO)**; senden Sie Passwort-Hash/Geheimnis/interne ID/Rolle nicht an den Client.',
    'Rate-Limit: **Rate-Limit + Kontingent** je Konto+IP+Endpunkt; kostenbasierte Grenze für schwere Endpunkte.',
    'Version: Deaktivieren Sie ungenutzte/alte API-Versionen. GraphQL: **Deaktivieren Sie in der Produktion die Introspection**; fügen Sie ein Abfragetiefen-/Komplexitätslimit hinzu.',
  ],
  fixCleanDe: ['Objekt-/Funktionsberechtigung serverseitig, Antwort-DTO-Allowlist, Rate-Limit+Kontingent, alte Versionen deaktiviert, GraphQL-Introspection deaktiviert (proaktiv).'],
  cleanGenelDe: 'An den entdeckten API-Endpunkten wurde kein eindeutiger Indikator für übermäßige Datenoffenlegung, fehlendes Rate-Limit, Shadow-Version oder offene GraphQL-Introspection gefunden.',
  whatCheckedEn: [
    '5 checks on REAL API endpoints discovered from same-origin JS/HTML that return JSON (NOT an SPA catch-all shell) — all read-only. Without a real API (Firebase/client-SDK/SPA) this section is **out of scope**.',
    '**F1 BOLA/BFLA (API1/API5):** object/function-level authorization — evaluated in the **Authenticated IDOR** + **Forced Browsing** sections (not re-probed here to avoid duplicate findings).',
    '**F2 Excessive data exposure / BOPLA (API3):** sensitive/excessive field in the API response (password-hash/role/internal-ID) — value REDACTED.',
    '**F3 Rate-limit (API4):** whether a 429/rate-limit header appears after a MODEST burst (NOT DoS) — the target was not exhausted.',
    '**F4 Shadow/deprecated version (API9):** whether version endpoints like /v1,/v2,/api/v1 are reachable (SPA shell filtered out).',
    '**F5 GraphQL introspection (APIT-99):** if a GraphQL endpoint exists, whether introspection is enabled — **read-only query; NO mutation**.',
  ],
  confidenceNoteEn: 'Findings are "indicators"; only at genuinely observed (JSON, non-SPA-shell) endpoints. Sensitive data REDACTED; no mutation/data-change/DoS performed.',
  fixTitleEn: 'API Security Hardening',
  fixFoundEn: [
    'BOLA/BFLA: enforce object-ownership + function-role checks server-side on every API request (ID validity is not enough).',
    'Excessive data: restrict responses with a **field allowlist (DTO)**; do not send password-hash/secret/internal-ID/role to the client.',
    'Rate-limit: **rate-limit + quota** per account+IP+endpoint; a cost-based limit for heavy endpoints.',
    'Version: disable unused/old API versions. GraphQL: **disable introspection in production**; add a query depth/complexity limit.',
  ],
  fixCleanEn: ['Object/function authorization server-side, response DTO allowlist, rate-limit+quota, old versions disabled, GraphQL introspection disabled (proactive).'],
  cleanGenelEn: 'No clear indicator of excessive data exposure, missing rate-limit, shadow version or open GraphQL introspection was found at the discovered API endpoints.',
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
  whatCheckedDe: [
    'Nur aus der ECHTEN Org-Domain gelesene DNS-Einträge; alle PASSIV DNS/TXT + ein einziges sicheres MTA-STS-GET (kein Angriff/keine Zustandsänderung). Für Subdomains wird DMARC auf der Ebene der **organisatorischen Domain** bewertet.',
    '**G1 DMARC** Richtlinienstärke (p=none/quarantine/reject, pct, sp Subdomain, adkim/aspf, rua).',
    '**G2 SPF** Tiefe (-all/~all/?all/+all + Anzahl der Top-Level-DNS-Lookups, RFC 7208).',
    '**G3 DKIM** Erkennung gängiger Selektoren (default/google/selector1…) + Schlüssellänge (~1024/2048) + Widerruf (p= leer).',
    '**G4 MTA-STS** (_mta-sts TXT + Richtlinie: enforce/testing/none) · **G5 TLS-RPT** Reporting.',
    '**G6 DNSSEC** (Signatur/Validierung — AD-Flag, nur Beobachtung) · **G7 CAA** (Beschränkung der Zertifikatsausstellung) + **BIMI** (informativ).',
  ],
  confidenceNoteDe: 'Nachweis = der tatsächlich vom DNS zurückgegebene öffentliche Eintrag (keine Redaktion nötig). Sprache „Indikator"; bei einer Domain, die keine E-Mails versendet (kein MX), wird der Schweregrad fehlender DMARC/SPF gesenkt. Keine erfundenen/geratenen Einträge.',
  fixTitleDe: 'E-Mail- & DNS-Härtung',
  fixFoundDe: [
    'DMARC: Verschärfen Sie schrittweise \`p=none\`→\`quarantine\`→\`reject\` (pct=100); aktivieren Sie das Reporting mit \`rua=\`; für Subdomains \`sp=reject\`.',
    'SPF: Verwenden Sie \`-all\` (Hardfail); vermeiden Sie \`+all\`/\`?all\`; halten Sie die Anzahl der DNS-Lookups ≤10 (PermError).',
    'DKIM: 2048-Bit-Schlüssel, entfernen Sie widerrufene Selektoren. MTA-STS: \`mode=enforce\`. Fügen Sie TLS-RPT hinzu.',
    'Aktivieren Sie DNSSEC (DS+RRSIG). Beschränken Sie mit CAA die autorisierten CAs.',
  ],
  fixCleanDe: ['DMARC p=reject, SPF -all, DKIM 2048-Bit, MTA-STS enforce, TLS-RPT, DNSSEC, CAA — Anti-Spoofing/DNS-Integrität stark (proaktiv).'],
  cleanGenelDe: 'In den E-Mail-/DNS-Einträgen der abgefragten Org-Domain wurde kein eindeutiger Indikator für eine Anti-Spoofing-Schwäche (fehlendes/lockeres DMARC-SPF, offenes +all, unsigniertes DNSSEC usw.) gefunden.',
  whatCheckedEn: [
    'Only DNS records read from the REAL org domain; all PASSIVE DNS/TXT + a single safe MTA-STS GET (no attack/state-change). For a subdomain, DMARC is evaluated at the **organizational domain** level.',
    '**G1 DMARC** policy strength (p=none/quarantine/reject, pct, sp subdomain, adkim/aspf, rua).',
    '**G2 SPF** depth (-all/~all/?all/+all + top-level DNS-lookup count, RFC 7208).',
    '**G3 DKIM** common-selector discovery (default/google/selector1…) + key length (~1024/2048) + revocation (empty p=).',
    '**G4 MTA-STS** (_mta-sts TXT + policy: enforce/testing/none) · **G5 TLS-RPT** reporting.',
    '**G6 DNSSEC** (signature/validation — AD flag, observation only) · **G7 CAA** (certificate-issuance restriction) + **BIMI** (informational).',
  ],
  confidenceNoteEn: 'Evidence = the public record DNS actually returned (no redaction needed). "indicator" language; on a non-mail-sending domain (no MX), the severity of missing DMARC/SPF is lowered. No fabricated/guessed records.',
  fixTitleEn: 'E-mail & DNS Hardening',
  fixFoundEn: [
    'DMARC: tighten gradually `p=none`→`quarantine`→`reject` (pct=100); enable reporting with `rua=`; `sp=reject` for subdomains.',
    'SPF: use `-all` (hardfail); avoid `+all`/`?all`; keep the DNS-lookup count ≤10 (PermError).',
    'DKIM: 2048-bit key, remove revoked selectors. MTA-STS: `mode=enforce`. Add TLS-RPT.',
    'Enable DNSSEC (DS+RRSIG). Restrict authorized CAs with CAA.',
  ],
  fixCleanEn: ['DMARC p=reject, SPF -all, DKIM 2048-bit, MTA-STS enforce, TLS-RPT, DNSSEC, CAA — anti-spoofing/DNS integrity strong (proactive).'],
  cleanGenelEn: 'No clear indicator of an anti-spoofing weakness (missing/loose DMARC-SPF, open +all, unsigned DNSSEC etc.) was found in the queried org domain\'s e-mail/DNS records.',
};

// (Faz 5) Taşıma Katmanı, CORS & Güvenlik Başlığı Derinliği — H1/H3/H4. Read-only/pasif.
const TRANSPORT_CFG = {
  title: 'Taşıma Katmanı, CORS & Güvenlik Başlığı Derinliği',
  whatChecked: [
    'Hepsi read-only/pasif gözlem — veri değiştirme, DoS, cipher istismarı YOK.',
    '**H1 CORS:** keşfedilen GERÇEK uçlara kurgu `Origin` ile tek istek — ACAO yansıması + ACAC=true (kimlik-bilgili sızıntı → Yüksek), yalnız yansıma (Orta, "tasarım olabilir"), `*` (bilgilendirici), `null` kabul (gösterge).',
    '**H3 TLS protokol/cipher:** protokol başına 1 güvenli handshake — TLS 1.0/1.1 (eski, gösterge), zayıf cipher (RC4/3DES/NULL/EXPORT). Sertifika süre/hostname/zincir yalnız GERÇEK sorunda bulgu (çift-CT yok).',
    '**H4 güvenlik başlığı derinliği:** HSTS (varlık + max-age yeterlilik + preload), clickjacking (X-Frame-Options **veya** CSP frame-ancestors çift-mekanizma), CSP zayıflık (unsafe-inline/eval/*), Referrer-Policy / Permissions-Policy / X-Content-Type-Options.',
    'Temel başlık VARLIK kontrolü diğer paketlerde kalır; bu bölüm DERİNLİK katar (kopyalanmadı).',
  ],
  confidenceNote: 'Bulgular gerçek gözleme dayanır ("gösterge, doğrulama gerekir"); reflected-CORS + credentials NET kötüdür (Yüksek), credentials\'sız yansıma tasarım olabilir (Orta). Deterministik (aynı host → aynı protokol/başlık).',
  fixTitle: 'Taşıma Katmanı & Başlık Sertleştirme',
  fixFound: [
    'CORS: origin\'i allowlist\'leyin; `credentials` ile wildcard/yansıtma kullanmayın; `null` origin kabul etmeyin.',
    'TLS: yalnız TLS 1.2/1.3 bırakın; RC4/3DES/NULL/EXPORT cipher\'ları kapatın; modern AEAD (ECDHE+AES-GCM/CHACHA20).',
    'HSTS `max-age≥15768000; includeSubDomains; preload`; clickjacking için X-Frame-Options **ve/veya** CSP frame-ancestors.',
    'CSP\'den unsafe-inline/unsafe-eval kaldırın (nonce/hash); Referrer-Policy/Permissions-Policy/X-Content-Type-Options ekleyin.',
  ],
  fixClean: ['CORS sıkı (allowlist, credentials\'sız), yalnız TLS 1.2/1.3 + modern cipher, HSTS/clickjacking/CSP/başlıklar tam — taşıma & tarayıcı-taraflı savunma güçlü (proaktif).'],
  cleanGenel: 'Taşıma katmanı (CORS/TLS) ve güvenlik başlıklarında belirgin bir yanlış yapılandırma veya sertleştirme boşluğu göstergesi bulunamadı.',
  whatCheckedDe: [
    'Alles read-only/passive Beobachtung — KEINE Datenänderung, kein DoS, keine Cipher-Ausnutzung.',
    '**H1 CORS:** eine einzige Anfrage mit fiktivem `Origin` an entdeckte ECHTE Endpunkte — ACAO-Reflexion + ACAC=true (Leck mit Anmeldedaten → Hoch), reine Reflexion (Mittel, „kann beabsichtigt sein"), `*` (informativ), `null`-Akzeptanz (Indikator).',
    '**H3 TLS-Protokoll/Cipher:** 1 sicherer Handshake pro Protokoll — TLS 1.0/1.1 (veraltet, Indikator), schwache Cipher (RC4/3DES/NULL/EXPORT). Zertifikatsgültigkeit/Hostname/Kette nur bei ECHTEM Problem als Befund (kein Doppel-CT).',
    '**H4 Security-Header-Tiefe:** HSTS (Vorhandensein + max-age-Angemessenheit + preload), Clickjacking (X-Frame-Options **oder** CSP frame-ancestors Doppelmechanismus), CSP-Schwäche (unsafe-inline/eval/*), Referrer-Policy / Permissions-Policy / X-Content-Type-Options.',
    'Die grundlegende Header-VORHANDENSEIN-Prüfung verbleibt in anderen Paketen; dieser Abschnitt fügt TIEFE hinzu (nicht kopiert).',
  ],
  confidenceNoteDe: 'Die Befunde beruhen auf echter Beobachtung („Indikator, Verifizierung erforderlich"); reflektiertes CORS + Credentials ist EINDEUTIG schlecht (Hoch), Reflexion ohne Credentials kann beabsichtigt sein (Mittel). Deterministisch (gleicher Host → gleiches Protokoll/Header).',
  fixTitleDe: 'Transportschicht- & Header-Härtung',
  fixFoundDe: [
    'CORS: Setzen Sie Origins auf eine Allowlist; verwenden Sie mit `credentials` kein Wildcard/keine Reflexion; akzeptieren Sie keinen `null`-Origin.',
    'TLS: Belassen Sie nur TLS 1.2/1.3; deaktivieren Sie RC4/3DES/NULL/EXPORT-Cipher; modernes AEAD (ECDHE+AES-GCM/CHACHA20).',
    'HSTS `max-age≥15768000; includeSubDomains; preload`; gegen Clickjacking X-Frame-Options **und/oder** CSP frame-ancestors.',
    'Entfernen Sie unsafe-inline/unsafe-eval aus CSP (nonce/hash); fügen Sie Referrer-Policy/Permissions-Policy/X-Content-Type-Options hinzu.',
  ],
  fixCleanDe: ['CORS streng (Allowlist, ohne Credentials), nur TLS 1.2/1.3 + moderne Cipher, HSTS/Clickjacking/CSP/Header vollständig — Transport- & browserseitige Verteidigung stark (proaktiv).'],
  cleanGenelDe: 'In der Transportschicht (CORS/TLS) und den Security-Headern wurde kein eindeutiger Indikator für eine Fehlkonfiguration oder Härtungslücke gefunden.',
  whatCheckedEn: [
    'All read-only/passive observation — NO data change, DoS or cipher exploitation.',
    '**H1 CORS:** a single request with a crafted `Origin` to discovered REAL endpoints — ACAO reflection + ACAC=true (credentialed leak → High), reflection only (Medium, "may be by design"), `*` (informational), `null` acceptance (indicator).',
    '**H3 TLS protocol/cipher:** 1 safe handshake per protocol — TLS 1.0/1.1 (old, indicator), weak cipher (RC4/3DES/NULL/EXPORT). Certificate validity/hostname/chain is a finding only on a REAL problem (no double CT).',
    '**H4 security-header depth:** HSTS (presence + max-age sufficiency + preload), clickjacking (X-Frame-Options **or** CSP frame-ancestors dual-mechanism), CSP weakness (unsafe-inline/eval/*), Referrer-Policy / Permissions-Policy / X-Content-Type-Options.',
    'The basic header-PRESENCE check remains in other packages; this section adds DEPTH (not copied).',
  ],
  confidenceNoteEn: 'Findings are based on real observation ("indicator, verification required"); reflected CORS + credentials is CLEARLY bad (High), reflection without credentials may be by design (Medium). Deterministic (same host → same protocol/header).',
  fixTitleEn: 'Transport Layer & Header Hardening',
  fixFoundEn: [
    'CORS: allowlist origins; do not use a wildcard/reflection with `credentials`; do not accept a `null` origin.',
    'TLS: leave only TLS 1.2/1.3; disable RC4/3DES/NULL/EXPORT ciphers; modern AEAD (ECDHE+AES-GCM/CHACHA20).',
    'HSTS `max-age≥15768000; includeSubDomains; preload`; X-Frame-Options **and/or** CSP frame-ancestors against clickjacking.',
    'Remove unsafe-inline/unsafe-eval from CSP (nonce/hash); add Referrer-Policy/Permissions-Policy/X-Content-Type-Options.',
  ],
  fixCleanEn: ['CORS strict (allowlist, no credentials), only TLS 1.2/1.3 + modern ciphers, HSTS/clickjacking/CSP/headers complete — transport & browser-side defence strong (proactive).'],
  cleanGenelEn: 'No clear indicator of a misconfiguration or hardening gap was found in the transport layer (CORS/TLS) and security headers.',
};
// (Faz 5) Subdomain Takeover — recon/DNS. Yalnız DNS çözümü + tek güvenli GET (parmak-izi); claim YOK.
const TAKEOVER_CFG = {
  title: 'Subdomain Takeover (Dangling DNS)',
  whatChecked: [
    'Certificate Transparency (crt.sh/certSpotter) ile keşfedilen GERÇEK alt-alanlarda CNAME çözümü.',
    'CNAME bilinen 3P servise (S3/GitHub Pages/Heroku/Azure/Netlify/Fastly/Shopify/… kapsamlı liste) işaret ediyor **VE** "sahiplenilmemiş" parmak-izi (NoSuchBucket / "There isn\'t a GitHub Pages site here" / NXDOMAIN vb.) dönüyorsa → OLASI takeover.',
    'Yalnız DNS çözümü + tek güvenli GET (parmak-izi gözlemi) — HİÇBİR kayıt/registrasyon/claim YAPILMAZ. Uydurma alt-alan yok.',
  ],
  confidenceNote: 'Yalnız dangling + parmak-izi eşleşince bulgu; canlı/sahiplenilmiş CNAME bilgilendirici. CT kaynağı erişilemezse "incelenemedi" (temiz değil).',
  fixTitle: 'Subdomain Takeover',
  fixFound: [
    'Kullanılmayan/boşta CNAME kayıtlarını DNS\'ten kaldırın (bulut kaynağını silmeden ÖNCE DNS kaydını silin).',
    'Alt-alan envanteri tutun; terk edilen 3P servis kayıtlarını periyodik denetleyin.',
  ],
  fixClean: ['Alt-alan CNAME envanteri temiz; boşta/dangling kayıt yok (proaktif).'],
  cleanGenel: 'Keşfedilen alt-alanlarda devralınabilir (dangling) CNAME + sahiplenilmemiş parmak-izi göstergesi bulunamadı.',
  whatCheckedDe: [
    'CNAME-Auflösung bei ECHTEN, über Certificate Transparency (crt.sh/certSpotter) entdeckten Subdomains.',
    'Zeigt der CNAME auf einen bekannten 3P-Dienst (S3/GitHub Pages/Heroku/Azure/Netlify/Fastly/Shopify/… umfassende Liste) **UND** kommt ein „nicht beanspruchter" Fingerabdruck (NoSuchBucket / „There isn\'t a GitHub Pages site here" / NXDOMAIN usw.) zurück → MÖGLICHES Takeover.',
    'Nur DNS-Auflösung + ein einziges sicheres GET (Fingerabdruck-Beobachtung) — es wird KEINE Registrierung/Beanspruchung durchgeführt. Keine erfundenen Subdomains.',
  ],
  confidenceNoteDe: 'Ein Befund nur bei Übereinstimmung von Dangling + Fingerabdruck; ein aktiver/beanspruchter CNAME ist informativ. Ist die CT-Quelle nicht erreichbar, „nicht prüfbar" (nicht sauber).',
  fixTitleDe: 'Subdomain-Takeover',
  fixFoundDe: [
    'Entfernen Sie ungenutzte/verwaiste CNAME-Einträge aus dem DNS (löschen Sie den DNS-Eintrag, BEVOR Sie die Cloud-Ressource löschen).',
    'Führen Sie ein Subdomain-Inventar; prüfen Sie verlassene 3P-Dienst-Einträge regelmäßig.',
  ],
  fixCleanDe: ['Subdomain-CNAME-Inventar sauber; kein verwaister/dangling Eintrag (proaktiv).'],
  cleanGenelDe: 'In den entdeckten Subdomains wurde kein Indikator für einen übernehmbaren (dangling) CNAME + nicht beanspruchten Fingerabdruck gefunden.',
  whatCheckedEn: [
    'CNAME resolution on REAL subdomains discovered via Certificate Transparency (crt.sh/certSpotter).',
    'If the CNAME points to a known 3P service (S3/GitHub Pages/Heroku/Azure/Netlify/Fastly/Shopify/… comprehensive list) **AND** an "unclaimed" fingerprint (NoSuchBucket / "There isn\'t a GitHub Pages site here" / NXDOMAIN etc.) is returned → POSSIBLE takeover.',
    'DNS resolution + a single safe GET (fingerprint observation) only — NO registration/claim is made. No fabricated subdomains.',
  ],
  confidenceNoteEn: 'A finding only when dangling + fingerprint match; a live/claimed CNAME is informational. If the CT source is unreachable, "not assessable" (not clean).',
  fixTitleEn: 'Subdomain Takeover',
  fixFoundEn: [
    'Remove unused/dangling CNAME records from DNS (delete the DNS record BEFORE deleting the cloud resource).',
    'Keep a subdomain inventory; periodically audit abandoned 3P service records.',
  ],
  fixCleanEn: ['Subdomain CNAME inventory clean; no dangling/orphaned record (proactive).'],
  cleanGenelEn: 'No indicator of a takeover-able (dangling) CNAME + unclaimed fingerprint was found in the discovered subdomains.',
};

// (Faz 8) Authenticated Güvenli Aktif Göstergeler — Faz 6 modülü login-sonrası yüzeyde. Read-only.
const AUTH_INDICATORS_CFG = {
  title: 'Authenticated Güvenli Aktif Göstergeler (LFI/Redirect/HPP/SSTI)',
  whatChecked: [
    'Faz 6 güvenli aktif göstergeleri **login sonrası** (TEST oturumu) erişilen GET parametreleri + Faz 7 SPA-keşif/auth-kapılı uçlarda — hepsi read-only (veri yazma/yükleme/komut/time-based YOK).',
    '**B1 LFI/path-traversal:** kademeli prob; yalnız dosya İMZASI=bulgu (Yüksek), içerik **REDAKTE**.',
    '**B2 Open redirect:** zararsız kanarya (redirect TAKİP EDİLMEZ). **B3 HPP:** tekrarlı parametre (salt gözlem).',
    '**B5 SSTI:** yalnız aritmetik `{{1234*3}}`→`3702` (kod/komut YOK).',
    '**B4 boolean-SQLi** → Authenticated Enjeksiyon (SQLi/XSS) bölümünde; **B6 dosya yükleme** → konfig gözlemi (gerçek yükleme YOK). Çift-CT önlemek için çapraz-referans.',
  ],
  confidenceNote: 'Login-sonrası yüzey login-öncesinden farklıdır (paketin süper-set gerekçesi). "gösterge, doğrulama gerekir"; yalnız gözlemlenen parametrelerde. İyi-yapılandırılmış authenticated backend\'de temiz/az bulgu BEKLENEN sonuçtur.',
  fixTitle: 'Authenticated Güvenli Aktif Göstergeler',
  fixFound: [
    'LFI: girdiyi dosya yoluna koymayın; allowlist + `basename` + kök-dizin hapsi. Open redirect: hedefleri sunucuda allowlist.',
    'HPP: parametreleri tek-değere normalize edin. SSTI: girdiyi şablona interpolasyonla koymayın (logic-less + kaçış + sandbox).',
  ],
  fixClean: ['Login-sonrası parametrelerde dosya-yolu/şablon/yönlendirme hedefine doğrudan girdi konmuyor (proaktif).'],
  cleanGenel: 'Login-sonrası erişilen parametrelerde LFI imzası, açık yönlendirme, HTTP parametre kirliliği veya SSTI göstergesi bulunamadı.',
  whatCheckedDe: [
    'Sichere aktive Indikatoren aus Phase 6 auf **nach dem Login** (TEST-Sitzung) erreichten GET-Parametern + Phase-7-SPA-Entdeckungs-/auth-gesperrten Endpunkten — alle read-only (KEIN Schreiben/Hochladen/Befehl/zeitbasiert).',
    '**B1 LFI/Path-Traversal:** abgestufte Sonde; nur Datei-SIGNATUR=Befund (Hoch), Inhalt **REDIGIERT**.',
    '**B2 Open Redirect:** harmloser Canary (Redirect wird NICHT verfolgt). **B3 HPP:** wiederholter Parameter (reine Beobachtung).',
    '**B5 SSTI:** nur arithmetisch `{{1234*3}}`→`3702` (KEIN Code/Befehl).',
    '**B4 boolean-SQLi** → im Abschnitt Authentifizierte Injektion (SQLi/XSS); **B6 Datei-Upload** → Konfigurationsbeobachtung (KEIN echter Upload). Querverweis zur Vermeidung von Doppel-CT.',
  ],
  confidenceNoteDe: 'Die Oberfläche nach dem Login unterscheidet sich von der vor dem Login (Begründung für den Superset-Charakter des Pakets). „Indikator, Verifizierung erforderlich"; nur auf beobachteten Parametern. Bei einem gut konfigurierten authentifizierten Backend ist ein sauberer/geringer Befund das ERWARTETE Ergebnis.',
  fixTitleDe: 'Authentifizierte sichere aktive Indikatoren',
  fixFoundDe: [
    'LFI: Legen Sie Eingaben nicht in den Dateipfad; Allowlist + `basename` + Wurzelverzeichnis-Beschränkung. Open Redirect: Ziele serverseitig per Allowlist.',
    'HPP: Normalisieren Sie Parameter auf einen Einzelwert. SSTI: Interpolieren Sie Eingaben nicht in Templates (logikfrei + Escaping + Sandbox).',
  ],
  fixCleanDe: ['In den Parametern nach dem Login wird keine Eingabe direkt in Dateipfad/Template/Weiterleitungsziel gelegt (proaktiv).'],
  cleanGenelDe: 'In den nach dem Login erreichten Parametern wurde kein Indikator für LFI-Signatur, Open Redirect, HTTP Parameter Pollution oder SSTI gefunden.',
  whatCheckedEn: [
    'Phase 6 safe active indicators on GET parameters accessed **after login** (TEST session) + Phase-7 SPA-discovery/auth-gated endpoints — all read-only (NO data writing/upload/command/time-based).',
    '**B1 LFI/path-traversal:** graduated probe; only a file SIGNATURE=finding (High), content **REDACTED**.',
    '**B2 Open redirect:** harmless canary (redirect NOT followed). **B3 HPP:** repeated parameter (observation only).',
    '**B5 SSTI:** arithmetic only `{{1234*3}}`→`3702` (NO code/command).',
    '**B4 boolean-SQLi** → in the Authenticated Injection (SQLi/XSS) section; **B6 file upload** → config observation (NO real upload). Cross-referenced to avoid double CT.',
  ],
  confidenceNoteEn: 'The post-login surface differs from the pre-login one (the rationale for the package being a super-set). "indicator, verification required"; only on observed parameters. On a well-configured authenticated backend, a clean/low finding is the EXPECTED result.',
  fixTitleEn: 'Authenticated Safe Active Indicators',
  fixFoundEn: [
    'LFI: do not place input in the file path; allowlist + `basename` + root-directory confinement. Open redirect: allowlist targets server-side.',
    'HPP: normalise parameters to a single value. SSTI: do not interpolate input into templates (logic-less + escaping + sandbox).',
  ],
  fixCleanEn: ['No input is placed directly into a file path/template/redirect target in post-login parameters (proactive).'],
  cleanGenelEn: 'No indicator of LFI signature, open redirect, HTTP parameter pollution or SSTI was found in the parameters accessed after login.',
};

// (Çok-bölge) run başlıkları hem `## <title>` bölüm başlığı hem tablo/özet etiketi olarak AYNEN kullanılır.
// Almanca karşılıkları; T(tr) yalnız de=true iken çevirir, yoksa TR AYNEN kalır.
const AUTH_TITLE_DE: Record<string, string> = {
  'Oturum Çerezi Bayrakları': 'Sitzungs-Cookie-Flags',
  'Session Fixation': 'Session Fixation',
  'Logout / Oturum Geçersizleştirme': 'Logout / Sitzungsinvalidierung',
  'Forced Browsing / Fonksiyon-Seviye Yetki': 'Forced Browsing / Funktionsebenen-Autorisierung',
  'Authenticated Enjeksiyon (SQLi/XSS)': 'Authentifizierte Injektion (SQLi/XSS)',
  'Authenticated IDOR (kendi kaynakları)': 'Authentifizierte IDOR (eigene Ressourcen)',
  'Yetki Yükseltme (Privilege Escalation)': 'Rechteausweitung (Privilege Escalation)',
  'Çok-Adımlı İş Mantığı': 'Mehrstufige Geschäftslogik',
  'JWT / Token Güvenliği': 'JWT / Token-Sicherheit',
  'Giriş Baypası (SQLi Göstergesi)': 'Login-Bypass (SQLi-Indikator)',
  'Client-Side / JS Analizi': 'Client-Side / JS-Analyse',
  'Client-Side Statik Analiz': 'Client-Side-Statikanalyse',
  'Kimlik-Doğrulama Derinliği': 'Authentifizierungstiefe',
  'Oturum Güvenliği Derinliği': 'Sitzungssicherheit (Tiefe)',
  'Girdi & Header Derinliği': 'Eingabe- & Header-Tiefe',
  'Yapılandırma & İfşa Derinliği': 'Konfiguration & Exposition (Tiefe)',
  'API Güvenliği Derinliği (OWASP API Top 10)': 'API-Sicherheit (Tiefe, OWASP API Top 10)',
  'E-posta & DNS Derinliği (Anti-Spoofing)': 'E-Mail & DNS (Tiefe, Anti-Spoofing)',
  'Taşıma Katmanı, CORS & Güvenlik Başlığı Derinliği': 'Transportschicht, CORS & Security-Header (Tiefe)',
  'Subdomain Takeover (Dangling DNS)': 'Subdomain-Takeover (Dangling DNS)',
  'Authenticated Güvenli Aktif Göstergeler (LFI/Redirect/HPP/SSTI)': 'Authentifizierte sichere aktive Indikatoren (LFI/Redirect/HPP/SSTI)',
};
const AUTH_TITLE_EN: Record<string, string> = {
  'Oturum Çerezi Bayrakları': 'Session Cookie Flags',
  'Session Fixation': 'Session Fixation',
  'Logout / Oturum Geçersizleştirme': 'Logout / Session Invalidation',
  'Forced Browsing / Fonksiyon-Seviye Yetki': 'Forced Browsing / Function-Level Authorization',
  'Authenticated Enjeksiyon (SQLi/XSS)': 'Authenticated Injection (SQLi/XSS)',
  'Authenticated IDOR (kendi kaynakları)': 'Authenticated IDOR (own resources)',
  'Yetki Yükseltme (Privilege Escalation)': 'Privilege Escalation',
  'Çok-Adımlı İş Mantığı': 'Multi-Step Business Logic',
  'JWT / Token Güvenliği': 'JWT / Token Security',
  'Giriş Baypası (SQLi Göstergesi)': 'Login Bypass (SQLi Indicator)',
  'Client-Side / JS Analizi': 'Client-Side / JS Analysis',
  'Client-Side Statik Analiz': 'Client-Side Static Analysis',
  'Kimlik-Doğrulama Derinliği': 'Authentication Depth',
  'Oturum Güvenliği Derinliği': 'Session Security Depth',
  'Girdi & Header Derinliği': 'Input & Header Depth',
  'Yapılandırma & İfşa Derinliği': 'Configuration & Exposure Depth',
  'API Güvenliği Derinliği (OWASP API Top 10)': 'API Security Depth (OWASP API Top 10)',
  'E-posta & DNS Derinliği (Anti-Spoofing)': 'E-mail & DNS Depth (Anti-Spoofing)',
  'Taşıma Katmanı, CORS & Güvenlik Başlığı Derinliği': 'Transport Layer, CORS & Security-Header Depth',
  'Subdomain Takeover (Dangling DNS)': 'Subdomain Takeover (Dangling DNS)',
  'Authenticated Güvenli Aktif Göstergeler (LFI/Redirect/HPP/SSTI)': 'Authenticated Safe Active Indicators (LFI/Redirect/HPP/SSTI)',
};

type Run = { title: string; conf: 'Yüksek' | 'Orta' | 'Düşük'; rep: { findings: string; fixText: string } | null; inputs: number; probes: number; fc: number; agentCheck?: boolean; agentUsed?: boolean; agentStatus?: 'analyzed' | 'no_candidate' | 'unavailable' | 'disabled'; enumerableSurface?: { param: string; count: number } | null };

/** 6 authenticated kontrolü çalıştır + TEK rapora birleştir. Hedefe ulaşılamazsa null. */
export async function generateAuthenticatedReport(host: string, session: AuthSession, locale: string = 'tr'): Promise<{ findings: string; fixText: string } | null> {
  const de = locale === 'de', en = locale === 'en';
  const t = (trS: string, deS: string, enS?: string) => (de ? deS : en ? (enS ?? trS) : trS);
  const rw = (l: Level) => (de ? RISK_WORD_DE[l] : en ? RISK_WORD_EN[l] : RISK_WORD[l]);
  const T = (tr: string) => (de ? (AUTH_TITLE_DE[tr] ?? tr) : en ? (AUTH_TITLE_EN[tr] ?? tr) : tr);
  void SEV_DISP;
  // (Faz 4 / Bölüm 2) DİNAMİK FİYAT ÖNERİSİ — yalnız 6. paket; pasif sinyallerden deterministik skor.
  // Müşteri PDF'ine GİRMEZ (satış sinyali); admin/panel için log'a yazılır. Ekstra tarama yapmaz (cache'li corpus).
  try {
    const { signals, suggestion } = await suggestPricingForHost(host);
    logScanStep({ step: 'Fiyat Önerisi (dahili)', level: 'info', summary: `skor=${suggestion.score} kademe=${suggestion.tier.label} · sinyaller: uç=${signals.uniqueEndpoints} api=${signals.realApiEndpoints} auth=${signals.authSurface} altalan=${signals.subdomains} tekno=${signals.techDiversity} · ${suggestion.priceRange.placeholder ? 'fiyat=PLACEHOLDER (Vedat ayarlar)' : `fiyat=${suggestion.priceRange.minTL}-${suggestion.priceRange.maxTL} TL`}` });
  } catch { /* fiyat önerisi rapor akışını asla bozmaz */ }

  const runs: Run[] = [];
  const cookieEv = collectCookieFlagsEvidence(session, locale);
  runs.push({ title: T('Oturum Çerezi Bayrakları'), conf: 'Yüksek', rep: buildActiveCheckReport(cookieEv, COOKIE_CFG, locale), inputs: cookieEv.inputsFound, probes: cookieEv.probesSent, fc: cookieEv.findings.length });
  const fixEv = await collectSessionFixationEvidence(host, session, locale).catch(() => null);
  runs.push({ title: T('Session Fixation'), conf: 'Orta', rep: fixEv ? buildActiveCheckReport(fixEv, FIXATION_CFG, locale) : null, inputs: fixEv?.inputsFound ?? 0, probes: fixEv?.probesSent ?? 0, fc: fixEv?.findings.length ?? 0 });
  const logoutEv = await collectLogoutEvidence(host, session, locale).catch(() => null);
  runs.push({ title: T('Logout / Oturum Geçersizleştirme'), conf: 'Orta', rep: logoutEv ? buildActiveCheckReport(logoutEv, LOGOUT_CFG, locale) : null, inputs: logoutEv?.inputsFound ?? 0, probes: logoutEv?.probesSent ?? 0, fc: logoutEv?.findings.length ?? 0 });
  const forcedEv = await collectForcedBrowsingEvidence(host, session, locale).catch(() => null);
  runs.push({ title: T('Forced Browsing / Fonksiyon-Seviye Yetki'), conf: 'Orta', rep: forcedEv ? buildActiveCheckReport(forcedEv, FORCED_CFG, locale) : null, inputs: forcedEv?.inputsFound ?? 0, probes: forcedEv?.probesSent ?? 0, fc: forcedEv?.findings.length ?? 0 });
  const injEv = await collectInjectionEvidence(host, session, locale).catch(() => null);
  runs.push({ title: T('Authenticated Enjeksiyon (SQLi/XSS)'), conf: 'Yüksek', rep: injEv ? buildInjectionReport(injEv, locale) : null, inputs: injEv?.inputsFound ?? 0, probes: injEv?.probesSent ?? 0, fc: injEv?.findings.length ?? 0 });
  const idorEv = await collectIdorEvidence(host, session, locale).catch(() => null);
  runs.push({ title: T('Authenticated IDOR (kendi kaynakları)'), conf: 'Orta', rep: idorEv ? buildIdorReport(idorEv, locale) : null, inputs: idorEv?.candidates ?? 0, probes: idorEv?.probesSent ?? 0, fc: idorEv?.findings.length ?? 0, enumerableSurface: idorEv?.enumerableSurface ?? null });
  // (FAZ D) SINIRLI/KONTROLLÜ AJAN KATMANI — priv-esc + çok-adımlı iş mantığı (ajan öneri, backend uygular).
  const privEv = await collectPrivilegeEscalationEvidence(host, session, locale).catch(() => null);
  // (İş A) advisor AÇIK (analyzed) ise AI-danışma dili; KAPALI (varsayılan) ise deterministik dil.
  const privCfg = privEv?.agentStatus === 'analyzed' ? { ...PRIVESC_CFG, whatChecked: [PRIVESC_WC_AI, ...PRIVESC_CFG.whatChecked.slice(1)], whatCheckedDe: [PRIVESC_WC_AI_DE, ...(PRIVESC_CFG.whatCheckedDe ?? []).slice(1)], whatCheckedEn: [PRIVESC_WC_AI_EN, ...(PRIVESC_CFG.whatCheckedEn ?? []).slice(1)] } : PRIVESC_CFG;
  runs.push({ title: T('Yetki Yükseltme (Privilege Escalation)'), conf: 'Orta', rep: privEv ? buildActiveCheckReport(privEv, privCfg, locale) : null, inputs: privEv?.inputsFound ?? 0, probes: privEv?.probesSent ?? 0, fc: privEv?.findings.length ?? 0, agentCheck: true, agentUsed: privEv?.agentUsed ?? false, agentStatus: privEv?.agentStatus });
  const multiEv = await collectMultiStepBusinessLogicEvidence(host, session, locale).catch(() => null);
  const multiCfg = multiEv?.agentStatus === 'analyzed' ? { ...MULTISTEP_CFG, whatChecked: [MULTISTEP_WC_AI, ...MULTISTEP_CFG.whatChecked.slice(1)], whatCheckedDe: [MULTISTEP_WC_AI_DE, ...(MULTISTEP_CFG.whatCheckedDe ?? []).slice(1)], whatCheckedEn: [MULTISTEP_WC_AI_EN, ...(MULTISTEP_CFG.whatCheckedEn ?? []).slice(1)] } : MULTISTEP_CFG;
  runs.push({ title: T('Çok-Adımlı İş Mantığı'), conf: 'Düşük', rep: multiEv ? buildActiveCheckReport(multiEv, multiCfg, locale) : null, inputs: multiEv?.inputsFound ?? 0, probes: multiEv?.probesSent ?? 0, fc: multiEv?.findings.length ?? 0, agentCheck: true, agentUsed: multiEv?.agentUsed ?? false, agentStatus: multiEv?.agentStatus });
  const advisorActive = privEv?.agentStatus === 'analyzed' || multiEv?.agentStatus === 'analyzed'; // (İş A) tek bayrak
  // (İŞ 3) JWT/token güvenliği + giriş baypası (SQLi göstergesi) — deterministik, gözlemsel.
  const jwtEv = await collectJwtAnalysis(host, session, locale).catch(() => null);
  runs.push({ title: T('JWT / Token Güvenliği'), conf: 'Yüksek', rep: jwtEv ? buildActiveCheckReport(jwtEv, JWT_CFG, locale) : null, inputs: jwtEv?.inputsFound ?? 0, probes: jwtEv?.probesSent ?? 0, fc: jwtEv?.findings.length ?? 0 });
  const loginBypassEv = await collectLoginBypassEvidence(host, session.loginUrl, locale).catch(() => null);
  runs.push({ title: T('Giriş Baypası (SQLi Göstergesi)'), conf: 'Yüksek', rep: loginBypassEv ? buildActiveCheckReport(loginBypassEv, LOGIN_BYPASS_CFG, locale) : null, inputs: loginBypassEv?.inputsFound ?? 0, probes: loginBypassEv?.probesSent ?? 0, fc: loginBypassEv?.findings.length ?? 0 });

  // (YENİ — 6. pakete özel) Client-Side / JS Analizi: pasif JS bundle sır + source-map + zafiyetli-kütüphane.
  const jsEv = await collectJsAnalysisEvidence(host, locale).catch(() => null);
  runs.push({ title: T('Client-Side / JS Analizi'), conf: 'Yüksek', rep: jsEv ? buildActiveCheckReport(jsEv, JS_ANALYSIS_CFG, locale) : null, inputs: jsEv?.inputsFound ?? 0, probes: jsEv?.probesSent ?? 0, fc: jsEv?.findings.length ?? 0 });

  // (YENİ — Faz 1-B) Client-Side Statik Analiz: DOM-XSS gösterge / postMessage / storage / SRI / tabnabbing / open-redirect.
  const csEv = await collectClientSideEvidence(host, locale).catch(() => null);
  runs.push({ title: T('Client-Side Statik Analiz'), conf: 'Orta', rep: csEv ? buildActiveCheckReport(csEv, CLIENT_SIDE_CFG, locale) : null, inputs: csEv?.inputsFound ?? 0, probes: csEv?.probesSent ?? 0, fc: csEv?.findings.length ?? 0 });

  // (YENİ — Faz 2-A) Kimlik-Doğrulama Derinliği: enum/varsayılan-kimlik/lockout/reset/politika/cache/MFA/HTTP.
  const adEv = await collectAuthDepthEvidence(host, session, locale).catch(() => null);
  runs.push({ title: T('Kimlik-Doğrulama Derinliği'), conf: 'Yüksek', rep: adEv ? buildActiveCheckReport(adEv, AUTH_DEPTH_CFG, locale) : null, inputs: adEv?.inputsFound ?? 0, probes: adEv?.probesSent ?? 0, fc: adEv?.findings.length ?? 0 });

  // (YENİ — Faz 2-B) Oturum Güvenliği Derinliği: CSRF/SameSite, session-id entropi, oturum-URL, prefix, timeout.
  const sdEv = await collectSessionDepthEvidence(host, session, locale).catch(() => null);
  runs.push({ title: T('Oturum Güvenliği Derinliği'), conf: 'Orta', rep: sdEv ? buildActiveCheckReport(sdEv, SESSION_DEPTH_CFG, locale) : null, inputs: sdEv?.inputsFound ?? 0, probes: sdEv?.probesSent ?? 0, fc: sdEv?.findings.length ?? 0 });

  // (YENİ — Faz 3-A) Girdi & Header + Yapılandırma & İfşa derinliği (güvenli GET/OPTIONS/TRACE + statik).
  const ihEv = await collectInputHeaderEvidence(host, session, locale).catch(() => null);
  runs.push({ title: T('Girdi & Header Derinliği'), conf: 'Orta', rep: ihEv ? buildActiveCheckReport(ihEv, INPUT_HEADER_CFG, locale) : null, inputs: ihEv?.inputsFound ?? 0, probes: ihEv?.probesSent ?? 0, fc: ihEv?.findings.length ?? 0 });
  const ceEv = await collectConfigExposureEvidence(host, session, locale).catch(() => null);
  runs.push({ title: T('Yapılandırma & İfşa Derinliği'), conf: 'Yüksek', rep: ceEv ? buildActiveCheckReport(ceEv, CONFIG_EXPOSURE_CFG, locale) : null, inputs: ceEv?.inputsFound ?? 0, probes: ceEv?.probesSent ?? 0, fc: ceEv?.findings.length ?? 0 });
  const apiEv = await collectApiSecurityEvidence(host, session, locale).catch(() => null);
  runs.push({ title: T('API Güvenliği Derinliği (OWASP API Top 10)'), conf: 'Orta', rep: apiEv ? buildActiveCheckReport(apiEv, API_SECURITY_CFG, locale) : null, inputs: apiEv?.inputsFound ?? 0, probes: apiEv?.probesSent ?? 0, fc: apiEv?.findings.length ?? 0 });
  const edEv = await collectEmailDnsEvidence(host, locale).catch(() => null);
  runs.push({ title: T('E-posta & DNS Derinliği (Anti-Spoofing)'), conf: 'Orta', rep: edEv ? buildActiveCheckReport(edEv, EMAIL_DNS_CFG, locale) : null, inputs: edEv?.inputsFound ?? 0, probes: edEv?.probesSent ?? 0, fc: edEv?.findings.length ?? 0 });
  const tsEv = await collectTransportSecurityEvidence(host, locale).catch(() => null);
  runs.push({ title: T('Taşıma Katmanı, CORS & Güvenlik Başlığı Derinliği'), conf: 'Orta', rep: tsEv ? buildActiveCheckReport(tsEv, TRANSPORT_CFG, locale) : null, inputs: tsEv?.inputsFound ?? 0, probes: tsEv?.probesSent ?? 0, fc: tsEv?.findings.length ?? 0 });
  const stkEv = await collectSubdomainTakeoverEvidence(host, locale).catch(() => null);
  runs.push({ title: T('Subdomain Takeover (Dangling DNS)'), conf: 'Orta', rep: stkEv ? buildActiveCheckReport(stkEv, TAKEOVER_CFG, locale) : null, inputs: stkEv?.inputsFound ?? 0, probes: stkEv?.probesSent ?? 0, fc: stkEv?.findings.length ?? 0 });
  const aiEv = await collectActiveIndicatorsEvidence(host, session, locale).catch(() => null);
  runs.push({ title: T('Authenticated Güvenli Aktif Göstergeler (LFI/Redirect/HPP/SSTI)'), conf: 'Orta', rep: aiEv ? buildActiveCheckReport(aiEv, AUTH_INDICATORS_CFG, locale) : null, inputs: aiEv?.inputsFound ?? 0, probes: aiEv?.probesSent ?? 0, fc: aiEv?.findings.length ?? 0 });

  // (DÜRÜSTLÜK) Hiçbir kontrol veri toplayamadıysa (hedefe ulaşılamadı) -> "İncelenemedi" (null->Düşük DEĞİL).
  if (runs.every((r) => !r.rep)) return unscannableReport(host, t('kimlik-doğrulamalı kontroller', 'authentifizierte Kontrollen', 'authenticated checks'), locale);

  const levels: Array<Level | null> = runs.map((r) => (r.rep ? extractLevel(r.rep.findings) : null));
  const ranked = levels.map((lv, i) => ({ lv, i })).filter((x): x is { lv: Level; i: number } => x.lv !== null).sort((a, b) => levelRank(b.lv) - levelRank(a.lv));
  const worst: Level = ranked.length ? ranked[0].lv : 'low';
  const worstTitle = ranked.length ? runs[ranked[0].i].title : '';
  const anyFinding = runs.some((r) => r.fc > 0);
  const totalProbes = runs.reduce((s, r) => s + r.probes, 0);
  const dataOk = runs.filter((r) => r.rep).length;

  const enBox = `> ### Assessment Summary (Authenticated)\n` +
      `> **This scan was performed in an AUTHENTICATED (logged-in) context using the session of the provided TEST account.** ` +
      `${runs.length} authenticated checks were assessed; **${totalProbes}** requests in total. ` +
      (anyFinding ? `The highest risk is in the **${worstTitle}** area (detailed below).` : `No confirmed critical/high vulnerability stood out.`) +
      `\n>\n> _The password was never sent externally/to a third-party service; the backend performed a deterministic login and used only the session (cookie/token)._`;
  const box = de
    ? `> ### Bewertungszusammenfassung (Authentifiziert)\n` +
      `> **Dieser Scan wurde mit der Sitzung des bereitgestellten TEST-Kontos in einem AUTHENTIFIZIERTEN (angemeldeten) Kontext durchgeführt.** ` +
      `${runs.length} authentifizierte Kontrollen wurden bewertet; insgesamt **${totalProbes}** Anfragen. ` +
      (anyFinding ? `Das höchste Risiko liegt im Bereich **${worstTitle}** (unten detailliert).` : `Es trat keine bestätigte kritische/hohe Schwachstelle hervor.`) +
      `\n>\n> _Das Passwort wurde zu keinem Zeitpunkt nach außen/an einen Drittdienst gesendet; das Backend führte einen deterministischen Login durch und nutzte nur die Sitzung (Cookie/Token)._`
    : `> ### Değerlendirme Özeti (Authenticated)\n` +
    `> **Bu tarama, verilen TEST hesabının oturumuyla KİMLİK-DOĞRULAMALI (login’li) bağlamda yapılmıştır.** ` +
    `${runs.length} authenticated kontrol değerlendirildi; toplam **${totalProbes}** istek. ` +
    (anyFinding ? `En yüksek risk **${worstTitle}** alanında (aşağıda detaylı).` : `Doğrulanmış kritik/yüksek seviyeli bir zafiyet öne çıkmadı.`) +
    `\n>\n> _Şifre hiçbir aşamada dışarı/üçüncü bir servise gönderilmedi; backend deterministik login yapıp yalnız oturumu (cookie/token) kullandı._`;
  const boxFinal = en ? enBox : box;

  // AJAN kontrolleri için 3 durum NET ayrılır (dürüstlük): 'unavailable' = advisory tamamlanamadı;
  // 'analyzed' = advisory GERÇEKTEN çalıştı (bulgu varsa gösterge, yoksa "AI analiz etti, vektör yok");
  // 'no_candidate' = pasif keşifle aday yoktu, advisory çağrılmadı (gerçek "kapsam dışı"). Böylece
  // "AI çalıştı ama temiz" ile "hiç uygulanamadı" birbirine KARIŞMAZ.
  const confWord = (c: string) => (de ? (c === 'Yüksek' ? 'Hoch' : c === 'Orta' ? 'Mittel' : c === 'Düşük' ? 'Niedrig' : c) : en ? (c === 'Yüksek' ? 'High' : c === 'Orta' ? 'Medium' : c === 'Düşük' ? 'Low' : c) : c);
  const statusOf = (r: Run, lv: Level | null): string => {
    if (!r.rep) return t('Veri toplanamadı', 'Keine Daten erhoben', 'No data collected');
    if (r.fc > 0 && lv === 'high') return t('⚠ Zafiyet göstergesi', '⚠ Schwachstellenindikator', '⚠ Vulnerability indicator');
    if (r.fc > 0) return t('⚠ Sınırlı gösterge', '⚠ Begrenzter Indikator', '⚠ Limited indicator');
    if (r.agentCheck) {
      // (Deney) advisory VARSAYILAN KAPALI -> bu kontrol deterministik çalışır; sonucu deterministik durumdan türet.
      if (r.agentStatus === 'disabled') return r.inputs === 0 ? t('İncelenemedi — güvenli test edilebilir yüzey yok', 'Nicht prüfbar — keine sicher prüfbare Oberfläche', 'Not assessable — no safely testable surface') : t('✓ Zafiyet kanıtı yok', '✓ Kein Schwachstellennachweis', '✓ No vulnerability evidence');
      if (r.agentStatus === 'unavailable' || r.agentUsed === false) return t('Ajan analizi tamamlanamadı (deterministik göstergeyle sınırlı)', 'Agentenanalyse nicht abgeschlossen (auf deterministischen Indikator beschränkt)', 'Agent analysis could not be completed (limited to the deterministic indicator)');
      if (r.agentStatus === 'analyzed') return t('✓ AI advisory analiz etti — vektör yok', '✓ KI-Advisory hat analysiert — kein Vektor', '✓ AI advisory analysed — no vector');
      return t('Uygulanabilir giriş noktası yok (advisory çalıştırılmadı)', 'Kein anwendbarer Eingabepunkt (Advisory nicht ausgeführt)', 'No applicable input point (advisory not run)'); // no_candidate
    }
    // (İş 2 tutarlılık) Numaralandırılabilir yüzey BULUNDU ama cross-account testi kapsam dışı olduğundan
    // komşu-ID probu BİLİNÇLİ çalıştırılmadı -> "temiz" DEĞİL; detay bölümüyle tutarlı ayrı durum.
    if (r.enumerableSurface && r.fc === 0) return t('⚠ Yüzey bulundu — cross-account testi kapsam dışı', '⚠ Oberfläche gefunden — Cross-Account-Test außerhalb des Umfangs', '⚠ Surface found — cross-account test out of scope');
    if (r.inputs === 0) return t('Uygulanabilir giriş noktası yok (Kapsam dışı)', 'Kein anwendbarer Eingabepunkt (Außerhalb des Umfangs)', 'No applicable input point (out of scope)');
    return t('✓ Zafiyet kanıtı yok', '✓ Kein Schwachstellennachweis', '✓ No vulnerability evidence');
  };
  const confCell = (r: Run): string => {
    if (!r.rep) return t('Kapsam dışı', 'Außerhalb des Umfangs', 'Out of scope');
    if (r.agentCheck) {
      if (r.agentStatus === 'disabled') return r.inputs > 0 || r.fc > 0 ? confWord(r.conf) : t('Kapsam dışı', 'Außerhalb des Umfangs', 'Out of scope');
      if (r.agentStatus === 'unavailable' || r.agentUsed === false) return t('Sınırlı', 'Begrenzt', 'Limited');
      if (r.agentStatus === 'analyzed') return confWord(r.conf); // AI gerçekten çalıştı -> güven göster
      return t('Kapsam dışı', 'Außerhalb des Umfangs', 'Out of scope'); // no_candidate
    }
    if (r.enumerableSurface && r.fc === 0) return t('Kapsam dışı', 'Außerhalb des Umfangs', 'Out of scope'); // yüzey var ama test çalıştırılmadı -> güven yok
    return r.inputs > 0 ? confWord(r.conf) : t('Kapsam dışı', 'Außerhalb des Umfangs', 'Out of scope');
  };
  // (blocker fix) YÖNETİCİ ÖZETİ satırı, KONTROL ÖZETİ tablosuyla AYNI kaynaktan/mantıktan türer —
  // ayrı statik "Düşük — bulunamadı" şablonu YOK. statusOf ile birebir tutarlı (her satır tek doğru durum).
  const statusSummary = (r: Run, lv: Level | null): string => {
    if (!r.rep || !lv) return t('veri toplanamadı', 'keine Daten erhoben', 'no data collected');
    const hl = headlineOf(r.rep.findings);
    if (r.fc > 0) return `${rw(lv)}${hl ? ` — ${hl}` : ''}`;                       // bulgu var -> seviye + başlık
    if (r.agentCheck) {
      if (r.agentStatus === 'disabled') return r.inputs === 0 ? t('İncelenemedi — güvenle test edilebilir yüzey bulunamadı (deterministik kontrol)', 'Nicht prüfbar — keine sicher prüfbare Oberfläche gefunden (deterministische Kontrolle)', 'Not assessable — no safely testable surface found (deterministic control)') : `${rw(lv)} — ${t('deterministik kontrol, göstergesi yok', 'deterministische Kontrolle, kein Indikator', 'deterministic control, no indicator')}`;
      if (r.agentStatus === 'unavailable' || r.agentUsed === false) return t('Ajan analizi tamamlanamadı — deterministik göstergeyle sınırlı', 'Agentenanalyse nicht abgeschlossen — auf deterministischen Indikator beschränkt', 'Agent analysis could not be completed — limited to the deterministic indicator');
      if (r.agentStatus === 'analyzed') return t('Yapay zekâ destekli advisory analiz etti — uygulanabilir vektör tespit edilmedi', 'KI-gestütztes Advisory hat analysiert — kein anwendbarer Vektor festgestellt', 'The AI-assisted advisory analysed — no applicable vector detected');
      return t('Kapsam dışı — pasif keşifle uygulanabilir giriş noktası yok (advisory çalıştırılmadı)', 'Außerhalb des Umfangs — durch passive Entdeckung kein anwendbarer Eingabepunkt (Advisory nicht ausgeführt)', 'Out of scope — no applicable input point from passive discovery (advisory not run)'); // no_candidate
    }
    if (r.enumerableSurface && r.fc === 0) return de
      ? `Enumerierbare Oberfläche gefunden (${r.enumerableSurface.count} Werte) — Zugriff auf eigene Ressource berechtigt; Cross-Account-IDOR außerhalb des Umfangs (benachbarte ID bewusst nicht ausgeführt)`
      : en ? `Enumerable surface found (${r.enumerableSurface.count} values) — access to own resource authorized; cross-account IDOR out of scope (neighbouring ID deliberately not run)`
      : `Numaralandırılabilir yüzey bulundu (${r.enumerableSurface.count} değer) — kendi kaynağına erişim yetkili; cross-account IDOR kapsam dışı (komşu-ID bilinçli çalıştırılmadı)`;
    if (r.inputs === 0) return t('Kapsam dışı — uygulanabilir giriş noktası yok', 'Außerhalb des Umfangs — kein anwendbarer Eingabepunkt', 'Out of scope — no applicable input point');
    return `${rw(lv)}${hl ? ` — ${hl}` : ''}`;                                      // temiz çalıştı -> seviye + başlık
  };
  const tableRows = runs.map((r, i) => `| ${r.title} | ${statusOf(r, levels[i])} | ${confCell(r)} |`).join('\n');
  const controlTable = de
    ? `## KONTROLLÜBERSICHT\n\n| Kontrolle | Ergebnis | Konfidenz |\n|---------|-------|-------|\n${tableRows}\n\n> Konfidenz wird nur für tatsächlich anwendbare (Eingabe/Cookie/Endpunkt gefunden) Kontrollen angezeigt; nicht anwendbare Kontrollen sind **außerhalb des Umfangs** (z. B. Cookie-Flag/Fixation bei einer Sitzung, die statt Cookies ein Token nutzt).\n`
    : en
    ? `## CONTROLS SUMMARY\n\n| Control | Result | Confidence |\n|---------|-------|-------|\n${tableRows}\n\n> Confidence is shown only for actually applicable checks (input/cookie/endpoint found); non-applicable checks are **out of scope** (e.g. cookie-flag/fixation on a session that uses a token instead of cookies).\n`
    : `## KONTROL ÖZETİ\n\n| Kontrol | Sonuç | Güven |\n|---------|-------|-------|\n${tableRows}\n\n> Güven yalnızca gerçekten uygulanabilen (giriş/çerez/uç bulunan) kontroller için gösterilir; uygulanamayan kontroller **Kapsam dışı**dır (ör. çerez yerine token kullanan oturumda çerez-bayrağı/fixation).\n`;

  const summary: string[] = [];
  summary.push(
    worst === 'low'
      ? t(`- **Genel risk seviyesi: Düşük** — ${runs.length} authenticated kontrol değerlendirildi; doğrulanmış kritik/yüksek seviyeli bir zafiyet öne çıkmadı.`, `- **Gesamtrisikostufe: Niedrig** — ${runs.length} authentifizierte Kontrollen wurden bewertet; es trat keine bestätigte kritische/hohe Schwachstelle hervor.`, `- **Overall risk level: Low** — ${runs.length} authenticated checks were assessed; no confirmed critical/high-level vulnerability stood out.`)
      : t(`- **Genel risk seviyesi: ${RISK_WORD[worst]}** — en yüksek risk **${worstTitle}** alanında.`, `- **Gesamtrisikostufe: ${RISK_WORD_DE[worst]}** — das höchste Risiko liegt im Bereich **${worstTitle}**.`, `- **Overall risk level: ${RISK_WORD_EN[worst]}** — the highest risk is in the **${worstTitle}** area.`),
  );
  summary.push(
    de
      ? `- **Umfang:** Dieser Abschnitt arbeitet in einem **authentifizierten (angemeldeten)** Kontext; er umfasst Cookie/Sitzung/Berechtigung, authentifizierte Injektion/IDOR sowie Indikatoren für Rechteausweitung + mehrstufige Geschäftslogik ${advisorActive ? 'unterstützt durch eine optionale **KI-Beratungsschicht**' : 'mit **deterministischen Sicherheitskontrollen**'} (das Backend führt dies sicher aus; KEIN Abschluss von Zahlung/Kontoänderung). Cross-Account-IDOR (Daten eines anderen Benutzers) liegt außerhalb des Umfangs dieser Version.`
      : en
      ? `- **Scope:** This section operates in an **authenticated (logged-in)** context; it covers cookie/session/authorization, authenticated injection/IDOR and indicators of privilege escalation + multi-step business logic ${advisorActive ? 'supported by an optional **AI advisory layer**' : 'with **deterministic security controls**'} (the backend runs this safely; NO completion of payment/account change). Cross-account IDOR (another user's data) is outside the scope of this version.`
      : `- **Kapsam:** Bu bölüm **kimlik-doğrulamalı (login’li)** bağlamda çalışır; çerez/oturum/yetki, authenticated enjeksiyon/IDOR ve ${advisorActive ? 'isteğe bağlı bir **yapay zekâ danışma katmanı** destekli' : '**deterministik güvenlik kontrolleriyle**'} yetki yükseltme + çok-adımlı iş mantığı göstergelerini kapsar (backend güvenli uygular; ödeme/hesap-değişikliği tamamlama YOK). Cross-account (başka kullanıcının verisi) IDOR bu sürümün kapsamı dışındadır.`,
  );
  runs.forEach((r, i) => {
    summary.push(`- **${r.title}:** ${statusSummary(r, levels[i])}`);
  });
  summary.push(t('- **Önerilen ilk adım:** Çalıştırılan kontrollerdeki bulguları giderin; hazır adımlar "AI Çözüm Önerileri" bölümünde.', '- **Empfohlener erster Schritt:** Beheben Sie die Befunde der ausgeführten Kontrollen; fertige Schritte im Abschnitt „KI-Lösungsvorschläge".', '- **Recommended first step:** Remediate the findings from the checks that were run; ready-made steps are in the "AI Solution Recommendations" section.'));

  const genel =
    (worst === 'low'
      ? t(`${runs.length} authenticated doğrulama kontrolü değerlendirildi; doğrulanmış kritik/yüksek seviyeli bir zafiyet öne çıkmadı.`, `${runs.length} authentifizierte Verifizierungskontrollen wurden bewertet; es trat keine bestätigte kritische/hohe Schwachstelle hervor.`, `${runs.length} authenticated verification checks were assessed; no confirmed critical/high-level vulnerability stood out.`)
      : t(`Çalıştırılan authenticated kontrollerde en yüksek risk **${worstTitle}** alanında tespit edildi; öncelikli olarak giderilmesi/doğrulanması önerilir.`, `In den ausgeführten authentifizierten Kontrollen wurde das höchste Risiko im Bereich **${worstTitle}** festgestellt; eine vorrangige Behebung/Verifizierung wird empfohlen.`, `In the authenticated checks that were run, the highest risk was detected in the **${worstTitle}** area; priority remediation/verification is recommended.`)) +
    t(` Tüm kontroller GET-only/gözlemseldir; state-değiştiren istek gönderilmemiştir. Şifre dışarı/üçüncü bir servise gönderilmemiş, backend login yapıp yalnız oturumu kullanmıştır.`, ` Alle Kontrollen sind GET-only/beobachtend; es wurde keine zustandsändernde Anfrage gesendet. Das Passwort wurde nicht nach außen/an einen Drittdienst gesendet; das Backend führte den Login durch und nutzte nur die Sitzung.`, ` All checks are GET-only/observational; no state-changing request was sent. The password was not sent externally/to a third-party service; the backend performed the login and used only the session.`);

  const sections = runs.map((r) => {
    if (!r.rep) return `## ${r.title}\n\n> ${t('Bu kontrol için veri toplanamadı.', 'Für diese Kontrolle konnten keine Daten erhoben werden.', 'No data could be collected for this check.')}\n`;
    return `## ${r.title}\n\n${detailOnly(r.rep.findings)}\n`;
  }).join('\n');

  const findingsRaw =
    `${boxFinal}\n\n` +
    `## ${t('YÖNETİCİ ÖZETİ', 'MANAGEMENTZUSAMMENFASSUNG', 'EXECUTIVE SUMMARY')}\n\n${summary.join('\n')}\n\n` +
    `## ${t('GENEL DEĞERLENDİRME', 'GESAMTBEWERTUNG', 'OVERALL ASSESSMENT')}\n\n**${t('Risk Seviyesi', 'Risikostufe', 'Risk level')}: ${rw(worst)}**\n\n${genel}\n\n` +
    `${controlTable}\n${sections}`;

  const fixParts = runs.map((r) => (r.rep && r.rep.fixText.trim() ? `### ${r.title}\n\n${r.rep.fixText.trim()}` : '')).filter(Boolean);
  const fixTextRaw = t(`Bu bölüm, çalıştırılan authenticated kontrollerde tespit edilen bulgular için düzeltme önerileri içerir.\n\n${fixParts.join('\n\n')}`, `Dieser Abschnitt enthält Behebungsvorschläge für die in den ausgeführten authentifizierten Kontrollen festgestellten Befunde.\n\n${fixParts.join('\n\n')}`, `This section contains remediation recommendations for the findings detected in the authenticated checks that were run.\n\n${fixParts.join('\n\n')}`);

  void dataOk;
  // (part 2) MİRAS login'siz cümleleri authenticated bağlama çevir (kaynak şablonlara dokunmadan).
  return { findings: toAuthenticatedContext(findingsRaw, locale), fixText: toAuthenticatedContext(fixTextRaw, locale) };
}

// ======================================================================================
// (LOGİNSİZ TAM PENTEST — nazik degradasyon) Müşteri "login'siz devam" seçtiğinde: paket ÇÖKMEZ.
// Login gerektirmeyen alt küme (Aktif Doğrulama unauth: injection/IDOR göstergesi/SSRF/RCE/upload/
// business/race) GERÇEKTEN çalışır; login-gerektiren authenticated kontroller "İncelenemedi — login
// sağlanmadı" olarak ÜÇ-DURUM çerçevesinde işaretlenir ("temiz/bulgu yok" DEĞİL). Login'li akış (session
// verilen generateAuthenticatedReport) BU FONKSİYONDAN ETKİLENMEZ — ayrı, yeni bir yol.
// ======================================================================================

// Ana sayfa HTTP durum kodu (403/401 = erişildi-ama-reddedildi ayrımı için). Yanıt yoksa 0.
async function homepageStatus(origin: string): Promise<number> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 10_000);
  try {
    const r = await fetch(`${origin}/`, { signal: ctrl.signal, redirect: 'manual', headers: { 'user-agent': 'CyberTestify-PassiveCheck/1.0' } });
    return r.status;
  } catch { return 0; } finally { clearTimeout(timer); }
}

// (P3.2/P3.3) ERİŞİLEBİLİR ama test edilebilir yüzey YOK — "ulaşılamadı" ASLA DENMEZ (site yanıt veriyor).
// status 403/401 → "erişimi reddediyor (WAF)"; aksi (200-statik/404/belirsiz) → "test edilebilir dinamik
// yüzey elde edilemedi". unscannableReport ile AYNI "İncelenemedi" markörü (pdf amber) ama mesaj DOĞRU.
function reachableNoSurfaceReport(host: string, status: number, locale: string): { findings: string; fixText: string } {
  const de = locale === 'de', en = locale === 'en';
  const t = (trS: string, deS: string, enS?: string) => (de ? deS : en ? (enS ?? trS) : trS);
  const H = t('YÖNETİCİ ÖZETİ', 'MANAGEMENTZUSAMMENFASSUNG', 'EXECUTIVE SUMMARY');
  const G = t('GENEL DEĞERLENDİRME', 'GESAMTBEWERTUNG', 'OVERALL ASSESSMENT');
  const R = t('TESPİT EDİLEN RİSKLER', 'FESTGESTELLTE RISIKEN', 'IDENTIFIED RISKS');
  const level = t('İncelenemedi', 'Nicht prüfbar', 'Not assessable');
  const rl = t('Risk Seviyesi', 'Risikostufe', 'Risk level');
  const blocked = status === 403 || status === 401;
  const reason = blocked
    ? t(`erişimi **reddediyor** (HTTP ${status} — WAF/erişim kısıtı)`, `verweigert den **Zugriff** (HTTP ${status} — WAF/Zugriffsbeschränkung)`, `**denies access** (HTTP ${status} — WAF/access restriction)`)
    : t(`yanıt veriyor ancak **test edilebilir bir dinamik yüzey** (form/parametre/API) elde edilemedi (statik içerik veya erişim kısıtı olabilir)`, `antwortet, aber es konnte **keine prüfbare dynamische Oberfläche** (Formular/Parameter/API) ermittelt werden (statischer Inhalt oder Zugriffsbeschränkung möglich)`, `responds but **no testable dynamic surface** (form/parameter/API) could be obtained (static content or access restriction possible)`);
  const findings =
    `## ${H}\n\n` +
    t(`- **Genel risk seviyesi: İncelenemedi** — hedef (${host}) ${reason}.`, `- **Gesamtrisikostufe: Nicht prüfbar** — das Ziel (${host}) ${reason}.`, `- **Overall risk level: Not assessable** — the target (${host}) ${reason}.`) + `\n` +
    t(`- Bu sonuç sitenin GÜVENLİ olduğu anlamına **GELMEZ** ve "ulaşılamadı" da **DEĞİLDİR** — site erişilebilir.`, `- Dieses Ergebnis bedeutet **NICHT**, dass die Website SICHER ist, und ist auch **NICHT** „nicht erreichbar" — die Website ist erreichbar.`, `- This result does **NOT** mean the website is SECURE, and it is **NOT** "unreachable" either — the site is reachable.`) + `\n` +
    t(`- **Önerilen ilk adım:** ${blocked ? 'Tarayıcı IP\'sine erişim izni (allowlist) verin veya WAF kuralını gevşetip' : 'Test edilebilir bir uygulama yüzeyi (form/giriş/parametre) olan bir hedefte'} taramayı tekrarlayın.`, `- **Empfohlener erster Schritt:** ${blocked ? 'Erlauben Sie die Scanner-IP (Allowlist) oder lockern Sie die WAF-Regel und' : 'Wiederholen Sie die Prüfung bei einem Ziel mit einer prüfbaren Anwendungsoberfläche (Formular/Login/Parameter) und'} wiederholen Sie die Prüfung.`, `- **Recommended first step:** ${blocked ? 'Allow the scanner IP (allowlist) or relax the WAF rule, then' : 'Repeat the scan on a target that has a testable application surface (form/login/parameter);'} repeat the scan.`) + `\n\n` +
    `## ${G}\n\n**${rl}: ${level}**\n\n` +
    t(`Sunucu **yanıt veriyor** (yani "ulaşılamadı" değil) ancak ${blocked ? `HTTP ${status} ile erişimi reddettiği` : 'test edilebilir bir dinamik yüzey elde edilemediği'} için kontroller çalıştırılamadı. Bu rapor bir "temiz/güvenli" sonucu **DEĞİLDİR**.`, `Der Server **antwortet** (also nicht „nicht erreichbar"), aber da er ${blocked ? `den Zugriff mit HTTP ${status} verweigerte` : 'keine prüfbare dynamische Oberfläche lieferte'}, konnten die Kontrollen nicht ausgeführt werden. Dieser Bericht ist **KEIN** „sauberes/sicheres" Ergebnis.`, `The server **responds** (so it is not "unreachable"), but because it ${blocked ? `denied access with HTTP ${status}` : 'did not yield a testable dynamic surface'}, the controls could not be run. This report is **NOT** a "clean/secure" result.`) + `\n\n` +
    `## ${R}\n\n_` + t('Test edilebilir yüzey elde edilemedi — sonuç değerlendirilemez (ama hedef erişilebilir).', 'Es konnte keine prüfbare Oberfläche ermittelt werden — das Ergebnis ist nicht bewertbar (das Ziel ist jedoch erreichbar).', 'No testable surface could be obtained — the result is not assessable (but the target is reachable).') + `_\n`;
  return { findings, fixText: '' };
}

// Login-gerektiren authenticated kontroller — hepsi "İncelenemedi — login sağlanmadı" (üç-durum; temiz DEĞİL).
function loginlessAuthedSection(locale: string): string {
  const de = locale === 'de', en = locale === 'en';
  const t = (trS: string, deS: string, enS?: string) => (de ? deS : en ? (enS ?? trS) : trS);
  const controls = de
    ? ['Sitzungs-Cookie-Flags', 'Session Fixation', 'Logout / Sitzungsentwertung', 'Forced Browsing / Funktionsebenen-Autorisierung', 'Authentifizierte Injektion (SQLi/XSS)', 'Authentifiziertes IDOR (eigene Ressourcen)', 'Rechteausweitung (Privilege Escalation)', 'Mehrstufige Geschäftslogik', 'JWT-/Token-Sicherheit', 'Authentifizierungstiefe', 'Sitzungssicherheitstiefe']
    : en
    ? ['Session Cookie Flags', 'Session Fixation', 'Logout / Session Invalidation', 'Forced Browsing / Function-Level Authorization', 'Authenticated Injection (SQLi/XSS)', 'Authenticated IDOR (own resources)', 'Privilege Escalation', 'Multi-Step Business Logic', 'JWT / Token Security', 'Authentication Depth', 'Session Security Depth']
    : ['Oturum Çerezi Bayrakları', 'Session Fixation', 'Logout / Oturum Geçersizleştirme', 'Forced Browsing / Fonksiyon-Seviye Yetki', 'Authenticated Enjeksiyon (SQLi/XSS)', 'Authenticated IDOR (kendi kaynakları)', 'Yetki Yükseltme (Privilege Escalation)', 'Çok-Adımlı İş Mantığı', 'JWT / Token Güvenliği', 'Kimlik-Doğrulama Derinliği', 'Oturum Güvenliği Derinliği'];
  const state = t('⚠️ İncelenemedi — login sağlanmadı', '⚠️ Nicht prüfbar — keine Anmeldung', '⚠️ Not assessable — no login provided');
  const rows = controls.map((c) => `| ${c} | ${state} |`).join('\n');
  const head = t('KİMLİK-DOĞRULAMALI KONTROLLER — İNCELENEMEDİ (LOGİN SAĞLANMADI)', 'AUTHENTIFIZIERTE KONTROLLEN — NICHT PRÜFBAR (KEINE ANMELDUNG)', 'AUTHENTICATED CONTROLS — NOT ASSESSABLE (NO LOGIN PROVIDED)');
  const colC = t('Kontrol', 'Kontrolle', 'Control');
  const colR = t('Sonuç', 'Ergebnis', 'Result');
  return `## ${head}\n\n` +
    t('Bu tarama bir **TEST hesabı sağlanmadan** (login\'siz) yapıldı. Aşağıdaki oturum-içi (giriş sonrası) kontroller **çalıştırılamadı**. Bu bir **"güvenli/temiz" sonucu DEĞİLDİR** — yalnızca login olmadan değerlendirilemediklerini gösterir:',
      'Dieser Scan wurde **ohne Bereitstellung eines TEST-Kontos** (ohne Anmeldung) durchgeführt. Die folgenden Kontrollen im angemeldeten Kontext konnten **nicht ausgeführt werden**. Dies ist **KEIN „sicheres/sauberes" Ergebnis** — es zeigt lediglich, dass sie ohne Anmeldung nicht bewertet werden konnten:',
      'This scan was performed **without a TEST account** (no login). The following logged-in (post-authentication) controls **could not be run**. This is **NOT a "secure/clean" result** — it only shows they could not be assessed without a login:') + `\n\n` +
    `| ${colC} | ${colR} |\n|-----|-----|\n${rows}\n\n` +
    `> ${t('Authenticated kontroller (yetkilendirme, IDOR-kendi-kaynağı, oturum güvenliği, JWT, iş mantığı) bir oturum gerektirir. Bir **TEST hesabı** sağlanırsa bu alanlar da değerlendirilebilir.',
      'Authentifizierte Kontrollen (Autorisierung, IDOR eigener Ressourcen, Sitzungssicherheit, JWT, Geschäftslogik) erfordern eine Sitzung. Wird ein **TEST-Konto** bereitgestellt, können auch diese Bereiche bewertet werden.',
      'Authenticated controls (authorization, own-resource IDOR, session security, JWT, business logic) require a session. If a **TEST account** is provided, these areas can also be assessed.')}\n`;
}

/** Login'siz Tam Pentest raporu: unauth aktif doğrulama (gerçek) + authed kontroller "İncelenemedi". */
export async function generateLoginlessFullPentestReport(host: string, locale: string = 'tr'): Promise<{ findings: string; fixText: string }> {
  const o = await resolveOrigin(host);
  // (P3.1) GERÇEKTEN ulaşılamaz (DNS yok / hiçbir yanıt yok) — "ulaşılamadı" YALNIZ burada.
  if (!o.reachable) return { findings: unscannableReport(host, locale === 'de' ? 'Kontrollen' : locale === 'en' ? 'checks' : 'kontroller', locale).findings, fixText: '' };
  // Unauth aktif doğrulama (login gerektirmeyen alt küme) — gerçekten çalışır.
  const av = await generateBundleActiveVerifyReport(host, locale).catch(() => null);
  const avUnscannable = !av || /İncelenemedi|Nicht prüfbar|Not assessable/i.test(av.findings.slice(0, 500));
  const authedSection = loginlessAuthedSection(locale);
  if (!avUnscannable && av) {
    // Unauth yüzey VAR → gerçek aktif-doğrulama raporu + authed "İncelenemedi" bölümü.
    return { findings: `${av.findings.trim()}\n\n${authedSection}`, fixText: av.fixText };
  }
  // (P3.2/P3.3) Erişilebilir ama test edilebilir yüzey yok — "ulaşılamadı" ASLA (reachable=true burada).
  // 403/401 → "reddedildi"; aksi → "test edilebilir yüzey yok". unscannableReport KULLANILMAZ (o "ulaşılamadı" der).
  const status = await homepageStatus(o.origin);
  const base = reachableNoSurfaceReport(host, status, locale);
  return { findings: `${base.findings.trim()}\n\n${authedSection}`, fixText: '' };
}
