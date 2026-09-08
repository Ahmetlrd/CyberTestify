'use client';

import { useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { api } from '../../lib/api';
import { renderEmphasis } from '../../lib/richText';
import { readRegionCookie } from '../../lib/region';
import { getRegion, type RegionCode } from '../../config/regions';
import { formatMoney } from '../../config/i18n';
import { DynamicContract } from '../../components/DynamicContract';
import { PromoCodeChip } from '../../components/PromoCodeChip';
import { trackEvent, currencyForRegion } from '../../lib/analytics';

type ActiveTest = { scope: { does: string[]; doesNot: string[] }; riskText: string; consentVersion: string };
type Pkg = {
  key: string; displayName: string; description: string; priceMinorUnit: number; currency?: string;
  securityProfile?: 'passive' | 'active-light'; activeTest?: ActiveTest | null; comingSoon?: boolean; bundleOnly?: boolean;
  crossBorderAi?: boolean; // yurt dışı AI'ya veri gidiyor mu (KVKK m.9 açık rıza gerekli mi)
};

// datetime-local `min` icin yerel saatte YYYY-MM-DDTHH:mm — gecmis tarihleri
// tarayici soluklastirir/secilemez yapar.
function minDateTimeLocal(): string {
  const d = new Date();
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}

// (Çok-bölge) Checkout metinleri tr/de. Client sayfa → region cookie'sinden lang (hydration-safe:
// 'tr' başlar, mount sonrası set). us/ae (en) → tr'ye düşer (mevcut davranışla aynı; checkout zaten
// TR'ydi + intlComingSoon bloklar). /de'de onay grupları Alman legal sayfalarına bağlanır (Widerruf dahil),
// KVKK yerine DSGVO. /tr metni birebir korunur.
const ORD = {
  tr: {
    orderEyebrow: 'SİPARİŞ',
    title: 'Taramanızı Başlatın', sub: 'Paketi seçin, onayları işaretleyin ve güvenli ödemeye geçin.',
    noDomainPre: 'Önce taranacak bir alan adı seçin.', noDomainLink: 'Alan adı seç →',
    dnsVerified: 'Alan adı DNS ile doğrulandı — aktif tarama ödeme onayından sonra başlar.',
    activeVerifyTitle: 'Bu paket aktif problar gönderir — DNS doğrulaması gerekir',
    activeVerifyBodyHtml: 'Alan adı sahipliğinizi DNS ile doğrulamadan aktif tarama (enjeksiyon/oturum denemeleri) <strong>başlamaz</strong> — ödeme alınsa bile sipariş <strong>“alan adı doğrulaması bekleniyor”</strong> durumunda tutulur, doğrulanınca <strong>otomatik başlar</strong>.',
    verifyNow: 'Şimdi DNS ile doğrula →',
    passiveNoVerify: 'Bu paket için doğrulama gerekmez — ödeme onaylanınca tarama hemen başlar.',
    step1: '1 · Paket seçin', entryBadge: 'Giriş',
    basitDesc: 'Hızlı, ucuz deneme taraması — ön izleme niteliğindedir (kapsamlı denetim değildir).',
    kdv: 'KDV Dahil', sampleReport: 'Örnek raporu gör', buy: 'Satın Al',
    popular: 'Popüler', includes: 'İçindekiler',
    reconItems: [
      'Terk edilmiş alt domain (Subdomain Takeover) taraması — CT loglarından alt domain envanteri',
      'Açık API / Swagger dokümantasyon keşfi',
      'CMS & teknoloji parmak izi analizi',
      'Site haritasından idari/hassas yol tespiti',
    ],
    reconNote: 'Pasif dış yüzey keşfidir; aktif uç nokta enjeksiyonu veya kimlik doğrulamalı test içermez.',
    soon: 'Yakında', soonClosed: 'Şu an satışa kapalı',
    testCredsMembers: 'Test hesabı bilgileri',
    // Aktif Doğrulama şeffaflık kutusu
    avTitle: 'Şeffaflık & Kapsam — ödemeden önce okuyun',
    avP1Html: 'Bu paket, web sitenizin <strong>herkese açık (login gerektirmeyen) dış saldırı yüzeyini</strong> zararsız problarla test eder — dışa açık arama, form, API ve login/kayıt akışı üzerindeki enjeksiyon, yetkilendirme ve mantık riskleri.',
    avP2Html: 'Sitenizde dışa açık <strong>arama, form, API veya id-tabanlı uç nokta bulunmuyorsa</strong>, içerikte listelenen <strong>IDOR / İş Mantığı / Dosya Yükleme / Race</strong> gibi kontroller raporda <strong>“İncelenemedi”</strong> görünebilir. Bu bir <strong>hata değildir</strong> — sitenizin dış yüzey yapısının doğal sonucudur (test edilecek açık bir giriş noktası olmaması).',
    avP3Html: 'Oturum içi (kullanıcı girişi <strong>sonrası</strong>) derin yetkilendirme/iş-mantığı testleri için <strong>Tam Kapsamlı Pentest</strong> paketini seçin.',
    // Tam Kapsamlı Pentest detay kutusu
    fpReviewHtml: '<strong class="text-ink">İnceleme süreci:</strong> Bu paket, güvenlik nedeniyle sipariş sonrası <strong>ödeme onaylanınca hemen</strong> başlar.',
    fpAccountHtml: '<strong class="text-ink">Test hesabı:</strong> Kimlik doğrulamalı test için bir <strong>TEST hesabı</strong> (ana/üretim hesabınız DEĞİL; 2FA’sız, sınırlı yetkili, tek-kullanımlık) vermelisiniz. Kimlik bilgileriniz <strong>şifreli/geçici</strong> saklanır ve tarama sonrası silinir.',
    fpMethodHtml: '<strong class="text-ink">Yöntem:</strong> Login sonrası çerez/oturum/yetki, authenticated enjeksiyon ve IDOR, yetki yükseltme ve çok-adımlı iş mantığı göstergeleri <strong>deterministik güvenlik kontrolleriyle</strong> incelenir. Gerçek veri/hesap değişikliği ve ödeme tamamlama <strong>kod seviyesinde engellidir</strong> — bu bir otonom/sınırsız pentest değildir.',
    fpAiHtml: '<strong class="text-ink">Opsiyonel AI katmanı:</strong> İki kontrolde (yetki yükseltme + çok-adımlı iş mantığı) isteğe bağlı, hafif bir <strong>yapay zekâ danışma katmanı</strong> vardır; <strong>varsayılan olarak kapalıdır</strong> ve yalnız açıkken ek, doğrulanabilir bir gösterge bulduğunda devreye girer. Kapalıyken sonuçlar <strong>tam deterministik authenticated kontrollerle</strong> üretilir — normal ve beklenen davranıştır, rapor bunu şeffaf gösterir.',
    fpScopeHtml: '<strong class="text-ink">Kapsam:</strong> <strong>Cross-account</strong> (başka bir kullanıcının verisine erişim) IDOR bu sürümün kapsamı dışındadır.',
    step2: '2 · Onaylar', needConsents: (n: number) => `Devam etmek için aşağıdaki ${n} onayı işaretleyin.`,
    contractShow: 'Bu siparişe özel Mesafeli Satış Sözleşmesi’ni görüntüle', contractHide: 'Bu siparişe özel sözleşmeyi gizle',
    step3: '3 · Tekrar', oneOff: 'Tek seferlik tarama', repeat: 'Düzenli tekrarla',
    frequency: 'Sıklık', weekly: 'Haftalık', biweekly: 'İki haftada bir', monthly: 'Aylık',
    howManyRuns: 'Kaç tarama (peşin)',
    recurringNote: (runs: number) => `${runs} tarama için baştan ödeme yaparsınız; ilki hemen, sonrakiler seçtiğiniz sıklıkta çalışır. (Minimum sıklık: haftalık.)`,
    step4: '4 · Başlangıç', firstScan: '(ilk tarama)', startNow: 'Hemen başlat', startLater: 'Belirli bir tarihte başlat',
    startDateTime: 'Başlangıç tarihi ve saati',
    startLaterNote: 'Tarama seçtiğiniz zamana en yakın kontrol turunda (birkaç dakika içinde) başlar.',
    // Active test authorization
    atTitle: 'Aktif Test Yetkilendirmesi (zorunlu)',
    atBody: 'Bu paket, zafiyeti doğrulamak için sınırlı aktif test istekleri gönderir. Devam etmek için kapsamı okuyup beyanı doldurmalısınız.',
    atDoes: 'Bu tarama NE YAPAR', atDoesNot: 'Bu tarama NE YAPMAZ',
    atConsentNote: 'Onayınız; hesabınız, zaman damgası, IP ve metin sürümü ile birlikte otomatik olarak kayıt altına alınır (ek bilgi girmenize gerek yoktur). İsterseniz bir yetkilendirme PDF’i olarak siparişinize bağlanır.',
    // Auth cred block
    acTitle: 'Test hesabı bilgileri', acOptional: '(opsiyonel)',
    acInfoHtml: 'Bu alan <strong>opsiyoneldir</strong>. Sitenizde bir <strong>giriş (login) mekanizması yoksa</strong> boş bırakın — tarama <strong>loginsiz (kimlik-doğrulamasız)</strong> yapılır. Giriş varsa, oturum-içi kontroller için bir <strong>TEST hesabı</strong> girebilirsiniz.',
    acWarnTitle: 'Yalnız TEST hesabı girin — ana/üretim hesabınızı DEĞİL',
    acWarnBodyHtml: 'Bu tarama için oluşturulmuş, <strong>sınırlı yetkili, tek-kullanımlık</strong> bir hesap kullanın; şifresini tarama sonrası değiştirin.',
    acWarn2Html: '<strong>2FA’sı olmayan</strong> bir hesap verin. Kimlik bilgileriniz <strong>şifreli</strong> saklanır ve tarama sonrası <strong>silinir</strong>.',
    acUser: 'Kullanıcı adı / e-posta', acPass: 'Şifre', acPassPh: 'Test hesabı şifresi',
    acCheckBtn: 'Test girişini doğrula (opsiyonel)', acChecking: 'Giriş deneniyor…',
    acCheckingHint: 'Giriş formu aranıp deneniyor — birkaç saniye sürebilir…',
    acNoCredsHtml: 'Test hesabı bilgisi girmediniz — tarama <strong>loginsiz (kimlik-doğrulamasız)</strong> yapılacak. Sitenizde giriş yoksa bu normaldir.',
    lcOk: 'Test hesabıyla giriş doğrulandı.',
    lcBad: 'Bu kullanıcı adı/şifreyle giriş yapılamadı — bilgileri kontrol edin.',
    lc2fa: 'Hesapta 2FA görünüyor — 2FA’sız bir test hesabı verin.',
    lcNoForm: 'Otomatik giriş formu bulunamadı — yine de devam edebilirsiniz (tarama daha kapsamlı deneyecektir).',
    lcTimeout: 'Doğrulama uzun sürdü — yine de devam edebilirsiniz (gerçek tarama daha kapsamlı deneyecektir).',
    lcOther: 'Giriş şu an doğrulanamadı — yine de devam edebilirsiniz.',
    // Promo
    promoLabel: 'Promosyon kodu (opsiyonel)', promoPh: 'Kodunuz', apply: 'Uygula', promoCheckFail: 'Kod kontrol edilemedi.',
    promoAppliedPre: 'Kod uygulandı — indirim', promoNewTotal: 'Yeni tutar:', promoFree: ' — ödeme adımı atlanır, tarama hemen kuyruğa alınır.',
    queueBusyHtml: 'Sipariş verebilirsiniz — <strong>taramanız en kısa sürede başlayacaktır</strong> ve durumu bu panelden takip edebilirsiniz.',
    // Precheck warnings
    checking: 'Hedefinize ulaşılıyor mu, ön kontrol yapılıyor…',
    unreachTitle: 'Hedefinize şu an dışarıdan ulaşılamıyor',
    unreachP1Html: 'Sitenizin ana adresi (<strong>443/HTTPS ve 80/HTTP</strong>) şu an yanıt vermiyor. Bu bir hata değildir — sitenizin <strong>yayında olmadığı, kapalı olduğu ya da bizim erişimimizi engellediği</strong> anlamına gelir. Tarama şu an başlatılırsa dışarıdan test edilecek bir yüzey bulunamayacağı için rapor büyük olasılıkla <strong>boş / "İncelenemedi"</strong> gelir.',
    unreachP2Html: '<strong>Önerimiz:</strong> sitenizin yayında ve erişilebilir olduğundan emin olun, sonra bu sayfayı yenileyip tekrar deneyin. Erişim sorununun geçici olduğunu düşünüyorsanız yine de devam edebilirsiniz.',
    unreachAck: 'Erişim sorununu anladım; yine de şimdi başlatmak istiyorum.',
    lowTitle: 'Önemli Ön Kontrol',
    lowP1Html: 'Sitenizde otomatik hızlı taramada <strong>test edilebilir giriş noktası</strong> (form, query parametresi, sayısal ID içeren uç nokta) <strong>neredeyse hiç bulunamadı</strong>. Bu genellikle sitenin <strong>JavaScript ile render edilen (SPA)</strong> bir yapıya sahip olmasından kaynaklanır.',
    lowP2Html: 'Tarama yine de çalıştırılacaktır, ancak çoğu kontrol <strong>"kapsam dışı / incelenemedi"</strong> olarak sonuçlanabilir. Ödenen tutar <strong>bulgu garantisi değildir</strong>; kapsamlı bir değerlendirme sürecinin tamamı içindir.',
    lowAck: 'Devam etmek istiyorum.',
    // Summary
    summary: 'Sipariş Özeti', domainLabel: 'Alan adı', freqLabel: 'Sıklık', startLabelKey: 'Başlangıç', contentLabel: 'İçerik',
    scanCount: (n: number) => `${n} tarama`, total: 'Toplam', totalRuns: (n: number) => `Toplam · ${n} tarama`, kdvIncl: 'KDV dahildir',
    verifyDomain: 'Alan adını doğrula',
    verifyHint: 'Aktif tarama için önce alan adı sahipliğinizi DNS ile doğrulayın — doğrulandıktan sonra satın alabilirsiniz.',
    scheduledHint: 'Zamanlanmış taramalarım ekranından yönetebilirsiniz.', autoStartHint: 'Ödeme onaylanınca tarama otomatik başlar.',
    selectPackage: 'Devam etmek için bir paket seçin.',
    freqOneOff: 'Tek seferlik', freqEvery: (label: string, runs: number) => `${label} · ${runs} tarama`, startImmediate: 'Hemen',
    // CTA labels
    ctaStarting: 'Başlatılıyor…', ctaBuyBundle: 'Paketi Satın Al', ctaSetupRecurring: 'Düzenli Taramayı Kur', ctaSchedule: 'Taramayı Zamanla', ctaStart: 'Taramayı Başlat',
    // disabled hints
    hintSelectDomain: 'Önce site sahipliğinizi doğrulayın.', hintSelectModules: 'Paket içeriğini seçin.',
    hintConsents: 'Devam etmek için aşağıdaki onayları işaretleyin →', hintLowScope: 'Ön kontrol uyarısını okuyup onaylayın →', hintUnreach: 'Erişim uyarısını okuyup onaylayın →', hintChecking: 'Ön kontrol yapılıyor…',
    // Payment errors + validation
    payPageErr: 'Ödeme sayfası alınamadı. Lütfen tekrar deneyin.',
    errSelectPackage: 'Lütfen bir paket seçin.',
    errAllConsents: 'Devam etmek için onayların tümünü işaretlemelisiniz.',
    errActiveNoSchedule: 'Aktif-test paketleri zamanlanamaz; tek seferlik ve hemen çalıştırılır.',
    errActiveRisk: 'Aktif test için risk kabul kutusunu işaretlemelisiniz.',
    errFutureDate: 'İleri tarih için gelecekte bir tarih/saat seçin.',
    errAuthConsents: 'Test hesabı bilgisi girdiniz — kimlik-doğrulamalı test için ek onayları (test hesabı beyanı ve yüksek-risk kabulü) işaretleyin. (Ya da bilgileri boş bırakıp loginsiz devam edin.)',
    errSelectModule: 'En az bir modül seçin.',
    errLowScopeAck: 'Devam etmek için ön kontrol uyarısını onaylamalısınız.',
    errUnreachAck: 'Hedefe erişilemiyor — devam etmek için uyarıyı onaylamalısınız.',
    // Trust strip
    trustSSL: '256-bit SSL · iyzico güvenli ödeme', trustCard: 'Kart bilgileri iyzico’da işlenir, bizde saklanmaz', trustKvkk: 'KVKK’ya uygun · veriler şifreli saklanır',
    payAlt: 'iyzico ile Öde',
    // Mobile bar
    noPackage: 'Paket seçilmedi', mobileVerify: 'Doğrula',
    // Consents (gruplu)
    cGenStrong: 'Okudum, onaylıyorum:', cGenOwn1: 'Bu alan adının', cGenOwn2: 've altyapısının', cGenOwn3: 'sahibi/yetkilisiyim ve bu hedefe',
    cGenActive: 'bir aktif-hafif doğrulama testi', cGenPassive: 'pasif', cGenScan: 'tarama', cGenConsent: 'yapılmasına rıza gösteriyorum;',
    cGenLegalMid: 'koşullarını ve', cGenLegalRead: '’ni okudum, kabul ediyorum.',
    cGenActiveRiskHtml: ' Bu paketin <strong>daha yüksek risk</strong> taşıyan aktif test istekleri gönderdiğini kabul ediyorum.',
    cGenAuthHtml: ' Vereceğim hesabın üretim/ana hesabım <strong>olmadığını</strong>, sınırlı yetkili tek-kullanımlık bir <strong>TEST hesabı</strong> olduğunu beyan ederim.',
    cCrossStrong: 'Yapay zekâ analizi:', cCrossBodyPre: ' Bu pakette tarama verilerim', cCrossAuth: ' ve verdiğim ', cCrossAuthStrong: 'test hesabı bilgilerim', cCrossBodyPost: ', analiz için ', cCrossForeign: 'yurt dışında yerleşik bir yapay zekâ hizmetine', cCrossBodyEnd: ' aktarılır; buna açıkça rıza gösteriyorum.', cCrossAuthNote: ' Bilgilerim şifreli saklanır ve tarama sonrası silinir.',
    cWithStrong: 'Cayma hakkı:', cWithBodyHtml: ' Hizmetin cayma süresi dolmadan <strong>onayımla derhal başlatılmasını</strong> istiyorum ve bu durumda <strong>cayma hakkımı kaybedeceğimi</strong> kabul ediyorum.',
    // Legal link labels + hrefs (tr)
    legalOn: 'Ön Bilgilendirme', legalMesafeli: 'Mesafeli Satış', legalIptal: 'İptal/İade', legalGizlilik: 'Gizlilik Politikası', legalKvkk: 'KVKK Aydınlatma Metni',
    legalOnHref: '/legal/on-bilgilendirme', legalMesafeliHref: '/legal/mesafeli-satis', legalIptalHref: '/legal/iptal-iade', legalGizlilikHref: '/legal/gizlilik', legalKvkkHref: '/legal/kvkk-aydinlatma',
    legalSlash: ' /',
    intlSoonHtml: '',
  },
  de: {
    orderEyebrow: 'BESTELLUNG',
    title: 'Starten Sie Ihren Scan', sub: 'Paket wählen, Zustimmungen ankreuzen und zur sicheren Zahlung.',
    noDomainPre: 'Wählen Sie zuerst eine zu scannende Domain.', noDomainLink: 'Domain wählen →',
    dnsVerified: 'Domain per DNS bestätigt — der aktive Scan startet nach der Zahlungsbestätigung.',
    activeVerifyTitle: 'Dieses Paket sendet aktive Prüfungen — DNS-Bestätigung erforderlich',
    activeVerifyBodyHtml: 'Ohne DNS-Bestätigung Ihrer Domain-Inhaberschaft startet der aktive Scan (Injection-/Session-Versuche) <strong>nicht</strong> — selbst nach Zahlung wird die Bestellung im Status <strong>„Domain-Bestätigung ausstehend“</strong> gehalten und startet nach der Bestätigung <strong>automatisch</strong>.',
    verifyNow: 'Jetzt per DNS bestätigen →',
    passiveNoVerify: 'Für dieses Paket ist keine Bestätigung nötig — der Scan startet direkt nach der Zahlungsbestätigung.',
    step1: '1 · Paket wählen', entryBadge: 'Einstieg',
    basitDesc: 'Ein schneller, günstiger Test-Scan — als Vorschau gedacht (keine umfassende Prüfung).',
    kdv: 'inkl. MwSt.', sampleReport: 'Musterbericht ansehen', buy: 'Jetzt kaufen',
    popular: 'Beliebt', includes: 'Enthält',
    reconItems: [
      'Scan auf aufgegebene Subdomains (Takeover) — Subdomain-Inventar aus CT-Logs',
      'Erkennung öffentlicher API- / Swagger-Dokumentation',
      'CMS- & Technologie-Fingerprint-Analyse',
      'Erkennung administrativer/sensibler Pfade aus der Sitemap',
    ],
    reconNote: 'Passive Erkundung der externen Oberfläche; keine aktive Endpunkt-Injection und keine authentifizierten Tests.',
    soon: 'Bald', soonClosed: 'Derzeit nicht im Verkauf',
    testCredsMembers: 'Testkonto-Daten',
    avTitle: 'Transparenz & Umfang — bitte vor der Zahlung lesen',
    avP1Html: 'Dieses Paket testet die <strong>öffentliche (kein Login erforderliche) externe Angriffsfläche</strong> Ihrer Website mit harmlosen Prüfungen — Injection-, Autorisierungs- und Logik-Risiken bei öffentlichen Such-, Formular-, API- und Login-/Registrierungs-Flows.',
    avP2Html: 'Wenn Ihre Website <strong>keine öffentlichen Such-, Formular-, API- oder ID-basierten Endpunkte</strong> hat, können im Inhalt gelistete Prüfungen wie <strong>IDOR / Geschäftslogik / Datei-Upload / Race</strong> im Bericht als <strong>„nicht geprüft“</strong> erscheinen. Das ist <strong>kein Fehler</strong> — es ergibt sich natürlich aus der externen Oberflächenstruktur Ihrer Website (kein offener Einstiegspunkt zum Testen).',
    avP3Html: 'Für tiefe Autorisierungs-/Geschäftslogik-Tests <strong>nach</strong> dem Login wählen Sie das Paket <strong>Umfassender Pentest</strong>.',
    fpReviewHtml: '<strong class="text-ink">Ablauf:</strong> Dieses Paket startet aus Sicherheitsgründen nach der Bestellung <strong>unmittelbar nach der Zahlungsbestätigung</strong>.',
    fpAccountHtml: '<strong class="text-ink">Testkonto:</strong> Für authentifizierte Tests müssen Sie ein <strong>TEST-Konto</strong> bereitstellen (NICHT Ihr Produktivkonto; ohne 2FA, minimale Rechte, Einmalgebrauch). Ihre Zugangsdaten werden <strong>verschlüsselt/temporär</strong> gespeichert und nach dem Scan gelöscht.',
    fpMethodHtml: '<strong class="text-ink">Methode:</strong> Nach dem Login werden Cookie/Session/Autorisierung, authentifizierte Injection und IDOR, Rechteausweitung und mehrstufige Geschäftslogik-Indikatoren mit <strong>deterministischen Sicherheitsprüfungen</strong> untersucht. Echte Daten-/Kontoänderungen und Zahlungsabschluss sind <strong>auf Code-Ebene blockiert</strong> — dies ist kein autonomer/unbegrenzter Pentest.',
    fpAiHtml: '<strong class="text-ink">Optionale KI-Schicht:</strong> Bei zwei Prüfungen (Rechteausweitung + mehrstufige Geschäftslogik) gibt es eine optionale, leichte <strong>KI-Beratungsschicht</strong>; sie ist <strong>standardmäßig deaktiviert</strong> und greift nur ein, wenn sie aktiviert ist und einen zusätzlichen, nachweisbaren Indikator findet. Deaktiviert werden die Ergebnisse mit <strong>vollständig deterministischen authentifizierten Prüfungen</strong> erzeugt — das ist normal und erwartet; der Bericht zeigt dies transparent.',
    fpScopeHtml: '<strong class="text-ink">Umfang:</strong> <strong>Cross-Account</strong>-IDOR (Zugriff auf Daten eines anderen Nutzers) ist in dieser Version außerhalb des Scope.',
    step2: '2 · Zustimmungen', needConsents: (n: number) => `Kreuzen Sie die folgenden ${n} Zustimmungen an, um fortzufahren.`,
    contractShow: 'Für diese Bestellung gültigen Fernabsatzvertrag anzeigen', contractHide: 'Vertrag für diese Bestellung ausblenden',
    step3: '3 · Wiederholung', oneOff: 'Einmaliger Scan', repeat: 'Regelmäßig wiederholen',
    frequency: 'Häufigkeit', weekly: 'Wöchentlich', biweekly: 'Alle zwei Wochen', monthly: 'Monatlich',
    howManyRuns: 'Wie viele Scans (im Voraus)',
    recurringNote: (runs: number) => `Sie zahlen im Voraus für ${runs} Scans; der erste sofort, die weiteren in der gewählten Häufigkeit. (Mindesthäufigkeit: wöchentlich.)`,
    step4: '4 · Start', firstScan: '(erster Scan)', startNow: 'Sofort starten', startLater: 'An einem bestimmten Datum starten',
    startDateTime: 'Startdatum und -uhrzeit',
    startLaterNote: 'Der Scan startet in der Kontrollrunde, die Ihrem gewählten Zeitpunkt am nächsten liegt (innerhalb weniger Minuten).',
    atTitle: 'Autorisierung für aktive Tests (erforderlich)',
    atBody: 'Dieses Paket sendet begrenzte aktive Testanfragen, um Schwachstellen zu bestätigen. Zum Fortfahren müssen Sie den Umfang lesen und die Erklärung ausfüllen.',
    atDoes: 'Was dieser Scan TUT', atDoesNot: 'Was dieser Scan NICHT tut',
    atConsentNote: 'Ihre Zustimmung wird zusammen mit Ihrem Konto, Zeitstempel, IP und der Textversion automatisch protokolliert (keine zusätzlichen Angaben nötig). Auf Wunsch wird sie als Autorisierungs-PDF an Ihre Bestellung angehängt.',
    acTitle: 'Testkonto-Daten', acOptional: '(optional)',
    acInfoHtml: 'Dieses Feld ist <strong>optional</strong>. Wenn Ihre Website <strong>keinen Login-Mechanismus</strong> hat, lassen Sie es leer — der Scan wird <strong>ohne Login (ohne Authentifizierung)</strong> durchgeführt. Gibt es einen Login, können Sie ein <strong>TEST-Konto</strong> für sitzungsinterne Prüfungen eingeben.',
    acWarnTitle: 'Geben Sie nur ein TEST-Konto ein — NICHT Ihr Produktivkonto',
    acWarnBodyHtml: 'Verwenden Sie ein für diesen Scan erstelltes Konto mit <strong>minimalen Rechten und Einmalgebrauch</strong>; ändern Sie das Passwort nach dem Scan.',
    acWarn2Html: 'Geben Sie ein Konto <strong>ohne 2FA</strong> an. Ihre Zugangsdaten werden <strong>verschlüsselt</strong> gespeichert und nach dem Scan <strong>gelöscht</strong>.',
    acUser: 'Benutzername / E-Mail', acPass: 'Passwort', acPassPh: 'Testkonto-Passwort',
    acCheckBtn: 'Test-Login prüfen (optional)', acChecking: 'Anmeldung wird versucht…',
    acCheckingHint: 'Login-Formular wird gesucht und versucht — kann einige Sekunden dauern…',
    acNoCredsHtml: 'Sie haben keine Testkonto-Daten eingegeben — der Scan wird <strong>ohne Login (ohne Authentifizierung)</strong> durchgeführt. Wenn Ihre Website keinen Login hat, ist das normal.',
    lcOk: 'Anmeldung mit dem Testkonto bestätigt.',
    lcBad: 'Mit diesem Benutzernamen/Passwort war keine Anmeldung möglich — bitte prüfen Sie die Daten.',
    lc2fa: 'Beim Konto scheint 2FA aktiv zu sein — bitte geben Sie ein Testkonto ohne 2FA an.',
    lcNoForm: 'Kein automatisches Login-Formular gefunden — Sie können dennoch fortfahren (der Scan versucht mehr).',
    lcTimeout: 'Die Prüfung hat zu lange gedauert — Sie können dennoch fortfahren (der echte Scan versucht mehr).',
    lcOther: 'Die Anmeldung konnte derzeit nicht bestätigt werden — Sie können dennoch fortfahren.',
    promoLabel: 'Aktionscode (optional)', promoPh: 'Ihr Code', apply: 'Anwenden', promoCheckFail: 'Code konnte nicht geprüft werden.',
    promoAppliedPre: 'Code angewendet — Rabatt', promoNewTotal: 'Neuer Betrag:', promoFree: ' — der Zahlungsschritt entfällt, der Scan wird sofort eingereiht.',
    queueBusyHtml: 'Sie können bestellen — <strong>Ihr Scan startet baldmöglichst</strong> und Sie verfolgen den Status über dieses Panel.',
    checking: 'Erreichbarkeit Ihres Ziels wird vorab geprüft…',
    unreachTitle: 'Ihr Ziel ist derzeit von außen nicht erreichbar',
    unreachP1Html: 'Die Hauptadresse Ihrer Website (<strong>443/HTTPS und 80/HTTP</strong>) antwortet derzeit nicht. Das ist kein Fehler — es bedeutet, dass Ihre Website <strong>offline oder geschlossen ist oder unseren Zugriff blockiert</strong>. Wird der Scan jetzt gestartet, findet er keine von außen testbare Oberfläche, sodass der Bericht wahrscheinlich <strong>leer / „nicht geprüft“</strong> ausfällt.',
    unreachP2Html: '<strong>Unsere Empfehlung:</strong> Stellen Sie sicher, dass Ihre Website online und erreichbar ist, aktualisieren Sie dann diese Seite und versuchen Sie es erneut. Wenn Sie meinen, das Problem sei vorübergehend, können Sie dennoch fortfahren.',
    unreachAck: 'Ich habe das Zugriffsproblem verstanden; ich möchte trotzdem jetzt starten.',
    lowTitle: 'Wichtige Vorabprüfung',
    lowP1Html: 'Bei der automatischen Schnellprüfung wurde <strong>fast kein testbarer Einstiegspunkt</strong> (Formular, Query-Parameter, Endpunkt mit numerischer ID) auf Ihrer Website gefunden. Das liegt meist an einer <strong>per JavaScript gerenderten (SPA)</strong> Struktur der Website.',
    lowP2Html: 'Der Scan wird dennoch ausgeführt, aber viele Prüfungen können als <strong>„außerhalb des Scope / nicht geprüft“</strong> enden. Der gezahlte Betrag ist <strong>keine Fundgarantie</strong>; er gilt für den gesamten umfassenden Bewertungsprozess.',
    lowAck: 'Ich möchte fortfahren.',
    summary: 'Bestellübersicht', domainLabel: 'Domain', freqLabel: 'Häufigkeit', startLabelKey: 'Start', contentLabel: 'Inhalt',
    scanCount: (n: number) => `${n} Scans`, total: 'Gesamt', totalRuns: (n: number) => `Gesamt · ${n} Scans`, kdvIncl: 'inkl. MwSt.',
    verifyDomain: 'Domain bestätigen',
    verifyHint: 'Für den aktiven Scan bestätigen Sie zuerst Ihre Domain-Inhaberschaft per DNS — danach können Sie kaufen.',
    scheduledHint: 'Sie können sie über „Geplante Scans“ verwalten.', autoStartHint: 'Nach der Zahlungsbestätigung startet der Scan automatisch.',
    selectPackage: 'Wählen Sie ein Paket, um fortzufahren.',
    freqOneOff: 'Einmalig', freqEvery: (label: string, runs: number) => `${label} · ${runs} Scans`, startImmediate: 'Sofort',
    ctaStarting: 'Wird gestartet…', ctaBuyBundle: 'Paket kaufen', ctaSetupRecurring: 'Regelmäßigen Scan einrichten', ctaSchedule: 'Scan planen', ctaStart: 'Scan starten',
    hintSelectDomain: 'Bestätigen Sie zuerst Ihre Website-Inhaberschaft.', hintSelectModules: 'Wählen Sie den Paketinhalt.',
    hintConsents: 'Kreuzen Sie zum Fortfahren die Zustimmungen unten an →', hintLowScope: 'Lesen und bestätigen Sie den Vorabprüfungs-Hinweis →', hintUnreach: 'Lesen und bestätigen Sie den Zugriffs-Hinweis →', hintChecking: 'Vorabprüfung läuft…',
    payPageErr: 'Zahlungsseite konnte nicht geladen werden. Bitte versuchen Sie es erneut.',
    errSelectPackage: 'Bitte wählen Sie ein Paket.',
    errAllConsents: 'Zum Fortfahren müssen Sie alle Zustimmungen ankreuzen.',
    errActiveNoSchedule: 'Aktiv-Test-Pakete können nicht geplant werden; sie laufen einmalig und sofort.',
    errActiveRisk: 'Für den aktiven Test müssen Sie das Risiko-Kästchen ankreuzen.',
    errFutureDate: 'Für einen späteren Start wählen Sie ein Datum/eine Uhrzeit in der Zukunft.',
    errAuthConsents: 'Sie haben Testkonto-Daten eingegeben — kreuzen Sie für den authentifizierten Test die zusätzlichen Zustimmungen an (Testkonto-Erklärung und Akzeptanz des höheren Risikos). (Oder lassen Sie die Felder leer und fahren Sie ohne Login fort.)',
    errSelectModule: 'Wählen Sie mindestens ein Modul.',
    errLowScopeAck: 'Zum Fortfahren müssen Sie den Vorabprüfungs-Hinweis bestätigen.',
    errUnreachAck: 'Ziel nicht erreichbar — zum Fortfahren müssen Sie den Hinweis bestätigen.',
    trustSSL: '256-Bit-SSL · sichere Zahlung über iyzico', trustCard: 'Kartendaten werden bei iyzico verarbeitet, nicht bei uns gespeichert', trustKvkk: 'DSGVO-konform · Daten werden verschlüsselt gespeichert',
    payAlt: 'Mit iyzico bezahlen',
    noPackage: 'Kein Paket gewählt', mobileVerify: 'Bestätigen',
    cGenStrong: 'Ich habe gelesen und stimme zu:', cGenOwn1: 'Ich bin Inhaber/Berechtigter dieser Domain', cGenOwn2: 'und ihrer Infrastruktur', cGenOwn3: 'und willige ein, dass an diesem Ziel',
    cGenActive: 'ein aktiv-leichter Verifizierungstest', cGenPassive: 'ein passiver', cGenScan: 'Scan', cGenConsent: 'durchgeführt wird;',
    cGenLegalMid: 'sowie die', cGenLegalRead: ' gelesen und akzeptiere sie.',
    cGenActiveRiskHtml: ' Ich akzeptiere, dass dieses Paket aktive Testanfragen mit <strong>höherem Risiko</strong> sendet.',
    cGenAuthHtml: ' Ich erkläre, dass das von mir angegebene Konto <strong>nicht</strong> mein Produktiv-/Hauptkonto ist, sondern ein <strong>TEST-Konto</strong> mit minimalen Rechten und Einmalgebrauch.',
    cCrossStrong: 'KI-Analyse:', cCrossBodyPre: ' In diesem Paket werden meine Scan-Daten', cCrossAuth: ' und die von mir angegebenen ', cCrossAuthStrong: 'Testkonto-Daten', cCrossBodyPost: ' zur Analyse an einen ', cCrossForeign: 'außerhalb der EU ansässigen KI-Dienst', cCrossBodyEnd: ' übermittelt; dem stimme ich ausdrücklich zu.', cCrossAuthNote: ' Meine Daten werden verschlüsselt gespeichert und nach dem Scan gelöscht.',
    cWithStrong: 'Widerrufsrecht:', cWithBodyHtml: ' Ich verlange, dass die Dienstleistung mit meiner Zustimmung <strong>vor Ablauf der Widerrufsfrist unmittelbar beginnt</strong>, und akzeptiere, dass ich dadurch <strong>mein Widerrufsrecht verliere</strong> (§ 356 Abs. 5 BGB).',
    legalOn: 'AGB', legalMesafeli: 'Widerrufsbelehrung', legalIptal: 'Widerruf', legalGizlilik: 'Datenschutzerklärung', legalKvkk: 'Datenschutz',
    legalOnHref: '/de/legal/agb', legalMesafeliHref: '/de/legal/widerruf', legalIptalHref: '/de/legal/widerruf', legalGizlilikHref: '/de/legal/datenschutz', legalKvkkHref: '/de/legal/datenschutz',
    legalSlash: '',
    intlSoonHtml: '',
  },
  en: {
    orderEyebrow: 'ORDER',
    title: 'Start Your Scan', sub: 'Choose a package, tick the consents and proceed to secure payment.',
    noDomainPre: 'First choose a domain to scan.', noDomainLink: 'Choose a domain →',
    dnsVerified: 'Domain verified via DNS — the active scan starts after payment confirmation.',
    activeVerifyTitle: 'This package sends active probes — DNS verification required',
    activeVerifyBodyHtml: 'Without DNS verification of your domain ownership the active scan (injection/session attempts) <strong>will not start</strong> — even after payment the order is held in the <strong>“awaiting domain verification”</strong> status and starts <strong>automatically</strong> once verified.',
    verifyNow: 'Verify via DNS now →',
    passiveNoVerify: 'No verification is required for this package — the scan starts immediately after payment confirmation.',
    step1: '1 · Choose a package', entryBadge: 'Entry',
    basitDesc: 'A quick, low-cost trial scan — intended as a preview (not a comprehensive audit).',
    kdv: 'VAT included', sampleReport: 'View sample report', buy: 'Buy now',
    popular: 'Popular', includes: 'Includes',
    reconItems: [
      'Abandoned subdomain (Subdomain Takeover) scan — subdomain inventory from CT logs',
      'Public API / Swagger documentation discovery',
      'CMS & technology fingerprint analysis',
      'Detection of administrative/sensitive paths from the sitemap',
    ],
    reconNote: 'Passive external-surface reconnaissance; no active endpoint injection or authenticated testing.',
    soon: 'Coming soon', soonClosed: 'Not currently on sale',
    testCredsMembers: 'Test account details',
    avTitle: 'Transparency & Scope — please read before payment',
    avP1Html: 'This package tests your website’s <strong>public (no-login) external attack surface</strong> with harmless probes — injection, authorisation and logic risks across public search, form, API and login/registration flows.',
    avP2Html: 'If your website has <strong>no public search, form, API or ID-based endpoints</strong>, checks listed in the contents such as <strong>IDOR / Business Logic / File Upload / Race</strong> may appear as <strong>“Not assessed”</strong> in the report. This is <strong>not an error</strong> — it is a natural consequence of your site’s external-surface structure (no open entry point to test).',
    avP3Html: 'For deep authorisation/business-logic testing <strong>after</strong> login, choose the <strong>Full-Scope Pentest</strong> package.',
    fpReviewHtml: '<strong class="text-ink">Review process:</strong> For security reasons this package starts <strong>immediately after payment confirmation</strong> once ordered.',
    fpAccountHtml: '<strong class="text-ink">Test account:</strong> For authenticated testing you must provide a <strong>TEST account</strong> (NOT your main/production account; without 2FA, minimal privileges, single-use). Your credentials are stored <strong>encrypted/temporarily</strong> and deleted after the scan.',
    fpMethodHtml: '<strong class="text-ink">Method:</strong> After login, cookie/session/authorisation, authenticated injection and IDOR, privilege escalation and multi-step business-logic indicators are examined with <strong>deterministic security checks</strong>. Real data/account changes and payment completion are <strong>blocked at code level</strong> — this is not an autonomous/unrestricted pentest.',
    fpAiHtml: '<strong class="text-ink">Optional AI layer:</strong> Two checks (privilege escalation + multi-step business logic) have an optional, lightweight <strong>AI advisory layer</strong>; it is <strong>disabled by default</strong> and only engages when enabled and it finds an additional, verifiable indicator. When disabled, results are produced with <strong>fully deterministic authenticated checks</strong> — this is normal and expected, and the report shows it transparently.',
    fpScopeHtml: '<strong class="text-ink">Scope:</strong> <strong>Cross-account</strong> IDOR (accessing another user’s data) is out of scope in this version.',
    step2: '2 · Consents', needConsents: (n: number) => `Tick the following ${n} consents to continue.`,
    contractShow: 'View the Distance Sales Agreement for this order', contractHide: 'Hide the agreement for this order',
    step3: '3 · Repeat', oneOff: 'One-off scan', repeat: 'Repeat regularly',
    frequency: 'Frequency', weekly: 'Weekly', biweekly: 'Every two weeks', monthly: 'Monthly',
    howManyRuns: 'How many scans (prepaid)',
    recurringNote: (runs: number) => `You pay in advance for ${runs} scans; the first runs immediately, the rest at your chosen frequency. (Minimum frequency: weekly.)`,
    step4: '4 · Start', firstScan: '(first scan)', startNow: 'Start immediately', startLater: 'Start on a specific date',
    startDateTime: 'Start date and time',
    startLaterNote: 'The scan starts on the control cycle nearest to your chosen time (within a few minutes).',
    atTitle: 'Active Test Authorisation (required)',
    atBody: 'This package sends limited active test requests to confirm vulnerabilities. To continue you must read the scope and complete the declaration.',
    atDoes: 'What this scan DOES', atDoesNot: 'What this scan does NOT do',
    atConsentNote: 'Your consent is logged automatically together with your account, timestamp, IP and the text version (no extra details needed). On request it is attached to your order as an authorisation PDF.',
    acTitle: 'Test account details', acOptional: '(optional)',
    acInfoHtml: 'This field is <strong>optional</strong>. If your website has <strong>no login mechanism</strong>, leave it blank — the scan runs <strong>without login (unauthenticated)</strong>. If there is a login, you can enter a <strong>TEST account</strong> for in-session checks.',
    acWarnTitle: 'Enter a TEST account only — NOT your main/production account',
    acWarnBodyHtml: 'Use an account created for this scan with <strong>minimal privileges and single use</strong>; change its password after the scan.',
    acWarn2Html: 'Provide an account <strong>without 2FA</strong>. Your credentials are stored <strong>encrypted</strong> and <strong>deleted</strong> after the scan.',
    acUser: 'Username / email', acPass: 'Password', acPassPh: 'Test account password',
    acCheckBtn: 'Verify test login (optional)', acChecking: 'Attempting login…',
    acCheckingHint: 'Searching for and trying the login form — this may take a few seconds…',
    acNoCredsHtml: 'You have not entered any test account details — the scan will run <strong>without login (unauthenticated)</strong>. If your website has no login, this is normal.',
    lcOk: 'Login with the test account verified.',
    lcBad: 'Could not log in with this username/password — please check the details.',
    lc2fa: 'The account appears to have 2FA — please provide a test account without 2FA.',
    lcNoForm: 'No automatic login form found — you can still continue (the scan will try more thoroughly).',
    lcTimeout: 'Verification took too long — you can still continue (the real scan will try more thoroughly).',
    lcOther: 'Login could not be verified at the moment — you can still continue.',
    promoLabel: 'Promo code (optional)', promoPh: 'Your code', apply: 'Apply', promoCheckFail: 'Could not check the code.',
    promoAppliedPre: 'Code applied — discount', promoNewTotal: 'New total:', promoFree: ' — the payment step is skipped and the scan is queued immediately.',
    queueBusyHtml: 'You can place your order — <strong>your scan will start as soon as possible</strong> and you can track its status from this panel.',
    checking: 'Pre-checking whether your target is reachable…',
    unreachTitle: 'Your target is currently unreachable from outside',
    unreachP1Html: 'Your website’s main address (<strong>443/HTTPS and 80/HTTP</strong>) is not responding at the moment. This is not an error — it means your website is <strong>offline, closed, or blocking our access</strong>. If the scan starts now it will find no externally testable surface, so the report will most likely come back <strong>empty / “Not assessed”</strong>.',
    unreachP2Html: '<strong>Our recommendation:</strong> make sure your website is online and reachable, then refresh this page and try again. If you believe the issue is temporary you can still continue.',
    unreachAck: 'I understand the access issue; I want to start now anyway.',
    lowTitle: 'Important Pre-check',
    lowP1Html: 'The automatic quick scan found <strong>almost no testable entry point</strong> (form, query parameter, endpoint with a numeric ID) on your website. This is usually because the site has a <strong>JavaScript-rendered (SPA)</strong> structure.',
    lowP2Html: 'The scan will still run, but many checks may end up as <strong>“out of scope / not assessed”</strong>. The amount paid is <strong>not a guarantee of findings</strong>; it covers the entire comprehensive assessment process.',
    lowAck: 'I want to continue.',
    summary: 'Order Summary', domainLabel: 'Domain', freqLabel: 'Frequency', startLabelKey: 'Start', contentLabel: 'Contents',
    scanCount: (n: number) => `${n} scans`, total: 'Total', totalRuns: (n: number) => `Total · ${n} scans`, kdvIncl: 'VAT included',
    verifyDomain: 'Verify domain',
    verifyHint: 'For the active scan, first verify your domain ownership via DNS — you can purchase once verified.',
    scheduledHint: 'You can manage these from the Scheduled scans screen.', autoStartHint: 'The scan starts automatically after payment confirmation.',
    selectPackage: 'Choose a package to continue.',
    freqOneOff: 'One-off', freqEvery: (label: string, runs: number) => `${label} · ${runs} scans`, startImmediate: 'Immediately',
    ctaStarting: 'Starting…', ctaBuyBundle: 'Buy package', ctaSetupRecurring: 'Set up regular scan', ctaSchedule: 'Schedule scan', ctaStart: 'Start scan',
    hintSelectDomain: 'First verify your website ownership.', hintSelectModules: 'Choose the package contents.',
    hintConsents: 'Tick the consents below to continue →', hintLowScope: 'Read and acknowledge the pre-check notice →', hintUnreach: 'Read and acknowledge the access notice →', hintChecking: 'Pre-check in progress…',
    payPageErr: 'Payment page could not be loaded. Please try again.',
    errSelectPackage: 'Please choose a package.',
    errAllConsents: 'You must tick all consents to continue.',
    errActiveNoSchedule: 'Active-test packages cannot be scheduled; they run one-off and immediately.',
    errActiveRisk: 'For the active test you must tick the risk acceptance box.',
    errFutureDate: 'For a later start, choose a date/time in the future.',
    errAuthConsents: 'You entered test account details — tick the additional consents for authenticated testing (test-account declaration and acceptance of the higher risk). (Or leave the fields blank and continue without login.)',
    errSelectModule: 'Choose at least one module.',
    errLowScopeAck: 'To continue you must acknowledge the pre-check notice.',
    errUnreachAck: 'Target unreachable — to continue you must acknowledge the notice.',
    trustSSL: '256-bit SSL · secure payment via iyzico', trustCard: 'Card details are processed at iyzico, not stored by us', trustKvkk: 'GDPR-compliant · data stored encrypted',
    payAlt: 'Pay with iyzico',
    noPackage: 'No package selected', mobileVerify: 'Verify',
    cGenStrong: 'I have read and agree:', cGenOwn1: 'I am the owner/authorised person of this domain', cGenOwn2: 'and its infrastructure', cGenOwn3: 'and I consent to',
    cGenActive: 'an active-light verification test', cGenPassive: 'a passive', cGenScan: 'scan', cGenConsent: 'being carried out on this target;',
    cGenLegalMid: 'as well as the', cGenLegalRead: ' and I accept them.',
    cGenActiveRiskHtml: ' I accept that this package sends active test requests carrying <strong>higher risk</strong>.',
    cGenAuthHtml: ' I declare that the account I provide is <strong>not</strong> my production/main account, but a single-use <strong>TEST account</strong> with minimal privileges.',
    cCrossStrong: 'AI analysis:', cCrossBodyPre: ' In this package my scan data', cCrossAuth: ' and the ', cCrossAuthStrong: 'test account details', cCrossBodyPost: ' I provide are transferred for analysis to ', cCrossForeign: 'an AI service based outside the UK', cCrossBodyEnd: '; I expressly consent to this.', cCrossAuthNote: ' My details are stored encrypted and deleted after the scan.',
    cWithStrong: 'Cancellation rights:', cWithBodyHtml: ' I request that the service <strong>begins immediately</strong>, and I acknowledge that I will <strong>lose my right to cancel</strong> under the Consumer Contracts (Information, Cancellation and Additional Charges) Regulations 2013 once the service has been fully performed.',
    legalOn: 'Terms & Conditions', legalMesafeli: 'Cancellation Rights', legalIptal: 'Cancellation Rights', legalGizlilik: 'Privacy Policy', legalKvkk: 'Privacy Policy',
    legalOnHref: '/en/legal/terms', legalMesafeliHref: '/en/legal/cancellation', legalIptalHref: '/en/legal/cancellation', legalGizlilikHref: '/en/legal/privacy', legalKvkkHref: '/en/legal/privacy',
    legalSlash: '',
    intlSoonHtml: '',
  },
} as const;

export default function OrderPage() {
  const router = useRouter();
  const sp = useSearchParams();
  const domainId = sp.get('domainId');
  // Paketler sayfasindan "Satin Al" ile tasinan on-secim (paket veya bundle).
  const preselectPackage = sp.get('package');
  const preselectBundle = sp.get('bundle');
  const [packages, setPackages] = useState<Pkg[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  // Kombine paket (bundle) modu — bir bundle secilince tekil akis (recurring/promo) gizlenir.
  const [bundles, setBundles] = useState<any[]>([]);
  const [selectedBundle, setSelectedBundle] = useState<any | null>(null);
  const [bundleModules, setBundleModules] = useState<string[]>([]);
  // Tekil paket kategori akordeonlari (paketler sayfasiyla ayni duzen) — varsayilan KAPALI.
  const [region, setRegion] = useState<RegionCode>('tr');
  // Sipariş özetinde hangi alan adının taranacağını AÇIKÇA göster (domainId'den çözülür).
  const [hostname, setHostname] = useState<string | null>(null);
  // Seçili alan adı DNS ile doğrulanmış mı (AKTİF paket çelik kapısı için UI göstergesi).
  const [domainVerified, setDomainVerified] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Promosyon kodu (checkout onizleme + siparise gecirme).
  const [promoInput, setPromoInput] = useState('');
  const [promo, setPromo] = useState<{ valid: boolean; error?: string; code?: string; discountMinorUnit?: number; finalAmountMinorUnit?: number } | null>(null);
  const [promoBusy, setPromoBusy] = useState(false);
  // Aktif basit_tarama promo kodu (kampanya bloğu — yalnız Basit Tarama seçiliyken gösterilir).
  const [activePromo, setActivePromo] = useState<{ code: string } | null>(null);
  useEffect(() => { api.activeBasitPromo().then((r) => setActivePromo(r.promo)).catch(() => setActivePromo(null)); }, []);

  // (Faz 3 v2) active-light — tek risk-kabul checkbox'i (ek alan yok).
  const [atRisk, setAtRisk] = useState(false);
  // (Aktif Doğrulama Paketi) ödeme-öncesi düşük-kapsam ön-kontrolü.
  const [scopeLow, setScopeLow] = useState<boolean | null>(null); // null=henüz kontrol edilmedi
  const [scopeChecking, setScopeChecking] = useState(false); // ön-kontrol devam ediyor (SPA'da headless render ~birkaç sn)
  const [lowScopeAck, setLowScopeAck] = useState(false);
  // (TÜM paketler) ödeme-öncesi ERİŞİLEBİLİRLİK ön-kontrolü: hedef 443/80 yanıt vermiyorsa tarama
  // "İncelenemedi" (boş) sonuç verir; müşteri ödemeden önce uyarılmalı (yine de devam edebilir).
  const [reachable, setReachable] = useState<boolean | null>(null); // null=bilinmiyor/kontrol edilmedi
  const [unreachableAck, setUnreachableAck] = useState(false);
  // (#5) authenticated_scan — test hesabi kimlik bilgileri.
  const [authUser, setAuthUser] = useState('');
  const [authPass, setAuthPass] = useState('');
  // (ÖDEME ÖNCESİ TEST GİRİŞİ) tek buton + tek satır sonuç — BLOKLAMAZ, sadece bilgilendirir.
  const [loginCheck, setLoginCheck] = useState<'idle' | 'checking' | 'ok' | 'fail'>('idle');
  const [loginCheckMsg, setLoginCheckMsg] = useState<string>('');
  // (Tam Kapsamlı Pentest — FAZ A) kimlik-doğrulamalı/otonom paketlerde 3 EK onay.
  const [credShare, setCredShare] = useState(false);
  const [testAcct, setTestAcct] = useState(false);
  const [elevRisk, setElevRisk] = useState(false);
  // authConsentsOk aşağıda (selUsesForeignAi tanımlandıktan SONRA) hesaplanır — credShare (kimlik
  // bilgisi yurt dışı AI aktarımı rızası) YALNIZ yurt dışı AI kullanılıyorsa zorunludur.

  // Sahiplik beyani (TCK 243 — guvenlik) ayri; iyzico'nun bekledigi 2 ODEME-onay
  // checkbox'i: (1) On Bilgilendirme+Mesafeli+Iptal/Iade, (2) KVKK/Gizlilik.
  const [authConsent, setAuthConsent] = useState(false);
  const [contractConsent, setContractConsent] = useState(false); // On Bilgi + Mesafeli + Iptal/Iade
  const [withdrawalConsent, setWithdrawalConsent] = useState(false); // AYRI: cayma hakki feragati
  const [crossBorderConsent, setCrossBorderConsent] = useState(false); // AYRI: KVKK m.9 yurt disi acik riza
  const [kvkkConsent, setKvkkConsent] = useState(false); // Gizlilik + KVKK Aydinlatma
  const [showContract, setShowContract] = useState(false);

  // Düzenli (periyodik) tarama seçeneği
  const [recurring, setRecurring] = useState(false);
  const [intervalDays, setIntervalDays] = useState(7); // haftalık
  const [runs, setRuns] = useState(4);

  // Başlangıç zamanı: hemen mi, ileri tarih mi
  const [startMode, setStartMode] = useState<'now' | 'later'>('now');
  const [startAt, setStartAt] = useState(''); // datetime-local değeri

  // (#4) Kuyruk yogunlugu — esik asilmissa nazik uyari (engelleme YOK).
  const [queue, setQueue] = useState<{ busy: boolean; etaMinutes: number; queuedCount: number } | null>(null);

  useEffect(() => {
    if (typeof window !== 'undefined' && !window.localStorage.getItem('token')) {
      router.push('/login');
      return;
    }
    const rc = readRegionCookie();
    setRegion(rc);
    api.listPackages(rc).then((pk) => {
      setPackages(pk);
      // "Satin Al" ile gelen tekil paketi ON-SEC (kullanici tekrar secmesin). "Yakında" ise ETME.
      const pre = pk.find((p) => p.key === preselectPackage);
      if (pre && !pre.comingSoon && pre.key !== 'basit_tarama') {
        setSelected(preselectPackage);
        setSelectedBundle(null);
      }
    }).catch((err) => setError(err.message));
    api.listBundles(rc).then((bs) => {
      setBundles(bs);
      // "Satin Al" ile gelen bundle'i ON-SEC. "Yakında" ise ETME.
      if (preselectBundle) {
        const b = bs.find((x: any) => x.key === preselectBundle);
        if (b && !b.comingSoon) { setSelectedBundle(b); setSelected(null); }
      }
    }).catch(() => {});
    api.getQueueStatus().then(setQueue).catch(() => {}); // sessiz — uyari opsiyonel
    // Doğrulanmış domain listesinden domainId'nin hostname'ini çöz (özet + mobil çubukta göster).
    if (domainId) {
      api.listDomains()
        .then((ds) => { const d = ds.find((x) => x.id === domainId); if (d) { setHostname(d.hostname); setDomainVerified(d.valid); } })
        .catch(() => {});
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [router]);

  // Ödeme öncesi hızlı ön-kontrol. ERİŞİLEBİLİRLİK (reachable) TÜM paketler için kontrol edilir —
  // hedef 443/80 yanıt vermiyorsa tarama "İncelenemedi" (boş) sonuç verir, müşteri önceden uyarılır.
  // DÜŞÜK KAPSAM (lowSignal) yalnız Aktif Doğrulama için anlamlıdır (giriş noktası bulmaya dayalı).
  useEffect(() => {
    setLowScopeAck(false);
    setScopeLow(null);
    setReachable(null);
    setUnreachableAck(false);
    setScopeChecking(false);
    if (!domainId || !(selected || selectedBundle)) return; // domain + herhangi bir paket seçili
    let cancelled = false;
    setScopeChecking(true);
    api.scopeEstimate(domainId)
      .then((r) => {
        if (cancelled) return;
        setReachable(r.reachable);
        setScopeLow(selectedBundle?.key === 'bundle_active_verify' ? r.lowSignal : false);
      })
      .catch(() => { if (!cancelled) { setReachable(null); setScopeLow(false); } }) // hata -> engelleme yok
      .finally(() => { if (!cancelled) setScopeChecking(false); });
    return () => { cancelled = true; };
  }, [domainId, selected, selectedBundle?.key]);

  // (Çok-bölge) Dil: region cookie'sinden. de → Almanca metin + Alman legal linkleri (Widerruf dahil).
  const deLang = getRegion(region).lang === 'de';
  const enLang = getRegion(region).lang === 'en';
  const L = ORD[deLang ? 'de' : enLang ? 'en' : 'tr'];
  const selectedPkg = packages.find((p) => p.key === selected);
  // SATIS MODELI: tekil kontrol satisi YOK — secilebilir TEK "tekil" paket basit_tarama (giris).
  const basitPkg = packages.find((p) => p.key === 'basit_tarama');
  const isActiveLight = selectedPkg?.securityProfile === 'active-light';
  // (#4) Uluslararasi odeme (Paddle) henuz canli degil — TR disi bolgede nazik "yakinda".
  // /de artık gerçek iyzico+EUR ödemesiyle satın alınabilir → intlComingSoon'a DAHİL DEĞİL.
  // Yalnız us/ae (Paddle canlı değil) "yakında" olur.
  const intlComingSoon = region !== 'tr' && region !== 'de' && region !== 'en';
  const needsAuthCreds = selected === 'authenticated_scan';

  // (İŞ 3) Onay GRUPLAMA — UI'da ≤3 checkbox. Sunucu-tarafı zorunluluk DEĞİŞMEZ: her grup, altındaki
  // TÜM bireysel onay state'lerini birlikte set eder (ownership/contract/kvkk/atRisk/testAcct/elevRisk/
  // crossBorder/credShare/withdrawal). En hassas iki AÇIK RIZA (KVKK m.9 yurt dışı + cayma feragati)
  // hukuken AYRI checkbox olarak kalır; kalanlar tek "genel kabul" altında gruplanır.
  const isActiveLightSel = isActiveLight || selectedBundle?.category === 'active-light';
  const needsAuthSel = needsAuthCreds || !!selectedBundle?.members?.some((m: any) => m.key === 'authenticated_scan');
  // (LOGİNSİZ TEST) Test hesabı bilgileri artık OPSİYONEL — sitede login mekanizması olmayabilir. Bilgi
  // girilmişse kimlik-doğrulamalı, boşsa loginsiz (kimlik-doğrulamasız) tarama yapılır. hasCreds bunu ayırır:
  // creds varsa test-hesabı onayları/kimlik gönderimi devreye girer, yoksa hiçbiri zorunlu değildir.
  const hasCreds = !!(authUser.trim() && authPass);
  // (KVKK m.9) Seçili paket/bundle yurt dışı AI'ya veri gönderiyor mu? Sadece o zaman m.9 açık rıza gerekir.
  const selUsesForeignAi = !!(selectedBundle ? selectedBundle.crossBorderAi : selectedPkg?.crossBorderAi);
  // (BUG FIX) Kimlik-doğrulamalı testte 2 zorunlu beyan: TEST hesabı + yüksek-risk. credShare (kimlik
  // bilgisi YURT DIŞI AI aktarımı rızası) yalnız yurt dışı AI KULLANILIYORSA gerekir — advisory kapalıyken
  // o kutu hiç gösterilmez, dolayısıyla credShare hiç set edilemez; onu zorunlu tutmak butonu kilitliyordu.
  const authConsentsOk = testAcct && elevRisk && (!selUsesForeignAi || credShare);
  const activeConsentOk = (!isActiveLight || atRisk) && (!needsAuthCreds || !hasCreds || authConsentsOk);
  const allConsents =
    authConsent && contractConsent && withdrawalConsent && kvkkConsent && (!selUsesForeignAi || crossBorderConsent);
  // Grup 1 — Genel kabul (ownership + mesafeli/ön-bilgi + KVKK aydınlatma + [aktif-test riski] + [test hesabı beyanı]).
  const groupGeneralChecked =
    authConsent && contractConsent && kvkkConsent && (!isActiveLightSel || atRisk) && (!needsAuthSel || !hasCreds || (testAcct && elevRisk));
  const setGroupGeneral = (v: boolean) => {
    setAuthConsent(v); setContractConsent(v); setKvkkConsent(v);
    if (isActiveLightSel) setAtRisk(v);
    if (needsAuthSel) { setTestAcct(v); setElevRisk(v); }
  };
  // Grup 2 — AYRI: KVKK m.9 yurt dışı açık rıza. YALNIZ yurt dışı AI kullanan pakette gösterilir/
  // zorunludur; deterministik paketlerde veri yurt dışına gitmediği için gerekmez (otomatik geçer).
  const groupCrossBorderChecked = !selUsesForeignAi || (crossBorderConsent && (!needsAuthSel || !hasCreds || credShare));
  const setGroupCrossBorder = (v: boolean) => { setCrossBorderConsent(v); if (needsAuthSel) setCredShare(v); };
  // Grup 3 — AYRI: mesafeli satış cayma hakkı feragati (withdrawalConsent) — doğrudan.
  // (Aktif Doğrulama Paketi) düşük-kapsam uyarısı gösterilecek mi (ön-kontrol düşük sinyal döndüyse).
  const showLowScopeWarning = selectedBundle?.key === 'bundle_active_verify' && scopeLow === true;
  // (TÜM paketler) hedef ödeme öncesi ön-kontrolde erişilemiyorsa uyar (tarama boş/"İncelenemedi" verir).
  const showUnreachableWarning = reachable === false;

  async function applyPromo() {
    if (!promoInput.trim() || (!selected && !selectedBundle)) return;
    setPromoBusy(true);
    try {
      const target = selectedBundle ? { bundleKey: selectedBundle.key } : { packageKey: selected! };
      const r = await api.previewPromo(promoInput.trim(), target, region);
      setPromo(r);
    } catch {
      setPromo({ valid: false, error: L.promoCheckFail });
    } finally {
      setPromoBusy(false);
    }
  }

  async function handleStart() {
    if (!domainId || busy) return;
    if (!selected) return setError(L.errSelectPackage);
    if (!allConsents) return setError(L.errAllConsents);
    if (isActiveLight && (recurring || startMode === 'later')) return setError(L.errActiveNoSchedule);
    if (!activeConsentOk) return setError(L.errActiveRisk);
    // İleri tarih seçildiyse geçerli ve gelecekte olmalı.
    let startAtIso: string | undefined;
    if (startMode === 'later') {
      const t = new Date(startAt);
      if (!startAt || Number.isNaN(t.getTime()) || t.getTime() <= Date.now()) {
        return setError(L.errFutureDate);
      }
      startAtIso = t.toISOString();
    }
    setBusy(true);
    setError(null);
    try {
      // Düzenli tarama VEYA ileri tarihli tek atış → zamanlama motoruna gider
      // (aynı concurrency=1 kuyruğu, doğrulama tazeliği kontrolü, prepaid-N).
      if (recurring || startMode === 'later') {
        await api.createSchedule({
          domainId,
          packageKey: selected,
          intervalDays: recurring ? intervalDays : 7, // tek atışta yok sayılır (runs=1)
          runs: recurring ? runs : 1,
          startAt: startAtIso,
          region,
        });
        // (GA4 huni) Zamanlanmış/ileri-tarihli tarama oluşturuldu = aktivasyon (scan_start).
        trackEvent('scan_start', { region, package: selected, mode: recurring ? 'recurring' : 'scheduled' });
        router.push('/schedules');
        return;
      }
      const res = await api.createOrder(
        domainId,
        selected,
        {
          ownershipConfirmed: authConsent,
          distanceContractAccepted: contractConsent,
          withdrawalWaived: withdrawalConsent, // AYRI cayma feragati checkbox'i
          crossBorderTransfer: crossBorderConsent, // KVKK m.9 yurt disi acik riza checkbox'i
        },
        region,
        isActiveLight ? { riskAccepted: atRisk, ...(needsAuthCreds && hasCreds ? { credentialSharingAccepted: credShare, testAccountDeclared: testAcct, elevatedRiskAccepted: elevRisk } : {}) } : undefined,
        needsAuthCreds && hasCreds ? { username: authUser.trim(), password: authPass } : undefined, // loginsizse gönderilmez
        promo?.valid ? promo.code : undefined,
      );
      // (GA4 huni) Sipariş oluşturuldu = tarama aktivasyonu (ücretsiz promo dahil; tek submit → tek sefer, PII yok).
      trackEvent('scan_start', { region, package: selected });
      // %100 promo ile odendiyse odeme sayfasi YOK — dogrudan siparis detayina git.
      if (res.paidWithPromo) {
        router.push(`/dashboard/${res.orderId}`);
        return;
      }
      // (GA4 huni) Ödeme sayfasına yönlendiriliyor = begin_checkout (satışa en yakın sinyal). Değer bölge para birimiyle.
      trackEvent('begin_checkout', {
        value: unitAmountMinor / 100,
        currency: selectedPkg?.currency ?? currencyForRegion(region),
        items: [{ item_name: selected }],
      });
      window.location.href = res.paymentPageUrl!;
    } catch (err: any) {
      // (0) E-posta dogrulanmamis -> satin alma engellendi (409). Dogrulama ekranina yonlendir.
      if (err?.emailUnverified) {
        router.push(`/verify-email?next=${encodeURIComponent(window.location.pathname + window.location.search)}`);
        return;
      }
      setError(err.message);
      setBusy(false);
    }
  }

  async function handleBundleStart() {
    if (!domainId || busy || !selectedBundle) return;
    if (!allConsents) return setError(L.errAllConsents);
    const isAL = selectedBundle.category === 'active-light';
    if (isAL && !atRisk) return setError(L.errActiveRisk);
    const needsAuth = selectedBundle.members?.some((m: any) => m.key === 'authenticated_scan');
    // (LOGİNSİZ TEST) creds opsiyonel: boşsa loginsiz devam. Girildiyse ek onaylar gerekir.
    if (needsAuth && hasCreds && !authConsentsOk) return setError(L.errAuthConsents);
    if (selectedBundle.selectable && bundleModules.length === 0) return setError(L.errSelectModule);
    if (showLowScopeWarning && !lowScopeAck) return setError(L.errLowScopeAck);
    if (showUnreachableWarning && !unreachableAck) return setError(L.errUnreachAck);
    setBusy(true);
    setError(null);
    try {
      const res = await api.createBundleOrder({
        domainId,
        bundleKey: selectedBundle.key,
        selectedModules: selectedBundle.selectable ? bundleModules : undefined,
        ownershipConfirmed: authConsent,
        distanceContractAccepted: contractConsent,
        withdrawalWaived: withdrawalConsent, // AYRI cayma feragati
        crossBorderTransfer: crossBorderConsent, // KVKK m.9 yurt disi acik riza
        region,
        activeTestConsent: isAL ? { riskAccepted: atRisk, ...(needsAuth && hasCreds ? { credentialSharingAccepted: credShare, testAccountDeclared: testAcct, elevatedRiskAccepted: elevRisk } : {}) } : undefined,
        authCredentials: needsAuth && hasCreds ? { username: authUser.trim(), password: authPass } : undefined, // loginsizse gönderilmez
        promoCode: promo?.valid ? promo.code : undefined,
        lowScopeAcknowledged: showLowScopeWarning ? lowScopeAck : undefined,
      });
      // (GA4 huni) Bundle siparişi oluşturuldu = tarama aktivasyonu (scan_start; ücretsiz promo dahil, PII yok).
      trackEvent('scan_start', { region, package: selectedBundle.key });
      // (GA4 huni) Ödeme akışına giriliyorsa (promo değilse) begin_checkout — bundle toplamı, bölge para birimi.
      if (!res.paidWithPromo) {
        trackEvent('begin_checkout', {
          value: (res.bundleTotalMinorUnit ?? selectedBundle.amountMinorUnit ?? 0) / 100,
          currency: res.currency ?? currencyForRegion(region),
          items: [{ item_name: selectedBundle.key }],
        });
      }
      // %100 promo -> odeme YOK, dogrudan siparis paneli. Aksi halde: TR'de backend TEK gercek
      // iyzico CheckoutForm baslatir (paymentPageUrl) -> oraya yonlendir (tekil akisla ayni).
      // paymentPageUrl yoksa (TR disi placeholder) eski /pay bundle ekranina dus.
      if (res.paidWithPromo) {
        router.push(`/dashboard/${res.orderIds[0]}`);
      } else if (res.paymentPageUrl) {
        window.location.href = res.paymentPageUrl;
      } else {
        router.push(`/pay/${res.orderIds[0]}?bundle=${res.orderIds.join(',')}`);
      }
    } catch (err: any) {
      // (0) E-posta dogrulanmamis -> satin alma engellendi (409). Dogrulama ekranina yonlendir.
      if (err?.emailUnverified) {
        router.push(`/verify-email?next=${encodeURIComponent(window.location.pathname + window.location.search)}`);
        return;
      }
      setError(err.message);
      setBusy(false);
    }
  }

  // (İŞ 3) 3 GRUPLU onay — her label birden fazla bireysel state'i birlikte set eder (sunucu payload'ı
  // AYNEN korunur). Grup 1 = genel kabul; Grup 2/3 = hukuken AYRI açık rızalar (KVKK m.9 + cayma feragati).
  const consentGroups: Array<{ checked: boolean; set: (v: boolean) => void; node: React.ReactNode }> = [
    {
      checked: groupGeneralChecked,
      set: setGroupGeneral,
      node: deLang ? (
        <>
          <strong>Ich habe gelesen und stimme zu:</strong> Ich bin Inhaber/Berechtigter dieser Domain <strong>und ihrer Infrastruktur</strong> und
          willige ein, dass an diesem Ziel {isActiveLightSel ? <>ein <strong>aktiv-leichter Verifizierungstest</strong></> : <>ein <strong>passiver</strong> Scan</>} durchgeführt wird;
          ich habe die{' '}
          <Link href="/de/legal/agb" target="_blank" className="font-semibold text-accent-600 underline">AGB</Link>, die{' '}
          <Link href="/de/legal/widerruf" target="_blank" className="font-semibold text-accent-600 underline">Widerrufsbelehrung</Link>{' '}
          sowie die{' '}
          <Link href="/de/legal/datenschutz" target="_blank" className="font-semibold text-accent-600 underline">Datenschutzerklärung</Link>{' '}
          gelesen und akzeptiere sie.
          {isActiveLightSel && <> Ich akzeptiere, dass dieses Paket aktive Testanfragen mit <strong>höherem Risiko</strong> sendet.</>}
          {needsAuthSel && <> Ich erkläre, dass das von mir angegebene Konto <strong>nicht</strong> mein Produktiv-/Hauptkonto ist, sondern ein <strong>TEST-Konto</strong> mit minimalen Rechten und Einmalgebrauch.</>}
        </>
      ) : enLang ? (
        <>
          <strong>I have read and agree:</strong> I am the owner/authorised person of this domain <strong>and its infrastructure</strong> and
          I consent to {isActiveLightSel ? <>an <strong>active-light verification test</strong></> : <>a <strong>passive</strong> scan</>} being carried out on this target;
          I have read the{' '}
          <Link href="/en/legal/terms" target="_blank" className="font-semibold text-accent-600 underline">Terms &amp; Conditions</Link>, the{' '}
          <Link href="/en/legal/cancellation" target="_blank" className="font-semibold text-accent-600 underline">Cancellation Rights</Link>{' '}
          as well as the{' '}
          <Link href="/en/legal/privacy" target="_blank" className="font-semibold text-accent-600 underline">Privacy Policy</Link>{' '}
          and I accept them.
          {isActiveLightSel && <> I accept that this package sends active test requests carrying <strong>higher risk</strong>.</>}
          {needsAuthSel && <> I declare that the account I provide is <strong>not</strong> my production/main account, but a single-use <strong>TEST account</strong> with minimal privileges.</>}
        </>
      ) : (
        <>
          <strong>Okudum, onaylıyorum:</strong> Bu alan adının <strong>ve altyapısının</strong> sahibi/yetkilisiyim ve
          bu hedefe {isActiveLightSel ? <>bir <strong>aktif-hafif doğrulama testi</strong></> : <><strong>pasif</strong> tarama</>} yapılmasına
          rıza gösteriyorum;{' '}
          <Link href="/legal/on-bilgilendirme" target="_blank" className="font-semibold text-accent-600 underline">Ön Bilgilendirme</Link>,{' '}
          <Link href="/legal/mesafeli-satis" target="_blank" className="font-semibold text-accent-600 underline">Mesafeli Satış</Link>,{' '}
          <Link href="/legal/iptal-iade" target="_blank" className="font-semibold text-accent-600 underline">İptal/İade</Link>{' '}
          koşullarını ve{' '}
          <Link href="/legal/gizlilik" target="_blank" className="font-semibold text-accent-600 underline">Gizlilik Politikası</Link> /{' '}
          <Link href="/legal/kvkk-aydinlatma" target="_blank" className="font-semibold text-accent-600 underline">KVKK Aydınlatma Metni</Link>’ni
          okudum, kabul ediyorum.
          {isActiveLightSel && <> Bu paketin <strong>daha yüksek risk</strong> taşıyan aktif test istekleri gönderdiğini kabul ediyorum.</>}
          {needsAuthSel && <> Vereceğim hesabın üretim/ana hesabım <strong>olmadığını</strong>, sınırlı yetkili tek-kullanımlık bir <strong>TEST hesabı</strong> olduğunu beyan ederim.</>}
        </>
      ),
    },
    // AYRI (hukuken): yurt dışı AI açık rızası — YALNIZ yurt dışı AI kullanan pakette gösterilir
    // (deterministik paketlerde veri yurt dışına gitmediği için bu kutu hiç çıkmaz).
    ...(selUsesForeignAi
      ? [{
          checked: groupCrossBorderChecked,
          set: setGroupCrossBorder,
          node: deLang ? (
            <>
              <strong>KI-Analyse:</strong> In diesem Paket werden meine Scan-Daten{needsAuthSel && <> und die von mir angegebenen <strong>Testkonto-Daten</strong></>} zur Analyse an einen <strong>außerhalb der EU ansässigen KI-Dienst</strong> übermittelt; dem stimme ich ausdrücklich zu.{needsAuthSel && ' Meine Daten werden verschlüsselt gespeichert und nach dem Scan gelöscht.'}
            </>
          ) : enLang ? (
            <>
              <strong>AI analysis:</strong> In this package my scan data{needsAuthSel && <> and the <strong>test account details</strong> I provide</>} are transferred for analysis to <strong>an AI service based outside the UK</strong>; I expressly consent to this.{needsAuthSel && ' My details are stored encrypted and deleted after the scan.'}
            </>
          ) : (
            <>
              <strong>Yapay zekâ analizi:</strong> Bu pakette tarama verilerim{needsAuthSel && <> ve verdiğim <strong>test hesabı bilgilerim</strong></>}, analiz için <strong>yurt dışında yerleşik bir yapay zekâ hizmetine</strong> aktarılır; buna açıkça rıza gösteriyorum.{needsAuthSel && ' Bilgilerim şifreli saklanır ve tarama sonrası silinir.'}
            </>
          ),
        }]
      : []),
    {
      // AYRI (hukuken): mesafeli satış cayma hakkı feragati (Mesafeli Sözleşmeler Yön. m.15/ğ).
      // (/de) AB dijital-hizmet cayma feragati — §356 Abs. 5 BGB.
      checked: withdrawalConsent,
      set: setWithdrawalConsent,
      node: deLang ? (
        <>
          <strong>Widerrufsrecht:</strong> Ich verlange, dass die Dienstleistung mit meiner Zustimmung <strong>vor Ablauf der
          Widerrufsfrist unmittelbar beginnt</strong>, und akzeptiere, dass ich dadurch <strong>mein Widerrufsrecht verliere</strong> (§ 356 Abs. 5 BGB).
        </>
      ) : enLang ? (
        <>
          <strong>Cancellation rights:</strong> I request that the service <strong>begins immediately</strong>, and I acknowledge that I will
          <strong> lose my right to cancel</strong> under the Consumer Contracts (Information, Cancellation and Additional Charges) Regulations 2013 once the service has been fully performed.
        </>
      ) : (
        <>
          <strong>Cayma hakkı:</strong> Hizmetin cayma süresi dolmadan <strong>onayımla derhal başlatılmasını</strong> istiyorum
          ve bu durumda <strong>cayma hakkımı kaybedeceğimi</strong> kabul ediyorum.
        </>
      ),
    },
  ];

  // --- Ozet/CTA (sabit kenar karti + mobil alt cubuk) icin turetilmis degerler ---
  const activeBundles = bundles.filter((b) => !b.comingSoon);
  const soonBundles = bundles.filter((b) => b.comingSoon);
  const selName = selectedBundle ? selectedBundle.displayName : selectedPkg ? selectedPkg.displayName : null;
  const intervalLabel = intervalDays === 7 ? L.weekly : intervalDays === 14 ? L.biweekly : L.monthly;
  const freqLabel = selectedBundle || !recurring ? L.freqOneOff : L.freqEvery(intervalLabel, runs);
  const startLabel =
    !selectedBundle && startMode === 'later' && startAt
      ? new Date(startAt).toLocaleString(deLang ? 'de-DE' : enLang ? 'en-GB' : 'tr-TR', { dateStyle: 'short', timeStyle: 'short' })
      : L.startImmediate;
  const baseAmountMinor = selectedBundle ? selectedBundle.amountMinorUnit : selectedPkg ? selectedPkg.priceMinorUnit : 0;
  // Promo (tekil paket VEYA bundle) gecerliyse indirimli tutari goster.
  const unitAmountMinor =
    (selectedBundle || selectedPkg) && promo?.valid && promo.finalAmountMinorUnit != null
      ? promo.finalAmountMinorUnit
      : baseAmountMinor;
  const totalMinor = !selectedBundle && recurring ? unitAmountMinor * runs : unitAmountMinor;
  // (Kullanıcı isteği) AKTİF paket + DOĞRULANMAMIŞ alan adı: "Satın Al" HİÇ tıklanmasın. Ödeme-sonra-tut
  // yerine, kullanıcı önce doğrulamaya yönlendirilir. Bu durumda buy CTA'sı yerine "Doğrula" butonu çıkar
  // ve /verify'da o alan adının DNS paneline odaklanır (domainId param).
  const needsDomainVerify = isActiveLightSel && !!domainId && domainVerified === false;
  const verifyHref = domainId
    ? `/verify?domainId=${domainId}&${selectedBundle ? `bundle=${selectedBundle.key}` : `package=${selected}`}`
    : '/verify';
  // (TÜM paketler) ön-kontrol bitene kadar bekle; erişilemez uyarısı onaylanmadan ödeme yok.
  const preCheckGate = scopeChecking || (showUnreachableWarning && !unreachableAck);
  const ctaDisabled = selectedBundle
    ? !domainId || busy || !allConsents || intlComingSoon || needsDomainVerify ||
      (selectedBundle.category === 'active-light' && !atRisk) ||
      // (LOGİNSİZ TEST) kimlik-doğrulamalı üye: creds OPSİYONEL. Girildiyse ek onaylar gerekir; boşsa loginsiz geçer.
      (selectedBundle.members?.some((m: any) => m.key === 'authenticated_scan') && hasCreds && !authConsentsOk) ||
      (selectedBundle.selectable && bundleModules.length === 0) ||
      (showLowScopeWarning && !lowScopeAck) || // düşük-kapsam uyarısı onaylanmadan ödeme yok
      preCheckGate
    : !domainId || busy || !selected || !allConsents || !activeConsentOk || intlComingSoon || needsDomainVerify || preCheckGate;
  const ctaLabel = busy
    ? L.ctaStarting
    : selectedBundle
      ? L.ctaBuyBundle
      : recurring
        ? L.ctaSetupRecurring
        : startMode === 'later'
          ? L.ctaSchedule
          : L.ctaStart;
  const onCta = () => (selectedBundle ? handleBundleStart() : handleStart());

  // (İŞ 3 · Sorun A) "Satın Al" neden pasif? Müşteri tahmin etmesin — net sebep + onaylara kaydırma.
  const scrollToTarget = (id: string) => document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'center' });
  const allGroupsChecked = groupGeneralChecked && groupCrossBorderChecked && withdrawalConsent;
  // (MOBİL) Buton neden pasif? Uyarı/onay AŞAĞIDA olabilir; hint'e `target` verip mobil alt-çubukta da
  // "→ oraya kaydır" yapıyoruz. Aksi halde ön-kontrol uyarısının onay kutusuna ulaşılamayıp kilitleniyordu.
  const disabledHint: { text: string; scroll: boolean; target?: string } | null = (() => {
    if (!(selected || selectedBundle) || busy) return null;
    if (!domainId) return { text: L.hintSelectDomain, scroll: false };
    if (selectedBundle?.selectable && bundleModules.length === 0) return { text: L.hintSelectModules, scroll: false };
    // (LOGİNSİZ TEST) test hesabı bilgisi artık zorunlu değil — boş bırakılırsa loginsiz devam edilir (uyarı formda).
    if (!allGroupsChecked) return { text: L.hintConsents, scroll: true, target: 'onaylar' };
    if (showLowScopeWarning && !lowScopeAck) return { text: L.hintLowScope, scroll: true, target: 'oncontrol-uyari' };
    if (showUnreachableWarning && !unreachableAck) return { text: L.hintUnreach, scroll: true, target: 'oncontrol-uyari' };
    if (scopeChecking) return { text: L.hintChecking, scroll: false };
    return null;
  })();

  // Tek paket kart bileseni (basit + aktif bundle'lar ortak gorunum)
  const bundleCard = (b: any) => {
    const on = selectedBundle?.key === b.key;
    return (
      <button
        key={b.key}
        type="button"
        onClick={() => { setSelectedBundle(on ? null : b); setSelected(null); setBundleModules([]); setPromo(null); }}
        className={`card relative flex flex-col p-4 text-left transition ${
          on ? 'ring-2 ring-brand' : b.popular ? 'border-accent hover:border-accent' : 'hover:border-brand-300'
        }`}
      >
        {b.popular ? (
          <span className="absolute -top-3 left-6 rounded-pill bg-accent px-3 py-0.5 text-[10px] font-bold text-white">★ {L.popular}</span>
        ) : b.discountPct > 0 ? (
          <span className="absolute -top-3 left-6 rounded-pill bg-brand px-3 py-0.5 text-[10px] font-bold text-white">%{b.discountPct}</span>
        ) : null}
        <span className="font-bold text-brand">{b.displayName}</span>
        <p className="mt-1 text-xs leading-relaxed text-ink-soft">{renderEmphasis(b.description)}</p>
        {b.key === 'bundle_recon' ? (
          <div className="mt-1.5 flex-1 text-[11px] text-ink-muted">
            {L.includes}:
            <ul className="mt-1 space-y-0.5">
              {L.reconItems.map((it) => <li key={it}>· {it}</li>)}
            </ul>
            <p className="mt-1.5 italic">{L.reconNote}</p>
          </div>
        ) : (
          <p className="mt-1.5 flex-1 text-[11px] text-ink-muted">
            {L.includes}: {b.members.map((m: any) => m.displayName).join(' · ')}
          </p>
        )}
        <p className="mt-2 text-ink">
          {b.discountPct > 0 && (
            <span className="text-xs text-ink-muted line-through">{formatMoney(b.originalMinorUnit, getRegion(region))}</span>
          )}{' '}
          <span className="font-bold">{formatMoney(b.amountMinorUnit, getRegion(region))}</span>
          <span className="text-xs font-normal text-ink-muted"> · {L.kdv}</span>
        </p>
      </button>
    );
  };

  // (Tam Kapsamlı Pentest — FAZ A) Kimlik-doğrulamalı paketlerde: "test hesabı" uyarısı + kimlik
  // bilgisi girişleri + 3 EK onay. Kimlik-doğrulamalı üye seçiliyken gösterilir (comingSoon paket
  // FAZ E'de açıldığında canlı olur; şimdilik hazır).
  // (ÖDEME ÖNCESİ TEST GİRİŞİ) Girilen test hesabıyla kendi doğrulanmış domainine 1 login dener.
  // BLOKLAMAZ — sonuç bilgilendirmedir (yanlış-negatif olabilir; gerçek tarama daha kapsamlıdır).
  async function runLoginCheck() {
    if (!domainId || !authUser.trim() || !authPass || loginCheck === 'checking') return;
    setLoginCheck('checking');
    setLoginCheckMsg('');
    try {
      const r = await api.precheckLogin(domainId, authUser.trim(), authPass);
      if (r.ok) {
        setLoginCheck('ok');
        setLoginCheckMsg(L.lcOk);
      } else {
        setLoginCheck('fail');
        setLoginCheckMsg(
          r.reason === 'bad_credentials' ? L.lcBad
          : r.reason === 'two_factor' ? L.lc2fa
          : r.reason === 'no_login_endpoint' ? L.lcNoForm
          : r.reason === 'timeout' ? L.lcTimeout
          : L.lcOther,
        );
      }
    } catch {
      // (HIZ) İstemci zaman aşımı (AbortError) dahil — takılı kalmaz, bilgilendirici mesaj.
      setLoginCheck('fail');
      setLoginCheckMsg(L.lcTimeout);
    }
  }

  const authCredBlock = (
    <div className="mt-3 space-y-4 rounded-card border-2 border-brand/20 bg-brand-50/50 p-4 sm:p-5">
      <p className="flex items-center gap-2 text-sm font-bold text-brand">
        {L.acTitle} <span className="font-normal text-ink-muted">{L.acOptional}</span>
      </p>
      {/* (LOGİNSİZ TEST) Opsiyonel olduğunu net söyle — sitede login olmayabilir. */}
      <div className="rounded-card border border-brand-200 bg-white/70 px-4 py-3 text-sm text-ink-soft">
        <p dangerouslySetInnerHTML={{ __html: L.acInfoHtml }} />
      </div>
      {/* Uyarı — güçlü kontrast: sol accent bar + koyu kırmızı başlık + koyu metin */}
      <div className="rounded-card border border-red-300 border-l-4 border-l-red-600 bg-red-50 px-4 py-3 text-red-900">
        <p className="text-sm font-bold text-red-700">{L.acWarnTitle}</p>
        <p className="mt-1 text-sm" dangerouslySetInnerHTML={{ __html: L.acWarnBodyHtml }} />
        <p className="mt-1.5 text-xs text-red-800" dangerouslySetInnerHTML={{ __html: L.acWarn2Html }} />
      </div>
      {/* Etiketli girişler — beyaz alanlar tint zemine karşı belirgin */}
      <div className="grid gap-3 sm:grid-cols-2">
        <label className="block">
          <span className="label !mb-1 !text-ink">{L.acUser}</span>
          <input placeholder="test@example.com" value={authUser} onChange={(e) => { setAuthUser(e.target.value); setLoginCheck('idle'); }} className="field border-line/80" autoComplete="off" />
        </label>
        <label className="block">
          <span className="label !mb-1 !text-ink">{L.acPass}</span>
          <input type="password" placeholder={L.acPassPh} value={authPass} onChange={(e) => { setAuthPass(e.target.value); setLoginCheck('idle'); }} className="field border-line/80" autoComplete="new-password" />
        </label>
      </div>
      {/* (ÖDEME ÖNCESİ TEST GİRİŞİ) tek buton + tek satır sonuç — ek checkbox/uyarı YOK, bloklamaz. */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
        <button
          type="button"
          onClick={runLoginCheck}
          disabled={!domainId || !authUser.trim() || !authPass || loginCheck === 'checking'}
          className="btn-dark shrink-0 text-sm disabled:cursor-not-allowed disabled:opacity-50"
        >
          {loginCheck === 'checking' ? (
            <span className="flex items-center gap-2">
              <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-white/40 border-t-white" />
              {L.acChecking}
            </span>
          ) : (
            L.acCheckBtn
          )}
        </button>
        {loginCheck === 'checking' && (
          <span className="text-xs text-ink-muted">{L.acCheckingHint}</span>
        )}
        {loginCheck === 'ok' && (
          <span className="rounded-pill bg-emerald-100 px-3 py-1 text-sm font-semibold text-emerald-800">✓ {loginCheckMsg}</span>
        )}
        {loginCheck === 'fail' && (
          <span className="rounded-pill bg-amber-100 px-3 py-1 text-sm font-medium text-amber-900">{loginCheckMsg}</span>
        )}
      </div>
      {/* (LOGİNSİZ TEST) Bilgi girilmediyse küçük uyarı — tarama loginsiz yapılacak. */}
      {!hasCreds && (
        <p className="text-xs font-medium text-ink-muted" dangerouslySetInnerHTML={{ __html: L.acNoCredsHtml }} />
      )}
      {/* (İŞ 3) Test-hesabı beyanı + kimlik-bilgisi yurt dışı açık rıza + yüksek-risk kabulü aşağıdaki
          "2 · Onaylar" bölümündeki gruplu checkbox'larda (sunucu-tarafı alanlar AYNEN korunur). */}
    </div>
  );

  return (
    <main className="min-h-screen bg-canvas pb-36 lg:pb-14">
      {/* HERO — koyu yeşil gradyan (marka); krem zemin + amber vurgu ile profesyonel checkout. */}
      <div className="bg-gradient-to-b from-brand to-brand-deep text-white">
        <div className="container-page max-w-6xl pt-10 pb-20 lg:pt-14">
          <p className="font-mono text-[11px] font-semibold uppercase tracking-[0.14em] text-accent">{L.orderEyebrow}</p>
          <h1 className="mt-2 text-3xl font-extrabold tracking-tight sm:text-4xl">{L.title}</h1>
          <p className="mt-2 max-w-xl text-sm leading-relaxed text-white/70">{L.sub}</p>
        </div>
      </div>
      <div className="container-page max-w-6xl -mt-12">

      {!domainId && (
        <p className="mt-4 rounded-card border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
          {L.noDomainPre}{' '}
          <Link href="/verify" className="font-semibold underline">
            {L.noDomainLink}
          </Link>
        </p>
      )}

      {/* (PASİF/AKTİF AYRIMI) Doğrulama gereksinimi — paket tipine göre net mesaj. */}
      {domainId && (selected || selectedBundle) && (
        isActiveLightSel ? (
          domainVerified ? (
            <p className="mt-4 flex items-center gap-2 rounded-card border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm font-medium text-emerald-800">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" className="shrink-0" aria-hidden><path d="M20 6 9 17l-5-5" /></svg>
              {L.dnsVerified}
            </p>
          ) : (
            <div className="mt-4 rounded-card border border-amber-300 bg-amber-50 px-4 py-3 text-sm text-amber-900/90">
              <p className="font-bold text-amber-900">{L.activeVerifyTitle}</p>
              <p className="mt-1 leading-relaxed" dangerouslySetInnerHTML={{ __html: L.activeVerifyBodyHtml }} />
              <Link href={verifyHref} className="mt-2 inline-flex items-center gap-1 font-semibold text-amber-900 underline">
                {L.verifyNow}
              </Link>
            </div>
          )
        ) : (
          <p className="mt-4 flex items-center gap-2 rounded-card border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm font-medium text-emerald-800">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" className="shrink-0" aria-hidden><path d="M20 6 9 17l-5-5" /></svg>
            {L.passiveNoVerify}
          </p>
        )
      )}

      <div className="mt-6 grid gap-8 lg:grid-cols-[minmax(0,1fr)_340px] lg:gap-10">
        {/* ================= SOL: form adimlari ================= */}
        <div className="min-w-0">
      {/* Paket seçimi — SADECE paketler: Basit Tarama (giriş) + kombine paketler. Tekil kontrol satışı YOK. */}
      <h2 className="text-sm font-bold uppercase tracking-wide text-ink-muted">{L.step1}</h2>
      <div className="mt-3 grid items-stretch gap-3 sm:grid-cols-2">
        {/* Basit Tarama artik satin alinmaz — anasayfada ücretsiz "Hemen Dene" anlik taramasina yonlendirilir. */}
        {activeBundles.map((b) => bundleCard(b))}
      </div>
      {/* "Yakında" paketler — devre disi, gri, SONA alindi (secilemez). */}
      {soonBundles.length > 0 && (
        <div className="mt-5">
          <p className="text-[11px] font-bold uppercase tracking-wide text-ink-muted">{L.soon}</p>
          <div className="mt-2 grid items-stretch gap-3 sm:grid-cols-2">
            {soonBundles.map((b) => (
              <div
                key={b.key}
                aria-disabled="true"
                className="card relative flex cursor-not-allowed flex-col border-dashed bg-brand-50/30 p-4 text-left opacity-60"
              >
                <span className="absolute -top-3 left-6 rounded-pill bg-ink-muted px-3 py-0.5 text-[10px] font-bold text-white">{L.soon}</span>
                <span className="font-bold text-ink-soft">{b.displayName}</span>
                <p className="mt-1 flex-1 text-xs leading-relaxed text-ink-muted">{renderEmphasis(b.description)}</p>
                <p className="mt-2 text-xs font-semibold text-ink-muted">{L.soonClosed}</p>
              </div>
            ))}
          </div>
        </div>
      )}
      {/* (İŞ 3) Aktif-hafif risk kabulü aşağıdaki gruplu onaya taşındı; burada YALNIZ (varsa) test-hesabı
          giriş alanları gösterilir (kimlik-doğrulamalı bundle üyesi için). */}
      {selectedBundle?.members?.some((m: any) => m.key === 'authenticated_scan') && (
        <div className="mt-3 rounded-card border border-amber-300/60 bg-amber-50 px-4 py-3 text-sm">
          <p className="text-sm font-semibold text-brand">{L.testCredsMembers}</p>
          {authCredBlock}
        </div>
      )}

      {/* KAPSAM NETLIGI — Aktif Doğrulama Paketi seçiliyken HER müşteri, ÖDEME ÖNCESİ görür
          (düşük-sinyal ön-kontrol uyarısından bağımsız; o uyarı ek olarak gösterilir). */}
      {selectedBundle?.key === 'bundle_active_verify' && (
        <div className="mt-3 rounded-card border-2 border-amber-400 bg-amber-50 px-4 py-3 text-sm text-amber-900/90">
          <p className="font-bold text-amber-900">{L.avTitle}</p>
          <p className="mt-1 leading-relaxed" dangerouslySetInnerHTML={{ __html: L.avP1Html }} />
          <p className="mt-2 leading-relaxed" dangerouslySetInnerHTML={{ __html: L.avP2Html }} />
          <p className="mt-2 leading-relaxed" dangerouslySetInnerHTML={{ __html: L.avP3Html }} />
        </div>
      )}

      {/* (FAZ E) TAM KAPSAMLI PENTEST — bu paket diğerlerinden DAVRANIŞ olarak farklı; müşteri
          ödeme öncesi NET bilsin: inceleme süreci + test hesabı + sınırlı-otonom ajan. */}
      {selectedBundle?.key === 'bundle_full_pentest' && (
        <div className="mt-3 space-y-2 rounded-card border border-brand-200 bg-brand-50/50 px-4 py-3 text-sm text-ink-soft">
          <p dangerouslySetInnerHTML={{ __html: L.fpReviewHtml }} />
          <p dangerouslySetInnerHTML={{ __html: L.fpAccountHtml }} />
          <p dangerouslySetInnerHTML={{ __html: L.fpMethodHtml }} />
          <p dangerouslySetInnerHTML={{ __html: L.fpAiHtml }} />
          <p dangerouslySetInnerHTML={{ __html: L.fpScopeHtml }} />
        </div>
      )}

      {/* Onaylar — (İŞ 3) ≤3 gruplu checkbox; sunucu-tarafı bireysel zorunluluk korunur. */}
      <h2 id="onaylar" className="mt-8 scroll-mt-24 text-sm font-bold uppercase tracking-wide text-ink-muted">{L.step2}</h2>
      {(selected || selectedBundle) && !allConsents && (
        <p className="mt-2 rounded-card border border-amber-300 bg-amber-50 px-3.5 py-2 text-xs font-semibold text-amber-800">
          {L.needConsents(consentGroups.length)}
        </p>
      )}
      <div className="mt-3 space-y-2.5">
        {consentGroups.map(({ checked, set, node }, i) => (
          <label key={i} className={`flex items-start gap-3 rounded-card border p-3.5 text-sm text-ink-soft transition ${checked ? 'border-brand-200 bg-brand-50/50' : 'border-amber-300 bg-amber-50/40'}`}>
            <input type="checkbox" checked={checked} onChange={(e) => set(e.target.checked)} className="mt-0.5 h-4 w-4 accent-brand" />
            <span>{node}</span>
          </label>
        ))}
      </div>
      {selectedPkg && (
        <div className="mt-3">
          <button type="button" onClick={() => setShowContract((v) => !v)} className="text-xs font-semibold text-accent-600 underline">
            {showContract ? L.contractHide : L.contractShow}
          </button>
          {showContract && (
            <DynamicContract
              serviceName={selectedPkg.displayName}
              priceLabel={formatMoney(selectedPkg.priceMinorUnit, getRegion(region))}
              region={region}
            />
          )}
        </div>
      )}

      {/* Tekrar + Başlangıç YALNIZ tekil paket için (bundle'lar hemen çalışır, zamanlanamaz). */}
      {!selectedBundle && (
      <>
      {/* Düzenli tekrar (opsiyonel) */}
      <h2 className="mt-8 text-sm font-bold uppercase tracking-wide text-ink-muted">{L.step3}</h2>
      <div className="mt-3 space-y-2.5">
        <label className={`flex items-center gap-3 rounded-card border p-3.5 text-sm ${!recurring ? 'border-brand-300 bg-brand-50/50' : 'border-line'}`}>
          <input type="radio" checked={!recurring} onChange={() => setRecurring(false)} className="h-4 w-4 accent-brand" />
          <span className="font-medium text-ink">{L.oneOff}</span>
        </label>
        <label className={`flex items-center gap-3 rounded-card border p-3.5 text-sm ${recurring ? 'border-brand-300 bg-brand-50/50' : 'border-line'}`}>
          <input type="radio" checked={recurring} onChange={() => setRecurring(true)} className="h-4 w-4 accent-brand" />
          <span className="font-medium text-ink">{L.repeat}</span>
        </label>
        {recurring && (
          <div className="rounded-card border border-line bg-white p-4">
            <div className="flex flex-wrap items-end gap-4">
              <div>
                <label className="label">{L.frequency}</label>
                <select value={intervalDays} onChange={(e) => setIntervalDays(Number(e.target.value))} className="field">
                  <option value={7}>{L.weekly}</option>
                  <option value={14}>{L.biweekly}</option>
                  <option value={30}>{L.monthly}</option>
                </select>
              </div>
              <div>
                <label className="label">{L.howManyRuns}</label>
                <input
                  type="number"
                  min={1}
                  max={52}
                  value={runs}
                  onChange={(e) => setRuns(Math.max(1, Math.min(52, Number(e.target.value))))}
                  className="field w-28"
                />
              </div>
            </div>
            <p className="mt-3 text-xs text-ink-muted">{L.recurringNote(runs)}</p>
          </div>
        )}
      </div>

      {/* Başlangıç zamanı */}
      <h2 className="mt-8 text-sm font-bold uppercase tracking-wide text-ink-muted">
        {L.step4} {recurring && <span className="font-normal normal-case text-ink-muted">{L.firstScan}</span>}
      </h2>
      <div className="mt-3 space-y-2.5">
        <label className={`flex items-center gap-3 rounded-card border p-3.5 text-sm ${startMode === 'now' ? 'border-brand-300 bg-brand-50/50' : 'border-line'}`}>
          <input type="radio" checked={startMode === 'now'} onChange={() => setStartMode('now')} className="h-4 w-4 accent-brand" />
          <span className="font-medium text-ink">{L.startNow}</span>
        </label>
        <label className={`flex items-center gap-3 rounded-card border p-3.5 text-sm ${startMode === 'later' ? 'border-brand-300 bg-brand-50/50' : 'border-line'}`}>
          <input type="radio" checked={startMode === 'later'} onChange={() => setStartMode('later')} className="h-4 w-4 accent-brand" />
          <span className="font-medium text-ink">{L.startLater}</span>
        </label>
        {startMode === 'later' && (
          <div className="rounded-card border border-line bg-white p-4">
            <label className="label">{L.startDateTime}</label>
            <input
              type="datetime-local"
              value={startAt}
              min={minDateTimeLocal()}
              onChange={(e) => setStartAt(e.target.value)}
              className="field"
            />
            <p className="mt-2 text-xs text-ink-muted">{L.startLaterNote}</p>
          </div>
        )}
      </div>
      </>
      )}

      {/* (Faz 3) Active-light yetkilendirme beyani — pasif onaylarin USTUNE, ayri blok */}
      {isActiveLight && selectedPkg?.activeTest && (
        <div className="mt-6 rounded-card border-2 border-accent/60 bg-accent-soft/30 p-5">
          <h3 className="text-base font-bold text-brand">{L.atTitle}</h3>
          <p className="mt-1 text-sm text-ink-soft">{L.atBody}</p>
          <div className="mt-3 grid gap-3 sm:grid-cols-2">
            <div className="rounded-card bg-white/70 p-3">
              <p className="text-xs font-bold uppercase tracking-wide text-brand-500">{L.atDoes}</p>
              <ul className="mt-1 space-y-1 text-sm text-ink-soft">
                {selectedPkg.activeTest.scope.does.map((d) => (
                  <li key={d}>✓ {d}</li>
                ))}
              </ul>
            </div>
            <div className="rounded-card bg-white/70 p-3">
              <p className="text-xs font-bold uppercase tracking-wide text-red-600">{L.atDoesNot}</p>
              <ul className="mt-1 space-y-1 text-sm text-ink-soft">
                {selectedPkg.activeTest.scope.doesNot.map((d) => (
                  <li key={d}>✗ {d}</li>
                ))}
              </ul>
            </div>
          </div>
          {/* (İŞ 3) Risk kabulü aşağıdaki "2 · Onaylar" gruplu checkbox'ına taşındı. NOT: riskText backend'den
              (paket tanımı) gelir; şimdilik TR — backend paket i18n'i ayrı iş. */}
          <p className="mt-3 rounded-card bg-white/70 p-3 text-xs text-ink-soft">{selectedPkg.activeTest.riskText}</p>
          <p className="mt-2 text-xs text-ink-muted">{L.atConsentNote}</p>
          {needsAuthCreds && (
            <div className="mt-4 border-t border-accent/30 pt-4">
              <p className="text-sm font-semibold text-brand">{L.testCredsMembers}</p>
              {authCredBlock}
            </div>
          )}
        </div>
      )}


      {(selected || selectedBundle) && !intlComingSoon && (
        <div className="mt-5 rounded-card border border-brand-100 bg-white px-4 py-3 text-sm">
          <label className="label">{L.promoLabel}</label>
          {selected === 'basit_tarama' && activePromo?.code && (
            <PromoCodeChip
              code={activePromo.code}
              labels={{
                campaign: deLang ? 'AKTIONSANGEBOT' : enLang ? 'LAUNCH OFFER' : 'KAMPANYAYA ÖZEL',
                copy: deLang ? 'Kopieren' : enLang ? 'Copy' : 'Kopyala',
                copied: deLang ? 'Kopiert!' : enLang ? 'Copied!' : 'Kopyalandı!',
                hint: deLang
                  ? 'Geben Sie diesen Code unten ein, um den Basis-Scan kostenlos zu erhalten.'
                  : enLang
                  ? 'Enter this code below to get the Basic Scan for free.'
                  : 'Bu kodu aşağıya girerek Basit Tarama’yı ücretsiz alın.',
              }}
            />
          )}
          <div className="mt-1 flex gap-2">
            <input
              value={promoInput}
              onChange={(e) => { setPromoInput(e.target.value); setPromo(null); }}
              placeholder={L.promoPh}
              className="field flex-1 uppercase"
            />
            <button
              type="button"
              onClick={applyPromo}
              disabled={promoBusy || !promoInput.trim()}
              className="btn-dark disabled:opacity-50"
            >
              {promoBusy ? '…' : L.apply}
            </button>
          </div>
          {promo && !promo.valid && <p className="mt-2 text-xs text-red-600">{promo.error}</p>}
          {promo && promo.valid && (
            <p className="mt-2 text-xs text-emerald-700">
              {L.promoAppliedPre} {formatMoney(promo.discountMinorUnit ?? 0, getRegion(region))}. {L.promoNewTotal}{' '}
              <strong>{formatMoney(promo.finalAmountMinorUnit ?? 0, getRegion(region))}</strong>
              {promo.finalAmountMinorUnit === 0 && L.promoFree}
            </p>
          )}
        </div>
      )}

      {queue?.busy && !intlComingSoon && (
        <div className="mt-6 rounded-card border border-amber-300/60 bg-amber-50 px-4 py-3 text-sm text-ink-soft" dangerouslySetInnerHTML={{ __html: L.queueBusyHtml }} />
      )}

      {intlComingSoon && (
        <div className="mt-6 rounded-card border border-accent/40 bg-accent-soft/40 px-4 py-3 text-sm text-ink-soft">
          <strong>Online payment for your region is coming soon.</strong> Card payments are currently available for
          Türkiye only. Please contact us at{' '}
          <a href="mailto:support@cybertestify.com" className="text-accent-600 underline">
            support@cybertestify.com
          </a>{' '}
          to arrange your scan in the meantime.
        </div>
      )}

      {/* ÖN KONTROL UYARILARI — ana kolonda (mobil DÂHİL görünür). aside masaüstü-only olduğundan
          buraya taşındı; aksi halde mobilde onay kutusuna ulaşılamayıp sistem kilitleniyordu. */}
              {scopeChecking && (
                <p className="mt-3 text-center text-xs text-ink-muted">{L.checking}</p>
              )}
              {showUnreachableWarning && (
                <div id="oncontrol-uyari" className="mt-4 scroll-mt-24 rounded-card border-2 border-rose-400 bg-rose-50 p-4 text-sm">
                  <p className="font-bold text-rose-900">{L.unreachTitle}</p>
                  <p className="mt-1 leading-relaxed text-rose-900/90" dangerouslySetInnerHTML={{ __html: L.unreachP1Html }} />
                  <p className="mt-2 leading-relaxed text-rose-900/90" dangerouslySetInnerHTML={{ __html: L.unreachP2Html }} />
                  <label className="mt-3 flex cursor-pointer items-start gap-2 font-medium text-rose-900">
                    <input type="checkbox" checked={unreachableAck} onChange={(e) => setUnreachableAck(e.target.checked)} className="mt-0.5" />
                    <span>{L.unreachAck}</span>
                  </label>
                </div>
              )}
              {showLowScopeWarning && (
                <div id="oncontrol-uyari" className="mt-4 scroll-mt-24 rounded-card border-2 border-amber-400 bg-amber-50 p-4 text-sm">
                  <p className="font-bold text-amber-900">{L.lowTitle}</p>
                  <p className="mt-1 leading-relaxed text-amber-900/90" dangerouslySetInnerHTML={{ __html: L.lowP1Html }} />
                  <p className="mt-2 leading-relaxed text-amber-900/90" dangerouslySetInnerHTML={{ __html: L.lowP2Html }} />
                  <label className="mt-3 flex cursor-pointer items-start gap-2 font-medium text-amber-900">
                    <input type="checkbox" checked={lowScopeAck} onChange={(e) => setLowScopeAck(e.target.checked)} className="mt-0.5" />
                    <span>{L.lowAck}</span>
                  </label>
                </div>
              )}


      {/* MOBİL: sol kolon sonunda (özet kolonu masaüstünde görünür; mobilde sabit alt çubuk var). */}
      {error && <p className="mt-4 rounded-card border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700 lg:hidden">{error}</p>}

        </div>{/* ===== SOL kolon sonu ===== */}

        {/* ================= SAĞ: kaydırmada sabit özet (masaüstü) ================= */}
        <aside className="hidden lg:block">
          <div className="sticky top-6 space-y-3">
            <div className="rounded-card border border-line bg-white p-5 shadow-sm">
              <p className="text-xs font-bold uppercase tracking-wide text-ink-muted">{L.summary}</p>
              {selName ? (
                <>
                  <p className="mt-2 text-base font-bold text-brand">{selName}</p>
                  <dl className="mt-3 space-y-1.5 text-sm">
                    {hostname && (
                      <div className="flex justify-between gap-2">
                        <dt className="text-ink-muted">{L.domainLabel}</dt>
                        <dd className="text-right font-semibold text-ink break-all">{hostname}</dd>
                      </div>
                    )}
                    <div className="flex justify-between gap-2">
                      <dt className="text-ink-muted">{L.freqLabel}</dt>
                      <dd className="text-right font-medium text-ink">{freqLabel}</dd>
                    </div>
                    <div className="flex justify-between gap-2">
                      <dt className="text-ink-muted">{L.startLabelKey}</dt>
                      <dd className="text-right font-medium text-ink">{startLabel}</dd>
                    </div>
                    {selectedBundle && (
                      <div className="flex justify-between gap-2">
                        <dt className="text-ink-muted">{L.contentLabel}</dt>
                        <dd className="text-right font-medium text-ink">{L.scanCount(selectedBundle.members.length)}</dd>
                      </div>
                    )}
                  </dl>
                  <div className="mt-3 border-t border-line pt-3">
                    <div className="flex items-baseline justify-between">
                      <span className="text-sm text-ink-muted">{recurring ? L.totalRuns(runs) : L.total}</span>
                      <span className="text-2xl font-extrabold text-brand">{formatMoney(totalMinor, getRegion(region))}</span>
                    </div>
                    <p className="mt-0.5 text-right text-[11px] text-ink-muted">{L.kdvIncl}</p>
                  </div>
                </>
              ) : (
                <p className="mt-2 text-sm text-ink-soft">{L.selectPackage}</p>
              )}
              {needsDomainVerify ? (
                <button onClick={() => router.push(verifyHref)} className="btn-primary mt-4 flex w-full items-center justify-center gap-1.5">
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden><path d="M12 2l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V5l7-3z" /><path d="M9 12l2 2 4-4" /></svg>
                  {L.verifyDomain}
                </button>
              ) : (
                <button onClick={onCta} disabled={ctaDisabled} className="btn-primary mt-4 w-full disabled:cursor-not-allowed disabled:opacity-50">
                  {ctaLabel}
                </button>
              )}
              {needsDomainVerify ? (
                <p className="mt-2 text-center text-[11px] text-amber-700">{L.verifyHint}</p>
              ) : disabledHint ? (
                disabledHint.scroll ? (
                  <button type="button" onClick={() => scrollToTarget(disabledHint.target ?? 'onaylar')} className="mt-2 w-full rounded-card border border-amber-300 bg-amber-50 px-3 py-2 text-center text-xs font-semibold text-amber-800 hover:bg-amber-100">
                    {disabledHint.text}
                  </button>
                ) : (
                  <p className="mt-2 text-center text-[11px] font-semibold text-amber-700">{disabledHint.text}</p>
                )
              ) : (
                <p className="mt-2 text-center text-[11px] text-ink-muted">
                  {recurring || startMode === 'later' ? L.scheduledHint : L.autoStartHint}
                </p>
              )}
              {/* Ödeme/başlatma hatası — CTA'nın HEMEN ALTINDA (masaüstü özet kolonunda). */}
              {error && <p className="mt-3 rounded-card border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{error}</p>}
            </div>

            {/* Güven şeridi — DÜRÜST sinyaller (uydurma istatistik/puan YOK) */}
            <div className="rounded-card border border-line bg-brand-50/40 p-4 text-xs text-ink-soft">
              <ul className="space-y-1.5">
                <li className="flex items-center gap-2">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" className="shrink-0" aria-hidden><path d="M12 2l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V5l7-3z" fill="#123F3A"/><path d="M9 12l2 2 4-4" stroke="#F5A623" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" fill="none"/></svg>
                  {L.trustSSL}
                </li>
                <li className="flex items-center gap-2">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#123F3A" strokeWidth="2" className="shrink-0" aria-hidden><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>
                  {L.trustCard}
                </li>
                <li className="flex items-center gap-2">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#1C6B60" strokeWidth="2" className="shrink-0" aria-hidden><circle cx="12" cy="12" r="9"/><path d="M8 12l2.5 2.5L16 9" strokeLinecap="round" strokeLinejoin="round"/></svg>
                  {L.trustKvkk}
                </li>
              </ul>
              <div className="mt-3 flex flex-wrap items-center gap-3">
                {deLang || enLang ? (
                  <span className="inline-flex items-center rounded-md border border-line bg-white px-2 py-1 text-xs font-semibold text-brand">{L.payAlt}</span>
                ) : (
                  <img src="/iyzico/iyzico_ile_ode_colored_horizontal.svg" alt={L.payAlt} className="h-5 w-auto" width={175} height={26} />
                )}
                <img src="/iyzico/logo_band_colored.svg" alt="Visa, Mastercard, Troy" className="h-4 w-auto max-w-full" width={228} height={16} />
              </div>
            </div>
          </div>
        </aside>
      </div>{/* ===== grid sonu ===== */}

      {/* ================= MOBİL: kaydırmada sabit alt çubuk (özet önizleme + CTA) ================= */}
      <div className="fixed inset-x-0 bottom-0 z-40 border-t border-line bg-white/95 px-4 py-2.5 shadow-[0_-4px_16px_rgba(0,0,0,0.06)] backdrop-blur lg:hidden">
        <div className="mx-auto max-w-6xl">
          {/* Önizleme (paket/host/tutar) + CTA aynı satırda; buton HER ZAMAN kompakt → önizleme kırpılmaz/ezilmez. */}
          <div className="flex items-center justify-between gap-3">
            <div className="min-w-0">
              <p className="truncate text-xs font-semibold text-brand">{selName ?? L.noPackage}</p>
              {hostname && <p className="truncate text-[11px] text-ink-muted">{hostname}</p>}
              <p className="text-sm font-extrabold text-ink">
                {formatMoney(totalMinor, getRegion(region))}
                <span className="ml-1 text-[10px] font-normal text-ink-muted">{L.kdv}</span>
              </p>
            </div>
            {needsDomainVerify ? (
              <button type="button" onClick={() => router.push(verifyHref)} className="btn-primary shrink-0 px-5">
                {L.mobileVerify}
              </button>
            ) : (
              <button onClick={onCta} disabled={ctaDisabled} className="btn-primary shrink-0 px-5 disabled:cursor-not-allowed disabled:opacity-50">
                {ctaLabel}
              </button>
            )}
          </div>
          {/* Buton neden pasif? — TAM GENİŞLİK, önizlemenin ALTINDA (üstünde/yanında DEĞİL): uzun metin
              kutuyu ezmez; kaydırma gerektiren uyarıda tıklayınca ilgili bölüme götürür. */}
          {!needsDomainVerify && disabledHint && (
            disabledHint.scroll ? (
              <button
                type="button"
                onClick={() => scrollToTarget(disabledHint.target ?? 'onaylar')}
                className="mt-2 block w-full rounded-card border border-amber-300 bg-amber-50 px-3 py-1.5 text-center text-[11px] font-semibold text-amber-800 hover:bg-amber-100"
              >
                {disabledHint.text}
              </button>
            ) : (
              <p className="mt-2 text-center text-[11px] font-semibold text-amber-700">{disabledHint.text}</p>
            )
          )}
        </div>
      </div>
      </div>
    </main>
  );
}
