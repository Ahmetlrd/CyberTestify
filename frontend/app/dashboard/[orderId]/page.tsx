'use client';

import { useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import { api } from '../../../lib/api';
import { StatusTracker } from '../../../components/dashboard/StatusTracker';
import { ScanRunningView } from '../../../components/dashboard/ScanRunningView';
import { InvoiceRequestForm } from '../../../components/dashboard/InvoiceRequestForm';
import { ScanFailedActions } from '../../../components/dashboard/ScanFailedActions';
import { GA_ID } from '../../../lib/consent';
import { ScopeCertificate } from '../../../components/dashboard/ScopeCertificate';
import { TwoFaNudge } from '../../../components/TwoFaNudge';
import { readRegionCookie } from '../../../lib/region';
import { localizedPackageName } from '../../../lib/packageNames';
import { getRegion } from '../../../config/regions';

const TERMINAL = new Set(['scan_completed', 'scan_failed', 'scope_violation', 'report_purged']);

// (Çok-bölge) Dashboard metinleri tr/de. Client sayfa → cookie'den lang (hydration-safe).
const DASH = {
  tr: {
    headline: {
      awaiting_payment: 'Ödeme bekleniyor', awaiting_domain_verification: 'Alan adı doğrulaması gerekli',
      paid: 'Ödeme alındı — tarama hazırlanıyor', scan_queued: 'Taramanız başlatılıyor', scan_running: 'Taramanız çalışıyor',
      scan_completed: 'Raporunuz hazır', scan_failed: 'Tarama tamamlanamadı', scope_violation: 'Tarama güvenlik nedeniyle durduruldu',
      report_purged: 'Rapor saklama süresi doldu', refunded: 'Siparişiniz iade edildi',
    } as Record<string, string>,
    orderStatus: 'Sipariş Durumu', target: 'Hedef', reportReadyIncomplete: 'Rapor hazır — ancak eksik',
    dvTitle: 'Alan adı sahipliğinizi doğrulayın',
    dvBodyHtml: 'Ödemeniz alındı. Ancak bu paket <strong>aktif güvenlik probları</strong> (kimlik-doğrulamalı testler, enjeksiyon/oturum denemeleri) gönderir; bu testler yasal olarak yalnızca <strong>alan adının sahibi/yetkilisi olduğunuzu DNS ile doğruladıktan sonra</strong> başlatılabilir. Doğrulama tamamlanınca taramanız <strong>otomatik başlar</strong> — bu sayfa kendiliğinden güncellenir.',
    dvCta: 'DNS ile doğrula',
    apTitle: 'Ödemeniz henüz tamamlanmadı',
    apBodyHtml: 'Siparişiniz oluşturuldu ancak ödeme alınmadığı için tarama <strong>henüz başlamadı</strong>. Taramayı başlatmak için ödemeyi tamamlamanız yeterli.',
    apRedirecting: 'Ödeme sayfasına yönlendiriliyor…', apCta: 'Ödemeyi Tamamla',
    apNote: 'Güvenli ödeme iyzico altyapısıyla alınır. Ödeme onaylanınca tarama otomatik başlar ve bu sayfa kendiliğinden güncellenir.',
    payErr: 'Ödeme sayfası alınamadı. Lütfen tekrar deneyin.',
    refundTitle: 'Siparişiniz iade edildi',
    refundBodyPre: 'Bu sipariş iptal/iade edilmiştir. Bir ödeme yaptıysanız iade tutarı, bankanıza bağlı olarak birkaç iş günü içinde kartınıza/hesabınıza yansır. Sorunuz varsa ',
    refundBodyPost: ' ile iletişime geçebilirsiniz.',
    incompletePre: '⚠️ Bu tarama eksik tamamlandı.', incompleteDefault: 'Tarama beklenenden erken sonlandı ve rapor içeriği eksik/boş olabilir.',
    incompleteMid: ' Ücret iadesi veya taramanın yeniden çalıştırılması için ', incompleteTail: (id: string) => ` ile iletişime geçin (sipariş no: ${id}).`,
    reportDownloaded: 'Rapor indirildi ✓', reportReady: 'Şifreli raporunuz hazır', oneTimeCode: 'Tek kullanımlık erişim koduyla açılır',
    codeSentHtml: '<strong>Erişim kodunuz e-posta ile gönderildi.</strong> Raporunuzu açmak için e-postanızdaki tek kullanımlık kodu aşağıya girin. (Bir kez açtığınızda bu cihazda hatırlanır.)',
    accessCode: 'Erişim kodu', downloadReport: 'Raporu indir',
    fixTitle: 'AI Çözüm Önerileri', fixSub: 'Bulgularınız için somut, uygulanabilir düzeltme adımları (güvenli kod/config örnekleriyle).',
    campaign: 'KAMPANYA', campaignFree: '— kampanyaya özel ücretsiz, sizin için açıldı',
    fixUnlockedHtml: '✓ Açık — çözüm önerileri artık <strong>raporunuzun içinde</strong> yer alıyor. Güncel raporu (çözüm önerileri dahil) indirmek için aşağıdaki butonu kullanın.',
    downloadWithFix: 'Raporu indir (çözüm önerileri dahil)', enterCodeFirst: 'Önce yukarıdaki erişim kodunu girin.',
    fixLockedPre: '🔒 Bu içerik kilitli.', fixLockedPost: ' karşılığında açılır.',
    promoOptional: 'Promosyon kodu (opsiyonel)', promoPlaceholder: 'Kodunuz', processing: 'İşleniyor…', buyUnlock: 'Satın al ve aç',
    fixNote: 'Güvenli ödeme iyzico ile alınır. Promosyon kodu %100 ise ödeme adımı atlanır.',
    scopeViolation: 'Tarama, kapsam dışı bir hedefe erişim girişimi tespit edildiği için güvenlik gereği durduruldu. Bu, sizi ve üçüncü tarafları koruyan bilinçli bir önlemdir.',
    targetFallback: 'hedef',
  },
  de: {
    headline: {
      awaiting_payment: 'Zahlung ausstehend', awaiting_domain_verification: 'Domain-Verifizierung erforderlich',
      paid: 'Zahlung erhalten — Scan wird vorbereitet', scan_queued: 'Ihr Scan wird gestartet', scan_running: 'Ihr Scan läuft',
      scan_completed: 'Ihr Bericht ist fertig', scan_failed: 'Scan konnte nicht abgeschlossen werden', scope_violation: 'Scan aus Sicherheitsgründen gestoppt',
      report_purged: 'Aufbewahrungsfrist des Berichts abgelaufen', refunded: 'Ihre Bestellung wurde erstattet',
    } as Record<string, string>,
    orderStatus: 'Bestellstatus', target: 'Ziel', reportReadyIncomplete: 'Bericht fertig — jedoch unvollständig',
    dvTitle: 'Bestätigen Sie Ihre Domain-Inhaberschaft',
    dvBodyHtml: 'Ihre Zahlung ist eingegangen. Dieses Paket sendet jedoch <strong>aktive Sicherheitsprüfungen</strong> (authentifizierte Tests, Injection-/Session-Versuche); diese Tests dürfen rechtlich erst starten, nachdem Sie <strong>per DNS bestätigt haben, dass Sie Inhaber/Berechtigter der Domain sind</strong>. Nach der Bestätigung startet Ihr Scan <strong>automatisch</strong> — diese Seite aktualisiert sich von selbst.',
    dvCta: 'Per DNS bestätigen',
    apTitle: 'Ihre Zahlung ist noch nicht abgeschlossen',
    apBodyHtml: 'Ihre Bestellung wurde erstellt, aber da keine Zahlung eingegangen ist, hat der Scan <strong>noch nicht begonnen</strong>. Schließen Sie einfach die Zahlung ab, um den Scan zu starten.',
    apRedirecting: 'Weiterleitung zur Zahlungsseite…', apCta: 'Zahlung abschließen',
    apNote: 'Die sichere Zahlung erfolgt über iyzico. Nach Bestätigung der Zahlung startet der Scan automatisch und diese Seite aktualisiert sich von selbst.',
    payErr: 'Zahlungsseite konnte nicht geladen werden. Bitte versuchen Sie es erneut.',
    refundTitle: 'Ihre Bestellung wurde erstattet',
    refundBodyPre: 'Diese Bestellung wurde storniert/erstattet. Falls Sie gezahlt haben, wird der Erstattungsbetrag je nach Bank innerhalb weniger Werktage auf Ihrer Karte/Ihrem Konto gutgeschrieben. Bei Fragen erreichen Sie uns unter ',
    refundBodyPost: '.',
    incompletePre: '⚠️ Dieser Scan wurde unvollständig abgeschlossen.', incompleteDefault: 'Der Scan endete früher als erwartet und der Berichtsinhalt kann unvollständig/leer sein.',
    incompleteMid: ' Für eine Erstattung oder eine erneute Ausführung des Scans kontaktieren Sie ', incompleteTail: (id: string) => ` (Bestellnummer: ${id}).`,
    reportDownloaded: 'Bericht heruntergeladen ✓', reportReady: 'Ihr verschlüsselter Bericht ist fertig', oneTimeCode: 'Wird mit einem Einmal-Zugangscode geöffnet',
    codeSentHtml: '<strong>Ihr Zugangscode wurde per E-Mail gesendet.</strong> Geben Sie den Einmal-Code aus Ihrer E-Mail unten ein, um Ihren Bericht zu öffnen. (Nach dem ersten Öffnen wird er auf diesem Gerät gemerkt.)',
    accessCode: 'Zugangscode', downloadReport: 'Bericht herunterladen',
    fixTitle: 'KI-Lösungsempfehlungen', fixSub: 'Konkrete, umsetzbare Behebungsschritte für Ihre Befunde (mit sicheren Code-/Konfigurationsbeispielen).',
    campaign: 'AKTION', campaignFree: '— im Rahmen der Aktion kostenlos für Sie freigeschaltet',
    fixUnlockedHtml: '✓ Freigeschaltet — die Lösungsempfehlungen sind jetzt <strong>in Ihrem Bericht</strong> enthalten. Nutzen Sie die Schaltfläche unten, um den aktuellen Bericht (inkl. Empfehlungen) herunterzuladen.',
    downloadWithFix: 'Bericht herunterladen (inkl. Lösungsempfehlungen)', enterCodeFirst: 'Geben Sie zuerst oben den Zugangscode ein.',
    fixLockedPre: '🔒 Dieser Inhalt ist gesperrt.', fixLockedPost: ' freigeschaltet.',
    promoOptional: 'Aktionscode (optional)', promoPlaceholder: 'Ihr Code', processing: 'Wird verarbeitet…', buyUnlock: 'Kaufen und freischalten',
    fixNote: 'Die sichere Zahlung erfolgt über iyzico. Bei einem 100%-Aktionscode entfällt der Zahlungsschritt.',
    scopeViolation: 'Der Scan wurde aus Sicherheitsgründen gestoppt, weil ein Zugriffsversuch auf ein Ziel außerhalb des Scope erkannt wurde. Dies ist eine bewusste Schutzmaßnahme für Sie und Dritte.',
    targetFallback: 'Ziel',
  },
  en: {
    headline: {
      awaiting_payment: 'Awaiting payment', awaiting_domain_verification: 'Domain verification required',
      paid: 'Payment received — preparing scan', scan_queued: 'Your scan is starting', scan_running: 'Your scan is running',
      scan_completed: 'Your report is ready', scan_failed: 'The scan could not be completed', scope_violation: 'Scan stopped for security reasons',
      report_purged: 'Report retention period expired', refunded: 'Your order has been refunded',
    } as Record<string, string>,
    orderStatus: 'Order status', target: 'Target', reportReadyIncomplete: 'Report ready — but incomplete',
    dvTitle: 'Verify your domain ownership',
    dvBodyHtml: 'Your payment has been received. However, this package sends <strong>active security probes</strong> (authenticated tests, injection/session attempts); by law these tests can only start <strong>after you have verified via DNS that you are the owner/authorised person of the domain</strong>. Once verification is complete, your scan <strong>starts automatically</strong> — this page updates by itself.',
    dvCta: 'Verify via DNS',
    apTitle: 'Your payment is not complete yet',
    apBodyHtml: 'Your order has been created, but because no payment was received the scan <strong>has not started yet</strong>. Simply complete the payment to start the scan.',
    apRedirecting: 'Redirecting to the payment page…', apCta: 'Complete payment',
    apNote: 'Secure payment is processed via iyzico. Once payment is confirmed, the scan starts automatically and this page updates by itself.',
    payErr: 'The payment page could not be loaded. Please try again.',
    refundTitle: 'Your order has been refunded',
    refundBodyPre: 'This order has been cancelled/refunded. If you made a payment, the refund amount will be credited to your card/account within a few business days, depending on your bank. If you have any questions, you can contact ',
    refundBodyPost: '.',
    incompletePre: '⚠️ This scan completed incompletely.', incompleteDefault: 'The scan ended earlier than expected and the report content may be incomplete/empty.',
    incompleteMid: ' For a refund or to have the scan re-run, contact ', incompleteTail: (id: string) => ` (order number: ${id}).`,
    reportDownloaded: 'Report downloaded ✓', reportReady: 'Your encrypted report is ready', oneTimeCode: 'Opened with a one-time access code',
    codeSentHtml: '<strong>Your access code has been sent by email.</strong> Enter the one-time code from your email below to open your report. (Once opened, it is remembered on this device.)',
    accessCode: 'Access code', downloadReport: 'Download report',
    fixTitle: 'AI Remediation Suggestions', fixSub: 'Concrete, actionable remediation steps for your findings (with secure code/config examples).',
    campaign: 'CAMPAIGN', campaignFree: '— unlocked free for you as part of the campaign',
    fixUnlockedHtml: '✓ Unlocked — the remediation suggestions are now <strong>included in your report</strong>. Use the button below to download the current report (including suggestions).',
    downloadWithFix: 'Download report (including remediation suggestions)', enterCodeFirst: 'Enter the access code above first.',
    fixLockedPre: '🔒 This content is locked. Unlocks for', fixLockedPost: '.',
    promoOptional: 'Promo code (optional)', promoPlaceholder: 'Your code', processing: 'Processing…', buyUnlock: 'Buy and unlock',
    fixNote: 'Secure payment is processed via iyzico. If the promo code is 100%, the payment step is skipped.',
    scopeViolation: 'The scan was stopped for security reasons because an attempt to access an out-of-scope target was detected. This is a deliberate protective measure for you and third parties.',
    targetFallback: 'target',
  },
} as const;

function LockIcon({ open }: { open: boolean }) {
  return (
    <svg viewBox="0 0 24 24" className="h-7 w-7 text-brand transition-all duration-500" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <rect x="5" y="11" width="14" height="10" rx="2" />
      <path
        className="transition-all duration-500 origin-center"
        d={open ? 'M8 11V7a4 4 0 017.9-1' : 'M8 11V7a4 4 0 018 0v4'}
      />
      {open && <path d="M12 15v2" className="text-accent" stroke="currentColor" />}
    </svg>
  );
}

// (TASARIM: Report Ready v2) "Rapor hazır" ekranına özel metinler. Diğer 8 sipariş durumu
// DEĞİŞMEDİ. Renkler site marka token'larıyla (Nav/Footer ile uyumlu kalsın diye).
const RR = {
  tr: { eyebrow: 'Sipariş Durumu · Tamamlandı', processTitle: 'Süreç', orderedOn: 'Sipariş tarihi',
        steps: ['Sahiplik doğrulandı', 'Tarama çalıştı', 'Bulgular değerlendirildi', 'Rapor hazır'],
        resend: 'Kodu tekrar gönder', resendBusy: 'Gönderiliyor…',
        resendOk: 'Erişim kodu e-posta adresinize yeniden gönderildi.',
        resendFail: 'Kod gönderilemedi. Lütfen tekrar deneyin.' },
  de: { eyebrow: 'Bestellstatus · Abgeschlossen', processTitle: 'Ablauf', orderedOn: 'Bestelldatum',
        steps: ['Inhaberschaft bestätigt', 'Scan ausgeführt', 'Befunde bewertet', 'Bericht fertig'],
        resend: 'Code erneut senden', resendBusy: 'Wird gesendet…',
        resendOk: 'Der Zugangscode wurde erneut an Ihre E-Mail-Adresse gesendet.',
        resendFail: 'Der Code konnte nicht gesendet werden. Bitte erneut versuchen.' },
  en: { eyebrow: 'Order status · Completed', processTitle: 'Process', orderedOn: 'Order date',
        steps: ['Ownership verified', 'Scan completed', 'Findings assessed', 'Report ready'],
        resend: 'Resend code', resendBusy: 'Sending…',
        resendOk: 'The access code has been re-sent to your email address.',
        resendFail: 'The code could not be sent. Please try again.' },
} as const;

export default function OrderDashboard({ params }: { params: { orderId: string } }) {
  const router = useRouter();
  const [order, setOrder] = useState<any>(null);
  const [accessSecret, setAccessSecret] = useState('');
  const [unlocked, setUnlocked] = useState(false);
  const [busyFix, setBusyFix] = useState(false);
  const [busyPay, setBusyPay] = useState(false); // "Odemeyi Tamamla" -> gercek iyzico'ya yonlendirme
  const [fixPromo, setFixPromo] = useState(''); // AI Cozum Onerileri promosyon kodu
  const [error, setError] = useState<string | null>(null);
  const [dlError, setDlError] = useState<string | null>(null); // rapor indirme hatası — kutunun altında gösterilir
  // (HOOK SIRASI) Bu üç state + effect ESKİDEN erken return'ün ALTINDAydı; sipariş yüklenince
  // hook sayısı değişip React #310 ("rendered more hooks than during the previous render") ile
  // sayfa çöküyordu. Hook'lar KOŞULSUZ olmalı → diğer state'lerin yanına alındı.
  const [fixPromoSeen, setFixPromoSeen] = useState<boolean | null>(null);
  const [resendBusy, setResendBusy] = useState(false);
  const [resendMsg, setResendMsg] = useState<{ ok: boolean; text: string } | null>(null);
  // (UX) Bu cihazda kayıtlı kod varsa kullanıcı raporu ZATEN bir kez açmış demektir → "kodu tekrar
  // gönder" gereksiz (hep aynı kod geliyor). Sayfa yenilense de buton geri gelmesin diye ayrı state.
  const [codeRemembered, setCodeRemembered] = useState(false);
  // (KAMPANYA SADELESTIRME) AI kampanya bloğu sipariş başına YALNIZ İLK görüntülemede tam blok;
  // sonrasında tek satırlık sessiz not. Fiyat/indirim ORANI değişmez, sadece görünürlük.
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const k = `ct_fixpromo_${params.orderId}`;
    const seen = window.localStorage.getItem(k) === '1';
    setFixPromoSeen(seen);
    if (!seen) window.localStorage.setItem(k, '1');
  }, [params.orderId]);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);
  const [lang, setLang] = useState<'tr' | 'de' | 'en'>('tr');
  useEffect(() => { const l = getRegion(readRegionCookie()).lang; setLang(l === 'de' ? 'de' : l === 'en' ? 'en' : 'tr'); }, []);
  const rr = RR[lang];
  // (UX) "Kodu tekrar gönder" — e-postayı bulamayan kullanıcı kilitli kalmasın.
  async function handleResendCode() {
    setResendBusy(true);
    setResendMsg(null);
    try {
      await api.resendReportCode(params.orderId);
      setResendMsg({ ok: true, text: rr.resendOk });
    } catch (e: any) {
      setResendMsg({ ok: false, text: e?.message || rr.resendFail });
    } finally {
      setResendBusy(false);
    }
  }
  const t = DASH[lang];

  useEffect(() => {
    if (typeof window !== 'undefined' && !window.localStorage.getItem('token')) {
      router.push('/login');
      return;
    }
    // (ŞİFRE OTOMATİK DOLDURMA KAPALI) Erişim kodu artık sunucudan gelmez; herkes e-postasındaki
    // kodu girer. Ama BİR KEZ başarıyla açtıysa, kolaylık olsun diye bu cihazda saklanır (localStorage).
    if (typeof window !== 'undefined') {
      const saved = window.localStorage.getItem(`ct_access_${params.orderId}`);
      if (saved) { setAccessSecret((prev) => prev || saved); setCodeRemembered(true); }
    }
    async function load() {
      try {
        const o = await api.getOrder(params.orderId);
        setOrder(o);
        if (TERMINAL.has(o.status) && timer.current) {
          clearInterval(timer.current);
          timer.current = null;
        }
      } catch (err: any) {
        setError(err.message);
      }
    }
    load();
    timer.current = setInterval(load, 5000);
    return () => {
      if (timer.current) clearInterval(timer.current);
    };
  }, [params.orderId, router]);

  // (GA4 dönüşüm) Ödeme başarılı olduğunda 'purchase' event'i — sipariş başına YALNIZ BİR kez
  // (localStorage guard; sayfa yenilense/poll etse de tekrar atmaz). Consent denied olsa bile
  // Consent Mode ile modellenmiş dönüşüm çalışır. gtag hazır değilse guard yazılmaz → sonra tekrar denenir.
  useEffect(() => {
    if (!GA_ID || !order?.paidAt || !order?.id) return;
    if (typeof window === 'undefined' || typeof (window as any).gtag !== 'function') return;
    const key = `ga_purchase_${order.id}`;
    if (window.localStorage.getItem(key)) return;
    (window as any).gtag('event', 'purchase', {
      transaction_id: order.id,
      value: (order.amountMinorUnit ?? 0) / 100,
      currency: order.currency ?? 'TRY',
      items: [{ item_name: order.packageName ?? 'Paket' }],
    });
    window.localStorage.setItem(key, '1');
  }, [order?.paidAt, order?.id, order?.amountMinorUnit, order?.currency, order?.packageName]);

  function downloadBlob(blob: Blob, name: string) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    a.click();
  }

  async function handleDownload() {
    setError(null);
    setDlError(null);
    try {
      const blob = await api.downloadReport(params.orderId, accessSecret);
      setUnlocked(true);
      // Başarıyla açıldı — kodu bu cihazda sakla (bir daha girmesin). Kilit kaldırmak isterse
      // tarayıcı verisini temizlemesi yeter (sunucuda kod müşteriye asla dönmez).
      if (typeof window !== 'undefined') window.localStorage.setItem(`ct_access_${params.orderId}`, accessSecret);
      setCodeRemembered(true); // rapor açıldı → "kodu tekrar gönder" artık gösterilmez
      // Rapor artik PDF olarak uretiliyor (bkz backend reports.ts /download).
      downloadBlob(blob, `cybertestify-rapor-${params.orderId}.pdf`);
    } catch (err: any) {
      // (UX) İndirme hatasını sayfa DİBİNDE değil, erişim-kodu kutusunun HEMEN ALTINDA göster.
      setDlError(err.message);
    }
  }

  // (Ödeme Bekleniyor) "Ödemeyi Tamamla" -> GERÇEK iyzico ödeme sayfasını yeniden başlat, oraya yönlen.
  // (Env'de anahtar yoksa backend görsel /pay placeholder'ı döner — TEK route, dallanma sunucuda.)
  async function handleResumePayment() {
    setBusyPay(true);
    setError(null);
    try {
      const res = await api.resumePayment(params.orderId);
      if (res.paymentPageUrl) {
        window.location.href = res.paymentPageUrl;
        return;
      }
      setError(t.payErr);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setBusyPay(false);
    }
  }

  // (3) AI Cozum Onerileri: satin al. iyzico paymentPageUrl donerse ORAYA yonlen; %100 promo/
  // sandbox ise dogrudan acilir -> siparisi yenile.
  async function handleUnlockFix() {
    setBusyFix(true);
    setError(null);
    try {
      const res = await api.unlockFixSuggestions(params.orderId, fixPromo.trim() || undefined);
      if (res.paymentPageUrl) {
        window.location.href = res.paymentPageUrl; // gercek iyzico ek-odeme
        return;
      }
      const o = await api.getOrder(params.orderId);
      setOrder(o);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setBusyFix(false);
    }
  }

  if (!order && !error) {
    return (
      <main className="container-page max-w-xl py-16">
        <div className="h-40 animate-pulse rounded-card bg-brand-50" />
      </main>
    );
  }

  const status = order?.status as string;
  const hostname = order?.domain?.hostname ?? t.targetFallback;
  const active = status === 'scan_running' || status === 'paid' || status === 'scan_queued';
  // (TASARIM) Rapor hazır ekranı iki kolonlu → dar kap yerine geniş kap.
  const wide = active || status === 'scan_completed';

  let feed: Array<{ seq: number; text: string }> = [];
  try {
    if (order?.flow?.activityFeed) feed = JSON.parse(order.flow.activityFeed);
  } catch {
    feed = [];
  }

  return (
    <main className={`container-page py-16 ${wide ? "max-w-5xl" : "max-w-xl"}`}>
      <TwoFaNudge />
      {!active && status !== 'scan_completed' && <>
        <p className="eyebrow">{t.orderStatus}</p>
        <h1 className="mt-2 text-3xl font-extrabold text-brand">
          {status === 'scan_completed' && order?.report?.incomplete
            ? t.reportReadyIncomplete
            : t.headline[status] ?? status}
        </h1>
        {order && <p className="mt-1 text-sm text-ink-muted">{t.target}: {hostname}</p>}
      </>}

      {/* İade/süre-doldu gibi terminal durumlarda adım göstergesi YANILTICI olur — gösterilmez.
          ÖDEME BEKLENİYOR'da da gösterilmez: tarama HENÜZ BAŞLAMADI; "Tarama çalışıyor" adımı
          müşteriyi yanıltır (ödeme yapmadan tarama sanıyor). Onun yerine ödeme kartı gösterilir. */}
      {!active && !['refunded', 'report_purged', 'awaiting_payment', 'awaiting_domain_verification', 'scan_completed'].includes(status) && (
        <div className="mt-8">
          <StatusTracker status={status} lang={lang} />
        </div>
      )}

      {/* (ÇELİK KAPI) AKTİF paket ödendi ama alan adı DNS ile doğrulanmadı → tarama TUTULUYOR.
          Aktif problar (SQLi/XSS/login prob) yasal olarak yalnız sahiplik doğrulanınca çalışır. */}
      {status === 'awaiting_domain_verification' && (
        <div className="mt-8 rounded-card border-2 border-amber-300 bg-amber-50 p-6">
          <p className="text-lg font-bold text-amber-900">{t.dvTitle}</p>
          <p className="mt-1 text-sm leading-relaxed text-amber-900/80" dangerouslySetInnerHTML={{ __html: t.dvBodyHtml }} />
          <a href="/verify" className="btn-primary mt-4 inline-flex w-full items-center justify-center gap-1.5 sm:w-auto">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden><path d="M20 6 9 17l-5-5" /></svg>
            {t.dvCta}
          </a>
        </div>
      )}

      {/* ÖDEME BEKLENİYOR — müşteri ödeme ekranını göremiyordu (bug). Net ödeme kartı + "Ödemeyi
          Tamamla" CTA -> mevcut /pay/<orderId> ödeme sayfası (canlıda iyzico'ya yönlendirir). */}
      {status === 'awaiting_payment' && (
        <div className="mt-8 rounded-card border-2 border-accent/50 bg-accent-soft/30 p-6">
          <p className="text-lg font-bold text-brand">{t.apTitle}</p>
          <p className="mt-1 text-sm leading-relaxed text-ink-soft" dangerouslySetInnerHTML={{ __html: t.apBodyHtml }} />
          {order?.amountMinorUnit != null && (
            <div className="mt-4 flex items-baseline justify-between rounded-card bg-white/70 px-4 py-3">
              <span className="text-sm text-ink-soft">
                {hostname}{localizedPackageName(order?.packageKey, order?.packageName, lang) ? <> · {localizedPackageName(order?.packageKey, order?.packageName, lang)}</> : null}
              </span>
              <span className="text-2xl font-extrabold text-brand">
                {(order.amountMinorUnit / 100).toLocaleString(lang === 'de' ? 'de-DE' : 'tr-TR', { minimumFractionDigits: 2 })}{' '}
                {order.currency === 'TRY' || !order.currency ? 'TL' : order.currency}
              </span>
            </div>
          )}
          <button
            onClick={handleResumePayment}
            disabled={busyPay}
            className="btn-primary mt-4 flex w-full items-center justify-center gap-1.5 disabled:cursor-not-allowed disabled:opacity-60"
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden>
              <rect x="3" y="5" width="18" height="14" rx="2" />
              <path d="M3 10h18" />
            </svg>
            {busyPay ? t.apRedirecting : t.apCta}
          </button>
          <p className="mt-2 text-center text-[11px] text-ink-muted">{t.apNote}</p>
        </div>
      )}

      {status === 'refunded' && (
        <div className="mt-8 rounded-card border border-brand-200 bg-brand-50/60 p-6 text-sm text-ink-soft">
          <p className="font-semibold text-brand">{t.refundTitle}</p>
          <p className="mt-1">
            {t.refundBodyPre}
            <a href="mailto:support@cybertestify.com" className="font-semibold text-accent-600 underline">support@cybertestify.com</a>
            {t.refundBodyPost}
          </p>
        </div>
      )}

      {active && (() => {
        // (S1 OTONOM RED TEAM) Ayrı motor — Flow YOK. Fazları ödeme (paidAt) çıpasından ilerlet; koşu
        // ~20-30dk sürdüğü için cadence YAVAŞ (faz başına ~4dk) → "rapor hazırlanıyor"a erken atlamaz.
        const isS1 = order?.packageKey === 'redteam_s1';
        // (Sırada) Tarama HENÜZ başlamadıysa (kuyrukta veya flow başlamamış): ilerleme YOK, "başlatılıyor".
        const notStarted = isS1
          ? status === 'scan_queued' || status === 'paid' // S1: dispatch olunca scan_running → ilerler
          : status === 'scan_queued' || status === 'paid' || !order?.flow?.startedAt;
        const s1Started = order?.paidAt ?? order?.createdAt;
        return (
          // (Tasarım: Scan Status v2) TEMA: S1 → koyu, 6 paket → açık. Tarama türü de gösterilir.
          <ScanRunningView
            hostname={hostname}
            packageKey={order?.packageKey}
            packageName={order?.packageName}
            startedAt={isS1 ? s1Started : order?.flow?.startedAt}
            authConfirmedAt={order?.flow?.authConfirmedAt}
            feed={isS1 ? [] : (notStarted ? [] : feed)}
            notStarted={notStarted}
            dark={isS1}
            secondsPerPhase={isS1 ? 240 : undefined}
            verified={order?.domainVerified === true}
            loginless={order?.loginless === true}
            lang={lang}
          />
        );
      })()}

      {status === 'scan_completed' && (
        <div className="mt-8">
          {/* (TASARIM) Hero şeridi — sipariş durumu + hedef alan adı; düz başlık yerine geçer. */}
          <div className="overflow-hidden rounded-card bg-gradient-to-br from-brand-deep to-brand-500 px-6 py-8 text-white sm:px-8">
            <div className="flex flex-wrap items-center gap-5">
              <span className="flex h-14 w-14 shrink-0 items-center justify-center rounded-full bg-white/10">
                <svg width="26" height="26" viewBox="0 0 16 16" fill="none" aria-hidden>
                  <path d="M3 8.5L6.2 11.5L13 4" stroke="#7fe0b8" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </span>
              <div className="min-w-0 flex-1">
                <p className="text-xs font-bold uppercase tracking-[0.08em] text-emerald-300">{rr.eyebrow}</p>
                <h1 className="mt-1.5 text-2xl font-extrabold sm:text-3xl">
                  {order.report?.incomplete ? t.reportReadyIncomplete : t.headline.scan_completed}
                </h1>
                {/* (NETLİK) Hangi paket olduğu + siparişin TARİHİ görünsün — "hangi tarama, ne zaman". */}
                <p className="mt-1.5 text-sm text-white/70">
                  {localizedPackageName(order?.packageKey, order?.packageName, lang)}
                  {order?.createdAt && (
                    <>
                      {localizedPackageName(order?.packageKey, order?.packageName, lang) ? ' · ' : ''}
                      {rr.orderedOn}: {new Date(order.createdAt).toLocaleDateString(lang === 'de' ? 'de-DE' : lang === 'en' ? 'en-GB' : 'tr-TR')}
                    </>
                  )}
                </p>
              </div>
              <p className="rounded-card bg-white/10 px-4 py-2.5 font-mono text-sm text-white/75">
                {t.target}: <span className="font-semibold text-white">{hostname}</span>
              </p>
            </div>
          </div>

          {order.report?.incomplete && (
            <div className="mt-6 rounded-card border border-amber-300 bg-amber-50 px-4 py-3.5 text-sm text-amber-900">
              <strong>{t.incompletePre}</strong>{' '}
              {order.report.incompleteReason ?? t.incompleteDefault}
              {t.incompleteMid}
              <a href="mailto:destek@cybertestify.com" className="font-semibold underline">
                destek@cybertestify.com
              </a>
              {t.incompleteTail(order.id)}
            </div>
          )}

          {/* (TASARIM) İki kolon: solda süreç + kapsam sertifikası (yapışkan), sağda aksiyonlar. */}
          <div className="mt-6 grid items-start gap-6 lg:grid-cols-[300px_minmax(0,1fr)]">
            <aside className="space-y-5 lg:sticky lg:top-6">
              <div className="rounded-card border border-line bg-white p-5">
                <p className="mb-4 text-xs font-bold uppercase tracking-wide text-ink">{rr.processTitle}</p>
                <ol>
                  {rr.steps.map((stepLabel, i) => (
                    <li key={stepLabel} className="relative flex gap-3 pb-4 last:pb-0">
                      {i < rr.steps.length - 1 && (
                        <span aria-hidden className="absolute bottom-0 left-[11px] top-6 w-0.5 bg-brand-100" />
                      )}
                      <span className="relative z-[1] flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-brand-500">
                        <svg width="11" height="11" viewBox="0 0 16 16" fill="none" aria-hidden>
                          <path d="M3 8.5L6.2 11.5L13 4" stroke="white" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
                        </svg>
                      </span>
                      <span className="pt-0.5 text-sm font-semibold text-ink">{stepLabel}</span>
                    </li>
                  ))}
                </ol>
              </div>
              <ScopeCertificate hostname={hostname} flow={order.flow} lang={lang} />
            </aside>

            <div className="min-w-0 space-y-6">
          {/* Rapor teslim — kilit mikro-etkilesimi */}
          <div className="card p-6">
            <div className="flex items-center gap-3">
              <span className={`flex h-12 w-12 items-center justify-center rounded-full ${unlocked ? 'bg-emerald-50' : 'bg-brand-50'}`}>
                <LockIcon open={unlocked} />
              </span>
              <div>
                <h2 className="font-bold text-ink">{unlocked ? t.reportDownloaded : t.reportReady}</h2>
                <p className="text-xs text-ink-muted">{t.oneTimeCode}</p>
              </div>
            </div>

            {!unlocked && (
              <div className="mt-4 rounded-card border border-line bg-brand-50/40 p-3 text-xs text-ink-soft" dangerouslySetInnerHTML={{ __html: t.codeSentHtml }} />
            )}

            <div className="mt-4 flex flex-col gap-2 sm:flex-row">
              <input
                value={accessSecret}
                onChange={(e) => setAccessSecret(e.target.value)}
                placeholder={t.accessCode}
                className="flex-1 rounded-card border border-line bg-white px-3.5 py-2.5 text-sm outline-none focus:border-brand-300 focus:ring-2 focus:ring-brand-100"
              />
              <button onClick={handleDownload} disabled={!accessSecret} className="btn-primary disabled:opacity-50">
                {t.downloadReport}
              </button>
            </div>
            {dlError && (
              <p className="mt-2 rounded-card border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-600">{dlError}</p>
            )}
            {/* (UX) E-postayı bulamayanlar için: AYNI kod yeniden gönderilir (sunucuda dk/saat limiti var). */}
            {!unlocked && !codeRemembered && (
              <div className="mt-3 flex flex-wrap items-center gap-3">
                <button
                  type="button"
                  onClick={handleResendCode}
                  disabled={resendBusy}
                  className="text-xs font-semibold text-accent-600 underline underline-offset-2 hover:text-brand disabled:opacity-60"
                >
                  {resendBusy ? rr.resendBusy : rr.resend}
                </button>
                {resendMsg && (
                  <span className={`text-xs ${resendMsg.ok ? 'text-emerald-700' : 'text-red-600'}`}>{resendMsg.text}</span>
                )}
              </div>
            )}
          </div>

          {/* (ANKET — /tr YALNIZ, non-blocking) "Raporunuz hazır" ile "AI Çözüm Önerileri" ARASINDA;
              canlı/ışıltılı davet. Modal DEĞİL — indirmeyi engellemez. rel="noopener noreferrer": gizli
              rapor URL'i/token referrer olarak Google'a SIZMAZ. /de-/en'de GÖRÜNMEZ (anket Türkçe). */}
          {lang === 'tr' && (
            <div className="flex flex-col gap-3 rounded-card border border-accent/50 bg-gradient-to-br from-accent-soft/70 to-brand-50/50 px-5 py-4 shadow-[0_2px_12px_rgba(245,166,35,0.18)] sm:flex-row sm:items-center sm:justify-between">
              <div>
                <p className="text-sm font-bold text-ink">📝 Raporunuz nasıldı?</p>
                <p className="mt-0.5 text-xs text-ink-soft">Anonim — görüşleriniz raporlarımızı geliştirir (1 dakika).</p>
              </div>
              <span className="relative inline-flex shrink-0 self-start sm:self-auto">
                <span aria-hidden className="absolute -inset-1.5 animate-pulse rounded-pill bg-accent/35 blur-lg" />
                <a
                  href="https://forms.gle/NWYeG49GU6mZHFid6"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="group relative inline-flex items-center justify-center gap-1.5 overflow-hidden rounded-pill bg-accent px-6 py-2.5 text-sm font-bold text-white shadow-[0_4px_16px_rgba(245,166,35,0.5)] ring-2 ring-accent/40 transition-all duration-200 hover:scale-[1.05] hover:shadow-[0_6px_26px_rgba(245,166,35,0.8)]"
                >
                  <span aria-hidden className="pointer-events-none absolute inset-0 -translate-x-full bg-gradient-to-r from-transparent via-white/45 to-transparent transition-transform duration-[900ms] group-hover:translate-x-full" />
                  <span className="relative">Raporu değerlendirin (1 dk) →</span>
                </a>
              </span>
            </div>
          )}

          {/* (3) Ücretli eklenti: AI Çözüm Önerileri */}
          {order.report?.hasFixSuggestions && (
            <div className="card p-6">
              <h2 className="font-bold text-ink">{t.fixTitle}</h2>
              <p className="mt-1 text-xs text-ink-muted">{t.fixSub}</p>
              {order.report.fixSuggestionsUnlocked ? (
                <>
                  {order.report.fixCampaignFree && fixPromoSeen === true && (
                    <p className="mt-3 text-xs text-ink-muted">
                      <span className="mr-1.5 rounded-pill bg-brand-50 px-2 py-0.5 text-[10px] font-bold text-brand">{t.campaign}</span>
                      <strong className="text-ink">0 {order.currency}</strong>{t.campaignFree}
                    </p>
                  )}
                  {order.report.fixCampaignFree && fixPromoSeen === false && (
                    <div className="mt-3 flex flex-wrap items-center gap-2 rounded-card border border-amber-300 bg-amber-50 px-4 py-3 text-sm">
                      <span className="rounded-pill bg-amber-500 px-2.5 py-0.5 text-xs font-extrabold text-white">{t.campaign}</span>
                      <span className="font-semibold text-amber-900">
                        {order.report.fixSuggestionListMinorUnit != null && (
                          <span className="mr-1.5 font-normal text-amber-700 line-through">
                            {(order.report.fixSuggestionListMinorUnit / 100).toLocaleString(lang === 'de' ? 'de-DE' : 'tr-TR')} {order.currency}
                          </span>
                        )}
                        <strong className="mr-1">0 {order.currency}</strong>{t.campaignFree}
                      </span>
                    </div>
                  )}
                  <div className="mt-3 rounded-card border border-brand-200 bg-brand-50/40 px-4 py-3 text-sm text-ink-soft" dangerouslySetInnerHTML={{ __html: t.fixUnlockedHtml }} />
                  <button onClick={handleDownload} disabled={!accessSecret} className="btn-primary mt-3 disabled:opacity-50">
                    {t.downloadWithFix}
                  </button>
                  {!accessSecret && (
                    <p className="mt-2 text-xs text-ink-muted">{t.enterCodeFirst}</p>
                  )}
                </>
              ) : (
                <>
                  <div className="mt-3 rounded-card border border-line bg-brand-50/40 px-4 py-3 text-sm text-ink-soft">
                    {t.fixLockedPre}{' '}
                    {order.report.fixSuggestionPriceMinorUnit != null && (
                      <>
                        {order.report.fixSuggestionListMinorUnit != null &&
                          order.report.fixSuggestionListMinorUnit > order.report.fixSuggestionPriceMinorUnit && (
                            <span className="mr-1 text-ink-muted line-through">
                              {(order.report.fixSuggestionListMinorUnit / 100).toLocaleString(lang === 'de' ? 'de-DE' : 'tr-TR')} {order.currency}
                            </span>
                          )}
                        <strong>
                          {(order.report.fixSuggestionPriceMinorUnit / 100).toLocaleString(lang === 'de' ? 'de-DE' : 'tr-TR')} {order.currency}
                        </strong>
                      </>
                    )}{t.fixLockedPost}
                  </div>
                  <div className="mt-3">
                    <label className="text-xs font-medium text-ink-muted">{t.promoOptional}</label>
                    <input
                      value={fixPromo}
                      onChange={(e) => setFixPromo(e.target.value)}
                      placeholder={t.promoPlaceholder}
                      className="field mt-1 uppercase"
                    />
                  </div>
                  <button onClick={handleUnlockFix} disabled={busyFix} className="btn-primary mt-3 disabled:opacity-60">
                    {busyFix ? t.processing : t.buyUnlock}
                  </button>
                  <p className="mt-2 text-xs text-ink-muted">{t.fixNote}</p>
                </>
              )}
            </div>
          )}
            </div>{/* sağ kolon sonu */}
          </div>{/* grid sonu */}
        </div>
      )}

      {status === 'scope_violation' && (
        <p className="mt-6 rounded-card border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800">
          {t.scopeViolation}
        </p>
      )}

      {status === 'scan_failed' && (
        <ScanFailedActions
          orderId={order.id}
          packageKey={order.packageKey}
          attemptCount={order.attemptCount ?? 1}
          failureReason={order.failureReason}
          refundRequestedAt={order.refundRequestedAt ?? null}
          onRetry={() => window.location.reload()}
          lang={lang}
        />
      )}

      {/* (Fatura talebi) yalnız ödemesi tamamlanmış + başarısız/iade OLMAYAN siparişlerde göster. */}
      {order?.paidAt && !['scan_failed', 'scope_violation', 'report_purged', 'refunded'].includes(status) && (
        <InvoiceRequestForm
          orderId={order.id}
          defaultEmail={order.customer?.email ?? ''}
          existing={order.invoiceRequest ?? null}
          lang={lang}
        />
      )}

      {error && <p className="mt-4 text-sm text-red-600">{error}</p>}
    </main>
  );
}
