'use client';

import { useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { api } from '../../../lib/api';
import { readRegionCookie } from '../../../lib/region';
import { getRegion } from '../../../config/regions';

// (Çok-bölge) Bölge-öneksiz (cookie tabanlı) placeholder ödeme sayfası — dil cookie'den türetilir.
// TR'de gerçek iyzico formuna gidildiği için bu ekran ağırlıkla /de /en (placeholder) akışında görülür.
const T = {
  tr: {
    sandbox: (<><strong>Test / sandbox ortamı.</strong> Ödeme altyapımız (iyzico) yapılandırma aşamasındadır; canlıya geçtiğinde bu ekranda gerçek kart ödemesi alınacaktır. Bu sayfada girilen bilgilerle <strong>gerçek bir tahsilat yapılmaz</strong>.</>),
    secure: 'Güvenli Ödeme (256-bit SSL)',
    payWithIyzico: 'iyzico ile Öde',
    amountToPay: 'Ödenecek tutar',
    bundle: (n: number) => (<>Kombine paket — <strong>{n} tarama</strong></>),
    singleScan: (host: string) => `${host} taraması`,
    vat: 'KDV Dahildir',
    holder: 'Kart Sahibi',
    holderPh: 'Ad Soyad',
    cardNo: 'Kart Numarası',
    expiry: 'Son Kullanma',
    expiryPh: 'AA/YY',
    cvc: 'CVC',
    submitted: (<><strong>Ödeme altyapımız yapılandırma aşamasındadır.</strong> Gerçek işlem, iyzico entegrasyonu canlıya geçtiğinde aktif olacaktır. Siparişiniz oluşturuldu ancak henüz ödeme alınmadı — bu bir test ortamıdır ve tarama başlatılmamıştır.</>),
    pay: (amt: string) => `${amt} Öde`,
    stored: 'Kart bilgileriniz iyzico altyapısı ile işlenir; sistemlerimizde saklanmaz.',
    notFound: (e: string) => `Sipariş bulunamadı: ${e}`,
    locale: 'tr-TR',
  },
  de: {
    sandbox: (<><strong>Test-/Sandbox-Umgebung.</strong> Unsere Zahlungsinfrastruktur (iyzico) befindet sich in der Konfiguration; nach dem Livegang werden auf diesem Bildschirm echte Kartenzahlungen erfasst. Mit den hier eingegebenen Daten <strong>erfolgt keine echte Abbuchung</strong>.</>),
    secure: 'Sichere Zahlung (256-Bit-SSL)',
    payWithIyzico: 'Mit iyzico bezahlen',
    amountToPay: 'Zu zahlender Betrag',
    bundle: (n: number) => (<>Kombi-Paket — <strong>{n} Scans</strong></>),
    singleScan: (host: string) => `Scan von ${host}`,
    vat: 'inkl. MwSt.',
    holder: 'Karteninhaber',
    holderPh: 'Vor- und Nachname',
    cardNo: 'Kartennummer',
    expiry: 'Gültig bis',
    expiryPh: 'MM/JJ',
    cvc: 'CVC',
    submitted: (<><strong>Unsere Zahlungsinfrastruktur befindet sich in der Konfiguration.</strong> Die echte Transaktion wird nach dem Livegang der iyzico-Integration aktiv. Ihre Bestellung wurde erstellt, es wurde jedoch noch keine Zahlung erfasst — dies ist eine Testumgebung und es wurde kein Scan gestartet.</>),
    pay: (amt: string) => `${amt} bezahlen`,
    stored: 'Ihre Kartendaten werden über die iyzico-Infrastruktur verarbeitet und nicht in unseren Systemen gespeichert.',
    notFound: (e: string) => `Bestellung nicht gefunden: ${e}`,
    locale: 'de-DE',
  },
  en: {
    sandbox: (<><strong>Test / sandbox environment.</strong> Our payment infrastructure (iyzico) is being configured; once live, real card payments will be taken on this screen. No <strong>real charge is made</strong> with the details entered on this page.</>),
    secure: 'Secure Payment (256-bit SSL)',
    payWithIyzico: 'Pay with iyzico',
    amountToPay: 'Amount to pay',
    bundle: (n: number) => (<>Combined package — <strong>{n} scans</strong></>),
    singleScan: (host: string) => `${host} scan`,
    vat: 'VAT included',
    holder: 'Cardholder',
    holderPh: 'Full name',
    cardNo: 'Card Number',
    expiry: 'Expiry',
    expiryPh: 'MM/YY',
    cvc: 'CVC',
    submitted: (<><strong>Our payment infrastructure is being configured.</strong> The real transaction will be active once the iyzico integration goes live. Your order has been created but no payment has been taken yet — this is a test environment and no scan has been started.</>),
    pay: (amt: string) => `Pay ${amt}`,
    stored: 'Your card details are processed by iyzico’s infrastructure and are not stored in our systems.',
    notFound: (e: string) => `Order not found: ${e}`,
    locale: 'en-GB',
  },
} as const;

const CURRENCY_LABEL: Record<string, string> = { TRY: 'TL', EUR: '€', GBP: '£' };

/**
 * GÖRSEL ödeme sayfası (iyzico CheckoutForm placeholder). Gerçek sandbox/production
 * iyzico anahtarları .env'de OLMADIĞINDA backend buraya yönlendirir (createOrder →
 * paymentPageUrl=/pay/<orderId>). Anahtar girilince backend doğrudan iyzico'nun hosted
 * formuna yönlendirir ve bu sayfaya HİÇ gelinmez (tek route, env'e göre dallanma).
 *
 * KRİTİK: Bu sayfa siparişi ASLA otomatik 'paid' yapmaz, hiçbir ödeme/paid endpoint'i
 * çağırmaz, kart verisini HİÇBİR yere göndermez. "Öde" yalnızca bilgi mesajı gösterir.
 */
export default function PayPage({ params }: { params: { orderId: string } }) {
  const router = useRouter();
  const [lang, setLang] = useState<'tr' | 'de' | 'en'>('tr');
  useEffect(() => { const l = getRegion(readRegionCookie()).lang; setLang(l === 'de' ? 'de' : l === 'en' ? 'en' : 'tr'); }, []);
  const t = T[lang];
  // Kombine paket (bundle) satin alinca birden fazla siparis olusur; bundle sipariş
  // id'leri ?bundle=id1,id2,... ile gelir -> hepsini cekip TOPLAM tutari gosteririz.
  const bundleParam = useSearchParams().get('bundle');
  const bundleIds = bundleParam ? bundleParam.split(',').filter(Boolean) : null;

  const [order, setOrder] = useState<any>(null);
  const [orders, setOrders] = useState<any[] | null>(null); // bundle: tüm üye siparişler
  const [error, setError] = useState<string | null>(null);
  const [submitted, setSubmitted] = useState(false);

  const [card, setCard] = useState('');
  const [expiry, setExpiry] = useState('');
  const [cvc, setCvc] = useState('');
  const [holder, setHolder] = useState('');

  useEffect(() => {
    if (typeof window !== 'undefined' && !window.localStorage.getItem('token')) {
      router.push('/login');
      return;
    }
    if (bundleIds && bundleIds.length > 0) {
      Promise.all(bundleIds.map((id) => api.getOrder(id)))
        .then((list) => { setOrders(list); setOrder(list[0]); })
        .catch((e) => setError(e.message));
    } else {
      api.getOrder(params.orderId).then(setOrder).catch((e) => setError(e.message));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [params.orderId, router, bundleParam]);

  const currency = order?.currency ?? 'TRY';
  const totalMinor = orders ? orders.reduce((s, o) => s + (o.amountMinorUnit ?? 0), 0) : order?.amountMinorUnit ?? 0;
  const amountLabel = order
    ? `${(totalMinor / 100).toLocaleString(t.locale, { minimumFractionDigits: 2 })} ${CURRENCY_LABEL[currency] ?? currency}`
    : '…';
  const isBundle = !!orders && orders.length > 1;

  function fmtCard(v: string) {
    return v.replace(/\D/g, '').slice(0, 16).replace(/(.{4})/g, '$1 ').trim();
  }
  function fmtExpiry(v: string) {
    const d = v.replace(/\D/g, '').slice(0, 4);
    return d.length >= 3 ? `${d.slice(0, 2)}/${d.slice(2)}` : d;
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    // ASLA paid yapmaz — yalnızca bilgilendirme. Hiçbir API/paid çağrısı YOK.
    setSubmitted(true);
  }

  if (error) {
    return (
      <main className="container-page max-w-lg py-16">
        <div className="card p-6 text-sm text-red-600">{t.notFound(error)}</div>
      </main>
    );
  }

  return (
    <main className="container-page max-w-lg py-10">
      {/* Test ortamı bildirimi (net, dürüst) */}
      <div className="mb-5 rounded-card border border-amber-300/70 bg-amber-50 px-4 py-3 text-xs text-ink-soft">
        {t.sandbox}
      </div>

      <div className="overflow-hidden rounded-card border border-line bg-white shadow-sm">
        {/* Başlık şeridi */}
        <div className="flex items-center justify-between border-b border-line bg-brand-50/50 px-5 py-3">
          <span className="inline-flex items-center gap-1.5 text-sm font-semibold text-brand">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden>
              <path d="M12 2l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V5l7-3z" fill="#123F3A" />
              <path d="M9 12l2 2 4-4" stroke="#F5A623" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" fill="none" />
            </svg>
            {t.secure}
          </span>
          <img src="/iyzico/iyzico_ile_ode_colored_horizontal.svg" alt={t.payWithIyzico} className="h-6 w-auto max-w-full" width={210} height={31} />
        </div>

        {/* Sipariş özeti */}
        <div className="flex items-baseline justify-between border-b border-line px-5 py-4">
          <div>
            <div className="text-xs text-ink-muted">{t.amountToPay}</div>
            {isBundle ? (
              <div className="text-sm text-ink-soft">
                {t.bundle(orders!.length)}
                {order?.domain?.hostname && <> · {order.domain.hostname}</>}
              </div>
            ) : (
              order?.domain?.hostname && <div className="text-sm text-ink-soft">{t.singleScan(order.domain.hostname)}</div>
            )}
          </div>
          <div className="text-right">
            <div className="text-2xl font-extrabold text-brand">{amountLabel}</div>
            <div className="text-[11px] text-ink-muted">{t.vat}</div>
          </div>
        </div>

        {/* Kart formu */}
        <form onSubmit={handleSubmit} className="space-y-4 px-5 py-5">
          <div>
            <label className="label">{t.holder}</label>
            <input className="field" placeholder={t.holderPh} value={holder} onChange={(e) => setHolder(e.target.value)} autoComplete="off" />
          </div>
          <div>
            <label className="label">{t.cardNo}</label>
            <input className="field font-mono" inputMode="numeric" placeholder="0000 0000 0000 0000" value={card} onChange={(e) => setCard(fmtCard(e.target.value))} autoComplete="off" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="label">{t.expiry}</label>
              <input className="field font-mono" inputMode="numeric" placeholder={t.expiryPh} value={expiry} onChange={(e) => setExpiry(fmtExpiry(e.target.value))} autoComplete="off" />
            </div>
            <div>
              <label className="label">{t.cvc}</label>
              <input className="field font-mono" inputMode="numeric" placeholder="000" value={cvc} onChange={(e) => setCvc(e.target.value.replace(/\D/g, '').slice(0, 4))} autoComplete="off" />
            </div>
          </div>

          {submitted && (
            <div className="rounded-card border border-accent/40 bg-accent-soft/40 px-4 py-3 text-sm text-ink-soft">
              {t.submitted}
            </div>
          )}

          <button type="submit" className="btn-primary w-full">
            {t.pay(amountLabel)}
          </button>

          {/* Kart şeması rozetleri (Visa/Mastercard/Troy) */}
          <div className="flex items-center justify-center gap-3 pt-1">
            <img src="/iyzico/logo_band_colored.svg" alt="Visa, Mastercard, Troy" className="h-auto w-auto max-w-full" width={456} height={32} />
          </div>
          <p className="text-center text-[11px] text-ink-muted">
            {t.stored}
          </p>
        </form>
      </div>
    </main>
  );
}
