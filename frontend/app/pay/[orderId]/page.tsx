'use client';

import { useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { api } from '../../../lib/api';

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
    ? `${(totalMinor / 100).toLocaleString('tr-TR', { minimumFractionDigits: 2 })} ${currency === 'TRY' ? 'TL' : currency}`
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
        <div className="card p-6 text-sm text-red-600">Sipariş bulunamadı: {error}</div>
      </main>
    );
  }

  return (
    <main className="container-page max-w-lg py-10">
      {/* Test ortamı bildirimi (net, dürüst) */}
      <div className="mb-5 rounded-card border border-amber-300/70 bg-amber-50 px-4 py-3 text-xs text-ink-soft">
        <strong>Test / sandbox ortamı.</strong> Ödeme altyapımız (iyzico) yapılandırma aşamasındadır; canlıya
        geçtiğinde bu ekranda gerçek kart ödemesi alınacaktır. Bu sayfada girilen bilgilerle{' '}
        <strong>gerçek bir tahsilat yapılmaz</strong>.
      </div>

      <div className="overflow-hidden rounded-card border border-line bg-white shadow-sm">
        {/* Başlık şeridi */}
        <div className="flex items-center justify-between border-b border-line bg-brand-50/50 px-5 py-3">
          <span className="inline-flex items-center gap-1.5 text-sm font-semibold text-brand">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden>
              <path d="M12 2l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V5l7-3z" fill="#123F3A" />
              <path d="M9 12l2 2 4-4" stroke="#F5A623" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" fill="none" />
            </svg>
            Güvenli Ödeme (256-bit SSL)
          </span>
          <img src="/iyzico/iyzico_ile_ode_colored_horizontal.svg" alt="iyzico ile Öde" className="h-6 w-auto max-w-full" width={210} height={31} />
        </div>

        {/* Sipariş özeti */}
        <div className="flex items-baseline justify-between border-b border-line px-5 py-4">
          <div>
            <div className="text-xs text-ink-muted">Ödenecek tutar</div>
            {isBundle ? (
              <div className="text-sm text-ink-soft">
                Kombine paket — <strong>{orders!.length} tarama</strong>
                {order?.domain?.hostname && <> · {order.domain.hostname}</>}
              </div>
            ) : (
              order?.domain?.hostname && <div className="text-sm text-ink-soft">{order.domain.hostname} taraması</div>
            )}
          </div>
          <div className="text-right">
            <div className="text-2xl font-extrabold text-brand">{amountLabel}</div>
            <div className="text-[11px] text-ink-muted">KDV Dahildir</div>
          </div>
        </div>

        {/* Kart formu */}
        <form onSubmit={handleSubmit} className="space-y-4 px-5 py-5">
          <div>
            <label className="label">Kart Sahibi</label>
            <input className="field" placeholder="Ad Soyad" value={holder} onChange={(e) => setHolder(e.target.value)} autoComplete="off" />
          </div>
          <div>
            <label className="label">Kart Numarası</label>
            <input className="field font-mono" inputMode="numeric" placeholder="0000 0000 0000 0000" value={card} onChange={(e) => setCard(fmtCard(e.target.value))} autoComplete="off" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="label">Son Kullanma</label>
              <input className="field font-mono" inputMode="numeric" placeholder="AA/YY" value={expiry} onChange={(e) => setExpiry(fmtExpiry(e.target.value))} autoComplete="off" />
            </div>
            <div>
              <label className="label">CVC</label>
              <input className="field font-mono" inputMode="numeric" placeholder="000" value={cvc} onChange={(e) => setCvc(e.target.value.replace(/\D/g, '').slice(0, 4))} autoComplete="off" />
            </div>
          </div>

          {submitted && (
            <div className="rounded-card border border-accent/40 bg-accent-soft/40 px-4 py-3 text-sm text-ink-soft">
              <strong>Ödeme altyapımız yapılandırma aşamasındadır.</strong> Gerçek işlem, iyzico entegrasyonu
              canlıya geçtiğinde aktif olacaktır. Siparişiniz oluşturuldu ancak henüz ödeme alınmadı — bu bir test
              ortamıdır ve tarama başlatılmamıştır.
            </div>
          )}

          <button type="submit" className="btn-primary w-full">
            {amountLabel} Öde
          </button>

          {/* Kart şeması rozetleri (Visa/Mastercard/Troy) */}
          <div className="flex items-center justify-center gap-3 pt-1">
            <img src="/iyzico/logo_band_colored.svg" alt="Visa, Mastercard, Troy" className="h-auto w-auto max-w-full" width={456} height={32} />
          </div>
          <p className="text-center text-[11px] text-ink-muted">
            Kart bilgileriniz iyzico altyapısı ile işlenir; sistemlerimizde saklanmaz.
          </p>
        </form>
      </div>
    </main>
  );
}
