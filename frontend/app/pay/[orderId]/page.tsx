'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { api } from '../../../lib/api';
import { readRegionCookie } from '../../../lib/region';
import { getRegion } from '../../../config/regions';

/**
 * ÖDEME BAŞLATILAMADI ekranı.
 *
 * ESKİDEN: burada GÖRSEL bir kart formu vardı ("test/sandbox ortamı — gerçek tahsilat yapılmaz").
 * iyzico anahtarları yokken backend buraya düşürüyordu. Artık iyzico TR/EUR/GBP için CANLI ve tüm
 * akışlar gerçek ödeme sayfasına gidiyor → buraya düşmek ARTIK BİR HATA DURUMUDUR.
 * Sahte kart formu göstermek tehlikeliydi (kullanıcı gerçek kart bilgisini işlenmeyen bir forma
 * girebilir) ve reklamdan gelen ziyaretçide güveni yıkıyordu. Onun yerine dürüst hata + çıkış yolu.
 */
const T = {
  tr: {
    title: 'Ödeme başlatılamadı',
    body: 'Ödeme sayfasına yönlendirme şu an tamamlanamadı. Kartınızdan herhangi bir tahsilat yapılmadı ve siparişiniz açık kaldı.',
    what: 'Ne yapabilirsiniz:',
    retry: 'Panelinizden siparişi açıp ödemeyi yeniden başlatın.',
    contact: 'Sorun sürerse aşağıdaki adresten bize yazın; siparişinizi biz tamamlayalım.',
    cta: 'Siparişime dön',
    order: 'Sipariş no',
  },
  de: {
    title: 'Zahlung konnte nicht gestartet werden',
    body: 'Die Weiterleitung zur Zahlungsseite konnte derzeit nicht abgeschlossen werden. Es wurde nichts von Ihrer Karte abgebucht und Ihre Bestellung bleibt offen.',
    what: 'Was Sie tun können:',
    retry: 'Öffnen Sie die Bestellung in Ihrem Dashboard und starten Sie die Zahlung erneut.',
    contact: 'Falls das Problem bestehen bleibt, schreiben Sie uns an die folgende Adresse; wir schließen Ihre Bestellung ab.',
    cta: 'Zurück zur Bestellung',
    order: 'Bestellnummer',
  },
  en: {
    title: 'Payment could not be started',
    body: 'The redirect to the payment page could not be completed right now. Nothing has been charged to your card and your order is still open.',
    what: 'What you can do:',
    retry: 'Open the order in your dashboard and start the payment again.',
    contact: 'If the problem persists, email us at the address below and we will complete your order.',
    cta: 'Back to my order',
    order: 'Order number',
  },
} as const;

export default function PayPage({ params }: { params: { orderId: string } }) {
  const router = useRouter();
  const [lang, setLang] = useState<'tr' | 'de' | 'en'>('tr');
  useEffect(() => { const l = getRegion(readRegionCookie()).lang; setLang(l === 'de' ? 'de' : l === 'en' ? 'en' : 'tr'); }, []);
  const t = T[lang];

  useEffect(() => {
    if (typeof window !== 'undefined' && !window.localStorage.getItem('token')) router.push('/login');
  }, [router]);

  // Sipariş gerçekten var mı (yoksa panele yönlendir) — kart verisi İSTENMEZ, hiçbir ödeme çağrısı YOK.
  const [exists, setExists] = useState<boolean | null>(null);
  useEffect(() => {
    api.getOrder(params.orderId).then(() => setExists(true)).catch(() => setExists(false));
  }, [params.orderId]);

  return (
    <main className="container-page max-w-lg py-16">
      <div className="card p-7">
        <span className="flex h-12 w-12 items-center justify-center rounded-full bg-amber-50">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#b45309" strokeWidth="2" strokeLinecap="round" aria-hidden>
            <path d="M12 8v5" /><path d="M12 16.5v.01" /><circle cx="12" cy="12" r="9" />
          </svg>
        </span>
        <h1 className="mt-4 text-xl font-extrabold text-brand">{t.title}</h1>
        <p className="mt-2 text-sm leading-relaxed text-ink-soft">{t.body}</p>

        <p className="mt-5 text-xs font-bold uppercase tracking-wide text-ink-muted">{t.what}</p>
        <ul className="mt-2 space-y-1.5 text-sm text-ink-soft">
          <li>• {t.retry}</li>
          <li>
            • {t.contact}{' '}
            <a href="mailto:support@cybertestify.com" className="font-semibold text-accent-600 underline">support@cybertestify.com</a>
          </li>
        </ul>

        <p className="mt-5 text-xs text-ink-muted">{t.order}: <span className="font-mono">{params.orderId}</span></p>

        {exists !== false && (
          <Link href={`/dashboard/${params.orderId}`} className="btn-primary mt-6 w-full justify-center">{t.cta}</Link>
        )}
        <Link href="/verify" className="btn-outline mt-3 w-full justify-center">{lang === 'de' ? 'Zum Dashboard' : lang === 'en' ? 'Go to dashboard' : 'Panelime git'}</Link>
      </div>
    </main>
  );
}
