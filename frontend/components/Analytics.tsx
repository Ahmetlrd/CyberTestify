'use client';

import Script from 'next/script';
import { useEffect } from 'react';
import { usePathname, useSearchParams } from 'next/navigation';
import { GA_ID, getStoredConsent } from '../lib/consent';

/**
 * (GA4 + Google Consent Mode v2) gtag.js — YALNIZ NEXT_PUBLIC_GA_MEASUREMENT_ID setliyse yüklenir
 * (boşsa hiç render edilmez, site hata vermez). KVKK: Consent Mode VARSAYILAN = denied → onay öncesi
 * hiçbir izleme çerezi yazılmaz (yalnız çerezsiz/modellenmiş sinyal). Onay verilince CookieBanner
 * gtag('consent','update','granted') çağırır. SPA route değişiminde manuel page_view atılır.
 */
export function Analytics() {
  const pathname = usePathname();
  const searchParams = useSearchParams();

  // Geri dönen kullanıcı: daha önce 'granted' seçtiyse consent'i erkenden yükselt.
  useEffect(() => {
    if (!GA_ID) return;
    if (getStoredConsent() === 'granted') {
      (window as any).gtag?.('consent', 'update', {
        ad_storage: 'granted', analytics_storage: 'granted', ad_user_data: 'granted', ad_personalization: 'granted',
      });
    }
  }, []);

  // SPA istemci-tarafı navigasyonda page_view (ilk yükleme config ile otomatik gelir).
  useEffect(() => {
    if (!GA_ID || typeof window === 'undefined' || !(window as any).gtag) return;
    const qs = searchParams?.toString();
    (window as any).gtag('event', 'page_view', {
      page_path: pathname + (qs ? `?${qs}` : ''),
      page_location: window.location.href,
      page_title: document.title,
    });
  }, [pathname, searchParams]);

  if (!GA_ID) return null;

  return (
    <>
      {/* Consent Mode default DENIED — İLK HTML'de (beforeInteractive), gtag.js'ten ÖNCE çalışır.
          KVKK: onay öncesi hiçbir izleme çerezi yazılmaz. */}
      <Script
        id="ga-consent-init"
        strategy="beforeInteractive"
        dangerouslySetInnerHTML={{
          __html: `
            window.dataLayer = window.dataLayer || [];
            function gtag(){dataLayer.push(arguments);}
            window.gtag = gtag;
            gtag('consent','default',{ad_storage:'denied',analytics_storage:'denied',ad_user_data:'denied',ad_personalization:'denied',wait_for_update:500});
            gtag('js', new Date());
            gtag('config','${GA_ID}',{anonymize_ip:true});
          `,
        }}
      />
      <Script src={`https://www.googletagmanager.com/gtag/js?id=${GA_ID}`} strategy="afterInteractive" />
    </>
  );
}
