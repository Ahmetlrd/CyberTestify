'use client';

import Script from 'next/script';
import { useEffect } from 'react';
import { usePathname, useSearchParams } from 'next/navigation';
import { GA_ID, loadClarity } from '../lib/consent';

/**
 * (GA4 + Microsoft Clarity) — HER ZAMAN AÇIK. Site sahibinin kararıyla çerez onayı gating'i KALDIRILDI:
 * analitik/ölçüm (GA + Clarity) kabul/ret fark etmeksizin çalışır (Consent Mode varsayılan = granted).
 * GA yalnız NEXT_PUBLIC_GA_MEASUREMENT_ID setliyse yüklenir (boşsa render yok). SPA route değişiminde
 * manuel page_view. Clarity mount'ta yüklenir.
 */
export function Analytics() {
  const pathname = usePathname();
  const searchParams = useSearchParams();

  // Clarity'yi her zaman yükle (onay gerektirmez).
  useEffect(() => { loadClarity(); }, []);

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
      {/* Consent Mode default GRANTED — analitik/reklam çerezleri baştan açık (onay gating'i yok). */}
      <Script
        id="ga-consent-init"
        strategy="beforeInteractive"
        dangerouslySetInnerHTML={{
          __html: `
            window.dataLayer = window.dataLayer || [];
            function gtag(){dataLayer.push(arguments);}
            window.gtag = gtag;
            gtag('consent','default',{ad_storage:'granted',analytics_storage:'granted',ad_user_data:'granted',ad_personalization:'granted'});
            gtag('js', new Date());
            gtag('config','${GA_ID}');
          `,
        }}
      />
      <Script src={`https://www.googletagmanager.com/gtag/js?id=${GA_ID}`} strategy="afterInteractive" />
    </>
  );
}
