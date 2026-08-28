'use client';

import Script from 'next/script';
import { useEffect } from 'react';
import { usePathname, useSearchParams } from 'next/navigation';
import { GA_ID, loadClarity } from '../lib/consent';
import { trackEvent } from '../lib/analytics';
import { REGION_CODES } from '../config/regions';

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

  // (GA4 ikincil — gözlem) Fiyat sayfası görüntüleme: /{bölge}/packages'a her gelişte TEK sefer.
  // pathname'e bağlı → SPA'de doğru sayfaya girişte bir kez; query değişimi TEKRAR tetiklemez.
  useEffect(() => {
    if (!GA_ID) return;
    const seg = (pathname ?? '/').split('/');
    if (seg[2] === 'packages' && (REGION_CODES as readonly string[]).includes(seg[1])) {
      trackEvent('view_pricing', { region: seg[1] });
    }
  }, [pathname]);

  // (GA4 ikincil — gözlem) Örnek rapor görüntüleme: tüm site genelindeki sample-report linklerine
  // DELEGE tıklama dinleyicisi (tek yer, her anchor'ı yakalar). Paket anahtarı + bölge href'ten
  // türetilir — PII YOK. capture:true ki target=_blank yeni sekme açmadan önce yakalansın.
  useEffect(() => {
    if (!GA_ID || typeof document === 'undefined') return;
    const onClick = (e: MouseEvent) => {
      const a = (e.target as HTMLElement | null)?.closest?.('a[href*="/orders/sample-report/"]') as HTMLAnchorElement | null;
      if (!a) return;
      const href = a.getAttribute('href') || '';
      const pkg = href.match(/\/orders\/sample-report\/([^/?#]+)/)?.[1];
      const region = href.match(/[?&]region=([a-z]{2})/)?.[1];
      trackEvent('view_sample_report', { package: pkg ? decodeURIComponent(pkg) : undefined, region });
    };
    document.addEventListener('click', onClick, true);
    return () => document.removeEventListener('click', onClick, true);
  }, []);

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
