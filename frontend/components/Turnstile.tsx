'use client';

import { forwardRef, useEffect, useImperativeHandle, useRef } from 'react';
import { readRegionCookie } from '../lib/region';
import { getRegion } from '../config/regions';

// Cloudflare Turnstile SITE key. Gerçek key .env'de (NEXT_PUBLIC_TURNSTILE_SITE_KEY); bossa TEST key.
const SITE_KEY = process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY || '1x00000000000000000000AA';

declare global {
  interface Window { turnstile?: any }
}

let scriptLoading = false;

export type TurnstileStatus = 'loading' | 'ready' | 'error';
export type TurnstileHandle = { reset: () => void; retry: () => void };

/**
 * Yeniden kullanılabilir Turnstile widget'ı (bot doğrulaması). Normalde GÖRÜNMEZ (interaction-only).
 * Çözülünce `onToken(token)`; süresi dolunca/hata olunca token null. `onStatus` ile parent'a durum
 * ('loading'|'ready'|'error') bildirilir; parent hata halinde "tekrar dene" gösterebilir.
 *
 * DAYANIKLILIK: Görünmez akış takılırsa (script bloklandı / timeout / error / expiry) kullanıcı sonsuza
 * dek "bekliyor"da kalmasın diye:
 *  - script yüklenemezse → onStatus('error')
 *  - callback watchdog (token gelmezse) → onStatus('error')
 *  - error/timeout → GÖRÜNÜR checkbox'a (appearance:'always') düşülür + onStatus('error')
 *  - expiry → sessizce reset (yeni token)
 *  - ref.retry() → görünür moda geçip yeniden dener (script yoksa sayfayı yeniler)
 */
export const Turnstile = forwardRef<TurnstileHandle, { onToken: (t: string | null) => void; onStatus?: (s: TurnstileStatus) => void; action?: string }>(
  function Turnstile({ onToken, onStatus, action }, ref) {
    const host = useRef<HTMLDivElement>(null);
    const widgetId = useRef<string | null>(null);
    const onTokenRef = useRef(onToken);
    onTokenRef.current = onToken;
    const onStatusRef = useRef(onStatus);
    onStatusRef.current = onStatus;
    const forceVisible = useRef(false); // hata sonrası görünür checkbox'a düş
    const gotToken = useRef(false);

    function doRender() {
      if (!window.turnstile || !host.current) return;
      if (widgetId.current) {
        try { window.turnstile.remove(widgetId.current); } catch { /* */ }
        widgetId.current = null;
      }
      try {
        const lg = getRegion(readRegionCookie()).lang;
        onStatusRef.current?.('loading');
        widgetId.current = window.turnstile.render(host.current, {
          sitekey: SITE_KEY,
          action,
          theme: 'auto',
          // Normal: görünmez; hata sonrası: görünür checkbox (kullanıcı elle çözsün)
          appearance: forceVisible.current ? 'always' : 'interaction-only',
          language: lg === 'de' ? 'de' : lg === 'en' ? 'en' : 'tr',

          callback: (t: string) => { gotToken.current = true; onStatusRef.current?.('ready'); onTokenRef.current(t); },
          'expired-callback': () => {
            gotToken.current = false; onTokenRef.current(null);
            try { window.turnstile.reset(widgetId.current); onStatusRef.current?.('loading'); } catch { /* */ }
          },
          'timeout-callback': () => { onTokenRef.current(null); fail(); },
          'error-callback': () => { onTokenRef.current(null); fail(); },
        });
      } catch { /* çift render koruması */ }
    }

    // Görünmez akış çalışmadı → hata bildir + görünür checkbox'a düş (tek sefer)
    function fail() {
      onStatusRef.current?.('error');
      if (!forceVisible.current) { forceVisible.current = true; doRender(); }
    }

    useImperativeHandle(ref, () => ({
      reset() {
        if (window.turnstile && widgetId.current) {
          try { window.turnstile.reset(widgetId.current); } catch { /* */ }
        }
      },
      retry() {
        forceVisible.current = true;
        gotToken.current = false;
        if (window.turnstile) doRender();
        else if (typeof window !== 'undefined') window.location.reload();
      },
    }));

    useEffect(() => {
      let cancelled = false;

      if (!window.turnstile) {
        if (!document.getElementById('cf-turnstile-script') && !scriptLoading) {
          scriptLoading = true;
          const s = document.createElement('script');
          s.id = 'cf-turnstile-script';
          s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js';
          s.async = true;
          s.defer = true;
          s.onerror = () => { scriptLoading = false; if (!cancelled) onStatusRef.current?.('error'); };
          document.head.appendChild(s);
        }
      }

      const iv = setInterval(() => {
        if (window.turnstile && !widgetId.current && !cancelled) { clearInterval(iv); doRender(); }
      }, 150);

      // Watchdog: 9sn içinde token gelmezse (script bloklandı / sessiz takılma) → hata + görünür fallback
      const wd = setTimeout(() => { if (!cancelled && !gotToken.current) fail(); }, 9000);

      return () => {
        cancelled = true;
        clearInterval(iv);
        clearTimeout(wd);
        if (window.turnstile && widgetId.current) {
          try { window.turnstile.remove(widgetId.current); } catch { /* */ }
          widgetId.current = null;
        }
      };
    }, [action]);

    return <div ref={host} className="empty:hidden" />;
  },
);
