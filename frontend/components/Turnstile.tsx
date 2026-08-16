'use client';

import { forwardRef, useEffect, useImperativeHandle, useRef } from 'react';

// Cloudflare Turnstile SITE key. Gerçek key .env'de (NEXT_PUBLIC_TURNSTILE_SITE_KEY); bossa TEST key.
const SITE_KEY = process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY || '1x00000000000000000000AA';

declare global {
  interface Window { turnstile?: any }
}

let scriptLoading = false;

export type TurnstileHandle = { reset: () => void };

/**
 * Yeniden kullanılabilir Turnstile widget'ı (bot doğrulaması). GÖRÜNÜR bir kutu render eder; çözülünce
 * `onToken(token)` çağırır (süresi dolunca/hata olunca null). Parent, token gelene kadar submit'i
 * KİLİTLEMELİDİR (aksi halde token'sız istek 403 → "kutucuk yok" hissi). ref.reset() ile tek-kullanımlık
 * token yenilenir (tarama sonrası).
 */
export const Turnstile = forwardRef<TurnstileHandle, { onToken: (t: string | null) => void; action?: string }>(
  function Turnstile({ onToken, action }, ref) {
    const host = useRef<HTMLDivElement>(null);
    const widgetId = useRef<string | null>(null);
    const onTokenRef = useRef(onToken);
    onTokenRef.current = onToken;

    useImperativeHandle(ref, () => ({
      reset() {
        if (window.turnstile && widgetId.current) {
          try { window.turnstile.reset(widgetId.current); } catch { /* */ }
        }
      },
    }));

    useEffect(() => {
      let cancelled = false;
      function render() {
        if (cancelled || !window.turnstile || !host.current || widgetId.current) return;
        try {
          widgetId.current = window.turnstile.render(host.current, {
            sitekey: SITE_KEY,
            action,
            theme: 'auto',
            callback: (t: string) => onTokenRef.current(t),
            'expired-callback': () => onTokenRef.current(null),
            'timeout-callback': () => onTokenRef.current(null),
            'error-callback': () => onTokenRef.current(null),
          });
        } catch { /* çift render koruması */ }
      }

      if (window.turnstile) {
        render();
      } else {
        if (!document.getElementById('cf-turnstile-script') && !scriptLoading) {
          scriptLoading = true;
          const s = document.createElement('script');
          s.id = 'cf-turnstile-script';
          s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js';
          s.async = true;
          s.defer = true;
          document.head.appendChild(s);
        }
        const iv = setInterval(() => {
          if (window.turnstile) { clearInterval(iv); render(); }
        }, 150);
        return () => { cancelled = true; clearInterval(iv); };
      }
      return () => {
        cancelled = true;
        if (window.turnstile && widgetId.current) {
          try { window.turnstile.remove(widgetId.current); } catch { /* */ }
          widgetId.current = null;
        }
      };
    }, [action]);

    return <div ref={host} className="min-h-[65px]" />;
  },
);
