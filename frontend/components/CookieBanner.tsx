'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { noticeDismissed, dismissNotice, GA_ID, CLARITY_ID, OPEN_PREFS_EVENT } from '../lib/consent';

/**
 * Çerez BİLGİLENDİRME notu (gating YOK). Analitik/ölçüm (GA + Clarity) her zaman açıktır; bu not
 * yalnızca kullanıcıyı bilgilendirir. "Tamam" ile kapatılır (tekrar gösterilmez), footer'daki
 * "Çerez tercihleri" ile yeniden açılabilir. İzleme aracı hiç kurulmadıysa (env boş) gösterilmez.
 */
export function CookieBanner() {
  const [show, setShow] = useState(false);
  const analyticsEnabled = !!GA_ID || !!CLARITY_ID;

  useEffect(() => {
    if (analyticsEnabled && !noticeDismissed()) setShow(true);
    const reopen = () => setShow(true);
    window.addEventListener(OPEN_PREFS_EVENT, reopen);
    return () => window.removeEventListener(OPEN_PREFS_EVENT, reopen);
  }, [analyticsEnabled]);

  if (!show) return null;

  const close = () => { dismissNotice(); setShow(false); };

  return (
    <div
      role="dialog"
      aria-label="Çerez bilgilendirmesi"
      style={{
        position: 'fixed', bottom: 12, left: 12, right: 12, maxWidth: 460, margin: '0 auto',
        background: '#123F3A', color: '#f6f8fa', padding: '14px 16px', borderRadius: 14,
        boxShadow: '0 10px 30px rgba(0,0,0,0.25)', fontSize: 13.5, lineHeight: 1.5, zIndex: 60,
      }}
    >
      <p style={{ margin: 0, color: 'rgba(255,255,255,0.9)' }}>
        Deneyiminizi iyileştirmek için çerezler kullanıyoruz.{' '}
        <Link href="/legal/cerez" style={{ color: '#F5C97B', textDecoration: 'underline' }}>Çerez Politikası</Link>
      </p>
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 10 }}>
        <button
          onClick={close}
          style={{ padding: '8px 20px', borderRadius: 9, border: 'none', background: '#F5A623', color: '#123F3A', fontWeight: 800, cursor: 'pointer' }}
        >Tamam</button>
      </div>
    </div>
  );
}
