'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';

/**
 * Minimal cerez riza banner'i. Su an site yalnizca teknik/zorunlu cerez
 * (oturum tokeni localStorage) kullaniyor; izleyici/analitik cerez eklenirse
 * bu banner rizadan ONCE onlari yuklememelidir (KVKK).
 */
export function CookieBanner() {
  const [show, setShow] = useState(false);

  useEffect(() => {
    if (typeof window !== 'undefined' && !window.localStorage.getItem('cookieConsent')) {
      setShow(true);
    }
  }, []);

  if (!show) return null;

  function accept() {
    window.localStorage.setItem('cookieConsent', '1');
    setShow(false);
  }

  return (
    <div
      style={{
        position: 'fixed',
        bottom: 0,
        left: 0,
        right: 0,
        background: '#1f2328',
        color: '#f6f8fa',
        padding: '12px 16px',
        fontSize: 13,
        display: 'flex',
        gap: 12,
        alignItems: 'center',
        justifyContent: 'center',
        flexWrap: 'wrap',
        zIndex: 50,
      }}
    >
      <span>
        Bu site, hizmetin çalışması için gerekli teknik çerezleri kullanır. Ayrıntılar için{' '}
        <Link href="/legal/cerez" style={{ color: '#79c0ff' }}>
          Çerez Politikası
        </Link>
        .
      </span>
      <button onClick={accept} style={{ padding: '6px 14px' }}>
        Tamam
      </button>
    </div>
  );
}
