'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { applyConsent, getStoredConsent, loadClarity, GA_ID, CLARITY_ID, OPEN_PREFS_EVENT } from '../lib/consent';

/**
 * (KVKK) Çerez onay banner'ı + Google Consent Mode v2.
 *
 * - İlk açılışta seçim yapılmadıysa gösterilir. GA yüklüyse Consent Mode VARSAYILAN denied'dır
 *   (bkz Analytics.tsx) → onay öncesi izleme çerezi YAZILMAZ.
 * - "Kabul Et" → consent 'granted' (analytics + ads çerezleri açılır). "Reddet" → 'denied' kalır.
 * - Seçim localStorage'da saklanır (tekrar sorulmaz). Footer "Çerez tercihleri" ile yeniden açılır.
 */
export function CookieBanner() {
  const [show, setShow] = useState(false);

  useEffect(() => {
    const stored = getStoredConsent();
    if (!stored) setShow(true);            // seçim yoksa göster
    if (stored === 'granted') loadClarity(); // geri dönen kullanıcı: onay verdiyse Clarity'yi yükle
    const reopen = () => setShow(true);
    window.addEventListener(OPEN_PREFS_EVENT, reopen);
    return () => window.removeEventListener(OPEN_PREFS_EVENT, reopen);
  }, []);

  if (!show) return null;

  const choose = (state: 'granted' | 'denied') => { applyConsent(state); setShow(false); };

  // GA/Clarity hiç kurulmadıysa yalnız teknik çerez vardır — kısa bilgilendirme (izleme onayı gerekmez).
  const analyticsEnabled = !!GA_ID || !!CLARITY_ID;

  return (
    <div
      role="dialog"
      aria-label="Çerez tercihleri"
      style={{
        position: 'fixed', bottom: 12, left: 12, right: 12, maxWidth: 480, margin: '0 auto',
        background: '#123F3A', color: '#f6f8fa', padding: '16px 18px', borderRadius: 14,
        boxShadow: '0 10px 30px rgba(0,0,0,0.25)', fontSize: 13.5, lineHeight: 1.5, zIndex: 60,
      }}
    >
      <p style={{ margin: 0, fontWeight: 700, marginBottom: 4 }}>Çerezler</p>
      <p style={{ margin: 0, color: 'rgba(255,255,255,0.85)' }}>
        {analyticsEnabled
          ? 'Deneyiminizi ölçmek ve iyileştirmek için çerezler kullanıyoruz. Kabul ederseniz analiz/reklam çerezleri çalışır; reddederseniz yalnızca zorunlu teknik çerezler kalır.'
          : 'Bu site, hizmetin çalışması için gerekli zorunlu teknik çerezleri kullanır.'}{' '}
        <Link href="/legal/cerez" style={{ color: '#F5C97B', textDecoration: 'underline' }}>Çerez Politikası</Link>
      </p>
      <div style={{ display: 'flex', gap: 8, marginTop: 12, flexWrap: 'wrap' }}>
        {analyticsEnabled ? (
          <>
            <button
              onClick={() => choose('granted')}
              style={{ flex: 1, minWidth: 120, padding: '9px 14px', borderRadius: 9, border: 'none', background: '#F5A623', color: '#123F3A', fontWeight: 800, cursor: 'pointer' }}
            >Kabul Et</button>
            <button
              onClick={() => choose('denied')}
              style={{ flex: 1, minWidth: 120, padding: '9px 14px', borderRadius: 9, border: '1px solid rgba(255,255,255,0.35)', background: 'transparent', color: '#f6f8fa', fontWeight: 700, cursor: 'pointer' }}
            >Reddet</button>
          </>
        ) : (
          <button
            onClick={() => choose('denied')}
            style={{ flex: 1, padding: '9px 14px', borderRadius: 9, border: 'none', background: '#F5A623', color: '#123F3A', fontWeight: 800, cursor: 'pointer' }}
          >Tamam</button>
        )}
      </div>
    </div>
  );
}
