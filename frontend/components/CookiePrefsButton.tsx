'use client';

import { useEffect, useState } from 'react';
import { openCookiePrefs, GA_ID, CLARITY_ID } from '../lib/consent';
import { readRegionCookie } from '../lib/region';
import { getRegion } from '../config/regions';

/** Footer "Çerez tercihleri" — kullanıcı onay kararını sonradan değiştirsin (banner'ı yeniden açar). */
export function CookiePrefsButton({ className }: { className?: string }) {
  // (Çok-bölge) /de → Almanca etiket ("Cookie-Einstellungen").
  const [lang, setLang] = useState<'tr' | 'de'>('tr');
  useEffect(() => {
    setLang(getRegion(readRegionCookie()).lang === 'de' ? 'de' : 'tr');
  }, []);
  if (!GA_ID && !CLARITY_ID) return null; // izleme yoksa tercih ayarına gerek yok
  return (
    <button type="button" onClick={openCookiePrefs} className={className}>
      {lang === 'de' ? 'Cookie-Einstellungen' : 'Çerez tercihleri'}
    </button>
  );
}
