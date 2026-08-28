'use client';

import { usePathname } from 'next/navigation';
import { openCookiePrefs, GA_ID, CLARITY_ID } from '../lib/consent';
import { readRegionCookie } from '../lib/region';
import { getRegion, REGION_CODES } from '../config/regions';

/** Footer "Çerez tercihleri" — kullanıcı onay kararını sonradan değiştirsin (banner'ı yeniden açar). */
export function CookiePrefsButton({ className }: { className?: string }) {
  // (BUG DÜZELTME) Etiket dilini URL'den TÜRET (bölge değişince footer yeniden render edilmediğinden
  // eski dilde kalıyordu). URL bölge-önekli değilse cookie'ye düş. Footer/Nav/CookieBanner ile aynı desen.
  const pathname = usePathname();
  const seg = (pathname ?? '/').split('/')[1] ?? '';
  const lg = (REGION_CODES as readonly string[]).includes(seg) ? getRegion(seg).lang : getRegion(readRegionCookie()).lang;
  const lang: 'tr' | 'de' | 'en' = lg === 'de' ? 'de' : lg === 'en' ? 'en' : 'tr';
  if (!GA_ID && !CLARITY_ID) return null; // izleme yoksa tercih ayarına gerek yok
  return (
    <button type="button" onClick={openCookiePrefs} className={className}>
      {lang === 'de' ? 'Cookie-Einstellungen' : lang === 'en' ? 'Cookie settings' : 'Çerez tercihleri'}
    </button>
  );
}
