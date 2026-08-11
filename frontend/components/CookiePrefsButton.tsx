'use client';

import { openCookiePrefs, GA_ID } from '../lib/consent';

/** Footer "Çerez tercihleri" — kullanıcı onay kararını sonradan değiştirsin (banner'ı yeniden açar). */
export function CookiePrefsButton({ className }: { className?: string }) {
  if (!GA_ID) return null; // izleme yoksa tercih ayarına gerek yok
  return (
    <button type="button" onClick={openCookiePrefs} className={className}>
      Çerez tercihleri
    </button>
  );
}
