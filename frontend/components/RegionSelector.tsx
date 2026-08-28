'use client';

import { useState } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import { REGIONS, REGION_CODES, VISIBLE_REGION_CODES, type RegionCode } from '../config/regions';

export function RegionSelector({ current }: { current: RegionCode }) {
  const router = useRouter();
  const pathname = usePathname();
  const [open, setOpen] = useState(false);

  // (BUG DÜZELTME) `current` prop'u KÖK layout'ta cookie'den okunur; kök layout client-navigasyonda
  // YENİDEN RENDER EDİLMEZ → router.push('/de') sonrası sayfa güncellenir ama seçicideki bölge ESKİ kalır.
  // Çözüm: bölge-önekli sayfalarda (/tr, /de/...) görünen bölgeyi URL'den TÜRET (kaynak-doğru); yoksa
  // (cookie-tabanlı sayfa; zaten reload ediliyor) prop'a düş. Böylece usePathname değişince seçici tazelenir.
  const seg = (pathname ?? '/').split('/')[1] ?? '';
  const active: RegionCode = (REGION_CODES as readonly string[]).includes(seg) ? (seg as RegionCode) : current;
  const cur = REGIONS[active];

  // GEÇİCİ: Tek görünür bölge (TR) varken bölge seçici gösterilmez. Görünür bölge
  // sayısı >1 olunca (us/ae açılınca) seçici otomatik geri gelir.
  if (VISIBLE_REGION_CODES.length <= 1) return null;

  function choose(code: RegionCode) {
    document.cookie = `region=${code}; path=/; max-age=${60 * 60 * 24 * 365}`;
    setOpen(false);
    // (UX) Bölge değiştirmek OTURUMU/SAYFAYI KAYBETTİRMEZ. Token localStorage'da kalır.
    // - URL'de bölge segmenti olan sayfalar (/tr/paketler …) → AYNI alt-yolda yeni bölgeye geç.
    // - Bölge'yi cookie'den okuyan sayfalar (/verify, /profile, /dashboard, /login …) → YERİNDE
    //   kal, yalnız server-component'leri yeni cookie ile tazele (homepage'e ATMA → "logout" hissi yok).
    const seg = (pathname ?? '/').split('/')[1] ?? '';
    if ((REGION_CODES as readonly string[]).includes(seg)) {
      const rest = (pathname ?? '').slice(seg.length + 1); // '/tr/paketler' → '/paketler'
      router.push(`/${code}${rest}`);
    } else {
      // Cookie-tabanlı sayfa (çoğu client component dili mount'ta cookie'den okur): YERİNDE tam
      // yenile → dil güncellenir, token localStorage'da KALIR (logout YOK, homepage'e atma YOK).
      window.location.reload();
    }
  }

  return (
    <div className="relative">
      <button
        onClick={() => setOpen((o) => !o)}
        className="inline-flex items-center gap-1.5 rounded-pill border border-line bg-white px-2.5 py-1.5 text-xs font-medium text-ink-soft transition hover:border-brand-300"
        aria-haspopup="listbox"
        aria-expanded={open}
      >
        {cur.flag} {cur.code.toUpperCase()}
        <svg viewBox="0 0 24 24" className="h-3 w-3" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M6 9l6 6 6-6" />
        </svg>
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} />
          <ul className="absolute right-0 z-50 mt-2 w-48 overflow-hidden rounded-card border border-line bg-white py-1 shadow-card" role="listbox">
            {VISIBLE_REGION_CODES.map((code) => {
              const r = REGIONS[code];
              return (
                <li key={code}>
                  <button
                    onClick={() => choose(code)}
                    className={`flex w-full items-center gap-2 px-3.5 py-2 text-left text-sm hover:bg-brand-50 ${
                      code === active ? 'font-semibold text-brand' : 'text-ink-soft'
                    }`}
                    role="option"
                    aria-selected={code === active}
                  >
                    <span>{r.flag}</span>
                    <span>{r.label}</span>
                    <span className="ml-auto text-xs text-ink-muted">{r.currency}</span>
                  </button>
                </li>
              );
            })}
          </ul>
        </>
      )}
    </div>
  );
}
