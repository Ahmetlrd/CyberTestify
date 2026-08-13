'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { REGIONS, VISIBLE_REGION_CODES, type RegionCode } from '../config/regions';

export function RegionSelector({ current }: { current: RegionCode }) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const cur = REGIONS[current];

  // GEÇİCİ: Tek görünür bölge (TR) varken bölge seçici gösterilmez. Görünür bölge
  // sayısı >1 olunca (us/ae açılınca) seçici otomatik geri gelir.
  if (VISIBLE_REGION_CODES.length <= 1) return null;

  function choose(code: RegionCode) {
    document.cookie = `region=${code}; path=/; max-age=${60 * 60 * 24 * 365}`;
    setOpen(false);
    router.push(`/${code}`);
    router.refresh();
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
                      code === current ? 'font-semibold text-brand' : 'text-ink-soft'
                    }`}
                    role="option"
                    aria-selected={code === current}
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
