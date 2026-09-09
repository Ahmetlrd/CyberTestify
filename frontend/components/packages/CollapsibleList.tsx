'use client';
import { useState, type ReactNode } from 'react';

// (Paket İÇİNDEKİLER) Uzun kontrol listesini görsel olarak kısaltır: ilk N madde + "+X kontrol daha"
// (tıklanınca açılır). Salt-görsel özet — verinin tamamı DOM'da, açılınca hepsi + ek notlar görünür.
export function CollapsibleList({
  items,
  collapsedCount,
  moreLabel,
  lessLabel,
  dark,
  children,
}: {
  items: string[];
  collapsedCount: number;
  moreLabel: (n: number) => string;
  lessLabel: string;
  dark?: boolean;
  children?: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const shown = open ? items : items.slice(0, collapsedCount);
  const hidden = Math.max(0, items.length - collapsedCount);
  const link = dark ? 'text-accent hover:text-amber-200' : 'text-accent-600 hover:text-accent';
  const chip = dark ? 'bg-accent/25 text-accent' : 'bg-brand-50 text-brand';
  return (
    <>
      <ul className="mt-1.5 space-y-1.5">
        {shown.map((it) => (
          <li key={it} className="flex gap-2">
            <span aria-hidden className={`mt-px flex h-4 w-4 shrink-0 items-center justify-center rounded-full text-[9px] font-bold ${chip}`}>✓</span>
            <span>{it}</span>
          </li>
        ))}
      </ul>
      {hidden > 0 && (
        <button type="button" onClick={() => setOpen((v) => !v)} className={`mt-2 text-[11px] font-semibold underline-offset-2 hover:underline ${link}`}>
          {open ? lessLabel : moreLabel(hidden)}
        </button>
      )}
      {open && children}
    </>
  );
}
