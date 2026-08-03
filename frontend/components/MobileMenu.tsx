'use client';

import { useState } from 'react';
import Link from 'next/link';

/**
 * Mobil (md altı) gezinme menüsü. Nav linkleri desktop'ta `md:flex` ile görünür;
 * mobilde bu hamburger içine taşınır — böylece küçük ekranda hem taşma olmaz hem
 * de "Nasıl çalışır / Neden biz / Paketler" erişilebilir kalır.
 */
export function MobileMenu({
  links,
  authLabels,
}: {
  links: Array<[string, string]>;
  authLabels: { login: string; cta: string };
}) {
  const [open, setOpen] = useState(false);

  return (
    <div className="md:hidden">
      <button
        type="button"
        aria-label="Menü"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
        className="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-line/70 text-brand"
      >
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden>
          {open ? (
            <path d="M6 6l12 12M18 6L6 18" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
          ) : (
            <path d="M4 7h16M4 12h16M4 17h16" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
          )}
        </svg>
      </button>

      {open && (
        <>
          <button className="fixed inset-0 z-40 cursor-default bg-transparent" aria-hidden onClick={() => setOpen(false)} />
          <div className="absolute left-0 right-0 top-16 z-50 border-b border-line/70 bg-canvas/95 backdrop-blur">
            <div className="container-page flex flex-col py-2">
              {links.map(([label, href]) => (
                <Link
                  key={href}
                  href={href}
                  onClick={() => setOpen(false)}
                  className="py-3 text-sm font-medium text-ink-soft transition hover:text-brand"
                >
                  {label}
                </Link>
              ))}
              <div className="mt-2 flex gap-3 border-t border-line/70 pt-3">
                <Link href="/login" onClick={() => setOpen(false)} className="btn-ghost flex-1 justify-center">
                  {authLabels.login}
                </Link>
                <Link href="/register" onClick={() => setOpen(false)} className="btn-primary flex-1 justify-center">
                  {authLabels.cta}
                </Link>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
