'use client';
import { useEffect } from 'react';

// (İŞ — ÜCRETSİZ TARAMA → PAKET ODAĞI) URL'de ?focus=<paketKey> varsa ilgili kart merkeze kaydırılır ve
// kısa süreli amber halka ile vurgulanır. Salt-görsel; global CSS gerektirmez (stil JS ile uygulanır).
export function PackageFocus() {
  useEffect(() => {
    let key: string | null = null;
    try { key = new URLSearchParams(window.location.search).get('focus'); } catch { key = null; }
    if (!key) return;
    const el = document.getElementById(`pkg-${key}`);
    if (!el) return;
    const t = window.setTimeout(() => {
      el.scrollIntoView({ behavior: 'smooth', block: 'center' });
      const prev = el.style.boxShadow;
      el.style.transition = 'box-shadow .45s ease';
      el.style.boxShadow = '0 0 0 4px rgba(245,166,35,.65), 0 10px 34px rgba(245,166,35,.28)';
      window.setTimeout(() => { el.style.boxShadow = prev; }, 2800);
    }, 120);
    return () => window.clearTimeout(t);
  }, []);
  return null;
}
