'use client';

import { useState } from 'react';

// Basit Tarama kartında kampanya promo kodunu gösterir + tek tıkla kopyalatır.
export function PromoCodeChip({
  code,
  labels,
}: {
  code: string;
  labels: { campaign: string; copy: string; copied: string; hint: string };
}) {
  const [copied, setCopied] = useState(false);
  async function doCopy() {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      /* pano erişilemezse sessiz geç (kod zaten görünür) */
    }
  }
  return (
    <div className="mt-4 rounded-card border border-amber-300 bg-amber-50 p-3">
      <div className="text-[11px] font-extrabold uppercase tracking-wide text-orange-600">{labels.campaign}</div>
      <div className="mt-1.5 flex items-center gap-2">
        <code className="flex-1 rounded border border-amber-200 bg-white px-2.5 py-1.5 text-center font-mono text-sm font-bold tracking-widest text-orange-700">
          {code}
        </code>
        <button
          type="button"
          onClick={doCopy}
          aria-label={labels.copy}
          className="shrink-0 rounded-pill bg-orange-500 px-3 py-1.5 text-xs font-bold text-white transition hover:bg-orange-600"
        >
          {copied ? labels.copied : labels.copy}
        </button>
      </div>
      <p className="mt-1.5 text-[11px] leading-snug text-orange-900/80">{labels.hint}</p>
    </div>
  );
}
