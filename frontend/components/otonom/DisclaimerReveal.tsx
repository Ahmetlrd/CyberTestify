'use client';

import { useRef } from 'react';

/** RedTeamGate (kilitli) bu olayı dinler; 3-tık gelince kod alanını açar. */
export const RT_REVEAL_EVENT = 'rt-reveal-code';

/**
 * (OTONOM AI RED TEAM — gizli tetik) Disclaimer cümlesini olduğu gibi gösterir; ama
 * `word` (ör. "içermez") kelimesine KISA pencerede 3 kez tıklanınca kod alanını açan
 * bir olay yayınlar. GİZLİLİK: kelime GÖRSEL OLARAK normal metindir — pointer imleci,
 * hover stili, renk/altçizgi YOKTUR. Normal ziyaretçi tıklanabilir olduğunu anlamaz.
 * Triple-click'in varsayılan metin-seçimi sayaç mantığını bozmaz; tetik anında seçim temizlenir.
 */
export function DisclaimerReveal({ text, word, className }: { text: string; word: string; className?: string }) {
  const taps = useRef<number[]>([]);
  const idx = text.indexOf(word);

  function onWordClick() {
    const now = Date.now();
    // Yalnız son ~1.2 sn içindeki tıklamaları say (kısa pencere).
    taps.current = taps.current.filter((t) => now - t < 1200);
    taps.current.push(now);
    if (taps.current.length >= 3) {
      taps.current = [];
      // Triple-click'in seçtiği metni temizle (görsel kalıntı olmasın).
      window.getSelection?.()?.removeAllRanges();
      window.dispatchEvent(new CustomEvent(RT_REVEAL_EVENT));
    }
  }

  // Kelime bulunamazsa düz metin göster (güvenli geri düşüş).
  if (idx < 0) return <p className={className}>{text}</p>;

  return (
    <p className={className}>
      {text.slice(0, idx)}
      {/* GÖRSEL OLARAK normal metin: cursor:text, hover/renk yok. Sadece tıklama sayacı. */}
      <span onClick={onWordClick} style={{ cursor: 'text' }}>
        {word}
      </span>
      {text.slice(idx + word.length)}
    </p>
  );
}
