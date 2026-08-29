'use client';

import { useEffect, useRef, useState } from 'react';
import { readRegionCookie } from '../lib/region';
import { getRegion } from '../config/regions';

const ARIA_CODE = { tr: 'Doğrulama kodu', de: 'Bestätigungscode', en: 'Verification code' } as const;

// (2FA) iCloud tarzı 6-kutucuklu doğrulama kodu girişi: otomatik ilerleme, backspace, yapıştır (paste).
// Tema: 'light' (müşteri) | 'dark' (admin panel). Değer = birleşik rakam dizisi (ör. "123456").
// (Çok-bölge) ariaLabel verilmezse dili cookie'den türetir — /de /en'de Türkçe aria sızmaz.
export function OtpInput({
  value, onChange, length = 6, theme = 'light', autoFocus = false, ariaLabel, onComplete,
}: {
  value: string;
  onChange: (v: string) => void;
  length?: number;
  theme?: 'light' | 'dark';
  autoFocus?: boolean;
  ariaLabel?: string;
  onComplete?: (v: string) => void;
}) {
  const refs = useRef<Array<HTMLInputElement | null>>([]);
  const [lang, setLang] = useState<'tr' | 'de' | 'en'>('tr');
  useEffect(() => { const l = getRegion(readRegionCookie()).lang; setLang(l === 'de' ? 'de' : l === 'en' ? 'en' : 'tr'); }, []);
  const label = ariaLabel ?? ARIA_CODE[lang];
  const chars = Array.from({ length }, (_, i) => value[i] ?? '');
  const focus = (i: number) => { if (i >= 0 && i < length) refs.current[i]?.focus(); };

  const commit = (v: string) => {
    const clean = v.replace(/\D/g, '').slice(0, length);
    onChange(clean);
    if (clean.length === length) onComplete?.(clean);
    return clean;
  };
  const setChar = (i: number, ch: string) => {
    const next = value.split('');
    while (next.length < length) next.push('');
    next[i] = ch;
    return commit(next.join(''));
  };
  const handleChange = (i: number, raw: string) => {
    const d = raw.replace(/\D/g, '');
    if (!d) { setChar(i, ''); return; }
    if (d.length > 1) { const merged = commit((value.slice(0, i) + d)); focus(Math.min(merged.length, length - 1)); return; }
    setChar(i, d);
    focus(i + 1);
  };
  const handleKey = (i: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace') { if (chars[i]) setChar(i, ''); else { focus(i - 1); setChar(Math.max(0, i - 1), ''); } }
    else if (e.key === 'ArrowLeft') focus(i - 1);
    else if (e.key === 'ArrowRight') focus(i + 1);
  };

  const box: React.CSSProperties = {
    width: 44, height: 52, textAlign: 'center', fontSize: 22, fontWeight: 700, borderRadius: 10,
    fontFamily: 'ui-monospace, SFMono-Regular, monospace', outline: 'none',
    ...(theme === 'dark'
      ? { border: '1px solid #334155', background: '#0f172a', color: '#e2e8f0' }
      : { border: '1px solid #d8dfe0', background: '#fff', color: '#0e1a17' }),
  };

  return (
    <div style={{ display: 'flex', gap: 8, justifyContent: 'center' }} role="group" aria-label={label}>
      {chars.map((c, i) => (
        <input
          key={i}
          ref={(el) => { refs.current[i] = el; }}
          value={c}
          onChange={(e) => handleChange(i, e.target.value)}
          onKeyDown={(e) => handleKey(i, e)}
          onFocus={(e) => e.currentTarget.select()}
          inputMode="numeric"
          autoComplete="one-time-code"
          maxLength={1}
          autoFocus={autoFocus && i === 0}
          aria-label={`${label} ${i + 1}`}
          style={box}
        />
      ))}
    </div>
  );
}
