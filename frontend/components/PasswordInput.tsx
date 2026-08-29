'use client';

import { useEffect, useState } from 'react';
import { readRegionCookie } from '../lib/region';
import { getRegion } from '../config/regions';

const ARIA = {
  tr: { show: 'Şifreyi göster', hide: 'Şifreyi gizle' },
  de: { show: 'Passwort anzeigen', hide: 'Passwort verbergen' },
  en: { show: 'Show password', hide: 'Hide password' },
} as const;

/**
 * Şifre alanı + göster/gizle göz ikonu. type="password" ↔ "text" arası geçiş.
 * Kayıt (şifre + şifre tekrar) ve login şifre alanlarında kullanılır.
 * (Çok-bölge) aria-label dili cookie'den türetilir — /de /en'de Türkçe sızmaz.
 */
export function PasswordInput({
  value,
  onChange,
  placeholder,
  required,
  minLength,
  autoComplete,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  required?: boolean;
  minLength?: number;
  autoComplete?: string;
}) {
  const [show, setShow] = useState(false);
  const [lang, setLang] = useState<'tr' | 'de' | 'en'>('tr');
  useEffect(() => { const l = getRegion(readRegionCookie()).lang; setLang(l === 'de' ? 'de' : l === 'en' ? 'en' : 'tr'); }, []);
  const aria = ARIA[lang];
  return (
    <div className="relative">
      <input
        type={show ? 'text' : 'password'}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        required={required}
        minLength={minLength}
        autoComplete={autoComplete}
        className="field pr-11"
      />
      <button
        type="button"
        onClick={() => setShow((s) => !s)}
        aria-label={show ? aria.hide : aria.show}
        className="absolute right-2 top-1/2 -translate-y-1/2 p-1.5 text-ink-muted transition hover:text-ink"
        tabIndex={-1}
      >
        {show ? (
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
            <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />
            <line x1="1" y1="1" x2="23" y2="23" />
          </svg>
        ) : (
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
            <circle cx="12" cy="12" r="3" />
          </svg>
        )}
      </button>
    </div>
  );
}
