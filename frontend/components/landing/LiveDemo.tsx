'use client';

import { useEffect, useState } from 'react';
import type { Lang } from '../../config/regions';

type Line = { t: string; tone: 'muted' | 'run' | 'ok' | 'warn' | 'lock' };

const LINES: Record<Lang, Line[]> = {
  tr: [
    { t: '$ cybertestify scan ornek.com', tone: 'muted' },
    { t: '✓ Alan adı sahipliği doğrulandı', tone: 'ok' },
    { t: '→ Hedef taranıyor…', tone: 'run' },
    { t: '→ HTTP güvenlik başlıkları inceleniyor…', tone: 'run' },
    { t: '→ TLS yapılandırması kontrol ediliyor…', tone: 'run' },
    { t: '⚠ Bulgu: eksik Content-Security-Policy başlığı', tone: 'warn' },
    { t: '→ Bulgular önem derecesine göre sıralanıyor…', tone: 'run' },
    { t: '🔒 Rapor uçtan uca şifreleniyor…', tone: 'lock' },
    { t: '✓ Rapor hazır · 3 dk 12 sn · 0 kapsam dışı erişim', tone: 'ok' },
  ],
  en: [
    { t: '$ cybertestify scan example.com', tone: 'muted' },
    { t: '✓ Domain ownership verified', tone: 'ok' },
    { t: '→ Scanning target…', tone: 'run' },
    { t: '→ Inspecting HTTP security headers…', tone: 'run' },
    { t: '→ Checking TLS configuration…', tone: 'run' },
    { t: '⚠ Finding: missing Content-Security-Policy header', tone: 'warn' },
    { t: '→ Prioritizing findings by severity…', tone: 'run' },
    { t: '🔒 Encrypting report end-to-end…', tone: 'lock' },
    { t: '✓ Report ready · 3m 12s · 0 out-of-scope access', tone: 'ok' },
  ],
  de: [
    { t: '$ cybertestify scan beispiel.de', tone: 'muted' },
    { t: '✓ Domain-Inhaberschaft verifiziert', tone: 'ok' },
    { t: '→ Ziel wird gescannt…', tone: 'run' },
    { t: '→ HTTP-Sicherheitsheader werden geprüft…', tone: 'run' },
    { t: '→ TLS-Konfiguration wird geprüft…', tone: 'run' },
    { t: '⚠ Befund: fehlender Content-Security-Policy-Header', tone: 'warn' },
    { t: '→ Befunde werden nach Schweregrad priorisiert…', tone: 'run' },
    { t: '🔒 Bericht wird Ende-zu-Ende verschlüsselt…', tone: 'lock' },
    { t: '✓ Bericht fertig · 3 Min. 12 Sek. · 0 Zugriffe außerhalb des Scope', tone: 'ok' },
  ],
};

const TONE: Record<Line['tone'], string> = {
  muted: 'text-white/45',
  run: 'text-white/80',
  ok: 'text-emerald-300',
  warn: 'text-accent',
  lock: 'text-brand-300',
};

export function LiveDemo({ lang = 'tr' }: { lang?: Lang }) {
  const lines = LINES[lang];
  const [shown, setShown] = useState(1);

  useEffect(() => {
    const id = setInterval(() => {
      setShown((n) => (n >= lines.length ? 1 : n + 1));
    }, 950);
    return () => clearInterval(id);
  }, [lines.length]);

  return (
    <div className="overflow-hidden rounded-card border border-white/10 bg-[#0A1F1C] shadow-2xl">
      <div className="flex items-center gap-2 border-b border-white/10 px-4 py-3">
        <span className="h-3 w-3 rounded-full bg-red-400/70" />
        <span className="h-3 w-3 rounded-full bg-accent/70" />
        <span className="h-3 w-3 rounded-full bg-emerald-400/70" />
        <span className="ml-3 text-xs font-medium text-white/40">cybertestify — live scan</span>
      </div>
      {/* TÜM satırlar HER ZAMAN DOM'da; henüz "yazılmamış" olanlar `invisible` (yer tutar, görünmez).
          Böylece kutu yüksekliği HİÇ değişmez (döngüde büyüyüp küçülmez → mobilde sayfayı kendiliğinden
          kaydırmaz) VE hiçbir satır kırpılmaz (eski sabit-yükseklik + overflow-hidden son satırları
          kesiyordu). Yükseklik içeriğe göre otomatik; sabit px yok → farklı font/ekranda güvenli. */}
      <div className="p-5 font-mono text-[13px] leading-7">
        {lines.map((l, i) => (
          <div key={i} className={`${TONE[l.tone]} ${i < shown ? '' : 'invisible'}`} dir="ltr">
            {l.t}
            {i === shown - 1 && shown < lines.length && (
              <span className="ml-1 inline-block h-4 w-2 translate-y-0.5 animate-pulse bg-accent/80" />
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
