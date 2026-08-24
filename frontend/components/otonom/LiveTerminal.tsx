'use client';

import { useEffect, useState } from 'react';

// Canlı koşu terminali — dekoratif (gerçek koşu değil). Satırlar sırayla belirir, sona gelince başa döner.
// Renkler markamıza uyarlı: amber #F5A623 (uyarı), yeşil #34d399 (başarı), mor #a595c2 (elenen).
const LINES: Array<{ t: string; c: string }> = [
  { t: '$ redteam run --level S1 --target hedef.example.com', c: '#c9d6d1' },
  { t: '✓ Alan adı sahipliği doğrulandı (DNS TXT)', c: '#34d399' },
  { t: '→ Keşif: saldırı yüzeyi haritalanıyor…', c: '#8fa39c' },
  { t: '→ 14 uç nokta · 3 form · 2 API yüzeyi bulundu', c: '#8fa39c' },
  { t: '→ Hipotez #4: oturum çerezi SameSite eksik', c: '#8fa39c' },
  { t: '⚠ Bulgu adayı: yansıtılmış girdi izi (param ?q=)', c: '#F5A623' },
  { t: '⊙ Ham istek/yanıt kanıta bağlandı  [req#0231]', c: '#8b93a5' },
  { t: '✗ Hayalet iddia elendi: kanıt izi yok  [claim#7]', c: '#a595c2' },
  { t: '✓ Sınıflandırma: 2 Kanıtlı · 1 Belirsiz · 1 Elenen', c: '#34d399' },
  { t: '🔒 Rapor şifreleniyor…', c: '#c9d6d1' },
];

export function LiveTerminal() {
  const [visible, setVisible] = useState(1);
  const [evidence, setEvidence] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => {
      setVisible((v) => {
        const done = v >= LINES.length;
        setEvidence((e) => (done ? 0 : v % 3 === 0 ? e + 1 : e));
        return done ? 1 : v + 1;
      });
    }, 1400);
    return () => clearInterval(timer);
  }, []);

  return (
    <div style={{ position: 'relative' }}>
      <div style={{ position: 'relative', background: '#0b201b', border: '1px solid #1e3b33', borderRadius: 14, overflow: 'hidden', boxShadow: '0 24px 64px rgba(0,0,0,.5)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '12px 16px', borderBottom: '1px solid #17322c', background: '#0a1c18' }}>
          <span style={{ width: 11, height: 11, borderRadius: '50%', background: '#ff5f57' }} />
          <span style={{ width: 11, height: 11, borderRadius: '50%', background: '#febc2e' }} />
          <span style={{ width: 11, height: 11, borderRadius: '50%', background: '#28c840' }} />
          <span style={{ marginLeft: 10, fontFamily: 'var(--font-mono, ui-monospace, monospace)', fontSize: 12, color: '#7e938c' }}>redteam-agent · S1 · canlı koşu</span>
          <span style={{ marginLeft: 'auto', display: 'inline-flex', alignItems: 'center', gap: 6, fontFamily: 'var(--font-mono, ui-monospace, monospace)', fontSize: 11, color: '#34d399' }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#34d399', animation: 'rtPulseDot 1.2s infinite' }} />REC
          </span>
        </div>
        <div style={{ position: 'relative', padding: '20px 20px 24px', minHeight: 340, fontFamily: 'var(--font-mono, ui-monospace, monospace)', fontSize: 13, lineHeight: 1.85 }}>
          <div style={{ position: 'absolute', left: 0, right: 0, top: 0, height: 64, background: 'linear-gradient(rgba(245,166,35,.06), transparent)', animation: 'rtScanSweep 5s linear infinite', pointerEvents: 'none' }} />
          {LINES.slice(0, visible).map((l, i) => (
            <div key={i} style={{ color: l.c, whiteSpace: 'pre-wrap' }}>{l.t}</div>
          ))}
          <span style={{ display: 'inline-block', width: 8, height: 15, background: '#F5A623', verticalAlign: 'middle', animation: 'rtBlink 1s step-end infinite' }} />
        </div>
      </div>
      <div style={{ position: 'absolute', right: 8, bottom: 8, maxWidth: 'calc(100% - 16px)', background: '#0e241f', border: '1px solid #1e3b33', borderRadius: 10, padding: '12px 16px', display: 'flex', alignItems: 'center', gap: 12, boxShadow: '0 12px 32px rgba(0,0,0,.5)' }}>
        <div style={{ width: 34, height: 34, borderRadius: '50%', border: '2px solid #1e3b33', position: 'relative', overflow: 'hidden' }}>
          <div style={{ position: 'absolute', inset: 0, background: 'conic-gradient(from 0deg, transparent 70%, rgba(245,166,35,.7))', animation: 'rtRadarSpin 3s linear infinite' }} />
        </div>
        <div>
          <div style={{ fontFamily: 'var(--font-mono, ui-monospace, monospace)', fontSize: 11, color: '#7e938c' }}>HAM KANIT</div>
          <div style={{ fontSize: 14, fontWeight: 600, color: '#E7EEEB' }}>{evidence} kayıt bağlandı</div>
        </div>
      </div>
    </div>
  );
}
