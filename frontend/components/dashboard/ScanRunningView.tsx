'use client';

import { useEffect, useState } from 'react';
import { LiveScanPhases, phasesFor } from './LiveScanPhases';

/**
 * (Tasarım: Scan Status Page v2) MÜŞTERİ tarama-durumu görünümü — 2 kolon: adım şeridi + otomatik-not
 * (sol) · ilerleme halkası + canlı terminal + tarama türü (sağ). TEMA: 6 paket = AÇIK (beyaz), S1 = KOYU.
 * Metinler her iki temada da GÖRÜNÜR (kontrast garanti). Terminal her iki temada da koyudur (doğal).
 */
type Props = {
  hostname: string;
  packageKey?: string | null;
  packageName?: string | null;
  startedAt?: string | null;
  authConfirmedAt?: string | null;
  feed: Array<{ seq: number; text: string }>;
  notStarted: boolean;
  dark: boolean; // S1 → koyu, 6 paket → açık
  secondsPerPhase?: number;
};

// S1 tarama türü detayları (kartta gösterilir) — otonom RT seviyesi S1.
const S1_DETAILS: Array<[string, string]> = [
  ['Risk', 'Düşük — çoğunlukla okuma ve az-etkili denemeler'],
  ['Teknik', 'Pasif + hafif aktif göstergeler'],
  ['Tutarlılık', 'Görece kararlı (deterministik değil)'],
  ['Kontrol', 'Otomatik; kritik adımlarda insan kontrolü'],
];

export function ScanRunningView({ hostname, packageKey, packageName, startedAt, authConfirmedAt, feed, notStarted, dark, secondsPerPhase }: Props) {
  const [now, setNow] = useState<number>(() => Date.now());
  useEffect(() => { const t = setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(t); }, []);

  const isS1 = packageKey === 'redteam_s1';
  const PHASES = phasesFor(packageKey);
  const perPhase = secondsPerPhase && secondsPerPhase > 0 ? secondsPerPhase : 9;
  const startMs = startedAt ? new Date(startedAt).getTime() : now;
  const elapsed = Math.max(0, (now - startMs) / 1000);
  const phaseIdx = notStarted ? 0 : Math.min(Math.floor(elapsed / perPhase), PHASES.length - 1);
  // İlerleme % — FAZ ilerlemesinden (süre-sabitli değil) → S1'in uzun koşusunda yavaş ilerler.
  const pct = notStarted ? 4 : Math.min(95, Math.max(6, Math.round(((phaseIdx + 0.6) / PHASES.length) * 100)));
  const currentPhase = notStarted ? 'İzole ortam hazırlanıyor' : PHASES[phaseIdx];

  // 4 adımlı üst-düzey şerit (StatusTracker ile aynı anlam): tarama sürerken adım 2 aktif.
  const STEPS = [
    { t: 'Sahiplik doğrulandı', d: 'Alan adınızın sizin olduğu teyit edildi' },
    { t: 'Tarama çalışıyor', d: isS1 ? 'Otonom AI ajanı hedefinizi güvenli sınırlar içinde sınıyor' : 'Yapay zekâ destekli tarama sitenizi güvenli şekilde inceliyor' },
    { t: 'Bulgular değerlendiriliyor', d: 'Sonuçlar önem derecesine göre sıralanıyor' },
    { t: 'Rapor hazır', d: 'Şifreli raporunuz oluşturuldu' },
  ];
  const activeStep = 1; // tarama sürerken

  // ————— TEMA —————
  const t = dark
    ? { cardBg: 'rgba(255,255,255,0.035)', cardBorder: 'rgba(255,255,255,0.09)', title: '#f4faf7', text: '#c7d6d0', muted: '#8ea39c', dim: '#5c7069', eyebrow: '#F5A623', ok: '#34d399', okBg: '#2f8f6f', noteBg: 'rgba(245,166,35,0.06)', noteBorder: 'rgba(245,166,35,0.16)', ringTrack: 'rgba(255,255,255,0.08)', line: 'rgba(255,255,255,0.09)', typeBg: 'linear-gradient(150deg,#123832,#0e2a25)' }
    : { cardBg: '#ffffff', cardBorder: '#DCEAE6', title: '#123F3A', text: '#1b2b28', muted: '#5FA396', dim: '#9AB0A8', eyebrow: '#C4780A', ok: '#1C6B60', okBg: '#1C6B60', noteBg: '#FDF5E6', noteBorder: '#F5C77A', ringTrack: '#E1ECE8', line: '#E1ECE8', typeBg: '#F6FAF8' };
  const amber = '#F5A623';
  const card: React.CSSProperties = { background: t.cardBg, border: `1px solid ${t.cardBorder}`, borderRadius: 18, padding: 22 };

  // S1 (koyu): tüm görünüm KOYU bir panele oturur (site açık zemininde translucent kartlar görünsün).
  // 6 paket (açık): panel yok — beyaz kartlar açık sayfada durur.
  const wrapStyle: React.CSSProperties | undefined = dark
    ? { background: 'radial-gradient(circle at 15% 0%, #163530 0%, #0d1a17 60%)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 24, padding: 'clamp(18px,3.5vw,30px)' }
    : undefined;

  return (
    <div className="mt-6" style={wrapStyle}>
      <style>{`@keyframes srvSpin{to{transform:rotate(360deg)}}`}</style>
      <div className="grid gap-5 lg:grid-cols-[300px_1fr]">
      {/* ————— SOL: başlık + adım şeridi + not ————— */}
      <div className="flex flex-col gap-4">
        <div>
          <div style={{ fontSize: 11.5, fontWeight: 700, letterSpacing: '0.1em', color: t.eyebrow, textTransform: 'uppercase', marginBottom: 8 }}>Tarama Durumu</div>
          <h2 style={{ fontSize: 24, fontWeight: 800, color: t.title, margin: '0 0 8px', letterSpacing: '-0.01em', lineHeight: 1.15 }}>{notStarted ? 'Taramanız başlatılıyor' : 'Taramanız çalışıyor'}</h2>
          <div style={{ fontSize: 13.5, color: t.muted, fontFamily: 'var(--font-mono, ui-monospace, monospace)', wordBreak: 'break-all' }}>{hostname}</div>
        </div>

        <div style={card}>
          {STEPS.map((s, i) => {
            const state = i < activeStep ? 'done' : i === activeStep ? 'active' : 'pending';
            const isLast = i === STEPS.length - 1;
            return (
              <div key={s.t} style={{ display: 'flex', gap: 14, paddingBottom: isLast ? 0 : 20, position: 'relative' }}>
                {!isLast && <div style={{ position: 'absolute', left: 13, top: 28, bottom: 0, width: 2, background: t.line }} />}
                {state === 'done' ? (
                  <div style={{ width: 28, height: 28, borderRadius: '50%', background: t.okBg, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, zIndex: 1 }}>
                    <svg width="13" height="13" viewBox="0 0 16 16" fill="none"><path d="M3 8.5L6.2 11.5L13 4" stroke="white" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" /></svg>
                  </div>
                ) : state === 'active' ? (
                  <div style={{ width: 28, height: 28, borderRadius: '50%', border: `2px solid ${dark ? 'rgba(245,166,35,0.25)' : '#F5D9A0'}`, borderTopColor: amber, flexShrink: 0, animation: 'srvSpin 0.9s linear infinite', zIndex: 1, background: dark ? '#0d1a17' : '#fff' }} />
                ) : (
                  <div style={{ width: 28, height: 28, borderRadius: '50%', border: `1.5px solid ${t.cardBorder}`, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, fontSize: 11.5, fontWeight: 700, color: t.dim, zIndex: 1, background: dark ? '#0d1a17' : '#fff' }}>{i + 1}</div>
                )}
                <div>
                  <div style={{ fontSize: 14.5, fontWeight: 700, color: state === 'pending' ? t.dim : t.title, marginBottom: 3 }}>{s.t}</div>
                  <div style={{ fontSize: 12.5, color: state === 'pending' ? t.dim : t.muted, lineHeight: 1.45 }}>{s.d}</div>
                </div>
              </div>
            );
          })}
        </div>

        <div style={{ background: t.noteBg, border: `1px solid ${t.noteBorder}`, borderRadius: 14, padding: '15px 16px', fontSize: 12.5, color: t.text, lineHeight: 1.55 }}>
          Bu sayfa otomatik güncelleniyor — kapatabilirsiniz; sonuç hazır olduğunda erişim kodu e-postanıza gönderilecek.
        </div>
      </div>

      {/* ————— SAĞ: ilerleme halkası + tarama türü + canlı terminal ————— */}
      <div className="flex flex-col gap-5">
        <div style={{ ...card, background: t.typeBg, display: 'flex', alignItems: 'center', gap: 24, flexWrap: 'wrap' }}>
          <svg width="88" height="88" viewBox="0 0 88 88" style={{ flexShrink: 0 }}>
            <circle cx="44" cy="44" r="40" fill="none" stroke={t.ringTrack} strokeWidth="6" />
            <circle cx="44" cy="44" r="40" fill="none" stroke={amber} strokeWidth="6" strokeLinecap="round" strokeDasharray="251" strokeDashoffset={251 - (251 * pct) / 100} transform="rotate(-90 44 44)" style={{ transition: 'stroke-dashoffset 0.6s ease' }} />
            <text x="44" y="50" textAnchor="middle" fontFamily="JetBrains Mono, ui-monospace, monospace" fontSize="20" fontWeight="600" fill={t.title}>{pct}%</text>
          </svg>
          <div style={{ minWidth: 180, flex: 1 }}>
            <div style={{ fontSize: 12, fontWeight: 700, letterSpacing: '0.06em', color: amber, textTransform: 'uppercase', marginBottom: 6 }}>Adım {activeStep + 1} / {STEPS.length}</div>
            <div style={{ fontSize: 18, fontWeight: 700, color: t.title, marginBottom: 6 }}>{currentPhase}</div>
            <div style={{ fontSize: 13.5, color: t.muted, lineHeight: 1.5 }}>Siteniz izole bir ortamda güvenli şekilde inceleniyor.</div>
          </div>
        </div>

        {/* Tarama türü — 6 paket: paket adı · S1: tür + risk/teknik/tutarlılık */}
        <div style={card}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: isS1 ? 14 : 0, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 12, fontWeight: 700, letterSpacing: '0.06em', color: t.muted, textTransform: 'uppercase' }}>Tarama türü</span>
            <span style={{ fontSize: 14, fontWeight: 800, color: t.title, background: dark ? 'rgba(245,166,35,0.12)' : '#FDF3DE', border: `1px solid ${dark ? 'rgba(245,166,35,0.3)' : '#F5D9A0'}`, borderRadius: 999, padding: '4px 12px' }}>
              {isS1 ? 'S1 · Otonom AI Red Team' : (packageName || 'Tarama')}
            </span>
          </div>
          {isS1 && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 10 }}>
              {S1_DETAILS.map(([k, v]) => (
                <div key={k} style={{ display: 'flex', gap: 10 }}>
                  <span style={{ color: amber, fontSize: 11, marginTop: 4 }}>▪</span>
                  <div>
                    <div style={{ fontSize: 11.5, color: t.muted, fontFamily: 'var(--font-mono, ui-monospace, monospace)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>{k}</div>
                    <div style={{ fontSize: 13.5, color: t.text, lineHeight: 1.45 }}>{v}</div>
                  </div>
                </div>
              ))}
              <p style={{ fontSize: 12, color: t.dim, lineHeight: 1.5, margin: '4px 0 0' }}>Deneysel, deterministik-olmayan bir tarama; resmî pentest/denetim yerine geçmez.</p>
            </div>
          )}
        </div>

        {/* Canlı terminal — mevcut LiveScanPhases (koyu, her iki temada da doğal) */}
        <div className="overflow-hidden rounded-[18px] border border-white/10 bg-[#081714] shadow-lg">
          <div className="flex items-center gap-2 border-b border-white/10 px-5 py-3">
            <span className="h-2.5 w-2.5 rounded-full bg-red-400/70" />
            <span className="h-2.5 w-2.5 rounded-full bg-amber-400/70" />
            <span className="h-2.5 w-2.5 rounded-full bg-emerald-400/70" />
            <span className="ml-2 font-mono text-xs text-white/40">cybertestify — canlı tarama</span>
          </div>
          <LiveScanPhases hostname={hostname} feed={feed} startedAt={startedAt} packageKey={packageKey} queued={notStarted} authConfirmedAt={authConfirmedAt} secondsPerPhase={secondsPerPhase} />
          <div className="border-t border-white/5 px-5 py-3 text-xs text-white/32">Teknik loglar güvenlik ve gizlilik nedeniyle gizlenmiştir; yalnızca genel aktivite gösterilir.</div>
        </div>
      </div>
      </div>
    </div>
  );
}
