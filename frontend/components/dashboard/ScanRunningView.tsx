'use client';

import { useEffect, useState } from 'react';
import { LiveScanPhases, computeScanProgress } from './LiveScanPhases';
import { localizedPackageName } from '../../lib/packageNames';

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
  verified?: boolean; // sahiplik/DNS doğrulaması yapılmış paket (5 & 6) → "Sahiplik doğrulandı" adımı/logu gösterilir
  loginless?: boolean; // "loginsiz devam et" → login fazı atlanır (bkz LiveScanPhases/computeScanProgress)
  lang?: 'tr' | 'de' | 'en';
};

// S1 tarama türü detayları — S1 /de'de gösterilmez → yalnız TR (çevrilmez).
const S1_DETAILS: Array<[string, string]> = [
  ['Risk', 'Düşük — çoğunlukla okuma ve az-etkili denemeler'],
  ['Teknik', 'Pasif + hafif aktif göstergeler'],
  ['Tutarlılık', 'Görece kararlı (deterministik değil)'],
  ['Kontrol', 'Otomatik; kritik adımlarda insan kontrolü'],
];

const SRV = {
  tr: {
    eyebrow: 'Tarama Durumu', starting: 'Taramanız başlatılıyor', running: 'Taramanız çalışıyor',
    isolatedPrep: 'İzole ortam hazırlanıyor',
    stepVerified: { t: 'Sahiplik doğrulandı', d: 'Alan adınızın sizin olduğu teyit edildi' },
    stepReceived: { t: 'Talebiniz alındı', d: 'Ödemeniz onaylandı ve tarama sıraya alındı' },
    stepScanT: 'Tarama çalışıyor', stepScanD6: 'Yapay zekâ destekli tarama sitenizi güvenli şekilde inceliyor',
    stepAnalyze: { t: 'Bulgular değerlendiriliyor', d: 'Sonuçlar önem derecesine göre sıralanıyor' },
    stepReport: { t: 'Rapor hazır', d: 'Şifreli raporunuz oluşturuldu' },
    autoNote: 'Bu sayfa otomatik güncelleniyor — kapatabilirsiniz; sonuç hazır olduğunda erişim kodu e-postanıza gönderilecek.',
    step: 'Adım', ringNote: 'Siteniz izole bir ortamda güvenli şekilde inceleniyor.',
    scanType: 'Tarama türü', scanFallback: 'Tarama',
    termHeader: 'cybertestify — canlı tarama', termFooter: 'Teknik loglar güvenlik ve gizlilik nedeniyle gizlenmiştir; yalnızca genel aktivite gösterilir.',
  },
  de: {
    eyebrow: 'Scan-Status', starting: 'Ihr Scan wird gestartet', running: 'Ihr Scan läuft',
    isolatedPrep: 'Isolierte Umgebung wird vorbereitet',
    stepVerified: { t: 'Inhaberschaft bestätigt', d: 'Bestätigt, dass die Domain Ihnen gehört' },
    stepReceived: { t: 'Anfrage eingegangen', d: 'Ihre Zahlung wurde bestätigt und der Scan in die Warteschlange gestellt' },
    stepScanT: 'Scan läuft', stepScanD6: 'Der KI-gestützte Scan prüft Ihre Website auf sichere Weise',
    stepAnalyze: { t: 'Befunde werden ausgewertet', d: 'Ergebnisse werden nach Schweregrad sortiert' },
    stepReport: { t: 'Bericht fertig', d: 'Ihr verschlüsselter Bericht wurde erstellt' },
    autoNote: 'Diese Seite aktualisiert sich automatisch — Sie können sie schließen; sobald das Ergebnis fertig ist, wird der Zugangscode an Ihre E-Mail gesendet.',
    step: 'Schritt', ringNote: 'Ihre Website wird in einer isolierten Umgebung sicher geprüft.',
    scanType: 'Scan-Typ', scanFallback: 'Scan',
    termHeader: 'cybertestify — Live-Scan', termFooter: 'Technische Logs werden aus Sicherheits- und Datenschutzgründen ausgeblendet; nur die allgemeine Aktivität wird angezeigt.',
  },
  en: {
    eyebrow: 'Scan status', starting: 'Your scan is starting', running: 'Your scan is running',
    isolatedPrep: 'Preparing isolated environment',
    stepVerified: { t: 'Ownership verified', d: 'Confirmed that the domain belongs to you' },
    stepReceived: { t: 'Request received', d: 'Your payment was confirmed and the scan was queued' },
    stepScanT: 'Scan running', stepScanD6: 'The AI-assisted scan is inspecting your site safely',
    stepAnalyze: { t: 'Evaluating findings', d: 'Results are being sorted by severity' },
    stepReport: { t: 'Report ready', d: 'Your encrypted report has been generated' },
    autoNote: 'This page updates automatically — you can close it; once the result is ready, the access code will be sent to your email.',
    step: 'Step', ringNote: 'Your site is being inspected safely in an isolated environment.',
    scanType: 'Scan type', scanFallback: 'Scan',
    termHeader: 'cybertestify — live scan', termFooter: 'Technical logs are hidden for security and privacy reasons; only general activity is shown.',
  },
} as const;

export function ScanRunningView({ hostname, packageKey, packageName, startedAt, authConfirmedAt, feed, notStarted, dark, secondsPerPhase, verified, loginless, lang = 'tr' }: Props) {
  const L = SRV[lang === 'de' ? 'de' : lang === 'en' ? 'en' : 'tr'];
  // (ÇOK-DİLLİ SCAN TYPE) order.packageName sipariş dilinde gelir → görüntüleme diline lokalize et.
  const localizedPkgName = localizedPackageName(packageKey, packageName, lang);
  const [now, setNow] = useState<number>(() => Date.now());
  useEffect(() => { const t = setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(t); }, []);

  const isS1 = packageKey === 'redteam_s1';
  // (SENKRON) LiveScanPhases ile AYNI fonksiyon → halka, üst çubuk ve terminal LOG satırı HEP birlikte ilerler.
  const prog = computeScanProgress({ packageKey, startedAt, authConfirmedAt, now, perPhase: secondsPerPhase, loginless, lang });
  const pct = notStarted ? 4 : prog.pct;
  const currentPhase = notStarted ? L.isolatedPrep : prog.current;

  // 4 adımlı üst-düzey şerit (StatusTracker ile aynı anlam): tarama sürerken adım 2 aktif.
  const STEPS = [
    verified ? L.stepVerified : L.stepReceived,
    { t: L.stepScanT, d: isS1 ? 'Otonom AI ajanı hedefinizi güvenli sınırlar içinde sınıyor' : L.stepScanD6 },
    L.stepAnalyze,
    L.stepReport,
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
          <div style={{ fontSize: 11.5, fontWeight: 700, letterSpacing: '0.1em', color: t.eyebrow, textTransform: 'uppercase', marginBottom: 8 }}>{L.eyebrow}</div>
          <h2 style={{ fontSize: 24, fontWeight: 800, color: t.title, margin: '0 0 8px', letterSpacing: '-0.01em', lineHeight: 1.15 }}>{notStarted ? L.starting : L.running}</h2>
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
          {L.autoNote}
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
            <div style={{ fontSize: 12, fontWeight: 700, letterSpacing: '0.06em', color: amber, textTransform: 'uppercase', marginBottom: 6 }}>{L.step} {activeStep + 1} / {STEPS.length}</div>
            <div style={{ fontSize: 18, fontWeight: 700, color: t.title, marginBottom: 6 }}>{currentPhase}</div>
            <div style={{ fontSize: 13.5, color: t.muted, lineHeight: 1.5 }}>{L.ringNote}</div>
          </div>
        </div>

        {/* Tarama türü — 6 paket: paket adı · S1: tür + risk/teknik/tutarlılık */}
        <div style={card}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: isS1 ? 14 : 0, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 12, fontWeight: 700, letterSpacing: '0.06em', color: t.muted, textTransform: 'uppercase' }}>{L.scanType}</span>
            <span style={{ fontSize: 14, fontWeight: 800, color: t.title, background: dark ? 'rgba(245,166,35,0.12)' : '#FDF3DE', border: `1px solid ${dark ? 'rgba(245,166,35,0.3)' : '#F5D9A0'}`, borderRadius: 999, padding: '4px 12px' }}>
              {isS1 ? 'S1 · Otonom AI Red Team' : (localizedPkgName || L.scanFallback)}
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
            <span className="ml-2 font-mono text-xs text-white/40">{L.termHeader}</span>
          </div>
          <LiveScanPhases hostname={hostname} feed={feed} startedAt={startedAt} packageKey={packageKey} queued={notStarted} authConfirmedAt={authConfirmedAt} secondsPerPhase={secondsPerPhase} verified={verified} loginless={loginless} lang={lang} />
          <div className="border-t border-white/5 px-5 py-3 text-xs text-white/32">{L.termFooter}</div>
        </div>
      </div>
      </div>
    </div>
  );
}
