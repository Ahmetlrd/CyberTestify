'use client';

import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { api, type InstantScanResult } from '../../lib/api';
import { Turnstile, type TurnstileHandle } from '../Turnstile';

const PHASES = [
  'Hedefe bağlanılıyor…',
  'HTTPS / TLS sertifikası kontrol ediliyor…',
  'HTTP güvenlik başlıkları taranıyor…',
  'Sunucu / teknoloji imzası inceleniyor…',
  'Bulgular derleniyor…',
];

const SEV_LABEL: Record<'high' | 'medium' | 'low', string> = { high: 'Yüksek', medium: 'Orta', low: 'Düşük' };
const SEV_STYLE: Record<'high' | 'medium' | 'low', { box: string; chip: string }> = {
  high: { box: 'border-red-300 bg-red-50 text-red-900', chip: 'bg-red-600 text-white' },
  medium: { box: 'border-orange-300 bg-orange-50 text-orange-900', chip: 'bg-orange-500 text-white' },
  low: { box: 'border-amber-300 bg-amber-50 text-amber-900', chip: 'bg-amber-500 text-white' },
};

// Skor rengi (Grok/Gemini): yüksek=yeşil, orta=sarı, düşük=turuncu, kritik=kırmızı. Aciliyeti renkle ver.
function scoreTheme(score: number) {
  if (score >= 80) return { stroke: '#059669', text: 'text-emerald-700', soft: 'bg-emerald-50 border-emerald-200' };
  if (score >= 60) return { stroke: '#d97706', text: 'text-amber-700', soft: 'bg-amber-50 border-amber-200' };
  if (score >= 45) return { stroke: '#ea580c', text: 'text-orange-700', soft: 'bg-orange-50 border-orange-200' };
  return { stroke: '#dc2626', text: 'text-red-700', soft: 'bg-red-50 border-red-200' };
}

// Animasyonlu skor halkası (0→hedef dolar). Görsel ağırlık için büyük ve merkezî.
function ScoreRing({ score, grade }: { score: number; grade: string }) {
  const [display, setDisplay] = useState(0);
  useEffect(() => {
    let raf = 0;
    const dur = 900;
    let start: number | null = null;
    const step = (ts: number) => {
      if (start === null) start = ts;
      const p = Math.min(1, (ts - start) / dur);
      const eased = 1 - Math.pow(1 - p, 3);
      setDisplay(Math.round(eased * score));
      if (p < 1) raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [score]);
  const t = scoreTheme(score);
  const R = 52, C = 2 * Math.PI * R;
  const off = C * (1 - display / 100);
  return (
    <div className="relative h-32 w-32 shrink-0">
      <svg viewBox="0 0 120 120" className="h-32 w-32 -rotate-90">
        <circle cx="60" cy="60" r={R} fill="none" stroke="#e5e7eb" strokeWidth="10" />
        <circle cx="60" cy="60" r={R} fill="none" stroke={t.stroke} strokeWidth="10" strokeLinecap="round" strokeDasharray={C} strokeDashoffset={off} style={{ transition: 'stroke-dashoffset 60ms linear' }} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className={`text-3xl font-extrabold leading-none ${t.text}`}>{display}</span>
        <span className={`mt-0.5 text-xs font-bold ${t.text}`}>Not: {grade}</span>
      </div>
    </div>
  );
}

export function InstantScan() {
  const [url, setUrl] = useState('');
  const [website, setWebsite] = useState(''); // HONEYPOT
  const [token, setToken] = useState<string | null>(null);
  const [state, setState] = useState<'idle' | 'scanning' | 'done' | 'error'>('idle');
  const [phase, setPhase] = useState(0);
  const [result, setResult] = useState<InstantScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const turnstile = useRef<TurnstileHandle>(null);

  useEffect(() => {
    if (state !== 'scanning') return;
    setPhase(0);
    const iv = setInterval(() => setPhase((p) => Math.min(p + 1, PHASES.length - 1)), 620);
    return () => clearInterval(iv);
  }, [state]);

  async function onScan(e: React.FormEvent) {
    e.preventDefault();
    setError(null); setResult(null);
    if (!url.trim()) { setError('Bir alan adı girin (ör. example.com).'); return; }
    if (!token) { setError('Lütfen önce doğrulama kutusunu tamamlayın.'); return; }
    setState('scanning');
    const started = Date.now();
    try {
      const r = await api.instantScan(url.trim(), token, website);
      const wait = Math.max(0, 2200 - (Date.now() - started));
      await new Promise((res) => setTimeout(res, wait));
      setResult(r); setState('done');
    } catch (err: any) {
      setError(err?.message || 'Tarama şu an tamamlanamadı. Lütfen tekrar deneyin.');
      setState('error');
    } finally {
      setToken(null); turnstile.current?.reset(); // token tek-kullanımlık
    }
  }

  function again() { setState('idle'); setResult(null); setError(null); }

  const ok = result && result.status === 'ok' ? result : null;

  return (
    <div className="rounded-[20px] border border-line bg-white/95 p-5 shadow-xl backdrop-blur sm:p-7">
      <div className="flex items-center gap-2">
        <span className="inline-flex h-8 w-8 items-center justify-center rounded-lg bg-accent-soft text-accent-600">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden><circle cx="11" cy="11" r="7" /><path d="m21 21-4.3-4.3" strokeLinecap="round" /></svg>
        </span>
        <h2 className="text-lg font-extrabold text-brand sm:text-xl">Sitenizi ücretsiz, anında tarayın</h2>
      </div>
      <p className="mt-1.5 text-sm text-ink-soft">Saniyeler içinde bir güvenlik skoru ve öne çıkan eksikleri görün — kart/kayıt gerekmez.</p>

      {(state === 'idle' || state === 'error') && (
        <form onSubmit={onScan} className="mt-4">
          <div className="flex flex-col gap-2.5 sm:flex-row">
            <div className="relative flex-1">
              <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-sm text-ink-muted">https://</span>
              <input type="text" inputMode="url" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="example.com" className="field w-full pl-[68px]" aria-label="Taranacak alan adı" />
            </div>
            <input type="text" tabIndex={-1} autoComplete="off" value={website} onChange={(e) => setWebsite(e.target.value)} className="hidden" aria-hidden />
            <button type="submit" disabled={!token || !url.trim()} className="btn-primary shrink-0 justify-center disabled:cursor-not-allowed disabled:opacity-60">
              {token ? 'Ücretsiz Tara' : 'Doğrulama bekleniyor…'}
            </button>
          </div>
          {/* Turnstile (bot doğrulaması) — görünür kutu; token gelene kadar buton kilitli. */}
          <div className="mt-3">
            <Turnstile ref={turnstile} onToken={setToken} action="instant-scan" />
          </div>
          {error && <p className="mt-2 text-sm font-medium text-red-600">{error}</p>}
        </form>
      )}

      {state === 'scanning' && (
        <div className="mt-5">
          <div className="rounded-card border border-white/10 bg-[#0A1F1C] p-4 font-mono text-[13px] leading-7">
            <div className="text-white/45" dir="ltr">$ cybertestify instant-scan {url.trim()}</div>
            {PHASES.map((p, i) => (
              <div key={p} className={`${i === phase ? 'text-white/85' : 'text-emerald-300/90'} ${i <= phase ? '' : 'invisible'}`} dir="ltr">
                {i === phase ? '→' : '✓'} {p}
                {i === phase && <span className="ml-1 inline-block h-4 w-2 translate-y-0.5 animate-pulse bg-accent/80" />}
              </div>
            ))}
          </div>
          <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-line">
            <div className="h-full rounded-full bg-gradient-to-r from-accent to-emerald-400 transition-[width] duration-500 ease-out" style={{ width: `${((phase + 1) / PHASES.length) * 100}%` }} />
          </div>
        </div>
      )}

      {state === 'done' && result && (
        <div className="mt-5">
          {result.status === 'unreachable' ? (
            <div className="rounded-card border-2 border-amber-300 bg-amber-50 p-4 text-sm">
              <p className="font-bold text-amber-900">🚫 Hedefe ulaşılamadı — incelenemedi</p>
              <p className="mt-1 text-amber-900/90">
                Bu <strong>“güvenli”</strong> anlamına gelmez; yalnızca kontrollerin çalıştırılamadığını gösterir. Alan adının
                yayında/erişilebilir olduğundan emin olup tekrar deneyin.
              </p>
              <button onClick={again} className="btn-outline mt-3 justify-center">Tekrar dene</button>
            </div>
          ) : ok && ok.clean ? (
            <div className="rounded-card border-2 border-emerald-200 bg-emerald-50 p-5 text-center">
              <div className="flex justify-center"><ScoreRing score={ok.score} grade={ok.grade} /></div>
              <p className="mt-2 font-bold text-emerald-900">Temel katmanda görünen bir sorun yok ✓</p>
              <p className="mt-1 text-sm text-emerald-900/80">
                Pasif dış gözlemde öne çıkan bir eksik bulunmadı. <strong>Daha derini</strong> (aktif enjeksiyon/IDOR doğrulaması,
                kimlik-doğrulamalı test, tam rapor) paketlerde değerlendirilir.
              </p>
              <div className="mt-4 flex flex-col gap-2 sm:flex-row sm:justify-center">
                <Link href="/register" className="btn-primary justify-center">Detaylı taramayı başlat</Link>
                <Link href="/tr/packages" className="btn-outline justify-center">Paketleri gör</Link>
              </div>
              <button onClick={again} className="mt-3 inline-block rounded-pill px-3 py-1 text-xs font-semibold text-accent-600 hover:bg-accent-soft/50 hover:underline">↺ Başka bir site tara</button>
            </div>
          ) : ok ? (
            <div className="rounded-card border border-line bg-white p-5">
              {/* Skor + host — büyük ve merkezî görsel ağırlık */}
              <div className="flex flex-col items-center gap-3 sm:flex-row sm:items-center sm:gap-5">
                <ScoreRing score={ok.score} grade={ok.grade} />
                <div className="text-center sm:text-left">
                  <p className="text-xs font-medium uppercase tracking-wide text-ink-muted">Güvenlik skoru</p>
                  <p className="text-base font-bold text-ink">{ok.host}</p>
                  <p className="mt-1 text-sm text-ink-soft">{ok.total} güvenlik göstergesi tespit edildi.</p>
                  {ok.score >= 70 && (
                    <p className="mt-1 text-[11px] text-ink-muted">Büyük/kurumsal sitelerde bile temel katmanda eksikler görülebilir.</p>
                  )}
                </div>
              </div>

              {/* ≤3 GERÇEK bulgu başlığı — severity etiketli, tutarlı */}
              <ul className="mt-4 space-y-2">
                {ok.shown.map((f, i) => (
                  <li key={f.title} className={`animate-fade-up flex items-center gap-2.5 rounded-card border px-3 py-2.5 text-sm font-medium ${SEV_STYLE[f.severity].box}`} style={{ animationDelay: `${i * 110}ms` }}>
                    <span className={`shrink-0 rounded-pill px-2 py-0.5 text-[10px] font-bold uppercase ${SEV_STYLE[f.severity].chip}`}>{SEV_LABEL[f.severity]}</span>
                    <span>{f.title}</span>
                  </li>
                ))}
              </ul>

              {/* KİLİTLİ — blur'lu sahte satırlar + kilit + baskın CTA */}
              <div className="relative mt-4 overflow-hidden rounded-card border-2 border-dashed border-accent/50 bg-accent-soft/20 p-4">
                {/* arka planda silik/bulanık "kilitli" satır hissi */}
                <div aria-hidden className="pointer-events-none absolute inset-x-4 top-3 space-y-2 opacity-40 blur-[3px]">
                  <div className="h-3 w-3/4 rounded-full bg-ink/30" />
                  <div className="h-3 w-2/3 rounded-full bg-ink/25" />
                  <div className="h-3 w-4/5 rounded-full bg-ink/20" />
                </div>
                <div className="relative">
                  <p className="flex items-center gap-1.5 text-sm font-extrabold text-brand">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="animate-pulse" aria-hidden><rect x="5" y="11" width="14" height="10" rx="2" /><path d="M8 11V7a4 4 0 0 1 8 0v4" /></svg>
                    {ok.locked > 0 ? `+${ok.locked} bulgu daha kilitli` : 'Detaylar ve düzeltmeler kilitli'}
                  </p>
                  <p className="mt-1.5 text-xs leading-relaxed text-ink-soft">
                    Tüm bulguların detayları, <strong>platformunuza özel hazır düzeltme kodları</strong> ve
                    <strong> indirilebilir profesyonel PDF raporu</strong> için:
                  </p>
                  <div className="mt-3 flex flex-col gap-2 sm:flex-row">
                    <Link href="/register" className="btn-primary justify-center sm:flex-[2]">
                      Detaylı Raporu Aç →
                      <span className="ml-1.5 rounded-pill bg-white/20 px-1.5 py-0.5 text-[10px] font-bold">₺699</span>
                    </Link>
                    <Link href="/tr/packages" className="btn-outline justify-center text-sm sm:flex-1">Tüm paketler</Link>
                  </div>
                </div>
              </div>

              <button onClick={again} className="mt-3 inline-flex w-full items-center justify-center rounded-pill px-3 py-1.5 text-xs font-semibold text-accent-600 hover:bg-accent-soft/50 hover:underline">↺ Başka bir site tara</button>
            </div>
          ) : null}
        </div>
      )}

      <p className="mt-3 text-[11px] leading-relaxed text-ink-muted">
        Bu ücretsiz bir <strong>ön izlemedir</strong>; yalnızca <strong>pasif dış gözlem</strong> yapılır (resmî denetim/sızma
        testi değildir). Aktif test (enjeksiyon/IDOR vb.) yalnızca ücretli paketlerde ve yetki beyanıyla çalışır.
      </p>
    </div>
  );
}
