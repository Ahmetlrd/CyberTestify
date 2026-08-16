'use client';

import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { api, type InstantScanResult } from '../../lib/api';

// Cloudflare Turnstile (bot doğrulaması). VARSAYILAN = public TEST key (her zaman geçer) — Vedat
// gerçek key ekleyince (NEXT_PUBLIC_TURNSTILE_SITE_KEY) otomatik gerçek koruma devreye girer.
const SITE_KEY = process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY || '1x00000000000000000000AA';

declare global {
  interface Window { turnstile?: any }
}

const PHASES = [
  'Hedefe bağlanılıyor…',
  'HTTPS / TLS sertifikası kontrol ediliyor…',
  'HTTP güvenlik başlıkları taranıyor…',
  'Sunucu / teknoloji imzası inceleniyor…',
  'Bulgular derleniyor…',
];

const SEV_STYLE: Record<'high' | 'medium' | 'low', string> = {
  high: 'border-red-300 bg-red-50 text-red-800',
  medium: 'border-amber-300 bg-amber-50 text-amber-800',
  low: 'border-slate-300 bg-slate-50 text-slate-700',
};

function scoreColor(score: number) {
  if (score >= 80) return { ring: 'text-emerald-500', text: 'text-emerald-700', bg: 'bg-emerald-50 border-emerald-200' };
  if (score >= 55) return { ring: 'text-amber-500', text: 'text-amber-700', bg: 'bg-amber-50 border-amber-200' };
  return { ring: 'text-red-500', text: 'text-red-700', bg: 'bg-red-50 border-red-200' };
}

export function InstantScan() {
  const [url, setUrl] = useState('');
  const [website, setWebsite] = useState(''); // HONEYPOT (insan görmez)
  const [state, setState] = useState<'idle' | 'scanning' | 'done' | 'error'>('idle');
  const [phase, setPhase] = useState(0);
  const [result, setResult] = useState<InstantScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const tokenRef = useRef<string>('');
  const widgetHost = useRef<HTMLDivElement>(null);
  const widgetId = useRef<string | null>(null);

  // Turnstile script + widget
  useEffect(() => {
    function render() {
      if (!window.turnstile || !widgetHost.current || widgetId.current) return;
      try {
        widgetId.current = window.turnstile.render(widgetHost.current, {
          sitekey: SITE_KEY,
          theme: 'light',
          size: 'flexible',
          callback: (t: string) => { tokenRef.current = t; },
          'expired-callback': () => { tokenRef.current = ''; },
          'error-callback': () => { tokenRef.current = ''; },
        });
      } catch { /* zaten render edilmiş */ }
    }
    if (window.turnstile) { render(); return; }
    if (!document.getElementById('cf-turnstile-script')) {
      const s = document.createElement('script');
      s.id = 'cf-turnstile-script';
      s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js';
      s.async = true; s.defer = true;
      document.head.appendChild(s);
    }
    const iv = setInterval(() => { if (window.turnstile) { render(); clearInterval(iv); } }, 200);
    return () => clearInterval(iv);
  }, []);

  // Animasyon fazları (tarama sürerken ilerler)
  useEffect(() => {
    if (state !== 'scanning') return;
    setPhase(0);
    const iv = setInterval(() => setPhase((p) => Math.min(p + 1, PHASES.length - 1)), 620);
    return () => clearInterval(iv);
  }, [state]);

  function resetTurnstile() {
    tokenRef.current = '';
    if (window.turnstile && widgetId.current) { try { window.turnstile.reset(widgetId.current); } catch { /* */ } }
  }

  async function onScan(e: React.FormEvent) {
    e.preventDefault();
    setError(null); setResult(null);
    if (!url.trim()) { setError('Bir alan adı girin (ör. example.com).'); return; }
    setState('scanning');
    const started = Date.now();
    try {
      const r = await api.instantScan(url.trim(), tokenRef.current || undefined, website);
      const wait = Math.max(0, 2200 - (Date.now() - started)); // en az ~2.2sn "tarama" hissi
      await new Promise((res) => setTimeout(res, wait));
      setResult(r); setState('done');
      resetTurnstile(); // token tek-kullanımlık → sonraki tarama için yenile
    } catch (err: any) {
      setError(err?.message || 'Tarama şu an tamamlanamadı. Lütfen tekrar deneyin.');
      setState('error');
      resetTurnstile();
    }
  }

  function again() {
    setState('idle'); setResult(null); setError(null);
  }

  const ok = result && result.status === 'ok' ? result : null;

  return (
    <div className="rounded-[20px] border border-line bg-white/90 p-5 shadow-lg backdrop-blur sm:p-7">
      <div className="flex items-center gap-2">
        <span className="inline-flex h-8 w-8 items-center justify-center rounded-lg bg-accent-soft text-accent-600">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden><circle cx="11" cy="11" r="7" /><path d="m21 21-4.3-4.3" strokeLinecap="round" /></svg>
        </span>
        <h2 className="text-lg font-extrabold text-brand sm:text-xl">Sitenizi ücretsiz, anında tarayın</h2>
      </div>
      <p className="mt-1.5 text-sm text-ink-soft">Saniyeler içinde bir güvenlik skoru ve öne çıkan eksikleri görün — kart/kayıt gerekmez.</p>

      {/* FORM */}
      {state === 'idle' || state === 'error' ? (
        <form onSubmit={onScan} className="mt-4">
          <div className="flex flex-col gap-2.5 sm:flex-row">
            <div className="relative flex-1">
              <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-sm text-ink-muted">https://</span>
              <input
                type="text"
                inputMode="url"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="example.com"
                className="field w-full pl-[68px]"
                aria-label="Taranacak alan adı"
              />
            </div>
            {/* HONEYPOT — gizli; yalnız botlar doldurur */}
            <input
              type="text"
              tabIndex={-1}
              autoComplete="off"
              value={website}
              onChange={(e) => setWebsite(e.target.value)}
              className="hidden"
              aria-hidden
            />
            <button type="submit" className="btn-primary shrink-0 justify-center">Ücretsiz Tara</button>
          </div>
          {/* Turnstile widget (bot doğrulaması) */}
          <div ref={widgetHost} className="mt-3 min-h-[1px]" />
          {error && <p className="mt-2 text-sm font-medium text-red-600">{error}</p>}
        </form>
      ) : null}

      {/* ANİMASYON */}
      {state === 'scanning' && (
        <div className="mt-5">
          <div className="overflow-hidden rounded-card border border-white/10 bg-[#0A1F1C] p-4 font-mono text-[13px] leading-7">
            <div className="text-white/45" dir="ltr">$ cybertestify instant-scan {url.trim()}</div>
            {PHASES.slice(0, phase + 1).map((p, i) => (
              <div key={p} className={i === phase ? 'text-white/85' : 'text-emerald-300/90'} dir="ltr">
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

      {/* SONUÇ */}
      {state === 'done' && result && (
        <div className="mt-5">
          {result.status === 'unreachable' ? (
            <div className="rounded-card border-2 border-amber-300 bg-amber-50 p-4 text-sm">
              <p className="font-bold text-amber-900">🚫 Hedefe ulaşılamadı — incelenemedi</p>
              <p className="mt-1 text-amber-900/90">
                Bu <strong>“güvenli”</strong> anlamına gelmez; yalnızca kontrollerin çalıştırılamadığını gösterir. Alan adının
                yayında/erişilebilir olduğundan emin olup tekrar deneyin.
              </p>
            </div>
          ) : ok && ok.clean ? (
            <div className="rounded-card border-2 border-emerald-200 bg-emerald-50 p-5 text-center">
              <div className={`mx-auto flex h-16 w-16 items-center justify-center rounded-full border-4 ${scoreColor(ok.score).bg}`}>
                <span className={`text-xl font-extrabold ${scoreColor(ok.score).text}`}>{ok.score}</span>
              </div>
              <p className="mt-3 font-bold text-emerald-900">Temel katmanda görünen bir sorun yok ✓</p>
              <p className="mt-1 text-sm text-emerald-900/80">
                Pasif dış gözlemde öne çıkan bir eksik bulunmadı. <strong>Daha derini</strong> (aktif enjeksiyon/IDOR doğrulaması,
                kimlik-doğrulamalı test, tam rapor) paketlerde değerlendirilir.
              </p>
              <div className="mt-4 flex flex-col gap-2 sm:flex-row sm:justify-center">
                <Link href="/tr/packages" className="btn-primary justify-center">Paketleri gör</Link>
                <button onClick={again} className="btn-outline justify-center">Başka site tara</button>
              </div>
            </div>
          ) : ok ? (
            <div className="rounded-card border border-line bg-brand-50/40 p-5">
              {/* Skor + host */}
              <div className="flex items-center gap-4">
                <div className={`flex h-16 w-16 shrink-0 items-center justify-center rounded-full border-4 ${scoreColor(ok.score).bg}`}>
                  <span className={`text-xl font-extrabold ${scoreColor(ok.score).text}`}>{ok.score}</span>
                </div>
                <div>
                  <p className="text-xs font-medium text-ink-muted">Güvenlik skoru · {ok.host}</p>
                  <p className={`text-lg font-extrabold ${scoreColor(ok.score).text}`}>Not: {ok.grade} · {ok.total} bulgu göstergesi</p>
                </div>
              </div>

              {/* ≤3 GERÇEK bulgu başlığı (yalnız "ne eksik") */}
              <ul className="mt-4 space-y-2">
                {ok.shown.map((f) => (
                  <li key={f.title} className={`flex items-center gap-2 rounded-card border px-3 py-2 text-sm font-medium ${SEV_STYLE[f.severity]}`}>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" aria-hidden><path d="M12 9v4m0 4h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z" strokeLinecap="round" strokeLinejoin="round" /></svg>
                    {f.title}
                  </li>
                ))}
              </ul>

              {/* KİLİTLİ CTA — teaser NE vermiyor, Basit Tarama NE veriyor */}
              <div className="mt-4 rounded-card border-2 border-dashed border-accent/50 bg-accent-soft/30 p-4">
                <p className="flex items-center gap-1.5 text-sm font-bold text-brand">
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden><rect x="5" y="11" width="14" height="10" rx="2" /><path d="M8 11V7a4 4 0 0 1 8 0v4" /></svg>
                  {ok.locked > 0 ? `+${ok.locked} bulgu daha kilitli` : 'Detaylar ve düzeltmeler kilitli'}
                </p>
                <p className="mt-1 text-xs leading-relaxed text-ink-soft">
                  Her bulgunun <strong>tam detayı ve iş etkisi</strong>, <strong>platforma özel hazır düzeltme kodları</strong>
                  {' '}(Nginx / IIS / Vercel / Apache) ve <strong>indirilebilir profesyonel PDF rapor</strong> →{' '}
                  <strong>Basit Tarama (₺699)</strong> ve üstü paketlerde.
                </p>
                <div className="mt-3 flex flex-col gap-2 sm:flex-row">
                  <Link href="/register" className="btn-primary justify-center sm:flex-1">Ücretsiz Doğrula ve Başla</Link>
                  <Link href="/tr/packages" className="btn-outline justify-center sm:flex-1">Paketleri gör</Link>
                </div>
              </div>

              <button onClick={again} className="mt-3 w-full text-center text-xs font-semibold text-accent-600 hover:underline">↺ Başka bir site tara</button>
            </div>
          ) : null}
        </div>
      )}

      {/* HUKUKİ / GÜVEN NOTU */}
      <p className="mt-3 text-[11px] leading-relaxed text-ink-muted">
        Bu ücretsiz bir <strong>ön izlemedir</strong>; yalnızca <strong>pasif dış gözlem</strong> yapılır (resmî denetim/sızma
        testi değildir). Aktif test (enjeksiyon/IDOR vb.) yalnızca ücretli paketlerde ve yetki beyanıyla çalışır.
      </p>
    </div>
  );
}
