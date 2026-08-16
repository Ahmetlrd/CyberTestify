'use client';

import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { api, type InstantScanResult } from '../../lib/api';
import { Turnstile, type TurnstileHandle } from '../Turnstile';

const SEV_LABEL: Record<'high' | 'medium' | 'low', string> = { high: 'Yüksek', medium: 'Orta', low: 'Düşük' };
const SEV_STYLE: Record<'high' | 'medium' | 'low', { box: string; chip: string }> = {
  high: { box: 'border-red-300 bg-red-50 text-red-900', chip: 'bg-red-600 text-white' },
  medium: { box: 'border-orange-300 bg-orange-50 text-orange-900', chip: 'bg-orange-500 text-white' },
  low: { box: 'border-amber-300 bg-amber-50 text-amber-900', chip: 'bg-amber-500 text-white' },
};

function scoreTheme(score: number) {
  if (score >= 80) return { stroke: '#059669', text: 'text-emerald-700', soft: 'bg-emerald-50 border-emerald-200' };
  if (score >= 60) return { stroke: '#d97706', text: 'text-amber-700', soft: 'bg-amber-50 border-amber-200' };
  if (score >= 45) return { stroke: '#ea580c', text: 'text-orange-700', soft: 'bg-orange-50 border-orange-200' };
  return { stroke: '#dc2626', text: 'text-red-700', soft: 'bg-red-50 border-red-200' };
}
// Notun anlamı — kullanıcı skoru nasıl yorumlayacağını bilsin (Grok: "skorun anlamı belirsiz").
function gradeWord(grade: string) {
  return { A: 'Güçlü', B: 'İyi', C: 'Orta', D: 'Zayıf', E: 'Riskli', F: 'Kritik' }[grade] ?? '';
}

function ScoreRing({ score, grade }: { score: number; grade: string }) {
  const [display, setDisplay] = useState(0);
  useEffect(() => {
    let raf = 0, start: number | null = null;
    const step = (ts: number) => {
      if (start === null) start = ts;
      const p = Math.min(1, (ts - start) / 900);
      setDisplay(Math.round((1 - Math.pow(1 - p, 3)) * score));
      if (p < 1) raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [score]);
  const t = scoreTheme(score);
  const R = 52, C = 2 * Math.PI * R;
  return (
    <div className="relative h-32 w-32 shrink-0">
      <svg viewBox="0 0 120 120" className="h-32 w-32 -rotate-90">
        <circle cx="60" cy="60" r={R} fill="none" stroke="#e5e7eb" strokeWidth="10" />
        <circle cx="60" cy="60" r={R} fill="none" stroke={t.stroke} strokeWidth="10" strokeLinecap="round" strokeDasharray={C} strokeDashoffset={C * (1 - display / 100)} style={{ transition: 'stroke-dashoffset 60ms linear' }} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className={`text-3xl font-extrabold leading-none ${t.text}`}>{display}</span>
        <span className={`mt-0.5 text-xs font-bold ${t.text}`}>{grade} · {gradeWord(grade)}</span>
      </div>
    </div>
  );
}

const PHASES = [
  'HTTPS / TLS sertifikası kontrol ediliyor…',
  'HTTP güvenlik başlıkları taranıyor…',
  'Sunucu / teknoloji imzası inceleniyor…',
  'Bulgular derleniyor…',
];
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export function InstantScan() {
  const [url, setUrl] = useState('');
  const [website, setWebsite] = useState(''); // HONEYPOT
  const [token, setToken] = useState<string | null>(null);
  const [state, setState] = useState<'idle' | 'scanning' | 'done' | 'error'>('idle');
  const [phase, setPhase] = useState(-1); // -1: sadece "bağlanılıyor"; 0+: erişildikten SONRA fazlar
  const [reachFail, setReachFail] = useState(false);
  const [result, setResult] = useState<InstantScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const turnstile = useRef<TurnstileHandle>(null);

  async function onScan(e: React.FormEvent) {
    e.preventDefault();
    setError(null); setResult(null); setReachFail(false); setPhase(-1);
    if (!url.trim()) { setError('Bir alan adı girin (ör. example.com).'); return; }
    if (!token) { setError('Lütfen önce doğrulama kutusunu tamamlayın.'); return; }
    setState('scanning');
    try {
      const r = await api.instantScan(url.trim(), token, website);
      // (DÜRÜSTLÜK) Ulaşılamadıysa: SADECE "bağlanılıyor" gösterildi; sahte faz ilerlemesi YOK.
      if (r.status === 'unreachable') {
        setReachFail(true);
        await sleep(650);
      } else {
        // Erişildi → kontroller GERÇEKTEN çalıştı; fazları hızlıca göster.
        for (let p = 0; p < PHASES.length; p++) { setPhase(p); await sleep(300); }
        await sleep(250);
      }
      setResult(r); setState('done');
    } catch (err: any) {
      setError(err?.message || 'Tarama şu an tamamlanamadı. Lütfen tekrar deneyin.');
      setState('error');
    } finally {
      setToken(null); turnstile.current?.reset();
    }
  }

  function again() { setState('idle'); setResult(null); setError(null); setReachFail(false); }

  const ok = result && result.status === 'ok' ? result : null;
  const highScore = !!ok && ok.score >= 85;

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
          <div className="mt-3"><Turnstile ref={turnstile} onToken={setToken} action="instant-scan" /></div>
          {error && <p className="mt-2 text-sm font-medium text-red-600">{error}</p>}
        </form>
      )}

      {state === 'scanning' && (
        <div className="mt-5">
          <div className="rounded-card border border-white/10 bg-[#0A1F1C] p-4 font-mono text-[13px] leading-7">
            <div className="text-white/45" dir="ltr">$ cybertestify instant-scan {url.trim()}</div>
            {/* Faz 0'a (erişim) ULAŞILANA KADAR sadece bu satır. Ulaşılamazsa burada ✗ ile durur (dürüst). */}
            <div className={reachFail ? 'text-red-300' : 'text-white/85'} dir="ltr">
              {reachFail ? '✗' : '→'} Hedefe bağlanılıyor…
              {!reachFail && phase < 0 && <span className="ml-1 inline-block h-4 w-2 translate-y-0.5 animate-pulse bg-accent/80" />}
            </div>
            {reachFail && <div className="text-red-300/80" dir="ltr">✗ Ulaşılamadı — kontroller çalıştırılamadı</div>}
            {!reachFail && PHASES.map((p, i) => (
              <div key={p} className={`${i === phase ? 'text-white/85' : 'text-emerald-300/90'} ${i <= phase ? '' : 'invisible'}`} dir="ltr">
                {i === phase ? '→' : '✓'} {p}
                {i === phase && <span className="ml-1 inline-block h-4 w-2 translate-y-0.5 animate-pulse bg-accent/80" />}
              </div>
            ))}
          </div>
        </div>
      )}

      {state === 'done' && result && (
        <div className="mt-5">
          {result.status === 'unreachable' ? (
            /* ULAŞILAMADI — boş kart değil: düzelt-tekrar + 2 maddelik rehber (Gemini #3). */
            <div className="rounded-card border-2 border-amber-300 bg-amber-50 p-5 text-sm">
              <p className="font-bold text-amber-900">🚫 Hedefe ulaşılamadı — incelenemedi</p>
              <p className="mt-1 text-amber-900/90">
                Bu <strong>“güvenli”</strong> anlamına gelmez; kontroller çalıştırılamadı. Genellikle şu iki nedenden olur:
              </p>
              <ul className="mt-2 space-y-1.5 text-amber-900/90">
                <li className="flex gap-2"><span className="font-bold">1.</span><span>Alan adını doğru yazdınız mı? Yalnızca alan adını girin (ör. <code className="rounded bg-amber-100 px-1">example.com</code>).</span></li>
                <li className="flex gap-2"><span className="font-bold">2.</span><span>Siteniz yayında mı? <strong>DNS / Cloudflare</strong> ayarlarınızı ve sitenin açık olduğunu kontrol edin.</span></li>
              </ul>
              <button onClick={again} className="btn-primary mt-4 w-full justify-center sm:w-auto">← Düzelt ve tekrar dene</button>
            </div>
          ) : ok ? (
            <div className="rounded-card border border-line bg-white p-5">
              {/* Skor + anlamı — büyük, merkezî; ne demek olduğu 1 cümle */}
              <div className="flex flex-col items-center gap-3 sm:flex-row sm:gap-5">
                <ScoreRing score={ok.score} grade={ok.grade} />
                <div className="text-center sm:text-left">
                  <p className="text-xs font-medium uppercase tracking-wide text-ink-muted">Güvenlik skoru (0–100)</p>
                  <p className="text-base font-bold text-ink">{ok.host}</p>
                  <p className="mt-1 text-sm text-ink-soft">
                    {ok.clean ? 'Pasif dış yüzeyde öne çıkan bir eksik bulunmadı.' : `Dış yüzeyde ${ok.total} güvenlik göstergesi tespit edildi.`}
                  </p>
                </div>
              </div>

              {/* Bulgu başlıkları — severity etiketli, hizalı */}
              {ok.shown.length > 0 && (
                <ul className="mt-4 space-y-2">
                  {ok.shown.map((f, i) => (
                    <li key={f.title} className={`animate-fade-up flex items-center gap-2.5 rounded-card border px-3 py-2.5 text-sm font-medium ${SEV_STYLE[f.severity].box}`} style={{ animationDelay: `${i * 110}ms` }}>
                      <span className={`inline-flex shrink-0 items-center rounded-pill px-2 py-0.5 text-[10px] font-bold uppercase leading-none ${SEV_STYLE[f.severity].chip}`}>{SEV_LABEL[f.severity]}</span>
                      <span className="leading-snug">{f.title}</span>
                    </li>
                  ))}
                </ul>
              )}

              {ok.clean ? (
                /* TEMİZ (bulgu yok) — kilitlenecek bulgu olmadığı için "kilitli" kutusu YOK. Dürüst reframe:
                   pasif katman temiz; gerçek risk aktif/kimlik-doğrulamalı testlerde → somut Aktif Doğrulama CTA'sı. */
                <div className="mt-4 rounded-card border border-brand-200 bg-brand-50/60 p-4">
                  <p className="flex items-center gap-1.5 text-sm font-extrabold text-brand">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" aria-hidden><path d="M20 6 9 17l-5-5" /></svg>
                    Pasif katman temiz
                  </p>
                  <p className="mt-1.5 text-xs leading-relaxed text-ink-soft">
                    Dış yüzeyde öne çıkan bir eksik bulunmadı. Ancak bu tarama yalnızca <strong>pasif dış katmanı</strong> görür;
                    gerçek risk çoğu zaman <strong>login-sonrası, aktif zafiyetler ve iş mantığında</strong> saklıdır —
                    bunları ancak <strong>aktif/kimlik-doğrulamalı</strong> testler ortaya çıkarır.
                  </p>
                  <div className="mt-3 flex flex-col items-stretch gap-2">
                    <Link href="/tr/packages" className="btn-primary justify-center">Aktif Doğrulama Paketi ile Derinleştir → ₺14.999</Link>
                    <Link href="/tr/packages" className="text-center text-xs font-semibold text-accent-600 hover:underline">Tüm paketleri incele →</Link>
                  </div>
                </div>
              ) : (
                /* BULGU VAR — kilitli-liste efekti (blur satırlar + asma kilit) + değer odaklı + dinamik CTA */
                <div className="relative mt-4 overflow-hidden rounded-card border-2 border-dashed border-accent/60 bg-accent-soft/25 p-4">
                  <div aria-hidden className="pointer-events-none absolute inset-x-4 bottom-3 space-y-2 opacity-50 blur-[3px]">
                    {['bg-red-200', 'bg-orange-200', 'bg-amber-200'].map((c, i) => (
                      <div key={i} className="flex items-center gap-2">
                        <span className={`h-4 w-10 rounded-pill ${c}`} />
                        <span className="h-3 flex-1 rounded-full bg-ink/15" />
                      </div>
                    ))}
                  </div>
                  <div className="relative">
                    <p className="flex items-center gap-1.5 text-sm font-extrabold text-brand">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="animate-pulse" aria-hidden><rect x="5" y="11" width="14" height="10" rx="2" /><path d="M8 11V7a4 4 0 0 1 8 0v4" /></svg>
                      {ok.locked > 0 ? `+${ok.locked} bulgu daha · detaylar & düzeltmeler kilitli` : 'Detaylar & hazır düzeltmeler kilitli'}
                    </p>
                    <p className="mt-1.5 text-xs leading-relaxed text-ink-soft">
                      Her bulgunun <strong>tam detayı</strong>, <strong>platformunuza özel hazır düzeltme kodları</strong> ve
                      <strong> indirilebilir PDF raporu</strong> kilitli.
                    </p>
                    <div className="mt-3 flex flex-col items-stretch gap-2">
                      {highScore ? (
                        <Link href="/tr/packages" className="btn-primary justify-center">Aktif Doğrulama Paketi ile Derinleştir → ₺14.999</Link>
                      ) : (
                        <Link href="/register" className="btn-primary justify-center">Detaylı Raporu Aç (₺699)</Link>
                      )}
                      <Link href="/tr/packages" className="text-center text-xs font-semibold text-accent-600 hover:underline">Tüm paketleri incele →</Link>
                    </div>
                  </div>
                </div>
              )}

              <button onClick={again} className="mt-3 inline-flex w-full items-center justify-center rounded-pill border border-line px-3 py-2 text-xs font-semibold text-ink-soft hover:bg-brand-50">↺ Başka bir site tara</button>
            </div>
          ) : null}
        </div>
      )}

      {(state === 'idle' || state === 'error') && (
        <p className="mt-3 text-[11px] leading-relaxed text-ink-muted">
          Ücretsiz <strong>ön izleme</strong> · yalnızca <strong>pasif dış gözlem</strong> (resmî denetim/sızma testi değildir).
        </p>
      )}
    </div>
  );
}
