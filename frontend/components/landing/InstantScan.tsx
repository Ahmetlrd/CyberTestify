'use client';

import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { api, type InstantScanResult } from '../../lib/api';
import { Turnstile, type TurnstileHandle } from '../Turnstile';
import { readRegionCookie } from '../../lib/region';
import { getRegion } from '../../config/regions';

// (Çok-bölge) Hero teaser + tarama log/hata/CTA metinleri tr/de/en. TR birebir korunur.
const IS = {
  tr: {
    heading: 'Sitenizi ücretsiz, anında tarayın',
    sub: 'Saniyeler içinde bir güvenlik skoru ve öne çıkan eksikleri görün — kart/kayıt gerekmez.',
    scan: 'Ücretsiz Tara', waiting: 'Doğrulama bekleniyor…',
    errDomain: 'Bir alan adı girin (ör. example.com).',
    errToken: 'Lütfen önce doğrulama kutusunu tamamlayın.',
    errScan: 'Tarama şu an tamamlanamadı. Lütfen tekrar deneyin.',
    aria: 'Taranacak alan adı',
    sev: { high: 'Yüksek', medium: 'Orta', low: 'Düşük' },
    grade: { A: 'Güçlü', B: 'İyi', C: 'Orta', D: 'Zayıf', E: 'Riskli', F: 'Kritik' } as Record<string, string>,
    phases: ['HTTPS / TLS sertifikası kontrol ediliyor…', 'HTTP güvenlik başlıkları taranıyor…', 'Sunucu / teknoloji imzası inceleniyor…', 'Bulgular derleniyor…'],
    connecting: 'Hedefe bağlanılıyor…',
    unreachInline: 'Ulaşılamadı — kontroller çalıştırılamadı',
    unreachTitle: '🚫 Hedefe ulaşılamadı — incelenemedi',
    unreachIntro: 'Bu “güvenli” anlamına gelmez; kontroller çalıştırılamadı. Genellikle şu iki nedenden olur:',
    accessTitle: '🚫 Hedefe erişilemedi — incelenemedi',
    accessMsg: (host: string, code: number, reason: string) => `${host} adresine erişilemedi (HTTP ${code}${reason ? ` — ${reason}` : ''}). Bu, hedefin bizim isteğimizi engellediği veya siteye genel erişimin kapalı olduğu anlamına gelebilir. Güvenilir bir değerlendirme yapılamadı — bu "güvenli" demek DEĞİLDİR.`,
    guide1: <>Alan adını doğru yazdınız mı? Yalnızca alan adını girin (ör. <code className="rounded bg-amber-100 px-1">example.com</code>).</>,
    guide2: <>Siteniz yayında mı? <strong>DNS / Cloudflare</strong> ayarlarınızı ve sitenin açık olduğunu kontrol edin.</>,
    fixRetry: '← Düzelt ve tekrar dene',
    scoreLabel: 'Güvenlik skoru (0–100)',
    clean: 'Pasif dış yüzeyde öne çıkan bir eksik bulunmadı.',
    finding: (n: number) => `Dış yüzeyde ${n} güvenlik göstergesi tespit edildi.`,
    cleanTitle: 'Pasif katman temiz',
    cleanBody: <>Dış yüzeyde öne çıkan bir eksik bulunmadı. Ancak bu tarama yalnızca <strong>pasif dış katmanı</strong> görür; gerçek risk çoğu zaman <strong>login-sonrası, aktif zafiyetler ve iş mantığında</strong> saklıdır — bunları ancak <strong>aktif/kimlik-doğrulamalı</strong> testler ortaya çıkarır.</>,
    ctaDeepen: (p: string) => `Aktif Doğrulama Paketi ile Derinleştir → ${p}`,
    allPackages: 'Tüm paketleri incele →',
    lockedMore: (n: number) => `+${n} bulgu daha · detaylar & düzeltmeler kilitli`,
    lockedNoMore: 'Detaylar & hazır düzeltmeler kilitli',
    lockedBody: <>Her bulgunun <strong>tam detayı</strong>, <strong>platformunuza özel hazır düzeltme kodları</strong> ve<strong> indirilebilir PDF raporu</strong> kilitli.</>,
    ctaReport: (p: string) => `Detaylı Raporu Aç (${p})`,
    scanAnother: '↺ Başka bir site tara',
    hint: <>Ücretsiz <strong>ön izleme</strong> · yalnızca <strong>pasif dış gözlem</strong> (resmî denetim/sızma testi değildir).</>,
    priceBasit: '₺699', priceActive: '₺9.999',
  },
  de: {
    heading: 'Scannen Sie Ihre Website kostenlos und sofort',
    sub: 'Sehen Sie in Sekunden einen Sicherheits-Score und die wichtigsten Schwachstellen — ohne Karte oder Registrierung.',
    scan: 'Kostenlos scannen', waiting: 'Verifizierung ausstehend…',
    errDomain: 'Geben Sie eine Domain ein (z. B. example.com).',
    errToken: 'Bitte schließen Sie zuerst die Verifizierung ab.',
    errScan: 'Der Scan konnte derzeit nicht abgeschlossen werden. Bitte versuchen Sie es erneut.',
    aria: 'Zu scannende Domain',
    sev: { high: 'Hoch', medium: 'Mittel', low: 'Niedrig' },
    grade: { A: 'Stark', B: 'Gut', C: 'Mittel', D: 'Schwach', E: 'Riskant', F: 'Kritisch' } as Record<string, string>,
    phases: ['HTTPS / TLS-Zertifikat wird geprüft…', 'HTTP-Sicherheitsheader werden gescannt…', 'Server-/Technologie-Signatur wird untersucht…', 'Befunde werden zusammengestellt…'],
    connecting: 'Verbindung zum Ziel wird hergestellt…',
    unreachInline: 'Nicht erreichbar — Prüfungen konnten nicht ausgeführt werden',
    unreachTitle: '🚫 Ziel nicht erreichbar — nicht prüfbar',
    unreachIntro: 'Das bedeutet NICHT „sicher“; die Prüfungen konnten nicht ausgeführt werden. Meist liegt es an einem dieser zwei Gründe:',
    accessTitle: '🚫 Ziel nicht erreichbar — nicht prüfbar',
    accessMsg: (host: string, code: number, reason: string) => `${host} war nicht erreichbar (HTTP ${code}${reason ? ` — ${reason}` : ''}). Das Ziel blockiert möglicherweise unsere Anfrage oder der öffentliche Zugriff ist gesperrt. Eine verlässliche Bewertung war nicht möglich — das bedeutet NICHT „sicher“.`,
    guide1: <>Haben Sie die Domain korrekt eingegeben? Geben Sie nur die Domain ein (z. B. <code className="rounded bg-amber-100 px-1">example.com</code>).</>,
    guide2: <>Ist Ihre Website online? Prüfen Sie Ihre <strong>DNS-/Cloudflare</strong>-Einstellungen und ob die Website erreichbar ist.</>,
    fixRetry: '← Korrigieren und erneut versuchen',
    scoreLabel: 'Sicherheits-Score (0–100)',
    clean: 'An der passiven externen Oberfläche wurde keine auffällige Schwachstelle gefunden.',
    finding: (n: number) => `An der externen Oberfläche wurden ${n} Sicherheitsindikatoren festgestellt.`,
    cleanTitle: 'Passive Schicht sauber',
    cleanBody: <>An der externen Oberfläche wurde keine auffällige Schwachstelle gefunden. Dieser Scan sieht jedoch nur die <strong>passive externe Schicht</strong>; das eigentliche Risiko steckt oft in <strong>Post-Login-, aktiven Schwachstellen und der Geschäftslogik</strong> — diese deckt nur ein <strong>aktiver/authentifizierter</strong> Test auf.</>,
    ctaDeepen: (p: string) => `Mit dem Paket „Aktive Verifizierung“ vertiefen → ${p}`,
    allPackages: 'Alle Pakete ansehen →',
    lockedMore: (n: number) => `+${n} weitere Befunde · Details & Behebungen gesperrt`,
    lockedNoMore: 'Details & fertige Behebungen gesperrt',
    lockedBody: <>Die <strong>vollständigen Details</strong> jedes Befunds, <strong>auf Ihre Plattform zugeschnittene fertige Behebungscodes</strong> und der<strong> herunterladbare PDF-Bericht</strong> sind gesperrt.</>,
    ctaReport: (p: string) => `Detaillierten Bericht freischalten (${p})`,
    scanAnother: '↺ Eine andere Website scannen',
    hint: <>Kostenlose <strong>Vorschau</strong> · nur <strong>passive externe Beobachtung</strong> (kein offizielles Audit/kein Penetrationstest).</>,
    priceBasit: '19 €', priceActive: '678,75 €',
  },
  en: {
    heading: 'Scan your website for free, instantly',
    sub: 'See a security score and the top gaps in seconds — no card or sign-up required.',
    scan: 'Scan for free', waiting: 'Awaiting verification…',
    errDomain: 'Enter a domain (e.g. example.com).',
    errToken: 'Please complete the verification box first.',
    errScan: 'The scan could not be completed right now. Please try again.',
    aria: 'Domain to scan',
    sev: { high: 'High', medium: 'Medium', low: 'Low' },
    grade: { A: 'Strong', B: 'Good', C: 'Fair', D: 'Weak', E: 'Risky', F: 'Critical' } as Record<string, string>,
    phases: ['Checking HTTPS / TLS certificate…', 'Scanning HTTP security headers…', 'Inspecting server / technology signature…', 'Compiling findings…'],
    connecting: 'Connecting to the target…',
    unreachInline: 'Unreachable — checks could not be run',
    unreachTitle: '🚫 Target unreachable — not assessable',
    unreachIntro: 'This does NOT mean “secure”; the checks could not be run. It is usually one of these two reasons:',
    accessTitle: '🚫 Target unreachable — not assessable',
    accessMsg: (host: string, code: number, reason: string) => `${host} could not be accessed (HTTP ${code}${reason ? ` — ${reason}` : ''}). The target may be blocking our request or public access is disabled. A reliable assessment was not possible — this does NOT mean "secure".`,
    guide1: <>Did you type the domain correctly? Enter the domain only (e.g. <code className="rounded bg-amber-100 px-1">example.com</code>).</>,
    guide2: <>Is your site live? Check your <strong>DNS / Cloudflare</strong> settings and that the site is up.</>,
    fixRetry: '← Fix and try again',
    scoreLabel: 'Security score (0–100)',
    clean: 'No notable gap was found on the passive external surface.',
    finding: (n: number) => `${n} security indicators were detected on the external surface.`,
    cleanTitle: 'Passive layer clean',
    cleanBody: <>No notable gap was found on the external surface. But this scan sees only the <strong>passive external layer</strong>; the real risk is often hidden in <strong>post-login, active vulnerabilities and business logic</strong> — only an <strong>active/authenticated</strong> test reveals those.</>,
    ctaDeepen: (p: string) => `Go deeper with the Active Verification package → ${p}`,
    allPackages: 'Browse all packages →',
    lockedMore: (n: number) => `+${n} more findings · details & fixes locked`,
    lockedNoMore: 'Details & ready-made fixes locked',
    lockedBody: <>The <strong>full detail</strong> of each finding, <strong>ready-made fix code tailored to your platform</strong> and the<strong> downloadable PDF report</strong> are locked.</>,
    ctaReport: (p: string) => `Open the detailed report (${p})`,
    scanAnother: '↺ Scan another site',
    hint: <>Free <strong>preview</strong> · <strong>passive external observation</strong> only (not an official audit/penetration test).</>,
    priceBasit: '£16', priceActive: '£583.50',
  },
} as const;

// HTTP durum kodu → standart İngilizce reason-phrase (erişim-hatası mesajında; standart olduğu için lokalize edilmez).
const HTTP_REASON: Record<number, string> = {
  400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found', 405: 'Method Not Allowed',
  406: 'Not Acceptable', 408: 'Request Timeout', 409: 'Conflict', 410: 'Gone', 421: 'Misdirected Request',
  429: 'Too Many Requests', 451: 'Unavailable For Legal Reasons',
  500: 'Internal Server Error', 501: 'Not Implemented', 502: 'Bad Gateway', 503: 'Service Unavailable', 504: 'Gateway Timeout',
};
const httpReason = (code: number): string => HTTP_REASON[code] ?? '';

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

function ScoreRing({ score, grade, gradeWord }: { score: number; grade: string; gradeWord: string }) {
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
        <span className={`mt-0.5 text-xs font-bold ${t.text}`}>{grade} · {gradeWord}</span>
      </div>
    </div>
  );
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// (TÜRKÇE-LEAK FIX) Bölge-önekli sayfada (/de, /en) InstantScan dili URL'den GELMELİ; aksi halde
// cookie'ye/tr-default'a düşüp SSR'da Türkçe metin basıyordu (ör. "Doğrulama bekleniyor…" → /de leak).
// langProp verilirse (ana sayfa URL bölgesinden) kesin kullanılır; verilmezse cookie'ye düşülür.
export function InstantScan({ lang: langProp, regionCode: regionCodeProp }: { lang?: 'tr' | 'de' | 'en'; regionCode?: string } = {}) {
  const [url, setUrl] = useState('');
  const [website, setWebsite] = useState(''); // HONEYPOT
  const [token, setToken] = useState<string | null>(null);
  const [state, setState] = useState<'idle' | 'scanning' | 'done' | 'error'>('idle');
  // (İŞ 2) Login DEĞİLSE post-tarama satın-alma CTA'ları soğuk ziyaretçiyi doğrudan ödeme/register'a
  // itmesin → /paketler'e yönlendir; login İSE akış eskisi gibi (verify) devam eder. SSR uyumu için mount'ta okunur.
  const [loggedIn, setLoggedIn] = useState(false);
  useEffect(() => { try { setLoggedIn(!!window.localStorage.getItem('token')); } catch { setLoggedIn(false); } }, []);
  const [phase, setPhase] = useState(-1); // -1: sadece "bağlanılıyor"; 0+: erişildikten SONRA fazlar
  const [reachFail, setReachFail] = useState(false);
  const [result, setResult] = useState<InstantScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const turnstile = useRef<TurnstileHandle>(null);
  const [lang, setLang] = useState<'tr' | 'de' | 'en'>(langProp ?? 'tr');
  const [regionCode, setRegionCode] = useState(regionCodeProp ?? 'tr');
  useEffect(() => {
    if (langProp) return; // URL bölgesi verildi → kesin; cookie'ye düşme (leak yok)
    const r = getRegion(readRegionCookie());
    setLang(r.lang === 'de' ? 'de' : r.lang === 'en' ? 'en' : 'tr');
    setRegionCode(r.code);
  }, [langProp]);
  const L = IS[lang];
  const PHASES = L.phases;
  const packagesHref = `/${regionCode}/packages`;

  async function onScan(e: React.FormEvent) {
    e.preventDefault();
    setError(null); setResult(null); setReachFail(false); setPhase(-1);
    if (!url.trim()) { setError(L.errDomain); return; }
    if (!token) { setError(L.errToken); return; }
    setState('scanning');
    try {
      const r = await api.instantScan(url.trim(), token, website, regionCode);
      // (DÜRÜSTLÜK) Ulaşılamadıysa: SADECE "bağlanılıyor" gösterildi; sahte faz ilerlemesi YOK.
      if (r.status === 'unreachable' || r.status === 'access_error') {
        setReachFail(true);
        await sleep(650);
      } else {
        // Erişildi → kontroller GERÇEKTEN çalıştı; fazları hızlıca göster.
        for (let p = 0; p < PHASES.length; p++) { setPhase(p); await sleep(300); }
        await sleep(250);
      }
      setResult(r); setState('done');
    } catch (err: any) {
      setError(err?.message || L.errScan);
      setState('error');
    } finally {
      setToken(null); turnstile.current?.reset();
    }
  }

  function again() { setState('idle'); setResult(null); setError(null); setReachFail(false); }

  const ok = result && result.status === 'ok' ? result : null;
  const highScore = !!ok && ok.score >= 85;

  // (İş 2 — autopopulate) Teaser'da taranan alan adını satın-alma akışına TAŞI: kullanıcı tekrar yazmasın.
  const buyHostname = ok?.host ? encodeURIComponent(ok.host) : '';
  const passiveNext = ok?.host ? `/verify?package=basit_tarama&hostname=${buyHostname}` : '/verify';
  const passiveBuyHref = `/register?next=${encodeURIComponent(passiveNext)}`;
  const activeNext = ok?.host ? `/verify?bundle=bundle_active_verify&hostname=${buyHostname}` : '/verify';
  const activeBuyHref = `/register?next=${encodeURIComponent(activeNext)}`;
  // Login değilse → paketler; login ise → mevcut satın-alma akışı (eskisi gibi).
  const effActiveHref = loggedIn ? activeBuyHref : packagesHref;
  const effPassiveHref = loggedIn ? passiveBuyHref : packagesHref;

  return (
    <div className="rounded-[20px] border border-line bg-white/95 p-5 shadow-xl backdrop-blur sm:p-7">
      <div className="flex items-center gap-2">
        <span className="inline-flex h-8 w-8 items-center justify-center rounded-lg bg-accent-soft text-accent-600">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden><circle cx="11" cy="11" r="7" /><path d="m21 21-4.3-4.3" strokeLinecap="round" /></svg>
        </span>
        <h2 className="text-lg font-extrabold text-brand sm:text-xl">{L.heading}</h2>
      </div>
      <p className="mt-1.5 text-sm text-ink-soft">{L.sub}</p>

      {(state === 'idle' || state === 'error') && (
        <form onSubmit={onScan} className="mt-4">
          <div className="flex flex-col gap-2.5 sm:flex-row">
            <div className="relative flex-1">
              <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-sm text-ink-muted">https://</span>
              <input type="text" inputMode="url" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="example.com" className="field w-full pl-[68px]" aria-label={L.aria} />
            </div>
            <input type="text" tabIndex={-1} autoComplete="off" value={website} onChange={(e) => setWebsite(e.target.value)} className="hidden" aria-hidden />
            <button type="submit" disabled={!token || !url.trim()} className="btn-primary shrink-0 justify-center disabled:cursor-not-allowed disabled:opacity-60">
              {token ? L.scan : L.waiting}
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
              {reachFail ? '✗' : '→'} {L.connecting}
              {!reachFail && phase < 0 && <span className="ml-1 inline-block h-4 w-2 translate-y-0.5 animate-pulse bg-accent/80" />}
            </div>
            {reachFail && <div className="text-red-300/80" dir="ltr">✗ {L.unreachInline}</div>}
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
            /* ULAŞILAMADI — boş kart değil: düzelt-tekrar + 2 maddelik rehber. */
            <div className="rounded-card border-2 border-amber-300 bg-amber-50 p-5 text-sm">
              <p className="font-bold text-amber-900">{L.unreachTitle}</p>
              <p className="mt-1 text-amber-900/90">{L.unreachIntro}</p>
              <ul className="mt-2 space-y-1.5 text-amber-900/90">
                <li className="flex gap-2"><span className="font-bold">1.</span><span>{L.guide1}</span></li>
                <li className="flex gap-2"><span className="font-bold">2.</span><span>{L.guide2}</span></li>
              </ul>
              <button onClick={again} className="btn-primary mt-4 w-full justify-center sm:w-auto">{L.fixRetry}</button>
            </div>
          ) : result.status === 'access_error' ? (
            /* ERİŞİM-HATASI (403/401/5xx) — bağlantı kuruldu ama geçerli yanıt alınamadı; SAHTE skor YOK. */
            <div className="rounded-card border-2 border-amber-300 bg-amber-50 p-5 text-sm">
              <p className="font-bold text-amber-900">{L.accessTitle}</p>
              <p className="mt-1 text-amber-900/90">{L.accessMsg(result.host, result.httpStatus, httpReason(result.httpStatus))}</p>
              <button onClick={again} className="mt-4 inline-flex w-full items-center justify-center rounded-pill border border-amber-400 px-3 py-2 text-xs font-semibold text-amber-900 hover:bg-amber-100 sm:w-auto">{L.scanAnother}</button>
            </div>
          ) : ok ? (
            <div className="rounded-card border border-line bg-white p-5">
              {/* Skor + anlamı — büyük, merkezî; ne demek olduğu 1 cümle */}
              <div className="flex flex-col items-center gap-3 sm:flex-row sm:gap-5">
                <ScoreRing score={ok.score} grade={ok.grade} gradeWord={L.grade[ok.grade] ?? ''} />
                <div className="text-center sm:text-left">
                  <p className="text-xs font-medium uppercase tracking-wide text-ink-muted">{L.scoreLabel}</p>
                  <p className="text-base font-bold text-ink">{ok.host}</p>
                  <p className="mt-1 text-sm text-ink-soft">
                    {ok.clean ? L.clean : L.finding(ok.total)}
                  </p>
                </div>
              </div>

              {/* Bulgu başlıkları — severity etiketli, hizalı */}
              {ok.shown.length > 0 && (
                <ul className="mt-4 space-y-2">
                  {ok.shown.map((f, i) => (
                    <li key={f.title} className={`animate-fade-up flex items-center gap-2.5 rounded-card border px-3 py-2.5 text-sm font-medium ${SEV_STYLE[f.severity].box}`} style={{ animationDelay: `${i * 110}ms` }}>
                      <span className={`inline-flex shrink-0 items-center rounded-pill px-2 py-0.5 text-[10px] font-bold uppercase leading-none ${SEV_STYLE[f.severity].chip}`}>{L.sev[f.severity]}</span>
                      <span className="leading-snug">{f.title}</span>
                    </li>
                  ))}
                </ul>
              )}

              {ok.clean ? (
                /* TEMİZ (bulgu yok) — pasif katman temiz; aktif CTA. */
                <div className="mt-4 rounded-card border border-brand-200 bg-brand-50/60 p-4">
                  <p className="flex items-center gap-1.5 text-sm font-extrabold text-brand">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" aria-hidden><path d="M20 6 9 17l-5-5" /></svg>
                    {L.cleanTitle}
                  </p>
                  <p className="mt-1.5 text-xs leading-relaxed text-ink-soft">{L.cleanBody}</p>
                  <div className="mt-3 flex flex-col items-stretch gap-2">
                    <Link href={effActiveHref} className="btn-primary justify-center">{L.ctaDeepen(L.priceActive)}</Link>
                    <Link href={packagesHref} className="text-center text-xs font-semibold text-accent-600 hover:underline">{L.allPackages}</Link>
                  </div>
                </div>
              ) : (
                /* BULGU VAR — kilitli-liste efekti + değer odaklı + dinamik CTA */
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
                      {ok.locked > 0 ? L.lockedMore(ok.locked) : L.lockedNoMore}
                    </p>
                    <p className="mt-1.5 text-xs leading-relaxed text-ink-soft">{L.lockedBody}</p>
                    <div className="mt-3 flex flex-col items-stretch gap-2">
                      {highScore ? (
                        <Link href={effActiveHref} className="btn-primary justify-center">{L.ctaDeepen(L.priceActive)}</Link>
                      ) : (
                        <Link href={effPassiveHref} className="btn-primary justify-center">{L.ctaReport(L.priceBasit)}</Link>
                      )}
                      <Link href={packagesHref} className="text-center text-xs font-semibold text-accent-600 hover:underline">{L.allPackages}</Link>
                    </div>
                  </div>
                </div>
              )}

              <button onClick={again} className="mt-3 inline-flex w-full items-center justify-center rounded-pill border border-line px-3 py-2 text-xs font-semibold text-ink-soft hover:bg-brand-50">{L.scanAnother}</button>
            </div>
          ) : null}
        </div>
      )}

      {(state === 'idle' || state === 'error') && (
        <p className="mt-3 text-[11px] leading-relaxed text-ink-muted">{L.hint}</p>
      )}
    </div>
  );
}
