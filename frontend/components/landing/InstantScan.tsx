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
    scanPh: 'firmaniz.com',
    suggestLead: 'Bunu mu demek istediniz?',
    errToken: 'Lütfen önce doğrulama kutusunu tamamlayın.',
    errScan: 'Tarama şu an tamamlanamadı. Lütfen tekrar deneyin.',
    aria: 'Taranacak alan adı',
    sev: { high: 'Yüksek', medium: 'Orta', low: 'Düşük' },
    grade: { A: 'Güçlü', B: 'İyi', C: 'Orta', D: 'Zayıf', E: 'Riskli', F: 'Kritik' } as Record<string, string>,
    phases: ['HTTPS / TLS sertifikası doğrulanıyor…', 'HTTP güvenlik başlıkları taranıyor…', 'Sunucu ve teknoloji imzası çıkarılıyor…', 'Güvenlik başlığı politikaları karşılaştırılıyor…', 'Çerez ve yönlendirme yapılandırması inceleniyor…', 'Dış yüzey göstergeleri değerlendiriliyor…', 'Bulgular derleniyor ve puanlanıyor…'],
    connecting: 'Hedefe bağlanılıyor…',
    unreachInline: 'Ulaşılamadı — kontroller çalıştırılamadı',
    unreachTitle: 'Hedefe ulaşılamadı — incelenemedi',
    unreachIntro: 'Bu “güvenli” anlamına gelmez; kontroller çalıştırılamadı. Genellikle şu iki nedenden olur:',
    accessTitle: 'Hedefe erişilemedi — incelenemedi',
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
    nextTitle: 'Bir sonraki adım',
    nextSurface: 'Dış Yüzey & Yapılandırma',
    nextSurfaceHint: 'Yapılandırma ve başlık eksiklerini derinlemesine tarar, düzeltme kodları verir.',
    nextActive: 'Aktif Doğrulama',
    nextActiveHint: 'Login-sonrası ve aktif zafiyetleri gerçek problarla doğrular.',
    gapsFound: (n: number) => `Dış yüzeyinizde ${n} açık bulundu`,
    ratedHigh: (n: number) => `${n} tanesi YÜKSEK riskli`,
    summaryNote: 'Bu ekran özeti gösterir. Tam rapor her açığı ve nasıl kapatılacağını anlatır.',
    emailBtnFull: 'Tam PDF raporumu gönder',
    emailReassure: 'Ücretsiz · ~1 dk içinde gelir · kart yok, satış görüşmesi yok',
    topFindings: 'Öne çıkan bulgular',
    fixIncluded: 'Çözümü şu pakette →',
    pkgSurfaceShort: 'Dış Yüzey',
    moreInReport: (n: number) => `+${n} tanesi tam raporda`,
    cantSee: 'Bu taramanın göremedikleri',
    biggerRisk: 'Genelde asıl risk',
    cantSeeBody: 'Login-sonrası zafiyetler, iş mantığı hataları ve API kötüye kullanımı ancak aktif/kimlik-doğrulamalı testlerle ortaya çıkar.',
    coversGaps: (n: number) => `${n} BULGUNU KAPSAR`,
    recommended: 'ÖNERİLEN',
    beyondScan: 'BU TARAMANIN ÖTESİ',
    viewPackage: 'Paketi gör →',
    lockedMore: (n: number) => `+${n} bulgu daha · detaylar & düzeltmeler kilitli`,
    lockedNoMore: 'Detaylar & hazır düzeltmeler kilitli',
    lockedBody: <>Her bulgunun <strong>tam detayı</strong>, <strong>platformunuza özel hazır düzeltme kodları</strong> ve<strong> indirilebilir PDF raporu</strong> kilitli.</>,
    ctaReport: (p: string) => `Detaylı Raporu Aç (${p})`,
    deeperTitle: 'Daha derine inin',
    deeperBody: <>Bu tarama yalnızca <strong>pasif dış katmanı</strong> görür. Gerçek risk çoğu zaman <strong>login-sonrası, aktif zafiyetler ve iş mantığında</strong> saklıdır — bunları <strong>aktif/kimlik-doğrulamalı</strong> testler ortaya çıkarır.</>,
    scanAnother: '↺ Başka bir site tara',
    findingFix: 'Bunu düzelten paketi gör',
    hint: <>Ücretsiz <strong>ön izleme</strong> · yalnızca <strong>pasif dış gözlem</strong> (resmî denetim/sızma testi değildir).</>,
    emailTitle: 'Tam raporu görün — e-postanızı yazın',
    emailEyebrow: 'ÜCRETSİZ TAM RAPOR',
    emailSub: 'Gerçek zamanlı Basit Tarama raporunuzu PDF olarak hemen indirin. Kart gerekmez.',
    emailPh: 'ornek@sirket.com',
    emailBtn: 'Raporu Gör',
    emailBusy: 'Raporunuz hazırlanıyor…',
    emailInvalid: 'Geçerli bir e-posta adresi girin.',
    reportReady: 'Raporunuz hazır',
    reportDownload: '⬇ Basit Tarama Raporunu İndir (PDF)',
    reportErrMsg: 'Rapor şu an oluşturulamadı. Lütfen tekrar deneyin.',
    priceBasit: '₺699', priceActive: '₺9.999',
  },
  de: {
    heading: 'Scannen Sie Ihre Website kostenlos und sofort',
    sub: 'Sehen Sie in Sekunden einen Sicherheits-Score und die wichtigsten Schwachstellen — ohne Karte oder Registrierung.',
    scan: 'Kostenlos scannen', waiting: 'Verifizierung ausstehend…',
    errDomain: 'Geben Sie eine Domain ein (z. B. example.com).',
    scanPh: 'ihre-firma.de',
    suggestLead: 'Meinten Sie?',
    errToken: 'Bitte schließen Sie zuerst die Verifizierung ab.',
    errScan: 'Der Scan konnte derzeit nicht abgeschlossen werden. Bitte versuchen Sie es erneut.',
    aria: 'Zu scannende Domain',
    sev: { high: 'Hoch', medium: 'Mittel', low: 'Niedrig' },
    grade: { A: 'Stark', B: 'Gut', C: 'Mittel', D: 'Schwach', E: 'Riskant', F: 'Kritisch' } as Record<string, string>,
    phases: ['HTTPS / TLS-Zertifikat wird verifiziert…', 'HTTP-Sicherheitsheader werden gescannt…', 'Server- und Technologiesignatur wird extrahiert…', 'Sicherheitsheader-Richtlinien werden verglichen…', 'Cookie- und Weiterleitungskonfiguration wird geprüft…', 'Indikatoren der Außenfläche werden bewertet…', 'Befunde werden zusammengestellt und bewertet…'],
    connecting: 'Verbindung zum Ziel wird hergestellt…',
    unreachInline: 'Nicht erreichbar — Prüfungen konnten nicht ausgeführt werden',
    unreachTitle: 'Ziel nicht erreichbar — nicht prüfbar',
    unreachIntro: 'Das bedeutet NICHT „sicher“; die Prüfungen konnten nicht ausgeführt werden. Meist liegt es an einem dieser zwei Gründe:',
    accessTitle: 'Ziel nicht erreichbar — nicht prüfbar',
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
    nextTitle: 'Nächster Schritt',
    nextSurface: 'Außenfläche & Konfiguration',
    nextSurfaceHint: 'Prüft Konfigurations- und Header-Lücken tiefgehend und liefert Fix-Codes.',
    nextActive: 'Aktive Verifizierung',
    nextActiveHint: 'Verifiziert Post-Login- und aktive Schwachstellen mit echten Proben.',
    gapsFound: (n: number) => `${n} Lücken auf Ihrer Außenfläche gefunden`,
    ratedHigh: (n: number) => `${n} als HOCH eingestuft`,
    summaryNote: 'Diese Ansicht zeigt die Zusammenfassung. Der vollständige Bericht erklärt jede Lücke und wie man sie behebt.',
    emailBtnFull: 'Vollständigen PDF-Bericht senden',
    emailReassure: 'Kostenlos · in ~1 Min · keine Karte, kein Verkaufsgespräch',
    topFindings: 'Wichtigste Funde',
    fixIncluded: 'Behebung enthalten in →',
    pkgSurfaceShort: 'Außenfläche',
    moreInReport: (n: number) => `+${n} weitere im vollständigen Bericht`,
    cantSee: 'Was dieser Scan nicht sieht',
    biggerRisk: 'Meist das größere Risiko',
    cantSeeBody: 'Post-Login-Schwachstellen, Geschäftslogikfehler und API-Missbrauch zeigen sich nur bei aktiven/authentifizierten Tests.',
    coversGaps: (n: number) => `DECKT IHRE ${n} LÜCKEN AB`,
    recommended: 'EMPFOHLEN',
    beyondScan: 'ÜBER DIESEN SCAN HINAUS',
    viewPackage: 'Paket ansehen →',
    lockedMore: (n: number) => `+${n} weitere Befunde · Details & Behebungen gesperrt`,
    lockedNoMore: 'Details & fertige Behebungen gesperrt',
    lockedBody: <>Die <strong>vollständigen Details</strong> jedes Befunds, <strong>auf Ihre Plattform zugeschnittene fertige Behebungscodes</strong> und der<strong> herunterladbare PDF-Bericht</strong> sind gesperrt.</>,
    ctaReport: (p: string) => `Detaillierten Bericht freischalten (${p})`,
    deeperTitle: 'Gehen Sie tiefer',
    deeperBody: <>Dieser Scan sieht nur die <strong>passive Außenschicht</strong>. Das echte Risiko liegt oft <strong>nach dem Login, in aktiven Schwachstellen und der Geschäftslogik</strong> — das zeigen <strong>aktive/authentifizierte</strong> Tests.</>,
    scanAnother: '↺ Eine andere Website scannen',
    findingFix: 'Paket ansehen, das dies behebt',
    hint: <>Kostenlose <strong>Vorschau</strong> · nur <strong>passive externe Beobachtung</strong> (kein offizielles Audit/kein Penetrationstest).</>,
    emailTitle: 'Vollständigen Bericht ansehen — E-Mail eingeben',
    emailEyebrow: 'KOSTENLOSER VOLLBERICHT',
    emailSub: 'Laden Sie Ihren Echtzeit-Basis-Scan-Bericht sofort als PDF herunter. Keine Karte nötig.',
    emailPh: 'name@firma.de',
    emailBtn: 'Bericht ansehen',
    emailBusy: 'Ihr Bericht wird erstellt…',
    emailInvalid: 'Bitte geben Sie eine gültige E-Mail-Adresse ein.',
    reportReady: 'Ihr Bericht ist fertig',
    reportDownload: '⬇ Basis-Scan-Bericht herunterladen (PDF)',
    reportErrMsg: 'Der Bericht konnte derzeit nicht erstellt werden. Bitte erneut versuchen.',
    priceBasit: '55 €', priceActive: '279 €',
  },
  en: {
    heading: 'Scan your website for free, instantly',
    sub: 'See a security score and the top gaps in seconds — no card or sign-up required.',
    scan: 'Scan for free', waiting: 'Awaiting verification…',
    errDomain: 'Enter a domain (e.g. example.com).',
    scanPh: 'yourcompany.com',
    suggestLead: 'Did you mean?',
    errToken: 'Please complete the verification box first.',
    errScan: 'The scan could not be completed right now. Please try again.',
    aria: 'Domain to scan',
    sev: { high: 'High', medium: 'Medium', low: 'Low' },
    grade: { A: 'Strong', B: 'Good', C: 'Fair', D: 'Weak', E: 'Risky', F: 'Critical' } as Record<string, string>,
    phases: ['Verifying HTTPS / TLS certificate…', 'Scanning HTTP security headers…', 'Extracting server and technology signature…', 'Comparing security-header policies…', 'Inspecting cookie and redirect configuration…', 'Evaluating external-surface indicators…', 'Compiling and scoring findings…'],
    connecting: 'Connecting to the target…',
    unreachInline: 'Unreachable — checks could not be run',
    unreachTitle: 'Target unreachable — not assessable',
    unreachIntro: 'This does NOT mean “secure”; the checks could not be run. It is usually one of these two reasons:',
    accessTitle: 'Target unreachable — not assessable',
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
    nextTitle: 'Next step',
    nextSurface: 'External Surface & Config',
    nextSurfaceHint: 'Deep-scans configuration and header gaps and provides fix codes.',
    nextActive: 'Active Verification',
    nextActiveHint: 'Verifies post-login and active vulnerabilities with real probes.',
    gapsFound: (n: number) => `${n} gaps found on your external surface`,
    ratedHigh: (n: number) => `${n} rated HIGH`,
    summaryNote: 'This page shows the summary. The full report explains each gap and how to fix it.',
    emailBtnFull: 'Send my full PDF report',
    emailReassure: 'Free · arrives in ~1 min · no card, no sales call',
    topFindings: 'Top findings',
    fixIncluded: 'Fix included in →',
    pkgSurfaceShort: 'External Surface',
    moreInReport: (n: number) => `+${n} more in the full report`,
    cantSee: "What this scan can't see",
    biggerRisk: 'Usually the bigger risk',
    cantSeeBody: 'Post-login vulnerabilities, business-logic flaws and API abuse only show up with active/authenticated testing.',
    coversGaps: (n: number) => `COVERS YOUR ${n} GAPS`,
    recommended: 'RECOMMENDED',
    beyondScan: 'GOES BEYOND THIS SCAN',
    viewPackage: 'View package →',
    lockedMore: (n: number) => `+${n} more findings · details & fixes locked`,
    lockedNoMore: 'Details & ready-made fixes locked',
    lockedBody: <>The <strong>full detail</strong> of each finding, <strong>ready-made fix code tailored to your platform</strong> and the<strong> downloadable PDF report</strong> are locked.</>,
    ctaReport: (p: string) => `Open the detailed report (${p})`,
    deeperTitle: 'Go deeper',
    deeperBody: <>This scan only sees the <strong>passive external layer</strong>. Real risk often hides <strong>post-login, in active vulnerabilities and business logic</strong> — surfaced by <strong>active/authenticated</strong> testing.</>,
    scanAnother: '↺ Scan another site',
    findingFix: 'See the package that fixes this',
    hint: <>Free <strong>preview</strong> · <strong>passive external observation</strong> only (not an official audit/penetration test).</>,
    emailTitle: 'See the full report — enter your e-mail',
    emailEyebrow: 'FREE FULL REPORT',
    emailSub: 'Download your real-time Basic Scan report as a PDF right away. No card needed.',
    emailPh: 'you@company.com',
    emailBtn: 'See the report',
    emailBusy: 'Preparing your report…',
    emailInvalid: 'Enter a valid e-mail address.',
    reportReady: 'Your report is ready',
    reportDownload: '⬇ Download Basic Scan report (PDF)',
    reportErrMsg: 'The report could not be created right now. Please try again.',
    priceBasit: '£49', priceActive: '£249',
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

function ScoreRing({ score, grade, gradeWord, dark = false }: { score: number; grade: string; gradeWord: string; dark?: boolean }) {
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
        <circle cx="60" cy="60" r={R} fill="none" stroke={dark ? 'rgba(255,255,255,0.16)' : '#e5e7eb'} strokeWidth="10" />
        <circle cx="60" cy="60" r={R} fill="none" stroke={t.stroke} strokeWidth="10" strokeLinecap="round" strokeDasharray={C} strokeDashoffset={C * (1 - display / 100)} style={{ transition: 'stroke-dashoffset 60ms linear' }} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className={`text-3xl font-extrabold leading-none ${dark ? 'text-white' : t.text}`}>{display}</span>
        <span className={`mt-0.5 text-xs font-bold ${dark ? 'text-amber-300' : t.text}`}>{grade} · {gradeWord}</span>
      </div>
    </div>
  );
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// (TÜRKÇE-LEAK FIX) Bölge-önekli sayfada (/de, /en) InstantScan dili URL'den GELMELİ; aksi halde
// cookie'ye/tr-default'a düşüp SSR'da Türkçe metin basıyordu (ör. "Doğrulama bekleniyor…" → /de leak).
// langProp verilirse (ana sayfa URL bölgesinden) kesin kullanılır; verilmezse cookie'ye düşülür.
// (KALICILIK) Ücretsiz tarama sonucu tarayıcıda (localStorage) kısa süre saklanır → sayfa yenilense/
// yanlışlıkla kapatılsa da sonuç + rapor erişimi KAYBOLMAZ. 1 saat TTL; sadece bu ziyaretçinin cihazında,
// sunucuya gitmez. "Başka bir site tara" ile temizlenir.
const STORE_KEY = 'ct_instant_scan_v1';
const STORE_TTL_MS = 60 * 60 * 1000;

/**
 * Tarama sonrası "Bir sonraki adım" önerisi — FİYAT GÖSTERMEZ (kullanıcı isteği: fiyatı
 * ancak tıklayıp paketler sayfasına gidince görsün). Bulguya göre sıralama değişir:
 *  - Bulgu VARSA: önce "Dış Yüzey & Yapılandırma" (bulunan config/başlık eksiklerini derinleştirir),
 *  - TEMİZSE: önce "Aktif Doğrulama" (pasifin ötesine, login-sonrası/aktif zafiyetlere geçer).
 */
function NextSteps({ clean, L, packagesHref }: { clean: boolean; L: any; packagesHref: string }) {
  const surface = { key: 'bundle_surface', name: L.nextSurface, hint: L.nextSurfaceHint };
  const active = { key: 'bundle_active_verify', name: L.nextActive, hint: L.nextActiveHint };
  const options = clean ? [active, surface] : [surface, active];
  return (
    <div className="mt-3">
      <p className="text-[11px] font-extrabold uppercase tracking-wide text-ink-soft/70">{L.nextTitle}</p>
      <div className="mt-2 flex flex-col items-stretch gap-2">
        {options.map((o, i) => (
          <Link
            key={o.key}
            href={`${packagesHref}?focus=${o.key}`}
            className={`flex items-center gap-2 rounded-card px-3 py-2.5 text-left transition ${
              i === 0
                ? 'bg-accent-600 text-white shadow-sm hover:brightness-105'
                : 'border border-line bg-white text-ink hover:bg-brand-50'
            }`}
          >
            <span className="min-w-0 flex-1">
              <span className="block text-sm font-bold">{o.name}</span>
              <span className={`mt-0.5 block text-[11px] font-normal leading-snug ${i === 0 ? 'text-white/85' : 'text-ink-soft'}`}>{o.hint}</span>
            </span>
            <span aria-hidden className="shrink-0 text-lg leading-none">→</span>
          </Link>
        ))}
        <Link href={packagesHref} className="mt-0.5 text-center text-xs font-semibold text-accent-600 hover:underline">{L.allPackages}</Link>
      </div>
    </div>
  );
}

// (AKILLI ÖNERİ) Kullanıcı TLD'siz yazarsa (ör. "firma") tek-tıkla ".com" öner. Nokta VARSA zaten
// geçerli aday → öneri yok; boşluk varsa (çok kelime) güvenilmez → öneri yok, normal hata yolu işler.
function suggestDomain(v: string): string | null {
  const h = v.trim().toLowerCase()
    .replace(/^[a-z][a-z0-9+.-]*:\/\//, '')
    .replace(/[/?#].*$/, '')
    .replace(/^www\./, '');
  if (!h || h.includes('.') || /\s/.test(h)) return null;
  return `${h}.com`;
}

export function InstantScan({ lang: langProp, regionCode: regionCodeProp, priceBasit: priceBasitProp, priceActive: priceActiveProp }: { lang?: 'tr' | 'de' | 'en'; regionCode?: string; priceBasit?: string | null; priceActive?: string | null } = {}) {
  const [url, setUrl] = useState('');
  const [website, setWebsite] = useState(''); // HONEYPOT
  const [token, setToken] = useState<string | null>(null);
  const [state, setState] = useState<'idle' | 'scanning' | 'done' | 'error'>('idle');
  // (İŞ 2) Login DEĞİLSE post-tarama satın-alma CTA'ları soğuk ziyaretçiyi doğrudan ödeme/register'a
  // itmesin → /paketler'e yönlendir; login İSE akış eskisi gibi (verify) devam eder. SSR uyumu için mount'ta okunur.
  const [loggedIn, setLoggedIn] = useState(false);
  useEffect(() => { try { setLoggedIn(!!window.localStorage.getItem('token')); } catch { setLoggedIn(false); } }, []);
  // (KALICILIK) Mount'ta son sonucu geri yükle (TTL içindeyse). Rapor blob'u oturuma özeldir → geri
  // gelmez; ama sonuç + e-posta korunur, kullanıcı "Raporu Gör"e tekrar basınca rapor yeniden gelir.
  useEffect(() => {
    try {
      const raw = window.localStorage.getItem(STORE_KEY);
      if (!raw) return;
      const saved = JSON.parse(raw) as { result?: InstantScanResult; email?: string; ts?: number; lang?: string };
      if (!saved?.result || !saved.ts || Date.now() - saved.ts > STORE_TTL_MS) { window.localStorage.removeItem(STORE_KEY); return; }
      // (ÇOK-DİL LEAK FIX) Sonuç, TARANDIĞI dilde saklanır (bulgu başlıkları backend'de o dile göre üretilir).
      // Şu anki sayfanın dili farklıysa GERİ YÜKLEME — aksi halde /tr'de taranan Türkçe başlıklar /de arayüzünde
      // görünür. Silme (o dile dönülürse dursun); yalnız bu dilde gösterme.
      const effLang = langProp ?? ((): 'tr' | 'de' | 'en' => { const l = getRegion(readRegionCookie()).lang; return l === 'de' ? 'de' : l === 'en' ? 'en' : 'tr'; })();
      if (saved.lang && saved.lang !== effLang) return;
      setResult(saved.result);
      if (saved.email) setEmail(saved.email);
      setState('done');
    } catch { /* noop */ }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps
  const [phase, setPhase] = useState(-1); // -1: sadece "bağlanılıyor"; 0+: erişildikten SONRA fazlar
  // (ANA SAYFA LEAD — TAM RAPOR) e-posta karşılığı gerçek Basit Tarama PDF'i (ödeme/kayıt/admin-onayı YOK).
  const [email, setEmail] = useState('');
  const [reportState, setReportState] = useState<'idle' | 'busy' | 'ready' | 'error'>('idle');
  const [reportUrl, setReportUrl] = useState<string | null>(null);
  const [reportErr, setReportErr] = useState<string | null>(null);
  const [reachFail, setReachFail] = useState(false);
  const [result, setResult] = useState<InstantScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [suggest, setSuggest] = useState<string | null>(null); // AKILLI ÖNERİ: noktasız girişte '.com' adayı
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

  // Çekirdek tarama — hem form gönderimi hem "akıllı öneri" tıklaması buradan geçer.
  async function doScan(raw: string) {
    setError(null); setResult(null); setReachFail(false); setPhase(-1); setSuggest(null);
    const v = raw.trim();
    if (!v) { setError(L.errDomain); return; }
    if (!token) { setError(L.errToken); return; }
    setState('scanning');
    // (GERÇEK TARAMA — terminal) Fazları GERÇEK Basit Tarama SÜRESİNCE ilerlet: yanıt gelene kadar her ~850ms
    // bir satır büyür (son fazda bekler). Yanıt gelince durur. Böylece süre sahte değil, gerçek taramaya bağlı.
    let advanced = -1;
    const phaseTimer = setInterval(() => { advanced = Math.min(advanced + 1, PHASES.length - 1); setPhase(advanced); }, 850);
    try {
      const r = await api.instantScan(v, token, website, regionCode);
      clearInterval(phaseTimer);
      // (DÜRÜSTLÜK) Ulaşılamadı/erişilemedi → "bağlanılıyor"a dön, sahte tamamlanma yok.
      if (r.status === 'unreachable' || r.status === 'access_error') {
        setReachFail(true); setPhase(-1);
        await sleep(650);
      } else {
        setPhase(PHASES.length - 1); // tüm adımlar tamamlandı
        await sleep(300);
      }
      setResult(r); setState('done');
      try { window.localStorage.setItem(STORE_KEY, JSON.stringify({ result: r, email: '', ts: Date.now(), lang })); } catch { /* noop */ }
    } catch (err: any) {
      clearInterval(phaseTimer);
      setError(err?.message || L.errScan);
      setState('error');
    } finally {
      setToken(null); turnstile.current?.reset();
    }
  }

  function onScan(e: React.FormEvent) {
    e.preventDefault();
    setSuggest(null); setError(null);
    const v = url.trim();
    if (!v) { setError(L.errDomain); return; }
    // Nokta yok = TLD yok (ör. "firma") → backend'e gitmeden ".com" öner, tek tıkla düzelt.
    const guess = v.includes('.') ? null : suggestDomain(v);
    if (guess) { setSuggest(guess); return; }
    doScan(v);
  }

  function again() {
    setState('idle'); setResult(null); setError(null); setReachFail(false); setSuggest(null);
    setEmail(''); setReportState('idle'); setReportErr(null);
    if (reportUrl) { URL.revokeObjectURL(reportUrl); setReportUrl(null); }
    try { window.localStorage.removeItem(STORE_KEY); } catch { /* noop */ }
  }

  const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  // (#1) Rapor ham blob PDF olarak acilinca sekme about:blank + jenerik ikon oluyordu. Onun yerine
  // markali bir HTML wrapper (blob) ac: sekme "CyberTestify | {domain}" + site favicon, PDF iframe icinde.
  function openBrandedReport(pdfBlobUrl: string, host: string) {
    const safeHost = String(host).replace(/[<>&"']/g, '');
    const title = `CyberTestify | ${safeHost}`;
    const html = `<!doctype html><html lang="${lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${title}</title><link rel="icon" href="https://cybertestify.com/icon.svg" type="image/svg+xml"><style>html,body{margin:0;height:100%;background:#1b2b2a}iframe{width:100%;height:100%;border:0;display:block}</style></head><body><iframe src="${pdfBlobUrl}" title="${title}"></iframe></body></html>`;
    const wrapperUrl = URL.createObjectURL(new Blob([html], { type: 'text/html' }));
    window.open(wrapperUrl, '_blank');
  }

  async function submitReport(host: string, logId?: string) {
    const em = email.trim();
    if (!EMAIL_RE.test(em)) { setReportErr(L.emailInvalid); return; }
    setReportState('busy'); setReportErr(null);
    try {
      const blob = await api.instantScanReport({ logId, url: host, email: em, region: regionCode });
      if (reportUrl) URL.revokeObjectURL(reportUrl);
      setReportUrl(URL.createObjectURL(blob)); setReportState('ready');
      try { window.localStorage.setItem(STORE_KEY, JSON.stringify({ result, email: em, ts: Date.now(), lang })); } catch { /* noop */ }
    } catch (e) {
      setReportErr((e as Error)?.message || L.reportErrMsg); setReportState('error');
    }
  }

  const ok = result && result.status === 'ok' ? result : null;
  const highScore = !!ok && ok.score >= 85;

  // (İş 2 — autopopulate) Teaser'da taranan alan adını satın-alma akışına TAŞI: kullanıcı tekrar yazmasın.
  const buyHostname = ok?.host ? encodeURIComponent(ok.host) : '';
  const passiveNext = ok?.host ? `/verify?package=basit_tarama&hostname=${buyHostname}` : '/verify';
  const passiveBuyHref = `/register?next=${encodeURIComponent(passiveNext)}`;
  const activeNext = ok?.host ? `/verify?bundle=bundle_active_verify&hostname=${buyHostname}` : '/verify';
  const activeBuyHref = `/register?next=${encodeURIComponent(activeNext)}`;
  // Login değilse → paketler; login ise → mevcut satın-alma akışı (eskisi gibi).
  // (#4) Taranan domain'i paketler zincirine tasi (login degilse packages -> Satin Al -> /verify?hostname=).
  const domainQ = buyHostname ? `&domain=${buyHostname}` : '';
  const effActiveHref = loggedIn ? activeBuyHref : `${packagesHref}?focus=bundle_active_verify${domainQ}`;
  const effPassiveHref = loggedIn ? passiveBuyHref : `${packagesHref}?focus=basit_tarama${domainQ}`;
  // (İŞ 1) Fiyatlar CANLI API'den (server sayfası prop geçer) → de/en/tr her zaman doğru, hardcoded drift YOK.
  const pxBasit = priceBasitProp ?? L.priceBasit;
  const pxActive = priceActiveProp ?? L.priceActive;

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
              <input type="text" inputMode="url" value={url} onChange={(e) => setUrl(e.target.value)} placeholder={L.scanPh} className="field w-full pl-[68px]" aria-label={L.aria} />
            </div>
            <input type="text" tabIndex={-1} autoComplete="off" value={website} onChange={(e) => setWebsite(e.target.value)} className="hidden" aria-hidden />
            <button type="submit" disabled={!token || !url.trim()} className="btn-primary shrink-0 justify-center disabled:cursor-not-allowed disabled:opacity-60">
              {token ? L.scan : L.waiting}
            </button>
          </div>
          <div className="mt-3"><Turnstile ref={turnstile} onToken={setToken} action="instant-scan" /></div>
          {error && <p className="mt-2 text-sm font-medium text-red-600">{error}</p>}
          {suggest && (
            <p className="mt-2 text-sm text-ink-soft">
              {L.suggestLead}{' '}
              <button type="button" onClick={() => { setUrl(suggest); doScan(suggest); }} className="font-bold text-brand underline decoration-accent decoration-2 underline-offset-2 transition hover:text-accent-600">{suggest}</button>
            </p>
          )}
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
            <div className="rounded-card border border-line bg-brand-50/30 p-4 sm:p-5">
              {/* ===== 1b — KOYU SKOR KUTUSU: skor + TEK birincil aksiyon (e-posta) AYNI kutuda ===== */}
              <div className="rounded-card bg-brand p-4 text-white sm:p-5">
                <div className="flex flex-col items-center gap-4 sm:flex-row sm:gap-5">
                  <ScoreRing score={ok.score} grade={ok.grade} gradeWord={L.grade[ok.grade] ?? ''} dark />
                  <div className="min-w-0 text-center sm:text-left">
                    <p className="text-[10.5px] font-semibold uppercase tracking-wider text-white/55">{ok.host}</p>
                    <p className="mt-0.5 text-base font-bold leading-snug">
                      {ok.clean ? L.cleanTitle : (
                        <>{L.gapsFound(ok.total)}{ok.shown.some((f) => f.severity === 'high') && (<span className="text-amber-300"> — {L.ratedHigh(ok.shown.filter((f) => f.severity === 'high').length)}</span>)}</>
                      )}
                    </p>
                    <p className="mt-1 text-xs leading-relaxed text-white/65">{ok.clean ? L.cleanBody : L.summaryNote}</p>
                  </div>
                </div>
                {/* E-posta formu — dark box İÇİNDE (rapor hazır olunca indir butonuna döner) */}
                <div className="mt-4">
                  {reportState === 'ready' && reportUrl ? (
                    <div className="flex flex-col items-center gap-2.5 rounded-lg bg-white/10 p-3 text-center sm:flex-row sm:justify-between sm:text-left">
                      <p className="flex items-center gap-2 text-sm font-bold">
                        <span className="inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-emerald-400 text-brand"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" aria-hidden><path d="M20 6 9 17l-5-5" /></svg></span>
                        {L.reportReady}
                      </p>
                      <button type="button" onClick={() => reportUrl && openBrandedReport(reportUrl, ok.host)} className="btn-primary w-full justify-center sm:w-auto">{L.reportDownload}</button>
                    </div>
                  ) : (
                    <>
                      <div className="flex flex-col gap-2 sm:flex-row">
                        <input
                          type="email" inputMode="email" value={email} onChange={(e) => setEmail(e.target.value)}
                          onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); submitReport(ok.host, ok.logId); } }}
                          placeholder={L.emailPh} aria-label={L.emailBtnFull} disabled={reportState === 'busy'}
                          className="flex-1 rounded-lg border border-white/20 bg-white/10 px-3 py-3 text-sm text-white placeholder-white/45 outline-none transition focus:border-white/45"
                        />
                        <button type="button" onClick={() => submitReport(ok.host, ok.logId)} disabled={reportState === 'busy'} className="btn-primary shrink-0 justify-center disabled:cursor-not-allowed disabled:opacity-60">
                          {reportState === 'busy' ? L.emailBusy : L.emailBtnFull}
                        </button>
                      </div>
                      <p className="mt-2 text-[11px] text-white/55">{L.emailReassure}</p>
                      {reportErr && <p className="mt-2 text-xs font-medium text-red-300">{reportErr}</p>}
                    </>
                  )}
                </div>
              </div>

              {/* ===== 2 — ÖNE ÇIKAN BULGULAR: her satır çözen pakete bağlanır (bulgu varsa) ===== */}
              {ok.shown.length > 0 && (
                <div className="mt-3 rounded-card border border-line bg-white p-4">
                  <div className="flex items-baseline justify-between gap-2">
                    <p className="text-[13px] font-bold text-ink">{L.topFindings}</p>
                    <p className="shrink-0 text-[11px] text-ink-muted">{L.fixIncluded}</p>
                  </div>
                  <ul className="mt-2 space-y-2">
                    {ok.shown.map((f, i) => (
                      <li key={f.title} className="animate-fade-up" style={{ animationDelay: `${i * 90}ms` }}>
                        <div className={`flex items-center gap-2.5 rounded-card border px-3 py-2.5 text-[12.5px] font-medium ${SEV_STYLE[f.severity].box}`}>
                          <span className={`inline-flex shrink-0 items-center rounded-pill px-2 py-0.5 text-[9px] font-bold uppercase leading-none ${SEV_STYLE[f.severity].chip}`}>{L.sev[f.severity]}</span>
                          <span className="min-w-0 flex-1 leading-snug">{f.title}</span>
                          <Link href={`${packagesHref}?focus=bundle_surface`} title={L.findingFix} className="ml-auto shrink-0 whitespace-nowrap rounded-pill bg-accent-soft px-2.5 py-1 text-[10.5px] font-bold text-accent-600 transition hover:bg-accent/25">{L.pkgSurfaceShort}</Link>
                        </div>
                      </li>
                    ))}
                  </ul>
                  {ok.total > ok.shown.length && (
                    <p className="mt-2 text-center text-xs text-ink-muted">{L.moreInReport(ok.total - ok.shown.length)}</p>
                  )}
                </div>
              )}

              {/* ===== 3 — BU TARAMANIN GÖREMEDİKLERİ: 2 paket (Dış Yüzey vurgulu / Aktif Doğrulama) ===== */}
              <div className="mt-3 rounded-card border border-line bg-white p-4">
                <div className="flex items-baseline justify-between gap-2">
                  <p className="text-[13px] font-bold text-ink">{L.cantSee}</p>
                  <p className="shrink-0 text-[11px] font-bold text-red-600">{L.biggerRisk}</p>
                </div>
                <p className="mt-1 text-xs leading-relaxed text-ink-soft">{L.cantSeeBody}</p>
                <div className="mt-3 grid gap-2 sm:grid-cols-2">
                  <Link href={`${packagesHref}?focus=bundle_surface`} className="flex flex-col gap-1.5 rounded-card border-[1.5px] border-accent bg-accent-soft/40 p-3 transition hover:brightness-[0.98]">
                    <span className="text-[10px] font-extrabold uppercase tracking-wide text-accent-600">{ok.clean ? L.recommended : L.coversGaps(ok.total)}</span>
                    <span className="text-[13px] font-bold text-ink">{L.nextSurface}</span>
                    <span className="flex-1 text-[11px] leading-snug text-ink-soft">{L.nextSurfaceHint}</span>
                    <span className="mt-1 inline-flex items-center justify-center rounded-lg bg-accent px-3 py-2 text-xs font-bold text-ink">{L.viewPackage}</span>
                  </Link>
                  <Link href={`${packagesHref}?focus=bundle_active_verify`} className="flex flex-col gap-1.5 rounded-card border border-line bg-white p-3 transition hover:border-ink-soft">
                    <span className="text-[10px] font-extrabold uppercase tracking-wide text-ink-muted">{L.beyondScan}</span>
                    <span className="text-[13px] font-bold text-ink">{L.nextActive}</span>
                    <span className="flex-1 text-[11px] leading-snug text-ink-soft">{L.nextActiveHint}</span>
                    <span className="mt-1 inline-flex items-center justify-center rounded-lg border border-line px-3 py-2 text-xs font-bold text-ink">{L.viewPackage}</span>
                  </Link>
                </div>
              </div>

              {/* ===== 4 — FOOTER ===== */}
              <div className="mt-3 flex items-center justify-between gap-3 text-xs">
                <button onClick={again} className="font-semibold text-ink-soft transition hover:text-brand">{L.scanAnother}</button>
                <Link href={packagesHref} className="font-semibold text-accent-600 hover:underline">{L.allPackages}</Link>
              </div>
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
