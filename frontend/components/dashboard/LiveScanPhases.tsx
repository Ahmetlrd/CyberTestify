'use client';

import { useEffect, useState } from 'react';

/**
 * (İŞ 1) GERÇEK tarama sırasında adım-adım, animasyonlu ilerleme — boş spinner yerine "momentum".
 *
 * YENİLEMEDE SIFIRLANMAZ: ilerleme, mount anındaki timer'a DEĞİL, taramanın GERÇEK başlangıç
 * zamanına (startedAt) göre hesaplanır (elapsed). Böylece sayfayı yenileyince aynı noktadan devam eder.
 *
 * PAKETE ÖZGÜ: her paket kendi kontrol adımlarını gösterir (jenerik değil). DÜRÜSTLÜK: etiketler o
 * pakette GERÇEKTEN yapılan fazlardır; UYDURMA SPESİFİK BULGU YOK. İlerleme çubuğu momentum
 * göstergesidir (kesin yüzde değil); backend gerçek redakte akış (feed) yayarsa altta gösterilir.
 */
const DEFAULT_PHASES = [
  'Hedef erişilebilirliği ve yüzey kontrolü',
  'HTTP güvenlik başlıkları inceleniyor',
  'TLS/SSL yapılandırması kontrol ediliyor',
  'Uygulama yüzeyi ve girdi noktaları taranıyor',
  'Bulgular değerlendiriliyor ve önceliklendiriliyor',
  'Rapor hazırlanıyor',
];

const PHASE_SETS: Record<string, string[]> = {
  // (S1 Otonom Red Team) MÜŞTERİ-YÜZÜ soyut fazlar — teknik altyapı (droplet/SSH/PentAGI/faz adları)
  // ASLA gösterilmez. Süre uzun sürebilir; son faz "onay" beklerken de aktif kalır (customerFacingStatus
  // awaiting_admin_review'i scan_running'e maskeler → burada "rapor hazırlanıyor" görünür).
  redteam_s1: [
    'İzole test ortamı hazırlanıyor',
    'Hedef inceleniyor ve saldırı yüzeyi keşfediliyor',
    'Otonom ajan güvenlik tekniklerini deniyor',
    'Bulgular ham kanıta bağlanıyor ve doğrulanıyor',
    'Rapor hazırlanıyor',
  ],
  basit_tarama: [
    'Hedef erişilebilirliği kontrol ediliyor',
    'HTTP güvenlik başlıkları taranıyor',
    'TLS/SSL yapılandırması inceleniyor',
    'Yaygın açık noktalar (OWASP ön-tarama) kontrol ediliyor',
    'Bulgular derleniyor',
    'Rapor hazırlanıyor',
  ],
  bundle_surface: [
    'Hedef erişilebilirliği kontrol ediliyor',
    'SSL/TLS yapılandırması inceleniyor',
    'HTTP güvenlik başlıkları taranıyor',
    'DNS & e-posta güvenliği (SPF/DKIM/DMARC)',
    'CORS & çerez güvenliği kontrol ediliyor',
    'İçerik Güvenlik Politikası (CSP) analiz ediliyor',
    'Rapor hazırlanıyor',
  ],
  bundle_recon: [
    'Hedef saldırı yüzeyi haritalanıyor',
    'Alt alan adı (subdomain) & DNS keşfi',
    'Subdomain-takeover riski kontrol ediliyor',
    'API & Swagger/OpenAPI keşfi',
    'CMS/framework parmak izi & bilinen CVE eşleştirme',
    'Bulgular önceliklendiriliyor',
    'Rapor hazırlanıyor',
  ],
  bundle_compliance: [
    'Dışarıdan gözlemlenebilir yüzey inceleniyor',
    'KVKK hazırlık kontrolleri',
    'PCI-DSS hazırlık kontrolleri',
    'ISO 27001 hazırlık kontrolleri',
    'Eksikler ilgili ilkelerle eşleştiriliyor',
    'Rapor hazırlanıyor',
  ],
  bundle_active_verify: [
    'Yüzey & girdi noktaları keşfediliyor',
    'Enjeksiyon (SQLi/XSS) doğrulanıyor',
    'IDOR / yetkisiz erişim doğrulanıyor',
    'SSRF & dosya yükleme kontrol ediliyor',
    'İş mantığı & race gözlemleniyor',
    'Bulgular doğrulanıyor',
    'Rapor hazırlanıyor',
  ],
  bundle_full_pentest: [
    'Test hesabıyla oturum açılıyor',
    'Çerez/oturum & yetki kontrolleri',
    'Kimlik-doğrulamalı enjeksiyon/IDOR kontrolleri',
    'Yetki yükseltme analizi (yapay zekâ destekli)',
    'Çok-adımlı iş mantığı analizi',
    'Bulgular derleniyor',
    'Rapor şifreleniyor',
  ],
};

// (Almanya /de) Almanca faz setleri — YALNIZ /de'de görünen paketler: default + basit + surface +
// recon + active_verify + full_pentest. bundle_compliance ve redteam_s1 /de'de GİZLİ → çevrilmez (TR).
// full_pentest index 0 = login fazı (AUTH_GATE_IDX ile aynı yapı korunur).
const DEFAULT_PHASES_DE = [
  'Erreichbarkeit des Ziels und Oberflächenprüfung',
  'HTTP-Sicherheitsheader werden geprüft',
  'TLS/SSL-Konfiguration wird geprüft',
  'Anwendungsoberfläche und Eingabepunkte werden gescannt',
  'Befunde werden ausgewertet und priorisiert',
  'Bericht wird erstellt',
];
const PHASE_SETS_DE: Record<string, string[]> = {
  basit_tarama: [
    'Erreichbarkeit des Ziels wird geprüft',
    'HTTP-Sicherheitsheader werden gescannt',
    'TLS/SSL-Konfiguration wird geprüft',
    'Häufige Schwachstellen (OWASP-Vorabprüfung) werden geprüft',
    'Befunde werden zusammengestellt',
    'Bericht wird erstellt',
  ],
  bundle_surface: [
    'Erreichbarkeit des Ziels wird geprüft',
    'SSL/TLS-Konfiguration wird geprüft',
    'HTTP-Sicherheitsheader werden gescannt',
    'DNS- & E-Mail-Sicherheit (SPF/DKIM/DMARC)',
    'CORS- & Cookie-Sicherheit werden geprüft',
    'Content-Security-Policy (CSP) wird analysiert',
    'Bericht wird erstellt',
  ],
  bundle_recon: [
    'Angriffsfläche des Ziels wird kartiert',
    'Subdomain- & DNS-Erkundung',
    'Subdomain-Takeover-Risiko wird geprüft',
    'API- & Swagger/OpenAPI-Erkennung',
    'CMS-/Framework-Fingerprinting & Abgleich bekannter CVEs',
    'Befunde werden priorisiert',
    'Bericht wird erstellt',
  ],
  bundle_active_verify: [
    'Oberfläche & Eingabepunkte werden erkundet',
    'Injection (SQLi/XSS) wird verifiziert',
    'IDOR / unbefugter Zugriff wird verifiziert',
    'SSRF & Datei-Upload werden geprüft',
    'Geschäftslogik & Race Conditions werden beobachtet',
    'Befunde werden verifiziert',
    'Bericht wird erstellt',
  ],
  bundle_full_pentest: [
    'Anmeldung mit Testkonto',
    'Cookie-/Session- & Berechtigungsprüfungen',
    'Authentifizierte Injection-/IDOR-Prüfungen',
    'Rechteausweitungs-Analyse (KI-gestützt)',
    'Mehrstufige Geschäftslogik-Analyse',
    'Befunde werden zusammengestellt',
    'Bericht wird verschlüsselt',
  ],
};

// (İngiltere /en) İngilizce faz setleri — YALNIZ /en'de görünen paketler (default + basit + surface +
// recon + active_verify + full_pentest). bundle_compliance ve redteam_s1 /en'de GİZLİ → çevrilmez.
const DEFAULT_PHASES_EN = [
  'Checking target reachability and surface',
  'Checking HTTP security headers',
  'Checking TLS/SSL configuration',
  'Scanning the application surface and input points',
  'Evaluating and prioritising findings',
  'Preparing the report',
];
const PHASE_SETS_EN: Record<string, string[]> = {
  basit_tarama: [
    'Checking target reachability',
    'Scanning HTTP security headers',
    'Checking TLS/SSL configuration',
    'Checking common vulnerabilities (OWASP pre-assessment)',
    'Compiling findings',
    'Preparing the report',
  ],
  bundle_surface: [
    'Checking target reachability',
    'Checking SSL/TLS configuration',
    'Scanning HTTP security headers',
    'DNS & email security (SPF/DKIM/DMARC)',
    'Checking CORS & cookie security',
    'Analysing Content-Security-Policy (CSP)',
    'Preparing the report',
  ],
  bundle_recon: [
    'Mapping the target attack surface',
    'Subdomain & DNS reconnaissance',
    'Checking subdomain-takeover risk',
    'API & Swagger/OpenAPI discovery',
    'CMS/framework fingerprinting & known-CVE matching',
    'Prioritising findings',
    'Preparing the report',
  ],
  bundle_active_verify: [
    'Discovering surface & input points',
    'Verifying injection (SQLi/XSS)',
    'Verifying IDOR / unauthorised access',
    'Checking SSRF & file upload',
    'Observing business logic & race conditions',
    'Verifying findings',
    'Preparing the report',
  ],
  bundle_full_pentest: [
    'Signing in with the test account',
    'Cookie/session & authorization checks',
    'Authenticated injection/IDOR checks',
    'Privilege-escalation analysis (AI-assisted)',
    'Multi-step business-logic analysis',
    'Compiling findings',
    'Encrypting the report',
  ],
};

export function phasesFor(key?: string | null, lang: 'tr' | 'de' | 'en' = 'tr'): string[] {
  if (lang === 'de') return (key && PHASE_SETS_DE[key]) || DEFAULT_PHASES_DE;
  if (lang === 'en') return (key && PHASE_SETS_EN[key]) || DEFAULT_PHASES_EN;
  return (key && PHASE_SETS[key]) || DEFAULT_PHASES;
}

// (SENKRON) Tek kaynak: hem terminal LOG satırı hem ilerleme çubuğu/halkası BURADAN beslenir → aynı
// faz index'i → aynı %. % FAZ-bazlıdır (zaman-sabitli DEĞİL): log ilerledikçe çubuk da ilerler, log bir
// fazda beklerken (ör. login gate) çubuk da bekler. Böylece "log duruyor ama çubuk artıyor" karışıklığı biter.
export function computeScanProgress(opts: { packageKey?: string | null; startedAt?: string | null; authConfirmedAt?: string | null; now: number; perPhase?: number; loginless?: boolean; lang?: 'tr' | 'de' | 'en' }): { phases: string[]; idx: number; pct: number; current: string } {
  let phases = phasesFor(opts.packageKey, opts.lang === 'de' ? 'de' : opts.lang === 'en' ? 'en' : 'tr');
  const per = opts.perPhase && opts.perPhase > 0 ? opts.perPhase : SECONDS_PER_PHASE;
  const startMs = opts.startedAt ? new Date(opts.startedAt).getTime() : opts.now;
  const elapsed = Math.max(0, (opts.now - startMs) / 1000);
  let gateIdx = opts.packageKey ? AUTH_GATE_IDX[opts.packageKey] : undefined;
  // (LOGINSİZ) "loginsiz devam et" seçilirse GERÇEK login YOK → login fazını tamamen ÇIKAR ve gate'i
  // KALDIR. Aksi halde "Test hesabıyla oturum açılıyor" fazı hiç gelmeyecek authConfirmedAt'i bekleyip
  // TAKILI kalırdı (kullanıcı şikayeti). Böylece adımlar normal ilerler.
  if (opts.loginless && gateIdx != null) { phases = phases.filter((_, i) => i !== gateIdx); gateIdx = undefined; }
  const rawIdx = Math.min(Math.floor(elapsed / per), phases.length - 1);
  let idx = rawIdx;
  if (gateIdx != null) {
    if (!opts.authConfirmedAt) idx = Math.min(rawIdx, gateIdx);
    else { const sinceConfirm = Math.max(0, (opts.now - new Date(opts.authConfirmedAt).getTime()) / 1000); idx = Math.min(gateIdx + 1 + Math.floor(sinceConfirm / per), phases.length - 1); }
  }
  const pct = Math.min(97, Math.max(5, Math.round(((idx + 0.5) / phases.length) * 100)));
  return { phases, idx, pct, current: phases[idx] };
}

// (MANTIK TUTARLILIĞI) Test hesabıyla giriş İÇEREN paketlerde, "oturum açılıyor" fazı SAHTE zamanlayıcıyla
// GEÇİLMEZ — yanlış kimlik bilgisiyle her şey ✓ görünüp sonra "giriş yapılamadı" demek müşteri için
// mantıksızdı (bkz support isyanı). Bu index'e ULAŞTIKTAN sonra backend'in GERÇEK authConfirmedAt
// damgası gelene kadar burada BEKLENİR (spinner, ✓ verilmez). Giriş başarısız olursa zaten order.status
// scan_failed'e döner ve bu bileşenin tamamı ekrandan kalkar (bkz dashboard/[orderId] sayfası).
const AUTH_GATE_IDX: Record<string, number> = { bundle_full_pentest: 0 };

const SECONDS_PER_PHASE = 9; // her faz ~9 sn; son "çalışan" fazda durur (bitiş gerçek durumdan gelir)

const LP = {
  tr: { verified: '✓ Alan adı sahipliği doğrulandı', starting: '→ Tarama başlatılıyor…', liveActivity: '— canlı aktivite —' },
  de: { verified: '✓ Domain-Inhaberschaft bestätigt', starting: '→ Scan wird gestartet…', liveActivity: '— Live-Aktivität —' },
  en: { verified: '✓ Domain ownership verified', starting: '→ Starting scan…', liveActivity: '— live activity —' },
} as const;

export function LiveScanPhases({
  hostname, feed, startedAt, packageKey, queued, authConfirmedAt, secondsPerPhase, verified, loginless, lang = 'tr',
}: {
  hostname: string;
  feed: Array<{ seq: number; text: string }>;
  startedAt?: string | null;
  packageKey?: string | null;
  queued?: boolean;
  authConfirmedAt?: string | null; // backend'den: login GERÇEKTEN ne zaman doğrulandı (bkz AUTH_GATE_IDX)
  secondsPerPhase?: number; // (S1) uzun-süren koşularda faz cadence'ını yavaşlat (varsayılan 9sn)
  verified?: boolean; // "✓ Alan adı sahipliği doğrulandı" YALNIZ DNS-doğrulaması olan paketlerde (5 & 6) gösterilir
  loginless?: boolean; // "loginsiz devam et" seçildi → login fazı çıkarılır, gate kaldırılır (bkz computeScanProgress)
  lang?: 'tr' | 'de' | 'en';
}) {
  const lp = LP[lang === 'de' ? 'de' : lang === 'en' ? 'en' : 'tr'];
  const perPhase = secondsPerPhase && secondsPerPhase > 0 ? secondsPerPhase : SECONDS_PER_PHASE;
  const [now, setNow] = useState<number>(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  // (Sırada/başlamamış) Tarama HENÜZ başlamadıysa fazlar İLERLEMEZ — yalnız "başlatılıyor" gösterilir.
  // startedAt yoksa flow başlamamıştır; queued bayrağı da açıkça sırada olduğunu belirtir.
  const notStarted = queued || !startedAt;
  if (notStarted) {
    return (
      <div className="min-h-[180px] p-5 font-mono text-[13px] leading-7">
        <div className="text-white/45" dir="ltr">$ cybertestify scan {hostname}</div>
        {verified && <div className="text-emerald-300" dir="ltr">{lp.verified}</div>}
        <div className="text-white/85" dir="ltr">{lp.starting}<span className="ml-1 inline-block h-4 w-2 translate-y-0.5 animate-pulse bg-accent/80" /></div>
        <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-white/10">
          <div className="h-full w-1/4 animate-pulse rounded-full bg-gradient-to-r from-accent/60 to-emerald-400/70" />
        </div>
      </div>
    );
  }

  // (SENKRON) idx + pct TEK kaynaktan (computeScanProgress) — ScanRunningView halkası da aynı fonksiyonu
  // kullanır → terminal log satırı, alt çubuk ve üst halka HEP birlikte ilerler.
  const { phases: PHASES, idx, pct } = computeScanProgress({ packageKey, startedAt, authConfirmedAt, now, perPhase, loginless, lang });

  return (
    <div className="min-h-[180px] p-5 font-mono text-[13px] leading-7">
      <div className="text-white/45" dir="ltr">$ cybertestify scan {hostname}</div>
      {verified && <div className="text-emerald-300" dir="ltr">{lp.verified}</div>}
      {PHASES.map((label, i) => {
        if (i > idx) return null;
        const current = i === idx;
        return (
          <div key={label} className={current ? 'text-white/85' : 'text-emerald-300/90'} dir="ltr">
            {current ? '→' : '✓'} {label}
            {current && <span className="ml-1 inline-block h-4 w-2 translate-y-0.5 animate-pulse bg-accent/80" />}
          </div>
        );
      })}

      <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-white/10">
        <div className="h-full rounded-full bg-gradient-to-r from-accent/70 to-emerald-400/80 transition-[width] duration-700 ease-out" style={{ width: `${pct}%` }} />
      </div>

      {feed.length > 0 && (
        <div className="mt-3 border-t border-white/10 pt-2">
          <div className="text-white/35" dir="ltr">{lp.liveActivity}</div>
          {feed.map((it) => (
            <div key={it.seq} className="text-white/70" dir="ltr">→ {it.text}</div>
          ))}
        </div>
      )}
    </div>
  );
}
