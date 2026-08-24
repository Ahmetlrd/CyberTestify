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
    'Rapor hazırlanıyor ve gözden geçiriliyor',
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

function phasesFor(key?: string | null): string[] {
  return (key && PHASE_SETS[key]) || DEFAULT_PHASES;
}

// (MANTIK TUTARLILIĞI) Test hesabıyla giriş İÇEREN paketlerde, "oturum açılıyor" fazı SAHTE zamanlayıcıyla
// GEÇİLMEZ — yanlış kimlik bilgisiyle her şey ✓ görünüp sonra "giriş yapılamadı" demek müşteri için
// mantıksızdı (bkz support isyanı). Bu index'e ULAŞTIKTAN sonra backend'in GERÇEK authConfirmedAt
// damgası gelene kadar burada BEKLENİR (spinner, ✓ verilmez). Giriş başarısız olursa zaten order.status
// scan_failed'e döner ve bu bileşenin tamamı ekrandan kalkar (bkz dashboard/[orderId] sayfası).
const AUTH_GATE_IDX: Record<string, number> = { bundle_full_pentest: 0 };

const SECONDS_PER_PHASE = 9; // her faz ~9 sn; son "çalışan" fazda durur (bitiş gerçek durumdan gelir)

export function LiveScanPhases({
  hostname, feed, startedAt, packageKey, queued, authConfirmedAt, secondsPerPhase,
}: {
  hostname: string;
  feed: Array<{ seq: number; text: string }>;
  startedAt?: string | null;
  packageKey?: string | null;
  queued?: boolean;
  authConfirmedAt?: string | null; // backend'den: login GERÇEKTEN ne zaman doğrulandı (bkz AUTH_GATE_IDX)
  secondsPerPhase?: number; // (S1) uzun-süren koşularda faz cadence'ını yavaşlat (varsayılan 9sn)
}) {
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
        <div className="text-emerald-300" dir="ltr">✓ Alan adı sahipliği doğrulandı</div>
        <div className="text-white/85" dir="ltr">→ Tarama başlatılıyor…<span className="ml-1 inline-block h-4 w-2 translate-y-0.5 animate-pulse bg-accent/80" /></div>
        <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-white/10">
          <div className="h-full w-1/4 animate-pulse rounded-full bg-gradient-to-r from-accent/60 to-emerald-400/70" />
        </div>
      </div>
    );
  }

  const PHASES = phasesFor(packageKey);
  const startMs = startedAt ? new Date(startedAt).getTime() : now;
  const elapsed = Math.max(0, (now - startMs) / 1000); // sn — YENİLEMEDEN bağımsız (gerçek başlangıçtan)
  const rawIdx = Math.min(Math.floor(elapsed / perPhase), PHASES.length - 1);
  // (MANTIK TUTARLILIĞI) Login-fazlı paket: gate index'ine ULAŞINCA, backend'in GERÇEK authConfirmedAt
  // damgası gelmeden ÖTESİNE SAHTE zamanlayıcıyla GEÇİLMEZ — orada bekler (spinner). Damga gelince
  // KALAN fazlar o GERÇEK andan itibaren ilerler (hâlâ tahmini süre ama artık gerçek bir olaya bağlı).
  const gateIdx = packageKey ? AUTH_GATE_IDX[packageKey] : undefined;
  let idx = rawIdx;
  if (gateIdx != null) {
    if (!authConfirmedAt) {
      idx = Math.min(rawIdx, gateIdx);
    } else {
      const sinceConfirm = Math.max(0, (now - new Date(authConfirmedAt).getTime()) / 1000);
      idx = Math.min(gateIdx + 1 + Math.floor(sinceConfirm / SECONDS_PER_PHASE), PHASES.length - 1);
    }
  }
  const pct = Math.min(92, Math.max(6, Math.round(100 * (1 - Math.exp(-elapsed / 55))))); // ~%92'ye yumuşak yaklaşır

  return (
    <div className="min-h-[180px] p-5 font-mono text-[13px] leading-7">
      <div className="text-white/45" dir="ltr">$ cybertestify scan {hostname}</div>
      <div className="text-emerald-300" dir="ltr">✓ Alan adı sahipliği doğrulandı</div>
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
          <div className="text-white/35" dir="ltr">— canlı aktivite —</div>
          {feed.map((it) => (
            <div key={it.seq} className="text-white/70" dir="ltr">→ {it.text}</div>
          ))}
        </div>
      )}
    </div>
  );
}
