import 'dotenv/config';

function required(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Eksik ortam degiskeni: ${name}`);
  return v;
}

export const config = {
  port: Number(process.env.PORT ?? 4000),
  databaseUrl: required('DATABASE_URL'),
  // Frontend'in origin'i — CORS ve mock odeme sonrasi yonlendirme icin.
  frontendUrl: process.env.FRONTEND_URL ?? 'http://localhost:3000',
  // Admin paneli AYRI subdomain'den (admin.cybertestify.com) servis edilir; CORS'a
  // eklenmezse admin.* origin'inden yapilan istekler bloklanir. Dev'de bos (admin
  // ayni origin'de calisir). Birden fazla ise virgulle.
  adminUrl: process.env.ADMIN_URL ?? '',
  // Gercek iyzico kimlik bilgisi girilene kadar odeme "mock" modda calisir:
  // siparis olusturulunca otomatik odendi sayilip tarama baslar. IYZICO_API_KEY
  // tanimlaninca otomatik olarak gercek odeme akisina gecilir.
  mockPayment: (process.env.MOCK_PAYMENT ?? 'true') === 'true' && !process.env.IYZICO_API_KEY,
  // (Is 3) Uluslararasi (TR disi) odeme saglayici secimi: 'paddle' (onerilen, MoR) |
  // 'stripe' | 'sandbox'. Gercek anahtar gelene kadar 'sandbox' (mockInitiate) kalir.
  intlPaymentProvider: (process.env.INTL_PAYMENT_PROVIDER ?? 'sandbox') as 'paddle' | 'stripe' | 'sandbox',
  pentagi: {
    graphqlUrl: required('PENTAGI_GRAPHQL_URL'),
    serviceToken: required('PENTAGI_SERVICE_TOKEN'),
  },
  jwtSecret: required('JWT_SECRET'),
  // Ic yonetim paneli (admin) — MUSTERI JWT'sinden TAMAMEN AYRI secret. Musteri
  // token'i (jwtSecret ile imzali) admin endpoint'lerinde ASLA gecerli olmasin.
  adminJwtSecret: required('ADMIN_JWT_SECRET'),
  // Admin paneli IP kisitlamasi (opsiyonel). Bos ise kisitlama YOK. Virgulle IP.
  adminIpAllowlist: (process.env.ADMIN_IP_ALLOWLIST ?? '')
    .split(',').map((s) => s.trim()).filter(Boolean),
  reportEncryptionPepper: required('REPORT_ENCRYPTION_PEPPER'),
  // Veri minimizasyonu: rapor icerigi bu sure sonunda silinir (siparis/odeme
  // kaydi KORUNUR — muhasebe/fatura mevzuati). Ham PentAGI verisi zaten rapor
  // uretilir uretilmez siliniyor.
  reportRetentionDays: Number(process.env.REPORT_RETENTION_DAYS ?? 30),
  dnsVerificationPrefix: process.env.DNS_VERIFICATION_PREFIX ?? 'pentest-verify',
  // Yururlukteki hukuki metinlerin (ToS/KVKK/MSS/OBF) surumu. Metinler
  // guncellenince artirilir; rizalar bu surumle damgalanir (ispat icin).
  legalVersion: process.env.LEGAL_VERSION ?? '2026-07-26',
  // Kapsam (scope) izleme modu: 'enforce' = izin disi hedefte flow'u durdur;
  // 'monitor' = sadece logla/audit birak (yanlis pozitif riskini test ederken).
  scopeEnforcement: (process.env.SCOPE_ENFORCEMENT ?? 'enforce') as 'enforce' | 'monitor',
  // PentAGI ajaninin mesru sekilde eristigi referans/altyapi alanlari — kapsam
  // ihlali sayilmaz (CVE/zafiyet DB'leri, paket aynalari, arac depolari).
  // Egress proxy <-> backend arasi internal API sirri (yalnizca ic ag). Proxy,
  // aktif flow kapsamini bu endpoint'ten ceker; header ile dogrulanir.
  internalApiSecret: process.env.INTERNAL_API_SECRET ?? 'dev-internal-secret-change-me',
  // Egress proxy'nin dinledigi port (PentAGI terminal container'lari buraya
  // PROXY_URL uzerinden baglanir).
  egressProxyPort: Number(process.env.EGRESS_PROXY_PORT ?? 8899),
  // Backend/worker'in egress proxy'ye saglik kontrolu icin ulasacagi URL.
  egressProxyUrl: process.env.EGRESS_PROXY_URL ?? `http://localhost:${Number(process.env.EGRESS_PROXY_PORT ?? 8899)}`,
  // Egress proxy'nin backend'e (internal endpoint) ulasacagi URL. Docker'da
  // proxy container'i host'taki backend'e host.docker.internal ile ulasir.
  backendInternalUrl: process.env.BACKEND_INTERNAL_URL ?? 'http://localhost:4000',
  // Ham ag/port (networkLayer) paketleri ANCAK bypass-proof izolasyon
  // (internal:true network + dual-homed proxy container — bkz HANDOFF.md)
  // tamamlandiginda ve bu bayrak true iken aktif olabilir. Aksi halde runtime
  // olarak pasiflestirilir/reddedilir (insan hafizasina guvenmeyiz).
  hardenedNetworkIsolation: (process.env.HARDENED_NETWORK_ISOLATION ?? 'false') === 'true',
  // Periyodik tarama guvenceleri (sistemi zorlamamak icin).
  maxActiveScheduledScans: Number(process.env.MAX_ACTIVE_SCHEDULED_SCANS ?? 100),
  minScheduleIntervalDays: Number(process.env.MIN_SCHEDULE_INTERVAL_DAYS ?? 7),
  scheduledQueueWarnThreshold: Number(process.env.SCHEDULED_QUEUE_WARN_THRESHOLD ?? 20),
  // WATCHDOG (dayaniklilik): bir tarama bu sureden uzun 'running' kalirsa takilmis
  // sayilir (sunucu/PentAGI cokmesi, kredi/token bitmesi, ag kesintisi vs) → basa
  // alinir, siparis scan_failed olur, concurrency=1 slotu SERBEST kalir (kuyruk
  // sonsuza kadar kilitlenmez). Orphan rezervasyon (createFlow tamamlanmadan process
  // olduyse pentagiFlowId 'reserving-...' kalir) daha kisa esikte temizlenir.
  scanTimeoutMinutes: Number(process.env.SCAN_TIMEOUT_MINUTES ?? 120),
  reservationTimeoutMinutes: Number(process.env.RESERVATION_TIMEOUT_MINUTES ?? 3),
  // Tarama basladiktan sonra ajan hic arac cagrisi yapmadan 'waiting'e duserse (erken
  // durdurma/cokme), bu tolerans suresi gecince RAPOR URETMEDEN scan_failed yapilir.
  emptyScanGraceSeconds: Number(process.env.EMPTY_SCAN_GRACE_SECONDS ?? 60),
  // SCRIPT DEBUG-LOOP KESME: ajan ayni Python/Bash script'ini tekrar tekrar yazip
  // calistirip "duzeltme" dongusune girer (bkz nomorelink vakasi) → butce bosa yanar.
  // Ayni (normalize) script adi bu kadar terminal cagrisinda gecerse dongu sayilir;
  // overCap gibi ERKEN DUR + elde edilen ham veriyle rapor uret. 0 = kapali.
  scriptDebugLoopThreshold: Number(process.env.SCRIPT_DEBUG_LOOP_THRESHOLD ?? 6),
  scopeAllowlist: (process.env.SCOPE_ALLOWLIST ??
    [
      'cve.mitre.org', 'cve.org', 'nvd.nist.gov', 'exploit-db.com', 'cvedetails.com',
      'github.com', 'raw.githubusercontent.com', 'pypi.org', 'files.pythonhosted.org',
      'registry.npmjs.org', 'deb.debian.org', 'archive.ubuntu.com', 'security.ubuntu.com',
      'alpinelinux.org', 'dl-cdn.alpinelinux.org', 'crt.sh', 'api.anthropic.com',
      // Genel DNS cozumleyicileri: dns_email/dig recon'da hedefi cozmek icin mesru
      // altyapi (hedef DEGIL). Aksi halde 'dig @8.8.8.8 hedef' kapsam-disi sayiliyordu.
      '8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9',
    ].join(',')
  ).split(',').map((s) => s.trim().toLowerCase()).filter(Boolean),
  iyzico: {
    apiKey: process.env.IYZICO_API_KEY ?? '',
    secretKey: process.env.IYZICO_SECRET_KEY ?? '',
    baseUrl: process.env.IYZICO_BASE_URL ?? 'https://sandbox-api.iyzipay.com',
  },
};

/**
 * Kapsam kilidiyle (scope lock) ilgili KRITIK konfigurasyonu acilistata dogrula.
 * Eksik/gecersizse process sessizce yanlis konfigurasyonla ayaga KALKMAMALI —
 * hemen anlamli bir hatayla dursun (fail-fast). server/worker/egress-proxy
 * acilisinda cagrilir.
 */
export function validateScopeLockConfig(): void {
  const errors: string[] = [];
  if (!config.internalApiSecret || config.internalApiSecret.trim() === '') {
    errors.push('INTERNAL_API_SECRET bos olamaz (egress proxy <-> backend kimlik dogrulamasi).');
  }
  if (!Number.isFinite(config.egressProxyPort) || config.egressProxyPort <= 0) {
    errors.push(`EGRESS_PROXY_PORT gecersiz: ${process.env.EGRESS_PROXY_PORT}`);
  }
  for (const [name, val] of [
    ['BACKEND_INTERNAL_URL', config.backendInternalUrl],
    ['EGRESS_PROXY_URL', config.egressProxyUrl],
  ] as const) {
    try {
      new URL(val);
    } catch {
      errors.push(`${name} gecerli bir URL degil: ${val}`);
    }
  }
  // Prod'da varsayilan sir birakilmamali.
  if (process.env.NODE_ENV === 'production' && config.internalApiSecret === 'dev-internal-secret-change-me') {
    errors.push('Production ortaminda varsayilan INTERNAL_API_SECRET kullanilamaz.');
  }
  if (errors.length) {
    throw new Error(
      '[config] Kapsam kilidi konfigurasyon dogrulamasi BASARISIZ:\n  - ' + errors.join('\n  - '),
    );
  }
}
