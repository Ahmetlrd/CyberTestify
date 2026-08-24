import { SCAN_PACKAGES } from './scanPackages.js';

/**
 * Cok-bolgeli fiyatlandirma verisi (config-driven — dagitik if(region) YOK).
 * TR fiyatlari authoritative (scanPackages.priceMinorUnit). US/AE su an TAHMINI
 * placeholder — gercek pazar kalibrasyonu Vedat tarafindan yapilacak (bkz HANDOFF).
 * Yeni bolge = REGION_CURRENCY + ESTIMATED'e satir eklemek yeterli.
 */
export const REGION_CURRENCY: Record<string, string> = { tr: 'TRY', us: 'USD', ae: 'AED', de: 'EUR', en: 'GBP' };

/**
 * GECICI TEST OVERRIDE — env TEST_PRICE_OVERRIDE_MINOR set ise TUM fiyatlar (tekil paket,
 * bundle, AI-eklenti) bu minor-unit degere sabitlenir ( or. "100" = 1 TL). Gercek kart ile
 * uctan uca odeme/iade testi icindir. Kalici fiyat sayilarina DOKUNMAZ — env kaldirilinca
 * eski fiyatlar aynen doner. Baseline: memory/price-list-baseline.md.
 */
export const PRICE_OVERRIDE_MINOR: number | null =
  process.env.TEST_PRICE_OVERRIDE_MINOR && Number.isFinite(Number(process.env.TEST_PRICE_OVERRIDE_MINOR))
    ? Math.max(0, Math.round(Number(process.env.TEST_PRICE_OVERRIDE_MINOR)))
    : null;

// USD fiyatlari (cent). Vedat'in onayladigi tabloya gore; kur ~47,5 TL/USD ile TL'yle
// tutarli. Listede OLMAYAN paketler icin TL'den turetilir (round(TL-kurus / 47.5) = USD-cent).
const USD_CENTS: Record<string, number> = {
  basit_tarama: 1100, // $11 (mevcut TL 499 — Vedat'in "~999" varsayimi yanlisti, TL degismedi)
  ssl_tls: 1700, // $17
  kvkk_hazirlik: 5200, // $52
  pci_hazirlik: 6300, // $63
  iso27001_hazirlik: 7400, // $74
  injection_verify: 8400, // $84
  idor_verify: 8400, // $84
  ssrf_verify: 9500, // $95
  file_upload_verify: 9500, // $95
  business_logic_verify: 12600, // $126
  race_massassign_verify: 12600, // $126
  rce_verify: 14700, // $147
  // (Fiyat karari — bkz scanPackages) bundle_full_pentest'in degeri kimlik-dogrulamali bilesende;
  // AI/otonom bilesen hafif advisory oldugu icin ucuz. TR ile AYNI yon (authenticated pahali, autonomous
  // ucuz) korunur ki hicbir bolgede AI bileseni pahali gorunmesin. Uyeler bundle-only (standalone satilmaz).
  authenticated_scan: 39900, // $399 (bundle degerinin tasiyicisi)
  autonomous_pentest: 10900, // $109 (hafif advisory — dusuk etiket)
};

// (Almanya lansmanı — FAZ 1) EUR fiyatları KUR ÇEVRİMİYLE OTOMATİK HESAPLANMAZ — Vedat'ın gireceği
// BAĞIMSIZ € tutarlarıdır (kurus/cent = €1 -> 100). Bu tablo ŞİMDİLİK BOŞ; /de görünür olmadan
// (VISIBLE_REGION_CODES) önce buraya paket-başı gerçek EUR-cent değerleri girilecek. Boşken 'de'
// REGIONAL_PRICING'de undefined kalır ve getPricing güvenli şekilde TR tutarına düşer (currency EUR) —
// bu YALNIZ /de gizliyken geçerli bir placeholder'dır; canlıya çıkmadan doldurulmalıdır.
// YAKLAŞIK değerler (Alman/AB pazarı için temiz euro fiyat noktaları; kur türevi DEĞİL, bağımsız
// tutarlar). Vedat kesinleştirecek. Bundle fiyatı = üye tekil EUR toplamı × (1 - indirim) (bkz
// bundlePrice). /de'de gizli paketler (Uyum: kvkk/pci/iso) ve S1 dahil edilmedi (görünmüyorlar).
const EUR_CENTS: Record<string, number> = {
  // Tekil / Basit
  basit_tarama: 1900, // €19
  // Dış Yüzey & Yapılandırma üyeleri
  ssl_tls: 2500, // €25
  header_leak: 2500, // €25
  dns_email: 2900, // €29
  cors_cookie: 2500, // €25
  csp_analiz: 2500, // €25
  // Keşif üyeleri
  subdomain_takeover: 4500, // €45
  api_discovery: 3900, // €39
  cms_cve: 4500, // €45
  // Aktif Doğrulama üyeleri
  injection_verify: 9900, // €99
  idor_verify: 9900, // €99
  ssrf_verify: 11500, // €115
  file_upload_verify: 11500, // €115
  business_logic_verify: 14900, // €149
  race_massassign_verify: 14900, // €149
  rce_verify: 17900, // €179
  // Tam Kapsamlı Pentest üyeleri
  authenticated_scan: 49900, // €499 (bundle değerinin taşıyıcısı)
  autonomous_pentest: 12900, // €129 (hafif advisory — düşük etiket)
};

// ============================================================================
// !!! PLACEHOLDER_KULLANICI_ONAYI_GEREKLI — GBP fiyatları (İngiltere/UK lansmanı) !!!
// ----------------------------------------------------------------------------
// Bu £ tutarları GERÇEK/NİHAİ DEĞİLDİR. EUR_CENTS'ten YAKLAŞIK ~0.86 GBP/EUR oranıyla
// türetilip tam-pound'a yuvarlanmış TAHMİNİ değerlerdir (kur türevi bir mekanizma DEĞİL,
// yalnız otonom-ilerleme için makul başlangıç). Vedat nihai £ rakamlarını girip
// `npm run seed` çalıştırana kadar bunlar PLACEHOLDER'dır. /en gizli olduğu sürece
// (VISIBLE_REGION_CODES'ta 'en' YOK) canlı müşteriye ulaşmaz. Nihai fiyatları buraya
// açıkça girin (kur çevrimiyle DEĞİL). Uyum paketi üyeleri (kvkk/pci/iso) ve S1 /en'de
// gizli olduğundan dahil edilmedi.
const GBP_PER_EUR_PLACEHOLDER = 0.86; // PLACEHOLDER kur — yalnız tahmini türetme için
const GBP_CENTS: Record<string, number> = Object.fromEntries(
  Object.entries(EUR_CENTS).map(([key, eur]) => [key, Math.round((eur * GBP_PER_EUR_PLACEHOLDER) / 100) * 100]),
);

const TRY_PER_USD = 47.5; // yaklasik kur — USD turetimi icin
const AED_PER_USD = 3.67; // sabit (BAE dirhemi USD'ye peg)

function usdCentsFor(key: string, tryMinor: number): number {
  return USD_CENTS[key] ?? Math.round(tryMinor / TRY_PER_USD);
}

// [packageKey][region] -> amountMinorUnit. Seed bu haritadan PackagePricing yazar.
// TR authoritative (scanPackages.priceMinorUnit); US tablodan/turetilir; AE = USD * 3.67.
export const REGIONAL_PRICING: Record<string, Record<string, number>> = Object.fromEntries(
  SCAN_PACKAGES.map((p) => {
    const us = usdCentsFor(p.key, p.priceMinorUnit);
    // de: yalnız EUR_CENTS'te AÇIKÇA girilmişse konur (kur türevi YOK); girilmemişse undefined →
    // getPricing TR tutarına düşer (yalnız /de gizliyken geçerli placeholder).
    const de = EUR_CENTS[p.key];
    // en (UK/GBP): PLACEHOLDER — yalnız EUR_CENTS'te açıkça girilmiş paketler için türetilir;
    // girilmemişse undefined → getPricing TR tutarına düşer (yalnız /en gizliyken geçerli placeholder).
    const en = GBP_CENTS[p.key];
    return [p.key, { tr: p.priceMinorUnit, us, ae: Math.round(us * AED_PER_USD), ...(de != null ? { de } : {}), ...(en != null ? { en } : {}) }];
  }),
);

export function currencyFor(region: string): string {
  return REGION_CURRENCY[region] ?? 'TRY';
}

export function getPricing(packageKey: string, region: string): { amountMinorUnit: number; currency: string } {
  const byRegion = REGIONAL_PRICING[packageKey] ?? {};
  const amountMinorUnit = byRegion[region] ?? byRegion.tr ?? 0;
  // Bilinmeyen bolge -> TR/TRY'ye guvenli dusus.
  const currency = REGION_CURRENCY[region] ? currencyFor(region) : 'TRY';
  if (PRICE_OVERRIDE_MINOR != null) return { amountMinorUnit: PRICE_OVERRIDE_MINOR, currency };
  return { amountMinorUnit, currency };
}
