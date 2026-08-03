import { SCAN_PACKAGES } from './scanPackages.js';

/**
 * Cok-bolgeli fiyatlandirma verisi (config-driven — dagitik if(region) YOK).
 * TR fiyatlari authoritative (scanPackages.priceMinorUnit). US/AE su an TAHMINI
 * placeholder — gercek pazar kalibrasyonu Vedat tarafindan yapilacak (bkz HANDOFF).
 * Yeni bolge = REGION_CURRENCY + ESTIMATED'e satir eklemek yeterli.
 */
export const REGION_CURRENCY: Record<string, string> = { tr: 'TRY', us: 'USD', ae: 'AED' };

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
  authenticated_scan: 17800, // $178
  autonomous_pentest: 33600, // $336
};

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
    return [p.key, { tr: p.priceMinorUnit, us, ae: Math.round(us * AED_PER_USD) }];
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
  return { amountMinorUnit, currency };
}
