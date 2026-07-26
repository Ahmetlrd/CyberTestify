import { SCAN_PACKAGES } from './scanPackages.js';

/**
 * Cok-bolgeli fiyatlandirma verisi (config-driven — dagitik if(region) YOK).
 * TR fiyatlari authoritative (scanPackages.priceMinorUnit). US/AE su an TAHMINI
 * placeholder — gercek pazar kalibrasyonu Vedat tarafindan yapilacak (bkz HANDOFF).
 * Yeni bolge = REGION_CURRENCY + ESTIMATED'e satir eklemek yeterli.
 */
export const REGION_CURRENCY: Record<string, string> = { tr: 'TRY', us: 'USD', ae: 'AED' };

// TR disi bolgeler icin tahmini tutarlar (ilgili para biriminin minor unit'i).
const ESTIMATED: Record<string, { us: number; ae: number }> = {
  basit_tarama: { us: 1900, ae: 6900 },
  ssl_tls: { us: 2900, ae: 10900 },
  header_leak: { us: 2900, ae: 10900 },
  dns_email: { us: 3900, ae: 14900 },
  cms_cve: { us: 5900, ae: 21900 },
  pci_hazirlik: { us: 9900, ae: 36900 },
  kvkk_hazirlik: { us: 7900, ae: 29900 },
  iso27001_hazirlik: { us: 11900, ae: 43900 },
};

// [packageKey][region] -> amountMinorUnit. Seed bu haritadan PackagePricing yazar.
export const REGIONAL_PRICING: Record<string, Record<string, number>> = Object.fromEntries(
  SCAN_PACKAGES.map((p) => [
    p.key,
    { tr: p.priceMinorUnit, us: ESTIMATED[p.key]?.us ?? p.priceMinorUnit, ae: ESTIMATED[p.key]?.ae ?? p.priceMinorUnit },
  ]),
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
