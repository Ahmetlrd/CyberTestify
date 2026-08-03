import { prisma } from '../db.js';
import type { Prisma, PrismaClient } from '@prisma/client';

/**
 * (Is 2) Kredi / Bundle sistemi.
 *
 * Model: bir KREDI, degeri CREDIT_UNIT_VALUE_MINOR olan bir "tarama fisi"dir. Pahali
 * paketler birden fazla kredi harcar: creditsForPackagePrice = ceil(fiyat / birim).
 * Bu, arbitraji onler (ucuz kredi alip pahali paketi bedavaya getirme) ve cogu paket
 * (<= birim) icin "1 kredi" beklentisini korur. Bundle = N kredi, indirimli tek odeme.
 *
 * FIYAT/INDIRIM PLACEHOLDER — Vedat onaylayacak; bundle'lar available:false baslar.
 * Gercek bundle odeme akisi (PaymentProvider) SONRAKI adim; su an buyBundle MOCK
 * (krediyi dogrudan ekler + ledger'a yazar), gercek tahsilat tetiklenmez.
 */

// Bir kredinin kapsadigi azami tarama degeri (kurus). 999,00 TRY — populer/orta tier.
export const CREDIT_UNIT_VALUE_MINOR = 99900;

export interface BundleDef {
  key: string;
  displayName: string;
  credits: number;
  priceMinorUnit: number; // TRY kurus — PLACEHOLDER
  discountPct: number; // gosterim icin (liste fiyatina gore)
  available: boolean;
}

// Liste fiyati = credits * CREDIT_UNIT_VALUE_MINOR. priceMinorUnit indirimli tutardir.
export const BUNDLES: BundleDef[] = [
  { key: 'bundle_5', displayName: '5’li Tarama Paketi', credits: 5, priceMinorUnit: 439900, discountPct: 12, available: false },
  { key: 'bundle_10', displayName: '10’lu Tarama Paketi', credits: 10, priceMinorUnit: 819900, discountPct: 18, available: false },
];

export function getBundle(key: string): BundleDef | undefined {
  return BUNDLES.find((b) => b.key === key);
}

// Bir paketin (bolgesel) fiyatinin kac krediye denk geldigi — en az 1.
// Math.round (ceil DEGIL): ceil, fiyati bir katın hemen ustundeki paketleri FAZLA
// ucretlendiriyordu (1999 TL -> 3 kredi). round ile adil, temiz kademe:
//   1 kredi: <=1299 TL (basit/ssl/header/dns/cors/csp/api)
//   2 kredi: 1499-1999 TL (cms/subdomain/kvkk)
//   3 kredi: 2499-2999 TL (pci/iso)
export function creditsForPackagePrice(priceMinorUnit: number): number {
  return Math.max(1, Math.round(priceMinorUnit / CREDIT_UNIT_VALUE_MINOR));
}

type Tx = Omit<PrismaClient, '$connect' | '$disconnect' | '$on' | '$transaction' | '$use' | '$extends'>;

// Bakiye + ledger'i AYNI transaction'da gunceller (tutarlilik).
async function applyDelta(
  tx: Tx,
  customerId: string,
  delta: number,
  reason: string,
  meta: { bundleKey?: string; orderId?: string } = {},
): Promise<number> {
  const c = await tx.customer.update({
    where: { id: customerId },
    data: { creditBalance: { increment: delta } },
    select: { creditBalance: true },
  });
  await tx.creditTransaction.create({
    data: { customerId, delta, reason, bundleKey: meta.bundleKey ?? null, orderId: meta.orderId ?? null, balanceAfter: c.creditBalance },
  });
  return c.creditBalance;
}

// Bundle satin alma (su an MOCK — krediyi ekler). Gercek odeme entegrasyonu SONRAKI adim.
export async function purchaseBundleMock(customerId: string, bundleKey: string): Promise<{ balance: number; credits: number }> {
  const bundle = getBundle(bundleKey);
  if (!bundle) throw new Error('bundle_not_found');
  if (!bundle.available) throw new Error('bundle_unavailable');
  const balance = await prisma.$transaction((tx) =>
    applyDelta(tx as unknown as Tx, customerId, bundle.credits, 'bundle_purchase', { bundleKey }),
  );
  return { balance, credits: bundle.credits };
}

// Tarama icin kredi harca. Yeterli degilse throw. AYNI transaction icinde cagrilabilir.
export async function spendCredits(tx: Tx, customerId: string, credits: number, orderId: string): Promise<number> {
  const c = await tx.customer.findUniqueOrThrow({ where: { id: customerId }, select: { creditBalance: true } });
  if (c.creditBalance < credits) throw new Error('insufficient_credits');
  return applyDelta(tx, customerId, -credits, 'scan_use', { orderId });
}

export type { Tx as CreditTx };
