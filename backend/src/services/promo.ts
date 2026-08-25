import { prisma } from '../db.js';
import type { Prisma, PrismaClient } from '@prisma/client';

export interface PromoResult {
  valid: boolean;
  error?: string;
  code?: string;
  discountType?: 'percentage' | 'fixed';
  discountValue?: number;
  originalAmountMinorUnit?: number;
  discountMinorUnit?: number;
  finalAmountMinorUnit?: number;
}

/**
 * Bir promo kodunu bir tutara karsi degerlendir (SATIN ALMADAN — checkout onizleme +
 * siparis aninda ayni mantik). Kod bulunamaz/pasif/suresi dolmus/limit dolmussa gecersiz.
 * Indirim tutari [0, amount] araligina kelepcelenir (negatif/asiri koruma).
 */
export async function evaluatePromo(codeRaw: string, amountMinorUnit: number, locale: string = 'tr'): Promise<PromoResult> {
  const de = locale === 'de', en = locale === 'en';
  const t = (tr: string, deS: string, enS: string) => (de ? deS : en ? enS : tr);
  const code = (codeRaw ?? '').trim().toUpperCase();
  if (!code) return { valid: false, error: t('Promosyon kodu boş.', 'Aktionscode ist leer.', 'Promo code is empty.') };
  const promo = await prisma.promoCode.findUnique({ where: { code } });
  if (!promo || !promo.active) return { valid: false, error: t('Kod geçersiz veya pasif.', 'Code ungültig oder inaktiv.', 'Code is invalid or inactive.') };
  if (promo.expiresAt && promo.expiresAt.getTime() < Date.now()) return { valid: false, error: t('Kodun süresi dolmuş.', 'Der Code ist abgelaufen.', 'The code has expired.') };
  if (promo.maxUses != null && promo.usedCount >= promo.maxUses) return { valid: false, error: t('Kod kullanım limiti dolmuş.', 'Nutzungslimit des Codes erreicht.', 'The code has reached its usage limit.') };

  const raw =
    promo.discountType === 'percentage'
      ? Math.round((amountMinorUnit * promo.discountValue) / 100)
      : promo.discountValue;
  const discount = Math.max(0, Math.min(raw, amountMinorUnit));
  return {
    valid: true,
    code,
    discountType: promo.discountType as 'percentage' | 'fixed',
    discountValue: promo.discountValue,
    originalAmountMinorUnit: amountMinorUnit,
    discountMinorUnit: discount,
    finalAmountMinorUnit: amountMinorUnit - discount,
  };
}

type Db = PrismaClient | Prisma.TransactionClient;

/** Kullanim kaydi + sayac artir. Siparis olusumuyla ayni transaction'da cagrilmali. */
export async function recordPromoUsage(
  db: Db,
  args: { code: string; orderId: string; customerId: string; original: number; discount: number; final: number },
): Promise<void> {
  const code = args.code.trim().toUpperCase();
  const promo = await db.promoCode.findUnique({ where: { code } });
  if (!promo) return;
  await db.promoCode.update({ where: { id: promo.id }, data: { usedCount: { increment: 1 } } });
  await db.promoCodeUsage.create({
    data: {
      promoCodeId: promo.id,
      orderId: args.orderId,
      customerId: args.customerId,
      code,
      originalAmountMinorUnit: args.original,
      discountMinorUnit: args.discount,
      finalAmountMinorUnit: args.final,
    },
  });
}
