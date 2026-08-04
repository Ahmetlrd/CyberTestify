/**
 * Promosyon kodu olusturur/gunceller (idempotent). Varsayilan: Vedat'in %100,
 * sinirsiz, suresiz test kodu. Genel amacli — pazarlama indirimleri icin de kullanilir.
 *
 * Kullanim:
 *   docker exec cybertestify-api npx tsx prisma/seedPromo.ts
 *   docker exec -e PROMO_CODE=YAZBAHAR -e PROMO_TYPE=percentage -e PROMO_VALUE=25 \
 *     -e PROMO_MAX_USES=100 -e PROMO_EXPIRES=2026-12-31 cybertestify-api npx tsx prisma/seedPromo.ts
 */
import { prisma } from '../src/db.js';

async function main() {
  const code = (process.env.PROMO_CODE ?? 'VEDAT-TEST-2026').trim().toUpperCase();
  const discountType = (process.env.PROMO_TYPE ?? 'percentage') as 'percentage' | 'fixed';
  const discountValue = Number(process.env.PROMO_VALUE ?? 100);
  const maxUses = process.env.PROMO_MAX_USES ? Number(process.env.PROMO_MAX_USES) : null;
  const expiresAt = process.env.PROMO_EXPIRES ? new Date(process.env.PROMO_EXPIRES) : null;

  const promo = await prisma.promoCode.upsert({
    where: { code },
    update: { discountType, discountValue, active: true, maxUses, expiresAt },
    create: { code, discountType, discountValue, active: true, maxUses, expiresAt },
  });

  console.log('=== PROMO KODU HAZIR ===');
  console.log('Kod       :', promo.code);
  console.log('Indirim   :', discountType === 'percentage' ? `%${discountValue}` : `${discountValue / 100} TL sabit`);
  console.log('Limit     :', maxUses ?? 'sinirsiz');
  console.log('Bitis     :', expiresAt ? expiresAt.toISOString() : 'suresiz');
  console.log('Kullanildi:', promo.usedCount);
}

main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
