import { PrismaClient } from '@prisma/client';
import { SCAN_PACKAGES } from '../src/services/scanPackages.js';
import { REGIONAL_PRICING, currencyFor } from '../src/services/pricing.js';

const prisma = new PrismaClient();

// GATE: Ham ag/port (networkLayer) paketleri, bypass-proof izolasyon
// (HARDENED_NETWORK_ISOLATION=true) olmadan DB'de bile 'active:false' seed edilir
// — insan hafizasina degil, koda guveniriz. Bkz HANDOFF.md.
const HARDENED = (process.env.HARDENED_NETWORK_ISOLATION ?? 'false') === 'true';

async function main() {
  for (const pkg of SCAN_PACKAGES) {
    const active = pkg.networkLayer ? HARDENED : true;
    if (pkg.networkLayer && !HARDENED) {
      console.warn(`[seed] ⚠️  ${pkg.key} networkLayer paketi HARDENED_NETWORK_ISOLATION olmadan PASIF birakildi.`);
    }
    await prisma.scanPackage.upsert({
      where: { key: pkg.key },
      update: {
        displayName: pkg.displayName,
        description: pkg.description,
        priceMinorUnit: pkg.priceMinorUnit,
        modelProvider: pkg.modelProvider,
        maxToolCalls: pkg.maxToolCalls,
        promptTemplate: pkg.promptTemplate('{{TARGET_HOST}}'),
        active,
      },
      create: {
        key: pkg.key,
        displayName: pkg.displayName,
        description: pkg.description,
        priceMinorUnit: pkg.priceMinorUnit,
        modelProvider: pkg.modelProvider,
        maxToolCalls: pkg.maxToolCalls,
        promptTemplate: pkg.promptTemplate('{{TARGET_HOST}}'),
        active,
      },
    });
    console.log(`[seed] ${pkg.key} eklendi/guncellendi.`);
  }

  // Eski paketler (varsa) pasiflestirilir — GET /orders/packages zaten koddaki
  // SCAN_PACKAGES dizisinden okudugu icin gorunmezler; bu sadece DB tutarliligi.
  const activeKeys = SCAN_PACKAGES.map((p) => p.key);
  const deactivated = await prisma.scanPackage.updateMany({
    where: { key: { notIn: activeKeys } },
    data: { active: false },
  });
  if (deactivated.count > 0) console.log(`[seed] ${deactivated.count} eski paket pasiflestirildi.`);

  // Cok-bolgeli fiyatlandirma satirlari (tr/us/ae). TR authoritative, US/AE tahmini.
  let priceRows = 0;
  for (const pkg of SCAN_PACKAGES) {
    const byRegion = REGIONAL_PRICING[pkg.key] ?? {};
    for (const region of Object.keys(byRegion)) {
      await prisma.packagePricing.upsert({
        where: { packageKey_region: { packageKey: pkg.key, region } },
        update: { currency: currencyFor(region), amountMinorUnit: byRegion[region] },
        create: { packageKey: pkg.key, region, currency: currencyFor(region), amountMinorUnit: byRegion[region] },
      });
      priceRows++;
    }
  }
  console.log(`[seed] ${priceRows} bolgesel fiyat satiri yazildi (PackagePricing).`);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
