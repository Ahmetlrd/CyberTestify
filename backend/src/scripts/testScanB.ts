// GECICI test scripti (B paket dogrulama): cors_cookie taramasini uygulama
// katmanindan (prisma.order.create + enqueueOrStartScan) tetikler. DB bypass DEGIL.
// Kullanim: npx tsx src/scripts/testScanB.ts
import { prisma } from '../db.js';
import { enqueueOrStartScan } from '../services/orchestrator.js';

async function main() {
  const key = 'cors_cookie' as const;
  const pkg = await prisma.scanPackage.findUniqueOrThrow({ where: { key } });
  const domain = await prisma.domain.findFirstOrThrow({
    where: { status: 'verified', hostname: 'nomorelink.com' },
  });
  const order = await prisma.order.create({
    data: {
      customerId: domain.customerId,
      domainId: domain.id,
      packageId: pkg.id,
      amountMinorUnit: pkg.priceMinorUnit,
      currency: 'TRY',
      status: 'paid', // pesin (test) — enqueue dogrudan kuyruga alir
      locale: 'tr',
      ownershipConfirmedAt: new Date(),
      distanceContractAcceptedAt: new Date(),
      withdrawalWaivedAt: new Date(),
      consentVersion: 'test',
    },
  });
  console.log('[testB] order olusturuldu:', order.id, 'paket:', key, 'hedef:', domain.hostname);
  await enqueueOrStartScan(order.id);
  console.log('[testB] enqueueOrStartScan cagrildi. Worker loglarini izle.');
  await prisma.$disconnect();
}

main().catch((e) => {
  console.error('[testB] hata:', e);
  process.exit(1);
});
