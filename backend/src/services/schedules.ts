import { prisma } from '../db.js';
import { config } from '../config.js';
import { getPackageDef, localeFor } from './scanPackages.js';
import { getPricing } from './pricing.js';
import { isVerificationStillValid } from './verification.js';
import { enqueueOrStartScan } from './orchestrator.js';

const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * Bir zamanlanmis taramadan (prepaid) NORMAL siparis akisiyla yeni bir Order
 * olusturur. status 'paid' (pesin odenmis) -> enqueueOrStartScan concurrency=1
 * kuyruguna sokar. Ayri bir yol acmaz; egress/concurrency kilidini bozmaz.
 */
export async function createScheduledOrder(schedule: {
  id: string;
  customerId: string;
  domainId: string;
  packageKey: string;
  region: string;
}) {
  const packageDb = await prisma.scanPackage.findUniqueOrThrow({ where: { key: schedule.packageKey as any } });
  const packageDef = getPackageDef(schedule.packageKey);
  // Ham ag/port paketi + hardened degilse zamanlanmis da olsa calistirma.
  if (packageDef.networkLayer && !config.hardenedNetworkIsolation) {
    throw new Error('networkLayer paketi zamanlanmis taramada da devre disi (HARDENED yok).');
  }
  const { amountMinorUnit, currency } = getPricing(schedule.packageKey, schedule.region);

  const order = await prisma.order.create({
    data: {
      customerId: schedule.customerId,
      domainId: schedule.domainId,
      packageId: packageDb.id,
      amountMinorUnit,
      currency,
      status: 'paid', // prepaid (pesin) — odeme adimi yok, dogrudan kuyruga
      locale: localeFor(schedule.region), // (2) cikti dili
      paidAt: new Date(),
      scheduledScanId: schedule.id,
      // Musteri zamanlama olustururken riza vermisti; her tetiklemede damgalanir.
      ownershipConfirmedAt: new Date(),
      distanceContractAcceptedAt: new Date(),
      withdrawalWaivedAt: new Date(),
      consentVersion: config.legalVersion,
    },
  });

  await enqueueOrStartScan(order.id);
  return order;
}

/**
 * Zamani gelen aktif zamanlanmis taramalari tetikler (worker her tick cagirir).
 * Her tetikleme: dogrulama tazeligi + kalan-kosum kontrolu; sonra createScheduledOrder.
 */
export async function runDueSchedules() {
  const now = new Date();
  const due = await prisma.scheduledScan.findMany({
    where: { active: true, nextRunAt: { lte: now } },
    include: { domain: true },
    orderBy: { nextRunAt: 'asc' },
  });

  for (const s of due) {
    if (s.remainingRuns <= 0) {
      await prisma.scheduledScan.update({ where: { id: s.id }, data: { active: false } });
      continue;
    }

    // Dogrulama TTL'i (30 gun) doldu mu? Sessizce atlama — kapat + bildir.
    if (!isVerificationStillValid(s.domain)) {
      await prisma.scheduledScan.update({ where: { id: s.id }, data: { active: false } });
      // TODO(email): musteriye "domain dogrulamaniz suresi doldu, yeniden dogrulayin"
      console.warn(
        `[schedules] Domain dogrulamasi suresi doldu -> zamanlanmis tarama pasiflestirildi: ${s.domain.hostname} (musteri ${s.customerId}). Musteri bilgilendirilmeli.`,
      );
      continue;
    }

    try {
      await createScheduledOrder(s);
      const remaining = s.remainingRuns - 1;
      await prisma.scheduledScan.update({
        where: { id: s.id },
        data: {
          remainingRuns: remaining,
          nextRunAt: new Date(now.getTime() + s.intervalDays * DAY_MS),
          active: remaining > 0, // pesin kosumlar bittiyse kapat
        },
      });
      console.log(`[schedules] Tetiklendi: ${s.domain.hostname} · kalan ${remaining} · sonraki ~${s.intervalDays} gun sonra`);
    } catch (err) {
      // Tetikleme hatasi: nextRunAt'i ilerlet ki sonsuz tekrar denemesin.
      console.error(`[schedules] Tetikleme hatasi (${s.id}):`, err);
      await prisma.scheduledScan.update({
        where: { id: s.id },
        data: { nextRunAt: new Date(now.getTime() + s.intervalDays * DAY_MS) },
      });
    }
  }
}

/**
 * Zamanlanmis taramadan olusan bir siparis TERMINAL duruma ulasinca cagrilir.
 * Basarili -> failCount sifirla. Basarisiz -> arttir; 3 ardarda -> pasiflestir.
 */
export async function recordScheduleOutcome(scheduledScanId: string | null | undefined, ok: boolean) {
  if (!scheduledScanId) return;
  if (ok) {
    await prisma.scheduledScan.update({ where: { id: scheduledScanId }, data: { failCount: 0 } }).catch(() => {});
    return;
  }
  const s = await prisma.scheduledScan
    .update({ where: { id: scheduledScanId }, data: { failCount: { increment: 1 } } })
    .catch(() => null);
  if (s && s.failCount >= 3) {
    await prisma.scheduledScan.update({ where: { id: scheduledScanId }, data: { active: false } }).catch(() => {});
    // TODO(email): musteriye "zamanlanmis taramaniz ardarda basarisiz oldu, durduruldu"
    console.warn(`[schedules] 3 ardarda basarisizlik -> pasiflestirildi: ${scheduledScanId}. Musteri bilgilendirilmeli.`);
  }
}
