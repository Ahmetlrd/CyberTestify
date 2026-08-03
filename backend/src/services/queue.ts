import { prisma } from '../db.js';

/**
 * (#3/#4) Kuyruk gorunurlugu — concurrency=1 mimarisi degismeden, mevcut
 * scan_queued/FIFO kuyrugunun DURUMUNU musteriye acar. Kod tarafinda yeni bir
 * kuyruk YOK; sadece hesap/okuma.
 */

const DEFAULT_AVG_MIN = 6; // gercek veri yoksa (bkz kapasite denetimi) makul varsayilan

/**
 * Ortalama tarama suresi (dk) — son N basarili flow'un (finishedAt-startedAt)
 * ortalamasindan DINAMIK. Sabit kodlama yerine gercek performansi yansitir; hic
 * ornek yoksa DEFAULT_AVG_MIN'e duser. Absurd degerler (negatif / >24s) elenir.
 */
export async function getAvgScanMinutes(sample = 20): Promise<number> {
  const flows = await prisma.flow.findMany({
    where: { status: 'finished', finishedAt: { not: null } },
    orderBy: { finishedAt: 'desc' },
    take: sample,
    select: { startedAt: true, finishedAt: true },
  });
  const durations = flows
    .map((f) => (f.finishedAt!.getTime() - f.startedAt.getTime()) / 60_000)
    .filter((m) => m > 0 && m < 24 * 60);
  if (durations.length === 0) return DEFAULT_AVG_MIN;
  const avg = durations.reduce((a, b) => a + b, 0) / durations.length;
  return Math.max(1, Math.round(avg));
}

/** Genel kuyruk durumu (yeni siparis oncesi yogunluk uyarisi icin). */
export async function getQueueStats() {
  const [queuedCount, runningCount, avgScanMinutes] = await Promise.all([
    prisma.order.count({ where: { status: 'scan_queued' } }),
    prisma.flow.count({ where: { status: 'running' } }),
    getAvgScanMinutes(),
  ]);
  const running = runningCount > 0;
  // Yeni bir siparis en kotu durumda: mevcut kuyruk + calisan tarama kadar bekler.
  const etaMinutes = (queuedCount + (running ? 1 : 0)) * avgScanMinutes;
  return { queuedCount, running, avgScanMinutes, etaMinutes };
}

/**
 * Belirli bir (kuyrukta bekleyen) siparisin pozisyonu + ETA. position = bu siparis
 * baslamadan ONCE bitmesi gereken tarama sayisi = onunde kuyrukta bekleyenler +
 * (varsa) su an calisan tarama.
 */
export async function getQueuePosition(order: { createdAt: Date }) {
  const [ahead, runningCount, avgScanMinutes] = await Promise.all([
    prisma.order.count({ where: { status: 'scan_queued', createdAt: { lt: order.createdAt } } }),
    prisma.flow.count({ where: { status: 'running' } }),
    getAvgScanMinutes(),
  ]);
  const position = ahead + (runningCount > 0 ? 1 : 0);
  return { position, peopleAhead: position, etaMinutes: position * avgScanMinutes, avgScanMinutes };
}
