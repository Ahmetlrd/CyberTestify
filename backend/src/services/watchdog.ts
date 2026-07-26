import { prisma } from '../db.js';
import { config } from '../config.js';
import * as pentagi from '../pentagi/client.js';
import { recordScheduleOutcome } from './schedules.js';

/**
 * WATCHDOG (dayaniklilik guvencesi). Tek tek dayaniklilik onlemlerinden ziyade
 * TEK bir emniyet supabi: bir tarama makul sureden uzun 'running' kaldiysa
 * takilmis kabul edilir. Bu, asagidaki senaryolarin HEPSINI kapsar cunku hepsi
 * ayni belirtiyle sonuclanir — flow sonsuza kadar 'running'da asili kalir:
 *   - PentAGI/sunucu cokmesi veya guc kesintisi (tarama ortasinda)
 *   - Anthropic kredi/token bitmesi (ajan ilerleyemez)
 *   - Ag kesintisi / PentAGI'ye ulasilamamasi (getFlowStatus her tick hata atar,
 *     worker'daki ana dongudeki catch sadece loglar → flow running kalirdi)
 *   - Orphan rezervasyon: 'running' slotu DB'de rezerve edildi ama createFlow
 *     tamamlanmadan process oldu → pentagiFlowId 'reserving-...' takili kalir
 *
 * Takilan flow basa alinmazsa concurrency=1 kilidi HIC acilmaz ve kuyruktaki TUM
 * musteri taramalari sonsuza kadar bekler. Bu fonksiyon slotu serbest birakir:
 * flow 'failed', siparis 'scan_failed', zamanlanmis ise failCount++.
 *
 * NOT: Basa alinan bir kerelik siparis su an OTOMATIK iade/yeniden-deneme almiyor
 * (scan_failed'da kalir) — bu bilincli bir eksik, bkz HANDOFF.md.
 */
export async function reapStuckFlows() {
  const nowMs = Date.now();
  const scanCutoff = new Date(nowMs - config.scanTimeoutMinutes * 60_000);
  const resvCutoff = new Date(nowMs - config.reservationTimeoutMinutes * 60_000);
  const running = await prisma.flow.findMany({
    where: { status: 'running' },
    include: { order: { select: { id: true, scheduledScanId: true } } },
  });

  let reaped = 0;
  for (const flow of running) {
    const orphanReservation = flow.pentagiFlowId.startsWith('reserving-') && flow.startedAt < resvCutoff;
    const timedOut = flow.startedAt < scanCutoff;
    if (!orphanReservation && !timedOut) continue;

    const reason = orphanReservation
      ? `Rezervasyon ${config.reservationTimeoutMinutes} dk icinde gercek taramaya donusmedi (orphan).`
      : `Tarama ${config.scanTimeoutMinutes} dk zaman asimina ugradi (cokme/kredi-token bitmesi/ag kesintisi olabilir).`;
    console.error(`[watchdog] Flow ${flow.pentagiFlowId} (siparis ${flow.order.id}) basa aliniyor: ${reason}`);

    // PentAGI'yi durdurmayi DENE ama basarisizligi DB guncellemesini ENGELLEMESIN
    // (proxy/pentagi coktuyse stopFlow zaten patlar; onemli olan slotu serbest birakmak).
    if (!orphanReservation) await pentagi.stopFlow(flow.pentagiFlowId).catch(() => {});

    await prisma.flow
      .update({ where: { id: flow.id }, data: { status: 'failed', finishedAt: new Date(), errorMessage: reason } })
      .catch((e) => console.error('[watchdog] flow update hatasi:', e));
    await prisma.order.update({ where: { id: flow.order.id }, data: { status: 'scan_failed' } }).catch(() => {});
    await recordScheduleOutcome(flow.order.scheduledScanId, false);
    reaped++;
  }
  return reaped;
}
