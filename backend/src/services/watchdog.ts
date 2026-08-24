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
    // deleteFlow: takilan flow'un terminal container'ini da yik (orphan birakma).
    // 'reserving-'/'deterministic-' sentinel'lerinde gercek PentAGI flow'u yok → stop/deleteFlow
    // cagirma (bosuna patlar). (deterministic- yalniz worker cokup >120dk kalirsa buraya duser.)
    const noRealFlow = flow.pentagiFlowId.startsWith('reserving-') || flow.pentagiFlowId.startsWith('deterministic-');
    if (!noRealFlow) {
      await pentagi.stopFlow(flow.pentagiFlowId).catch(() => {});
      await pentagi.deleteFlow(flow.pentagiFlowId).catch(() => {});
    }

    await prisma.flow
      .update({ where: { id: flow.id }, data: { status: 'failed', finishedAt: new Date(), errorMessage: reason } })
      .catch((e) => console.error('[watchdog] flow update hatasi:', e));
    await prisma.order.update({ where: { id: flow.order.id }, data: { status: 'scan_failed' } }).catch(() => {});
    await recordScheduleOutcome(flow.order.scheduledScanId, false);
    reaped++;
  }

  // MUTABAKAT: bir siparis 'scan_running' ama hicbir Flow'u YOKSA (guc kesintisi,
  // olusum sirasinda cokme, tutarsiz durum) — normalde scan_running her zaman bir
  // running flow'a eslik eder. Baslangic toleransindan sonra bunu scan_failed yap;
  // aksi halde musteri panelinde sonsuza kadar "tarama calisiyor" gorunur.
  //
  // (S1 MUAFIYETI — KRITIK) S1 Otonom Red Team siparisleri PentAGI Flow KULLANMAZ; ayri
  // RedTeamJob motoruyla kosarlar (izole droplet). Bu yuzden S1 icin 'scan_running + flow yok'
  // NORMALDIR — droplet provisioning DAKIKALAR surer. redTeamJob: null suzgeci olmadan watchdog
  // 60sn grace sonrasi gercek-kosan S1 siparisini yanlislikla scan_failed yapardi (musteri ekraninda
  // "Tarama tamamlanamadi" cikarken admin panelinde droplet hala provisioning'de). RedTeamJob'lu
  // siparisler burada ele ALINMAZ — onlarin yasam dongusunu runner/kill-switch/watchdog-D5 yonetir.
  const graceCutoff = new Date(nowMs - config.emptyScanGraceSeconds * 1000);
  const orphanOrders = await prisma.order.findMany({
    where: { status: 'scan_running', flow: null, redTeamJob: null, createdAt: { lt: graceCutoff } },
    select: { id: true, scheduledScanId: true },
  });
  for (const o of orphanOrders) {
    console.error(`[watchdog] Siparis ${o.id} 'scan_running' ama flow yok -> scan_failed (tutarsiz durum).`);
    await prisma.order.update({ where: { id: o.id }, data: { status: 'scan_failed' } }).catch(() => {});
    await recordScheduleOutcome(o.scheduledScanId, false);
    reaped++;
  }
  return reaped;
}
