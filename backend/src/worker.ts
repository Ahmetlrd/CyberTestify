import { prisma } from './db.js';
import { config, validateScopeLockConfig } from './config.js';
import * as pentagi from './pentagi/client.js';
import { getPackageDef } from './services/scanPackages.js';
import { generateAndStoreReport } from './services/report.js';
import { findOutOfScope, findForbiddenMethods, detectScriptDebugLoop } from './services/scope.js';
import { encryptSecret } from './services/crypto.js';
import { buildActivityFeed } from './services/activityFeed.js';
import { promoteQueued } from './services/orchestrator.js';
import { checkEgressProxyHealth } from './services/egressHealth.js';
import { runDueSchedules, recordScheduleOutcome } from './services/schedules.js';
import { reapStuckFlows } from './services/watchdog.js';

// Fail-fast: kapsam kilidi konfigurasyonu eksik/gecersizse hemen dur.
validateScopeLockConfig();

/**
 * Arka plan poller — calisan flow'lari periyodik olarak kontrol eder:
 *  1) Paketin tool-call tavanini asan flow'lari durdurur (maliyet korumasi;
 *     bkz pentagi/client.ts'teki not — bu API seviyesinde degil, polling
 *     seviyesinde uygulanan yumusak bir tavan).
 *  2) Tamamlanan flow'lar icin rapor uretimini tetikler.
 *
 * Production'da bunu ayri bir process/cron olarak (ör. `npm run worker`)
 * calistir, web sunucusuyla ayni process'te degil.
 */

const POLL_INTERVAL_MS = 8000;

/**
 * BASARISIZ/IHLAL/TIMEOUT bitis yollarinda terminal container'i yikar. Basari yolu
 * (rapor uretimi) zaten report.ts -> purgeFlowRawData ile deleteFlow cagirir; ama
 * hata yollari yalniz stopFlow (duraklat) cagiriyordu → container ayakta kalip
 * orphan olarak birikirdi. best-effort: hata olsa da bitis akisini ENGELLEMEZ
 * (saatlik cron guvenlik agi yine de temizler). 'reserving-' rezervasyonlarda
 * gercek PentAGI flow'u yok — deleteFlow cagirma.
 */
async function teardownFlowContainer(pentagiFlowId: string) {
  if (!pentagiFlowId || pentagiFlowId.startsWith('reserving-')) return;
  await pentagi
    .deleteFlow(pentagiFlowId)
    .catch((e) => console.error(`[worker] deleteFlow (terminal temizligi) hata (yine de devam): ${e?.message ?? e}`));
}

async function tick() {
  // Once takilan flow'lari basa al (slotu serbest birak) — PentAGI'ye ULASILAMASA
  // bile calisir, cunku sadece DB'deki startedAt'e bakar. Ana poll dongusunun
  // ONUNDE olmali ki serbest kalan slot ayni cycle'da promoteQueued ile dolabilsin.
  await reapStuckFlows();

  const runningFlows = await prisma.flow.findMany({
    where: { status: 'running' },
    include: { order: { include: { package: true, domain: true } } },
  });

  // Periyodik egress proxy saglik kontrolu: proxy tarama SIRASINDA cokerse
  // yuksek gorunurlukle uyar (terminaller cikis yapamaz → tarama dogal olarak
  // basarisiz olur; burada surface ediyoruz). Yeni tarama zaten reddedilir.
  if (runningFlows.length > 0 && !(await checkEgressProxyHealth())) {
    console.error(
      '[worker][GUARD] ⚠️  Egress proxy AYAKTA DEGIL ama calisan tarama(lar) var! ' +
        'Terminaller cikis yapamaz; taramalar basarisiz olabilir. Proxy\'yi baslatin.',
    );
  }

  for (const flow of runningFlows) {
    try {
      const pkg = getPackageDef(flow.order.package.key);
      const prevCount = flow.toolCallCount;
      const toolCallCount = await pentagi.getToolCallCount(flow.pentagiFlowId);

      if (toolCallCount !== prevCount) {
        await prisma.flow.update({ where: { id: flow.id }, data: { toolCallCount } });
      }

      const remoteStatus = await pentagi.getFlowStatus(flow.pentagiFlowId);
      const overCap = toolCallCount >= pkg.maxToolCalls;

      // --- SEVIYE 3: Kapsam (scope) izleme -----------------------------------
      // Ajanin calistirdigi komut/tool argumanlarindan eristigi hedefleri cikar;
      // izin verilen kapsam (dogrulanan hostname + cozumlenen IP'ler + referans
      // allowlist) disinda bir hedef varsa flow'u durdur (enforce) veya logla.
      let violationTarget: string | null = flow.scopeViolationTarget;
      let forbiddenMethodHit: string | null = null;
      // Script debug-loop (ayni script'i tekrar tekrar yazip duzeltme dongusu) tespiti.
      let scriptLoopHit: { base: string; count: number } | null = null;
      try {
        const logs = await pentagi.getScopeLogs(flow.pentagiFlowId);

        // (A) DOSTANE aktivite akışı — her tick güncelle. Ham log DEĞİL;
        // kategorilenmiş + redakte (bkz activityFeed.ts). Müşteriye bu gösterilir.
        const feed = buildActivityFeed(logs.toolCallLogs);
        await prisma.flow.update({ where: { id: flow.id }, data: { activityFeed: JSON.stringify(feed) } });

        // (C) YASAK HTTP METODU — tum paketlerimiz PASIF (yalniz GET/HEAD/OPTIONS).
        // Ajan POST/PUT/DELETE/PATCH denerse bu APACIK bir ihlaldir; HTTP metodu
        // NET bir sinyal (yanlis-pozitif riski yok) → SCOPE_ENFORCEMENT modundan
        // BAGIMSIZ, HER ZAMAN durdurulur (bkz asagidaki always-enforce blogu).
        // GET-only guard (passive_guard.go) POST'u ARAC SEVIYESINDE zaten engelliyor;
        // burada worker YALNIZ guard'i ATLATAN (result'ta guard imzasi olmayan,
        // gerceklesmis) bir yasak-metot icin halt eder (defense-in-depth). Guard'in
        // blokladigi denemeler gormezden gelinir → ajan GET ile devam edip raporu bitirir.
        if (!pkg.networkLayer) {
          const methods = findForbiddenMethods(
            logs.toolCallLogs.map((t) => ({ name: t.name, args: t.args, result: t.result })),
          );
          if (methods.length) forbiddenMethodHit = methods.join(', ');
        }

        // (D) SCRIPT DEBUG-LOOP — ajan ayni script'i tekrar tekrar yazip/calistirip
        // duzeltmeye calisip butceyi yakarsa (bkz nomorelink vakasi) yakala; asagida
        // overCap gibi ERKEN DUR + elde edilen ham veriyle rapor uret.
        scriptLoopHit = detectScriptDebugLoop(
          logs.toolCallLogs.map((t) => ({ name: t.name, args: t.args })),
          config.scriptDebugLoopThreshold,
        );

        // (B) SEVIYE 3 kapsam izleme — yalnızca henüz ihlal kaydı yoksa.
        // SADECE ajanin ISTEDIGI hedefi (tool cagri ARGUMANLARI) tara; yanıt
        // gövdeleri 3. taraf linkleri içerir → yanlış pozitif. Gerçek egress
        // kontrolü zaten Seviye 1 proxy'de.
        if (!violationTarget) {
          const texts = logs.toolCallLogs.map((t) => t.args);
          const scope = {
            hostname: flow.order.domain.hostname,
            ips: (flow.order.domain.resolvedIps ?? '').split(',').map((s) => s.trim()).filter(Boolean),
            allowlist: config.scopeAllowlist,
          };
          const violations = findOutOfScope(texts, scope);
          if (violations.length) {
            violationTarget = violations.join(', ').slice(0, 500);
            await prisma.flow.update({ where: { id: flow.id }, data: { scopeViolationTarget: violationTarget } });
            console.error(
              `[SCOPE-VIOLATION] Flow ${flow.pentagiFlowId} order ${flow.orderId} hedef "${scope.hostname}" — kapsam disi: ${violationTarget} (mod=${config.scopeEnforcement})`,
            );
          }
        }
      } catch (err) {
        console.error(`[worker][SCOPE/FEED] Flow ${flow.pentagiFlowId} log islenirken hata:`, err);
      }

      // YASAK METOT — HER ZAMAN ENFORCE (SCOPE_ENFORCEMENT'tan bagimsiz). Veri
      // degistiren metot (POST/PUT/DELETE/PATCH) pasif pakette apacik ihlaldir ve
      // metot net bir sinyaldir → monitor modunda BILE durdurulur.
      if (forbiddenMethodHit) {
        await pentagi
          .stopFlow(flow.pentagiFlowId)
          .catch((e) => console.error(`[worker] stopFlow hata (yine de durduruluyor): ${e?.message ?? e}`));
        const target = `yasak HTTP metodu: ${forbiddenMethodHit}`;
        await prisma.flow.update({
          where: { id: flow.id },
          data: { status: 'finished', finishedAt: new Date(), scopeViolationTarget: (flow.scopeViolationTarget ? flow.scopeViolationTarget + ' | ' : '') + target },
        });
        await prisma.order.update({ where: { id: flow.orderId }, data: { status: 'scope_violation' } });
        await recordScheduleOutcome(flow.order.scheduledScanId, false);
        await teardownFlowContainer(flow.pentagiFlowId); // orphan terminal birakma
        console.error(`[POLICY-VIOLATION] Flow ${flow.pentagiFlowId} order ${flow.orderId} — ${target} tespit edildi, tarama DURDURULDU (always-enforce).`);
        continue; // rapor URETME
      }

      // ENFORCE — try/catch DISINDA olmali: stopFlow HATA verse bile rapor
      // URETILMEMELI (aksi halde ihlalli tarama tamamlanip teslim edilir). Onceki
      // tick'te stopFlow patlayip iz kaldiysa (violationTarget dolu) burada tekrar
      // denenir. monitor modunda durdurmayiz — yalnizca loglanir, tarama surer.
      if (violationTarget && config.scopeEnforcement === 'enforce') {
        await pentagi
          .stopFlow(flow.pentagiFlowId)
          .catch((e) => console.error(`[worker] stopFlow hata (yine de scope_violation): ${e?.message ?? e}`));
        await prisma.flow.update({ where: { id: flow.id }, data: { status: 'finished', finishedAt: new Date() } });
        await prisma.order.update({ where: { id: flow.orderId }, data: { status: 'scope_violation' } });
        await recordScheduleOutcome(flow.order.scheduledScanId, false);
        await teardownFlowContainer(flow.pentagiFlowId); // orphan terminal birakma
        continue; // rapor URETME — tarama kapsam ihlali nedeniyle iptal
      }

      // PentAGI tarafinda gercekten basarisiz olduysa -> siparisi de basarisiz say.
      if (remoteStatus.status === 'failed') {
        await prisma.flow.update({ where: { id: flow.id }, data: { status: 'failed', finishedAt: new Date() } });
        await prisma.order.update({ where: { id: flow.orderId }, data: { status: 'scan_failed' } });
        await recordScheduleOutcome(flow.order.scheduledScanId, false);
        await teardownFlowContainer(flow.pentagiFlowId); // orphan terminal birakma
        continue;
      }

      // PentAGI ajani isini bitirince cogu zaman 'finished' yerine 'waiting'
      // durumuna gecip YENI KOMUT bekler (interaktif mod). stopFlow / PentAGI UI'dan
      // manuel durdurma da flow'u 'waiting'e alir. Bir onceki poll'dan beri yeni
      // arac cagrisi OLMAMISSA (idle) bunu sonlanmis say.
      const idleWaiting = remoteStatus.status === 'waiting' && toolCallCount === prevCount;

      // ERKEN DURDURMA: hic arac cagrisi yapilmadan (toolCallCount===0) flow 'waiting'e
      // dustuyse tarama daha basında durdurulmus/coktu demektir. Kisa bir baslangic
      // toleransindan (ajan henuz ilk cagrisini yapmamis olabilir) sonra, RAPOR
      // URETMEDEN dogrudan basarisiz say — musteri "hazir ama bos rapor" gormesin,
      // 120 dk watchdog'u da beklemesin.
      const graceMs = config.emptyScanGraceSeconds * 1000;
      if (idleWaiting && toolCallCount === 0 && Date.now() - flow.startedAt.getTime() > graceMs) {
        await pentagi.stopFlow(flow.pentagiFlowId).catch(() => {});
        await prisma.flow.update({
          where: { id: flow.id },
          data: { status: 'failed', finishedAt: new Date(), errorMessage: 'Tarama hicbir islem yapmadan sonlandi/durduruldu.' },
        });
        await prisma.order.update({ where: { id: flow.orderId }, data: { status: 'scan_failed' } });
        await recordScheduleOutcome(flow.order.scheduledScanId, false);
        await teardownFlowContainer(flow.pentagiFlowId); // orphan terminal birakma
        console.warn(`[worker] Flow ${flow.pentagiFlowId} arac cagrisi yapmadan durdu -> scan_failed.`);
        continue;
      }

      // Bitirme kosulu: dogal 'finished' | maliyet tavani asildi | idle 'waiting'.
      // ONEMLI: stopFlow flow'u 'finished' DEGIL 'waiting' durumuna alir
      // (PentAGI'de "stopped" statusu yok), bu yuzden bitirmeyi BIZ tetikliyoruz.
      const done = remoteStatus.status === 'finished' || overCap || idleWaiting || !!scriptLoopHit;
      if (done) {
        if ((overCap || scriptLoopHit) && remoteStatus.status !== 'finished') {
          if (scriptLoopHit) {
            console.warn(
              `[worker] Flow ${flow.pentagiFlowId} SCRIPT DEBUG-LOOP tespit edildi (script "${scriptLoopHit.base}" x${scriptLoopHit.count} ≥ ${config.scriptDebugLoopThreshold}), durduruluyor ve elde edilen ham veriyle rapor uretiliyor.`,
            );
          } else {
            console.warn(`[worker] Flow ${flow.pentagiFlowId} tavani asti (${toolCallCount}/${pkg.maxToolCalls}), durduruluyor ve rapor uretiliyor.`);
          }
          await pentagi.stopFlow(flow.pentagiFlowId);
        }

        // Rapor uret (siparisi scan_completed yapar, ham veriyi PentAGI'den siler).
        const { accessSecret } = await generateAndStoreReport(flow.id);
        // generateAndStoreReport flow.status'u degistirmez; burada 'finished'
        // yapiyoruz ki bir sonraki tick'te tekrar islenmesin.
        await prisma.flow.update({ where: { id: flow.id }, data: { status: 'finished', finishedAt: new Date() } });

        // ERISIM SIFRESINI HER ZAMAN sakla — ama PEPPER ile SIFRELI (encryptSecret).
        // Neden: e-posta servisi henuz yok; giris yapmis SAHIP musteri kendi raporunu
        // acabilmeli (order detail endpoint pepper'i cozup sahibe verir, dashboard otomatik
        // doldurur). Duz saklamak yerine pepper'li: ham DB dump'i REPORT_ENCRYPTION_PEPPER
        // olmadan raporu cozemez (savunma derinligi). (Onceden yalniz mockPayment'ta duz
        // saklaniyordu -> NODE_ENV=production ile mockPayment=false olunca rapor ERISILEMEZ
        // hale gelmisti; bu o regresyonu kapatir.)
        await prisma.report.update({
          where: { orderId: flow.orderId },
          data: { devAccessSecret: encryptSecret(accessSecret) },
        });

        // TODO: e-posta gonderim servisine baglan — accessSecret'i rapor indirme
        // linkinden AYRI bir e-postada musteriye ilet.
        console.log(`[worker] Rapor hazir, siparis ${flow.orderId}. Erisim sifresi (dev'de panelde de gorunur, prod'da e-postaya tasi): ${accessSecret}`);
        // Zamanlanmis taramadan olustuysa: basari -> failCount sifirla.
        await recordScheduleOutcome(flow.order.scheduledScanId, true);
      }
    } catch (err) {
      console.error(`[worker] Flow ${flow.pentagiFlowId} islenirken hata:`, err);
    }
  }
}

/**
 * Veri saklama suresi dolan raporlarin ICERIGINI siler. Rapor satiri (sifreli
 * blob + erisim metadatasi) tamamen kaldirilir; SIPARIS kaydi (kim/ne zaman/ne
 * kadar) KORUNUR — muhasebe ve fatura mevzuati geregi. Ham PentAGI verisi zaten
 * rapor uretilir uretilmez siliniyor (report.ts -> purgeFlowRawData).
 */
async function purgeExpiredReports() {
  const cutoff = new Date(Date.now() - config.reportRetentionDays * 24 * 60 * 60 * 1000);
  const expired = await prisma.report.findMany({
    where: { createdAt: { lt: cutoff } },
    select: { id: true, orderId: true },
  });
  if (expired.length === 0) return;
  await prisma.report.deleteMany({ where: { id: { in: expired.map((r) => r.id) } } });
  // Siparisi "raporu suresi doldu/silindi" olarak isaretle (kayit korunur).
  await prisma.order.updateMany({
    where: { id: { in: expired.map((r) => r.orderId) } },
    data: { status: 'report_purged' },
  });
  console.log(`[worker] ${expired.length} adet suresi dolmus rapor icerigi silindi (siparis kaydi korundu).`);
}

async function main() {
  console.log('[worker] Baslatildi, PentAGI flow durumlari izleniyor...');
  // Acilista egress proxy sagligini kontrol et (loud uyari — proxy'siz tarama yok).
  if (await checkEgressProxyHealth()) console.log('[worker] Egress proxy (kapsam kilidi) SAGLIKLI.');
  else console.warn('[worker] ⚠️  UYARI: Egress proxy AYAKTA DEGIL! `npm run egress-proxy` calistirin.');
  // eslint-disable-next-line no-constant-condition
  while (true) {
    await tick();
    try {
      // Concurrency=1: aktif tarama bittiyse kuyruktaki bir sonrakini baslat.
      await promoteQueued();
    } catch (err) {
      console.error('[worker] Kuyruk promote sirasinda hata:', err);
    }
    try {
      await purgeExpiredReports();
    } catch (err) {
      console.error('[worker] Rapor saklama temizligi sirasinda hata:', err);
    }
    try {
      // Zamani gelen periyodik taramalari tetikle (normal siparis akisi, concurrency=1).
      await runDueSchedules();
    } catch (err) {
      console.error('[worker] Zamanlanmis tarama tetikleme sirasinda hata:', err);
    }
    try {
      // Kuyruk cok birikirse gorunur uyari (sistemin zorlandiginin isareti).
      const queued = await prisma.order.count({ where: { status: 'scan_queued' } });
      if (queued >= config.scheduledQueueWarnThreshold) {
        console.warn(`[worker] ⚠️  Kuyrukta ${queued} sipariş bekliyor (esik ${config.scheduledQueueWarnThreshold}) — sistem yogun.`);
      }
    } catch {
      /* sayim hatasi kritik degil */
    }
    await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
  }
}

main().catch((err) => {
  console.error('[worker] Beklenmeyen hata, process kapatiliyor:', err);
  process.exit(1);
});
