import './tlsBypass.js'; // EN BAŞTA: bad-cert hedeflere fetch() TypeError ile düşmesin (güvenlik tarayıcı)
import { prisma } from './db.js';
import { config, validateScopeLockConfig } from './config.js';
import * as pentagi from './pentagi/client.js';
import { getPackageDef, securityProfileFor } from './services/scanPackages.js';
import { generateAndStoreReport } from './services/report.js';
import { runWithScanLog, purgeOldScanLogs } from './services/scanLogger.js';
import { sendReportReady } from './services/mailer.js';
import { publishDailyIfDue } from './services/blog.js';
import { findOutOfScope, findForbiddenMethods, forbiddenMethodsForProfile, detectScriptDebugLoop, detectRepeatedFetch } from './services/scope.js';
import { encryptSecret } from './services/crypto.js';
import { purgeExpiredCredentials } from './services/testCredentials.js';
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
  // 'reserving-'/'deterministic-' sentinel'lerinde gercek PentAGI flow'u yok -> deleteFlow cagirma.
  if (!pentagiFlowId || pentagiFlowId.startsWith('reserving-') || pentagiFlowId.startsWith('deterministic-')) return;
  await pentagi
    .deleteFlow(pentagiFlowId)
    .catch((e) => console.error(`[worker] deleteFlow (terminal temizligi) hata (yine de devam): ${e?.message ?? e}`));
}

// Sipariş henüz terminal DEĞİLSE net biçimde başarısız işaretle (kimlik bilgisi tüketilmiş olabilir).
const TERMINAL_ORDER = new Set(['scan_failed', 'scan_completed', 'report_delivered', 'report_purged', 'scope_violation', 'refunded']);
let lastLogRetentionAt = 0; // (gözlemlenebilirlik) log retention'ı günde bir kez çalıştırmak için guard
async function failOrderIfPending(orderId: string, reason: string): Promise<void> {
  const o = await prisma.order.findUnique({ where: { id: orderId }, select: { status: true } });
  if (!o || TERMINAL_ORDER.has(o.status)) return;
  await prisma.order.update({ where: { id: orderId }, data: { status: 'scan_failed', failureReason: reason } }).catch(() => {});
}

// (Fix) Açılışta: bir önceki worker rapor üretimi SIRASINDA çöktü/yeniden başladıysa, o flow
// 'running' + reportGenStartedAt DOLU kalır (ORPHAN). Tek-kullanımlık kimlik bilgisi tüketilmiş
// olabileceğinden TEKRAR İŞLENMEZ (no_login_endpoint üretirdi) — net başarısız yapılır.
async function sweepOrphanReportGen(): Promise<void> {
  const orphans = await prisma.flow.findMany({
    where: { status: 'running', reportGenStartedAt: { not: null } },
    select: { id: true, orderId: true, pentagiFlowId: true, order: { select: { scheduledScanId: true } } },
  });
  for (const f of orphans) {
    await prisma.flow.update({ where: { id: f.id }, data: { status: 'error', finishedAt: new Date(), errorMessage: 'worker yeniden başladı; rapor üretimi kesildi' } }).catch(() => {});
    await failOrderIfPending(f.orderId, 'scan_interrupted');
    await recordScheduleOutcome(f.order.scheduledScanId, false).catch(() => {});
    console.warn(`[worker] Orphan rapor-üretim flow'u temizlendi -> sipariş ${f.orderId} scan_failed (tarama kesildi).`);
  }
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
      // (PENTAGI'SIZ) Deterministik paket (basit_tarama): PentAGI flow'u YOK (sentinel
      // 'deterministic-'). Ajan/sandbox poll'lama; raporu backend collector'lariyla DOGRUDAN
      // uret (generateAndStoreReport basit_tarama'da generateBasitReport'u cagirir) ve flow'u
      // hemen bitir. Done-tail (rapor + sifre + mail) normal yol ile AYNI. Diger flow'lar
      // asagidaki normal PentAGI yolundan gecer (DEGISMEDI).
      if (flow.pentagiFlowId.startsWith('deterministic-')) {
        // (Fix) ATOMİK CLAIM: bu flow'u işleme almadan önce reportGenStartedAt damgasını koy.
        // Authenticated (full_pentest) rapor üretimi DAKİKALAR sürer; worker bu sırada YENİDEN
        // BAŞLARSA yeni worker aynı 'running' flow'u TEKRAR işleyip tek-kullanımlık kimlik bilgisini
        // ikinci kez tüketiyor -> no_login_endpoint. Claim (koşullu update) yalnız BİR işlemin
        // devam etmesini sağlar; ikinci işleme count!==1 ile elenir. Status 'running' kalır (eş-
        // zamanlılık=1 korunur); orphan claim'ler açılışta sweepOrphanReportGen ile temizlenir.
        const claim = await prisma.flow.updateMany({
          where: { id: flow.id, status: 'running', reportGenStartedAt: null },
          data: { reportGenStartedAt: new Date() },
        });
        if (claim.count !== 1) continue; // zaten üretimde/işlendi -> tekrar tüketme
        let res: Awaited<ReturnType<typeof generateAndStoreReport>>;
        try {
          res = await runWithScanLog(flow.orderId, flow.id, () => generateAndStoreReport(flow.id));
        } catch (genErr) {
          console.error(`[worker] deterministik rapor üretimi hata (sipariş ${flow.orderId}):`, genErr);
          await prisma.flow.update({ where: { id: flow.id }, data: { status: 'error', finishedAt: new Date(), errorMessage: String((genErr as Error)?.message ?? genErr).slice(0, 300) } }).catch(() => {});
          await failOrderIfPending(flow.orderId, 'report_generation_error');
          await recordScheduleOutcome(flow.order.scheduledScanId, false);
          continue;
        }
        await prisma.flow.update({ where: { id: flow.id }, data: { status: 'finished', finishedAt: new Date() } });
        if (!res) {
          // (FAZ E) Tam Kapsamlı Pentest: login başarısız -> rapor YOK (sipariş zaten scan_failed +
          // müşteri maili). Flow bitirildi; rapor-hazır maili GÖNDERME.
          await recordScheduleOutcome(flow.order.scheduledScanId, false);
          console.log(`[worker] ${flow.pentagiFlowId} — login başarısız; rapor üretilmedi (sipariş ${flow.orderId}).`);
          continue;
        }
        const { accessSecret } = res;
        await prisma.report.update({ where: { orderId: flow.orderId }, data: { devAccessSecret: encryptSecret(accessSecret) } });
        // (İÇ KALİTE KAPISI) Kapı açıksa erişim kodu e-postasını ŞİMDİ GÖNDERME — rapor
        // 'awaiting_admin_review'da bekler; admin onaylayınca (admin route) e-posta gider.
        if (config.adminReportGate) {
          console.log(`[worker] ${flow.pentagiFlowId} — rapor üretildi, ADMIN ONAYI bekliyor (sipariş ${flow.orderId}). E-posta onayda gönderilecek.`);
        } else {
          await sendReportReady(flow.orderId, accessSecret);
          console.log(`[worker] ${flow.pentagiFlowId} — PentAGI'siz deterministik rapor uretildi (siparis ${flow.orderId}).`);
        }
        await recordScheduleOutcome(flow.order.scheduledScanId, true);
        continue;
      }

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
      // Tekrar-fetch (ayni URL/path'i defalarca cekme) tespiti — yalniz pasif paketlerde.
      let repeatFetchHit: { url: string; count: number } | null = null;
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
          // PROFIL-FARKINDA: active-light/active-verify-only'de POST'a izin ver (egress-proxy ile
          // TUTARLI); PUT/PATCH/DELETE her profilde yasak. Bkz forbiddenMethodsForProfile.
          const effective = forbiddenMethodsForProfile(methods, securityProfileFor(pkg));
          if (effective.length) forbiddenMethodHit = effective.join(', ');
        }

        // (D) SCRIPT DEBUG-LOOP / SCRIPT-ETRAFINDA-DONME — ajan bir script yazip etrafinda
        // (yazma/chmod/cat/calistirma) verimsiz cagrilar yaparsa (bkz nomorelink KVKK vakasi:
        // 14 cagri, rapor eksik) yakala; asagida overCap gibi ERKEN DUR + ham veriyle rapor uret.
        // SABIT/DAR checklist (pasif) paketlerde script ZATEN YASAK -> cok daha DUSUK esik (3),
        // boylece etrafinda donme < 6 referansta bile erken kesilir. Active-light: normal esik.
        const loopThreshold =
          securityProfileFor(pkg) === 'passive'
            ? Math.min(3, config.scriptDebugLoopThreshold)
            : config.scriptDebugLoopThreshold;
        scriptLoopHit = detectScriptDebugLoop(
          logs.toolCallLogs.map((t) => ({ name: t.name, args: t.args })),
          loopThreshold,
        );

        // (E) TEKRAR-FETCH — ayni URL/path'i defalarca cekme (canli nomorelink: anasayfa
        // 5 kez). YALNIZ pasif (sabit/dar checklist) paketlerde; active-light HARIC (onlar
        // mesru sekilde ayni endpoint'e farkli acilardan istek atabilir). Esik config'ten.
        if (securityProfileFor(pkg) === 'passive' && config.urlRepeatThreshold > 0) {
          repeatFetchHit = detectRepeatedFetch(
            logs.toolCallLogs.map((t) => ({ name: t.name, args: t.args })),
            config.urlRepeatThreshold,
          );
        }

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

      // IDLE-WAITING SABIR (grace): >0 cagri yapmis bir ajan adimlar-arasi kisa 'waiting'e
      // duserse (dusunme/planlama molasi) bunu TEK poll'da "bitti" SAYMA. idle ilk gozlemde
      // idleSince'i damgala; aktivite donerse (status waiting DEGIL, ya da yeni arac cagrisi)
      // temizle. Yalniz idle KESINTISIZ idleWaitingGraceSeconds boyunca surerse "onaylanmis
      // idle" say. Gercekten biten ajan suresiz 'waiting' kalir (maliyetsiz bekleme); planlayan
      // ajan devam eder (bkz flow 70: 1 cagri + plan sonrasi ilk poll'da HAKSIZ olduruluyordu).
      // NOT: toolCallCount===0 (hic cagri yok) hali AYRI ele alinir (asagida, scan_failed).
      let idleConfirmed = false;
      if (idleWaiting && toolCallCount > 0) {
        if (!flow.idleSince) {
          await prisma.flow.update({ where: { id: flow.id }, data: { idleSince: new Date() } });
        } else if (Date.now() - flow.idleSince.getTime() >= config.idleWaitingGraceSeconds * 1000) {
          idleConfirmed = true;
        }
      } else if (flow.idleSince) {
        // aktivite dondu (artik idle degil) → sayaci sifirla.
        await prisma.flow.update({ where: { id: flow.id }, data: { idleSince: null } });
      }

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
      const done = remoteStatus.status === 'finished' || overCap || idleConfirmed || !!scriptLoopHit || !!repeatFetchHit;
      if (done) {
        if (idleConfirmed && remoteStatus.status !== 'finished' && !overCap && !scriptLoopHit && !repeatFetchHit) {
          console.log(
            `[worker] Flow ${flow.pentagiFlowId} ${config.idleWaitingGraceSeconds}sn boyunca kesintisiz idle ('waiting', ${toolCallCount} cagri) — bitmis sayilip rapor uretiliyor.`,
          );
        }
        if ((overCap || scriptLoopHit || repeatFetchHit) && remoteStatus.status !== 'finished') {
          if (scriptLoopHit) {
            console.warn(
              `[worker] Flow ${flow.pentagiFlowId} SCRIPT DEBUG-LOOP tespit edildi (script "${scriptLoopHit.base}" x${scriptLoopHit.count} ≥ ${config.scriptDebugLoopThreshold}), durduruluyor ve elde edilen ham veriyle rapor uretiliyor.`,
            );
          } else if (repeatFetchHit) {
            console.warn(
              `[worker] Flow ${flow.pentagiFlowId} TEKRAR-FETCH tespit edildi (URL "${repeatFetchHit.url}" x${repeatFetchHit.count} ≥ ${config.urlRepeatThreshold}), durduruluyor ve elde edilen ham veriyle rapor uretiliyor.`,
            );
          } else {
            console.warn(`[worker] Flow ${flow.pentagiFlowId} tavani asti (${toolCallCount}/${pkg.maxToolCalls}), durduruluyor ve rapor uretiliyor.`);
          }
          await pentagi.stopFlow(flow.pentagiFlowId);
        }

        // Rapor uret (siparisi scan_completed yapar, ham veriyi PentAGI'den siler).
        const res = await runWithScanLog(flow.orderId, flow.id, () => generateAndStoreReport(flow.id));
        // generateAndStoreReport flow.status'u degistirmez; burada 'finished'
        // yapiyoruz ki bir sonraki tick'te tekrar islenmesin.
        await prisma.flow.update({ where: { id: flow.id }, data: { status: 'finished', finishedAt: new Date() } });
        if (!res) { // savunma (bu yolda normalde null olmaz — full-pentest deterministik yoldan geçer)
          console.warn(`[worker] ${flow.orderId}: rapor null döndü, atlandı.`);
          continue;
        }
        const { accessSecret } = res;

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

        // (D) Rapor hazir + erisim sifresi e-postasi. Sifre AYRI bir kanaldan (e-posta) iletilir.
        // (İÇ KALİTE KAPISI) Kapı açıksa e-postayı ŞİMDİ GÖNDERME — admin onayına ertelenir.
        if (config.adminReportGate) {
          console.log(`[worker] Rapor hazir, siparis ${flow.orderId} — ADMIN ONAYI bekliyor (awaiting_admin_review). E-posta onayda gönderilecek.`);
        } else {
          await sendReportReady(flow.orderId, accessSecret);
          console.log(`[worker] Rapor hazir, siparis ${flow.orderId}. Erisim sifresi e-posta ile gonderildi (panelde de gorunur).`);
        }
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
  // (Fix) Önceki worker rapor üretimi sırasında yeniden başladıysa orphan flow'ları temizle
  // (tek-kullanımlık kimlik bilgisi tüketilmiş olabilir; TEKRAR işleme no_login_endpoint üretir).
  await sweepOrphanReportGen().catch((e) => console.error('[worker] orphan sweep hata:', e));
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
      // (Tam Kapsamlı Pentest — FAZ A) Kimlik bilgisi güvenlik ağı: flow başlamasa/patlasa bile
      // 1 saatten eski test kimlik bilgilerini temizle (ciphertext=null). Normal yolda orchestrator
      // zaten kullanır kullanmaz siler; bu, o silme atlanırsa devreye giren yedek katmandır.
      await purgeExpiredCredentials();
      // (GÖZLEMLENEBİLİRLİK RETENTION) Günde bir kez 60 günden eski tarama loglarını temizle.
      if (Date.now() - lastLogRetentionAt > 24 * 60 * 60 * 1000) {
        lastLogRetentionAt = Date.now();
        await purgeOldScanLogs(60);
      }
    } catch (err) {
      console.error('[worker] Test kimlik bilgisi temizligi sirasinda hata:', err);
    }
    try {
      // (SEO BLOG) Gunde 1: bugun (TR) henuz yayin yoksa en eski draft'i yayinla (restart-guvenli).
      await publishDailyIfDue();
    } catch (err) {
      console.error('[worker] Blog gunluk yayin sirasinda hata:', err);
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
