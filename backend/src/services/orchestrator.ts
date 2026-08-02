import { prisma } from '../db.js';
import { config } from '../config.js';
import { getPackageDef } from './scanPackages.js';
import { isVerificationStillValid } from './verification.js';
import { checkEgressProxyHealth } from './egressHealth.js';
import * as pentagi from '../pentagi/client.js';

/**
 * Kapsam kilidi guvencesi: egress proxy (Seviye 1) ayakta DEGILSE tarama
 * baslatilamaz. Aksi halde terminaller filtresiz internete cikardi. Sessiz
 * basarisizlik yerine ACIK red + Order 'scan_failed'.
 */
async function assertEgressProxyHealthy(orderId?: string): Promise<void> {
  if (await checkEgressProxyHealth()) return;
  if (orderId) {
    await prisma.order.update({ where: { id: orderId }, data: { status: 'scan_failed' } }).catch(() => {});
  }
  const msg = 'Kapsam kilidi (egress proxy) ayakta degil, guvenlik nedeniyle tarama baslatilamadi.';
  console.error(`[orchestrator][GUARD] ${msg}${orderId ? ' Siparis: ' + orderId : ''}`);
  throw new Error(msg);
}

/**
 * SEVIYE 1 (egress kilidi) icin CONCURRENCY = 1.
 *
 * Ayni anda yalnizca TEK bir tarama (flow) 'scan_running' olabilir. Nedeni:
 * egress proxy'nin (egress-proxy/) allowlist'i o an aktif olan TEK flow'un
 * kapsamiyla (hostname + resolvedIps) eslesiyor. Birden fazla flow ayni anda
 * calisirsa proxy TUM aktif hedeflerin BIRLESIMINE izin vermek zorunda kalir —
 * bu da musteriler arasi (cross-tenant) kapsam sizintisi riski dogurur. Bu
 * yuzden, per-flow dinamik izolasyon/allowlist yazilana kadar concurrency=1
 * BILINCLI bir tercihtir. Fazla siparisler 'scan_queued'da bekler, worker
 * sirayla promote eder (promoteQueued).
 */
async function hasActiveScan(): Promise<boolean> {
  const running = await prisma.flow.count({ where: { status: 'running' } });
  return running > 0;
}

/**
 * Odeme onaylandiktan SONRA cagrilir. Aktif tarama varsa siparisi kuyruga alir
 * (scan_queued), yoksa hemen baslatir. Boylece concurrency=1 garanti edilir.
 */
export async function enqueueOrStartScan(orderId: string) {
  // Aktif tarama varsa nasilsa kuyruga alacagiz; yoksa hemen baslatmadan ONCE
  // egress proxy saglikli mi kontrol et (kuyruga alinan siparisler promote
  // sirasinda ayrica kontrol edilir).
  if (await hasActiveScan()) {
    await prisma.order.update({ where: { id: orderId }, data: { status: 'scan_queued' } });
    return { queued: true as const };
  }
  await assertEgressProxyHealthy(orderId);
  const flow = await startScanForOrder(orderId);
  return { queued: false as const, flow };
}

/**
 * Musteri hicbir asamada PentAGI'ye dogrudan dokunmuyor — sadece bu fonksiyon
 * bizim servis hesabimizla PentAGI'ye baglaniyor. 'paid' veya 'scan_queued'
 * (kuyruktan promote edilen) siparisler icin cagrilabilir.
 */
export async function startScanForOrder(orderId: string) {
  const order = await prisma.order.findUniqueOrThrow({
    where: { id: orderId },
    include: { domain: true, package: true },
  });

  if (order.status !== 'paid' && order.status !== 'scan_queued') {
    throw new Error(`Siparis odenmemis/uygun degil, tarama baslatilamaz: ${order.status}`);
  }

  // Concurrency=1 guvencesi: promote sirasinda yaris olmasin diye son bir kontrol.
  if (await hasActiveScan()) {
    await prisma.order.update({ where: { id: orderId }, data: { status: 'scan_queued' } });
    throw new Error('Zaten aktif bir tarama var; siparis kuyruga alindi.');
  }

  // Odeme ile tarama arasinda gecen surede domain sahipligi degismis olabilir
  // (bkz konusmadaki "once dogrula, sonra ode" sirasi) — burada tekrar kontrol.
  if (!isVerificationStillValid(order.domain)) {
    await prisma.order.update({ where: { id: orderId }, data: { status: 'scan_failed' } });
    throw new Error('Domain dogrulamasi gecersiz veya suresi dolmus, tarama baslatilamiyor.');
  }

  const pkg = getPackageDef(order.package.key);

  // Savunma katmani: ham ag/port paketi (networkLayer) ancak bypass-proof
  // izolasyon aktifken calisabilir (route'ta da guard var; burada ikinci hat).
  if (pkg.networkLayer && !config.hardenedNetworkIsolation) {
    await prisma.order.update({ where: { id: orderId }, data: { status: 'scan_failed' } });
    throw new Error('Ham ag/port paketi icin bypass-proof izolasyon (HARDENED_NETWORK_ISOLATION) gerekli.');
  }

  // Egress proxy saglikli mi? (defense-in-depth — enqueue'da da kontrol edildi)
  await assertEgressProxyHealthy(orderId);

  // Su an tek paket (basit_tarama) var; hepsi bizim tek servis provider'imizi
  // ("anthropic") kullanir. BYOK (musteri kendi anahtari) akisi ileride ayri
  // bir provider create/delete mantigiyla eklenecek.
  // (2) Cikti dili: siparisin locale'ine gore ajana YANIT dilini soyle (prompt
  // govdesini cevirmeye gerek yok; ajan cok-dilli). tr->Turkce, en->Ingilizce.
  const langLine =
    order.locale === 'en'
      ? '\n\nIMPORTANT — LANGUAGE: Write the ENTIRE report, all findings and all fix suggestions in ENGLISH.'
      : '\n\nONEMLI — DIL: Raporun tamamini, tum bulgulari ve cozum onerilerini TURKCE yaz.';

  // (2) SOMUT butce esigi. "Yaklasik yari" gibi goreceli ifade ise yaramiyordu
  // (ajan tool-call sayacini bilmiyor). Net sayi ver: butcenin ~%55'inde kesfi
  // birak, kalanini rapor yazmaya ayir. Boylece tavana carpmadan ONCE rapor uretilir.
  const budget = pkg.maxToolCalls;
  const stopAt = Math.max(3, Math.floor(budget * 0.55));
  const budgetLine =
    order.locale === 'en'
      ? `\n\nTOOL-CALL BUDGET: You have at most ${budget} tool calls. After about the ${stopAt}th call, STOP all new exploration and START writing the report (findings + '===FIX_SUGGESTIONS===' if any). Never hit the limit with an empty report.`
      : `\n\nARAC CAGRI BUTCESI: En fazla ${budget} arac cagrin var. Yaklasik ${stopAt}. cagridan sonra TUM yeni kesfi DURDUR ve raporu (bulgular + varsa '===FIX_SUGGESTIONS===') YAZMAYA BASLA. Tavana bos raporla carpma.`;

  const prompt = pkg.promptTemplate(order.domain.hostname) + langLine + budgetLine;
  const modelProvider = pkg.modelProvider;

  // YARIS-GUVENLI concurrency=1: PentAGI'yi cagirmadan ONCE 'running' slotunu
  // DB'de rezerve et. Postgres'te kismi unique index (WHERE status='running')
  // ayni anda yalnizca TEK 'running' flow'a izin verir; iki istek tam ayni anda
  // gelirse ikincisinin insert'i P2002 ile patlar → siparis kuyruga alinir.
  // Boylece iki gercek PentAGI flow'u yaratma israfi da onlenir.
  let flow;
  try {
    // Postgres advisory lock (transaction boyunca) es zamanli istekleri
    // SERILESTIRIR: iki istek ayni anda gelse bile kilit sirayla verilir; ikinci
    // istek kilidi aldiginda count>0 gorur ve kuyruga alinir. (Kismi unique index
    // de defense-in-depth olarak durur; dogruluk bu kilitten bagimsizdir.)
    flow = await prisma.$transaction(async (tx) => {
      await tx.$executeRawUnsafe('SELECT pg_advisory_xact_lock(918273645)');
      const running = await tx.flow.count({ where: { status: 'running' } });
      if (running > 0) {
        const e: any = new Error('queued');
        e.__queued = true;
        throw e;
      }
      return tx.flow.create({
        data: { orderId: order.id, pentagiFlowId: `reserving-${order.id}`, status: 'running' },
      });
    });
  } catch (err: any) {
    if (err?.__queued || err?.code === 'P2002') {
      await prisma.order.update({ where: { id: orderId }, data: { status: 'scan_queued' } });
      throw new Error('Es zamanli baska bir tarama var; siparis kuyruga alindi.');
    }
    throw err;
  }

  // Slot bizim — simdi PentAGI flow'unu yarat ve gercek ID ile guncelle.
  try {
    const created = await pentagi.createFlow(modelProvider, prompt);
    flow = await prisma.flow.update({ where: { id: flow.id }, data: { pentagiFlowId: created.id } });
  } catch (err) {
    // PentAGI cagrisi patlarsa rezervasyonu birak (slotu serbest birak).
    await prisma.flow.delete({ where: { id: flow.id } }).catch(() => {});
    await prisma.order.update({ where: { id: orderId }, data: { status: 'scan_failed' } });
    throw err;
  }

  await prisma.order.update({ where: { id: orderId }, data: { status: 'scan_running' } });

  return flow;
}

/**
 * Aktif tarama yoksa, kuyruktaki en eski siparisi baslatir (FIFO). Worker her
 * tick sonunda cagirir. Concurrency=1 icin sira mekanizmasi.
 */
export async function promoteQueued() {
  if (await hasActiveScan()) return;
  const next = await prisma.order.findFirst({
    where: { status: 'scan_queued' },
    orderBy: { createdAt: 'asc' },
  });
  if (!next) return;
  // Egress proxy ayakta degilse kuyruktakini de baslatma — sirada bekletmeye
  // devam et (tarama filtresiz cikamaz).
  if (!(await checkEgressProxyHealth())) {
    console.error('[orchestrator][GUARD] Egress proxy sagliksiz — kuyruktaki tarama promote EDILMEDI, bekliyor.');
    return;
  }
  try {
    await startScanForOrder(next.id);
    console.log(`[orchestrator] Kuyruktan tarama baslatildi: siparis ${next.id}`);
  } catch (err) {
    console.error(`[orchestrator] Kuyruktan baslatma hatasi (siparis ${next.id}):`, err);
  }
}
