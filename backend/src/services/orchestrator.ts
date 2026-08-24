import { prisma } from '../db.js';
import { config } from '../config.js';
import { getPackageDef, securityProfileFor, isActivePackage, requiresManualReview, METHOD_GUARD_EN, METHOD_GUARD_TR, NO_SCRIPT_HARD_EN, NO_SCRIPT_HARD_TR } from './scanPackages.js';
import { hasValidActiveTestConsent } from './activeTestConsent.js';
import { isVerificationStillValid } from './verification.js';
import { checkEgressProxyHealth } from './egressHealth.js';
import * as pentagi from '../pentagi/client.js';
import { sendScanStarted } from './mailer.js';
import { isDeterministicPackage } from './report.js';

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
  // ÇELİK KAPI (erken kontrol — İş 3): AKTİF paket + doğrulanmamış domain ise kuyruğa BİLE
  // alma; doğrudan 'awaiting_domain_verification'a al ki müşteri durumu net görsün
  // ("kuyrukta" değil "doğrulama bekliyor"). startScanForOrder'daki kapı yine de nihai
  // garantidir (promote/retry gibi doğrudan yollar için).
  const gate = await prisma.order.findUnique({
    where: { id: orderId },
    include: { domain: true, package: { select: { key: true } } },
  });
  if (gate && isActivePackage(gate.package.key) && !isVerificationStillValid(gate.domain)) {
    await prisma.order.update({ where: { id: orderId }, data: { status: 'awaiting_domain_verification' } });
    console.log(`[steel-gate] AKTİF paket ${gate.package.key} sipariş ${orderId}: domain doğrulanmadı → awaiting_domain_verification (kuyruğa alınmadı).`);
    return { queued: false as const, held: true as const };
  }

  // (S1 OTONOM RED TEAM) Ayrı, izole droplet motoru — 6-paketin PAYLAŞIMLI PentAGI concurrency'si
  // (hasActiveScan) ve CyberTestify egress-proxy sağlığı (assertEgressProxyHealthy) BURADA UYGULANMAZ.
  // Aksi halde başka bir 6-paket taraması aktifken S1 kuyruğa takılır ya da proxy sağlıksızsa S1 haksız
  // yere BAŞARISIZ olurdu (S1 o proxy'i kullanmaz). Doğrudan dispatch'e git.
  if (gate?.package.key === 'redteam_s1') {
    const flow = await startScanForOrder(orderId);
    return { queued: false as const, flow };
  }

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
 * (Tam Kapsamlı Pentest — FAZ A) Ödeme sonrası akış: paket YARI-MANUEL onay istiyorsa siparişi
 * 'awaiting_review'da TUT (flow başlamaz — admin onayı bekler); istemiyorsa normal kuyruğa alır.
 * Ödemenin TÜM yolları (finalizePaidOrder + orders.ts promo/kredi/bundle) bunu çağırır. Admin
 * onayı (approve) doğrudan enqueueOrStartScan çağırır → kapıyı BİLEREK atlar.
 */
export async function enqueueUnlessReview(orderId: string): Promise<void> {
  const o = await prisma.order.findUniqueOrThrow({ where: { id: orderId }, include: { package: { select: { key: true } } } });
  if (requiresManualReview(o.package.key)) {
    await prisma.order.update({ where: { id: orderId }, data: { status: 'awaiting_review' } });
    console.log(`[review] Sipariş ${orderId} (${o.package.key}) yarı-manuel onay bekliyor (awaiting_review).`);
    return;
  }
  await enqueueOrStartScan(orderId);
}

/**
 * (ÇELİK KAPI — resume) Alan adı DNS ile DOĞRULANDIĞINDA çağrılır (domains verify route).
 * O alan adında 'awaiting_domain_verification'da TUTULAN (ödenmiş) aktif siparişleri bulur ve
 * yeniden kuyruğa alır → tarama otomatik başlar (full_pentest ise önce yarı-manuel admin kapısı).
 * Idempotent: eşleşen sipariş yoksa sessizce döner. Doğrulama akışını asla bloklamaz (best-effort).
 */
export async function resumeVerifiedDomainOrders(domainId: string): Promise<void> {
  const held = await prisma.order.findMany({
    where: { domainId, status: 'awaiting_domain_verification' },
    select: { id: true, package: { select: { key: true } } },
  });
  for (const o of held) {
    // Tutulan sipariş ÖDENMİŞTİ (finalizePaidOrder 'paid' yaptıktan sonra kapı tuttu); enqueue
    // yolunun beklediği 'paid' ara durumuna geri al, sonra normal akışa sok.
    await prisma.order.update({ where: { id: o.id }, data: { status: 'paid' } });
    try {
      await enqueueUnlessReview(o.id);
      console.log(`[steel-gate] Domain doğrulandı → aktif sipariş ${o.id} (${o.package.key}) resume edildi.`);
    } catch (e) {
      console.error(`[steel-gate] resume sipariş ${o.id} başarısız:`, e);
    }
  }
}

/**
 * Musteri hicbir asamada PentAGI'ye dogrudan dokunmuyor — sadece bu fonksiyon
 * bizim servis hesabimizla PentAGI'ye baglaniyor. 'paid' veya 'scan_queued'
 * (kuyruktan promote edilen) siparisler icin cagrilabilir.
 */
// (S1) Ödeme sonrası Otonom Red Team dispatch: Order'a 1:1 bağlı RedTeamJob oluştur + runner'ı arka
// planda tetikle. İdempotent (orderId @unique + idempotencyKey). runner import'u DİNAMİK — orchestrator↔
// redteam/runner döngüsel bağımlılığını önler. Aşama 2'de runner tamamlanınca Order awaiting_admin_review'e alınır.
async function dispatchRedTeamS1Order(o: { id: string; customerId: string | null; hostname: string; consentIp: string | null }): Promise<void> {
  const existing = await prisma.redTeamJob.findUnique({ where: { orderId: o.id }, select: { id: true } });
  if (existing) {
    console.log(`[redteam-s1] order ${o.id} için RedTeamJob zaten var (${existing.id}) — tekrar tetiklenmedi (idempotent)`);
    return;
  }
  const now = new Date();
  const job = await prisma.redTeamJob.create({
    data: {
      idempotencyKey: `redteam-order-${o.id}`,
      orderId: o.id,
      customerId: o.customerId,
      domain: o.hostname,
      level: 'S1',
      environment: 'prod', // müşterinin gerçek sitesi (S1 pasif + hafif-aktif; kendi izolasyon/onay guard'ları)
      ownershipConfirmed: true, // Order riza damgalarıyla alındı (ownershipConfirmedAt zorunluydu)
      riskAccepted: true,
      prodElevatedAccepted: false,
      consentIp: o.consentIp,
      status: 'queued',
      startedAt: now,
      log: [{ at: now.toISOString(), phase: 'queued', message: `ödeme sonrası tetiklendi — order ${o.id}, S1/prod` }],
    },
  });
  // Müşteri dashboard'unda "taranıyor" görünsün (customerFacingStatus scan_running'i doğal gösterir).
  await prisma.order.update({ where: { id: o.id }, data: { status: 'scan_running' } });
  const { runJob } = await import('../redteam/runner.js');
  setImmediate(() => {
    runJob(job.id, { dryRun: false }).catch((e) => console.error('[redteam-s1] runJob hata:', (e as Error).message));
  });
  console.log(`[redteam-s1] order ${o.id} → RedTeamJob ${job.id} oluşturuldu + runner tetiklendi (S1/prod, ${o.hostname})`);
}

export async function startScanForOrder(orderId: string) {
  const order = await prisma.order.findUniqueOrThrow({
    where: { id: orderId },
    include: { domain: true, package: true },
  });

  if (order.status !== 'paid' && order.status !== 'scan_queued') {
    throw new Error(`Siparis odenmemis/uygun degil, tarama baslatilamaz: ${order.status}`);
  }

  // (S1 OTONOM RED TEAM) — bu paket PentAGI worker akışını (Flow/createFlow) KULLANMAZ. Ödeme sonrası
  // AYRI RedTeamJob runner'ına (izole droplet + cap 900s/$2.50/30) yönlendirilir. 6-paket çelik-kapısı/
  // ActiveTestConsent/PentAGI-concurrency buraya UYGULANMAZ (isActivePackage=false); S1 kendi onayı
  // (ownershipConfirmed+riskAccepted) + runner guard'larıyla (pin/egress-deny/watchdog D1-D5) korunur.
  // Koşu tamamlanınca runner Order'ı awaiting_admin_review'e alır (Aşama 2 — mevcut onay kapısı).
  if (order.package.key === 'redteam_s1') {
    await dispatchRedTeamS1Order({ id: order.id, customerId: order.customerId, hostname: order.domain.hostname, consentIp: null });
    return null;
  }

  // Concurrency=1 guvencesi: promote sirasinda yaris olmasin diye son bir kontrol.
  if (await hasActiveScan()) {
    await prisma.order.update({ where: { id: orderId }, data: { status: 'scan_queued' } });
    throw new Error('Zaten aktif bir tarama var; siparis kuyruga alindi.');
  }

  // ============================ ÇELİK KAPI (İş 3) ============================
  // AKTİF paketler (SQLi/XSS payload + login prob) alan adı DNS ile DOĞRULANMADAN
  // ASLA çalışmaz — ödeme alınmış olsa BİLE. Bu TEK choke-point tüm yolları kapsar:
  // ödeme, %100-promo, kuyruk-promote, admin-approve, admin-retry (hepsi buradan geçer).
  // Doğrulanmamışsa sipariş 'awaiting_domain_verification'da TUTULUR (scan_failed DEĞİL —
  // müşteri parasını kaybetmez); /verify'da DNS TXT tamamlanınca domains route otomatik
  // resume eder (resumeVerifiedDomainOrders). PASİF paketler doğrulama gerektirmez → atlanır.
  if (isActivePackage(order.package.key) && !isVerificationStillValid(order.domain)) {
    await prisma.order.update({ where: { id: orderId }, data: { status: 'awaiting_domain_verification' } });
    console.log(`[steel-gate] AKTİF paket ${order.package.key} sipariş ${orderId}: domain DOĞRULANMADI → awaiting_domain_verification. Tarama BAŞLATILMADI.`);
    return null;
  }
  // ==========================================================================

  const pkg = getPackageDef(order.package.key);
  const pkgProfile = securityProfileFor(pkg);
  const isActiveProfile = pkgProfile === 'active-light' || pkgProfile === 'active-verify-only';

  // (Faz 3) GUARD (defense-in-depth): active-light/verify-only paket, gecerli bir Aktif Test
  // Yetkilendirme Beyani OLMADAN calistirilamaz. Route'ta da zorunlu; bu ikinci hat
  // atlanamaz olsun diye (or. ileride farkli bir akistan siparis gelirse).
  if (isActiveProfile && !(await hasValidActiveTestConsent(orderId))) {
    await prisma.order.update({ where: { id: orderId }, data: { status: 'scan_failed' } });
    throw new Error('Active-light paket icin gecerli yetkilendirme beyani (ActiveTestConsent) yok; tarama reddedildi.');
  }

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

  // (Tam Kapsamlı Pentest) Kimlik bilgisi ARTIK burada TÜKETİLMEZ. Ajana ASLA gönderilmez (credLine boş).
  // Şifre, RAPOR ÜRETİM anında backend-deterministik login için gerekir: report.ts -> generateAndStoreReport
  // -> authenticateOrder oturumu alırken kimlik bilgisini TÜKETİR + SİLER (tek kullanım). Orchestrator burada
  // tüketirse (eski FAZ A davranışı) rapor üretimi kimlik bilgisini boş bulurdu (canlı bug: no_login_endpoint).
  const credLine = '';

  // (Yontem disiplini) TUM paketlere merkezi olarak eklenir — ajanin script-yazma/
  // debug dongusune sapmasini onler (bkz METHOD_GUARD_* ve scanPackages.ts yorumu).
  const methodLine = '\n\n' + (order.locale === 'en' ? METHOD_GUARD_EN : METHOD_GUARD_TR);
  // (A) SABIT/DAR checklist (pasif) paketlerde KESIN script yasagi — active-light DAHIL DEGIL.
  const noScriptLine =
    pkgProfile === 'passive' ? '\n\n' + (order.locale === 'en' ? NO_SCRIPT_HARD_EN : NO_SCRIPT_HARD_TR) : '';

  // (basit_tarama) "AI Cozum Onerileri" paralı eklentisi POST-SCAN upsell'dir: icerik HER tarama'da
  // uretilir (===FIX_SUGGESTIONS=== sonrasi), AYRI sifrelenip saklanir ve satin alinca render/
  // download'da acilir (bkz report.ts split + reports.ts fixSuggestionsUnlockedAt). Bu yuzden yeni
  // prompt'taki "paid add-on flag" HER ZAMAN PRESENT olarak enjekte edilir → ajan icerigi hep yazar;
  // gercek kilit/satis downstream'de uygulanir. (Scan-aninda satin-alma modeli yok.)
  const fixAddonLine =
    pkg.key === 'basit_tarama'
      ? '\n\nPAID ADD-ON FLAG: PRESENT — the "AI Çözüm Önerileri" content IS included in this generation. Always write the full, concrete remediation content in Turkish after the ===FIX_SUGGESTIONS=== line (it will be encrypted and unlocked on purchase downstream). Do NOT output the "kilitli" placeholder line.'
      : '';

  const prompt =
    pkg.promptTemplate(order.domain.hostname) + credLine + langLine + budgetLine + methodLine + noScriptLine + fixAddonLine;
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

  // (PENTAGI'SIZ) Rapor TAMAMEN backend collector'lariyla uretilen paketler (basit_tarama +
  // bundle_surface ve 5 uyesi ssl_tls/header_leak/dns_email/cors_cookie/csp_analiz) icin PentAGI
  // ajani/sandbox'i GEREKSIZ (tool-call + dakikalarca bosa gidiyordu). Flow KAYDI durum/kuyruk/
  // ilerleme/mail icin DURUR ama PentAGI flow'u ACILMAZ — pentagiFlowId 'deterministic-' sentinel'i
  // alir; worker bunu gorup raporu DOGRUDAN uretir (generateAndStoreReport paket key'ine gore dogru
  // ureticiyi cagirir). Uyum/Kesif paketleri ve verify paketleri DEGISMEZ: normal PentAGI akisi.
  if (isDeterministicPackage(order.package.key)) {
    flow = await prisma.flow.update({ where: { id: flow.id }, data: { pentagiFlowId: `deterministic-${order.id}` } });
  } else {
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
  }

  await prisma.order.update({ where: { id: orderId }, data: { status: 'scan_running' } });

  // (C) Flow GERCEKTEN kuyruktan cikip calismaya basladi (scan_running) — "taramaniz basladi"
  // e-postasi. "Siparis olusturuldu" anina degil, bu gercek event'e baglanir. Mail akisi bozmaz.
  void sendScanStarted(orderId);

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
