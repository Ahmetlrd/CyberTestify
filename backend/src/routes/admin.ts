import { Router } from 'express';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { prisma } from '../db.js';
import { config } from '../config.js';
import { checkEgressProxyHealth } from '../services/egressHealth.js';
import { sendRefundNotice, sendReportReady } from '../services/mailer.js';
import { createDraftsFromBulk, listAllAdmin, publishNextDraft, normalizeBlogLang } from '../services/blog.js';
import { enqueueOrStartScan } from '../services/orchestrator.js';
import { hasTestCredential } from '../services/testCredentials.js';
import { decryptReport, decryptSecret } from '../services/crypto.js';
import { renderReportPdf, htmlToPdfBuffer } from '../services/pdf.js';
import { renderRedTeamFullHtml, redteamReportNo } from '../redteam/report.js';
import { storeRedTeamCustomerReport } from '../services/redteamOrderReport.js';
import { PASSIVE_EXTRAS_DELIM } from '../services/passiveExtras.js';
import { LEVEL_CFG } from '../redteam/orchestrator.js';
import { appendLogs } from '../redteam/observability.js';
import { hardkill } from '../redteam/hardkill.js';
import { scriptsDir } from '../redteam/runner.js';
import { redteamKeyPath } from '../redteam/controlChannel.js';
import { logReportAccess } from '../services/reportAudit.js';
import crypto from 'node:crypto';
import { runJob } from '../redteam/runner.js';
import { MODEL_CATALOG, DEFAULT_ROLE_MODELS, PENTAGI_ROLES, estimateRunCost } from '../redteam/models.js';

const execFileAsync = promisify(execFile);

// Ic yonetim paneli VERI endpoint'leri. Hepsi server.ts'te requireAdmin +
// adminIpAllowlist + rate limit ARKASINDA mount edilir. Bu router auth VARSAYAR.
export const adminRouter = Router();

const ORDER_STATUSES = [
  'awaiting_payment', 'awaiting_review', 'paid', 'scan_queued', 'scan_running', 'scan_completed',
  'awaiting_admin_review', 'scan_failed', 'scope_violation', 'report_delivered', 'report_purged', 'refunded',
] as const;

/** ?page & ?pageSize -> {skip, take, page, pageSize} (pageSize 1..100, vars. 25). */
function paginate(q: any): { skip: number; take: number; page: number; pageSize: number } {
  const page = Math.max(1, Number(q.page) || 1);
  const pageSize = Math.min(100, Math.max(1, Number(q.pageSize) || 25));
  return { skip: (page - 1) * pageSize, take: pageSize, page, pageSize };
}

// --- Musteriler ---------------------------------------------------------------
adminRouter.get('/customers', async (req, res) => {
  const { skip, take, page, pageSize } = paginate(req.query);
  const [total, rows] = await Promise.all([
    prisma.customer.count(),
    prisma.customer.findMany({
      skip, take, orderBy: { createdAt: 'desc' },
      select: { id: true, email: true, createdAt: true, _count: { select: { domains: true, orders: true } } },
    }),
  ]);
  res.json({
    page, pageSize, total,
    items: rows.map((c) => ({
      id: c.id, email: c.email, createdAt: c.createdAt,
      domainCount: c._count.domains, orderCount: c._count.orders,
    })),
  });
});

// --- Musteri DETAY (her sey: alan adlari, siparisler, raporlar, planli taramalar, rizalar) ---
adminRouter.get('/customers/:id', async (req, res) => {
  const c = await prisma.customer.findUnique({
    where: { id: req.params.id },
    select: {
      id: true, email: true, fullName: true, createdAt: true, emailVerified: true,
      termsAcceptedAt: true, termsVersion: true, googleId: true,
      domains: {
        orderBy: { createdAt: 'desc' },
        select: {
          id: true, hostname: true, status: true, verificationMethod: true, verifiedAt: true,
          lastCheckedAt: true, createdAt: true, resolvedIps: true, hostingType: true,
        },
      },
      orders: {
        orderBy: { createdAt: 'desc' },
        select: {
          id: true, status: true, amountMinorUnit: true, currency: true, createdAt: true, paidAt: true,
          archived: true, paymentProvider: true, paymentRef: true,
          ownershipConfirmedAt: true,
          package: { select: { key: true, displayName: true } },
          domain: { select: { hostname: true } },
          report: {
            select: {
              id: true, createdAt: true, deliveredAt: true, adminReleasedAt: true,
              incomplete: true, incompleteReason: true,
            },
          },
          flow: {
            select: {
              status: true, toolCallCount: true, pentagiFlowId: true, scopeViolationTarget: true,
              errorMessage: true, startedAt: true, finishedAt: true,
            },
          },
        },
      },
      scheduledScans: {
        orderBy: { createdAt: 'desc' },
        select: {
          id: true, packageKey: true, region: true, intervalDays: true, remainingRuns: true,
          nextRunAt: true, active: true, failCount: true, createdAt: true,
          domain: { select: { hostname: true } },
        },
      },
      activeTestConsents: {
        orderBy: { createdAt: 'desc' },
        select: { id: true, orderId: true, legalName: true, riskAccepted: true, textVersion: true, createdAt: true },
      },
    },
  });
  if (!c) return res.status(404).json({ error: 'Musteri bulunamadi.' });
  const { googleId, ...rest } = c;
  res.json({ ...rest, hasGoogle: !!googleId });
});

// --- Tum alan adlari (global; musteri e-postasi ile) --------------------------
adminRouter.get('/domains', async (req, res) => {
  const { skip, take, page, pageSize } = paginate(req.query);
  const q = typeof req.query.q === 'string' && req.query.q.trim() ? req.query.q.trim() : undefined;
  const where = q ? { hostname: { contains: q, mode: 'insensitive' as const } } : {};
  const [total, rows] = await Promise.all([
    prisma.domain.count({ where }),
    prisma.domain.findMany({
      where, skip, take, orderBy: { createdAt: 'desc' },
      select: {
        id: true, hostname: true, status: true, verifiedAt: true, resolvedIps: true, hostingType: true,
        createdAt: true, customer: { select: { id: true, email: true } }, _count: { select: { orders: true } },
      },
    }),
  ]);
  res.json({
    page, pageSize, total,
    items: rows.map((d) => ({
      id: d.id, hostname: d.hostname, status: d.status, verifiedAt: d.verifiedAt, resolvedIps: d.resolvedIps,
      hostingType: d.hostingType, createdAt: d.createdAt,
      customerId: d.customer.id, customerEmail: d.customer.email, orderCount: d._count.orders,
    })),
  });
});

// --- Siparisler (status filtreli) ---------------------------------------------
adminRouter.get('/orders', async (req, res) => {
  const { skip, take, page, pageSize } = paginate(req.query);
  const status = typeof req.query.status === 'string' && (ORDER_STATUSES as readonly string[]).includes(req.query.status)
    ? (req.query.status as any) : undefined;
  const where = status ? { status } : {};
  const [total, rows] = await Promise.all([
    prisma.order.count({ where }),
    prisma.order.findMany({
      where, skip, take, orderBy: { createdAt: 'desc' },
      select: {
        id: true, status: true, amountMinorUnit: true, currency: true, createdAt: true, paidAt: true,
        region: true,
        failureReason: true, attemptCount: true, refundRequestedAt: true, refundRequestReason: true,
        customer: { select: { email: true } },
        domain: { select: { hostname: true } },
        package: { select: { displayName: true, key: true } },
        flow: { select: { status: true, toolCallCount: true, scopeViolationTarget: true } },
        report: { select: { id: true, adminReleasedAt: true } },
      },
    }),
  ]);
  const refundRequestsPending = await prisma.order.count({ where: { refundRequestedAt: { not: null }, status: { not: 'refunded' } } });
  // (İÇ KALİTE KAPISI) Admin onayı bekleyen rapor sayısı — panelde uyarı rozeti için.
  const reportReviewsPending = await prisma.order.count({ where: { status: 'awaiting_admin_review' } });
  res.json({
    page, pageSize, total, statusFilter: status ?? null, refundRequestsPending, reportReviewsPending,
    items: rows.map((o) => ({
      id: o.id, status: o.status, amountMinorUnit: o.amountMinorUnit, currency: o.currency,
      createdAt: o.createdAt, paidAt: o.paidAt, region: o.region,
      failureReason: o.failureReason, attemptCount: o.attemptCount,
      refundRequestedAt: o.refundRequestedAt, refundRequestReason: o.refundRequestReason,
      customerEmail: o.customer.email, hostname: o.domain.hostname,
      packageName: o.package.displayName, packageKey: o.package.key,
      flowStatus: o.flow?.status ?? null, toolCallCount: o.flow?.toolCallCount ?? null,
      scopeViolationTarget: o.flow?.scopeViolationTarget ?? null,
      hasReport: !!o.report, reportReleasedAt: o.report?.adminReleasedAt ?? null,
    })),
  });
});

// --- Tek siparis detayi -------------------------------------------------------
adminRouter.get('/orders/:id', async (req, res) => {
  const o = await prisma.order.findUniqueOrThrow({
    where: { id: req.params.id },
    select: {
      id: true, status: true, amountMinorUnit: true, currency: true,
      createdAt: true, updatedAt: true, paidAt: true, paymentProvider: true,
      ownershipConfirmedAt: true, distanceContractAcceptedAt: true, withdrawalWaivedAt: true, consentVersion: true,
      customer: { select: { id: true, email: true, createdAt: true } },
      domain: { select: { hostname: true, status: true, resolvedIps: true, hostingType: true } },
      package: { select: { displayName: true, key: true, maxToolCalls: true } },
      flow: { select: { pentagiFlowId: true, status: true, toolCallCount: true, startedAt: true, finishedAt: true, scopeViolationTarget: true, errorMessage: true, rawDataPurgedAt: true } },
      report: { select: { createdAt: true, deliveredAt: true, incomplete: true, incompleteReason: true } },
    },
  });
  res.json(o);
});

// --- (GÖZLEMLENEBİLİRLİK) Tarama adım-adım logu — admin "arkada ne oldu" görsün ---------------
// Kronolojik (seq) sıralı; en fazla 5000 satır. Best-effort yazıldığı için bazı taramalarda boş olabilir.
adminRouter.get('/orders/:id/logs', async (req, res) => {
  const logs = await prisma.scanLog.findMany({
    where: { orderId: req.params.id },
    orderBy: { seq: 'asc' },
    take: 5000,
    select: { seq: true, ts: true, step: true, level: true, method: true, url: true, status: true, durationMs: true, sizeBytes: true, rule: true, severity: true, summary: true },
  });
  const order = await prisma.order.findUnique({ where: { id: req.params.id }, select: { domain: { select: { hostname: true } }, package: { select: { displayName: true, key: true } }, status: true } });
  res.json({ order, count: logs.length, logs });
});

// --- (E) IADE olarak isaretle (admin-only; iyzico iadesi ELLE yapilir) --------
// Iyzico panelinden iadeyi yaptiktan sonra admin bu aksiyonla siparisi 'refunded'
// isaretler + musteriye iade bildirim e-postasi gonderir. requireAdmin arkasindadir.
adminRouter.post('/orders/:id/refund', async (req, res) => {
  const order = await prisma.order.findUnique({ where: { id: req.params.id }, select: { id: true, status: true } });
  if (!order) return res.status(404).json({ error: 'Siparis bulunamadi.' });
  if (order.status === 'refunded') return res.json({ ok: true, alreadyRefunded: true });
  await prisma.order.update({ where: { id: order.id }, data: { status: 'refunded' } });
  const mailed = await sendRefundNotice(order.id); // mailer no-throw
  console.log(`[admin] Siparis ${order.id} 'refunded' isaretlendi (mail=${mailed}).`);
  res.json({ ok: true, mailed });
});

// --- (İÇ KALİTE KAPISI) TARAMA SONRASI RAPOR ONAYI ---------------------------
// Tarama bitip rapor üretilince sipariş 'awaiting_admin_review'da bekler; müşteri "hala
// taranıyor" görür (kod/e-posta gitmez). Admin (Vedat) raporu inceler (AI dahil açık),
// sonra ONAYLAR (müşteriye açılır + kod e-postası gider) veya YENİDEN DENER (baştan tarar).

// (1) Onayla → scan_completed + erişim kodu e-postası (kod pepper'dan çözülür).
adminRouter.post('/orders/:id/approve-report', async (req, res) => {
  const order = await prisma.order.findUnique({
    where: { id: req.params.id },
    select: {
      id: true, status: true,
      customer: { select: { id: true, email: true } },
      report: { select: { id: true, devAccessSecret: true } },
    },
  });
  if (!order) return res.status(404).json({ error: 'Siparis bulunamadi.' });
  if (order.status !== 'awaiting_admin_review') {
    return res.status(409).json({ error: `Siparis rapor-onayi bekleyen durumda degil (mevcut: ${order.status}).` });
  }
  // Erisim kodunu pepper'dan coz — musteriye e-posta ile SIMDI gonderilecek (onaya kadar bekliyordu).
  let accessSecret: string | null = null;
  if (order.report?.devAccessSecret) {
    try { accessSecret = decryptSecret(order.report.devAccessSecret); } catch { accessSecret = null; }
  }
  await prisma.order.update({ where: { id: order.id }, data: { status: 'scan_completed' } });
  await prisma.report.update({ where: { orderId: order.id }, data: { adminReleasedAt: new Date() } });
  // (HESAP VEREBİLİRLİK) Admin erişim kodunu çözüp raporu açtı → audit (secret YAZILMAZ).
  if (order.report?.id) {
    await logReportAccess({
      adminId: req.adminId!, reportId: order.report.id, orderId: order.id,
      customerId: order.customer.id, customerEmail: order.customer.email,
      action: 'approve_release', ip: req.ip ?? null,
    });
  }
  const mailed = accessSecret ? await sendReportReady(order.id, accessSecret) : false;
  console.log(`[admin] Rapor ONAYLANDI + musteriye acildi: ${order.id} (mail=${mailed}).`);
  res.json({ ok: true, released: true, mailed });
});

// (2) Yeniden dene → eski rapor+flow'u sil, siparisi 'paid'e cek, taramayi tekrar kuyruga al.
// (Kimlik-dogrulamali paketlerde tek-kullanimlik kimlik bilgisi silinmis olabilir; o pakette
// yeniden tarama login'de basarisiz olabilir — deterministik/pasif paketler icin sorunsuz.)
adminRouter.post('/orders/:id/retry-scan', async (req, res) => {
  const order = await prisma.order.findUnique({ where: { id: req.params.id }, select: { id: true, status: true } });
  if (!order) return res.status(404).json({ error: 'Siparis bulunamadi.' });
  const retryable = ['awaiting_admin_review', 'scan_completed', 'scan_failed', 'scope_violation'];
  if (!retryable.includes(order.status)) {
    return res.status(409).json({ error: `Bu durumda yeniden taranamaz (mevcut: ${order.status}).` });
  }
  // Eski rapor + flow'u temizle (Report.orderId ve Flow.orderId unique — yeni tarama yeni flow yaratir).
  await prisma.report.deleteMany({ where: { orderId: order.id } });
  await prisma.flow.deleteMany({ where: { orderId: order.id } });
  // (S1) Bağlı RedTeamJob'u da temizle → dispatch idempotent olduğundan, silinmezse yeniden KOŞMAZDI.
  // Silince startScanForOrder S1 dalı taze bir RedTeamJob açıp runner'ı yeniden tetikler.
  await prisma.redTeamJob.deleteMany({ where: { orderId: order.id } });
  await prisma.order.update({ where: { id: order.id }, data: { status: 'paid' } });
  try {
    const r = await enqueueOrStartScan(order.id);
    console.log(`[admin] Rapor YENIDEN DENENDI: ${order.id} (queued=${r.queued}).`);
    res.json({ ok: true, retried: true, queued: r.queued });
  } catch (err: any) {
    console.error(`[admin] retry-scan hata (${order.id}):`, err?.message ?? err);
    res.status(503).json({ error: 'Yeniden tarama baslatilamadi: ' + (err?.message ?? 'bilinmeyen hata') });
  }
});

// (3) Raporu görüntüle → admin ŞİFRELİ raporu (AI Çözüm Önerileri DAHİL, her zaman açık) PDF
// olarak görür. Erişim kodu pepper'dan çözülür; müşteriye HİÇBİR ŞEY sızmaz (yalnız admin).
adminRouter.get('/orders/:id/report.pdf', async (req, res) => {
  const report = await prisma.report.findFirst({
    where: { orderId: req.params.id },
    include: {
      order: {
        include: {
          domain: { select: { hostname: true } },
          package: { select: { displayName: true, key: true } },
          customer: { select: { id: true, email: true } },
        },
      },
    },
  });
  if (!report) return res.status(404).json({ error: 'Rapor bulunamadi.' });
  // Eski (legacy) raporlarda erişim kodu hiç saklanmamış olabilir (yalnız e-posta ile gitmişti) →
  // anahtar geri getirilemez, çözülemez. Yeni raporlarda kod pepper'lı saklanır (worker.ts).
  if (!report.devAccessSecret)
    return res.status(409).json({ error: 'Bu rapor için erişim kodu saklanmamış (eski kayıt); içerik çözülemiyor.' });
  let accessSecret: string;
  try { accessSecret = decryptSecret(report.devAccessSecret); } catch { return res.status(500).json({ error: 'Erisim kodu cozulemedi (pepper?).' }); }

  let plaintext: Buffer;
  try {
    plaintext = decryptReport({
      encryptedBlob: report.encryptedBlob as Buffer, iv: report.iv as Buffer,
      authTag: report.authTag as Buffer, keyDerivationSalt: report.keyDerivationSalt as Buffer, accessSecret,
    });
  } catch { return res.status(500).json({ error: 'Rapor cozulemedi.' }); }

  // (S1) redteam_s1: şifreli blob = RedTeamReport JSON. Admin ÖNİZLEMESİ TAM veriyle (admin modu —
  // maliyet/LLM/süre/artefakt-ID hepsi görünür); 6-paket markdown/fix yolu ATLANIR. Böylece admin,
  // orders onay kuyruğundan S1 raporunu tam görüp onaylayabilir.
  if (report.order.package.key === 'redteam_s1') {
    let rt: any;
    try { rt = JSON.parse(plaintext.toString('utf-8')); } catch { return res.status(500).json({ error: 'Rapor içeriği çözümlenemedi.' }); }
    if (rt?.meta) rt.meta.jobId = rt.meta.jobId ?? report.orderId;
    const reportNo = redteamReportNo(rt?.meta ?? { generatedAt: '', target: report.order.domain.hostname });
    const pdf = await htmlToPdfBuffer(renderRedTeamFullHtml(rt, 'admin'), `CyberTestify · Otonom AI Red Team (ADMIN) · ${reportNo}`);
    await logReportAccess({
      adminId: req.adminId!, reportId: report.id, orderId: report.orderId,
      customerId: report.order.customer.id, customerEmail: report.order.customer.email,
      action: 'view_pdf', ip: req.ip ?? null,
    });
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `inline; filename="redteam-admin-${reportNo}.pdf"`);
    res.setHeader('Cache-Control', 'no-store');
    return res.send(pdf);
  }

  // AI Çözüm Önerileri — admin İNCELEMESİ için HER ZAMAN açık (kampanya/kilit durumundan bağımsız).
  let fixMarkdown: string | null = null;
  if (report.fixSuggestions && report.fixSuggestionsIv && report.fixSuggestionsAuthTag && report.fixSuggestionsSalt) {
    try {
      fixMarkdown = decryptReport({
        encryptedBlob: report.fixSuggestions as Buffer, iv: report.fixSuggestionsIv as Buffer,
        authTag: report.fixSuggestionsAuthTag as Buffer, keyDerivationSalt: report.fixSuggestionsSalt as Buffer, accessSecret,
      }).toString('utf-8');
    } catch { fixMarkdown = null; }
  }

  const fullText = plaintext.toString('utf-8');
  const di = fullText.indexOf(PASSIVE_EXTRAS_DELIM);
  const reportMd = di === -1 ? fullText : fullText.slice(0, di).trim();
  const extrasMarkdown = di === -1 ? null : fullText.slice(di + PASSIVE_EXTRAS_DELIM.length).trim();
  const locale: 'tr' | 'en' = report.order.locale === 'en' ? 'en' : 'tr';

  const pdf = await renderReportPdf(
    reportMd,
    {
      hostname: report.order.domain.hostname, packageName: report.order.package.displayName,
      packageKey: report.order.package.key, createdAt: report.createdAt, locale,
    },
    { fixMarkdown, extrasMarkdown },
  );
  // (HESAP VEREBİLİRLİK) Admin rapor-içeriğine erişti → DEĞİŞTİRİLEMEZ audit (secret YAZILMAZ).
  await logReportAccess({
    adminId: req.adminId!, reportId: report.id, orderId: report.orderId,
    customerId: report.order.customer.id, customerEmail: report.order.customer.email,
    action: 'view_pdf', ip: req.ip ?? null,
  });

  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `inline; filename="admin-onceizleme-${report.orderId}.pdf"`);
  res.setHeader('Cache-Control', 'no-store');
  res.send(pdf);
});

// --- (Tam Kapsamlı Pentest — FAZ A) YARI-MANUEL ONAY KAPISI -------------------
// Kimlik-doğrulamalı/otonom paketler ödendikten sonra 'awaiting_review'da bekler. Bu uçlar
// SADECE bizim (admin) kullanımımız içindir (requireAdmin + IP allowlist arkasında). ŞİFRE
// HİÇBİR ZAMAN gösterilmez — yalnız "kimlik bilgisi sağlandı mı" (varlık) bilgisi.
adminRouter.get('/reviews', async (_req, res) => {
  const orders = await prisma.order.findMany({
    where: { status: 'awaiting_review' },
    orderBy: { paidAt: 'asc' },
    include: {
      customer: { select: { email: true } },
      domain: { select: { hostname: true } },
      package: { select: { key: true, displayName: true } },
      activeTestConsent: {
        select: { credentialSharingAcceptedAt: true, testAccountDeclaredAt: true, elevatedRiskAcceptedAt: true, textVersion: true },
      },
    },
  });
  const items = await Promise.all(orders.map(async (o) => ({
    orderId: o.id,
    hostname: o.domain.hostname,
    packageKey: o.package.key,
    packageName: o.package.displayName,
    customerEmail: o.customer.email,
    paidAt: o.paidAt,
    amountMinorUnit: o.amountMinorUnit,
    currency: o.currency,
    // ŞİFRE GÖSTERİLMEZ — yalnız varlık.
    credentialProvided: await hasTestCredential(o.id, 'primary'),
    consents: {
      credentialSharing: !!o.activeTestConsent?.credentialSharingAcceptedAt,
      testAccountDeclared: !!o.activeTestConsent?.testAccountDeclaredAt,
      elevatedRisk: !!o.activeTestConsent?.elevatedRiskAcceptedAt,
      version: o.activeTestConsent?.textVersion ?? null,
    },
  })));
  res.json({ total: items.length, items });
});

// Onayla: kapıyı BİLEREK atlayıp taramayı başlat (concurrency=1; bkz orchestrator).
adminRouter.post('/reviews/:id/approve', async (req, res) => {
  const order = await prisma.order.findUnique({ where: { id: req.params.id }, select: { id: true, status: true } });
  if (!order) return res.status(404).json({ error: 'Siparis bulunamadi.' });
  if (order.status !== 'awaiting_review') {
    return res.status(409).json({ error: `Siparis 'awaiting_review' degil (mevcut: ${order.status}).` });
  }
  // Gate bypass: doğrudan enqueueOrStartScan (enqueueUnlessReview DEĞİL — onay verildi).
  await prisma.order.update({ where: { id: order.id }, data: { status: 'paid' } });
  await enqueueOrStartScan(order.id);
  console.log(`[review] Sipariş ${order.id} ONAYLANDI → tarama kuyruğa alındı/başlatıldı.`);
  res.json({ ok: true, approved: true });
});

// Reddet: taramayı başlatma (FAZ B: kredi/iade süreci). Şimdilik 'scan_failed' + sebep.
adminRouter.post('/reviews/:id/reject', async (req, res) => {
  const order = await prisma.order.findUnique({ where: { id: req.params.id }, select: { id: true, status: true } });
  if (!order) return res.status(404).json({ error: 'Siparis bulunamadi.' });
  if (order.status !== 'awaiting_review') {
    return res.status(409).json({ error: `Siparis 'awaiting_review' degil (mevcut: ${order.status}).` });
  }
  const reason = typeof req.body?.reason === 'string' ? req.body.reason.slice(0, 300) : 'inceleme reddedildi';
  await prisma.order.update({ where: { id: order.id }, data: { status: 'scan_failed' } });
  // Kimlik bilgisi kalıntısı kalmasın: reddedince de hemen temizlenmeli (purge cron ayrıca yakalar).
  await prisma.testCredential.updateMany({ where: { orderId: order.id, ciphertext: { not: null } }, data: { ciphertext: null, purgedAt: new Date() } });
  console.log(`[review] Sipariş ${order.id} REDDEDİLDİ (${reason}). Kredi/iade FAZ B'de. Kimlik bilgisi temizlendi.`);
  res.json({ ok: true, rejected: true, reason });
});

// --- (Fatura talebi — MANUEL) Vedat fatura bilgilerini + fiyatı görür, durumu işaretler --------
// Sistem OTOMATİK e-fatura KESMEZ; Vedat kendi e-fatura aracıyla ELLE keser/gönderir, burada takip eder.
adminRouter.get('/invoice-requests', async (req, res) => {
  const status = typeof req.query.status === 'string' && ['requested', 'issued', 'sent'].includes(req.query.status)
    ? (req.query.status as 'requested' | 'issued' | 'sent')
    : undefined;
  const rows = await prisma.invoiceRequest.findMany({
    where: status ? { status } : undefined,
    orderBy: { requestedAt: 'desc' },
    include: {
      order: {
        select: {
          id: true, amountMinorUnit: true, currency: true, paidAt: true,
          customer: { select: { email: true } },
          package: { select: { displayName: true } },
          domain: { select: { hostname: true } },
        },
      },
    },
  });
  const items = rows.map((r) => ({
    id: r.id,
    orderId: r.orderId,
    packageName: r.order.package.displayName,
    hostname: r.order.domain.hostname,
    amountMinorUnit: r.order.amountMinorUnit,
    currency: r.order.currency,
    customerEmail: r.order.customer.email,
    type: r.type,
    companyName: r.companyName, taxOffice: r.taxOffice, taxNumber: r.taxNumber,
    fullName: r.fullName, nationalId: r.nationalId,
    address: r.address, invoiceEmail: r.invoiceEmail,
    status: r.status, notes: r.notes,
    requestedAt: r.requestedAt, issuedAt: r.issuedAt, sentAt: r.sentAt,
  }));
  const pendingCount = await prisma.invoiceRequest.count({ where: { status: 'requested' } });
  res.json({ total: items.length, pendingCount, items });
});

// Durum güncelle: 'issued' (kesildi) / 'sent' (gönderildi) + opsiyonel not. Zaman damgalarını basar.
adminRouter.patch('/invoice-requests/:id', async (req, res) => {
  const status = req.body?.status;
  if (status && !['requested', 'issued', 'sent'].includes(status)) {
    return res.status(400).json({ error: 'Geçersiz durum.' });
  }
  const existing = await prisma.invoiceRequest.findUnique({ where: { id: req.params.id } });
  if (!existing) return res.status(404).json({ error: 'Fatura talebi bulunamadı.' });
  const data: Record<string, unknown> = {};
  if (typeof req.body?.notes === 'string') data.notes = req.body.notes.slice(0, 1000);
  if (status) {
    data.status = status;
    if (status === 'issued' && !existing.issuedAt) data.issuedAt = new Date();
    if (status === 'sent') { data.sentAt = new Date(); if (!existing.issuedAt) data.issuedAt = new Date(); }
  }
  const updated = await prisma.invoiceRequest.update({ where: { id: req.params.id }, data });
  res.json({ ok: true, status: updated.status });
});

// --- (SEO BLOG) admin-only yonetim -------------------------------------------
// Toplu front-matter yukleme -> draft; liste; "simdi yayinla" (en eski draft). requireAdmin arkasinda.
adminRouter.post('/blog/bulk', async (req, res) => {
  const text = typeof req.body?.text === 'string' ? req.body.text : '';
  if (!text.trim()) return res.status(400).json({ error: 'Boş içerik.' });
  const lang = normalizeBlogLang(req.body?.lang); // hangi dile/bölgeye (tr|de) — varsayılan tr
  const result = await createDraftsFromBulk(text, lang);
  res.json({ ...result, lang }); // { created[], conflicts[], errors[], lang }
});

adminRouter.get('/blog', async (req, res) => {
  // ?lang=tr|de ile filtre; yoksa TÜM diller (admin hepsini görür, satırda lang etiketi olur).
  const lang = typeof req.query.lang === 'string' ? normalizeBlogLang(req.query.lang) : undefined;
  res.json(await listAllAdmin(lang)); // { posts[], draftCount, publishedCount, lastPublishedAt }
});

adminRouter.post('/blog/publish-next', async (req, res) => {
  const lang = typeof req.body?.lang === 'string' ? normalizeBlogLang(req.body.lang) : undefined;
  const done = await publishNextDraft(lang);
  if (!done) return res.json({ ok: true, published: null, message: 'Sırada yayınlanacak taslak yok.' });
  console.log(`[admin][blog] elle yayinlandi: ${done.slug}`);
  res.json({ ok: true, published: done });
});

// --- Kapsam ihlali audit log'u ------------------------------------------------
adminRouter.get('/scope-violations', async (req, res) => {
  const { skip, take, page, pageSize } = paginate(req.query);
  const where = { scopeViolationTarget: { not: null } };
  const [total, rows] = await Promise.all([
    prisma.flow.count({ where }),
    prisma.flow.findMany({
      where, skip, take, orderBy: { startedAt: 'desc' },
      select: {
        pentagiFlowId: true, status: true, startedAt: true, finishedAt: true, scopeViolationTarget: true,
        order: { select: { id: true, status: true, customer: { select: { email: true } }, domain: { select: { hostname: true } } } },
      },
    }),
  ]);
  res.json({
    page, pageSize, total,
    items: rows.map((f) => ({
      flowId: f.pentagiFlowId, flowStatus: f.status, startedAt: f.startedAt, finishedAt: f.finishedAt,
      target: f.scopeViolationTarget, orderId: f.order.id, orderStatus: f.order.status,
      customerEmail: f.order.customer.email, hostname: f.order.domain.hostname,
    })),
  });
});

// --- Sistem sagligi -----------------------------------------------------------
async function pentagiHealthy(timeoutMs = 2500): Promise<boolean> {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    const r = await fetch(config.pentagi.graphqlUrl, {
      method: 'POST', signal: ctrl.signal,
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${config.pentagi.serviceToken}` },
      body: JSON.stringify({ query: '{ __typename }' }),
    });
    clearTimeout(t);
    return r.ok;
  } catch {
    return false;
  }
}

async function diskUsage(): Promise<{ usedPct: number | null; raw: string }> {
  try {
    const { stdout } = await execFileAsync('df', ['-P', '/']);
    const line = stdout.trim().split('\n').pop() ?? '';
    const pctMatch = line.match(/(\d+)%/);
    return { usedPct: pctMatch ? Number(pctMatch[1]) : null, raw: line.replace(/\s+/g, ' ') };
  } catch {
    return { usedPct: null, raw: 'df calistirilamadi' };
  }
}

adminRouter.get('/system-health', async (_req, res) => {
  const [egress, pentagi, activeScans, queuedOrders, disk, newCustomers24h] = await Promise.all([
    checkEgressProxyHealth(),
    pentagiHealthy(),
    prisma.flow.count({ where: { status: 'running' } }),
    prisma.order.count({ where: { status: 'scan_queued' } }),
    diskUsage(),
    prisma.customer.count({ where: { createdAt: { gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } } }),
  ]);
  res.json({
    egressProxyHealthy: egress,
    pentagiHealthy: pentagi,
    activeScans,          // concurrency durumu (1 = normal, 0 = bosta)
    queuedOrders,         // kuyrukta bekleyen
    diskUsedPct: disk.usedPct,
    diskRaw: disk.raw,
    newCustomers24h,
    scopeEnforcement: config.scopeEnforcement,
    checkedAt: new Date().toISOString(),
  });
});

// --- Otonom Red Team işleri — CANLI GÖZLEM (yalnız admin; beta-müşteri GÖRMEZ) ------------------
// Veri, orchestrator'ın SSH kontrol-kanalından PULL edip yazdığı RedTeamJob/RedTeamJobLog'dan gelir.
// Droplet CyberTestify'a HİÇ bağlanmaz (PUSH yok). reportJson/log secret İÇERMEZ (puller maskeler).
adminRouter.get('/redteam-jobs', async (req, res) => {
  const { skip, take, page, pageSize } = paginate(req.query);
  const [total, rows] = await Promise.all([
    prisma.redTeamJob.count(),
    prisma.redTeamJob.findMany({
      skip, take, orderBy: { createdAt: 'desc' },
      select: {
        id: true, domain: true, level: true, environment: true, status: true, phase: true,
        createdAt: true, startedAt: true, finishedAt: true, costUsd: true, llmCalls: true,
        egressTargetOk: true, egressCyberBlocked: true, lastPulledAt: true,
      },
    }),
  ]);
  res.json({ page, pageSize, total, items: rows });
});

adminRouter.get('/redteam-jobs/:id', async (req, res) => {
  const job = await prisma.redTeamJob.findUnique({
    where: { id: req.params.id },
    select: {
      id: true, domain: true, level: true, environment: true, status: true, phase: true,
      createdAt: true, startedAt: true, finishedAt: true, ownershipConfirmed: true, riskAccepted: true,
      prodElevatedAccepted: true, consentIp: true, dropletId: true, dropletIp: true, targetIp: true,
      llmCalls: true, costUsd: true, elapsedSec: true, egressTargetOk: true, egressCyberBlocked: true,
      lastPulledAt: true, reportJson: true, error: true, modelUsage: true,
      transcriptJson: true, binderTraceJson: true,
    },
  });
  if (!job) return res.status(404).json({ error: 'İş bulunamadı.' });
  const cap = LEVEL_CFG[job.level as 'S1' | 'S2' | 'S3'] ?? null; // cap metresi için tavanlar
  res.json({ ...job, cap });
});

// Canlı log akışı (polling): ?after=<seq> ile artımlı çek.
adminRouter.get('/redteam-jobs/:id/logs', async (req, res) => {
  const after = Math.max(0, Number(req.query.after) || 0);
  const logs = await prisma.redTeamJobLog.findMany({
    where: { jobId: req.params.id, seq: { gt: after } },
    orderBy: { seq: 'asc' }, take: 500,
    select: { seq: true, at: true, source: true, phase: true, level: true, message: true },
  });
  res.json({ logs });
});

// KILL-SWITCH (D1-D3 düzeltme) — ORCHESTRATOR'ın kendi (tıkanabilir) sürecine BAĞIMLI DEĞİL.
// KÖK NEDEN (elle test edilip başarısız bulundu): eski uygulama yalnız SSH ile kill-switch.sh
// çalıştırıyordu — SSH'ın kendisi 900s timeout'luydu (asılabilirdi) VE script'in konteyner-etiket
// süzgeci muhtemelen HİÇBİR konteynerle eşleşmiyordu (PentAGI'nin kendi compose'u bu etiketi
// koymuyor) — yani "ok" dönse bile GERÇEKTE hiçbir şey durmuyordu; DO API'ye HİÇ gidilmiyordu.
// ARTIK: hardkill.ts (watchdog'un da kullandığı AYNI, test edilmiş çekirdek) — DOĞRUDAN DO API ile
// droplet imha eder (SSH'a bağımlı değil), imha ÖNCESİ best-effort rapor yakalar, imha SONRASI DO
// API'den GERÇEKTEN gittiğini doğrular. Hata SESSİZCE YUTULMAZ — gerçek sebep UI'a döner.
adminRouter.post('/redteam-jobs/:id/kill', async (req, res) => {
  const job = await prisma.redTeamJob.findUnique({
    where: { id: req.params.id },
    select: { id: true, dropletIp: true, dropletId: true, targetIp: true, domain: true, level: true, environment: true, status: true, orderId: true },
  });
  if (!job) return res.status(404).json({ error: 'İş bulunamadı.' });
  if (!job.dropletIp && !job.dropletId) return res.status(400).json({ error: 'Droplet IP/ID yok (aktif/canlı iş değil) — durduracak bir şey yok.' });

  const result = await hardkill({
    dropletIp: job.dropletIp, dropletId: job.dropletId, scriptsDir: scriptsDir(), keyPath: redteamKeyPath(),
    target: job.domain, targetIp: job.targetIp ?? '', level: job.level as 'S1' | 'S2' | 'S3', environment: job.environment as 'test' | 'staging' | 'prod',
    reason: 'admin panelden elle KILL-SWITCH',
  });

  await prisma.redTeamJob.update({
    where: { id: job.id },
    data: {
      status: 'aborted', phase: 'teardown', finishedAt: new Date(),
      error: `admin kill-switch${result.destroyError ? ` — İMHA HATASI: ${result.destroyError}` : ''}`,
      ...(result.liveCost != null ? { costUsd: result.liveCost } : {}),
      ...(result.report ? { reportJson: result.report as any } : {}),
      ...(result.rawFlow ? { rawFlowJson: result.rawFlow as any } : {}),
      ...(result.transcript ? { transcriptJson: result.transcript as any } : {}),
    },
  });
  await appendLogs(job.id, [{
    source: 'killswitch', level: result.destroyError ? 'error' : 'warn',
    message: `admin KILL-SWITCH: imha ${result.destroyRequested ? (result.destroyError ? `İSTENDİ ama HATA — ${result.destroyError}` : 'İSTENDİ ✓') : 'İSTENEMEDİ'} · doğrulama=${result.verified} · rapor ${result.report ? `üretildi (kanıtlı ${result.report.counts.kanitli}/belirsiz ${result.report.counts.belirsiz})` : 'üretilemedi'}`,
  }]);

  // (S1) Kill'lenen job bir ödemeli Order'a bağlıysa order'ı DETERMİNİSTİK yönet (kill akışı SAHİPLENİR;
  // runner geç-tamamlanma artık aborted job'da order'a dokunmuyor). Kısmi rapor varsa müşteri onay
  // kuyruğuna (awaiting_admin_review); yoksa scan_failed (koşu durduruldu, teslim edilecek bir şey yok).
  if (job.orderId) {
    try {
      if (result.report) {
        await storeRedTeamCustomerReport(job.orderId, result.report, { incomplete: true, incompleteReason: 'Koşu durduruldu (kill-switch); rapor o ana kadarki ham kanıttan üretildi.' });
      } else {
        await prisma.order.updateMany({
          where: { id: job.orderId, status: { notIn: ['scan_completed', 'awaiting_admin_review'] } },
          data: { status: 'scan_failed', failureReason: 'Tarama durduruldu (kill-switch) — rapor üretilemedi.' },
        });
      }
    } catch (e) { console.error('[redteam-s1] kill→order işaretleme hatası:', (e as Error).message); }
  }

  // D2/D3: sahte-başarı YOK — gerçek durum + doğrulanmış/doğrulanamamış ayrımı dönülür.
  res.json({
    ok: result.destroyRequested && !result.destroyError,
    verified: result.verified, // 'destroyed' | 'unverified' | 'skipped'
    error: result.destroyError,
    reportGenerated: !!result.report,
  });
});

// --- Rapor erişim AUDIT (hesap verebilirlik; değiştirilemez append-only kayıtlar) --------------
// Her admin rapor-erişimini gösterir: admin id + zaman + rapor + müşteri + eylem. Secret İÇERMEZ.
adminRouter.get('/report-access-logs', async (req, res) => {
  const { skip, take, page, pageSize } = paginate(req.query);
  const reportId = typeof req.query.reportId === 'string' ? req.query.reportId : undefined;
  const customerId = typeof req.query.customerId === 'string' ? req.query.customerId : undefined;
  const where = { ...(reportId ? { reportId } : {}), ...(customerId ? { customerId } : {}) };
  const [total, rows] = await Promise.all([
    prisma.reportAccessLog.count({ where }),
    prisma.reportAccessLog.findMany({
      where, skip, take, orderBy: { at: 'desc' },
      select: { id: true, at: true, adminId: true, reportId: true, orderId: true, customerId: true, customerEmail: true, action: true, ip: true },
    }),
  ]);
  res.json({ page, pageSize, total, items: rows });
});

// --- Otonom Red Team: MODEL YÖNETİMİ + MALİYET + CANLI TETİK (yalnız admin) ---------------------
const RT_LEVELS = ['S1', 'S2', 'S3'] as const;

// Model kataloğu + fiyatlar + rol varsayılanları + seviye cap'leri (panel için).
adminRouter.get('/redteam/model-catalog', (_req, res) => {
  res.json({ catalog: MODEL_CATALOG, roles: PENTAGI_ROLES, defaults: DEFAULT_ROLE_MODELS, levels: LEVEL_CFG });
});

// Koşu-öncesi maliyet TAHMİNİ (seviye + model config + cap).
adminRouter.post('/redteam/estimate', (req, res) => {
  const b = req.body ?? {};
  const level = (RT_LEVELS as readonly string[]).includes(b.level) ? (b.level as 'S1' | 'S2' | 'S3') : 'S1';
  const calls = Number.isFinite(+b.capCallsOverride) && +b.capCallsOverride > 0 ? +b.capCallsOverride : LEVEL_CFG[level].capCalls;
  res.json(estimateRunCost(calls, b.modelConfig ?? null));
});

// CANLI KOŞU TETİK — admin (Vedat) kendi hedefi + seviye seçip başlatır. Ownership OTOMATİK (admin +
// kendi hedef); yine de audit'e (job log) yazılır. Runner arka planda çalışır (istek beklemez).
adminRouter.post('/redteam-jobs', async (req, res) => {
  const b = req.body ?? {};
  if (typeof b.domain !== 'string' || b.domain.trim().length < 3) return res.status(400).json({ error: 'Geçerli bir hedef girin.' });
  if (!(RT_LEVELS as readonly string[]).includes(b.level)) return res.status(400).json({ error: 'Seviye S1/S2/S3 olmalı.' });
  const host = b.domain.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
  const level = b.level as 'S1' | 'S2' | 'S3';
  const now = new Date();
  const num = (v: any) => (Number.isFinite(+v) && +v > 0 ? +v : null);
  const capCallsOverride = num(b.capCallsOverride);
  const est = estimateRunCost(capCallsOverride ?? LEVEL_CFG[level].capCalls, b.modelConfig ?? null);
  const idempotencyKey = crypto.createHash('sha256').update(['admin', host, level, now.toISOString()].join('|')).digest('hex');

  const job = await prisma.redTeamJob.create({
    data: {
      idempotencyKey, domain: host, level, environment: 'test',
      ownershipConfirmed: true, riskAccepted: true, prodElevatedAccepted: false,
      consentIp: req.ip ?? null, status: 'queued', startedAt: now,
      modelConfig: b.modelConfig ?? undefined,
      capCallsOverride, capSecOverride: num(b.capSecOverride), capCostOverride: num(b.capCostOverride),
      estCostUsd: est.estUsd,
      log: [{ at: now.toISOString(), phase: 'queued', message: `admin(${req.adminId}) başlattı — kendi hedefi, seviye ${level}, tahmini $${est.estUsd}${est.hasOpus ? ' (OPUS!)' : ''}` }],
    },
  });
  // Arka planda çalıştır (isteği bekletme). dryRun=true → maliyet YAKMADAN zinciri doğrular.
  const dryRun = b.dryRun === true;
  setImmediate(() => { runJob(job.id, { dryRun }).catch((e) => console.error('[redteam] runJob hata:', (e as Error).message)); });
  res.json({ ok: true, jobId: job.id, dryRun, estimate: est });
});

// Koşu-öncesi model/cap düzenleme (yalnız 'queued' işte).
adminRouter.patch('/redteam-jobs/:id', async (req, res) => {
  const job = await prisma.redTeamJob.findUnique({ where: { id: req.params.id }, select: { status: true, level: true } });
  if (!job) return res.status(404).json({ error: 'İş bulunamadı.' });
  if (job.status !== 'queued') return res.status(409).json({ error: 'Yalnız kuyruktaki (başlamamış) iş düzenlenebilir.' });
  const b = req.body ?? {};
  const num = (v: any) => (Number.isFinite(+v) && +v > 0 ? +v : null);
  const capCallsOverride = num(b.capCallsOverride);
  const est = estimateRunCost(capCallsOverride ?? LEVEL_CFG[job.level as 'S1' | 'S2' | 'S3'].capCalls, b.modelConfig ?? null);
  await prisma.redTeamJob.update({
    where: { id: req.params.id },
    data: {
      ...(b.modelConfig !== undefined ? { modelConfig: b.modelConfig } : {}),
      capCallsOverride, capSecOverride: num(b.capSecOverride), capCostOverride: num(b.capCostOverride),
      estCostUsd: est.estUsd,
    },
  });
  res.json({ ok: true, estimate: est });
});

// --- Otonom Red Team: TAM RAPOR (okunur HTML + indirilebilir PDF; geriye-dönük) -----------------
// (P0-B) mode: admin panel VARSAYILAN 'admin' (tüm iç veri korunur — kriter 4); ?view=customer ile
// müşteriye gidecek SADELEŞTİRİLMİŞ belge önizlenir/indirilir. jobId meta'ya enjekte → Rapor No stabil.
adminRouter.get('/redteam-jobs/:id/report.html', async (req, res) => {
  const job = await prisma.redTeamJob.findUnique({ where: { id: req.params.id }, select: { reportJson: true } });
  if (!job?.reportJson) return res.status(404).json({ error: 'Bu koşu için rapor yok (koşu tamamlanmamış olabilir).' });
  const mode = req.query.view === 'customer' ? 'customer' : 'admin';
  const report = job.reportJson as any;
  if (report?.meta) report.meta.jobId = req.params.id;
  res.type('html').send(renderRedTeamFullHtml(report, mode));
});

adminRouter.get('/redteam-jobs/:id/report.pdf', async (req, res) => {
  const job = await prisma.redTeamJob.findUnique({ where: { id: req.params.id }, select: { reportJson: true, domain: true } });
  if (!job?.reportJson) return res.status(404).json({ error: 'Bu koşu için rapor yok.' });
  const mode = req.query.view === 'customer' ? 'customer' : 'admin';
  const report = job.reportJson as any;
  if (report?.meta) report.meta.jobId = req.params.id;
  const reportNo = redteamReportNo({ ...report.meta, jobId: req.params.id });
  const footer = `CyberTestify · Otonom AI Red Team (deneysel) · ${reportNo}`;
  const pdf = await htmlToPdfBuffer(renderRedTeamFullHtml(report, mode), footer);
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `inline; filename="redteam-${(job.domain || 'hedef').replace(/[^a-z0-9.-]/gi, '_')}-${reportNo}.pdf"`);
  res.setHeader('Cache-Control', 'no-store');
  res.send(pdf);
});
