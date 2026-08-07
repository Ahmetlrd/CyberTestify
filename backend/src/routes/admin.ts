import { Router } from 'express';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { prisma } from '../db.js';
import { config } from '../config.js';
import { checkEgressProxyHealth } from '../services/egressHealth.js';
import { sendRefundNotice } from '../services/mailer.js';
import { createDraftsFromBulk, listAllAdmin, publishNextDraft } from '../services/blog.js';

const execFileAsync = promisify(execFile);

// Ic yonetim paneli VERI endpoint'leri. Hepsi server.ts'te requireAdmin +
// adminIpAllowlist + rate limit ARKASINDA mount edilir. Bu router auth VARSAYAR.
export const adminRouter = Router();

const ORDER_STATUSES = [
  'awaiting_payment', 'paid', 'scan_queued', 'scan_running', 'scan_completed',
  'scan_failed', 'scope_violation', 'report_delivered', 'report_purged', 'refunded',
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
        customer: { select: { email: true } },
        domain: { select: { hostname: true } },
        package: { select: { displayName: true, key: true } },
        flow: { select: { status: true, toolCallCount: true, scopeViolationTarget: true } },
      },
    }),
  ]);
  res.json({
    page, pageSize, total, statusFilter: status ?? null,
    items: rows.map((o) => ({
      id: o.id, status: o.status, amountMinorUnit: o.amountMinorUnit, currency: o.currency,
      createdAt: o.createdAt, paidAt: o.paidAt,
      customerEmail: o.customer.email, hostname: o.domain.hostname,
      packageName: o.package.displayName, packageKey: o.package.key,
      flowStatus: o.flow?.status ?? null, toolCallCount: o.flow?.toolCallCount ?? null,
      scopeViolationTarget: o.flow?.scopeViolationTarget ?? null,
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

// --- (SEO BLOG) admin-only yonetim -------------------------------------------
// Toplu front-matter yukleme -> draft; liste; "simdi yayinla" (en eski draft). requireAdmin arkasinda.
adminRouter.post('/blog/bulk', async (req, res) => {
  const text = typeof req.body?.text === 'string' ? req.body.text : '';
  if (!text.trim()) return res.status(400).json({ error: 'Boş içerik.' });
  const result = await createDraftsFromBulk(text);
  res.json(result); // { created[], conflicts[], errors[] }
});

adminRouter.get('/blog', async (_req, res) => {
  res.json(await listAllAdmin()); // { posts[], draftCount, publishedCount, lastPublishedAt }
});

adminRouter.post('/blog/publish-next', async (_req, res) => {
  const done = await publishNextDraft();
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
