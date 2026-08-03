import { Router } from 'express';
import { z } from 'zod';
import { prisma } from '../db.js';
import { config } from '../config.js';
import { getPackageDef, securityProfileFor } from '../services/scanPackages.js';
import { isVerificationStillValid } from '../services/verification.js';
import { requireAuth } from '../middleware/auth.js';

export const schedulesRouter = Router();

const createSchema = z.object({
  domainId: z.string().uuid(),
  packageKey: z.enum([
    'basit_tarama',
    'ssl_tls',
    'header_leak',
    'dns_email',
    'cms_cve',
    'pci_hazirlik',
    'kvkk_hazirlik',
    'iso27001_hazirlik',
    'cors_cookie',
    'csp_analiz',
    'subdomain_takeover',
    'api_discovery',
    'injection_verify',
    'idor_verify',
    'ssrf_verify',
    'file_upload_verify',
    'business_logic_verify',
    'race_massassign_verify',
    'rce_verify',
    'authenticated_scan',
    'autonomous_pentest',
  ]),
  intervalDays: z.number().int(),
  runs: z.number().int().min(1).max(52), // pesin odenen tekrar sayisi (N)
  startAt: z.string().datetime().optional(), // ISO; ilk taramanin ILERI tarihi (yoksa hemen)
  region: z.enum(['tr', 'us', 'ae']).optional().default('tr'),
});

// Musterinin zamanlanmis taramalari.
schedulesRouter.get('/', requireAuth, async (req, res) => {
  const rows = await prisma.scheduledScan.findMany({
    where: { customerId: req.customerId! },
    orderBy: { createdAt: 'desc' },
    include: { domain: { select: { hostname: true } } },
  });
  res.json(
    rows.map((s) => ({
      id: s.id,
      hostname: s.domain.hostname,
      packageKey: s.packageKey,
      intervalDays: s.intervalDays,
      remainingRuns: s.remainingRuns,
      nextRunAt: s.nextRunAt,
      active: s.active,
    })),
  );
});

schedulesRouter.post('/', requireAuth, async (req, res) => {
  const parsed = createSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
  const { domainId, packageKey, intervalDays, runs, startAt, region } = parsed.data;

  // IS KURALI: haftaliktan sik tekrar YOK (maliyet + egress/concurrency yuku).
  // Tek seferlik (runs===1) taramada TEKRAR olmadigi icin aralik kurali gecersiz —
  // bu durumda intervalDays yalnizca ileri-tarihli tek atisi ifade eder.
  if (runs > 1 && intervalDays < config.minScheduleIntervalDays) {
    return res.status(400).json({ error: `Tarama araligi en az ${config.minScheduleIntervalDays} gun olmalidir.` });
  }

  // Ileri tarihli baslatma: verilirse GELECEKTE olmali. Yoksa hemen (bir sonraki tick).
  let nextRunAt = new Date();
  if (startAt) {
    const t = new Date(startAt);
    if (Number.isNaN(t.getTime()) || t.getTime() <= Date.now()) {
      return res.status(400).json({ error: 'Baslangic tarihi gelecekte bir zaman olmalidir.' });
    }
    nextRunAt = t;
  }

  const packageDef = getPackageDef(packageKey);
  if (packageDef.networkLayer && !config.hardenedNetworkIsolation) {
    return res.status(409).json({ error: 'Bu paket tipi su an devre disi (bkz HANDOFF.md).' });
  }
  if (packageDef.available === false) {
    return res.status(409).json({ error: 'Bu paket su an satista degil.' });
  }
  // (Faz 3) active-light paketler HER tarama icin ayri yetkilendirme beyani gerektirir;
  // zamanlanmis (tekrarlayan) taramaya UYGUN DEGIL.
  if (securityProfileFor(packageDef) === 'active-light') {
    return res.status(409).json({ error: 'Aktif-test paketleri zamanlanamaz; her tarama için ayrı yetkilendirme beyanı gerekir.' });
  }

  const domain = await prisma.domain.findFirstOrThrow({ where: { id: domainId, customerId: req.customerId! } });
  if (!isVerificationStillValid(domain)) {
    return res.status(403).json({ error: 'Domain dogrulanmamis veya suresi dolmus. Once dogrulayin.' });
  }

  // GUVENCE: sistem genelinde aktif zamanlanmis tarama ust siniri.
  const activeCount = await prisma.scheduledScan.count({ where: { active: true } });
  if (activeCount >= config.maxActiveScheduledScans) {
    return res.status(503).json({
      error: 'Sistem su an azami zamanlanmis tarama kapasitesinde. Lutfen daha sonra tekrar deneyin.',
    });
  }

  const schedule = await prisma.scheduledScan.create({
    data: {
      customerId: req.customerId!,
      domainId,
      packageKey,
      region,
      intervalDays,
      remainingRuns: runs,
      // Ilk tarama: startAt verildiyse o tarihte, yoksa hemen (bir sonraki tick).
      // Sonraki tekrarlar intervalDays sonra (runDueSchedules ilerletir).
      nextRunAt,
      active: true,
    },
  });

  // NOT: Pesin (prepaid) N-tarama modeli. Gercek otomatik tekrarlayan odeme
  // (recurring billing) henuz YOK — bkz HANDOFF.md. Sandbox'ta ucret alinmaz.
  res.json({ id: schedule.id, remainingRuns: schedule.remainingRuns, intervalDays, nextRunAt: schedule.nextRunAt });
});

// Iptal (pasiflestir).
schedulesRouter.delete('/:id', requireAuth, async (req, res) => {
  const s = await prisma.scheduledScan.findFirst({ where: { id: req.params.id, customerId: req.customerId! } });
  if (!s) return res.status(404).json({ error: 'Bulunamadi.' });
  await prisma.scheduledScan.update({ where: { id: s.id }, data: { active: false } });
  res.json({ ok: true });
});
