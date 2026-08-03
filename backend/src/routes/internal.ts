import { Router } from 'express';
import crypto from 'node:crypto';
import { z } from 'zod';
import { prisma } from '../db.js';
import { config } from '../config.js';
import { getPackageDef, securityProfileFor } from '../services/scanPackages.js';

/** Sabit-zamanli sir karsilastirmasi (timing attack'a karsi). */
function secretMatches(provided: string | undefined): boolean {
  if (!provided) return false;
  const a = Buffer.from(provided);
  const b = Buffer.from(config.internalApiSecret);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

/**
 * SADECE IC AG icin endpoint'ler — egress proxy (egress-proxy/) bunlari kullanir.
 * Internete acilmamali; header'daki paylasimli sir ile korunur.
 *
 * Concurrency=1 oldugu icin ayni anda en fazla TEK 'running' flow vardir; proxy
 * o an aktif olan flow'un kapsamini buradan cekip allowlist olarak uygular.
 */
export const internalRouter = Router();

internalRouter.use((req, res, next) => {
  if (!secretMatches(req.header('x-internal-secret'))) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  next();
});

// Aktif (running) flow'un izin verilen kapsami. Yoksa active:false.
internalRouter.get('/active-scope', async (_req, res) => {
  const flow = await prisma.flow.findFirst({
    where: { status: 'running' },
    include: { order: { include: { domain: true, package: true } } },
    orderBy: { startedAt: 'desc' },
  });
  if (!flow) return res.json({ active: false, allowlist: config.scopeAllowlist });
  const ips = (flow.order.domain.resolvedIps ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  // Pasif paket (networkLayer degil) → proxy, veri degistiren HTTP metotlarini
  // (POST/PUT/DELETE/PATCH) DUZ HTTP'de reddeder (defense-in-depth; HTTPS tunelde
  // metot gorunmez, o yuzden asil enforce worker'daki tool-call tespitindedir).
  let passiveOnly = true;
  let securityProfile: 'passive' | 'active-light' = 'passive';
  try {
    const def = getPackageDef(flow.order.package.key);
    passiveOnly = !def.networkLayer;
    securityProfile = securityProfileFor(def);
  } catch {
    passiveOnly = true; // bilinmeyen paket → guvenli taraf
    securityProfile = 'passive';
  }
  res.json({
    active: true,
    flowId: flow.id,
    pentagiFlowId: flow.pentagiFlowId,
    hostname: flow.order.domain.hostname,
    ips,
    allowlist: config.scopeAllowlist,
    passiveOnly,
    // Faz 1: aktif flow'un guvenlik profili (per-flow kanal). Su an tum paketler 'passive'.
    securityProfile,
  });
});

const auditSchema = z.object({ target: z.string().min(1).max(300), flowId: z.string().optional() });

// Proxy bir istegi kapsam disi diye reddettiginde buraya audit yazar.
internalRouter.post('/scope-audit', async (req, res) => {
  const parsed = auditSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'bad request' });
  const { target } = parsed.data;

  const flow = await prisma.flow.findFirst({ where: { status: 'running' } });
  if (flow) {
    const existing = flow.scopeViolationTarget ?? '';
    if (!existing.includes(target)) {
      const merged = (existing ? existing + ', ' : '') + target;
      await prisma.flow.update({
        where: { id: flow.id },
        data: { scopeViolationTarget: merged.slice(0, 500) },
      });
    }
  }
  // Yuksek gorunurluklu, greplenebilir log. TODO(alerting): gercek uyari
  // kanalina (email/Slack/webhook) da bildirim gonder — proaktif egress blogu
  // guvenlik/hukuki acidan kritik bir olaydir.
  console.error(`[SCOPE-VIOLATION] Egress proxy kapsam disi hedefi ENGELLEDI: ${target}`);
  res.json({ ok: true });
});
