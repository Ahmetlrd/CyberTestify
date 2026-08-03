import { Router } from 'express';
import { z } from 'zod';
import { prisma } from '../db.js';
import { requireAuth } from '../middleware/auth.js';
import { BUNDLES, purchaseBundleMock, CREDIT_UNIT_VALUE_MINOR } from '../services/credits.js';

export const creditsRouter = Router();

// Kredi bakiyesi + son hareketler + satin alinabilir bundle'lar.
creditsRouter.get('/', requireAuth, async (req, res) => {
  const customer = await prisma.customer.findUniqueOrThrow({
    where: { id: req.customerId! },
    select: { creditBalance: true },
  });
  const transactions = await prisma.creditTransaction.findMany({
    where: { customerId: req.customerId! },
    orderBy: { createdAt: 'desc' },
    take: 20,
    select: { delta: true, reason: true, bundleKey: true, balanceAfter: true, createdAt: true },
  });
  res.json({
    balance: customer.creditBalance,
    creditUnitValueMinor: CREDIT_UNIT_VALUE_MINOR,
    // Yalnizca satista olan (available) bundle'lar gosterilir.
    bundles: BUNDLES.filter((b) => b.available).map((b) => ({
      key: b.key, displayName: b.displayName, credits: b.credits,
      priceMinorUnit: b.priceMinorUnit, discountPct: b.discountPct,
    })),
    transactions,
  });
});

const buySchema = z.object({ bundleKey: z.string().min(1) });

// Bundle satin al (su an MOCK — gercek odeme entegrasyonu SONRAKI adim, bkz credits.ts).
creditsRouter.post('/buy-bundle', requireAuth, async (req, res) => {
  const parsed = buySchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
  try {
    const { balance, credits } = await purchaseBundleMock(req.customerId!, parsed.data.bundleKey);
    res.json({ ok: true, balance, creditsAdded: credits });
  } catch (err) {
    const msg = (err as Error).message;
    if (msg === 'bundle_not_found') return res.status(404).json({ error: 'Paket bulunamadi.' });
    if (msg === 'bundle_unavailable') return res.status(409).json({ error: 'Bu paket su an satista degil.' });
    throw err;
  }
});
