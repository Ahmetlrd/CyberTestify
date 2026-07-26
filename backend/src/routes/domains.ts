import { Router } from 'express';
import { z } from 'zod';
import { prisma } from '../db.js';
import {
  createDomainVerification,
  checkDomainVerification,
  isVerificationStillValid,
} from '../services/verification.js';
import { requireAuth } from '../middleware/auth.js';

export const domainsRouter = Router();

const createSchema = z.object({ hostname: z.string().min(3) });

// Musterinin daha once ekledigi domainler + guncel gecerlilik + DNS talimatlari.
// Frontend, yeni siparis baslatirken bunu gosterip gecerli olanlarda dogrudan
// paket secimine gecirir (30 gun icinde tekrar DNS dogrulamasi gerekmez).
domainsRouter.get('/', requireAuth, async (req, res) => {
  const domains = await prisma.domain.findMany({
    where: { customerId: req.customerId! },
    orderBy: { createdAt: 'desc' },
    select: { id: true, hostname: true, status: true, verifiedAt: true, verificationToken: true },
  });
  res.json(
    domains.map((d) => ({
      id: d.id,
      hostname: d.hostname,
      status: d.status,
      verifiedAt: d.verifiedAt,
      valid: isVerificationStillValid(d),
      instructions: {
        recordName: `_pentest-verify.${d.hostname}`,
        recordValue: d.verificationToken,
      },
    })),
  );
});

domainsRouter.post('/', requireAuth, async (req, res) => {
  const parsed = createSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });

  const domain = await createDomainVerification(req.customerId!, parsed.data.hostname);
  res.json({
    domainId: domain.id,
    hostname: domain.hostname,
    instructions: {
      type: 'DNS TXT',
      recordName: `_pentest-verify.${domain.hostname}`,
      recordValue: domain.verificationToken,
      note: 'DNS panelinize bu TXT kaydini ekleyin. Yayilim birkac dakika surebilir.',
    },
  });
});

domainsRouter.post('/:domainId/verify', requireAuth, async (req, res) => {
  const verified = await checkDomainVerification(req.params.domainId);
  res.json({ verified });
});
