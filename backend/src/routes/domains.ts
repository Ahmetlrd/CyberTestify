import { Router } from 'express';
import { z } from 'zod';
import { createDomainVerification, checkDomainVerification } from '../services/verification.js';
import { requireAuth } from '../middleware/auth.js';

export const domainsRouter = Router();

const createSchema = z.object({ hostname: z.string().min(3) });

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
