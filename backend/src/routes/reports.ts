import { Router } from 'express';
import { z } from 'zod';
import { prisma } from '../db.js';
import { decryptReport } from '../services/crypto.js';
import { requireAuth } from '../middleware/auth.js';

export const reportsRouter = Router();

const downloadSchema = z.object({ accessSecret: z.string().min(10) });

// Rapor indirme: musteri hem oturum acmis olmali (requireAuth) HEM DE
// e-posta ile ayrica gonderilen tek seferlik erisim sifresini girmeli.
// Iki faktorlu bu yaklasim, sadece hesap ele gecirilse bile raporun
// okunamamasini saglar.
reportsRouter.post('/:orderId/download', requireAuth, async (req, res) => {
  const parsed = downloadSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });

  const report = await prisma.report.findFirstOrThrow({
    where: { orderId: req.params.orderId, order: { customerId: req.customerId! } },
  });

  try {
    const plaintext = decryptReport({
      encryptedBlob: report.encryptedBlob as Buffer,
      iv: report.iv as Buffer,
      authTag: report.authTag as Buffer,
      keyDerivationSalt: report.keyDerivationSalt as Buffer,
      accessSecret: parsed.data.accessSecret,
    });

    await prisma.report.update({ where: { id: report.id }, data: { deliveredAt: new Date() } });

    res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="rapor-${report.orderId}.md"`);
    res.send(plaintext);
  } catch {
    res.status(403).json({ error: 'Erisim sifresi hatali.' });
  }
});
