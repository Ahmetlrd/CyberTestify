import { Router } from 'express';
import { z } from 'zod';
import { prisma } from '../db.js';
import { config } from '../config.js';
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

// --- (3) Ucretli eklenti: AI Cozum Onerileri --------------------------------
// Icerik tarama sirasinda uretilip AYRI/sifreli saklanir; ODEME (unlock) yapilana
// kadar asagidaki download DONMEZ (kilitli).

// Satin al (unlock). Su an MOCK/sandbox — gercek iyzico ek-odeme akisi TODO
// (bkz HANDOFF). Odeme onaylaninca fixSuggestionsUnlockedAt damgalanir.
reportsRouter.post('/:orderId/fix-suggestions/unlock', requireAuth, async (req, res) => {
  const report = await prisma.report.findFirstOrThrow({
    where: { orderId: req.params.orderId, order: { customerId: req.customerId! } },
  });
  if (!report.fixSuggestions) {
    return res.status(404).json({ error: 'Bu rapor icin cozum onerisi uretilmedi.' });
  }
  if (!config.mockPayment) {
    // TODO(odeme): gercek iyzico ek-odeme akisi burada baslatilmali; onay
    // webhook'unda fixSuggestionsUnlockedAt set edilmeli. Su an yalniz mock.
    return res.status(501).json({ error: 'Ek-odeme entegrasyonu henuz aktif degil (mock kapali).' });
  }
  const updated = await prisma.report.update({
    where: { id: report.id },
    data: { fixSuggestionsUnlockedAt: report.fixSuggestionsUnlockedAt ?? new Date() },
  });
  res.json({ ok: true, unlockedAt: updated.fixSuggestionsUnlockedAt });
});

// Cozum onerilerini indir — YALNIZCA unlock edilmisse + erisim sifresiyle.
reportsRouter.post('/:orderId/fix-suggestions/download', requireAuth, async (req, res) => {
  const parsed = downloadSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });

  const report = await prisma.report.findFirstOrThrow({
    where: { orderId: req.params.orderId, order: { customerId: req.customerId! } },
  });
  if (!report.fixSuggestions || !report.fixSuggestionsIv || !report.fixSuggestionsAuthTag || !report.fixSuggestionsSalt) {
    return res.status(404).json({ error: 'Bu rapor icin cozum onerisi yok.' });
  }
  // KILIT: odeme yapilmadan icerik DONMEZ.
  if (!report.fixSuggestionsUnlockedAt) {
    return res.status(402).json({ error: 'Cozum onerileri kilitli — once eklentiyi satin alin.' });
  }
  try {
    const plaintext = decryptReport({
      encryptedBlob: report.fixSuggestions as Buffer,
      iv: report.fixSuggestionsIv as Buffer,
      authTag: report.fixSuggestionsAuthTag as Buffer,
      keyDerivationSalt: report.fixSuggestionsSalt as Buffer,
      accessSecret: parsed.data.accessSecret,
    });
    res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="cozum-onerileri-${report.orderId}.md"`);
    res.send(plaintext);
  } catch {
    res.status(403).json({ error: 'Erisim sifresi hatali.' });
  }
});
