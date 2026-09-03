/**
 * (LINKEDIN MEDYA — PUBLIC) Buffer -> LinkedIn zinciri medyayi PUBLIC bir URL'den ceker; bu yuzden
 * bu uc KIMLIK DOGRULAMASIZ olmak ZORUNDADIR. Servis edilen icerik zaten LinkedIn'de yayinlanacak
 * pazarlama materyalidir — musteri/tarama verisi DEGILDIR (o veriler sifreli rapor akisinda kalir).
 * Id rastgele UUID'dir; listeleme ucu YOKTUR (yalniz dogrudan id ile erisim).
 */
import { Router } from 'express';
import { prisma } from '../db.js';

export const linkedinAssetsRouter = Router();

linkedinAssetsRouter.get('/:id', async (req, res) => {
  const a = await prisma.linkedinAsset.findUnique({
    where: { id: req.params.id },
    select: { data: true, mime: true, title: true, kind: true },
  });
  if (!a) return res.status(404).end();
  res.setHeader('Content-Type', a.mime);
  // Icerik id basina degismez (yeni surum = yeni id) -> uzun sureli cache guvenli.
  res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
  // helmet varsayilani CORP=same-origin; LinkedIn/Buffer BASKA origin'den ceker -> acilmali.
  res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
  const safe = a.title.replace(/[^\w .-]+/g, '_').slice(0, 80) || 'cybertestify';
  res.setHeader('Content-Disposition', `inline; filename="${safe}.${a.kind === 'pdf' ? 'pdf' : 'png'}"`);
  res.send(Buffer.from(a.data));
});
