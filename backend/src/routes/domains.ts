import { Router } from 'express';
import { z } from 'zod';
import { zodError } from '../httpErrors.js';
import { prisma } from '../db.js';
import {
  createDomainVerification,
  checkDomainVerification,
  isVerificationStillValid,
  normalizeHostname,
} from '../services/verification.js';
import { requireAuth } from '../middleware/auth.js';
import { resumeVerifiedDomainOrders } from '../services/orchestrator.js';
import { quickScopeSignal } from '../services/activeVerifyEvidence.js';

export const domainsRouter = Router();

// (çok-bölge) kullanıcıya dönen hata metni bölgeye göre — tr/de/en.
const dLoc = (req: { body?: any; query?: any }): string => {
  const r = typeof req.body?.region === 'string' ? req.body.region : (typeof req.query?.region === 'string' ? req.query.region : 'tr');
  return r === 'de' ? 'de' : r === 'en' ? 'en' : 'tr';
};
const M = (loc: string, tr: string, de: string, en: string): string => (loc === 'de' ? de : loc === 'en' ? en : tr);

// Gecerli bir alan adi olmali (rastgele metin degil): en az bir nokta, gecerli
// etiketler. Kullanici "https://", "www.", sondaki "/" vb. girebilir -> ONCE normalizeHostname
// ile CIPLAK host'a indiriyoruz, SONRA bu regex ile dogruluyoruz (aksi halde sema/www yuzunden
// gecerli alan adi bile reddedilir ve "Ekle ve dogrula" calismaz).
const HOSTNAME_RE = /^(?=.{4,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$/;
const createSchema = z.object({
  hostname: z
    .string()
    .transform(normalizeHostname)
    .refine((h) => HOSTNAME_RE.test(h), 'Gecerli bir alan adi girin (ornek: ornek.com).'),
});

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
  if (!parsed.success) return res.status(400).json({ error: M(dLoc(req), 'Geçerli bir alan adı girin (ör. ornek.com).', 'Geben Sie eine gültige Domain ein (z. B. beispiel.de).', 'Enter a valid domain (e.g. example.com).') });

  const domain = await createDomainVerification(req.customerId!, parsed.data.hostname);
  // Zaten ekli VE doğrulaması geçerliyse: yeniden DNS doğrulatma; net "zaten var" bilgisi dön.
  const alreadyVerified = isVerificationStillValid(domain);
  if (alreadyVerified) {
    return res.json({
      domainId: domain.id,
      hostname: domain.hostname,
      alreadyVerified: true,
      message: M(dLoc(req), `“${domain.hostname}” zaten ekli ve doğrulanmış — yeniden DNS doğrulaması gerekmez.`, `„${domain.hostname}“ ist bereits hinzugefügt und verifiziert — keine erneute DNS-Verifizierung nötig.`, `“${domain.hostname}” is already added and verified — no re-verification needed.`),
    });
  }
  res.json({
    domainId: domain.id,
    hostname: domain.hostname,
    alreadyVerified: false,
    instructions: {
      type: 'DNS TXT',
      recordName: `_pentest-verify.${domain.hostname}`,
      recordValue: domain.verificationToken,
      note: M(dLoc(req), 'DNS panelinize bu TXT kaydını ekleyin. Yayılım birkaç dakika sürebilir.', 'Fügen Sie diesen TXT-Eintrag in Ihrem DNS-Panel hinzu. Die Verbreitung kann einige Minuten dauern.', 'Add this TXT record to your DNS panel. Propagation may take a few minutes.'),
    },
  });
});

domainsRouter.post('/:domainId/verify', requireAuth, async (req, res) => {
  // Sahiplik kontrolü: domain bu müşteriye ait olmalı (aksi halde başkasının domain'ini
  // doğrulayıp resume tetiklenemesin).
  const owned = await prisma.domain.findFirst({ where: { id: req.params.domainId, customerId: req.customerId! }, select: { id: true } });
  if (!owned) return res.status(404).json({ error: M(dLoc(req), 'Alan adı bulunamadı.', 'Domain nicht gefunden.', 'Domain not found.') });
  const verified = await checkDomainVerification(req.params.domainId);
  // ÇELİK KAPI (resume): doğrulama tamamlandıysa bu alan adında 'doğrulama bekliyor'da TUTULAN
  // aktif siparişleri otomatik başlat. Best-effort — doğrulama yanıtını bloklamaz.
  if (verified) {
    resumeVerifiedDomainOrders(req.params.domainId).catch((e) => console.error('[steel-gate] resume error', e));
  }
  res.json({ verified });
});

// ODEME-ONCESI hizli kapsam tahmini (SADECE Aktif Doğrulama Paketi UI'si cagirir). Statik,
// ucuz sinyal: hedefte test edilebilir giris noktasi (form/parametre/ID) var mi. Asil tarama
// odeme sonrasi (headless dahil) calisir. Domain musteriye ait olmali.
domainsRouter.get('/:domainId/scope-estimate', requireAuth, async (req, res) => {
  const domain = await prisma.domain.findFirst({
    where: { id: req.params.domainId, customerId: req.customerId! },
    select: { hostname: true },
  });
  if (!domain) return res.status(404).json({ error: M(dLoc(req), 'Alan adı bulunamadı.', 'Domain nicht gefunden.', 'Domain not found.') });
  try {
    const sig = await quickScopeSignal(domain.hostname);
    res.json({ lowSignal: sig.lowSignal, jsRendered: sig.jsRendered, inputCount: sig.inputCount, reachable: sig.reachable });
  } catch {
    // On-kontrol basarisiz olursa akisi ENGELLEME — uyari gostermeden devam (lowSignal:false).
    res.json({ lowSignal: false, jsRendered: false, inputCount: 0, reachable: false });
  }
});

// Tek alan adi sil. Taramasi (siparisi) olan alan adi silinemez (kayit butunlugu).
domainsRouter.delete('/:domainId', requireAuth, async (req, res) => {
  const domain = await prisma.domain.findFirst({
    where: { id: req.params.domainId, customerId: req.customerId! },
  });
  if (!domain) return res.status(404).json({ error: 'Bulunamadi.' });
  const orderCount = await prisma.order.count({ where: { domainId: domain.id } });
  if (orderCount > 0) {
    return res.status(409).json({ error: 'Bu alan adinin taramalari var, silinemez.' });
  }
  await prisma.scheduledScan.deleteMany({ where: { domainId: domain.id } });
  await prisma.domain.delete({ where: { id: domain.id } });
  res.json({ ok: true });
});

// Taramasi olmayan TUM alan adlarini sil (taramasi olanlar korunur).
domainsRouter.delete('/', requireAuth, async (req, res) => {
  const domains = await prisma.domain.findMany({ where: { customerId: req.customerId! }, select: { id: true } });
  const deletable: string[] = [];
  for (const d of domains) {
    if ((await prisma.order.count({ where: { domainId: d.id } })) === 0) deletable.push(d.id);
  }
  await prisma.scheduledScan.deleteMany({ where: { domainId: { in: deletable } } });
  await prisma.domain.deleteMany({ where: { id: { in: deletable } } });
  res.json({ ok: true, deleted: deletable.length, kept: domains.length - deletable.length });
});
