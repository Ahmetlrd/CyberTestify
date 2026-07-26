import { Router } from 'express';
import { z } from 'zod';
import { prisma } from '../db.js';
import { config } from '../config.js';
import { SCAN_PACKAGES, getPackageDef } from '../services/scanPackages.js';
import { initiatePayment } from '../services/payment/iyzico.js';
import { isVerificationStillValid } from '../services/verification.js';
import { requireAuth } from '../middleware/auth.js';

export const ordersRouter = Router();

ordersRouter.get('/packages', async (_req, res) => {
  res.json(
    SCAN_PACKAGES
      // Ham ag/port (networkLayer) paketleri, bypass-proof izolasyon aktif
      // DEGILSE musteriye HIC gosterilmez (bkz HARDENED_NETWORK_ISOLATION).
      .filter((p) => !p.networkLayer || config.hardenedNetworkIsolation)
      .map((p) => ({
        key: p.key,
        displayName: p.displayName,
        description: p.description,
        priceMinorUnit: p.priceMinorUnit,
      })),
  );
});

const createOrderSchema = z.object({
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
  ]),
  // Pentest yetkilendirmesi (TCK 243 hukuka uygunluk) — true olmadan siparis yok.
  ownershipConfirmed: z.literal(true, {
    errorMap: () => ({ message: 'Alan adi/altyapi sahiplik/yetki beyani onaylanmalidir.' }),
  }),
  // Mesafeli Satis Sozlesmesi + On Bilgilendirme Formu onayi.
  distanceContractAccepted: z.literal(true, {
    errorMap: () => ({ message: 'Mesafeli Satis Sozlesmesi ve On Bilgilendirme Formu onaylanmalidir.' }),
  }),
  // Cayma hakki feragati (dijital/aninda ifa).
  withdrawalWaived: z.literal(true, {
    errorMap: () => ({ message: 'Cayma hakki feragat beyani onaylanmalidir.' }),
  }),
});

ordersRouter.post('/', requireAuth, async (req, res) => {
  const parsed = createOrderSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
  const { domainId, packageKey } = parsed.data;

  const domain = await prisma.domain.findFirstOrThrow({
    where: { id: domainId, customerId: req.customerId! },
  });

  // Sira ONEMLI: once dogrulama, sonra odeme. Dogrulanmamis/suresi gecmis
  // domain icin siparis olusturulamaz — bkz konusmadaki sira gerekcesi.
  if (!isVerificationStillValid(domain)) {
    return res.status(403).json({ error: 'Domain dogrulanmamis veya dogrulama suresi dolmus.' });
  }

  const packageDb = await prisma.scanPackage.findUniqueOrThrow({ where: { key: packageKey } });
  const packageDef = getPackageDef(packageKey);

  // GATE: Ham ag/port (networkLayer) paketleri, bypass-proof izolasyon
  // (HARDENED_NETWORK_ISOLATION) tamamlanmadan ASLA calistirilamaz. Biri ileride
  // boyle bir paket eklerse sistem kendini korur (insan hafizasina guvenmeyiz).
  if (packageDef.networkLayer && !config.hardenedNetworkIsolation) {
    return res.status(409).json({
      error:
        'Bu paket tipi (ham ag/port) su an devre disi: bypass-proof ag izolasyonu (HARDENED_NETWORK_ISOLATION) ' +
        'tamamlanmadan sunulamaz. Bkz HANDOFF.md.',
    });
  }

  // SEVIYE 2: Ham ag/port katmani iceren paketler, Host header'a saygi duymadigi
  // icin paylasimli hosting'te komsu siteleri etkileyebilir. Bu nedenle yalnizca
  // IP'si hedefe ozel (dedicated) dogrulanmis hedeflerde acilir.
  if (packageDef.networkLayer && domain.hostingType !== 'dedicated') {
    return res.status(409).json({
      error:
        'Bu paket ham ag/port taramasi icerir ve yalnizca IP adresi size ozel (dedicated) hedeflerde ' +
        'calistirilabilir. Hedefiniz paylasimli/CDN altyapida gorunuyor; luften HTTP/uygulama katmani ' +
        'paketlerinden birini secin.',
    });
  }

  const order = await prisma.order.create({
    data: {
      customerId: req.customerId!,
      domainId: domain.id,
      packageId: packageDb.id,
      amountMinorUnit: packageDef.priceMinorUnit,
      status: 'awaiting_payment',
      // Rizalarin zaman damgali + IP + surum ile kaydi (ispat yuku bizde).
      ownershipConfirmedAt: new Date(),
      distanceContractAcceptedAt: new Date(),
      withdrawalWaivedAt: new Date(),
      consentIp: req.ip ?? null,
      consentVersion: config.legalVersion,
    },
  });

  const payment = await initiatePayment(order.id);

  res.json({ orderId: order.id, ...payment });
});

ordersRouter.get('/:orderId', requireAuth, async (req, res) => {
  const order = await prisma.order.findFirstOrThrow({
    where: { id: req.params.orderId, customerId: req.customerId! },
    include: {
      flow: true,
      domain: { select: { hostname: true } },
      report: { select: { id: true, createdAt: true, deliveredAt: true, devAccessSecret: true } },
    },
  });
  res.json(order);
});
