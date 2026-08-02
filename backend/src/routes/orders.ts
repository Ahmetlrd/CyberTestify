import { Router } from 'express';
import { z } from 'zod';
import { prisma } from '../db.js';
import { config } from '../config.js';
import { SCAN_PACKAGES, getPackageDef, localeFor, localizedPackage, fixSuggestionPrice } from '../services/scanPackages.js';
import { getPricing, currencyFor } from '../services/pricing.js';
import { getPaymentProvider } from '../services/payment/index.js';
import { isVerificationStillValid } from '../services/verification.js';
import { requireAuth } from '../middleware/auth.js';

export const ordersRouter = Router();

// ?region=tr|us|ae — bolgesel fiyat + para birimi ile paket listesi.
ordersRouter.get('/packages', async (req, res) => {
  const region = typeof req.query.region === 'string' ? req.query.region : 'tr';
  const locale = localeFor(region);
  const pricingRows = await prisma.packagePricing.findMany({ where: { region } });
  const priceByKey = new Map(pricingRows.map((r) => [r.packageKey, r]));

  res.json(
    SCAN_PACKAGES
      // Ham ag/port (networkLayer) paketleri, bypass-proof izolasyon aktif
      // DEGILSE musteriye HIC gosterilmez (bkz HARDENED_NETWORK_ISOLATION).
      .filter((p) => !p.networkLayer || config.hardenedNetworkIsolation)
      // (2) kvkk_hazirlik Turkiye'ye ozel mevzuattir; EN/global menude GOSTERILMEZ.
      // GDPR/CCPA esdegerleri ileride ayri paket olarak eklenecek (bkz HANDOFF).
      .filter((p) => !(locale === 'en' && p.key === 'kvkk_hazirlik'))
      .map((p) => {
        const row = priceByKey.get(p.key);
        const t = localizedPackage(p, locale);
        return {
          key: p.key,
          displayName: t.displayName,
          description: t.description,
          // Bolge satiri yoksa TR tabanina guvenli dusus.
          priceMinorUnit: row?.amountMinorUnit ?? p.priceMinorUnit,
          currency: row?.currency ?? currencyFor(region),
          // (3) Ucretli "AI Cozum Onerileri" eklentisi fiyati (PLACEHOLDER).
          fixSuggestionPriceMinorUnit: fixSuggestionPrice(p),
        };
      }),
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
  // Bolge (fiyat + para birimi). Yoksa tr.
  region: z.enum(['tr', 'us', 'ae']).optional().default('tr'),
});

ordersRouter.post('/', requireAuth, async (req, res) => {
  const parsed = createOrderSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
  const { domainId, packageKey, region } = parsed.data;

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

  // Bolgesel fiyat + para birimi (config-driven; bkz services/pricing.ts).
  const { amountMinorUnit, currency } = getPricing(packageKey, region);

  const order = await prisma.order.create({
    data: {
      customerId: req.customerId!,
      domainId: domain.id,
      packageId: packageDb.id,
      amountMinorUnit,
      currency,
      status: 'awaiting_payment',
      locale: localeFor(region), // (2) cikti dili bolgeden turetilir
      // Rizalarin zaman damgali + IP + surum ile kaydi (ispat yuku bizde).
      ownershipConfirmedAt: new Date(),
      distanceContractAcceptedAt: new Date(),
      withdrawalWaivedAt: new Date(),
      consentIp: req.ip ?? null,
      consentVersion: config.legalVersion,
    },
  });

  // Bölgeye göre ödeme sağlayıcı (tr→iyzico, us/ae→stripe; hepsi sandbox).
  const payment = await getPaymentProvider(region).initiatePayment(order.id);

  res.json({ orderId: order.id, ...payment });
});

// Musterinin tum taramalari (panelde listelemek icin — sekme kapatilsa da erisilir).
ordersRouter.get('/', requireAuth, async (req, res) => {
  const orders = await prisma.order.findMany({
    where: { customerId: req.customerId! },
    orderBy: { createdAt: 'desc' },
    include: {
      domain: { select: { hostname: true } },
      package: { select: { displayName: true } },
    },
  });
  res.json(
    orders.map((o) => ({
      id: o.id,
      hostname: o.domain.hostname,
      packageName: o.package.displayName,
      status: o.status,
      createdAt: o.createdAt,
    })),
  );
});

ordersRouter.get('/:orderId', requireAuth, async (req, res) => {
  const order = await prisma.order.findFirstOrThrow({
    where: { id: req.params.orderId, customerId: req.customerId! },
    include: {
      flow: true,
      domain: { select: { hostname: true } },
      package: { select: { key: true } },
      // fixSuggestions BLOB'unu ASLA gonderme; yalnizca varlik (iv) + kilit durumu.
      report: {
        select: {
          id: true, createdAt: true, deliveredAt: true, devAccessSecret: true,
          incomplete: true, incompleteReason: true,
          fixSuggestionsIv: true, fixSuggestionsUnlockedAt: true,
        },
      },
    },
  });

  // (3) Rapor cikisini guvenli sekilde donustur: icerik degil, DURUM bilgisi.
  const r = order.report;
  const report = r
    ? {
        id: r.id, createdAt: r.createdAt, deliveredAt: r.deliveredAt, devAccessSecret: r.devAccessSecret,
        incomplete: r.incomplete, incompleteReason: r.incompleteReason,
        hasFixSuggestions: r.fixSuggestionsIv != null,
        fixSuggestionsUnlocked: r.fixSuggestionsUnlockedAt != null,
        fixSuggestionPriceMinorUnit: fixSuggestionPrice(getPackageDef(order.package.key)),
      }
    : null;

  res.json({ ...order, package: undefined, report });
});
