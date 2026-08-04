import { Router } from 'express';
import { z } from 'zod';
import { prisma } from '../db.js';
import { config } from '../config.js';
import { SCAN_PACKAGES, getPackageDef, localeFor, localizedPackage, fixSuggestionPrice, securityProfileFor } from '../services/scanPackages.js';
import { validateConsentInput, activeTestScope, ACTIVE_TEST_CONSENT_VERSION, ACTIVE_TEST_RISK_ACK, hasValidActiveTestConsent } from '../services/activeTestConsent.js';
import { renderConsentPdf } from '../services/pdf.js';
import { encryptSecret } from '../services/crypto.js';
import { getPricing, currencyFor } from '../services/pricing.js';
import { getPaymentProvider } from '../services/payment/index.js';
import { getSampleReportPdf } from '../services/sampleReports.js';
import { creditsForPackagePrice, spendCredits, type CreditTx } from '../services/credits.js';
import { enqueueOrStartScan } from '../services/orchestrator.js';
import { getQueueStats, getQueuePosition } from '../services/queue.js';
import { evaluatePromo, recordPromoUsage } from '../services/promo.js';
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
      // GEÇİCİ gizli paketler (available:false) — iso27001/pci, POST sorunu cozulene
      // kadar satista degil (bkz scanPackages 'available' + PATCHES.md GET-only).
      .filter((p) => p.available !== false)
      // (2) kvkk_hazirlik Turkiye'ye ozel mevzuattir; EN/global menude GOSTERILMEZ.
      // GDPR/CCPA esdegerleri ileride ayri paket olarak eklenecek (bkz HANDOFF).
      .filter((p) => !(locale === 'en' && p.key === 'kvkk_hazirlik'))
      .map((p) => {
        const row = priceByKey.get(p.key);
        const t = localizedPackage(p, locale);
        const profile = securityProfileFor(p);
        return {
          key: p.key,
          displayName: t.displayName,
          description: t.description,
          // Bolge satiri yoksa TR tabanina guvenli dusus.
          priceMinorUnit: row?.amountMinorUnit ?? p.priceMinorUnit,
          currency: row?.currency ?? currencyFor(region),
          // (3) Ucretli "AI Cozum Onerileri" eklentisi fiyati (PLACEHOLDER).
          fixSuggestionPriceMinorUnit: fixSuggestionPrice(p),
          // (Faz 3) guvenlik profili + active-light ise ek onay bloğu bilgisi (frontend).
          securityProfile: profile,
          activeTest:
            profile === 'active-light'
              ? { scope: activeTestScope(p.key), riskText: ACTIVE_TEST_RISK_ACK, consentVersion: ACTIVE_TEST_CONSENT_VERSION }
              : null,
        };
      }),
  );
});

// (1) ORNEK RAPOR — PUBLIC (satin almadan once onizleme). Statik/anonim, cache'li PDF.
ordersRouter.get('/sample-report/:packageKey', async (req, res) => {
  try {
    const pdf = await getSampleReportPdf(req.params.packageKey);
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'inline; filename="cybertestify-ornek-rapor.pdf"');
    res.setHeader('Cache-Control', 'public, max-age=86400');
    res.send(pdf);
  } catch {
    res.status(404).json({ error: 'Ornek rapor bulunamadi.' });
  }
});

// (Faz 3) Siparise bagli Aktif Test Yetkilendirme Beyani PDF'i — kayittan re-render.
ordersRouter.get('/:orderId/consent-pdf', requireAuth, async (req, res) => {
  const consent = await prisma.activeTestConsent.findUnique({
    where: { orderId: req.params.orderId },
    include: { order: { include: { domain: { select: { hostname: true } }, package: { select: { displayName: true } } } } },
  });
  if (!consent || consent.customerId !== req.customerId) return res.status(404).json({ error: 'Beyan bulunamadi.' });
  const scope = activeTestScope(consent.packageKey);
  const pdf = await renderConsentPdf({
    legalName: consent.legalName, companyName: consent.companyName,
    hostname: consent.order.domain.hostname, packageName: consent.order.package.displayName,
    does: scope.does, doesNot: scope.doesNot, riskText: ACTIVE_TEST_RISK_ACK,
    version: consent.textVersion, createdAt: consent.createdAt, ip: consent.consentIp,
  });
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `inline; filename="yetkilendirme-beyani-${consent.orderId}.pdf"`);
  res.send(pdf);
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
    'cors_cookie',
    'csp_analiz',
    'subdomain_takeover',
    'api_discovery',
    'injection_verify',
    'idor_verify',
    'ssrf_verify',
    'file_upload_verify',
    'business_logic_verify',
    'race_massassign_verify',
    'rce_verify',
    'authenticated_scan',
    'autonomous_pentest',
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
  // (Is 2) true ise odeme yerine hesap kredisinden dus (yeterliyse). Yoksa normal odeme.
  useCredits: z.boolean().optional().default(false),
  // Promosyon/indirim kodu (opsiyonel). Gecerliyse fiyat dusurulur; %100 -> odeme atlanir.
  promoCode: z.string().trim().max(64).optional(),
  // (Faz 3 v2) active-light: TEK checkbox — risk kabulu. Ek alan yok (yasal ad hesaptan otomatik).
  activeTestConsent: z.object({ riskAccepted: z.boolean() }).optional(),
  // (Faz 3 #5) authenticated_scan: test hesabi kimlik bilgileri. SIFRELI saklanir, flow'a
  // gecince SILINIR, asla loglanmaz. Yalniz authenticated_scan paketinde beklenir.
  authCredentials: z.object({ username: z.string().min(1).max(200), password: z.string().min(1).max(400) }).optional(),
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

  // GEÇİCİ gizli paket (available:false) API'den de reddedilir (menude yok ama
  // dogrudan istek gelebilir). iso27001/pci — POST sorunu (bkz PATCHES.md).
  if (packageDef.available === false) {
    return res.status(409).json({ error: 'Bu paket su an satista degil.' });
  }

  // (Faz 3) ACTIVE-LIGHT GUARD: bu paketler zafiyeti DOGRULAYAN aktif test istekleri
  // gonderir; siparis, gecerli bir yetkilendirme beyani (yasal ad + risk kabul) OLMADAN
  // OLUSTURULAMAZ. Tamlik kontrolu OTOMATIK (Vedat'in manuel onayi gerekmez).
  const profile = securityProfileFor(packageDef);
  const isActiveLight = profile === 'active-light' || profile === 'active-verify-only';
  if (isActiveLight) {
    const v = validateConsentInput(parsed.data.activeTestConsent);
    if (!v.ok) return res.status(400).json({ error: v.error });
  }

  // (#5) authenticated_scan: test kimlik bilgilerini SIFRELE (byokKeyEncrypted). Orchestrator
  // flow'a gecirir + HEMEN siler. Plaintext DB'de/logda ASLA durmaz.
  let byokKeyEncrypted: string | null = null;
  if (packageKey === 'authenticated_scan') {
    if (!parsed.data.authCredentials) {
      return res.status(400).json({ error: 'Bu paket için test hesabı kullanıcı adı ve şifresi zorunludur.' });
    }
    byokKeyEncrypted = encryptSecret(JSON.stringify(parsed.data.authCredentials));
  }

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

  // Promosyon kodu (opsiyonel). Gecerliyse fiyati dusurur; %100 -> effective 0 (odeme atlanir).
  // Kredi ile birlikte KULLANILMAZ (promo verildiyse promo yolu kazanir).
  let effectiveAmount = amountMinorUnit;
  let promoApplied: Awaited<ReturnType<typeof evaluatePromo>> | null = null;
  if (parsed.data.promoCode) {
    const p = await evaluatePromo(parsed.data.promoCode, amountMinorUnit);
    if (!p.valid) return res.status(400).json({ error: p.error ?? 'Promosyon kodu geçersiz.' });
    promoApplied = p;
    effectiveAmount = p.finalAmountMinorUnit!;
  }

  const consent = {
    ownershipConfirmedAt: new Date(),
    distanceContractAcceptedAt: new Date(),
    withdrawalWaivedAt: new Date(),
    consentIp: req.ip ?? null,
    consentVersion: config.legalVersion,
  };

  // (Faz 3) active-light: siparise ZORUNLU yetkilendirme beyanini bagla (tarama
  // baslamadan ONCE olmali; orchestrator guard'i da ayrica dogrular).
  const recordConsent = async (orderId: string) => {
    // Beyan eden hesaptan OTOMATIK (kullaniciya ek alan doldurtmayiz).
    const cust = await prisma.customer.findUniqueOrThrow({ where: { id: req.customerId! }, select: { fullName: true, email: true } });
    await prisma.activeTestConsent.create({
      data: {
        customerId: req.customerId!, orderId, packageKey,
        legalName: cust.fullName?.trim() || cust.email, companyName: null,
        riskAccepted: true, textVersion: ACTIVE_TEST_CONSENT_VERSION, consentIp: req.ip ?? null,
      },
    });
  };

  // PROMO %100 (effective 0): odeme adimini ATLA — siparisi 'paid' olustur, kullanim
  // kaydini yaz, taramayi kuyruga al. GERCEK iyzico cagrisi YAPILMAZ (krediyle-ode benzeri).
  if (promoApplied && effectiveAmount === 0) {
    const order = await prisma.$transaction(async (tx) => {
      const o = await tx.order.create({
        data: {
          customerId: req.customerId!, domainId: domain.id, packageId: packageDb.id,
          amountMinorUnit: 0, currency, status: 'paid', paymentProvider: 'promo', paidAt: new Date(),
          locale: localeFor(region), byokKeyEncrypted, ...consent,
        },
      });
      await recordPromoUsage(tx, {
        code: promoApplied!.code!, orderId: o.id, customerId: req.customerId!,
        original: amountMinorUnit, discount: promoApplied!.discountMinorUnit!, final: 0,
      });
      return o;
    });
    if (isActiveLight) await recordConsent(order.id); // tarama baslamadan ONCE
    await enqueueOrStartScan(order.id);
    return res.json({ orderId: order.id, paidWithPromo: true, code: promoApplied.code });
  }

  // (Is 2) KREDI ILE ODEME: yeterli bakiye varsa odeme adimini ATLA — krediyi dus,
  // siparisi 'paid' olustur, taramayi kuyruga al. Hepsi TEK transaction (tutarlilik).
  // Promo verildiyse kredi yolu KULLANILMAZ (cift indirim olmasin).
  if (parsed.data.useCredits && !promoApplied) {
    const creditsNeeded = creditsForPackagePrice(amountMinorUnit);
    const customer = await prisma.customer.findUniqueOrThrow({ where: { id: req.customerId! }, select: { creditBalance: true } });
    if (customer.creditBalance < creditsNeeded) {
      return res.status(402).json({ error: `Yetersiz kredi: bu paket ${creditsNeeded} kredi gerektirir, bakiyeniz ${customer.creditBalance}.`, creditsNeeded, balance: customer.creditBalance });
    }
    const order = await prisma.$transaction(async (tx) => {
      const o = await tx.order.create({
        data: {
          customerId: req.customerId!, domainId: domain.id, packageId: packageDb.id,
          amountMinorUnit, currency, status: 'paid', paymentProvider: 'credit', paidAt: new Date(),
          locale: localeFor(region), byokKeyEncrypted, ...consent,
        },
      });
      await spendCredits(tx as unknown as CreditTx, req.customerId!, creditsNeeded, o.id);
      return o;
    });
    if (isActiveLight) await recordConsent(order.id); // tarama baslamadan ONCE
    // Odeme yok — dogrudan tarama kuyruguna (concurrency=1; bkz orchestrator).
    await enqueueOrStartScan(order.id);
    return res.json({ orderId: order.id, paidWithCredits: true, creditsSpent: creditsNeeded });
  }

  // Kismi promo indirimi: siparis effectiveAmount ile olusur, kalan tutar iyzico'da odenir.
  const order = await prisma.order.create({
    data: {
      customerId: req.customerId!,
      domainId: domain.id,
      packageId: packageDb.id,
      amountMinorUnit: effectiveAmount,
      currency,
      status: 'awaiting_payment',
      locale: localeFor(region), // (2) cikti dili bolgeden turetilir
      byokKeyEncrypted,
      ...consent,
    },
  });
  if (isActiveLight) await recordConsent(order.id);
  if (promoApplied) {
    await recordPromoUsage(prisma, {
      code: promoApplied.code!, orderId: order.id, customerId: req.customerId!,
      original: amountMinorUnit, discount: promoApplied.discountMinorUnit!, final: effectiveAmount,
    });
  }

  // Bölgeye göre ödeme sağlayıcı (tr→iyzico, us/ae→stripe). Odeme baslatilamazsa
  // (anahtar yok / saglayici hatasi) siparis awaiting_payment KALIR — tarama BASLAMAZ.
  // Musteriye net hata don (500 degil), sistem butunlugu korunur.
  let payment;
  try {
    payment = await getPaymentProvider(region).initiatePayment(order.id);
  } catch (err: any) {
    console.error(`[order] odeme baslatilamadi (order ${order.id}):`, err?.message ?? err);
    return res.status(503).json({
      error: err?.message?.startsWith('Ödeme')
        ? err.message
        : 'Ödeme şu an başlatılamadı. Lütfen daha sonra tekrar deneyin veya destek ile iletişime geçin.',
      orderId: order.id,
    });
  }

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

// (#4) Yeni siparis oncesi kuyruk yogunlugu — order sayfasi bunu okuyup, esik
// asilmissa "su an yogunuz, tahmini bekleme X" nazik uyarisi gosterir (engelleme YOK).
// NOT: '/:orderId'den ONCE tanimli olmali ki '/queue/status' o kaliba dusmasin.
ordersRouter.get('/queue/status', requireAuth, async (_req, res) => {
  const stats = await getQueueStats();
  res.json({ ...stats, threshold: config.queueDepthWarnThreshold, busy: stats.queuedCount >= config.queueDepthWarnThreshold });
});

// Promo kodu ONIZLEME — checkout'ta kod girilince indirimli fiyati gostermek icin.
// Satin alma YAPMAZ; yalniz hesaplar (siparis aninda ayni mantik tekrar dogrulanir).
const promoPreviewSchema = z.object({
  code: z.string().trim().min(1).max(64),
  packageKey: z.enum(SCAN_PACKAGES.map((p) => p.key) as [string, ...string[]]),
  region: z.enum(['tr', 'us', 'ae']).optional().default('tr'),
});
ordersRouter.post('/promo/preview', requireAuth, async (req, res) => {
  const parsed = promoPreviewSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ valid: false, error: 'Geçersiz istek.' });
  const { amountMinorUnit, currency } = getPricing(parsed.data.packageKey, parsed.data.region);
  const result = await evaluatePromo(parsed.data.code, amountMinorUnit);
  res.json({ ...result, currency });
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

  // (#3) Kuyrukta bekleyen siparis icin pozisyon + ETA (mimari degismez; sadece gorunurluk).
  const queue = order.status === 'scan_queued' ? await getQueuePosition({ createdAt: order.createdAt }) : null;

  res.json({ ...order, package: undefined, report, queue });
});
