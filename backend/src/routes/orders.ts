import { Router } from 'express';
import { z } from 'zod';
import { prisma } from '../db.js';
import { config } from '../config.js';
import { SCAN_PACKAGES, getPackageDef, localeFor, localizedPackage, fixSuggestionPrice, fixSuggestionListPrice, securityProfileFor, requiresTestCredentials } from '../services/scanPackages.js';
import { validateConsentInput, activeTestScope, ACTIVE_TEST_CONSENT_VERSION, ACTIVE_TEST_RISK_ACK, hasValidActiveTestConsent } from '../services/activeTestConsent.js';
import { storeTestCredential } from '../services/testCredentials.js';
import { renderConsentPdf } from '../services/pdf.js';
import { decryptSecret } from '../services/crypto.js';
import { getPricing, currencyFor } from '../services/pricing.js';
import { getPaymentProvider } from '../services/payment/index.js';
import { initiateBundlePayment } from '../services/payment/iyzico.js';
import { getSampleReportPdf } from '../services/sampleReports.js';
import { creditsForPackagePrice, spendCredits, type CreditTx } from '../services/credits.js';
import { enqueueUnlessReview } from '../services/orchestrator.js';
import { sendOrderConfirmation } from '../services/mailer.js';
import { getQueueStats, getQueuePosition } from '../services/queue.js';
import { evaluatePromo, recordPromoUsage } from '../services/promo.js';
import { COMBO_BUNDLES, getBundle, bundlePrice, bundleMemberAmounts, resolveMembers, isBundleOnlyPackage, primaryBundleForPackage } from '../services/bundles.js';
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
      // Bundle "paketleri" (bundle_surface vb.) tekil paket listesinde GORUNMEZ — yalniz kombine
      // paket akisinda (GET /bundles + POST /bundle) satilir; burada bir ScanPackage satiri
      // olarak var ama musteriye tekil satis olarak sunulmaz.
      .filter((p) => !p.key.startsWith('bundle_'))
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
          // (3) Ucretli "AI Cozum Onerileri" eklentisi fiyati + ustu-cizili anchor ("indirimli gibi").
          fixSuggestionPriceMinorUnit: fixSuggestionPrice(p),
          fixSuggestionListMinorUnit: fixSuggestionListPrice(p),
          // "Yakında": listelenir ama satin ALINAMAZ (frontend CTA pasif + rozet).
          comingSoon: p.comingSoon ?? false,
          // SATIS MODELI: bundle-uyesi paketler tekil SATILAMAZ (basit_tarama HARIC). Frontend
          // tekil "Satın Al" CTA'sini gizler, "yalnizca X icinde" notu gosterir.
          bundleOnly: isBundleOnlyPackage(p.key),
          bundleName: isBundleOnlyPackage(p.key) ? primaryBundleForPackage(p.key, locale) : null,
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

// KOMBINE PAKETLER (bundle) — mevcut tekil paketleri SILMEZ; birden fazlasini birlikte
// isteyene indirimli EK secenek. ?region ile bolgesel fiyat + para birimi.
ordersRouter.get('/bundles', async (req, res) => {
  const region = typeof req.query.region === 'string' ? req.query.region : 'tr';
  const locale = localeFor(region);
  res.json(
    COMBO_BUNDLES.map((b) => {
      const price = bundlePrice(b, region);
      const memberInfo = (keys: string[]) =>
        keys.map((k) => {
          const def = SCAN_PACKAGES.find((p) => p.key === k);
          return { key: k, displayName: def ? localizedPackage(def, locale).displayName : k };
        });
      return {
        key: b.key,
        displayName: locale === 'en' ? b.displayNameEn : b.displayName,
        description: locale === 'en' ? b.descriptionEn : b.description,
        category: b.category,
        discountPct: price.discountPct, // GERCEK indirim (nihai fiyattan turetildi)
        popular: b.popular ?? false,
        comingSoon: b.comingSoon ?? false,
        contactOnly: b.contactOnly ?? false, // (vitrin) sabit fiyat yok -> "Kuruma özel teklif"
        selectable: !!b.selectable,
        // selectable ise musteri secer; TR disi bolgede trOnly (KVKK) havuzdan ELENIR.
        selectableModules: b.selectable
          ? memberInfo((b.selectableKeys ?? []).filter((k) => region === 'tr' || !b.trOnlyKeys?.includes(k)))
          : null,
        members: memberInfo(price.memberKeys),
        originalMinorUnit: price.originalMinorUnit,
        amountMinorUnit: price.amountMinorUnit,
        currency: price.currency,
        pricePlaceholder: false, // fiyatlar NIHAI kabul edildi (canlida "onay bekliyor" gosterilmez)
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
  // Cayma hakki feragati (dijital/aninda ifa) — AYRI checkbox.
  withdrawalWaived: z.literal(true, {
    errorMap: () => ({ message: 'Cayma hakki feragat beyani onaylanmalidir.' }),
  }),
  // KVKK m.9 — yurt disi (Anthropic/ABD) veri aktarimina ACIK RIZA (ayri checkbox).
  crossBorderTransfer: z.literal(true, {
    errorMap: () => ({ message: 'Yurt disi veri aktarimina acik riza onaylanmalidir.' }),
  }),
  // Bolge (fiyat + para birimi). Yoksa tr.
  region: z.enum(['tr', 'us', 'ae']).optional().default('tr'),
  // (Is 2) true ise odeme yerine hesap kredisinden dus (yeterliyse). Yoksa normal odeme.
  useCredits: z.boolean().optional().default(false),
  // Promosyon/indirim kodu (opsiyonel). Gecerliyse fiyat dusurulur; %100 -> odeme atlanir.
  promoCode: z.string().trim().max(64).optional(),
  // (Faz 3 v2) active-light: risk kabulu. (FAZ A) kimlik-doğrulamalı/otonom paketlerde 3 ek onay.
  activeTestConsent: z.object({
    riskAccepted: z.boolean(),
    credentialSharingAccepted: z.boolean().optional(),
    testAccountDeclared: z.boolean().optional(),
    elevatedRiskAccepted: z.boolean().optional(),
  }).optional(),
  // (Faz 3 #5) authenticated_scan: test hesabi kimlik bilgileri. SIFRELI saklanir, flow'a
  // gecince SILINIR, asla loglanmaz. Yalniz authenticated_scan paketinde beklenir.
  authCredentials: z.object({ username: z.string().min(1).max(200), password: z.string().min(1).max(400) }).optional(),
});

ordersRouter.post('/', requireAuth, async (req, res) => {
  // ODEME ONCESI E-POSTA DOGRULAMA ZORUNLU (fail-fast; sema parse'indan ONCE): erisilemez bir
  // mail adresiyle odeme yapip rapor-hazir/sifre mailini alamama riskini ONLE. Login/dashboard
  // KISITLANMAZ, yalniz satin alma adimi.
  const cust0 = await prisma.customer.findUnique({ where: { id: req.customerId! }, select: { emailVerified: true } });
  if (!cust0?.emailVerified) {
    return res.status(409).json({ error: 'Satın almadan önce e-posta adresinizi doğrulayın.', emailUnverified: true });
  }

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
  // "Yakında" paket: listelenir ama satin ALINAMAZ (defense-in-depth; frontend de kapatir).
  if (packageDef.comingSoon) {
    return res.status(409).json({ error: 'Bu paket yakında açılacak; şu an satın alınamıyor.' });
  }

  // SATIS MODELI (defense-in-depth): tekil paket satisi KAPALI — basit_tarama HARIC tum
  // bundle-uyesi paketler yalniz kombine paket icinde alinir. UI CTA'yi gizler; burada
  // dogrudan istek gelse bile REDDEDILIR (comingSoon'dan FARKLI mesaj/sebep).
  if (isBundleOnlyPackage(packageKey)) {
    const bname = primaryBundleForPackage(packageKey, localeFor(region) === 'en' ? 'en' : 'tr');
    return res.status(409).json({
      error: bname
        ? `Bu paket yalnızca "${bname}" içinde satın alınabilir.`
        : 'Bu paket yalnızca kombine paket içinde satın alınabilir.',
      bundleOnly: true,
    });
  }

  // (Faz 3) ACTIVE-LIGHT GUARD: bu paketler zafiyeti DOGRULAYAN aktif test istekleri
  // gonderir; siparis, gecerli bir yetkilendirme beyani (yasal ad + risk kabul) OLMADAN
  // OLUSTURULAMAZ. Tamlik kontrolu OTOMATIK (Vedat'in manuel onayi gerekmez).
  const profile = securityProfileFor(packageDef);
  const isActiveLight = profile === 'active-light' || profile === 'active-verify-only';
  // (Tam Kapsamlı Pentest — FAZ A) kimlik-doğrulamalı/otonom paketlerde 3 EK onay da ZORUNLU.
  const needsAuthConsents = requiresTestCredentials(packageKey);
  if (isActiveLight) {
    const v = validateConsentInput(parsed.data.activeTestConsent, { requireAuthConsents: needsAuthConsents });
    if (!v.ok) return res.status(400).json({ error: v.error });
  }

  // (Tam Kapsamlı Pentest — FAZ A) TEST hesabı kimlik bilgisi: requiresTestCredentials olan paketlerde
  // ZORUNLU. order.create'e plaintext/byok YAZILMAZ; sipariş oluşunca TestCredential'a ŞİFRELİ yazılır.
  const authCreds = needsAuthConsents ? parsed.data.authCredentials : undefined;
  if (needsAuthConsents && !authCreds) {
    return res.status(400).json({ error: 'Bu paket için test hesabı kullanıcı adı ve şifresi zorunludur.' });
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
    crossBorderConsentAt: new Date(), // KVKK m.9 yurt disi (Anthropic/ABD) acik riza zaman damgasi
    consentIp: req.ip ?? null,
    consentVersion: config.legalVersion,
  };

  // (Faz 3) active-light: siparise ZORUNLU yetkilendirme beyanini bagla (tarama
  // baslamadan ONCE olmali; orchestrator guard'i da ayrica dogrular).
  const recordConsent = async (orderId: string) => {
    // Beyan eden hesaptan OTOMATIK (kullaniciya ek alan doldurtmayiz).
    const cust = await prisma.customer.findUniqueOrThrow({ where: { id: req.customerId! }, select: { fullName: true, email: true } });
    const now = new Date();
    await prisma.activeTestConsent.create({
      data: {
        customerId: req.customerId!, orderId, packageKey,
        legalName: cust.fullName?.trim() || cust.email, companyName: null,
        riskAccepted: true, textVersion: ACTIVE_TEST_CONSENT_VERSION, consentIp: req.ip ?? null,
        // (FAZ A) kimlik-doğrulamalı/otonom paket onayları (yalnız o paketlerde işaretlenir).
        credentialSharingAcceptedAt: needsAuthConsents ? now : null,
        testAccountDeclaredAt: needsAuthConsents ? now : null,
        elevatedRiskAcceptedAt: needsAuthConsents ? now : null,
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
          locale: localeFor(region), ...consent,
        },
      });
      await recordPromoUsage(tx, {
        code: promoApplied!.code!, orderId: o.id, customerId: req.customerId!,
        original: amountMinorUnit, discount: promoApplied!.discountMinorUnit!, final: 0,
      });
      return o;
    });
    if (isActiveLight) await recordConsent(order.id); // tarama baslamadan ONCE
    if (authCreds) await storeTestCredential(order.id, authCreds); // (FAZ A) test hesabı — ŞİFRELİ
    await enqueueUnlessReview(order.id);
    await sendOrderConfirmation([order.id]); // (B) %100 promo ile odenen tekil siparis onayi
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
          locale: localeFor(region), ...consent,
        },
      });
      await spendCredits(tx as unknown as CreditTx, req.customerId!, creditsNeeded, o.id);
      return o;
    });
    if (isActiveLight) await recordConsent(order.id); // tarama baslamadan ONCE
    if (authCreds) await storeTestCredential(order.id, authCreds); // (FAZ A) test hesabı — ŞİFRELİ
    // Odeme yok — dogrudan tarama kuyruguna (concurrency=1; bkz orchestrator).
    await enqueueUnlessReview(order.id);
    await sendOrderConfirmation([order.id]); // (B) kredi ile odenen tekil siparis onayi
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
      ...consent,
    },
  });
  if (isActiveLight) await recordConsent(order.id);
  if (authCreds) await storeTestCredential(order.id, authCreds); // (FAZ A) test hesabı — ŞİFRELİ
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

// KOMBINE PAKET (bundle) SATIN ALMA — tekil paketleri SILMEDEN, uye paketlerin her biri
// icin ayri bir siparis olusturur (her uye kendi MEVCUT promptu/guard'iyla calisir; prompt
// TEKRARI YOK). Tek yetkilendirme beyani tum active-light uyeleri kapsar (ekstra onay YOK).
const bundleOrderSchema = z.object({
  domainId: z.string(),
  bundleKey: z.string(),
  selectedModules: z.array(z.string()).optional(), // Uyum paketi: secilen moduller
  ownershipConfirmed: z.literal(true),
  distanceContractAccepted: z.literal(true),
  withdrawalWaived: z.literal(true),
  crossBorderTransfer: z.literal(true), // KVKK m.9 yurt disi (Anthropic/ABD) acik riza
  region: z.enum(['tr', 'us', 'ae']).optional().default('tr'),
  // (FAZ A/E) kimlik-doğrulamalı bundle (bundle_full_pentest) için 3 EK onay da taşınır (yoksa Zod
  // bilinmeyen alanları kırpar -> backend "credentialSharingAccepted yok" der; canlı bug buydu).
  activeTestConsent: z.object({
    riskAccepted: z.boolean(),
    credentialSharingAccepted: z.boolean().optional(),
    testAccountDeclared: z.boolean().optional(),
    elevatedRiskAccepted: z.boolean().optional(),
  }).optional(),
  authCredentials: z.object({ username: z.string().min(1).max(200), password: z.string().min(1).max(400) }).optional(),
  promoCode: z.string().trim().max(64).optional(),
  // (Aktif Doğrulama Paketi) Ödeme öncesi "düşük kapsam" uyarısı gösterildiyse müşteri onayı.
  lowScopeAcknowledged: z.boolean().optional(),
});
ordersRouter.post('/bundle', requireAuth, async (req, res) => {
  // ODEME ONCESI E-POSTA DOGRULAMA ZORUNLU (bundle; fail-fast, sema parse'indan ONCE).
  const custB = await prisma.customer.findUnique({ where: { id: req.customerId! }, select: { emailVerified: true } });
  if (!custB?.emailVerified) {
    return res.status(409).json({ error: 'Satın almadan önce e-posta adresinizi doğrulayın.', emailUnverified: true });
  }

  const parsed = bundleOrderSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
  const { domainId, bundleKey, region } = parsed.data;

  const domain = await prisma.domain.findFirstOrThrow({ where: { id: domainId, customerId: req.customerId! } });
  if (!isVerificationStillValid(domain)) {
    return res.status(403).json({ error: 'Domain dogrulanmamis veya dogrulama suresi dolmus.' });
  }

  const bundle = getBundle(bundleKey);
  if (!bundle) return res.status(404).json({ error: 'Paket bulunamadi.' });
  if (bundle.comingSoon) {
    return res.status(409).json({ error: 'Bu paket yakında açılacak; şu an satın alınamıyor.' });
  }
  const memberKeys = resolveMembers(bundle, region, parsed.data.selectedModules);
  if (!memberKeys.length) return res.status(400).json({ error: 'Bu paket icin gecerli modul secilmedi.' });

  const memberDefs = memberKeys.map((k) => ({ key: k, def: getPackageDef(k), profile: securityProfileFor(getPackageDef(k)) }));
  const anyActiveLight = memberDefs.some((m) => m.profile === 'active-light' || m.profile === 'active-verify-only');
  const hasAuthScan = memberKeys.includes('authenticated_scan');

  // Tek yetkilendirme beyani TUM active-light uyeleri kapsar (ekstra adim YOK). (FAZ A) kimlik-
  // doğrulamalı üye (authenticated_scan) varsa 3 EK onay da ZORUNLU.
  if (anyActiveLight) {
    const v = validateConsentInput(parsed.data.activeTestConsent, { requireAuthConsents: hasAuthScan });
    if (!v.ok) return res.status(400).json({ error: v.error });
  }
  if (hasAuthScan && !parsed.data.authCredentials) {
    return res.status(400).json({ error: 'Kimlik Dogrulamali Tarama iceren pakette test hesabi kullanici adi ve sifresi zorunludur.' });
  }

  // TEK-siparis modelinde bundle tutari dogrudan tek Order'a yazilir (uye bazli bolme YOK).
  const price = bundlePrice(bundle, region, parsed.data.selectedModules);

  // Promo: bundle TOPLAMINA uygulanir. %100 -> tum uye siparisleri paid + kuyruk (odeme yok).
  let promoFree = false;
  let promoApplied: Awaited<ReturnType<typeof evaluatePromo>> | null = null;
  if (parsed.data.promoCode) {
    const p = await evaluatePromo(parsed.data.promoCode, price.amountMinorUnit);
    if (!p.valid) return res.status(400).json({ error: p.error ?? 'Promosyon kodu geçersiz.' });
    promoApplied = p;
    promoFree = p.finalAmountMinorUnit === 0;
  }

  const consent = {
    ownershipConfirmedAt: new Date(),
    distanceContractAcceptedAt: new Date(),
    withdrawalWaivedAt: new Date(),
    crossBorderConsentAt: new Date(), // KVKK m.9 yurt disi (Anthropic/ABD) acik riza zaman damgasi
    consentIp: req.ip ?? null,
    consentVersion: config.legalVersion,
  };
  const cust = await prisma.customer.findUniqueOrThrow({ where: { id: req.customerId! }, select: { fullName: true, email: true } });

  // SATIS MODELI (iki yol):
  //  (1) KAYITLI bundle (ScanPackage satiri var: bundle_surface, bundle_compliance) -> TEK Order
  //      (birlesik rapor generateBundle*Report). 1 Flow/Report/sifre/kilit + tek mail.
  //  (2) KAYITSIZ bundle (ör. bundle_recon — henuz tek-rapor'a gecmedi) -> LEGACY coklu-order
  //      (uye basina 1 order, ajan-yazimi rapor) — eski davranis KORUNUR (regresyon onleme).
  // Odeme (iyzico token) her iki yolda AYNI: initiateBundlePayment(createdOrderIds) token'i tum
  // order'lara yazar, callback token ile finalize eder (1 veya N fark etmez).
  const bundlePkgDb = await prisma.scanPackage.findUnique({ where: { key: bundleKey as any } });
  let createdOrderIds: string[];
  if (bundlePkgDb) {
    // --- (1) TEK ORDER ---
    const order = await prisma.order.create({
      data: {
        customerId: req.customerId!,
        domainId: domain.id,
        packageId: bundlePkgDb.id,
        amountMinorUnit: price.amountMinorUnit, // NIHAI bundle tutari (tek order == iyzico tutari)
        currency: price.currency,
        status: promoFree ? 'paid' : 'awaiting_payment',
        paymentProvider: promoFree ? 'promo' : 'bundle-placeholder',
        paidAt: promoFree ? new Date() : null,
        locale: localeFor(region),
        // (Aktif Doğrulama Paketi) düşük-kapsam uyarısı onayı — ispat için sakla.
        lowScopeWarningShown: parsed.data.lowScopeAcknowledged === true,
        lowScopeWarningAcknowledgedAt: parsed.data.lowScopeAcknowledged === true ? new Date() : null,
        ...consent,
      },
    });
    createdOrderIds = [order.id];
    // (FAZ A) test hesabı kimlik bilgisi — ŞİFRELİ (order.create'e plaintext yazılmaz).
    if (hasAuthScan && parsed.data.authCredentials) await storeTestCredential(order.id, parsed.data.authCredentials);
    if (anyActiveLight) {
      const now = new Date();
      await prisma.activeTestConsent.create({
        data: {
          customerId: req.customerId!, orderId: order.id, packageKey: bundleKey as any,
          legalName: cust.fullName?.trim() || cust.email, companyName: null,
          riskAccepted: true, textVersion: ACTIVE_TEST_CONSENT_VERSION, consentIp: req.ip ?? null,
          credentialSharingAcceptedAt: hasAuthScan ? now : null,
          testAccountDeclaredAt: hasAuthScan ? now : null,
          elevatedRiskAcceptedAt: hasAuthScan ? now : null,
        },
      });
    }
    if (promoFree) await enqueueUnlessReview(order.id);
  } else {
    // --- (2) LEGACY COKLU-ORDER (uye basina) — henuz tek-rapor'a gecmemis bundle'lar icin ---
    const memberAmountMap = new Map(
      bundleMemberAmounts(bundle, region, parsed.data.selectedModules).map((m) => [m.key, m.amountMinorUnit]),
    );
    const perMemberAmount = (k: string) => memberAmountMap.get(k) ?? 0;
    const packageDbs = await prisma.scanPackage.findMany({ where: { key: { in: memberKeys as any } } });
    const dbByKey = new Map(packageDbs.map((p) => [p.key, p]));
    createdOrderIds = [];
    for (const { key, profile } of memberDefs) {
      const packageDb = dbByKey.get(key as any);
      if (!packageDb) continue;
      const isAL = profile === 'active-light' || profile === 'active-verify-only';
      const { currency } = getPricing(key, region);
      const order = await prisma.order.create({
        data: {
          customerId: req.customerId!,
          domainId: domain.id,
          packageId: packageDb.id,
          amountMinorUnit: perMemberAmount(key),
          currency,
          status: promoFree ? 'paid' : 'awaiting_payment',
          paymentProvider: promoFree ? 'promo' : 'bundle-placeholder',
          paidAt: promoFree ? new Date() : null,
          locale: localeFor(region),
          ...consent,
        },
      });
      createdOrderIds.push(order.id);
      // (FAZ A) kimlik-doğrulamalı üye — kimlik bilgisi ŞİFRELİ saklanır (plaintext yazılmaz).
      const memberNeedsCreds = requiresTestCredentials(key);
      if (memberNeedsCreds && parsed.data.authCredentials) await storeTestCredential(order.id, parsed.data.authCredentials);
      if (isAL) {
        const now = new Date();
        await prisma.activeTestConsent.create({
          data: {
            customerId: req.customerId!, orderId: order.id, packageKey: key as any,
            legalName: cust.fullName?.trim() || cust.email, companyName: null,
            riskAccepted: true, textVersion: ACTIVE_TEST_CONSENT_VERSION, consentIp: req.ip ?? null,
            credentialSharingAcceptedAt: memberNeedsCreds ? now : null,
            testAccountDeclaredAt: memberNeedsCreds ? now : null,
            elevatedRiskAcceptedAt: memberNeedsCreds ? now : null,
          },
        });
      }
      if (promoFree) await enqueueUnlessReview(order.id);
    }
    if (!createdOrderIds.length) return res.status(400).json({ error: 'Bu paket icin gecerli uye bulunamadi.' });
  }

  if (promoFree && promoApplied) {
    // Bundle icin TEK kullanim kaydi (ilk uye siparisine bagli).
    await recordPromoUsage(prisma, {
      code: promoApplied.code!, orderId: createdOrderIds[0], customerId: req.customerId!,
      original: price.amountMinorUnit, discount: promoApplied.discountMinorUnit!, final: 0,
    });
    await sendOrderConfirmation(createdOrderIds); // (B) %100 promo ile odenen bundle onayi (tek mail)
    return res.json({ bundleKey, orderIds: createdOrderIds, paidWithPromo: true });
  }

  // BUNDLE ODEME: TR icin TEK gercek iyzico CheckoutForm — TUM uye order'larin TOPLAM tutari,
  // tek conversationId/basketId; callback token ile hepsini paid yapar (bkz initiateBundlePayment
  // + handleIyzicoCallback). Onceden bundle HIC odeme baslatmiyor, hep gorsel /pay placeholder'ina
  // dusuyordu → bundle odemesi CALISMIYORDU. Tekil akis (createOrder) DEGISMEDI.
  if (region === 'tr') {
    let payment;
    try {
      payment = await initiateBundlePayment(createdOrderIds);
    } catch (err: any) {
      console.error(`[bundle] odeme baslatilamadi (orders ${createdOrderIds.join(',')}):`, err?.message ?? err);
      return res.status(503).json({
        error: 'Ödeme şu an başlatılamadı. Lütfen daha sonra tekrar deneyin veya destek ile iletişime geçin.',
        orderIds: createdOrderIds,
      });
    }
    return res.json({ bundleKey, orderIds: createdOrderIds, bundleTotalMinorUnit: price.amountMinorUnit, currency: price.currency, ...payment });
  }

  // TR disi (stripe/paddle henuz canli DEGIL): mevcut placeholder davranisi korunur (paymentPending).
  return res.json({
    bundleKey,
    orderIds: createdOrderIds,
    bundleTotalMinorUnit: price.amountMinorUnit,
    currency: price.currency,
    paymentPending: true,
  });
});

// Musterinin tum taramalari (panelde listelemek icin — sekme kapatilsa da erisilir).
ordersRouter.get('/', requireAuth, async (req, res) => {
  // ?archived=true -> yalniz arsivlenenler; varsayilan yalniz aktif (arsivlenmemis) liste.
  const archived = req.query.archived === 'true';
  const orders = await prisma.order.findMany({
    where: { customerId: req.customerId!, archived },
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
      archived: o.archived,
    })),
  );
});

// ARSIVLE / ARSIVDEN CIKAR — veri SILINMEZ, yalniz gorunurluk (geri alinabilir).
ordersRouter.patch('/:orderId/archive', requireAuth, async (req, res) => {
  const archived = req.body?.archived !== false; // gövde yoksa arşivle (true)
  const order = await prisma.order.findFirst({ where: { id: req.params.orderId, customerId: req.customerId! } });
  if (!order) return res.status(404).json({ error: 'Sipariş bulunamadı.' });
  await prisma.order.update({ where: { id: order.id }, data: { archived } });
  res.json({ ok: true, archived });
});

// KALICI SIL — siparis + rapor + flow + rizalar tamamen silinir (geri ALINAMAZ).
// Aktif/islenen tarama silinmez (once bitmesi beklenir).
ordersRouter.delete('/:orderId', requireAuth, async (req, res) => {
  const order = await prisma.order.findFirst({ where: { id: req.params.orderId, customerId: req.customerId! } });
  if (!order) return res.status(404).json({ error: 'Sipariş bulunamadı.' });
  if (['paid', 'scan_queued', 'scan_running'].includes(order.status)) {
    return res.status(409).json({ error: 'İşlenen/aktif bir tarama silinemez; önce tamamlanmasını bekleyin.' });
  }
  await prisma.$transaction(async (tx) => {
    await tx.promoCodeUsage.deleteMany({ where: { orderId: order.id } });
    await tx.report.deleteMany({ where: { orderId: order.id } });
    await tx.flow.deleteMany({ where: { orderId: order.id } });
    await tx.activeTestConsent.deleteMany({ where: { orderId: order.id } });
    await tx.order.delete({ where: { id: order.id } });
  });
  res.json({ ok: true });
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
// packageKey VEYA bundleKey ile onizleme (tekil paket ya da kombine paket). Biri zorunlu.
const promoPreviewSchema = z.object({
  code: z.string().trim().min(1).max(64),
  packageKey: z.enum(SCAN_PACKAGES.map((p) => p.key) as [string, ...string[]]).optional(),
  bundleKey: z.string().optional(),
  region: z.enum(['tr', 'us', 'ae']).optional().default('tr'),
});
ordersRouter.post('/promo/preview', requireAuth, async (req, res) => {
  const parsed = promoPreviewSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ valid: false, error: 'Geçersiz istek.' });
  let amountMinorUnit: number;
  let currency: string;
  if (parsed.data.bundleKey) {
    const b = getBundle(parsed.data.bundleKey);
    if (!b) return res.status(400).json({ valid: false, error: 'Paket bulunamadı.' });
    const price = bundlePrice(b, parsed.data.region);
    amountMinorUnit = price.amountMinorUnit;
    currency = price.currency;
  } else if (parsed.data.packageKey) {
    ({ amountMinorUnit, currency } = getPricing(parsed.data.packageKey, parsed.data.region));
  } else {
    return res.status(400).json({ valid: false, error: 'Geçersiz istek.' });
  }
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
  // devAccessSecret DB'de PEPPER'li sifreli tutulur; burada SAHIP musteriye (requireAuth +
  // customerId eslesmesi zaten dogrulandi) COZULMUS erisim sifresi verilir — dashboard bunu
  // otomatik doldurur, musteri ekstra kod GIRMEDEN kendi raporunu acar. (Eski duz-metin
  // kalintilari da tolere edilir: cozulemezse ham degeri don.)
  const r = order.report;
  let ownerAccessSecret: string | null = null;
  if (r?.devAccessSecret) {
    try {
      ownerAccessSecret = decryptSecret(r.devAccessSecret);
    } catch {
      ownerAccessSecret = r.devAccessSecret; // eski duz-metin kaydi (varsa)
    }
  }
  const report = r
    ? {
        id: r.id, createdAt: r.createdAt, deliveredAt: r.deliveredAt, devAccessSecret: ownerAccessSecret,
        incomplete: r.incomplete, incompleteReason: r.incompleteReason,
        hasFixSuggestions: r.fixSuggestionsIv != null,
        fixSuggestionsUnlocked: r.fixSuggestionsUnlockedAt != null,
        fixSuggestionPriceMinorUnit: fixSuggestionPrice(getPackageDef(order.package.key)),
        fixSuggestionListMinorUnit: fixSuggestionListPrice(getPackageDef(order.package.key)),
      }
    : null;

  // (#3) Kuyrukta bekleyen siparis icin pozisyon + ETA (mimari degismez; sadece gorunurluk).
  const queue = order.status === 'scan_queued' ? await getQueuePosition({ createdAt: order.createdAt }) : null;

  res.json({ ...order, package: undefined, report, queue });
});
