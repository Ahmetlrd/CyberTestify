import { Router } from 'express';
import { z } from 'zod';
import { zodError } from '../httpErrors.js';
import { prisma } from '../db.js';
import { config } from '../config.js';
import { decryptReport } from '../services/crypto.js';
import { renderReportPdf, htmlToPdfBuffer } from '../services/pdf.js';
import { renderRedTeamFullHtml, redteamReportNo } from '../redteam/report.js';
import { PASSIVE_EXTRAS_DELIM } from '../services/passiveExtras.js';
import { requireAuth } from '../middleware/auth.js';
import { getPackageDef, fixSuggestionPrice, localizedPackage, localeFor } from '../services/scanPackages.js';
import { getBundle } from '../services/bundles.js';

const M = (loc: string, tr: string, de: string, en: string): string => (loc === 'de' ? de : loc === 'en' ? en : tr);
import { evaluatePromo } from '../services/promo.js';
import { initiateFixSuggestionPayment } from '../services/payment/iyzico.js';

export const reportsRouter = Router();

const downloadSchema = z.object({ accessSecret: z.string().min(10, 'Geçerli bir rapor erişim kodu girin.') });

// Rapor indirme: musteri hem oturum acmis olmali (requireAuth) HEM DE
// e-posta ile ayrica gonderilen tek seferlik erisim sifresini girmeli.
// Iki faktorlu bu yaklasim, sadece hesap ele gecirilse bile raporun
// okunamamasini saglar.
reportsRouter.post('/:orderId/download', requireAuth, async (req, res) => {
  const parsed = downloadSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: zodError(parsed.error) });

  const report = await prisma.report.findFirstOrThrow({
    where: { orderId: req.params.orderId, order: { customerId: req.customerId! } },
    include: { order: { include: { domain: { select: { hostname: true } }, package: { select: { displayName: true, key: true } } } } },
  });

  // (İÇ KALİTE KAPISI) Admin onayı beklerken rapor müşteriye VERİLMEZ (müşteri "hala taranıyor" görür).
  if (report.order.status === 'awaiting_admin_review') {
    return res.status(409).json({ error: M(report.order.locale, 'Raporunuz henüz hazırlanıyor.', 'Ihr Bericht wird noch erstellt.', 'Your report is still being prepared.') });
  }

  let plaintext: Buffer;
  try {
    plaintext = decryptReport({
      encryptedBlob: report.encryptedBlob as Buffer,
      iv: report.iv as Buffer,
      authTag: report.authTag as Buffer,
      keyDerivationSalt: report.keyDerivationSalt as Buffer,
      accessSecret: parsed.data.accessSecret,
    });
  } catch {
    return res.status(403).json({ error: 'Erisim sifresi hatali.' });
  }

  // (S1) redteam_s1 raporu: şifreli blob = RedTeamReport JSON (markdown DEĞİL). Müşteri-modunda
  // (iç-operasyon verisi gizli — maliyet/LLM/süre/ID/IP yok) HTML→PDF render edilir; 6-paket
  // markdown/fix yolu ATLANIR. Onay kapısı (409) yukarıda zaten uygulandı.
  if (report.order.package.key === 'redteam_s1') {
    let rt: any;
    try { rt = JSON.parse(plaintext.toString('utf-8')); } catch { return res.status(500).json({ error: M(report.order.locale, 'Rapor içeriği çözümlenemedi.', 'Der Berichtsinhalt konnte nicht dekodiert werden.', 'The report content could not be decoded.') }); }
    if (rt?.meta) rt.meta.jobId = rt.meta.jobId ?? req.params.orderId;
    const reportNo = redteamReportNo(rt?.meta ?? { generatedAt: '', target: report.order.domain.hostname });
    const html = renderRedTeamFullHtml(rt, 'customer');
    const pdf = await htmlToPdfBuffer(html, `CyberTestify · Otonom AI Red Team (deneysel) · ${reportNo}`);
    await prisma.report.update({ where: { id: report.id }, data: { deliveredAt: new Date() } });
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="cybertestify-redteam-${reportNo}.pdf"`);
    return res.send(pdf);
  }

  // (3) Fix onerileri: unlock edilmisse AYNI accessSecret ile coz + PDF'e bolum olarak
  // ekle; VAR ama kilitliyse PDF'te "kilitli" notu goster; hic yoksa hic gosterme.
  let fixMarkdown: string | null = null;
  const hasFix = !!(report.fixSuggestions && report.fixSuggestionsIv && report.fixSuggestionsAuthTag && report.fixSuggestionsSalt);
  // (LANSMAN KAMPANYASI) kampanya açıkken AI Çözüm Önerileri VARSAYILAN AÇIK — satın alma beklemeden çöz.
  const fixUnlocked = !!report.fixSuggestionsUnlockedAt || config.aiFixFreeCampaign;
  if (hasFix && fixUnlocked) {
    try {
      fixMarkdown = decryptReport({
        encryptedBlob: report.fixSuggestions as Buffer,
        iv: report.fixSuggestionsIv as Buffer,
        authTag: report.fixSuggestionsAuthTag as Buffer,
        keyDerivationSalt: report.fixSuggestionsSalt as Buffer,
        accessSecret: parsed.data.accessSecret,
      }).toString('utf-8');
    } catch {
      fixMarkdown = null; // ana rapor cozuldu ama fix cozulemezse sessizce atla
    }
  }

  // (Ek Pasif Kontroller) ana rapordan AYIR — PDF'te ayri/renkli bir bolume gider.
  const full = plaintext.toString('utf-8');
  const di = full.indexOf(PASSIVE_EXTRAS_DELIM);
  const reportMd = di === -1 ? full : full.slice(0, di).trim();
  const extrasMarkdown = di === -1 ? null : full.slice(di + PASSIVE_EXTRAS_DELIM.length).trim();

  const locale: 'tr' | 'en' | 'de' = report.order.locale === 'en' ? 'en' : report.order.locale === 'de' ? 'de' : 'tr';
  // (LOKALİZASYON — canlı yol) Paket adı bölgeye göre: BUNDLE ise bundles.ts lokalize adı
  // (displayNameDe/En; örnek raporların kullandığı aynı kaynak), tekil paket ise PACKAGE_I18N.
  // ESKİ HATA: bundle'lar localizedPackage'a düşüyordu (PACKAGE_I18N'de yok) → ham TR ad basılıyordu.
  const bundleDef = getBundle(report.order.package.key);
  const localizedPkgName = bundleDef
    ? (locale === 'de' ? bundleDef.displayNameDe : locale === 'en' ? bundleDef.displayNameEn : bundleDef.displayName)
    : localizedPackage(getPackageDef(report.order.package.key), locale).displayName;
  const pdf = await renderReportPdf(
    reportMd,
    {
      hostname: report.order.domain.hostname,
      packageName: localizedPkgName,
      packageKey: report.order.package.key,
      createdAt: report.createdAt,
      locale,
    },
    { fixMarkdown, fixLocked: hasFix && !fixUnlocked, extrasMarkdown },
  );

  await prisma.report.update({ where: { id: report.id }, data: { deliveredAt: new Date() } });

  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="cybertestify-rapor-${report.orderId}.pdf"`);
  res.send(pdf);
});

// --- (3) Ucretli eklenti: AI Cozum Onerileri --------------------------------
// Icerik tarama sirasinda uretilip AYRI/sifreli saklanir; ODEME (unlock) yapilana
// kadar asagidaki download DONMEZ (kilitli).

// Satin al (unlock). Odeme "canli" ise (gercek iyzico anahtari var) gercek ek-odeme
// akisi gerekir (TODO). Anahtar YOKSA sistem yayin-oncesi SANDBOX/placeholder modundadir
// (ana checkout da /pay placeholder'ina duser) — bu modda test/demo icin unlock'a izin
// verilir. Anahtar girilince otomatik olarak gercek-odeme dalina gecer (TEK kontrol, ana
// odeme akisiyla ayni "anahtar var mi" sinyali).
const unlockSchema = z.object({ promoCode: z.string().trim().max(64).optional() });
reportsRouter.post('/:orderId/fix-suggestions/unlock', requireAuth, async (req, res) => {
  const parsed = unlockSchema.safeParse(req.body ?? {});
  if (!parsed.success) return res.status(400).json({ error: M(localeFor(typeof (req.body as any)?.region === 'string' ? (req.body as any).region : 'tr'), 'Geçersiz istek.', 'Ungültige Anfrage.', 'Invalid request.') });

  const report = await prisma.report.findFirstOrThrow({
    where: { orderId: req.params.orderId, order: { customerId: req.customerId! } },
    include: { order: { select: { package: { select: { key: true } }, currency: true, locale: true } } },
  });
  if (!report.fixSuggestions) {
    return res.status(404).json({ error: 'Bu rapor icin cozum onerisi uretilmedi.' });
  }
  if (report.fixSuggestionsUnlockedAt) {
    return res.json({ ok: true, unlockedAt: report.fixSuggestionsUnlockedAt }); // zaten acik
  }

  // Fiyat + promo (CYBER-TEST-2026 gibi). %100 -> odeme YOK, dogrudan ac. Aksi halde iyzico.
  const pkgDef = getPackageDef(report.order.package.key as Parameters<typeof getPackageDef>[0]);
  const listPrice = fixSuggestionPrice(pkgDef);
  let amount = listPrice;
  if (parsed.data.promoCode) {
    const rloc = report.order.locale === 'en' ? 'en' : report.order.locale === 'de' ? 'de' : 'tr';
    const p = await evaluatePromo(parsed.data.promoCode, listPrice, rloc);
    if (!p.valid) return res.status(400).json({ error: p.error ?? 'Promo code is invalid.' });
    amount = p.finalAmountMinorUnit ?? listPrice;
  }

  const paymentLive = !!config.iyzico.apiKey && !!config.iyzico.secretKey;
  const freeByPromo = !!parsed.data.promoCode && amount === 0;

  // SANDBOX (anahtar yok) VEYA %100 promo -> odeme ALMADAN ac.
  if (!paymentLive || freeByPromo) {
    const updated = await prisma.report.update({
      where: { id: report.id },
      data: { fixSuggestionsUnlockedAt: new Date() },
    });
    return res.json({ ok: true, unlockedAt: updated.fixSuggestionsUnlockedAt });
  }

  // CANLI + tutar>0 -> gercek iyzico ek-odeme; frontend paymentPageUrl'e yonlenir, callback acar.
  try {
    const payment = await initiateFixSuggestionPayment(req.params.orderId, amount);
    return res.json({ paymentPageUrl: payment.paymentPageUrl });
  } catch (err: any) {
    console.error(`[fix-unlock] odeme baslatilamadi (order ${req.params.orderId}):`, err?.message ?? err);
    return res.status(503).json({ error: M(report.order.locale, 'Ödeme şu an başlatılamadı. Lütfen daha sonra tekrar deneyin.', 'Die Zahlung konnte derzeit nicht gestartet werden. Bitte versuchen Sie es später erneut.', 'Payment could not be started right now. Please try again later.') });
  }
});

// Cozum onerilerini indir — YALNIZCA unlock edilmisse + erisim sifresiyle.
reportsRouter.post('/:orderId/fix-suggestions/download', requireAuth, async (req, res) => {
  const parsed = downloadSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: zodError(parsed.error) });

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
