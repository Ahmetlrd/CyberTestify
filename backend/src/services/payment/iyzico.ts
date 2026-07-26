import crypto from 'node:crypto';
import { config } from '../../config.js';
import { prisma } from '../../db.js';
import { enqueueOrStartScan } from '../orchestrator.js';

/**
 * iyzico entegrasyon iskeleti — GERCEK bir SDK cagrisi degil, cunku sandbox/
 * production merchant kimlik bilgilerin yok. Resmi 'iyzipay' npm paketiyle
 * degistirilmesi gereken yerler acikca isaretlendi.
 *
 * Turkiye'de bireysel/KOBI odeme toplama icin Stripe yerine iyzico'yu
 * onerdim: Stripe, Turkiye merkezli isletmeler icin standart merchant
 * hesabi acmayi desteklemiyor; iyzico yerel kartlar ve TRY ile calisir.
 */

export interface CreatePaymentResult {
  paymentPageUrl: string;
  conversationId: string;
}

export async function initiatePayment(orderId: string): Promise<CreatePaymentResult> {
  await prisma.order.findUniqueOrThrow({ where: { id: orderId } });
  const conversationId = crypto.randomUUID();

  // --- DEV / MOCK MODU ---------------------------------------------------
  // Gercek iyzico kimlik bilgisi yokken (config.mockPayment) odeme adimini
  // atlayip siparisi otomatik "odendi" sayiyoruz ve taramayi baslatiyoruz.
  // Boylece localhost'ta uctan uca akis (buton -> tarama) calisir. Gercek
  // IYZICO_API_KEY girilince bu blok devre disi kalir.
  if (config.mockPayment) {
    await prisma.order.update({
      where: { id: orderId },
      data: { paymentProvider: 'mock', paymentRef: conversationId },
    });
    try {
      await handlePaymentSucceeded(conversationId);
    } catch (err) {
      console.error('[mock-payment] tarama baslatilamadi:', err);
      await prisma.order.update({ where: { id: orderId }, data: { status: 'scan_failed' } });
    }
    // Kullaniciyi kendi siparis panelimize yonlendir (harici odeme sayfasi yok).
    return {
      paymentPageUrl: `${config.frontendUrl}/dashboard/${orderId}`,
      conversationId,
    };
  }

  // --- GERCEK IYZICO (TODO) ----------------------------------------------
  // 'iyzipay' paketiyle CheckoutFormInitialize cagrisi yapip donen
  // paymentPageUrl'i kullaniciya yonlendir.
  // const iyzipay = new Iyzipay({ apiKey: config.iyzico.apiKey, secretKey: config.iyzico.secretKey, uri: config.iyzico.baseUrl });
  await prisma.order.update({
    where: { id: orderId },
    data: { paymentProvider: 'iyzico', paymentRef: conversationId },
  });

  return {
    paymentPageUrl: `${config.iyzico.baseUrl}/checkout/${conversationId}`,
    conversationId,
  };
}

/**
 * iyzico webhook imza dogrulamasi. GERCEK implementasyon iyzico'nun
 * dokumantasyonundaki HMAC formulunu kullanmali — burada sadece iskelet var.
 */
export function verifyWebhookSignature(rawBody: string, signatureHeader: string): boolean {
  const expected = crypto.createHmac('sha256', config.iyzico.secretKey).update(rawBody).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signatureHeader || ''));
}

export async function handlePaymentSucceeded(conversationId: string) {
  const order = await prisma.order.findFirstOrThrow({ where: { paymentRef: conversationId } });

  await prisma.order.update({ where: { id: order.id }, data: { status: 'paid', paidAt: new Date() } });

  // Odeme onaylanir onaylanmaz taramayi baslat (veya aktif tarama varsa kuyruga
  // al — concurrency=1, bkz orchestrator). Musteri PentAGI'yi hic gormeden.
  await enqueueOrStartScan(order.id);
}
