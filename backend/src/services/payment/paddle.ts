import { config } from '../../config.js';
import { prisma } from '../../db.js';
import { mockInitiate, type PaymentProvider, type CreatePaymentResult } from './core.js';

/**
 * Paddle ödeme sağlayıcısı (uluslararası, USD/EUR) — İSKELET.
 *
 * NEDEN PADDLE (Stripe yerine, bkz PAYMENT_PROVIDERS.md): Paddle bir MERCHANT OF
 * RECORD'dur — satışın yasal satıcısı Paddle'dır; AB KDV / ABD sales-tax / global
 * dijital hizmet vergisini O hesaplar, tahsil eder, beyan/iade eder. Türkiye'deki
 * küçük bir ekip için bu, her ülkede KDV kaydı + beyan yükünü TAMAMEN kaldırır.
 * Karşılığı daha yüksek komisyon (~%5 + sabit) ama uyum maliyeti sıfıra iner.
 *
 * Bu görevde YALNIZCA iskelet + sandbox: gerçek Paddle Billing entegrasyonu
 * (transaction/checkout oluşturma + webhook imza doğrulama) gerçek hesap/anahtar
 * geldiğinde eklenecek. Sandbox'ta mockInitiate ile siparişi "ödendi" sayar.
 */
export const paddleProvider: PaymentProvider = {
  name: 'paddle',
  async initiatePayment(orderId: string): Promise<CreatePaymentResult> {
    await prisma.order.findUniqueOrThrow({ where: { id: orderId } });
    if (config.mockPayment || config.intlPaymentProvider === 'sandbox') {
      return mockInitiate(orderId, 'paddle');
    }

    // --- GERÇEK PADDLE (TODO — gerçek anahtar/hesap sonra) --------------------
    // const paddle = new Paddle(process.env.PADDLE_API_KEY!);
    // const txn = await paddle.transactions.create({
    //   items: [{ priceId: mapOrderToPaddlePrice(order), quantity: 1 }],
    //   customData: { orderId },                     // webhook'ta geri gelir
    //   checkout: { url: `${config.frontendUrl}/dashboard/${orderId}` },
    // });
    // return { paymentPageUrl: txn.checkout!.url!, conversationId: txn.id };
    throw new Error('Paddle gerçek entegrasyonu henüz eklenmedi (sandbox dışı). Bkz PAYMENT_PROVIDERS.md.');
  },
};

// Paddle webhook imza doğrulaması (iskelet) — gerçek: Paddle-Signature HMAC (ts + h1)
// üzerinden hesaplanır; body RAW okunmalı (bkz webhooks.ts raw middleware).
export function verifyPaddleSignature(_rawBody: string, _signatureHeader: string): boolean {
  void config;
  return false; // gerçek doğrulama gelene kadar sandbox dışı reddedilir
}
