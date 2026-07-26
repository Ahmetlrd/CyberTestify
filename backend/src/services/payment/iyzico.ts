import crypto from 'node:crypto';
import { config } from '../../config.js';
import { prisma } from '../../db.js';
import { mockInitiate, type PaymentProvider, type CreatePaymentResult } from './core.js';

/**
 * iyzico ödeme sağlayıcısı (Türkiye). Sandbox'ta mockInitiate kullanır; gerçek
 * IYZICO_API_KEY girilince 'iyzipay' SDK ile CheckoutFormInitialize yapılacak.
 *
 * Türkiye'de KOBİ ödeme toplama için iyzico tercih edildi: Stripe, Türkiye
 * merkezli işletmeler için standart merchant hesabı açmayı desteklemiyor.
 */
export const iyzicoProvider: PaymentProvider = {
  name: 'iyzico',
  async initiatePayment(orderId: string): Promise<CreatePaymentResult> {
    await prisma.order.findUniqueOrThrow({ where: { id: orderId } });
    if (config.mockPayment) return mockInitiate(orderId, 'iyzico');

    // --- GERÇEK IYZICO (TODO) --------------------------------------------
    // const iyzipay = new Iyzipay({ apiKey: config.iyzico.apiKey, secretKey: config.iyzico.secretKey, uri: config.iyzico.baseUrl });
    const conversationId = crypto.randomUUID();
    await prisma.order.update({
      where: { id: orderId },
      data: { paymentProvider: 'iyzico', paymentRef: conversationId },
    });
    return { paymentPageUrl: `${config.iyzico.baseUrl}/checkout/${conversationId}`, conversationId };
  },
};

/**
 * iyzico webhook imza doğrulaması. GERÇEK implementasyon iyzico'nun HMAC
 * formülünü kullanmalı — burada iskelet var.
 */
export function verifyWebhookSignature(rawBody: string, signatureHeader: string): boolean {
  const expected = crypto.createHmac('sha256', config.iyzico.secretKey).update(rawBody).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signatureHeader || ''));
}
