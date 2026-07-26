import { config } from '../../config.js';
import { prisma } from '../../db.js';
import { mockInitiate, type PaymentProvider, type CreatePaymentResult } from './core.js';

/**
 * Stripe ödeme sağlayıcısı (US/AE) — İSKELET. Sandbox'ta mockInitiate kullanır.
 * Gerçek Stripe Checkout entegrasyonu (session oluşturma + webhook imza
 * doğrulama) ayrı bir görevde eklenecek; bu görevde yalnızca mimari "eklenebilir"
 * hale getirildi. AE için Stripe yerine bölgesel bir sağlayıcı (Telr/PayTabs/
 * Network International) da seçilebilir — o zaman yeni bir provider dosyası + bir
 * factory satırı yeterli.
 */
export const stripeProvider: PaymentProvider = {
  name: 'stripe',
  async initiatePayment(orderId: string): Promise<CreatePaymentResult> {
    await prisma.order.findUniqueOrThrow({ where: { id: orderId } });
    if (config.mockPayment) return mockInitiate(orderId, 'stripe');

    // --- GERÇEK STRIPE (TODO) --------------------------------------------
    // const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
    // const session = await stripe.checkout.sessions.create({ ... });
    // return { paymentPageUrl: session.url!, conversationId: session.id };
    throw new Error('Stripe gerçek entegrasyonu henüz eklenmedi (sandbox dışı). Bkz HANDOFF.md.');
  },
};

// stripe webhook imza doğrulaması (iskelet) — gerçek: stripe.webhooks.constructEvent
export function verifyStripeSignature(_rawBody: string, _sig: string): boolean {
  void config;
  return false;
}
