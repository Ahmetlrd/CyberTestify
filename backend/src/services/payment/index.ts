import { iyzicoProvider, verifyWebhookSignature } from './iyzico.js';
import { stripeProvider } from './stripe.js';
import type { PaymentProvider } from './core.js';

export type { PaymentProvider, CreatePaymentResult } from './core.js';
export { handlePaymentSucceeded } from './core.js';
export { verifyWebhookSignature };

// Bölge -> ödeme sağlayıcı (tek yerde; dağıtık if YOK). Yeni bölge = bir satır.
const BY_REGION: Record<string, PaymentProvider> = {
  tr: iyzicoProvider,
  us: stripeProvider,
  ae: stripeProvider,
};

export function getPaymentProvider(region: string): PaymentProvider {
  return BY_REGION[region] ?? iyzicoProvider;
}
