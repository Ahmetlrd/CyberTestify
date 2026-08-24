import { config } from '../../config.js';
import { iyzicoProvider, verifyWebhookSignature } from './iyzico.js';
import { stripeProvider } from './stripe.js';
import { paddleProvider } from './paddle.js';
import type { PaymentProvider } from './core.js';

export type { PaymentProvider, CreatePaymentResult } from './core.js';
export { handlePaymentSucceeded } from './core.js';
export { verifyWebhookSignature };

// (Is 3) Uluslararasi saglayici config.intlPaymentProvider ile secilir (Paddle onerilen).
// 'sandbox' da paddleProvider'i doner ama o mockInitiate'e duser (guvenli varsayilan).
function intlProvider(): PaymentProvider {
  return config.intlPaymentProvider === 'stripe' ? stripeProvider : paddleProvider;
}

// Bölge -> ödeme sağlayıcı (tek yerde; dağıtık if YOK). TR->iyzico (TL, gercek/sandbox),
// diğer bölgeler -> secili uluslararasi saglayici (USD/EUR). IP/locale -> bölge eslemesi
// middleware'de yapilir (Accept-Language/geo/cookie); burasi yalniz bölge->saglayici.
export function getPaymentProvider(region: string): PaymentProvider {
  if (region === 'tr') return iyzicoProvider;
  // (Almanya lansmanı — kullanıcı kararı) /de → iyzico + EUR (Paddle/Stripe DEĞİL). iyzico isteğe
  // göre order.currency'den EUR işler (bkz iyzico.ts iyziCurrency). NOT: iyzico MoR olmadığından
  // AB-KDV beyanı satıcıya aittir — bilinçli iş kararı.
  if (region === 'de') return iyzicoProvider;
  return intlProvider();
}
