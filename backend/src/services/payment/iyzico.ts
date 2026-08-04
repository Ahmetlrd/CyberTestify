import crypto from 'node:crypto';
import Iyzipay from 'iyzipay';
import { config } from '../../config.js';
import { prisma } from '../../db.js';
import { mockInitiate, finalizePaidOrder, type PaymentProvider, type CreatePaymentResult } from './core.js';

/**
 * iyzico ödeme sağlayıcısı (Türkiye) — CheckoutForm (hosted).
 *
 * config.mockPayment (IYZICO_API_KEY YOKSA) → mockInitiate. Anahtar girilince GERÇEK
 * CheckoutForm: kart formunu iyzico host eder (kart verisi bizim sunucumuza HIC ugramaz,
 * PCI-DSS yuku iyzico'da), musteri iyzico'nun sayfasinda oder, iyzico callback'e POST atar.
 *
 * Türkiye'de KOBİ ödeme toplama için iyzico tercih edildi: Stripe, Türkiye merkezli
 * işletmeler için standart merchant hesabı açmayı desteklemiyor.
 */

function client(): Iyzipay {
  return new Iyzipay({ apiKey: config.iyzico.apiKey, secretKey: config.iyzico.secretKey, uri: config.iyzico.baseUrl });
}

// SDK callback -> Promise.
function initializeCheckoutForm(iyzipay: Iyzipay, request: Record<string, unknown>): Promise<any> {
  return new Promise((resolve, reject) => {
    iyzipay.checkoutFormInitialize.create(request, (err, result) => (err ? reject(err) : resolve(result)));
  });
}
function retrieveCheckoutForm(iyzipay: Iyzipay, request: Record<string, unknown>): Promise<any> {
  return new Promise((resolve, reject) => {
    iyzipay.checkoutForm.retrieve(request, (err, result) => (err ? reject(err) : resolve(result)));
  });
}

// iyzico'nun beklediği ad/soyad ayrımı için basit bölme.
function splitName(full: string | null | undefined, fallbackEmail: string): { name: string; surname: string } {
  const s = (full ?? '').trim();
  if (!s) return { name: fallbackEmail.split('@')[0] || 'Musteri', surname: 'Musteri' };
  const parts = s.split(/\s+/);
  if (parts.length === 1) return { name: parts[0], surname: parts[0] };
  return { name: parts.slice(0, -1).join(' '), surname: parts[parts.length - 1] };
}

export const iyzicoProvider: PaymentProvider = {
  name: 'iyzico',
  async initiatePayment(orderId: string): Promise<CreatePaymentResult> {
    const order = await prisma.order.findUniqueOrThrow({
      where: { id: orderId },
      include: { customer: true, package: true, domain: true },
    });
    if (config.mockPayment) return mockInitiate(orderId, 'iyzico');

    const conversationId = order.id;
    const price = (order.amountMinorUnit / 100).toFixed(2); // TL, 2 ondalik (iyzico string bekler)
    const { name, surname } = splitName(order.customer.fullName, order.customer.email);

    const request: Record<string, unknown> = {
      locale: Iyzipay.LOCALE.TR,
      conversationId,
      price,
      paidPrice: price,
      currency: Iyzipay.CURRENCY.TRY,
      basketId: order.id,
      paymentGroup: Iyzipay.PAYMENT_GROUP.PRODUCT,
      // Odeme sonrasi iyzico buraya POST eder (token ile). Public API URL uzerinden.
      callbackUrl: `${config.publicApiUrl}/payments/iyzico/callback`,
      enabledInstallments: [1],
      buyer: {
        id: order.customer.id,
        name,
        surname,
        email: order.customer.email,
        // Sandbox/dijital hizmet — gercek TCKN toplanmaz; iyzico format bekler (11 hane).
        identityNumber: '11111111111',
        registrationAddress: 'CyberTestify — dijital hizmet',
        ip: '85.34.78.112',
        city: 'Istanbul',
        country: 'Turkey',
      },
      billingAddress: {
        contactName: `${name} ${surname}`,
        city: 'Istanbul',
        country: 'Turkey',
        address: 'CyberTestify — dijital hizmet (fatura e-posta ile iletilir)',
      },
      basketItems: [
        {
          id: order.packageId,
          name: order.package.displayName,
          category1: 'Guvenlik Hizmeti',
          itemType: Iyzipay.BASKET_ITEM_TYPE.VIRTUAL,
          price,
        },
      ],
    };

    const result = await initializeCheckoutForm(client(), request);
    if (result?.status !== 'success' || !result?.paymentPageUrl) {
      const msg = result?.errorMessage || 'iyzico CheckoutForm baslatilamadi.';
      console.error(`[iyzico] initialize hatasi (order ${orderId}):`, result?.errorCode, msg);
      throw new Error(msg);
    }

    // token'i sakla (callback'te retrieve icin) — paymentRef = iyzico token.
    await prisma.order.update({
      where: { id: orderId },
      data: { paymentProvider: 'iyzico', paymentRef: result.token },
    });

    return { paymentPageUrl: result.paymentPageUrl, conversationId };
  },
};

/**
 * Callback'te iyzico'dan gelen token'i DOGRULAR (retrieve). Basari + tutar eslesirse
 * siparisi finalize eder (paid + tarama). Musteriden gelen "basarili" bilgisine ASLA
 * guvenmeyiz — iyzico'ya sunucu-taraf sorariz (oynanma korumasi).
 */
export async function handleIyzicoCallback(token: string): Promise<{ ok: boolean; orderId?: string; error?: string }> {
  if (!token) return { ok: false, error: 'token yok' };
  const result = await retrieveCheckoutForm(client(), { locale: Iyzipay.LOCALE.TR, token });
  if (result?.status !== 'success' || result?.paymentStatus !== 'SUCCESS') {
    return { ok: false, orderId: result?.basketId, error: result?.errorMessage || result?.paymentStatus || 'odeme basarisiz' };
  }
  const orderId = result.basketId || result.conversationId;
  if (!orderId) return { ok: false, error: 'siparis eslesmedi' };

  // Tutar dogrulama: iyzico'nun paidPrice'i siparis tutariyla eslesmeli (oynanma korumasi).
  const order = await prisma.order.findUnique({ where: { id: orderId } });
  if (!order) return { ok: false, error: 'siparis bulunamadi' };
  const expected = (order.amountMinorUnit / 100).toFixed(2);
  if (String(result.paidPrice) !== expected && String(result.price) !== expected) {
    console.error(`[iyzico] tutar uyusmazligi order ${orderId}: beklenen ${expected}, gelen ${result.paidPrice}`);
    return { ok: false, orderId, error: 'tutar uyusmazligi' };
  }

  await finalizePaidOrder(orderId);
  return { ok: true, orderId };
}

/**
 * iyzico webhook imza doğrulaması (opsiyonel ek kanal). Callback zaten retrieve ile
 * server-side dogrulandigi icin birincil guvence odur; bu iskelet ileride webhook icin.
 */
export function verifyWebhookSignature(rawBody: string, signatureHeader: string): boolean {
  const expected = crypto.createHmac('sha256', config.iyzico.secretKey).update(rawBody).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signatureHeader || ''));
  } catch {
    return false;
  }
}
