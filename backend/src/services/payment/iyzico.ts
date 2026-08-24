import crypto from 'node:crypto';
import Iyzipay from 'iyzipay';
import { config } from '../../config.js';
import { prisma } from '../../db.js';
import { mockInitiate, finalizePaidOrder, type PaymentProvider, type CreatePaymentResult } from './core.js';
import { sendOrderConfirmation } from '../mailer.js';

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

// (Çok-bölge) iyzico'ya gönderilecek para birimi order.currency'den map edilir (eskiden sabit TRY'ydi).
// /de → EUR (kullanıcı kararı: /de iyzico + EUR). Bilinmeyen/eksik → TRY güvenli düşüş. iyzico tipi
// TRY/USD/EUR/GBP destekler (types/iyzipay.d.ts). NOT: AB müşterisine iyzico ile satışta AB-KDV/MoR
// yükümlülüğü satıcıdadır (iyzico MoR değil) — bu bir iş/uyum kararıdır, kod tarafı EUR'u işler.
function iyziCurrency(currency: string | null | undefined): string {
  const map: Record<string, string> = {
    TRY: Iyzipay.CURRENCY.TRY, USD: Iyzipay.CURRENCY.USD, EUR: Iyzipay.CURRENCY.EUR, GBP: Iyzipay.CURRENCY.GBP,
  };
  return map[(currency ?? 'TRY').toUpperCase()] ?? Iyzipay.CURRENCY.TRY;
}
// Ödeme formu dili: order.locale 'tr' → TR, aksi (en/de-fallback) → EN.
function iyziLocale(locale: string | null | undefined): string {
  return locale === 'tr' ? Iyzipay.LOCALE.TR : Iyzipay.LOCALE.EN;
}

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
    // Gercek anahtar YOKSA: mock'a DUSME (odeme almadan tarama baslamamali). Bunun yerine
    // kendi GORSEL odeme sayfamiza (/pay/<orderId>) yonlendir — gercek gorunumlu iyzico
    // CheckoutForm placeholder'i. O sayfa siparisi ASLA otomatik 'paid' yapmaz (form submit
    // yalniz "altyapi yapilandirma asamasinda" mesaji gosterir). Anahtar gelince bu dal
    // otomatik devre disi kalir (asagidaki gercek CheckoutForm'a gecer) — TEK route.
    if (!config.iyzico.apiKey || !config.iyzico.secretKey) {
      await prisma.order.update({ where: { id: orderId }, data: { paymentProvider: 'placeholder' } });
      return { paymentPageUrl: `${config.frontendUrl}/pay/${orderId}`, conversationId: orderId };
    }

    const conversationId = order.id;
    const price = (order.amountMinorUnit / 100).toFixed(2); // TL, 2 ondalik (iyzico string bekler)
    const { name, surname } = splitName(order.customer.fullName, order.customer.email);

    const request: Record<string, unknown> = {
      locale: iyziLocale(order.locale),
      conversationId,
      price,
      paidPrice: price,
      currency: iyziCurrency(order.currency),
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
 * BUNDLE (kombine paket) icin TEK gercek iyzico CheckoutForm baslatir: TUM uye order'larin
 * TOPLAM tutari, TEK conversationId/basketId. token TUM uye order'lara yazilir; callback
 * token'a sahip TUM order'lari finalize eder. Tekil (initiatePayment) akisi DEGISMEZ.
 * iyzico: basketItems fiyat TOPLAMI == price olmali; her uye kendi tutariyla eklenir.
 */
export async function initiateBundlePayment(orderIds: string[]): Promise<CreatePaymentResult> {
  const orders = await prisma.order.findMany({
    where: { id: { in: orderIds } },
    include: { customer: true, package: true },
  });
  if (!orders.length) throw new Error('Bundle siparisleri bulunamadi.');

  // DEV mock (yalniz NODE_ENV!=production + anahtar yok): odeme ALMADAN tum uyeleri finalize et.
  if (config.mockPayment) {
    for (const o of orders) await finalizePaidOrder(o.id);
    return { paymentPageUrl: `${config.frontendUrl}/dashboard/${orderIds[0]}`, conversationId: orderIds[0] };
  }
  // Gercek anahtar YOKSA: tekil akisla ayni — gorsel /pay placeholder'ina dus, paid YAPMA.
  if (!config.iyzico.apiKey || !config.iyzico.secretKey) {
    await prisma.order.updateMany({ where: { id: { in: orderIds } }, data: { paymentProvider: 'placeholder' } });
    return {
      paymentPageUrl: `${config.frontendUrl}/pay/${orderIds[0]}?bundle=${orderIds.join(',')}`,
      conversationId: orderIds[0],
    };
  }

  const totalMinor = orders.reduce((s, o) => s + o.amountMinorUnit, 0);
  const totalStr = (totalMinor / 100).toFixed(2);
  const groupId = crypto.randomUUID();
  const buyer = orders[0].customer;
  const { name, surname } = splitName(buyer.fullName, buyer.email);

  const request: Record<string, unknown> = {
    locale: iyziLocale(orders[0].locale),
    conversationId: groupId,
    price: totalStr,
    paidPrice: totalStr,
    currency: iyziCurrency(orders[0].currency),
    basketId: groupId,
    paymentGroup: Iyzipay.PAYMENT_GROUP.PRODUCT,
    callbackUrl: `${config.publicApiUrl}/payments/iyzico/callback`,
    enabledInstallments: [1],
    buyer: {
      id: buyer.id,
      name,
      surname,
      email: buyer.email,
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
    basketItems: orders.map((o) => ({
      id: o.packageId,
      name: o.package.displayName,
      category1: 'Guvenlik Hizmeti',
      itemType: Iyzipay.BASKET_ITEM_TYPE.VIRTUAL,
      price: (o.amountMinorUnit / 100).toFixed(2),
    })),
  };

  const result = await initializeCheckoutForm(client(), request);
  if (result?.status !== 'success' || !result?.paymentPageUrl) {
    const msg = result?.errorMessage || 'iyzico CheckoutForm baslatilamadi (bundle).';
    console.error(`[iyzico] bundle initialize hatasi (orders ${orderIds.join(',')}):`, result?.errorCode, msg);
    throw new Error(msg);
  }
  // token'i TUM uye order'lara yaz — callback token ile hepsini bulup finalize eder.
  await prisma.order.updateMany({
    where: { id: { in: orderIds } },
    data: { paymentProvider: 'iyzico', paymentRef: result.token },
  });
  return { paymentPageUrl: result.paymentPageUrl, conversationId: groupId };
}

/**
 * (3) AI COZUM ONERILERI ek-odemesi — bir raporun fix-suggestion'i icin TEK CheckoutForm.
 * Token + tahsil edilecek tutar Report'a yazilir; callback token ile raporu bulup dogrular ve
 * fixSuggestionsUnlockedAt set eder. Siparis/tarama akisindan BAGIMSIZ (ayri odeme).
 */
export async function initiateFixSuggestionPayment(orderId: string, amountMinor: number): Promise<CreatePaymentResult> {
  const order = await prisma.order.findUniqueOrThrow({
    where: { id: orderId },
    include: { customer: true, package: true, report: { select: { id: true } } },
  });
  if (!order.report) throw new Error('Bu siparis icin rapor yok.');
  if (!config.iyzico.apiKey || !config.iyzico.secretKey) throw new Error('Odeme yapilandirilmamis.');

  const priceStr = (amountMinor / 100).toFixed(2);
  const groupId = crypto.randomUUID();
  const { name, surname } = splitName(order.customer.fullName, order.customer.email);
  const request: Record<string, unknown> = {
    locale: iyziLocale(order.locale),
    conversationId: groupId,
    price: priceStr,
    paidPrice: priceStr,
    currency: iyziCurrency(order.currency),
    basketId: groupId,
    paymentGroup: Iyzipay.PAYMENT_GROUP.PRODUCT,
    callbackUrl: `${config.publicApiUrl}/payments/iyzico/callback`,
    enabledInstallments: [1],
    buyer: {
      id: order.customer.id, name, surname, email: order.customer.email,
      identityNumber: '11111111111', registrationAddress: 'CyberTestify — dijital hizmet',
      ip: '85.34.78.112', city: 'Istanbul', country: 'Turkey',
    },
    billingAddress: { contactName: `${name} ${surname}`, city: 'Istanbul', country: 'Turkey', address: 'CyberTestify — dijital hizmet (fatura e-posta ile iletilir)' },
    basketItems: [{ id: `fix-${order.packageId}`, name: `AI Çözüm Önerileri — ${order.package.displayName}`, category1: 'Guvenlik Hizmeti', itemType: Iyzipay.BASKET_ITEM_TYPE.VIRTUAL, price: priceStr }],
  };
  const result = await initializeCheckoutForm(client(), request);
  if (result?.status !== 'success' || !result?.paymentPageUrl) {
    const msg = result?.errorMessage || 'iyzico CheckoutForm baslatilamadi (fix).';
    console.error(`[iyzico] fix-suggestion initialize hatasi (order ${orderId}):`, result?.errorCode, msg);
    throw new Error(msg);
  }
  // token + tutari rapora yaz — callback token ile bulup dogrular.
  await prisma.report.update({ where: { id: order.report.id }, data: { fixSuggestionsPaymentRef: result.token, fixSuggestionsAmountMinor: amountMinor } });
  return { paymentPageUrl: result.paymentPageUrl, conversationId: groupId };
}

/**
 * Callback'te iyzico'dan gelen token'i DOGRULAR (retrieve). Basari + tutar eslesirse
 * siparis(ler)i finalize eder (paid + tarama). Musteriden gelen "basarili" bilgisine ASLA
 * guvenmeyiz — iyzico'ya sunucu-taraf sorariz (oynanma korumasi). TEKIL + BUNDLE + FIX birlesik.
 */
export async function handleIyzicoCallback(token: string): Promise<{ ok: boolean; orderId?: string; error?: string }> {
  if (!token) return { ok: false, error: 'token yok' };
  const result = await retrieveCheckoutForm(client(), { locale: Iyzipay.LOCALE.TR, token });
  if (result?.status !== 'success' || result?.paymentStatus !== 'SUCCESS') {
    return { ok: false, orderId: result?.basketId, error: result?.errorMessage || result?.paymentStatus || 'odeme basarisiz' };
  }

  // (3) AI Cozum Onerileri ek-odemesi mi? token'a sahip rapor varsa: tutari dogrula + UNLOCK.
  const fixReport = await prisma.report.findFirst({ where: { fixSuggestionsPaymentRef: token } });
  if (fixReport) {
    const toMinor = (v: unknown) => Math.round(Number(v) * 100);
    const expected = fixReport.fixSuggestionsAmountMinor ?? -1;
    const paidMinor = toMinor(result.paidPrice);
    const priceMinor = toMinor(result.price);
    const ok = (Number.isFinite(paidMinor) && Math.abs(paidMinor - expected) <= 1) || (Number.isFinite(priceMinor) && Math.abs(priceMinor - expected) <= 1);
    if (!ok) {
      console.error(`[iyzico] fix tutar uyusmazligi report ${fixReport.id}: beklenen ${expected}, gelen ${result.paidPrice}/${result.price}`);
      return { ok: false, orderId: fixReport.orderId, error: 'tutar uyusmazligi' };
    }
    await prisma.report.update({ where: { id: fixReport.id }, data: { fixSuggestionsUnlockedAt: fixReport.fixSuggestionsUnlockedAt ?? new Date() } });
    console.log(`[iyzico] AI Cozum Onerileri unlock (order ${fixReport.orderId})`);
    return { ok: true, orderId: fixReport.orderId };
  }

  // token'a sahip TUM order'lar. initiatePayment (tekil) ve initiateBundlePayment (N) token'i
  // order(lar)a yazdi. Geriye-uyum: bulunamazsa basketId/conversationId ile tekil order ara.
  let orders = await prisma.order.findMany({ where: { paymentRef: token } });
  if (!orders.length) {
    const fallbackId = result.basketId || result.conversationId;
    if (fallbackId) {
      const one = await prisma.order.findUnique({ where: { id: fallbackId } });
      if (one) orders = [one];
    }
  }
  if (!orders.length) return { ok: false, error: 'siparis eslesmedi' };

  // Tutar dogrulama SAYISAL (string DEGIL): iyzico tam-TL tutari "1"/"499" olarak dondurur
  // ("1.00" DEGIL) → eski string karsilastirmasi tum tam-TL odemeleri yanlis reddediyordu.
  // BUNDLE: beklenen = TUM uye order'larin TOPLAM tutari (uye order amount'larinin toplami =
  // iyzico'ya gonderilen price). paidPrice/price minor-unit'e cevrilip ~1 kurus tolerans ile
  // karsilastirilir; anti-tamper korunur (gercek dusuk tutar hala yakalanir).
  const expectedMinor = orders.reduce((s, o) => s + o.amountMinorUnit, 0);
  const toMinor = (v: unknown) => Math.round(Number(v) * 100);
  const paidMinor = toMinor(result.paidPrice);
  const priceMinor = toMinor(result.price);
  const amountOk =
    (Number.isFinite(paidMinor) && Math.abs(paidMinor - expectedMinor) <= 1) ||
    (Number.isFinite(priceMinor) && Math.abs(priceMinor - expectedMinor) <= 1);
  if (!amountOk) {
    console.error(
      `[iyzico] tutar uyusmazligi (${orders.length} order): beklenen ${expectedMinor} kurus, gelen paidPrice=${result.paidPrice} price=${result.price}`,
    );
    return { ok: false, orderId: orders[0].id, error: 'tutar uyusmazligi' };
  }

  // TUM uye order'lari finalize et (paid + fatura + tarama). finalizePaidOrder idempotent
  // (zaten paid ise sessizce gecer) → double-callback / kismi tekrar guvenli.
  for (const o of orders) await finalizePaidOrder(o.id);
  // (B) Siparis/odeme onayi — TEK e-posta (bundle icin tum uyeler birlikte). Mail hatasi akisi bozmaz.
  await sendOrderConfirmation(orders.map((o) => o.id));
  return { ok: true, orderId: orders[0].id };
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
