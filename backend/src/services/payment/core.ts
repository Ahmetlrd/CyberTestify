import crypto from 'node:crypto';
import { config } from '../../config.js';
import { prisma } from '../../db.js';
import { enqueueOrStartScan } from '../orchestrator.js';
import { getInvoicingProvider } from '../invoicing/index.js';

export interface CreatePaymentResult {
  paymentPageUrl: string;
  conversationId: string;
}

/** Bölgeye göre değişen ödeme sağlayıcı sözleşmesi (tr→iyzico, us/ae→stripe...). */
export interface PaymentProvider {
  name: string;
  initiatePayment(orderId: string): Promise<CreatePaymentResult>;
}

/**
 * SANDBOX/MOCK: gerçek merchant kimliği yokken (config.mockPayment) siparişi
 * otomatik "ödendi" say ve taramayı başlat. Tüm sağlayıcılar sandbox'ta bunu
 * kullanır; gerçek entegrasyon (iyzico/stripe) ayrı görevlerde eklenecek.
 */
export async function mockInitiate(orderId: string, providerName: string): Promise<CreatePaymentResult> {
  // GUVENLIK KILIDI (defense-in-depth): mock otomatik-odeme siparisi GERCEK odeme
  // olmadan 'paid' yapar. Bu YALNIZ dev/sandbox icindir; produksiyonda calisirsa odeme
  // almadan tarama baslar (gelir/guvenlik acigi). config.mockPayment zaten NODE_ENV
  // kontrol eder; burada ek olarak KOD seviyesinde de kesin engelliyoruz.
  if (process.env.NODE_ENV === 'production') {
    throw new Error('Odeme sistemi yapilandirilmadi: mock odeme produksiyonda devre disidir.');
  }
  const conversationId = crypto.randomUUID();
  await prisma.order.update({
    where: { id: orderId },
    data: { paymentProvider: `mock-${providerName}`, paymentRef: conversationId },
  });
  try {
    await handlePaymentSucceeded(conversationId);
  } catch (err) {
    console.error(`[mock-payment:${providerName}] tarama baslatilamadi:`, err);
    await prisma.order.update({ where: { id: orderId }, data: { status: 'scan_failed' } });
  }
  return { paymentPageUrl: `${config.frontendUrl}/dashboard/${orderId}`, conversationId };
}

/** Ödeme onaylanınca (conversationId=paymentRef ile bul): paid + fatura + tarama. */
export async function handlePaymentSucceeded(conversationId: string) {
  const order = await prisma.order.findFirstOrThrow({ where: { paymentRef: conversationId } });
  await finalizePaidOrder(order.id);
}

/**
 * Bir siparisi 'paid' yapip fatura + taramayi baslatir. Odeme onayinin TUM yollari
 * (mock, iyzico callback, %100 promo, kredi) buraya dusler — tek dogruluk noktasi.
 * Idempotent: zaten paid/ilerlemis sipariste tekrar tarama baslatmaz.
 */
export async function finalizePaidOrder(orderId: string) {
  const order = await prisma.order.findUniqueOrThrow({ where: { id: orderId } });
  if (order.status !== 'awaiting_payment') {
    // Zaten islenmis (double callback / tekrar cagri) — sessizce gec.
    return;
  }
  await prisma.order.update({ where: { id: order.id }, data: { status: 'paid', paidAt: new Date() } });

  // Faturalandırma bölgesel (para birimine göre) — şu an hepsi iskelet.
  try {
    await getInvoicingProvider(order.currency).generateInvoice(order.id);
  } catch (err) {
    console.error('[invoicing] fatura uretilemedi:', err);
  }

  // Müşteri PentAGI'yi hiç görmeden taramayı başlat (concurrency=1, bkz orchestrator).
  await enqueueOrStartScan(order.id);
}
