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

/** Ödeme onaylanınca: paid + (bölgesel) fatura + tarama başlat. */
export async function handlePaymentSucceeded(conversationId: string) {
  const order = await prisma.order.findFirstOrThrow({ where: { paymentRef: conversationId } });
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
