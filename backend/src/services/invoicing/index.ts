/**
 * Bölgesel faturalandırma soyutlaması. Şu an TAMAMI İSKELET (sandbox) — gerçek
 * entegrasyonlar ayrı görevlerde:
 *  - tr  → e-Arşiv (GİB/entegratör) [planlı]
 *  - us  → basit receipt + eyalet satış vergisi (ABD'de eyalete göre değişir;
 *          bir ABD mali müşaviriyle netleşecek) [placeholder]
 *  - ae  → BAE KDV (%5) + FTA uyumlu fatura alanları (TRN, VAT breakdown) [placeholder]
 *
 * Config-driven: yeni bölge = para birimi -> yöntem eşlemesi + bir iskelet.
 */

export interface InvoicingProvider {
  method: string;
  generateInvoice(orderId: string): Promise<void>;
}

// TODO(invoicing): gerçek entegrasyonlar. Şimdilik yalnızca ne yapılacağını loglar.
const earsiv: InvoicingProvider = {
  method: 'earsiv',
  async generateInvoice(orderId) {
    console.log(`[invoicing:earsiv] (iskelet) Sipariş ${orderId} için e-Arşiv faturası üretilecek.`);
  },
};

const usReceipt: InvoicingProvider = {
  method: 'us_receipt',
  async generateInvoice(orderId) {
    console.log(`[invoicing:us_receipt] (iskelet) Sipariş ${orderId} için makbuz + eyalet satış vergisi alanı (placeholder).`);
  },
};

const uaeVat: InvoicingProvider = {
  method: 'uae_vat',
  async generateInvoice(orderId) {
    console.log(`[invoicing:uae_vat] (iskelet) Sipariş ${orderId} için BAE KDV %5 + FTA fatura alanları (placeholder).`);
  },
};

// Para birimi -> faturalandırma yöntemi (tek yerde; dağıtık if YOK).
const BY_CURRENCY: Record<string, InvoicingProvider> = {
  TRY: earsiv,
  USD: usReceipt,
  AED: uaeVat,
};

export function getInvoicingProvider(currency: string): InvoicingProvider {
  return BY_CURRENCY[currency] ?? earsiv;
}
