# Uluslararası Ödeme Sağlayıcı Araştırması (İş 3)

Amaç: TR dışı müşterilerden **USD/EUR** tahsilatı. İyzico (TL) zaten çalışıyor ve
değişmiyor. Bu belge Stripe vs Paddle karşılaştırması + öneri + kurulan iskeleti anlatır.

## Stripe vs Paddle — özet

| Kriter | **Stripe** | **Paddle** (önerilen) |
|--------|-----------|------------------------|
| Model | Ödeme işlemcisi (siz satıcısınız) | **Merchant of Record** (Paddle satıcı) |
| KDV / sales-tax | **SİZİN sorumluluğunuz** — Stripe Tax hesaplar ama kaydı/beyanı/iadesi siz yaparsınız (AB için OSS kaydı, ABD nexus) | **Paddle üstlenir** — hesaplar, tahsil eder, beyan/iade eder. Sizin KDV kaydınız GEREKMEZ |
| Türk şirketi için uygunluk | AB'ye dijital satışta çok-ülke KDV yükü | Vergi yükü sıfır — küçük ekip için kritik avantaj |
| Komisyon | ~%2.9 + 0.30 (daha ucuz) | ~%5 + sabit (vergi hizmeti dahil) |
| Ülke/para desteği | Çok geniş, 135+ para | Geniş; dijital ürün/SaaS odaklı |
| Checkout | Hosted Checkout / Elements | Hosted overlay/checkout |
| Fatura | Kendi faturanız (bkz invoicing soyutlaması) | Paddle vergi-uyumlu fatura üretir |
| Webhook | `Stripe-Signature` HMAC | `Paddle-Signature` HMAC (ts+h1) |

## Öneri: **Paddle**

Gerekçe: CyberTestify Türkiye merkezli, küçük ekip. Yurt dışına **dijital hizmet**
satışında en büyük gizli maliyet ödeme komisyonu değil, **çok-ülke KDV/sales-tax
uyumu** (AB OSS, ABD eyalet nexus'ları, beyan/iade). Paddle Merchant-of-Record olarak
bunu tamamen üstlenir → yasal/muhasebe yükü sıfıra iner. Yüksek komisyon (~%5) bu yükün
bedeli olarak makul. Stripe, ileride kendi vergi altyapınızı kurmak isterseniz (daha
düşük komisyon) alternatif olarak bırakıldı.

> Not: AE (BAE) için Paddle uygundur; istenirse bölgesel bir sağlayıcı (Telr / PayTabs /
> Network International) ayrı bir provider dosyası + factory satırı ile eklenebilir.

## Kurulan iskelet (bu görev)

Mevcut `PaymentProvider` soyutlaması zaten sağlıklıydı; genişletildi:
- `services/payment/core.ts` — `PaymentProvider` interface + `mockInitiate` + `handlePaymentSucceeded` (değişmedi).
- `services/payment/iyzico.ts` — TR, TL (gerçek/sandbox) — **dokunulmadı**.
- `services/payment/stripe.ts` — mevcut iskelet (alternatif).
- **`services/payment/paddle.ts` (YENİ)** — önerilen MoR sağlayıcı iskeleti; sandbox'ta `mockInitiate`.
- `services/payment/index.ts` — factory: `tr → iyzico`, `diğer → config.intlPaymentProvider` seçimi (paddle|stripe), varsayılan **sandbox** (mock).
- `config.ts` — `intlPaymentProvider` (env `INTL_PAYMENT_PROVIDER`, varsayılan `sandbox`).

### IP/locale → bölge → sağlayıcı yönlendirmesi
- **IP/locale → bölge:** zaten var — `middleware` (Accept-Language / geo / cookie) bölgeyi
  belirler (`tr` | `us` | `ae`), sipariş `region` ile gelir.
- **Bölge → sağlayıcı:** `getPaymentProvider(region)` — `tr→iyzico (TL)`, diğer→intl (USD/EUR).
- Kesin kur/fiyat mantığı `pricing.ts`'te bölgesel (şu an US/AE placeholder — Vedat kalibre edecek).

### Aktive etme (gerçek entegrasyon — SONRAKİ adım, senin tarafında)
1. Paddle hesabı + API anahtarı (`PADDLE_API_KEY`) + webhook secret.
2. `.env`: `INTL_PAYMENT_PROVIDER=paddle`, `MOCK_PAYMENT=false`.
3. `paddle.ts` içindeki TODO'ları doldur (transaction/checkout create + `verifyPaddleSignature`).
4. `webhooks.ts`'e Paddle webhook handler (raw body + imza) — iyzico handler'ıyla aynı desen.
5. Paddle price ID'lerini paketlere eşle (`mapOrderToPaddlePrice`).

**Durum:** İskelet hazır, feature-flag ile **kapalı/sandbox**. Gerçek para akışı YOK;
gerçek anahtarlar + entegrasyon senin onayınla sonraki adımda.
