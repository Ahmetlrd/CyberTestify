# Guvenlik Tarama Raporu

**Hedef:** ornek-site.com
**Paket:** Keşif Paketi
**Olusturma tarihi:** 2026-01-15T10:00:00.000Z

---

## Bulgular

# ornek-site.com — Dış Keşif (Recon) Raporu

## 1. YÖNETİCİ ÖZETİ

ornek-site.com için pasif ve düşük-etkili keşif teknikleriyle dış saldırı yüzeyi çıkarıldı. Toplam **6 alt alan (subdomain)** tespit edildi; bunlardan biri (`staging.ornek-site.com`) internete açık bir hazırlık ortamı olarak öne çıkıyor. Ayrıca kimlik doğrulaması olmadan erişilebilen bir **API dokümantasyonu (Swagger UI)** ve sürüm bilgisi ifşa eden bir **CMS (WordPress)** kurulumu gözlemlendi. **Genel risk seviyesi: Orta.** Keşif bulguları tek başına bir istismar değildir; ancak saldırı yüzeyini genişleten ve önceliklendirilmesi gereken maruziyetlerdir.

## 2. ALT ALAN (SUBDOMAIN) ENVANTERİ

| Alt alan | Çözülen IP | Not |
|----------|-----------|-----|
| www.ornek-site.com | 203.0.113.10 | Ana uygulama |
| api.ornek-site.com | 203.0.113.11 | REST API uç noktası |
| staging.ornek-site.com | 203.0.113.24 | ⚠️ İnternete açık hazırlık ortamı |
| mail.ornek-site.com | 203.0.113.30 | Posta hizmeti |
| cdn.ornek-site.com | 198.51.100.7 | Statik içerik |
| old.ornek-site.com | 203.0.113.41 | ⚠️ Eski sürüm — bakım dışı olabilir |

**Değerlendirme:** `staging` ve `old` alt alanları genellikle üretim kadar sıkı yönetilmez; erişim kısıtlaması (IP allowlist / kimlik doğrulama) önerilir.

## 3. API & DOKÜMANTASYON KEŞFİ

- **Swagger UI:** `https://api.ornek-site.com/swagger` — ⚠️ kimlik doğrulaması olmadan erişilebilir. Uç nokta şeması, parametreler ve örnek istekler dışarıya açık.
- Dokümante edilmiş 24 uç noktadan 3'ü (`/v1/users`, `/v1/orders`, `/v1/admin/*`) hassas kaynaklara işaret ediyor.
- **Öneri:** Üretim ortamında API dokümantasyonu ya kapatılmalı ya da kimlik doğrulaması arkasına alınmalıdır.

## 4. CMS & BİLİNEN ZAFİYET (CVE) GÖSTERGESİ

- **Tespit edilen CMS:** WordPress 6.2 (sürüm meta etiketi ve `/wp-json` üzerinden çıkarıldı).
- Bu sürüm, kamuya açık zafiyet veritabanlarında **birkaç orta/yüksek dereceli CVE** ile eşleşiyor (temsilî: yorum eklentisinde XSS, REST API'de bilgi ifşası).
- Eklenti envanterinde güncel olmayan 2 eklenti işaret edildi.
- **Öneri:** CMS ve eklentileri en güncel sürüme yükseltin; sürüm ifşasını gizleyin.

## 5. TESPİT EDİLEN RİSKLER

| # | Bulgu | Şiddet | Kısa Açıklama |
|---|-------|--------|----------------|
| 1 | Açık Swagger/API dokümantasyonu | Orta | Saldırı yüzeyi ve uç nokta şeması dışa açık |
| 2 | İnternete açık staging ortamı | Orta | Üretim dışı ortam sıkı korunmuyor olabilir |
| 3 | CMS sürüm ifşası + eski eklentiler | Orta | Bilinen CVE'lerle eşleşme riski |
| 4 | Bakım-dışı `old` alt alanı | Düşük | Unutulmuş varlık; yama almıyor olabilir |

---

## Yasal Uyari ve Kapsam

- **Yapay zeka destekli:** Bu rapor yapay zeka destekli otomatik bir keşif akışıyla üretilmiştir; olgusal ifadeler bağımsız doğrulanmadan kullanılmamalıdır.
- **Kapsam:** Keşif YALNIZCA sahipliği doğrulanmış hedefe yönelik ve düşük-etkili yöntemlerle sınırlıdır; iç ağ ve sızma testi KAPSAM DIŞIDIR.
- **Resmi değildir:** Bu rapor resmi uyumluluk denetimi/sertifikasyon (ASV/QSA vb.) yerine geçmez.
- **Sorumluluk:** Bulguların doğrulanması ve giderilmesi müşterinin sorumluluğundadır.

> **Not:** Bu bir ÖRNEK rapordur. İçerik, gerçek bir taramanın formatını göstermek için anonimleştirilmiş/temsilidir; gerçek bir hedefe ait değildir.
