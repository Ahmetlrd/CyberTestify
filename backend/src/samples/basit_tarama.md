# Guvenlik Tarama Raporu

**Hedef:** ornek-site.com
**Paket:** Basit Tarama
**Olusturma tarihi:** 2026-01-15T10:00:00.000Z

---

## Bulgular

# ornek-site.com Hızlı Güvenlik Ön-Kontrolü

## Yönetici Özeti

ornek-site.com ana sayfası üzerinde gerçekleştirilen hızlı, pasif ön-kontrol; TLS geçerliliği, temel HTTP güvenlik başlıkları ve sunucu banner bilgisini özetler. Genel görünüm olumlu; şifreleme güncel ve HTTPS zorunlu tutulmakta. Ancak birkaç güvenlik başlığı eksik olup, bunların eklenmesi kısa vadede önerilir. Kritik veya yüksek seviyeli bir bulgu tespit edilmemiştir.

## 1. TLS / Sertifika

- **Durum**: ✅ Geçerli
- **Protokol**: TLS 1.3 (güncel)
- **HTTPS Yönlendirmesi**: ✅ Mevcut (HTTP → HTTPS, 301 kalıcı yönlendirme)

## 2. HTTP Güvenlik Başlıkları

| Başlık | Durum | Not |
|--------|-------|-----|
| Strict-Transport-Security | ✅ Mevcut | max-age=31536000 (1 yıl) |
| X-Frame-Options | ❌ Eksik | Clickjacking koruması yok |
| X-Content-Type-Options | ❌ Eksik | MIME-sniffing koruması yok |
| Content-Security-Policy | ❌ Eksik | XSS azaltma katmanı yok |

## 3. Sunucu Banner

- **Server**: nginx (sürüm bilgisi gizlenmiş) — ✅ iyi uygulama
- Teknoloji/sürüm ifşası gözlemlenmedi.

## Bulgu Özeti

| # | Bulgu | Şiddet | Öneri |
|---|-------|--------|-------|
| 1 | X-Frame-Options başlığı eksik | Orta | `X-Frame-Options: SAMEORIGIN` ekleyin |
| 2 | X-Content-Type-Options eksik | Orta | `X-Content-Type-Options: nosniff` ekleyin |
| 3 | Content-Security-Policy eksik | Orta | Sitenize uygun temel bir CSP tanımlayın |

---

## Yasal Uyari ve Kapsam

- **Yapay zeka uretimi:** Bu rapor yapay zeka tabanli otomatik bir ajan tarafindan uretilmistir; olgusal ifadeler bagimsiz dogrulanmadan kullanilmamalidir.
- **Kapsam:** Tarama YALNIZCA sahipligi dogrulanmis hedefle ve **pasif** yontemlerle sinirlidir; ic ag, kimlik dogrulamali test ve sizma testi KAPSAM DISIDIR.
- **Resmi degildir:** Bu rapor resmi uyumluluk denetimi/sertifikasyon (ASV/QSA vb.) yerine gecmez.
- **Sorumluluk:** Bulgularin dogrulanmasi ve giderilmesi musterinin sorumlulugundadir.

> **Not:** Bu bir ÖRNEK rapordur. İçerik, gerçek bir taramanın formatını göstermek için anonimleştirilmiş/temsilidir; gerçek bir hedefe ait değildir.
