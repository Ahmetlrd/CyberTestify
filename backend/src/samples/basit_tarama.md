# Guvenlik Tarama Raporu

**Hedef:** ornek-site.com
**Paket:** Basit Tarama
**Olusturma tarihi:** 2026-01-15T10:00:00.000Z

---

## Bulgular

# ornek-site.com — Hızlı Güvenlik Ön-Kontrolü

## 1. YÖNETİCİ ÖZETİ

ornek-site.com ana sayfası üzerinde hızlı ve pasif bir güvenlik ön-kontrolü yapıldı. Şifreleme güncel (TLS 1.3) ve HTTPS zorunlu tutuluyor; sunucu banner'ında sürüm ifşası yok. Buna karşılık üç temel HTTP güvenlik başlığı (X-Frame-Options, X-Content-Type-Options, Content-Security-Policy) eksik. Bu eksiklikler doğrudan bir açık oluşturmaz ancak tarayıcı seviyesindeki savunma katmanlarını zayıflatır. **Genel risk seviyesi: Orta.** Kritik veya yüksek seviyeli bir bulgu tespit edilmedi.

## 2. GENEL DEĞERLENDİRME

Hedefin temel taşıma güvenliği (TLS/HTTPS) sağlam durumda ve teknoloji imzası dikkatli şekilde gizlenmiş. Tespit edilen eksiklikler, eklenmesi kısa vadede önerilen ancak tek başına sömürülebilir olmayan başlıklarla sınırlı. Bu nedenle sitenin genel güvenlik duruşu **Orta Risk** olarak değerlendirilmiştir — hızlı ve düşük maliyetli düzeltmelerle Düşük seviyeye çekilebilir.

## 3. HTTP GÜVENLİK BAŞLIKLARI

| Başlık | Durum | Not |
|--------|-------|-----|
| Strict-Transport-Security | ✅ Mevcut | max-age=31536000 (1 yıl) |
| X-Frame-Options | ❌ Eksik | Clickjacking koruması yok |
| X-Content-Type-Options | ❌ Eksik | MIME-sniffing koruması yok |
| Content-Security-Policy | ❌ Eksik | XSS azaltma katmanı yok |
| Referrer-Policy | ⚠️ Eksik | Referrer sızıntısı ihtimali (düşük etki) |

## 4. TLS SERTİFİKA DURUMU

- **Durum:** ✅ Geçerli
- **Protokol:** TLS 1.3 (güncel)
- **HTTPS Yönlendirmesi:** ✅ Mevcut (HTTP → HTTPS, 301 kalıcı yönlendirme)
- Sertifika süresi geçerlilik aralığı içinde; zincir eksiği gözlemlenmedi.

## 5. SUNUCU/TEKNOLOJİ İMZASI

- **Server:** nginx (sürüm bilgisi gizlenmiş) — ✅ iyi uygulama
- Uygulama çatısı / dil sürümü ifşası gözlemlenmedi.
- Bilgi ifşası oluşturan hata sayfası veya debug çıktısı tespit edilmedi.

## 6. TESPİT EDİLEN RİSKLER

| # | Bulgu | Şiddet | Kısa Açıklama |
|---|-------|--------|----------------|
| 1 | X-Frame-Options başlığı eksik | Orta | Sayfa iframe içine alınıp clickjacking'e açık olabilir |
| 2 | X-Content-Type-Options eksik | Orta | Tarayıcı MIME-sniffing ile içeriği yanlış yorumlayabilir |
| 3 | Content-Security-Policy eksik | Orta | XSS ve içerik enjeksiyonuna karşı azaltma katmanı yok |
| 4 | Referrer-Policy eksik | Düşük | Dış bağlantılara referrer bilgisi sızabilir |

---

## Metodoloji ve Yaklaşım

Bu ön-kontrol YALNIZCA **pasif ve düşük-etkili** tekniklerle yapılır: ana sayfa yanıtı GET ile alınır, TLS el sıkışması `node:tls` ile kurulur ve HTTP güvenlik başlıkları kod düzeyinde çözümlenir. Hiçbir girdi enjekte edilmez, oturum açılmaz, veri değiştirilmez. Gözlemlenen değerler OWASP Secure Headers Project ve endüstri en iyi uygulamalarıyla karşılaştırılır.

## Test Ortamı ve Sınırlamalar

- **Kapsam:** Yalnız `https://ornek-site.com/` ana sayfası (giriş gerektiren alanlar ve alt sayfalar kapsam dışı).
- **Yöntem:** Salt-okunur GET/HEAD; oran sınırı ve 9 sn zaman aşımı korumalı; bant-dışı (OOB) kanal yok.
- **Sınır:** Bulgular tarama anındaki yanıtları yansıtır; sunucu tarafı değişiklikler sonucu etkileyebilir. Bu bir ön-kontroldür, kapsamlı bir denetim değildir.

## Kapsam ve Kontrol Listesi

Çalıştırılan tüm kontroller — geçenler dahil (10 kontrol; 6 temiz, 4 iyileştirme).

| Kontrol | Kapsam | Sonuç |
|---------|--------|-------|
| HTTPS zorunluluğu (HTTP→HTTPS 301) | Ana sayfa | ✅ Geçti |
| TLS sertifika geçerliliği | Sertifika zinciri | ✅ Geçti (66 gün kaldı) |
| TLS protokol sürümü | Handshake | ✅ Geçti (TLS 1.3) |
| Strict-Transport-Security (HSTS) | Yanıt başlığı | ✅ Geçti (max-age=1 yıl) |
| Sunucu sürüm ifşası | `Server` başlığı | ✅ Geçti (gizli) |
| Teknoloji/çatı sürüm ifşası | Yanıt + HTML | ✅ Geçti |
| X-Frame-Options | Yanıt başlığı | ⚠️ Eksik (Orta) |
| X-Content-Type-Options | Yanıt başlığı | ⚠️ Eksik (Orta) |
| Content-Security-Policy | Yanıt başlığı | ⚠️ Eksik (Orta) |
| Referrer-Policy | Yanıt başlığı | ⚠️ Eksik (Düşük) |

## Tarama İstatistikleri

| Ölçüt | Değer |
|-------|-------|
| Taranan sayfa | 1 (ana sayfa) |
| Gönderilen istek | 4 (GET + TLS handshake denemeleri) |
| İncelenen giriş noktası | 0 (pasif; girdi denenmedi) |
| Çalıştırılan kontrol | 10 |
| Tespit edilen bulgu | 4 (0 kritik · 0 yüksek · 3 orta · 1 düşük) |
| Yaklaşık süre | ~8 saniye |

## Sonraki Adımlar

1. **Öncelik 1 (Orta):** X-Frame-Options, X-Content-Type-Options ve Content-Security-Policy başlıklarını ekleyin.
2. **Öncelik 2 (Düşük):** Referrer-Policy başlığını ekleyin.
3. Panoya kopyalanabilir tüm düzeltmeler aşağıdaki **AI Çözüm Önerileri** bölümündedir; uyguladıktan sonra aynı paketle yeniden tarayarak doğrulayın.

---

## Yasal Uyari ve Kapsam

- **Yapay zeka uretimi:** Bu rapor yapay zeka tabanli otomatik bir ajan tarafindan uretilmistir; olgusal ifadeler bagimsiz dogrulanmadan kullanilmamalidir.
- **Kapsam:** Tarama YALNIZCA sahipligi dogrulanmis hedefle ve **pasif** yontemlerle sinirlidir; ic ag, kimlik dogrulamali test ve sizma testi KAPSAM DISIDIR.
- **Resmi degildir:** Bu rapor resmi uyumluluk denetimi/sertifikasyon (ASV/QSA vb.) yerine gecmez.
- **Sorumluluk:** Bulgularin dogrulanmasi ve giderilmesi musterinin sorumlulugundadir.

> **Not:** Bu bir ÖRNEK rapordur. İçerik, gerçek bir taramanın formatını göstermek için anonimleştirilmiş/temsilidir; gerçek bir hedefe ait değildir.
