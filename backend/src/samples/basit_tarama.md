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

## 7. AI Çözüm Önerileri (Eklenti)

> Bu bölüm **AI Çözüm Önerileri** eklentisiyle açılır. Aşağıda örnek içerik, eklentinin sunduğu somut düzeltme rehberinin formatını gösterir.

**1. X-Frame-Options ekleyin**
nginx yapılandırmanıza şu satırı ekleyin:
```
add_header X-Frame-Options "SAMEORIGIN" always;
```

**2. X-Content-Type-Options ekleyin**
```
add_header X-Content-Type-Options "nosniff" always;
```

**3. Content-Security-Policy tanımlayın**
Sitenize uygun temel bir politika ile başlayın, sonra sıkılaştırın:
```
add_header Content-Security-Policy "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'" always;
```

**4. Referrer-Policy ekleyin**
```
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

Değişikliklerden sonra `nginx -t` ile doğrulayıp yeniden yükleyin (`systemctl reload nginx`).

---

## Yasal Uyari ve Kapsam

- **Yapay zeka uretimi:** Bu rapor yapay zeka tabanli otomatik bir ajan tarafindan uretilmistir; olgusal ifadeler bagimsiz dogrulanmadan kullanilmamalidir.
- **Kapsam:** Tarama YALNIZCA sahipligi dogrulanmis hedefle ve **pasif** yontemlerle sinirlidir; ic ag, kimlik dogrulamali test ve sizma testi KAPSAM DISIDIR.
- **Resmi degildir:** Bu rapor resmi uyumluluk denetimi/sertifikasyon (ASV/QSA vb.) yerine gecmez.
- **Sorumluluk:** Bulgularin dogrulanmasi ve giderilmesi musterinin sorumlulugundadir.

> **Not:** Bu bir ÖRNEK rapordur. İçerik, gerçek bir taramanın formatını göstermek için anonimleştirilmiş/temsilidir; gerçek bir hedefe ait değildir.
