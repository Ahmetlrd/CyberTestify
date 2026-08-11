# Guvenlik Tarama Raporu

**Hedef:** ornek-site.com
**Paket:** Aktif Doğrulama Paketi
**Olusturma tarihi:** 2026-01-15T10:00:00.000Z

---

## Bulgular

# ornek-site.com — Aktif Doğrulama Raporu

## 1. YÖNETİCİ ÖZETİ

ornek-site.com üzerinde, **kanıtla-istismar-etme** (proof-not-exploit) ilkesiyle, güvenli ve doğrulayıcı aktif kontroller çalıştırıldı. Amaç zafiyeti sömürmek değil, **var olduğunu düşük-etkili bir göstergeyle doğrulamaktır.** Bir giriş formu parametresinde **olası SQL enjeksiyonu** göstergesi ve bir arama alanında **yansıyan XSS** göstergesi elde edildi. Ayrıca bir kaynak uç noktasında **IDOR** (yetkisiz nesne erişimi) sinyali gözlemlendi. **Genel risk seviyesi: Yüksek** — enjeksiyon göstergeleri öncelikli doğrulama gerektirir.

## 2. KONTROL ÖZETİ (7 Aktif Kontrol)

| # | Kontrol | Sonuç |
|---|---------|-------|
| 1 | SQL Enjeksiyonu (hata/zaman tabanlı gösterge) | ⚠️ Gösterge var |
| 2 | Yansıyan XSS (güvenli işaret enjeksiyonu) | ⚠️ Gösterge var |
| 3 | IDOR / yetkisiz nesne erişimi | ⚠️ Gösterge var |
| 4 | SSRF (dış geri-çağırma denemesi) | ✅ Gösterge yok |
| 5 | Açık yönlendirme (open redirect) | ✅ Gösterge yok |
| 6 | Güvensiz CORS yapılandırması | ⚠️ Gevşek politika |
| 7 | Kimlik doğrulama / oturum çerezi bayrakları | ⚠️ `HttpOnly` eksik |

## 3. ENJEKSİYON GÖSTERGELERİ (Kanıt, İstismar Değil)

**3.1 Olası SQL Enjeksiyonu — giriş formu `username` parametresi**
- Güvenli bir zaman-tabanlı sonda (`' AND SLEEP(0)-- -` benzeri, zarar vermeyen) ile yanıt süresinde tutarlı sapma gözlemlendi.
- **İstismar edilmedi; veri çekilmedi.** Yalnızca parametrenin sorguya süzülebildiğine dair gösterge kaydedildi.

**3.2 Yansıyan XSS — `q` arama parametresi**
- Zararsız bir işaret dizesi yanıtta kodlanmadan geri yansıdı (çıktı kodlaması eksik göstergesi).
- Tarayıcıda script çalıştırılmadı; yalnızca yansıma doğrulandı.

## 4. IDOR / YETKİLENDİRME GÖSTERGESİ

- `GET /api/v1/orders/1001` çağrısında, oturum sahibine ait olmayan bir kaydın alanları döndü (kimlik parametresi manipülasyonu).
- **Veri sızdırılmadı**; yalnızca yetki sınırının aşılabildiğine dair sinyal kaydedildi.

## 5. TESPİT EDİLEN RİSKLER

| # | Bulgu | Şiddet | Kısa Açıklama |
|---|-------|--------|----------------|
| 1 | Olası SQL enjeksiyonu (giriş formu) | Yüksek | Parametre sorguya süzülebiliyor (gösterge) |
| 2 | Yansıyan XSS (arama) | Orta | Çıktı kodlaması eksik göstergesi |
| 3 | IDOR (sipariş uç noktası) | Yüksek | Yetkisiz nesneye erişim sinyali |
| 4 | Gevşek CORS + eksik çerez bayrakları | Orta | Oturum güvenliği zayıflatıcı yapılandırma |

---

## Yasal Uyari ve Kapsam

- **Kanıt ilkesi:** Aktif kontroller yalnızca **var-yok doğrulaması** için düşük-etkili sondalarla yürütülmüştür; hiçbir zafiyet sömürülmemiş, veri çekilmemiş/değiştirilmemiştir.
- **Kapsam:** Test YALNIZCA sahipliği doğrulanmış hedefe yönelik ve yetkilendirilmiş kapsamla sınırlıdır; iç ağ ve tam sızma testi KAPSAM DIŞIDIR.
- **Resmi değildir:** Bu rapor resmi uyumluluk denetimi/sertifikasyon (ASV/QSA vb.) yerine geçmez.
- **Sorumluluk:** Bulguların doğrulanması ve giderilmesi müşterinin sorumluluğundadır.

> **Not:** Bu bir ÖRNEK rapordur. İçerik, gerçek bir taramanın formatını göstermek için anonimleştirilmiş/temsilidir; gerçek bir hedefe ait değildir.
