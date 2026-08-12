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

## Metodoloji ve Yaklaşım

Testler **"kanıtla — istismar etme"** ilkesiyle yürütülmüştür: her giriş noktasına önce zararsız bir temel istek, ardından ayırt edici tek bir gösterge probu gönderilir; yanıt içeriği veya zamanlama farkından zafiyet **göstergesi** türetilir. Zafiyet sömürülmez, veri çekilmez/değiştirilmez. Yüzey keşfi headless tarayıcıyla yapılmış, giriş noktaları (form alanları, sorgu parametreleri, JSON gövdeleri) çıkarılmıştır. Yaklaşım **OWASP WSTG** aktif test kılavuzuyla uyumludur.

## Test Ortamı ve Sınırlamalar

- **Kapsam:** `ornek-site.com` herkese açık yüzeyi; giriş-arkası alanlar için **Tam Kapsamlı Pentest** paketi gerekir.
- **Güvenlik:** Art arda 5xx/WAF yanıtında **devre kesici** probları durdurur. Yıkıcı yöntemler (DELETE / veri-yazan PUT, gerçek komut, exfiltrasyon, DoS) kod düzeyinde engellidir.
- **Sınır:** Bulgu olmaması, zafiyet olmadığını **kanıtlamaz**. Göstergeler kendi ortamınızda doğrulanmalıdır.

## Kapsam ve Kontrol Listesi

Çalıştırılan tüm kontroller — geçenler dahil (7 kontrol; 3 temiz, 4 gösterge).

| Kontrol | Sonuç | Güven |
|---------|-------|-------|
| SQL Enjeksiyonu (hata/zaman-tabanlı) | ⚠️ Gösterge | Yüksek |
| Yansıyan XSS | ⚠️ Gösterge | Orta |
| IDOR / yetkisiz nesne erişimi | ⚠️ Gösterge | Yüksek |
| SSRF (dış geri-çağırma) | ✅ Gösterge yok | — |
| Açık yönlendirme (open redirect) | ✅ Gösterge yok | — |
| Güvensiz CORS | ⚠️ Gevşek politika | Orta |
| Oturum çerezi bayrakları | ⚠️ `HttpOnly` eksik | Yüksek |

## Tarama İstatistikleri

| Ölçüt | Değer |
|-------|-------|
| Taranan sayfa | 12 |
| Bulunan giriş noktası | 18 (form + sorgu + JSON) |
| Gönderilen prob | 64 (baseline + gösterge) |
| Tespit edilen gösterge | 4 (0 kritik · 2 yüksek · 2 orta) |
| Devre kesici tetiklenmesi | 0 |
| Yaklaşık süre | ~3 dakika |

## Risk Matrisi

| # | Bulgu | Etki | Olasılık | Şiddet |
|---|-------|------|----------|--------|
| 1 | SQL enjeksiyonu (giriş formu) | Yüksek (veri erişimi) | Orta | **Yüksek** |
| 2 | IDOR (sipariş uç noktası) | Yüksek (yetki aşımı) | Orta | **Yüksek** |
| 3 | Yansıyan XSS (arama) | Orta (oturum/hesap) | Orta | **Orta** |
| 4 | Gevşek CORS + çerez bayrakları | Orta (oturum güvenliği) | Orta | **Orta** |

## Standart Eşleme

| Bulgu | OWASP Top 10 (2021) | CWE | WSTG |
|-------|---------------------|-----|------|
| SQL enjeksiyonu | A03: Injection | CWE-89 SQL Injection | WSTG-INPV-05 |
| IDOR | A01: Broken Access Control | CWE-639 Authorization Bypass | WSTG-ATHZ-04 |
| Yansıyan XSS | A03: Injection | CWE-79 Cross-Site Scripting | WSTG-INPV-01 |
| Gevşek CORS / çerez | A05: Security Misconfiguration | CWE-942 / CWE-1004 | WSTG-CLNT-07 |

## İş Etkisi (Business Impact)

- **SQL enjeksiyonu + IDOR (Yüksek):** Kötü niyetli bir kullanıcının başka müşterilerin sipariş/veri kayıtlarına erişme ihtimali — **veri sızıntısı, KVKK bildirim yükümlülüğü ve itibar riski** doğurur. Bu iki bulgu birlikte, hesap sınırlarını aşan bir maruziyet oluşturur.
- **XSS (Orta):** Oturum çalma/kimlik taklidi yoluyla **hesap ele geçirme** ve müşteri güveni kaybı.
- **CORS + çerez (Orta):** Oturum güvenliğini zayıflatarak yukarıdaki senaryoların **başarı olasılığını artırır**.

## Önceliklendirilmiş Yol Haritası + Yeniden Test

1. **Hemen (0-3 gün):** Parametreli sorgu (SQLi) + sunucu-tarafı yetki kontrolü (IDOR). En yüksek etki burada.
2. **Kısa vade (1-2 hafta):** Çıktı kodlaması + CSP (XSS); çerezlere `HttpOnly; Secure; SameSite`; CORS'u güvenilen origin'lerle sınırlayın.
3. **Yeniden test:** Düzeltmelerden sonra **aynı paketle** SQLi, IDOR ve XSS giriş noktalarını yeniden çalıştırıp göstergelerin kapandığını doğrulayın.

## Ekler (Appendix)

**Ek-A: Taranan giriş noktaları (özet)**

| Uç nokta / alan | Tür | Kontrol |
|-----------------|-----|---------|
| `/login` → `username` | Form | SQLi |
| `/search` → `q` | Sorgu | XSS |
| `/api/v1/orders/{id}` | REST | IDOR |
| `/profile` → `avatar_url` | Form | SSRF (temiz) |

**Ek-B: Prob özeti** — 64 prob gönderildi (18 giriş noktası × baseline + gösterge). Tüm problar zararsız/geri-alınamaz-etkisizdir; hiçbir veri değiştirilmemiştir.

## Sonraki Adımlar

1. **Öncelik 1 (Yüksek):** SQLi ve IDOR göstergelerini doğrulayıp giderin.
2. **Öncelik 2 (Orta):** XSS, CORS ve çerez bayraklarını düzeltin.
3. Panoya kopyalanabilir tüm düzeltmeler aşağıdaki **AI Çözüm Önerileri** bölümündedir.

---

## Yasal Uyari ve Kapsam

- **Kanıt ilkesi:** Aktif kontroller yalnızca **var-yok doğrulaması** için düşük-etkili sondalarla yürütülmüştür; hiçbir zafiyet sömürülmemiş, veri çekilmemiş/değiştirilmemiştir.
- **Kapsam:** Test YALNIZCA sahipliği doğrulanmış hedefe yönelik ve yetkilendirilmiş kapsamla sınırlıdır; iç ağ ve tam sızma testi KAPSAM DIŞIDIR.
- **Resmi değildir:** Bu rapor resmi uyumluluk denetimi/sertifikasyon (ASV/QSA vb.) yerine geçmez.
- **Sorumluluk:** Bulguların doğrulanması ve giderilmesi müşterinin sorumluluğundadır.

> **Not:** Bu bir ÖRNEK rapordur. İçerik, gerçek bir taramanın formatını göstermek için anonimleştirilmiş/temsilidir; gerçek bir hedefe ait değildir.
