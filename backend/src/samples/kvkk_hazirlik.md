# Guvenlik Tarama Raporu

**Hedef:** ornek-site.com
**Paket:** KVKK Ön Uyum Kontrolü
**Olusturma tarihi:** 2026-01-15T10:00:00.000Z

---

## Bulgular

# ornek-site.com KVKK Ön Uyum Kontrolü

## Yönetici Özeti

ornek-site.com'un herkese açık sayfaları, KVKK ilkeleri açısından dışarıdan gözlemlenebilir eksikler için pasif olarak incelenmiştir. Bir gizlilik/aydınlatma metni mevcut olmakla birlikte, çerez rızası yönetimi ve veri sorumlusu/VERBİS bilgilerinde iyileştirme alanları tespit edilmiştir. **Bu rapor hukuki görüş/uyum beyanı değildir; nihai değerlendirme için KVKK uzmanı/avukat gerekir.**

## KVKK İlkeleri — Gözlem Tablosu

| KVKK İlkesi/Konu | Gözlem | Durum | Öneri |
|------------------|--------|-------|-------|
| Aydınlatma metni / Gizlilik politikası | `/gizlilik-politikasi` sayfası erişilebilir | Uygun | Güncel tutun, veri kategorilerini netleştirin |
| Çerez rızası (consent) | Banner var; ancak rızadan ÖNCE analytics çerezi bırakılıyor | Dikkat | Rıza öncesi izleyici çerezleri bloklayın (opt-in) |
| Kişisel veri toplayan formlar | İletişim formu HTTPS üzerinde | Uygun | Açık rıza onay kutusu + aydınlatma bağlantısı ekleyin |
| Veri sorumlusu / İletişim / VERBİS | İletişim bilgisi var; VERBİS atfı gözlemlenmedi | Eksik | Veri sorumlusu kimliği ve VERBİS kaydına atıf ekleyin |
| Üçüncü taraf izleyiciler | Google Analytics ve Meta Pixel gözlemlendi | Dikkat | Aydınlatma metninde 3. taraf aktarımı açıklayın |

## Öne Çıkan Öneriler

1. **Çerez yönetimi:** Rıza alınmadan önce zorunlu olmayan (analytics/pazarlama) çerezlerin bırakılmaması için bir onay (CMP) mekanizması kurun.
2. **VERBİS/Veri sorumlusu:** Sitede veri sorumlusunun kimliği ve VERBİS kayıt durumuna açık atıf yapın.
3. **Açık rıza:** Kişisel veri toplayan formlara ayrı, işaretlenmemiş bir açık rıza kutusu ekleyin.

---

## Metodoloji ve Yaklaşım

Bu ön-değerlendirme, hedefin **herkese açık sayfalarını pasif olarak** inceleyerek KVKK'nın dışarıdan gözlemlenebilir hazırlık göstergelerini derler: aydınlatma/gizlilik metninin varlığı, çerez rıza (CMP) davranışı, rıza öncesi bırakılan çerezler, üçüncü taraf izleyiciler ve veri toplayan formların taşıma güvenliği kod düzeyinde gözlemlenir. Kesin bir uyum hükmü KURULMAZ; nötr durum etiketleri (**Uygun / Dikkat / Eksik**) kullanılır.

## Test Ortamı ve Sınırlamalar

- **Kapsam:** Yalnız herkese açık sayfalar; iç süreçler, politika/sözleşme belgeleri, VERBİS kaydının içeriği ve idari tedbirler **kapsam dışıdır**.
- **Yöntem:** Salt-okunur GET; kimlik doğrulama yapılmadı.
- **Sınır:** Bu rapor bir **hukuki görüş veya resmî uyum denetimi değildir**; nihai değerlendirme için KVKK uzmanı/avukat gereklidir.

## Kapsam ve Kontrol Listesi

Gözlemlenen tüm KVKK göstergeleri — uygun olanlar dahil (5 alan; 2 uygun, 3 iyileştirme).

| KVKK Konusu | Gözlem | Durum |
|-------------|--------|-------|
| Aydınlatma / gizlilik metni | `/gizlilik-politikasi` erişilebilir | ✅ Uygun |
| Kişisel veri formu — taşıma | İletişim formu HTTPS üzerinde | ✅ Uygun |
| Çerez rızası (CMP) | Rızadan ÖNCE analytics çerezi bırakılıyor | ⚠️ Dikkat |
| Üçüncü taraf izleyiciler | Google Analytics + Meta Pixel | ⚠️ Dikkat |
| Veri sorumlusu / VERBİS atfı | Gözlemlenmedi | ❌ Eksik |

## Tarama İstatistikleri

| Ölçüt | Değer |
|-------|-------|
| İncelenen sayfa | 4 (ana sayfa, gizlilik, iletişim, form) |
| Tespit edilen üçüncü taraf izleyici | 2 (Google Analytics, Meta Pixel) |
| Rıza öncesi bırakılan çerez | Var (analytics) |
| Veri toplayan form | 1 (iletişim; HTTPS) |
| Gözlemlenen KVKK alanı | 5 |
| Yaklaşık süre | ~15 saniye |

## Standart Eşleme (KVKK)

| Gözlem | İlgili KVKK Dayanağı |
|--------|----------------------|
| Aydınlatma metni | KVKK m.10 (Aydınlatma yükümlülüğü) |
| Çerez rızası / açık rıza | KVKK m.5-6 (İşleme şartları / açık rıza) |
| Üçüncü taraf izleyici aktarımı | KVKK m.8-9 (Yurt içi/yurt dışı aktarım) |
| Veri sorumlusu / VERBİS | KVKK m.16 (VERBİS kayıt yükümlülüğü) |

> Not: Yukarıdaki eşleme farkındalık amaçlıdır; bir uyum beyanı oluşturmaz.

## Sonraki Adımlar

1. **Öncelik 1:** Rıza öncesi zorunlu-olmayan çerezleri bloklayan bir CMP (opt-in) kurun; formlara ayrı açık rıza kutusu ekleyin.
2. **Öncelik 2:** Veri sorumlusu kimliğini ve VERBİS kayıt durumuna atfı siteye ekleyin; aydınlatma metninde üçüncü taraf aktarımını açıklayın.
3. **Nihai değerlendirme** için KVKK uzmanı/avukat ile çalışın. Panoya alınabilir adımlar **AI Çözüm Önerileri** bölümündedir.

---

## Yasal Uyari ve Kapsam

- **Yapay zeka uretimi:** Bu rapor yapay zeka tabanli otomatik bir ajan tarafindan uretilmistir; olgusal ifadeler bagimsiz dogrulanmadan kullanilmamalidir.
- **Hukuki gorus degildir:** Bu rapor bir hukuki gorus/uyum beyani DEGILDIR; farkindalik ve eksik tespiti amaclidir, nihai degerlendirme icin KVKK uzmani/avukat gerekir.
- **Kapsam:** Tarama YALNIZCA sahipligi dogrulanmis hedefin herkese acik sayfalariyla ve **pasif** yontemlerle sinirlidir.
- **Sorumluluk:** Bulgularin dogrulanmasi ve giderilmesi musterinin sorumlulugundadir.

> **Not:** Bu bir ÖRNEK rapordur. İçerik, gerçek bir taramanın formatını göstermek için temsilidir; gerçek bir hedefe ait değildir.
