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

## Yasal Uyari ve Kapsam

- **Yapay zeka uretimi:** Bu rapor yapay zeka tabanli otomatik bir ajan tarafindan uretilmistir; olgusal ifadeler bagimsiz dogrulanmadan kullanilmamalidir.
- **Hukuki gorus degildir:** Bu rapor bir hukuki gorus/uyum beyani DEGILDIR; farkindalik ve eksik tespiti amaclidir, nihai degerlendirme icin KVKK uzmani/avukat gerekir.
- **Kapsam:** Tarama YALNIZCA sahipligi dogrulanmis hedefin herkese acik sayfalariyla ve **pasif** yontemlerle sinirlidir.
- **Sorumluluk:** Bulgularin dogrulanmasi ve giderilmesi musterinin sorumlulugundadir.

> **Not:** Bu bir ÖRNEK rapordur. İçerik, gerçek bir taramanın formatını göstermek için temsilidir; gerçek bir hedefe ait değildir.
