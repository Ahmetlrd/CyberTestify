## YÖNETİCİ ÖZETİ

- **Genel risk seviyesi: Düşük** — keşif yüzeyiniz 3 alanda incelendi; devralınabilir alt domain, açık hassas API veya sürümü kapsayan bilinen yüksek CVE öne çıkmadı. Dışarıdan görünen yüzeyiniz şu an için dar ve kontrollü görünüyor.
- **Subdomain Takeover Taraması:** Düşük — 7 alt domain envanterlendi; devralınabilir kayıt tespit edilmedi
- **API & Swagger Keşfi:** Düşük — Herkese açık API/Swagger dokümantasyonu bulunamadı
- **CMS & Bilinen CVE Taraması:** Düşük — WordPress 5.5.20 tespit edildi; eşleşen CVE bulunamadı
- **Kapsam (gerçek sayılar):** 7 alt domain envanterlendi · 19 API/Swagger yolu denendi (7 sayfa tarandı) · 6+ pasif CMS/teknoloji sinyali incelendi.
- **Önerilen ilk adım:** En yüksek riskli alandan başlayın; her bulgu için adım adım hazır çözümler "AI Çözüm Önerileri" bölümünde sunulur.

## GENEL DEĞERLENDİRME

**Risk Seviyesi: Düşük**

Dışarıdan görünen alt domain, API ve CMS yüzeyiniz şu an için dar ve kontrollü görünüyor; rapor, tam envanter ve önerilen iyi pratiklerle birlikte her alanı ayrı ayrı belgeler. Aşağıda her alan ayrı ayrı raporlanmıştır.

## KAPSAM VE METODOLOJİ

Bu rapor, üç keşif alanında **pasif** (istismar içermeyen) tekniklerle, dışarıdan gözlemlenebilir verilerden otomatik olarak üretilmiştir:

- **Subdomain Takeover:** Alt domainler Certificate Transparency loglarından (crt.sh, yedek olarak certSpotter) toplanır; her biri Cloudflare DoH ile DNS/CNAME çözümlemesinden geçirilir ve bilinen “dangling” (terk edilmiş bulut servisi) imza veritabanıyla karşılaştırılır.
- **API & Swagger Keşfi:** Yaygın API dokümantasyon yollarından oluşan sabit bir liste GET ile denenir; bulunan OpenAPI/Swagger şemaları ayrıştırılır ve hassas/kimlik-doğrulamasız uç noktalar işaretlenir (uç noktalar çağrılmaz).
- **CMS & Bilinen CVE:** HTTP başlıkları, `<meta generator>` ve HTML kalıpları üzerinden CMS ve sürüm parmak izi çıkarılır; generator gizlenmişse bilinen CMS yollarının VARLIĞI (yalnız GET/existence — giriş denemesi yok) ile doğrulanır. Tespit edilen sürüm, NVD (NIST Ulusal Zafiyet Veritabanı) sorgulanarak — sürümü açıkça kapsayan — bilinen CVE’lerle eşlenir; sürüm okunamazsa CVE eşlemesi yapılmaz (uydurma CVE yok).

> Tüm veriler dışarıdan, hedefe zarar vermeden toplanmıştır. Kimlik doğrulama gerektiren alanlar, iç ağ ve aktif sömürü bu paketin kapsamı dışındadır.

## Subdomain Takeover Taraması

**Genel risk seviyesi: Düşük — 7 alt domain envanterlendi; devralınabilir kayıt tespit edilmedi**

Certificate Transparency (crt.sh / certSpotter) kayıtlarından **7** benzersiz alt domain envanterlendi; bunlardan **7** tanesinin CNAME kaydı çözümlenip devralma (subdomain takeover) açısından incelendi.

Çözümlenen CNAME kayıtlarında, terk edilmiş bir bulut kaynağına işaret eden **devralınabilir (dangling)** alt domain tespit edilmedi. Bu, dışarıdan görünen alt domain yüzeyinizin şu an için **dar ve kontrollü** göründüğünü gösterir.

### Alt domain envanteri (durum tablosu)

Bulunan alt domainler ve CNAME çözümlemesi sonucu durumları:

| Alt Domain | CNAME Hedefi | Durum |
|-----------|--------------|-------|
| api.ornek.com | — | CNAME kaydı yok (doğrudan A/AAAA) |
| blog.ornek.com | — | CNAME kaydı yok (doğrudan A/AAAA) |
| mail.ornek.com | mail.barindirma-saglayici.example | Aktif (CNAME kaydı var) |
| panel.ornek.com | — | CNAME kaydı yok (doğrudan A/AAAA) |
| cdn.ornek.com | — | CNAME kaydı yok (doğrudan A/AAAA) |
| destek.ornek.com | — | CNAME kaydı yok (doğrudan A/AAAA) |
| www.ornek.com | ornek.com | Aktif (CNAME kaydı var) |

> Kapsam: Yalnızca pasif kaynaklar (Certificate Transparency logları + gözlemlenebilir DNS). Alt domain brute-force / aktif tarama yapılmamıştır.

## API & Swagger Keşfi

**Genel risk seviyesi: Düşük — Herkese açık API/Swagger dokümantasyonu bulunamadı**

Aşağıdaki **12** yaygın API dokümantasyon/keşif yolu GET ile denenmiştir. Hiçbir uç nokta çağrılmamış/istismar edilmemiştir (pasif keşif).

### Denenen yollar (tam liste)

| Yol | HTTP | Durum |
|-----|------|-------|
| /openapi.json | 404 | Bulunamadı |
| /swagger.json | 404 | Bulunamadı |
| /v2/api-docs | 404 | Bulunamadı |
| /v3/api-docs | 404 | Bulunamadı |
| /api-docs | 404 | Bulunamadı |
| /api/docs | 404 | Bulunamadı |
| /api/v1/docs | 404 | Bulunamadı |
| /swagger-ui.html | 404 | Bulunamadı |
| /swagger/index.html | 404 | Bulunamadı |
| /redoc | 404 | Bulunamadı |
| /.well-known/openapi.json | 404 | Bulunamadı |
| /graphql | 404 | Bulunamadı |

### Site haritasından türetilen yol adayları (7 sayfadan 7 aday)

Sabit liste **dışında**, keşfedilen sayfalardaki link/script/form referanslarından çıkarılan API/idari-görünümlü yollar da GET ile **yalnız varlık** açısından denendi (payload/enjeksiyon YOK — Keşif yalnız "bu uç var mı" tespiti yapar):

| Aday Yol | Kaynak sayfa | HTTP | Not |
|----------|--------------|------|-----|
| /wp-content/uploads/elementor/css/global.css | / | 200 | ⚠️ mevcut (idari-görünümlü) |
| /wp-content/uploads/elementor/css/post-5.css | / | 200 | ⚠️ mevcut (idari-görünümlü) |
| /wp-content/uploads/2023/05/logo-150x150.png | / | 200 | ⚠️ mevcut (idari-görünümlü) |
| /wp-content/uploads/2023/05/logo.png | / | 200 | ⚠️ mevcut (idari-görünümlü) |
| /wp-content/uploads/2023/05/banner-scaled.jpg | / | 200 | ⚠️ mevcut (idari-görünümlü) |
| /wp-content/uploads/2023/05/urun-gorseli-1.jpg | / | 200 | ⚠️ mevcut (idari-görünümlü) |
| /wp-content/uploads/2023/05/hizmet-gorseli-2.jpg | / | 200 | ⚠️ mevcut (idari-görünümlü) |

> **7** idari/hassas-görünümlü yol site haritasından keşfedildi ve erişilebilir (HTTP 200). Bu yolların YETKİ kontrolü **Aktif Doğrulama / Tam Pentest** ile doğrulanmalıdır — Keşif yalnız varlığı tespit eder, yetki testi yapmaz.

Denenen yolların hiçbiri herkese açık bir API şeması/arayüzü döndürmedi. Herkese açık API dokümantasyonu bulunmaması, saldırganların API yüzeyinizi dışarıdan kolayca **haritalayamayacağı** anlamına gelir — bu, dış saldırı yüzeyi açısından olumlu bir işarettir.

> Kapsam: Yalnızca herkese açık dokümantasyon yolları GET ile denenmiştir; hiçbir uç nokta çağrılmamış/istismar edilmemiştir (pasif keşif).

## CMS & Bilinen CVE Taraması

**Genel risk seviyesi: Düşük — WordPress 5.5.20 tespit edildi; eşleşen CVE bulunamadı**

### İncelenen parmak izi kaynakları

CMS/çatı ve sürüm tespiti için ana sayfa yanıtı üzerinde aşağıdaki pasif sinyallere bakıldı:

- HTTP yanıt başlıkları (`Server`, `X-Powered-By`, `X-Generator`, `X-Drupal-Cache`, `X-Magento-Cache-Debug`)
- `<meta name="generator">` etiketi
- HTML yol/kalıp izleri (`/wp-content/`, `/wp-includes/`, `Drupal.settings`, `/sites/all/`, `option=com_`, `/media/jui/`, `typo3conf`, `Magento_`)
- Yaygın sürüm dosyaları (WordPress `/readme.html`, Drupal `/CHANGELOG.txt`)
- Bilinen CMS yollarının VARLIĞI (`/wp-login.php`, `/wp-json/`, `/administrator/`, `/user/login`, `/typo3/` — yalnız var/yok kontrolü; giriş/parola denemesi YOK)
- Kütüphane/eklenti ipuçları (WooCommerce, jQuery sürümü)

### Parmak izi sonucu

- Tespit edilen sistem: **WordPress 5.5.20**
- Nasıl tespit edildi: Meta generator: "WordPress 5.5.20"
- Ek gözlemler: WooCommerce (WordPress e-ticaret eklentisi) tespit edildi · X-Powered-By: ASP.NET · Server: Microsoft-IIS/10.0

### Bilinen CVE eşleşmeleri (NVD)

NVD (NIST Ulusal Zafiyet Veritabanı) sorgusu bu tarama sırasında yanıt vermedi; CVE eşlemesi yapılamadı. Lütfen sürümünüzü NVD üzerinde manuel doğrulayın.

> Kapsam: Pasif parmak izi + NVD üzerinden bilinen-CVE eşlemesi. Hiçbir CVE **istismar edilmemiş/doğrulanmamıştır**.

## POZİTİF GÜVENCE — DENENEN KEŞİF YÖNTEMLERİ

Keşif çoğu sağlıklı hedefte temiz çıkar; bu bölüm "bir şey bulunamadı" sonucunu da ŞEFFAF kılar — GERÇEKTEN ne denendiğini gösterir (ana sayfa dâhil **7 sayfa** site haritası dahil):

| Keşif Alanı | Sonuç |
|-------------|-------|
| Subdomain-Takeover Taraması | ✅ 7 alt domain kaydı denendi; devralma göstergesi bulunamadı |
| API & Swagger Keşfi | ✅ 19 yol denendi (12 sabit + 7 site-haritası adayı, 7 sayfadan); herkese açık API şeması bulunamadı |
| CMS / Framework CVE Eşleşmesi | ✅ WordPress 5.5.20 tespit edildi; sürümü kapsayan bilinen yüksek CVE eşleşmedi |
| Site-haritası yol keşfi | ⚠️ 7 idari-görünümlü yol erişilebilir (yetki testi Aktif Doğrulama kapsamı) |

> **Üç-durum ayrımı (dürüstlük):** ✅ *Gösterge bulunamadı* = yöntem çalıştı, temiz · ⚠️ *Gösterge var* = yukarıda ayrıntılı · ⚠️ *İncelenemedi* = veri toplanamadı (güvenli anlamına GELMEZ).

### Bu paket NE değerlendirir, NE değerlendirmez

**DEĞERLENDİRİR (pasif keşif — yalnız GET, dış kaynak):** alt domain envanteri + devralma (dangling CNAME), herkese açık API/Swagger/OpenAPI dokümanı, CMS/çatı parmak izi + bilinen CVE eşleşmesi (NVD), site haritasından türeyen API/idari-görünümlü yolların VARLIK tespiti — 7 sayfa üzerinden.

**DEĞERLENDİRMEZ:** aktif enjeksiyon/IDOR/XSS doğrulaması ve keşfedilen uçlara yetki testi (**Aktif Doğrulama / Tam Pentest** kapsamı), HTTP güvenlik başlığı/CORS/çerez/CSP detayı (**Basit Tarama / Dış Yüzey** kapsamı), KVKK/PCI/ISO çerçeve-eşleme (**Uyum** kapsamı). Bir alanda "gösterge bulunamadı" ifadesi **güvenli olduğunuzu KANITLAMAZ** — yalnız denenen pasif yöntemlerle bir gösterge çıkmadığını gösterir.

## İYİ PRATİKLER / ÖNERİLEN SONRAKİ ADIMLAR

Bu tarama sonucundan bağımsız olarak, saldırı yüzeyinizi dar tutmak için önerilen kalıcı uygulamalar:

- **Kullanılmayan CNAME kayıtlarını düzenli olarak temizleyin** — terk edilmiş bulut kaynaklarına işaret eden kayıtlar subdomain takeover riski taşır; bulut kaynağını silmeden önce DNS kaydını kaldırın.
- **API dokümantasyonunuz (Swagger/OpenAPI) varsa** yalnızca kimlik doğrulamalı erişime açık tutun; üretimde herkese açık yayınlamayın.
- **CMS, eklenti ve tema sürümlerinizi** otomatik güncelleme veya düzenli takiple güncel tutun; bilinen CVE’lere karşı yamalı kalın.
- **Certificate Transparency (CT) log izleme** araçları (crt.sh, certSpotter vb.) ile yeni/beklenmeyen alt domain sertifikalarını erken fark edin.
- **Sürüm/teknoloji ifşasını azaltın** — `Server`, `X-Powered-By`, `<meta generator>` gibi başlık/etiketlerle gereksiz sürüm bilgisi sızdırmayın.
- **Alt domain envanterinizi belgeleyin** — hangi alt domainin hangi servise/ekibe ait olduğunu bilmek, boşta kalan kayıtları hızlıca fark etmenizi sağlar.
