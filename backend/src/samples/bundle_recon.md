## YÖNETİCİ ÖZETİ

- **Genel risk seviyesi: Yüksek** — 3 alan incelendi; en yüksek risk **CMS & Bilinen CVE Taraması** alanında (Bilinen bir CMS parmak izi tespit edilmedi · sunucu/yazılım sürümünde 21 bilinen CVE).
- ⚠️ **HTTPS desteklenmiyor:** Hedef HTTPS (443) üzerinden yanıt vermedi; keşif http:// üzerinden yürütüldü. Şifresiz iletişim başlı başına ciddi bir bulgudur (aşağıda).
- **Subdomain Takeover Taraması:** Düşük — Sertifika şeffaflığı kayıtlarında alt domain görülmedi
- **API & Swagger Keşfi:** Düşük — Herkese açık API/Swagger dokümantasyonu bulunamadı
- **CMS & Bilinen CVE Taraması:** Yüksek — Bilinen bir CMS parmak izi tespit edilmedi · sunucu/yazılım sürümünde 21 bilinen CVE
- **Kapsam (gerçek sayılar):** 0 alt domain envanterlendi · 12 API/Swagger yolu denendi (2 sayfa tarandı) · 6+ pasif CMS/teknoloji sinyali incelendi.
- **Önerilen ilk adım:** En yüksek riskli alandan başlayın; her bulgu için adım adım hazır çözümler "AI Çözüm Önerileri" bölümünde sunulur.

## GENEL DEĞERLENDİRME

**Risk Seviyesi: Yüksek**

Bu hedef HTTPS üzerinden yanıt vermiyor; iletişim şifresiz taşınıyor (öncelikli olarak HTTPS’e geçilmelidir). En yüksek risk **CMS & Bilinen CVE Taraması** alanında (Bilinen bir CMS parmak izi tespit edilmedi · sunucu/yazılım sürümünde 21 bilinen CVE) tespit edildi; öncelikli olarak giderilmesi önerilir. Aşağıda her alan ayrı ayrı raporlanmıştır.

## TESPİT EDİLEN RİSKLER

| Bulgu | Şiddet | Açıklama |
|-------|--------|----------|
| HTTPS desteklenmiyor (şifresiz iletişim) | Yüksek | Hedef HTTPS'e yanıt vermiyor; tüm trafik şifresiz (düz metin) taşınıyor — dinlenebilir/değiştirilebilir. Çözüm: geçerli TLS sertifikası + HTTP→HTTPS yönlendirme + HSTS. |
| CMS & Bilinen CVE Taraması — Bilinen bir CMS parmak izi tespit edilmedi · sunucu/yazılım sürümünde 21 bilinen CVE | Yüksek | Ayrıntı aşağıdaki “CMS & Bilinen CVE Taraması” bölümündedir. |

## KAPSAM VE METODOLOJİ

Bu rapor, üç keşif alanında **pasif** (istismar içermeyen) tekniklerle, dışarıdan gözlemlenebilir verilerden otomatik olarak üretilmiştir:

- **Subdomain Takeover:** Alt domainler Certificate Transparency loglarından (crt.sh, yedek olarak certSpotter) toplanır; her biri Cloudflare DoH ile DNS/CNAME çözümlemesinden geçirilir ve bilinen “dangling” (terk edilmiş bulut servisi) imza veritabanıyla karşılaştırılır.
- **API & Swagger Keşfi:** Yaygın API dokümantasyon yollarından oluşan sabit bir liste GET ile denenir; bulunan OpenAPI/Swagger şemaları ayrıştırılır ve hassas/kimlik-doğrulamasız uç noktalar işaretlenir (uç noktalar çağrılmaz).
- **CMS & Bilinen CVE:** HTTP başlıkları, `<meta generator>` ve HTML kalıpları üzerinden CMS ve sürüm parmak izi çıkarılır; generator gizlenmişse bilinen CMS yollarının VARLIĞI (yalnız GET/existence — giriş denemesi yok) ile doğrulanır. Tespit edilen sürüm, NVD (NIST Ulusal Zafiyet Veritabanı) sorgulanarak — sürümü açıkça kapsayan — bilinen CVE’lerle eşlenir; sürüm okunamazsa CVE eşlemesi yapılmaz (uydurma CVE yok).

> Tüm veriler dışarıdan, hedefe zarar vermeden toplanmıştır. Kimlik doğrulama gerektiren alanlar, iç ağ ve aktif sömürü bu paketin kapsamı dışındadır.

## Subdomain Takeover Taraması

**Genel risk seviyesi: Düşük — Sertifika şeffaflığı kayıtlarında alt domain görülmedi**

Certificate Transparency (crt.sh / certSpotter) kayıtlarından **0** benzersiz alt domain envanterlendi; bunlardan **0** tanesinin CNAME kaydı çözümlenip devralma (subdomain takeover) açısından incelendi.

Çözümlenen CNAME kayıtlarında, terk edilmiş bir bulut kaynağına işaret eden **devralınabilir (dangling)** alt domain tespit edilmedi. Bu, dışarıdan görünen alt domain yüzeyinizin şu an için **dar ve kontrollü** göründüğünü gösterir.

> Kapsam: Yalnızca pasif kaynaklar (Certificate Transparency logları + gözlemlenebilir DNS). Alt domain brute-force / aktif tarama yapılmamıştır.

## API & Swagger Keşfi

**Genel risk seviyesi: Düşük — Herkese açık API/Swagger dokümantasyonu bulunamadı**

Aşağıdaki **12** yaygın API dokümantasyon/keşif yolu GET ile denenmiştir. Hiçbir uç nokta çağrılmamış/istismar edilmemiştir (pasif keşif).

### Denenen yollar (tam liste)

| Yol | HTTP | Durum |
|-----|------|-------|
| /openapi.json | 404 | Bulunamadı |
| /swagger.json | 404 | Bulunamadı |
| /v2/api-docs | 400 | Bulunamadı |
| /v3/api-docs | 400 | Bulunamadı |
| /api-docs | 404 | Bulunamadı |
| /api/docs | 400 | Bulunamadı |
| /api/v1/docs | 400 | Bulunamadı |
| /swagger-ui.html | 404 | Bulunamadı |
| /swagger/index.html | 400 | Bulunamadı |
| /redoc | 404 | Bulunamadı |
| /.well-known/openapi.json | 400 | Bulunamadı |
| /graphql | 404 | Bulunamadı |

Denenen yolların hiçbiri herkese açık bir API şeması/arayüzü döndürmedi. Herkese açık API dokümantasyonu bulunmaması, saldırganların API yüzeyinizi dışarıdan kolayca **haritalayamayacağı** anlamına gelir — bu, dış saldırı yüzeyi açısından olumlu bir işarettir.

> Kapsam: Yalnızca herkese açık dokümantasyon yolları GET ile denenmiştir; hiçbir uç nokta çağrılmamış/istismar edilmemiştir (pasif keşif).

## CMS & Bilinen CVE Taraması

**Genel risk seviyesi: Yüksek — Bilinen bir CMS parmak izi tespit edilmedi · sunucu/yazılım sürümünde 21 bilinen CVE**

### İncelenen parmak izi kaynakları

CMS/çatı ve sürüm tespiti için ana sayfa yanıtı üzerinde aşağıdaki pasif sinyallere bakıldı:

- HTTP yanıt başlıkları (`Server`, `X-Powered-By`, `X-Generator`, `X-Drupal-Cache`, `X-Magento-Cache-Debug`)
- `<meta name="generator">` etiketi
- HTML yol/kalıp izleri (`/wp-content/`, `/wp-includes/`, `Drupal.settings`, `/sites/all/`, `option=com_`, `/media/jui/`, `typo3conf`, `Magento_`)
- Yaygın sürüm dosyaları (WordPress `/readme.html`, Drupal `/CHANGELOG.txt`)
- Bilinen CMS yollarının VARLIĞI (`/wp-login.php`, `/wp-json/`, `/administrator/`, `/user/login`, `/typo3/` — yalnız var/yok kontrolü; giriş/parola denemesi YOK)
- Kütüphane/eklenti ipuçları (WooCommerce, jQuery sürümü)

Bu sinyallerin **hiçbiri** bilinen bir CMS/çatı ile eşleşmedi. Bu, özel geliştirilmiş bir uygulama veya CMS izlerini bilinçli olarak gizleyen bir kurulum olabileceğine işaret eder; her iki durum da dışarıdan otomatik CMS/CVE eşlemesini zorlaştırır.

### Sunucu/Yazılım Banner Sürümü — Bilinen CVE (NVD)

Banner'dan çıkan sürüm(ler) NVD'ye bağlandı (istismar/doğrulama YOK — yalnız "bu sürüm için bilinen CVE var mı" göstergesi):

| Yazılım/Sürüm | NVD sonucu | Örnek CVE |
|-----|-------|-------|
| Apache httpd 2.4.25 | sorgulanamadı (temiz DEĞİL) | — |
| PHP 7.1.26 | ⚠️ 21 bilinen CVE | [CVE-2017-8923](https://nvd.nist.gov/vuln/detail/CVE-2017-8923) |

> **Not:** Aşağıdaki CVE listesi, tespit edilen sürümle NVD (NIST Ulusal Zafiyet Veritabanı) üzerinden **otomatik eşlenen** bilinen zafiyetlerdir; sürümünüz için sömürülebilir oldukları **doğrulanmamıştır** ve bir kısmı eklenti/tema kaynaklı olabilir. Kesin durum için güncelleme + hedefli doğrulama önerilir.

> Kapsam: Pasif parmak izi + NVD üzerinden bilinen-CVE eşlemesi. Hiçbir CVE **istismar edilmemiş/doğrulanmamıştır**.

## POZİTİF GÜVENCE — DENENEN KEŞİF YÖNTEMLERİ

Keşif çoğu sağlıklı hedefte temiz çıkar; bu bölüm "bir şey bulunamadı" sonucunu da ŞEFFAF kılar — GERÇEKTEN ne denendiğini gösterir (ana sayfa dâhil **2 sayfa** site haritası dahil):

| Keşif Alanı | Sonuç |
|-------------|-------|
| Subdomain-Takeover Taraması | ✅ 0 alt domain kaydı denendi; devralma göstergesi bulunamadı |
| API & Swagger Keşfi | ✅ 12 yol denendi (12 sabit + 0 site-haritası adayı, 2 sayfadan); herkese açık API şeması bulunamadı |
| CMS / Framework CVE Eşleşmesi | ✅ Bilinen bir CMS/çatı parmak izi tespit edilmedi |
| Sunucu/Yazılım Banner → Bilinen CVE | ⚠️ Banner sürümünde 21 bilinen CVE (PHP 7.1.26) |
| Site haritası + robots.txt yol keşfi | ✅ Site haritası + robots.txt Disallow’dan türetilen 0 yol denendi (yalnız varlık); hassas/idari uç bulunamadı |

> **Üç-durum ayrımı (dürüstlük):** ✅ *Gösterge bulunamadı* = yöntem çalıştı, temiz · ⚠️ *Gösterge var* = yukarıda ayrıntılı · ⚠️ *İncelenemedi* = veri toplanamadı (güvenli anlamına GELMEZ).

### Bu paket NE değerlendirir, NE değerlendirmez

**DEĞERLENDİRİR (pasif keşif — yalnız GET, dış kaynak):** alt domain envanteri + devralma (dangling CNAME), herkese açık API/Swagger/OpenAPI dokümanı, CMS/çatı ve sunucu/yazılım banner (Apache/nginx/PHP) parmak izi + bilinen CVE eşleşmesi (NVD), site haritası + robots.txt Disallow'dan türeyen API/idari-görünümlü yolların VARLIK tespiti — 2 sayfa üzerinden.

**DEĞERLENDİRMEZ:** aktif enjeksiyon/IDOR/XSS doğrulaması ve keşfedilen uçlara yetki testi (**Aktif Doğrulama / Tam Pentest** kapsamı), HTTP güvenlik başlığı/CORS/çerez/CSP detayı (**Basit Tarama / Dış Yüzey** kapsamı), KVKK/PCI/ISO çerçeve-eşleme (**Uyum** kapsamı). Bir alanda "gösterge bulunamadı" ifadesi **güvenli olduğunuzu KANITLAMAZ** — yalnız denenen pasif yöntemlerle bir gösterge çıkmadığını gösterir.

## İYİ PRATİKLER / ÖNERİLEN SONRAKİ ADIMLAR

Bu tarama sonucundan bağımsız olarak, saldırı yüzeyinizi dar tutmak için önerilen kalıcı uygulamalar:

- **Kullanılmayan CNAME kayıtlarını düzenli olarak temizleyin** — terk edilmiş bulut kaynaklarına işaret eden kayıtlar subdomain takeover riski taşır; bulut kaynağını silmeden önce DNS kaydını kaldırın.
- **API dokümantasyonunuz (Swagger/OpenAPI) varsa** yalnızca kimlik doğrulamalı erişime açık tutun; üretimde herkese açık yayınlamayın.
- **CMS, eklenti ve tema sürümlerinizi** otomatik güncelleme veya düzenli takiple güncel tutun; bilinen CVE’lere karşı yamalı kalın.
- **Certificate Transparency (CT) log izleme** araçları (crt.sh, certSpotter vb.) ile yeni/beklenmeyen alt domain sertifikalarını erken fark edin.
- **Sürüm/teknoloji ifşasını azaltın** — `Server`, `X-Powered-By`, `<meta generator>` gibi başlık/etiketlerle gereksiz sürüm bilgisi sızdırmayın.
- **Alt domain envanterinizi belgeleyin** — hangi alt domainin hangi servise/ekibe ait olduğunu bilmek, boşta kalan kayıtları hızlıca fark etmenizi sağlar.
