> ### Değerlendirme Özeti
> **7 aktif güvenlik kontrol kategorisinin tamamı değerlendirildi.** **8** benzersiz sayfa/uç nokta tarandı, **19** giriş noktası test edildi, toplam **149** istek gönderildi. **2** kontrolde yüksek/kritik seviyeli zafiyet göstergesi bulundu (aşağıda detaylı).
>
> _Keşif yöntemi: Bu tarama, JavaScript ile render edilen (SPA) hedef tespit edildiği için sayfalar **headless tarayıcı ile render edilerek** gerçekleştirilmiştir._

## YÖNETİCİ ÖZETİ

- **Genel risk seviyesi: Yüksek** — en yüksek risk **Enjeksiyon (SQLi/XSS) Doğrulama** alanında (aktif doğrulama ile enjeksiyon zafiyeti KANITLANDI.).
- **Kapsam dürüstlüğü:** Bu paket, kimlik doğrulaması **gerektirmeyen dış yüzeye** odaklanır — herkese açık uç noktalar (açık formlar/API'lar, arama, login/kayıt akışının kendisi). IDOR / İş Mantığı / Race-Mass-Assignment kontrolleri **yalnızca login-öncesi erişilebilir yüzeyde** (ör. genel API'lar, herkese açık id-tabanlı uç noktalar) çalışır; bu nedenle bu kategorilerde bazı hedeflerde **sınırlı veya "İncelenemedi"** sonuç normal ve beklenendir (siteye özgü yüzey azlığından; motor eksikliğinden değil). Login-**sonrası** oturum içi derin yetkilendirme/iş mantığı zafiyetleri kapsam dışıdır, **Tam Kapsamlı Pentest**'te ele alınır. Bu taramada en güçlü sonuç **Enjeksiyon (SQLi/XSS) Doğrulama** alanında tespit edilmiştir.
- **API saldırı yüzeyi:** **1** API uç noktası keşfedildi ancak **kimlik doğrulama gerektiriyor** (401/403) — kimlik-doğrulamalı derin test bu paketin kapsamı dışında olduğundan probe edilmedi (Tam Kapsamlı Pentest önerilir).
- **Enjeksiyon (SQLi/XSS) Doğrulama:** Yüksek — aktif doğrulama ile enjeksiyon zafiyeti KANITLANDI.
- **Yetkisiz Erişim (IDOR) Doğrulama:** Orta-Yüksek — kimlik doğrulaması olmadan komşu ID ile farklı kaynağa erişim göstergesi bulundu.
- **SSRF Doğrulama:** Düşük — belirgin bir zafiyet göstergesi bulunamadı.
- **Dosya Yükleme Doğrulama:** Düşük — hedefe ulaşıldı ancak bu kontrol için test edilebilir bir giriş/uç nokta saptanmadı; gerçek doğrulama probu çalıştırılamadı. Bu sonuç sitenin güvenli olduğu anlamına GELMEZ — yalnızca test edilebilir bir yüzey bulunamadığını gösterir.
- **İş Mantığı Doğrulama:** Düşük — hedefe ulaşıldı ancak bu kontrol için test edilebilir bir giriş/uç nokta saptanmadı; gerçek doğrulama probu çalıştırılamadı. Bu sonuç sitenin güvenli olduğu anlamına GELMEZ — yalnızca test edilebilir bir yüzey bulunamadığını gösterir.
- **Race / Mass-Assignment Doğrulama:** Düşük — hedefe ulaşıldı ancak bu kontrol için test edilebilir bir giriş/uç nokta saptanmadı; gerçek doğrulama probu çalıştırılamadı. Bu sonuç sitenin güvenli olduğu anlamına GELMEZ — yalnızca test edilebilir bir yüzey bulunamadığını gösterir.
- **RCE / Komut Enjeksiyonu Doğrulama:** Düşük — belirgin bir zafiyet göstergesi bulunamadı.
- **Giriş Baypası (SQLi Göstergesi):** Yüksek — aktif doğrulama ile zafiyet göstergesi KANITLANDI.
- **Şeffaflık:** 8/7 kontrol veri toplayabildi; **8** benzersiz sayfa, **19** giriş noktası (JS render sırasında gözlemlenen API uçları dâhil), **149** istek. SSRF/RCE tespitleri OOB altyapısı olmadan zaman-tabanlı/dolaylı (orta güven); gözlemsel kontroller (Dosya Yükleme/İş Mantığı/Race) kesin doğrulama için manuel test gerektirir.
- **Önerilen ilk adım:** Çalıştırılan kontrollerdeki bulguları giderin; hazır adımlar "AI Çözüm Önerileri" bölümünde.

## GENEL DEĞERLENDİRME

**Risk Seviyesi: Yüksek**

Çalıştırılan kontrollerde en yüksek risk **Enjeksiyon (SQLi/XSS) Doğrulama** alanında (aktif doğrulama ile enjeksiyon zafiyeti KANITLANDI.) tespit edildi; öncelikli olarak giderilmesi/doğrulanması önerilir. 8 benzersiz sayfa/uç nokta tarandı, 19 giriş noktasında toplam 149 istek gönderildi. SSRF/RCE zaman-tabanlı/dolaylıdır. Aşağıda her kontrol ayrı ayrı raporlanmıştır.

## KONTROL ÖZETİ

| Kontrol | Sonuç | Güven |
|---------|-------|-------|
| Enjeksiyon (SQLi/XSS) Doğrulama | ⚠ Zafiyet göstergesi | Yüksek |
| Yetkisiz Erişim (IDOR) Doğrulama | ⚠ Sınırlı gösterge | Orta |
| SSRF Doğrulama | ✓ Zafiyet kanıtı yok | Orta |
| Dosya Yükleme Doğrulama | Giriş noktası yok (Kapsam dışı) | Kapsam dışı |
| İş Mantığı Doğrulama | Giriş noktası yok (Kapsam dışı) | Kapsam dışı |
| Race / Mass-Assignment Doğrulama | Giriş noktası yok (Kapsam dışı) | Kapsam dışı |
| RCE / Komut Enjeksiyonu Doğrulama | ✓ Zafiyet kanıtı yok | Orta |
| Giriş Baypası (SQLi Göstergesi) | ⚠ Zafiyet göstergesi | Yüksek |

> Güven yalnızca gerçekten test çalıştırılan (giriş noktası bulunan) kontroller için gösterilir; giriş noktası bulunamayan kontroller **Kapsam dışı**dır. Test edilenlerde: SSRF/RCE dolaylı (zaman-tabanlı, OOB yok) → Orta; gözlemsel (Dosya Yükleme/İş Mantığı/Race) → Düşük; Enjeksiyon hata/yansıma-tabanlı → Yüksek.

## POZİTİF GÜVENCE — DENENEN AKTİF DOĞRULAMA YÖNTEMLERİ

Bulgu çıkmayan kontroller de dâhil, 8 aktif kontrol kategorisinin her biri keşfedilen yüzeyde gerçekten çalıştırıldı (toplam **149** istek, **8** benzersiz sayfa). Aşağıdaki tablo, "bulgu yok" sonuçlarını da — kaç giriş noktası denendi, kaçında kanıt bulunamadı — şeffaf gösterir:

| Kontrol | Denenen giriş noktası | Gönderilen istek | Sonuç |
|---------|-----------------------|------------------|-------|
| Enjeksiyon (SQLi/XSS) Doğrulama | 10 | 121 | ⚠️ Bulgu var (2 — zafiyet göstergesi; yukarıda) |
| Yetkisiz Erişim (IDOR) Doğrulama | 2 | 6 | ⚠️ Bulgu var (1 — sınırlı/dolaylı gösterge; yukarıda) |
| SSRF Doğrulama | 2 | 3 | ✅ Temiz (2 giriş noktası denendi, kanıt bulunamadı) |
| Dosya Yükleme Doğrulama | 0 | 1 | ⚠️ İncelenemedi (test edilebilir giriş noktası bulunamadı — “temiz” DEĞİL) |
| İş Mantığı Doğrulama | 0 | 1 | ⚠️ İncelenemedi (test edilebilir giriş noktası bulunamadı — “temiz” DEĞİL) |
| Race / Mass-Assignment Doğrulama | 0 | 1 | ⚠️ İncelenemedi (test edilebilir giriş noktası bulunamadı — “temiz” DEĞİL) |
| RCE / Komut Enjeksiyonu Doğrulama | 4 | 13 | ✅ Temiz (4 giriş noktası denendi, kanıt bulunamadı) |
| Giriş Baypası (SQLi Göstergesi) | 1 | 3 | ⚠️ Bulgu var (1 — zafiyet göstergesi; yukarıda) |


> **Üç-durum ayrımı (dürüstlük):** ✅ *Temiz* = kontrol çalıştı, kanıt bulunamadı · ⚠️ *Bulgu var* = yukarıda detaylı · ⚠️ *İncelenemedi* = test edilebilir giriş noktası bulunamadı (güvenli anlamına GELMEZ).

### Bu paket NE değerlendirir, NE değerlendirmez

**EDER ("kanıtla — istismar etme" ilkesiyle; zararsız, veri-değiştirmeyen problar):** SQLi/XSS enjeksiyonu, yetkisiz erişim (IDOR), SSRF, dosya yükleme, iş mantığı, race/mass-assignment ve RCE/komut enjeksiyonu göstergeleri — kimlik doğrulaması **gerektirmeyen** yüzeyde, keşfedilen 8 sayfada.

**ETMEZ:** Veri değiştiren/silen istismar, ödeme tamamlama veya gerçek RCE çalıştırma **yapılmaz** (yalnızca gösterge/kanıt toplanır). IDOR / İş Mantığı / Race-Mass-Assignment kontrolleri **yalnızca login-öncesi erişilebilir yüzeyde** çalışır; **login-SONRASI** oturum içi derin yetkilendirme/yetki-yükseltme/iş-mantığı zafiyetleri bu paketin **dışındadır** — bunlar **Tam Kapsamlı Pentest** (kimlik-doğrulamalı, kapsam sözleşmeli) kapsamındadır. Bu nedenle bu üç kategoride bazı hedeflerde **sınırlı veya "İncelenemedi"** sonuç normal ve beklenendir (siteye özgü yüzey azlığından; motor eksikliğinden değil). Bir kontrolde "bulgu yok", aktif istismar bilinçli olarak sınırlı/pasif-güvenli tutulduğu için **güvenli olduğunu KANITLAMAZ**.

## Enjeksiyon (SQLi/XSS) Doğrulama

### NE KONTROL EDİLDİ

Taranan sayfalardan (ana sayfa + iç linkler + iyi-bilinen yollar) keşfedilen giriş noktaları (URL query parametreleri + form alanları) üzerinde, giriş noktası başına zararsız doğrulama probları:

- **SQLi (hata-tabanlı):** Tek tırnak (`'`) enjekte edilip yanıtta veritabanı hata imzası (MySQL/PostgreSQL/Oracle/MSSQL/SQLite) arandı.
- **SQLi (zaman-tabanlı):** Hata görülmeyen noktalarda tek bir zararsız gecikme probu (SLEEP) ile yanıt süresi baseline’a göre ölçüldü (blind SQLi göstergesi).
- **SQLi (boolean-tabanlı):** Sayısal/ID-benzeri noktalarda TRUE (`1=1`) ve FALSE (`1=2`) koşullu iki istek gönderilip yanıtları (status + içerik uzunluğu) karşılaştırıldı; TRUE tekrarında tutarlı ve FALSE'tan KALICI farklıysa boolean-based SQLi göstergesidir (yanlış-pozitife karşı stabilite doğrulaması yapılır).
- **XSS (yansıyan):** Benzersiz, zararsız bir işaret dizesi enjekte edilip yanıt HTML’inde **kaçırılmadan (unencoded)** yansıyıp yansımadığı kontrol edildi (JS çalıştırılmadı; stored XSS denenmedi).
### BULGULAR

| Giriş Noktası | Tür | Teknik | Kanıt | Güven (gerekçe) | Ciddiyet |
|---------------|-----|--------|-------|-----------------|----------|
| GET /rest/products/search?q | SQLi | hata-tabanlı | Yanıtta veritabanı hata imzası görüldü ("')" payload'ı ile): "SQLITE_ERROR" | Yüksek — yanıtta veritabanı hata imzası (doğrudan kanıt) | Yüksek |
| GET /redirect?to | XSS | yansıma | İşaret dizesi yansıdı ancak KISMİ/ENCODE EDİLMİŞ (özel karakterler `< > "` kaçırılmış) — bağlama bağlı düşük güvenli gösterge; manuel doğrulama önerilir. | Düşük — yansıdı ancak kodlanmış/kaçırılmış; bağlama bağlı zayıf gösterge | Düşük |

> **Kapsam ve yöntem:** Bu paket, "kanıtla — istismar etme" ilkesiyle çalışır. Backend, hedefe sınırlı sayıda **zararsız** doğrulama probu göndermiştir; hiçbir veri çekilmemiş, değiştirilmemiş veya silinmemiştir. İstekler arası bekleme ve hedef-sağlığı devre kesici (art arda 5xx / aşırı yavaşlama / WAF) uygulanır. Kimlik doğrulama gerektiren alanlar ve iç mantık bu paketin kapsamı dışındadır.

## Yetkisiz Erişim (IDOR) Doğrulama

### NE KONTROL EDİLDİ

Taranan sayfalardan keşfedilen, tahmin edilebilir/sayısal ID içeren uç noktalar (ör. `?id=123`, `/user/45`) üzerinde:

- ID değeri **komşu bir değere** (N-1 / N+1) değiştirilip, kimlik doğrulaması olmadan **GET** isteği gönderildi.
- Yalnızca yanıt **durumu ve boyutu** karşılaştırıldı; **dönen içerik saklanmadı/alıntılanmadı**.
- Farklı ve geçerli görünen bir kaynak dönmesi, numaralandırılabilir erişim göstergesi sayıldı.
### BULGULAR

| Uç Nokta | ID | Gözlem | Ciddiyet |
|----------|-----|--------|----------|
| /api/products/1 | path-id | Kimlik doğrulaması olmadan komşu ID (2) için 200 yanıt ve aynı YAPIDA (JSON iskeleti) ancak FARKLI İÇERİKLİ yanıt döndü — büyük olasılıkla başka bir kaydın verisi (dönen veri raporda gösterilmez). Numaralandırılabilir kaynak erişimi (olası IDOR) göstergesi. | Orta |

### KAPSAM SINIRI (ÖNEMLİ)

Bu paket **kimlik doğrulaması olmadan** çalışır. Bu nedenle yalnızca **herkese açık, numaralandırılabilir kaynaklara** yetkisiz erişimi tespit edebilir. Klasik IDOR (bir kullanıcının, oturum açmış başka bir kullanıcının verisine erişmesi) **iki farklı hesap/oturum** gerektirir ve bu paketin kapsamı dışındadır. Bu bölümde bulgu olmaması, kimlik doğrulamalı akışlarda IDOR olmadığını **kanıtlamaz** — bu, ayrı bir kimlik-doğrulamalı test gerektirir (**İnceleme gerekli / Kapsam Dışı**).

> Ayrıca **1** koleksiyon-benzeri uçtan (ör. `/rest/products`) sıralı sayısal ID'ler (`/{1..3}`) türetilip GET ile içerik-farkı yöntemiyle test edildi.

> **Kapsam ve yöntem:** Bu paket, "kanıtla — istismar etme" ilkesiyle çalışır. Backend, hedefe sınırlı sayıda **zararsız** doğrulama probu göndermiştir; hiçbir veri çekilmemiş, değiştirilmemiş veya silinmemiştir. İstekler arası bekleme ve hedef-sağlığı devre kesici (art arda 5xx / aşırı yavaşlama / WAF) uygulanır. Kimlik doğrulama gerektiren alanlar ve iç mantık bu paketin kapsamı dışındadır.

## SSRF Doğrulama

### NE KONTROL EDİLDİ

- Sunucu-taraflı fetch tetikleyebilecek parametreler (url/webhook/image/redirect vb.) tespit edildi.
- Bu parametrelere, **kontrolümüzdeki** gecikmeli bir echo URL’i verildi; hedefin yanıt süresi baseline ile karşılaştırıldı (sunucu bu URL’i çekerse yanıt gecikir).
- İç ağ / bulut-metadata / localhost (169.254.169.254, RFC1918, 127.0.0.1 vb.) **asla** hedeflenmedi (koda gömülü hard-guard).

### BULGULAR

Gönderilen zararsız problara karşı belirgin bir zafiyet göstergesi bulunamadı.

> OOB doğrulama altyapısı kullanılmadığı için bu tespit **zaman-tabanlı, dolaylı ve orta güvenilirliktedir**; kesin doğrulama için ek/manuel test önerilir.

> **Kapsam ve yöntem:** Bu paket, "kanıtla — istismar etme" ilkesiyle çalışır. Backend, hedefe sınırlı sayıda **zararsız** doğrulama probu göndermiştir; hiçbir veri çekilmemiş, değiştirilmemiş veya silinmemiştir. İstekler arası bekleme ve hedef-sağlığı devre kesici (art arda 5xx / aşırı yavaşlama / WAF) uygulanır. Kimlik doğrulama gerektiren alanlar ve iç mantık bu paketin kapsamı dışındadır.

## Dosya Yükleme Doğrulama

### NE KONTROL EDİLDİ

- Dosya yükleme formu (input type=file) tespit edildi.
- Tek seferlik, **zararsız ve çalıştırılamaz (inert)**, çift uzantılı (.php.txt) bir test dosyası gönderildi; yalnızca kabul/red durumu gözlemlendi.
- Yüklenen dosya **geri çağrılmadı/çalıştırılmadı** (koda gömülü kural).

### BULGULAR

Gönderilen zararsız problara karşı belirgin bir zafiyet göstergesi bulunamadı.

> Taranan 8 benzersiz sayfada dosya yükleme formu (input type=file) veya ağ trafiğinde dosya-yükleme ucu bulunamadı. **Not:** Hedef JavaScript ile render edilen (SPA) bir uygulamadır ve bu tarama sayfalar **headless tarayıcı ile render edilerek** yapılmıştır; buna rağmen test edilebilir giriş noktası bulunamaması, render sonrası sayfada gerçekten giriş noktası olmadığını gösterir (ham-HTML sınırlaması değil — daha güçlü bir "temiz" göstergesi; yine de kimlik-doğrulamalı akışlar kapsam dışıdır).

> **Kapsam ve yöntem:** Bu paket, "kanıtla — istismar etme" ilkesiyle çalışır. Backend, hedefe sınırlı sayıda **zararsız** doğrulama probu göndermiştir; hiçbir veri çekilmemiş, değiştirilmemiş veya silinmemiştir. İstekler arası bekleme ve hedef-sağlığı devre kesici (art arda 5xx / aşırı yavaşlama / WAF) uygulanır. Kimlik doğrulama gerektiren alanlar ve iç mantık bu paketin kapsamı dışındadır.

## İş Mantığı Doğrulama

### NE KONTROL EDİLDİ

- Ana sayfa/formlar üzerinde **istemci-tarafında değiştirilebilir** fiyat/miktar alanları (hidden input) gözlemlendi (yalnızca gözlem — istek gönderilmedi).
- Bir "başarılı/onay" adımı sayfasına ön koşul olmadan **yalnızca GET** ile erişilip erişilemediği kontrol edildi (adım-atlama göstergesi).
- ⚠️ Bu kontrol **hiçbir state-değiştiren istek (POST/PUT/…) göndermez** — sepet/ödeme **asla** oluşturulmaz/tamamlanmaz (koda gömülü kural).

### BULGULAR

Gönderilen zararsız problara karşı belirgin bir zafiyet göstergesi bulunamadı.

> İş mantığı zafiyetleri bağlama özeldir; bu kontrol yüzey/gösterge seviyesindedir. Kesin doğrulama kimlik-doğrulamalı manuel test gerektirir.

> Taranan 8 benzersiz sayfada gözlemlenebilir bir istemci-tarafı fiyat/miktar alanı veya doğrudan erişilebilir "onay" adımı bulunamadı. **Not:** Hedef JavaScript ile render edilen (SPA) bir uygulamadır ve bu tarama sayfalar **headless tarayıcı ile render edilerek** yapılmıştır; buna rağmen test edilebilir giriş noktası bulunamaması, render sonrası sayfada gerçekten giriş noktası olmadığını gösterir (ham-HTML sınırlaması değil — daha güçlü bir "temiz" göstergesi; yine de kimlik-doğrulamalı akışlar kapsam dışıdır).

> **Kapsam ve yöntem:** Bu paket, "kanıtla — istismar etme" ilkesiyle çalışır. Backend, hedefe sınırlı sayıda **zararsız** doğrulama probu göndermiştir; hiçbir veri çekilmemiş, değiştirilmemiş veya silinmemiştir. İstekler arası bekleme ve hedef-sağlığı devre kesici (art arda 5xx / aşırı yavaşlama / WAF) uygulanır. Kimlik doğrulama gerektiren alanlar ve iç mantık bu paketin kapsamı dışındadır.

## Race / Mass-Assignment Doğrulama

### NE KONTROL EDİLDİ

- Kayıt/profil benzeri bir POST formu tespit edildi (ödeme/tamamlama uç noktaları **hariç tutuldu** — koda gömülü blocklist).
- Forma fazladan `isAdmin/role` alanları eklenmiş **tek** bir istek gönderildi; yalnızca kabul/red gözlendi (yetki değişikliği **teyit edilmedi**; tekrar/retry **yok**).
- Race-condition (eşzamanlılık) testi, tüketilebilir bir kaynağı gerçekten değiştirme riski taşıdığından **otomatik çalıştırılmadı** (aşağıda not).

### BULGULAR

Gönderilen zararsız problara karşı belirgin bir zafiyet göstergesi bulunamadı.

> Mass-assignment göstergesi yalnızca ilk yanıttan çıkarılmıştır (düşük güven). Race-condition için güvenli/test edilebilir bir uç nokta ile manuel doğrulama önerilir.

> Race-condition (eşzamanlılık) testi, tüketilebilir bir kaynağı (kupon/stok) gerçekten değiştirme riski taşıdığından bu otomatik taramada **çalıştırılmadı**; güvenli/test edilebilir bir uç nokta ile manuel doğrulama önerilir.
> Taranan 8 benzersiz sayfada mass-assignment için uygun (tamamlama/ödeme dışı) kayıt/profil formu bulunamadı. **Not:** Hedef JavaScript ile render edilen (SPA) bir uygulamadır ve bu tarama sayfalar **headless tarayıcı ile render edilerek** yapılmıştır; buna rağmen test edilebilir giriş noktası bulunamaması, render sonrası sayfada gerçekten giriş noktası olmadığını gösterir (ham-HTML sınırlaması değil — daha güçlü bir "temiz" göstergesi; yine de kimlik-doğrulamalı akışlar kapsam dışıdır).

> **Kapsam ve yöntem:** Bu paket, "kanıtla — istismar etme" ilkesiyle çalışır. Backend, hedefe sınırlı sayıda **zararsız** doğrulama probu göndermiştir; hiçbir veri çekilmemiş, değiştirilmemiş veya silinmemiştir. İstekler arası bekleme ve hedef-sağlığı devre kesici (art arda 5xx / aşırı yavaşlama / WAF) uygulanır. Kimlik doğrulama gerektiren alanlar ve iç mantık bu paketin kapsamı dışındadır.

## RCE / Komut Enjeksiyonu Doğrulama

### NE KONTROL EDİLDİ

- Komuta ulaşabilecek giriş parametreleri tespit edildi.
- Yalnızca **zararsız, zaman-tabanlı** gecikme payload’ları (sleep) gönderildi; yanıt süresi baseline ile karşılaştırıldı (blind kanıt).
- Gerçek komut çalıştırma (dosya okuma/yazma, ağ bağlantısı, reverse shell) **asla** denenmedi (koda gömülü hard-guard: yalnız sabit sleep payload listesi).

### BULGULAR

Gönderilen zararsız problara karşı belirgin bir zafiyet göstergesi bulunamadı.

> OOB/canary altyapısı kullanılmadığı için bu tespit **zaman-tabanlı, dolaylı ve orta güvenilirliktedir** (ağ gecikmesi yanıltabilir); kesin doğrulama için manuel test önerilir.

> **Kapsam ve yöntem:** Bu paket, "kanıtla — istismar etme" ilkesiyle çalışır. Backend, hedefe sınırlı sayıda **zararsız** doğrulama probu göndermiştir; hiçbir veri çekilmemiş, değiştirilmemiş veya silinmemiştir. İstekler arası bekleme ve hedef-sağlığı devre kesici (art arda 5xx / aşırı yavaşlama / WAF) uygulanır. Kimlik doğrulama gerektiren alanlar ve iç mantık bu paketin kapsamı dışındadır.

## Giriş Baypası (SQLi Göstergesi)

### NE KONTROL EDİLDİ

- Giriş (login) ucuna önce **geçersiz kimlik** (kontrol) gönderildi; ardından klasik SQLi payload’ları (`' OR '1'='1` vb.) denenip, kontrolün AKSİNE oturum/başarı (token/2xx) dönüp dönmediği gözlemlendi.
- Login POST’u zaten izinli bir akıştır; bu, TEK ve zararsız bir gözlemdir.
- ⚠️ Oturum ele geçirme/istismar YOK — yalnız "kimlik doğrulama atlatma göstergesi var mı" gözlemi.

### BULGULAR

| Giriş/Uç Nokta | Teknik | Kanıt | Güven | Yan-etki riski | Ciddiyet |
|----------------|--------|-------|-------|----------------|----------|
| POST /rest/user/login | giriş baypası (SQLi: `' OR 1=1--`) | Kontrol (geçersiz kimlik) → HTTP 401 (başarısız). SQLi payload `' OR 1=1--` → HTTP 200 + AÇIK başarı sinyali: "{"authentication":{"token":"***","bid":1,"umail":"admin@juice-sh.op"}}". Kimlik doğrulama SQL enjeksiyonuyla ATLATILIYOR (oturum/authorization token döndü — güçlü kanıt). Oturum ele geçirme/istismar YAPILMADI; token değeri raporda gösterilmez (redakte). | Yüksek | yok | Yüksek |

> Gösterge, kontrol denemesiyle karşılaştırmaya dayanır; kesin doğrulama manuel test gerektirir.

> **Kapsam ve yöntem:** Bu paket, "kanıtla — istismar etme" ilkesiyle çalışır. Backend, hedefe sınırlı sayıda **zararsız** doğrulama probu göndermiştir; hiçbir veri çekilmemiş, değiştirilmemiş veya silinmemiştir. İstekler arası bekleme ve hedef-sağlığı devre kesici (art arda 5xx / aşırı yavaşlama / WAF) uygulanır. Kimlik doğrulama gerektiren alanlar ve iç mantık bu paketin kapsamı dışındadır.
