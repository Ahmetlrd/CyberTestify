## YÖNETİCİ ÖZETİ

- **Genel risk seviyesi: Yüksek** — site HTTPS desteklemiyor; iletişim şifresiz (düz metin) taşınıyor — dinlenebilir/değiştirilebilir. Öncelikli olarak HTTPS’e geçilmelidir.
- ⚠️ Bu hedef HTTPS (443) üzerinden yanıt vermedi; tarama **http:// üzerinden** yürütüldü. HTTPS eksikliği başlı başına bir bulgudur (aşağıda).
- 6/6 önemli güvenlik başlığı eksik: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, Referrer-Policy, Permissions-Policy.
- **Kapsam:** Güvenlik başlığı ve sürüm imzası kontrolleri, ana sayfa dâhil **8 benzersiz sayfada** yürütüldü (tek sayfa değil).
- **Önerilen ilk adım:** Geçerli bir TLS sertifikası kurup tüm trafiği HTTPS’e taşıyın; adım adım hazır komutlar "AI Çözüm Önerileri" eklentisinde sunulur.

> **Kapsam ve sınır:** Bu paket **pasif, GET-tabanlı** bir dış gözlemdir; hiçbir aktif istismar veya prob denenmemiştir. Bir alanda "bulgu yok" ifadesi, aktif test yapılmadığı için **güvenli olduğunu KANITLAMAZ** — yalnızca dışarıdan gözlemlenen yapılandırmanın temiz olduğunu gösterir.

## GENEL DEĞERLENDİRME

**Risk Seviyesi: Yüksek**

Bu hedef HTTPS üzerinden yanıt vermiyor; iletişim şifresiz (düz metin) HTTP ile yürüyor. Bu, aynı ağdaki bir saldırganın trafiği dinlemesine/değiştirmesine ve oturum/şifre çalmasına olanak tanıyan ciddi bir eksiktir; modern tarayıcılar siteyi "Güvenli değil" olarak işaretler. Öncelik, geçerli bir TLS sertifikasıyla HTTPS’e geçmek ve HTTP→HTTPS yönlendirmesi + HSTS eklemektir. Diğer başlık kontrolleri http:// üzerinden yürütülmüştür.

## HTTP GÜVENLİK BAŞLIKLARI

| Başlık | Durum | Açıklama |
|--------|-------|----------|
| Strict-Transport-Security | Yok | HTTPS zorunluluğu tarayıcıya bildirilmiyor; ilk isteklerde SSL-stripping/MITM riski var. |
| Content-Security-Policy | Yok | Tarayıcı hangi kaynakların yükleneceğini kısıtlayamıyor; XSS ve içerik enjeksiyonuna karşı temel savunma yok. |
| X-Frame-Options | Yok | Sayfa başka bir sitenin iframe’ine gömülebilir; clickjacking ile kullanıcı kandırılabilir. |
| X-Content-Type-Options | Yok | Tarayıcı içerik türünü tahmin edebilir (MIME-sniffing); yüklenen dosyalar script gibi çalıştırılabilir. |
| Referrer-Policy | Yok | Dış bağlantılara tam URL (Referer) gönderilir; oturum/gizlilik bilgisi sızabilir. |
| Permissions-Policy | Yok | Kamera/mikrofon/konum gibi hassas API’ler kısıtlanmamış; üçüncü taraf içerik kötüye kullanabilir. |
| X-XSS-Protection | Yok | Eski tarayıcı XSS filtresi ayarlı değil (modern tarayıcılarda kritik değildir; asıl koruma CSP’dir). |
| Content-Type | Var | text/html |

## TLS SERTİFİKA DURUMU

⚠️ Bu hedef **HTTPS (443) üzerinden yanıt vermedi**; geçerli bir TLS sertifikası bulunamadı. Site yalnızca **şifresiz HTTP** üzerinden yayında (bkz. Tespit Edilen Riskler → “HTTPS desteklenmiyor”). Aşağıdaki başlık kontrolleri http:// üzerinden yürütülmüştür.

## SUNUCU / TEKNOLOJİ İMZASI

- Sunucu: Microsoft-IIS/8.5
- X-Powered-By: ASP.NET

## TESPİT EDİLEN RİSKLER

| Bulgu | Şiddet | Açıklama |
|-------|--------|----------|
| HTTPS desteklenmiyor (şifresiz iletişim) | Yüksek | Site HTTPS'e yanıt vermiyor; sayfaya gelen/giden tüm trafik şifresiz (düz metin) taşınıyor — aynı ağdaki bir saldırgan trafiği dinleyebilir, oturum/şifre çalabilir veya içeriği değiştirebilir. Tarama http:// üzerinden yürütüldü. |
| Kritik güvenlik başlıkları eksik (Content-Security-Policy, X-Frame-Options) | Orta | XSS ve/veya clickjacking saldırılarına karşı tarayıcı seviyesinde savunma bulunmuyor. Taranan 8 benzersiz sayfanın TAMAMINDA eksik. |
| Ek güvenlik başlıkları eksik (X-Content-Type-Options, Strict-Transport-Security, Referrer-Policy, Permissions-Policy) | Orta | Savunma derinliği zayıf; tek tek düşük etkili olsa da birlikte saldırı yüzeyini genişletir. Taranan 8 benzersiz sayfanın TAMAMINDA eksik. |

## POZİTİF GÜVENCE — KONTROL EDİLEN ALANLAR

Bulgu çıkmayan alanlar da dâhil, Basit Tarama kontrolleri ana sayfa dâhil **8 benzersiz sayfada** gerçekten çalıştırıldı. Aşağıdaki tablo, "sorun bulunamadı" sonuçlarını da şeffaf biçimde gösterir:

| Kontrol Alanı | Sonuç |
|---------------|-------|
| HTTP güvenlik başlıkları (8 sayfada) | ⚠️ Bulgu var (6/6 önerilen başlık eksik — yukarıda detaylı) |
| TLS / sertifika | ⚠️ Bulgu var (HTTPS yanıt vermedi — şifresiz iletişim) |
| Sunucu/yazılım sürüm imzası (8 sayfada) | ✅ Sorun bulunmadı (bilinen eski/EOL sürüm imzası saptanmadı) |

> **Üç-durum ayrımı (dürüstlük):** ✅ *Sorun bulunmadı* = kontrol çalıştı, temiz çıktı · ⚠️ *Bulgu var* = yukarıda detaylı · ⚠️ *İncelenemedi* = veri toplanamadı (güvenli anlamına GELMEZ).

### Bu paket NE kontrol EDER, NE ETMEZ

**EDER (pasif — yalnız GET ile sayfa çekme, hiçbir prob/payload gönderilmez):** HTTP güvenlik başlıkları, TLS/sertifika durumu (geçerlilik · hostname · TLS sürümü), sunucu-yazılım sürüm imzası ve bilinen eski/EOL sürüm tespiti — keşfedilen 8 sayfada.

**ETMEZ:** CORS politikası, çerez bayrağı detayı, Content-Security-Policy analizi, DNS/e-posta kayıtları (SPF/DKIM/DMARC) ve açıkta hassas dosya taraması **Dış Yüzey** paketindedir; KVKK/PCI/ISO çerçeve-eşlemesi **Uyum** paketinde; subdomain/API/CVE keşfi **Keşif** paketinde; aktif zafiyet doğrulaması (SQLi/XSS/IDOR prob’u) **Aktif Doğrulama** ve **Tam Kapsamlı Pentest** paketlerinde ele alınır. Bu rapor pasif gözleme dayanır; "bulgu yok", aktif istismar denenmediği için **güvenli olduğunu KANITLAMAZ**.

