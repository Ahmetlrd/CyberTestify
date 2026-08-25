## YÖNETİCİ ÖZETİ

- **Genel risk seviyesi: Yüksek** — 5 alan incelendi; en yüksek risk **SSL/TLS Yapılandırma Denetimi** alanında (sertifika ve/veya protokol düzeyinde acil ele alınması gereken bir sorun tespit edildi.).
- ⚠️ **HTTPS desteklenmiyor:** Hedef HTTPS (443) üzerinden yanıt vermedi; iletişim şifresiz (düz metin) taşınıyor. Tarama http:// üzerinden yürütüldü. Bu başlı başına ciddi bir bulgudur (aşağıda).
- **SSL/TLS Yapılandırma Denetimi:** Yüksek — sertifika ve/veya protokol düzeyinde acil ele alınması gereken bir sorun tespit edildi.
- **Güvenlik Başlıkları & Bilgi Sızıntısı:** Yüksek — dışarıdan erişilebilir hassas dosya tespit edildi.
- **DNS & E-posta Güvenliği:** Orta — e-posta kimlik doğrulamasında giderilmesi gereken eksikler var.
- **CORS & Çerez Güvenliği:** Düşük — belirgin bir CORS/çerez sorunu öne çıkmadı.
- **CSP (İçerik Güvenlik Politikası) Analizi:** Orta — CSP eksik/enforce edilmiyor.
- **Önerilen ilk adım:** En yüksek riskli alandan başlayın; her bulgu için adım adım hazır komutlar "AI Çözüm Önerileri" bölümünde sunulur.

## GENEL DEĞERLENDİRME

**Risk Seviyesi: Yüksek**

Bu hedef HTTPS üzerinden yanıt vermiyor; iletişim şifresiz (düz metin) taşınıyor — öncelikli olarak geçerli bir TLS sertifikasıyla HTTPS’e geçilmelidir. Diğer alanlar http:// üzerinden incelenmiştir. En yüksek risk **SSL/TLS Yapılandırma Denetimi** alanında (sertifika ve/veya protokol düzeyinde acil ele alınması gereken bir sorun tespit edildi.) tespit edildi; öncelikli olarak giderilmesi önerilir. Aşağıda her alan ayrı ayrı raporlanmıştır.

## TESPİT EDİLEN RİSKLER

| Bulgu | Şiddet | Açıklama |
|-------|--------|----------|
| HTTPS desteklenmiyor (şifresiz iletişim) | Yüksek | Site HTTPS'e yanıt vermiyor; tüm trafik şifresiz (düz metin) taşınıyor — dinlenebilir/değiştirilebilir, oturum/şifre çalınabilir. Çözüm: geçerli TLS sertifikası + HTTP→HTTPS yönlendirme + HSTS. |

## SSL/TLS Yapılandırma Denetimi

### TLS SERTİFİKA DURUMU

⚠️ Bu hedef **HTTPS (443) üzerinden yanıt vermedi**; geçerli bir TLS sertifikası bulunamadı. Site yalnızca **şifresiz HTTP** üzerinden yayında.

### TLS PROTOKOL & CIPHER

- **Aktif protokol:** tespit edilemedi
- **Cipher:** tespit edilemedi
- **Eski/zayıf sürüm desteği:** Gözlemlenmedi (yalnızca TLS 1.2+ görüldü)

### HSTS (HTTP Strict Transport Security)

- **Durum:** Yok — Tarayıcıya HTTPS zorunluluğu bildirilmiyor; ilk isteklerde SSL-stripping/downgrade saldırısı riski var.

### TESPİT EDİLEN RİSKLER

| Bulgu | Şiddet | Açıklama |
|-------|--------|----------|
| HTTPS desteklenmiyor (şifresiz iletişim) | Yüksek | Site HTTPS'e yanıt vermiyor; tüm trafik şifresiz (düz metin) taşınıyor. Aynı ağdaki bir saldırgan dinleyebilir, oturum/şifre çalabilir veya içeriği değiştirebilir. Çözüm: geçerli TLS sertifikası + HTTP→HTTPS yönlendirme + HSTS. |
| HSTS eksik | Orta | HTTPS zorunluluğu tarayıcıya bildirilmiyor; downgrade saldırılarına açık. |

## Güvenlik Başlıkları & Bilgi Sızıntısı

### HTTP GÜVENLİK BAŞLIKLARI

| Başlık | Durum | Açıklama |
|--------|-------|----------|
| Strict-Transport-Security | Yok | HTTPS zorunluluğu bildirilmiyor; SSL-stripping riski. |
| Content-Security-Policy | Yok | XSS/enjeksiyona karşı tarayıcı savunması yok. |
| X-Frame-Options | Yok | Clickjacking’e açık; iframe’e gömülebilir. |
| X-Content-Type-Options | Yok | MIME-sniffing mümkün. |
| Referrer-Policy | Yok | Referrer bilgisi dış kaynaklara sızabilir. |
| Permissions-Policy | Yok | Hassas tarayıcı API’leri kısıtlanmamış. |
| X-XSS-Protection | Yok | Eski tarayıcı XSS filtresi ayarlı değil (modernlerde kritik değil). |

### BİLGİ SIZINTISI / AÇIKTA DOSYALAR

Yaygın hassas yollar tek GET ile kontrol edildi (içerik doğrulandı — yalnız HTTP 200 kanıt sayılmaz):

| Yol | Durum | Not |
|-----|-------|-----|
| `/.git/config` | Kapalı | HTTP 400 / boş gövde — erişilebilir değil |
| `/.env` | Kapalı | HTTP 404 / boş gövde — erişilebilir değil |
| `/.git/HEAD` | Kapalı | HTTP 400 / boş gövde — erişilebilir değil |
| `/backup.zip` | Kapalı | HTTP 404 / boş gövde — erişilebilir değil |
| `/.DS_Store` | Kapalı | HTTP 404 / boş gövde — erişilebilir değil |
| `/wp-config.php.bak` | Kapalı | HTTP 404 / boş gövde — erişilebilir değil |
| `/ftp` | Kapalı | HTTP 404 / boş gövde — erişilebilir değil |
| `/backup` | Kapalı | HTTP 404 / boş gövde — erişilebilir değil |
| `/backups` | Kapalı | HTTP 404 / boş gövde — erişilebilir değil |
| `/uploads` | Kapalı | HTTP 404 / boş gövde — erişilebilir değil |
| `/files` | Kapalı | HTTP 400 / boş gövde — erişilebilir değil |
| `/admin` | Kapalı | HTTP 404 / boş gövde — erişilebilir değil |
| `/.svn/entries` | Kapalı | HTTP 400 / boş gövde — erişilebilir değil |
| `/.htaccess` | Kapalı | HTTP 403 / boş gövde — erişilebilir değil |
| `/config.php.bak` | Kapalı | HTTP 404 / boş gövde — erişilebilir değil |
| `/db.sql` | ⚠️ AÇIK | beklenen dosya formatı doğrulandı (catch-all değil) |
| `/dump.sql` | Kapalı | HTTP 404 / boş gövde — erişilebilir değil |
| `/backup.tar.gz` | Kapalı | HTTP 404 / boş gövde — erişilebilir değil |
| `/backup.tar` | Kapalı | HTTP 404 / boş gövde — erişilebilir değil |
| `/www.zip` | Kapalı | HTTP 404 / boş gövde — erişilebilir değil |
| `/site.zip` | Kapalı | HTTP 404 / boş gövde — erişilebilir değil |
| `/backup.old` | Kapalı | HTTP 404 / boş gövde — erişilebilir değil |
| `/backup.backup` | Kapalı | HTTP 404 / boş gövde — erişilebilir değil |
| `/index.php.bak` | Kapalı | HTTP 404 / boş gövde — erişilebilir değil |
| `/index.php~` | Kapalı | HTTP 404 / boş gövde — erişilebilir değil |
| `/.env.bak` | Kapalı | HTTP 404 / boş gövde — erişilebilir değil |
| `/.env.old` | Kapalı | HTTP 404 / boş gövde — erişilebilir değil |
| `/database.sql` | Kapalı | HTTP 404 / boş gövde — erişilebilir değil |

### EK BİLGİ-SIZINTISI GÖZLEMLERİ

| Kontrol | Sonuç |
|-----|-------|
| Dizin listeleme (autoindex / “Index of /”) · CWE-548 | ✅ 6 dizin denendi, listeleme yok |
| Ayrıntılı hata / sunucu-yol ifşası · CWE-209 | ✅ Gösterge bulunamadı |
| Parola alanı autocomplete politikası · CWE-522 | ✅ Uygun / parola alanı gözlenmedi |

> Hepsi GET-only/pasif gözlemdir — içerik ÇEKİLMEZ/gösterilmez; sızan yol REDAKTE edilir. “Gösterge bulunamadı” güvenli olduğunu KANITLAMAZ; yalnız denenen pasif yöntemlerle gösterge çıkmadığını gösterir.

### TESPİT EDİLEN RİSKLER

| Bulgu | Şiddet | Açıklama |
|-------|--------|----------|
| Hassas dosya erişilebilir (`/db.sql`) | Yüksek | İçerik doğrulandı; yapılandırma/kaynak sızıntısı riski. Erişim derhal engellenmeli. |
| Eski/desteksiz yazılım sürümü ifşa ediliyor (PHP/7.1.26 — EOL) | Yüksek | PHP 7.x serisi resmen desteklenmiyor (7.x güvenlik güncellemeleri 2022 sonunda bitti). Bilinen çok sayıda güvenlik açığı yamasız kalır. CWE-1104 · OWASP A06:2021 (Güncel Olmayan/Savunmasız Bileşenler). Çözüm: güncel ve desteklenen bir PHP sürümüne (8.2+) yükseltin; sürüm imzasını gizleyin (expose_php=Off). |
| Güncel olmayan yazılım sürümü ifşa ediliyor (Apache/2.4.25 — çok eski yama) | Orta | Apache 2.4 serisi desteklenmekle birlikte Apache/2.4.25 çok eski bir yama düzeyidir; aradaki güvenlik yamaları uygulanmamış görünüyor. CWE-1104 · OWASP A06:2021 (Güncel Olmayan/Savunmasız Bileşenler). Çözüm: 2.4 serisinin güncel yamasına yükseltin; sürüm imzasını gizleyin (ServerTokens Prod). |
| Kritik güvenlik başlıkları eksik (Content-Security-Policy, X-Frame-Options) | Orta | XSS/clickjacking’e karşı tarayıcı savunması zayıf. (2/2 sayfada eksik) |
| Ek başlıklar eksik (Strict-Transport-Security, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection) | Orta | Savunma derinliği zayıf. (2/2 sayfada eksik) |

## DNS & E-posta Güvenliği

### SPF (Gönderen Politikası) — kontrol edilen alan: `vulnweb.com`

- **Durum:** Var — `v=spf1 ~all`
- **Sertlik:** `~all` — yumuşak (softfail; kabul edilebilir, ideal değil).

### DMARC (Kimlik Doğrulama Politikası) — kontrol edilen alan: `vulnweb.com`

- **Durum:** Yok — DMARC kaydı bulunamadı. SPF/DKIM sonuçlarına göre uygulama yapılmıyor; spoofing’e karşı koruma zayıf.

### DKIM (İmza)

- **Durum:** Tespit edilemedi — Yaygın seçicilerde (default/google/selector1…) DKIM kaydı bulunamadı. Farklı bir seçici kullanıyor olabilirsiniz; bu kesin “yok” anlamına gelmez.

### DNSSEC

- **Durum:** Pasif/yok — DNS yanıtları imzalı değil; DNS spoofing/cache-poisoning riskine daha açık.

### TESPİT EDİLEN RİSKLER

| Bulgu | Şiddet | Açıklama |
|-------|--------|----------|
| DMARC eksik | Orta | SPF/DKIM sonuçları uygulanmıyor. |
| DKIM tespit edilemedi | Bilgilendirme | Yaygın seçicilerde bulunamadı (farklı seçici olabilir). |
| DNSSEC pasif | Bilgilendirme | DNS yanıtları imzalı değil. |

## CORS & Çerez Güvenliği

### CORS YAPILANDIRMASI (2/2 sayfada test edildi)

- **Test Origin:** `https://cybertestify-cors-probe.example` — her sayfaya zararsız bir Origin başlığı gönderilip yanıt değerlendirildi.
- **En açık gözlemlenen politika** (`/`): Access-Control-Allow-Origin: gönderilmiyor (kapalı — güvenli varsayılan); Allow-Credentials: gönderilmiyor.

### ÇEREZ BAYRAKLARI (2 sayfada gözlemlenen tüm çerezler)

- Taranan 2 sayfanın hiçbirinde Set-Cookie gözlemlenmedi.

### TESPİT EDİLEN RİSKLER

- CORS ve çerez yapılandırmasında belirgin bir risk öne çıkmadı.

## CSP (İçerik Güvenlik Politikası) Analizi

### CSP DURUMU

- **Durum:** Yok — Content-Security-Policy başlığı hiç gönderilmiyor.

### CSP DİREKTİF ANALİZİ

- Uygulanan bir CSP olmadığından direktif analizi yapılamadı.

### TESPİT EDİLEN RİSKLER

| Bulgu | Şiddet | Açıklama |
|-------|--------|----------|
| CSP tamamen eksik | Orta | XSS ve içerik enjeksiyonuna karşı tarayıcı seviyesinde savunma yok. Taranan 2 sayfanın TAMAMINDA CSP başlığı yok. |

## POZİTİF GÜVENCE — KONTROL EDİLEN ALANLAR

Bulgu çıkmayan alanlar da dâhil, dış-yüzey kontrolleri ana sayfa dâhil **2 benzersiz sayfada** gerçekten çalıştırıldı. Aşağıdaki tablo, "sorun bulunamadı" sonuçlarını da şeffaf biçimde gösterir:

| Kontrol Alanı | Sonuç |
|---------------|-------|
| SSL/TLS Yapılandırma Denetimi | ⚠️ Bulgu var (Yüksek — yukarıda ayrıntılı) |
| Güvenlik Başlıkları & Bilgi Sızıntısı | ⚠️ Bulgu var (Yüksek — yukarıda ayrıntılı) |
| DNS & E-posta Güvenliği | ⚠️ Bulgu var (Orta — yukarıda ayrıntılı) |
| CORS & Çerez Güvenliği | ✅ Sorun bulunmadı |
| CSP (İçerik Güvenlik Politikası) Analizi | ⚠️ Bulgu var (Orta — yukarıda ayrıntılı) |
| Dizin listeleme (autoindex / “Index of /”) · CWE-548 | ✅ 6 dizin denendi, listeleme yok |
| Ayrıntılı hata / sunucu-yol ifşası · CWE-209 | ✅ Gösterge bulunamadı |
| Parola alanı autocomplete politikası · CWE-522 | ✅ Uygun / parola alanı gözlenmedi |

> **Üç-durum ayrımı (dürüstlük):** ✅ *Sorun bulunmadı* = kontrol çalıştı, temiz çıktı · ⚠️ *Bulgu var* = yukarıda detaylı · ⚠️ *İncelenemedi* = veri toplanamadı (güvenli anlamına GELMEZ).

### Bu paket NE kontrol EDER, NE ETMEZ

**EDER (pasif — yalnız GET ile sayfa çekme + zararsız Origin/DNS sorgusu):** TLS/sertifika, HTTP güvenlik başlıkları, CORS politikası, çerez bayrakları (Secure/HttpOnly/SameSite), Content-Security-Policy, DNS/e-posta kayıtları (SPF/DKIM/DMARC/DNSSEC), açıkta hassas dosya (yaygın yedek kalıpları dâhil), dizin listeleme (autoindex), ayrıntılı-hata/sunucu-yol ifşası (redakte), parola alanı autocomplete politikası, eski/desteksiz yazılım sürümü — keşfedilen 2 sayfada.

**ETMEZ:** Aktif zafiyet doğrulaması (SQLi/XSS/IDOR gibi payload/prob denemesi), kimlik-doğrulamalı akış testi, iş-mantığı istismarı. Bunlar **Aktif Doğrulama** ve **Tam Kapsamlı Pentest** paketlerinin kapsamındadır. Bu rapor pasif gözleme dayanır; bir alanda "bulgu yok" ifadesi, aktif istismar denenmediği için **güvenli olduğunu KANITLAMAZ** — yalnız dışarıdan gözlemlenen yapılandırmanın temiz olduğunu gösterir.

