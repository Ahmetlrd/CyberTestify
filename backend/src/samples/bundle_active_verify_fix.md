Bu bölüm, çalıştırılan aktif doğrulama kontrollerinde tespit edilen bulgular için düzeltme önerileri içerir.

### Enjeksiyon (SQLi/XSS) Doğrulama

### Enjeksiyon (SQLi/XSS) — düzeltme

- **SQLi:** Tüm veritabanı sorgularını **parametreli sorgu / hazırlanmış ifade (prepared statement)** ile yazın; kullanıcı girdisini asla string olarak sorguya eklemeyin. ORM kullanıyorsanız ham SQL birleştirmeden kaçının. Veritabanı hata mesajlarını son kullanıcıya göstermeyin.
- **XSS:** Kullanıcı girdisini HTML’e basarken **bağlama uygun çıktı kodlaması** (HTML entity encoding) uygulayın; mümkünse otomatik kaçış yapan şablon motoru kullanın. `Content-Security-Policy` başlığı ile satır-içi script’leri kısıtlayın.
- Giderdikten sonra aynı giriş noktalarını yeniden test edin.

### Yetkisiz Erişim (IDOR) Doğrulama

### Yetkisiz Erişim (IDOR) — düzeltme

- **Nesne-düzeyi yetkilendirme:** Her kaynak erişiminde, isteyen kullanıcının o nesneye erişim hakkı olup olmadığını sunucu tarafında doğrulayın (sadece ID’nin geçerli olması yeterli değildir).
- **Tahmin edilemez tanımlayıcılar:** Sıralı sayısal ID yerine UUID/rastgele tanımlayıcı kullanın; numaralandırmayı zorlaştırın.
- Herkese açık olmaması gereken kaynakları kimlik doğrulama arkasına alın.

### SSRF Doğrulama

### SSRF — proaktif sertleştirme

- Kullanıcıdan URL alan tüm alanlarda sunucu-taraflı **allowlist** + iç ağ engellemesi uygulayın (proaktif).
- Dış fetch gerektiğinde şema/host doğrulaması + zaman aşımı + boyut limiti koyun.

### Dosya Yükleme Doğrulama

### Dosya Yükleme — proaktif sertleştirme

- Yükleme uç noktalarında sunucu-taraflı tip/MIME doğrulaması + allowlist + web-kökü dışı depolama uygulayın (proaktif).

### İş Mantığı Doğrulama

### İş Mantığı — proaktif sertleştirme

- Kritik değerleri (fiyat/miktar) sunucu tarafında doğrulayın; çok adımlı akışlarda adım sırası kontrolü uygulayın (proaktif).

### Race / Mass-Assignment Doğrulama

### Race / Mass-Assignment — proaktif sertleştirme

- Model bağlamada alan allowlist’i (mass-assignment koruması) uygulayın; kritik işlemlerde atomik/idempotent tasarım kullanın (proaktif).

### RCE / Komut Enjeksiyonu Doğrulama

### RCE / Komut Enjeksiyonu — proaktif sertleştirme

- Sistem komutu çağıran kod yollarını gözden geçirin; girdiyi allowlist ile doğrulayın, shell string birleştirmeden kaçının (proaktif).
- En düşük yetki + giden ağ kısıtı uygulayın.

### Giriş Baypası (SQLi Göstergesi)

### Giriş Baypası / SQL Enjeksiyonu — düzeltme

- Kimlik doğrulama sorgularında **parametreli sorgu / hazırlanmış ifade (prepared statement)** kullanın; kullanıcı girdisini asla SQL’e doğrudan koymayın.
- Girdi doğrulama + ORM güvenli API’leri; hatalı girişte tek-tip hata mesajı döndürün.