Bu bölüm, uyum ön-değerlendirmenizde dışarıdan gözlemlenen eksikler için çerçeve çerçeve düzeltme adımları içerir (resmî uyum beyanı değildir).

### KVKK Ön Uyum Kontrolü

Aşağıdaki adımlar dışarıdan gözlemlenen KVKK hazırlık eksiklerini gidermeye yöneliktir (resmî uyum beyanı değildir).

### Aydınlatma metni / Gizlilik politikası

KVKK m.10 kapsamında; hangi kişisel verilerin, hangi amaçla ve hukuki sebeple işlendiğini + veri sorumlusu/VERBIS bilgisini içeren erişilebilir bir metin yayınlayın (footer’dan linkleyin).

### Çerez açık rızası

İzleyici/analitik çerezleri **rıza alınmadan ÖNCE bırakmayın** (gözlemlenen izleyiciler: Google Tag Manager, Google Analytics, Facebook Pixel, Microsoft Clarity). Kategorili (zorunlu/analitik/pazarlama) bir çerez rıza banner’ı ekleyin; yalnızca onaylanan kategoriler yüklensin (Cookiebot/OneTrust/iubenda/Klaro vb.).

### Veri sorumlusu / iletişim

Veri sorumlusu kimliğini, iletişim bilgisini ve (varsa) VERBIS kaydını sitede erişilebilir kılın.

### Not

Bu öneriler dışarıdan gözlemlenebilir teknik göstergelere dayanır; tam uyum için veri envanteri, saklama/imha politikası ve gerekli sözleşmeler dâhil kapsamlı bir hukuki değerlendirme gereklidir.

### PCI-DSS Hazırlık Ön-Değerlendirmesi

Aşağıdaki adımlar PCI-DSS ile ilişkili, dışarıdan gözlemlenen eksiklikleri gidermeye yöneliktir.

### Güvenlik başlıkları

```nginx
add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'self'" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
```

### ISO 27001 Hazırlık Kontrol Listesi

Aşağıdaki adımlar ISO 27001 ile ilişkili, dışarıdan gözlemlenen eksiklikleri gidermeye yöneliktir.

### Güvenlik başlıkları

```nginx
add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'self'" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
```

### Politika sayfası

Erişilebilir bir gizlilik/güvenlik politikası sayfası yayınlayın.

### Ek öneriler

- `/.well-known/security.txt` ile bir zafiyet bildirim kanalı yayınlayın (A.5.7).
- Görünen dış bağımlılıkları (üçüncü taraf servisler) envanterleyip veri-işleyen değerlendirmesine dâhil edin (A.15).