Aşağıdaki öneriler, testasp.vulnweb.com ana sayfasında tespit edilen eksik güvenlik başlıklarını gidermeye yöneliktir. Her başlık için önce kısa açıklama, ardından Nginx örneği verilmiştir; en sonda Nginx dışı platformlar (Firebase, Vercel, Next.js, Apache) için hazır bloklar bulabilirsiniz. Kendi sunucunuza uygun olanı kopyalayın.

### 1. Content-Security-Policy (CSP) ekleyin

XSS ve içerik enjeksiyonuna karşı en etkili tarayıcı savunmasıdır. Sitenize uygun temel bir politikayla başlayıp zamanla sıkılaştırın:

```nginx
add_header Content-Security-Policy "default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'self'" always;
```

Üçüncü taraf script kullanıyorsanız (GTM, Analytics, Pixel) ilgili alan adlarını `script-src`/`connect-src`e ekleyin.

### 2. X-Frame-Options ekleyin

Sayfanızın başka bir sitenin iframe’ine gömülüp clickjacking’e maruz kalmasını engeller:

```nginx
add_header X-Frame-Options "SAMEORIGIN" always;
```

Modern alternatif olarak CSP `frame-ancestors 'self'` de aynı korumayı sağlar.

### 3. X-Content-Type-Options ekleyin

Tarayıcının MIME-type sniffing yapıp içeriği yanlış yorumlamasını (ve bunun açtığı XSS riskini) engeller:

```nginx
add_header X-Content-Type-Options "nosniff" always;
```

### 4. Strict-Transport-Security (HSTS) ekleyin

HTTPS’i zorunlu kılar ve SSL-stripping/MITM saldırılarını zorlaştırır. (Yalnızca siteniz tamamen HTTPS ise uygulayın.)

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

### 5. Referrer-Policy ekleyin

Dış bağlantılara giden `Referer` başlığındaki bilgi sızıntısını azaltır:

```nginx
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

### 6. Permissions-Policy ekleyin

Tarayıcı API’lerini (kamera, mikrofon, konum vb.) kısıtlar; üçüncü taraf iframe’lerin istenmeyen erişimini engeller:

```nginx
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
```

### 7. X-XSS-Protection (savunma derinliği)

Eski tarayıcılar için tarihi bir başlıktır; asıl koruma CSP’dedir. İsteğe bağlı olarak ekleyebilirsiniz:

```nginx
add_header X-XSS-Protection "1; mode=block" always;
```

### Tümünü birleştiren yapılandırma — Nginx

Sunucu bloğunuza (server { ... }) ekleyip `nginx -t` ile doğrulayın, ardından `systemctl reload nginx` ile yeniden yükleyin:

```nginx
add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'self'" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
```

### Diğer platformlar için hazır yapılandırma

Aynı başlıkları, sunucunuz Nginx değilse aşağıdaki hazır bloklardan uygun olanıyla ekleyebilirsiniz.

**Firebase Hosting — `firebase.json`:**

```json
{
  "hosting": {
    "headers": [
      {
        "source": "**",
        "headers": [
          { "key": "Content-Security-Policy", "value": "default-src 'self'; frame-ancestors 'self'" },
          { "key": "X-Frame-Options", "value": "SAMEORIGIN" },
          { "key": "X-Content-Type-Options", "value": "nosniff" },
          { "key": "Strict-Transport-Security", "value": "max-age=31536000; includeSubDomains" },
          { "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" },
          { "key": "Permissions-Policy", "value": "geolocation=(), microphone=(), camera=()" }
        ]
      }
    ]
  }
}
```

**Vercel — `vercel.json`:**

```json
{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
          { "key": "Content-Security-Policy", "value": "default-src 'self'; frame-ancestors 'self'" },
          { "key": "X-Frame-Options", "value": "SAMEORIGIN" },
          { "key": "X-Content-Type-Options", "value": "nosniff" },
          { "key": "Strict-Transport-Security", "value": "max-age=31536000; includeSubDomains" },
          { "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" },
          { "key": "Permissions-Policy", "value": "geolocation=(), microphone=(), camera=()" }
      ]
    }
  ]
}
```

**Next.js — `next.config.js`:**

```js
module.exports = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          { key: 'Content-Security-Policy', value: 'default-src 'self'; frame-ancestors 'self'' },
          { key: 'X-Frame-Options', value: 'SAMEORIGIN' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          { key: 'Permissions-Policy', value: 'geolocation=(), microphone=(), camera=()' }
        ],
      },
    ];
  },
};
```

**Apache — `.htaccess` (mod_headers):**

```apache
Header always set Content-Security-Policy "default-src 'self'; frame-ancestors 'self'"
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-Content-Type-Options "nosniff"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
```

**IIS / ASP.NET — `web.config`:**

```xml
<configuration>
  <system.webServer>
    <httpProtocol>
      <customHeaders>
      <add name="Content-Security-Policy" value="default-src 'self'; frame-ancestors 'self'" />
      <add name="X-Frame-Options" value="SAMEORIGIN" />
      <add name="X-Content-Type-Options" value="nosniff" />
      <add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains" />
      <add name="Referrer-Policy" value="strict-origin-when-cross-origin" />
      <add name="Permissions-Policy" value="geolocation=(), microphone=(), camera=()" />
      </customHeaders>
    </httpProtocol>
  </system.webServer>
</configuration>
```

Değişikliklerden sonra tarayıcı geliştirici araçları (Network sekmesi) veya `curl -I https://testasp.vulnweb.com` ile başlıkların yanıta eklendiğini doğrulayın.