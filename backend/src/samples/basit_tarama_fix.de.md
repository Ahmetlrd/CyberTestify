Die folgenden Empfehlungen dienen dazu, die auf der Startseite von testasp.vulnweb.com festgestellten fehlenden Sicherheits-Header zu beheben. Für jeden Header folgt zunächst eine kurze Erläuterung, anschließend ein Nginx-Beispiel; ganz am Ende finden Sie fertige Blöcke für andere Plattformen als Nginx (Firebase, Vercel, Next.js, Apache). Kopieren Sie den für Ihren Server passenden Block.

### 1. Content-Security-Policy (CSP) hinzufügen

Dies ist die wirksamste browserseitige Verteidigung gegen XSS und Content-Injektion. Beginnen Sie mit einer für Ihre Website passenden Basisrichtlinie und verschärfen Sie sie mit der Zeit:

```nginx
add_header Content-Security-Policy "default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'self'" always;
```

Wenn Sie Drittanbieter-Skripte verwenden (GTM, Analytics, Pixel), fügen Sie die entsprechenden Domains zu `script-src`/`connect-src` hinzu.

### 2. X-Frame-Options hinzufügen

Verhindert, dass Ihre Seite in ein iframe einer anderen Website eingebettet und so für Clickjacking anfällig wird:

```nginx
add_header X-Frame-Options "SAMEORIGIN" always;
```

Als moderne Alternative bietet die CSP `frame-ancestors 'self'` denselben Schutz.

### 3. X-Content-Type-Options hinzufügen

Verhindert, dass der Browser MIME-Type-Sniffing betreibt und Inhalte falsch interpretiert (und das dadurch entstehende XSS-Risiko):

```nginx
add_header X-Content-Type-Options "nosniff" always;
```

### 4. Strict-Transport-Security (HSTS) hinzufügen

Erzwingt HTTPS und erschwert SSL-Stripping-/MITM-Angriffe. (Nur anwenden, wenn Ihre Website vollständig über HTTPS läuft.)

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

### 5. Referrer-Policy hinzufügen

Verringert den Informationsabfluss im `Referer`-Header, der an externe Links gesendet wird:

```nginx
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

### 6. Permissions-Policy hinzufügen

Schränkt Browser-APIs (Kamera, Mikrofon, Standort usw.) ein; verhindert den unerwünschten Zugriff durch Drittanbieter-iframes:

```nginx
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
```

### 7. X-XSS-Protection (Tiefenverteidigung)

Ein historischer Header für ältere Browser; der eigentliche Schutz liegt in der CSP. Sie können ihn optional hinzufügen:

```nginx
add_header X-XSS-Protection "1; mode=block" always;
```

### Alles zusammenfassende Konfiguration — Nginx

Fügen Sie dies Ihrem Server-Block (server { ... }) hinzu, prüfen Sie es mit `nginx -t` und laden Sie anschließend mit `systemctl reload nginx` neu:

```nginx
add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'self'" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
```

### Fertige Konfiguration für andere Plattformen

Wenn Ihr Server nicht Nginx ist, können Sie dieselben Header mit dem passenden der folgenden fertigen Blöcke hinzufügen.

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

Überprüfen Sie nach den Änderungen mit den Entwicklertools des Browsers (Registerkarte „Network") oder mit `curl -I https://testasp.vulnweb.com`, ob die Header der Antwort hinzugefügt wurden.
