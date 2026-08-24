Dieser Abschnitt enthält bereichsweise Behebungsvorschläge für alle in Ihrem Scan der externen Angriffsfläche festgestellten Mängel. Kopieren Sie die für Ihren Server passenden Beispiele (Nginx/Firebase/Apache/DNS).

### SSL/TLS-Konfigurationsprüfung

Die folgenden Empfehlungen stärken die TLS-/Verschlüsselungskonfiguration für rest.vulnweb.com.

### 1. Fügen Sie den HSTS-Header hinzu

Weist den Browser an, sich nur über HTTPS mit der Website zu verbinden (nur anwenden, wenn Ihre Website vollständig über HTTPS läuft):

**Nginx:**

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

**Firebase Hosting — `firebase.json`:**

```json
{
  "hosting": {
    "headers": [
      {
        "source": "**",
        "headers": [
          { "key": "Strict-Transport-Security", "value": "max-age=31536000; includeSubDomains" }
        ]
      }
    ]
  }
}
```

**Apache — `.htaccess`:**

```apache
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
```

### Sicherheits-Header & Informationsabfluss

Die folgenden Empfehlungen dienen dazu, die auf der Startseite von rest.vulnweb.com festgestellten fehlenden Sicherheits-Header zu beheben. Für jeden Header folgt zunächst eine kurze Erläuterung, anschließend ein Nginx-Beispiel; ganz am Ende finden Sie fertige Blöcke für andere Plattformen als Nginx (Firebase, Vercel, Next.js, Apache). Kopieren Sie den für Ihren Server passenden Block.

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

Überprüfen Sie nach den Änderungen mit den Entwicklertools des Browsers (Registerkarte „Network") oder mit `curl -I https://rest.vulnweb.com`, ob die Header der Antwort hinzugefügt wurden.

### Blockieren Sie den Zugriff auf offen zugängliche Dateien

Festgestellte Pfade: `/db.sql`. Sperren Sie den Zugriff auf Serverebene:

**Nginx:**

```nginx
location ~ /\.(git|env|ht) { deny all; return 404; }
location ~* \.(bak|old|zip|sql)$ { deny all; return 404; }
```

**Apache — `.htaccess`:**

```apache
RedirectMatch 404 /\.git
RedirectMatch 404 /\.env
<FilesMatch "\.(bak|old|zip|sql)$">
  Require all denied
</FilesMatch>
```

Am gesündesten ist es zudem, solche Dateien gar nicht erst in das Web-Root (public) zu legen.

### DNS- & E-Mail-Sicherheit

Die folgenden Empfehlungen stärken die E-Mail-Authentifizierung der Domain vulnweb.com. Fügen Sie die Einträge über die TXT-Oberfläche Ihres DNS-Anbieters (Cloudflare/GoDaddy/…) hinzu.

### DMARC-Eintrag hinzufügen/verschärfen

Überwachen Sie zunächst mit `p=none`, prüfen Sie die Berichte und stellen Sie, sobald Sie sicher sind, dass es keine Falsch-Positiven gibt, auf `quarantine` → `reject` um:

```dns
_dmarc.vulnweb.com.  TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@vulnweb.com; fo=1"
```

### DKIM-Signierung aktivieren

Erzeugen Sie DKIM über das Panel Ihres E-Mail-Anbieters (Google Workspace/Microsoft 365/Versanddienst) und fügen Sie den bereitgestellten TXT-Eintrag unter `selektor._domainkey` hinzu:

```dns
google._domainkey.vulnweb.com.  TXT  "v=DKIM1; k=rsa; p=<vom-Anbieter-bereitgestellter-Schlüssel>"
```

### DNSSEC aktivieren

Aktivieren Sie **DNSSEC** über das Panel Ihres DNS-Anbieters; der Anbieter erzeugt den DS-Eintrag, den Sie bei Ihrem Domain-Registrar eintragen. Durch die Signierung der DNS-Antworten wird Cache-Poisoning erschwert.

### CORS- & Cookie-Sicherheit

Die folgenden Empfehlungen stärken die CORS- und Cookie-Sicherheit für rest.vulnweb.com.

Ihre CORS- und Cookie-Konfiguration liegt nahe an sicheren Standardwerten. Behalten Sie beim Hinzufügen neuer Endpunkte das Prinzip der Origin-Allowlist und der Cookie-Flags (Secure/HttpOnly/SameSite) bei.

### CSP-Analyse (Content-Security-Policy)

Die folgenden Empfehlungen stärken die Content-Security-Policy für rest.vulnweb.com. Testen Sie die CSP zunächst mit dem Header `Content-Security-Policy-Report-Only` und wechseln Sie erst dann zum durchgesetzten (enforce) Header, wenn Sie sicher sind, dass die Website nicht beeinträchtigt wird.

### Basis-CSP (Einstieg)

Erweitern Sie sie, indem Sie Ihre eigenen Drittanbieter-Domains (Analytics, CDN, Font) zu `script-src`/`connect-src`/`img-src` hinzufügen:

**Nginx:**

```nginx
add_header Content-Security-Policy "default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'self'; object-src 'none'; base-uri 'self'" always;
```

**Firebase Hosting — `firebase.json`:**

```json
{
  "hosting": {
    "headers": [
      {
        "source": "**",
        "headers": [
          { "key": "Content-Security-Policy", "value": "default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'self'; object-src 'none'; base-uri 'self'" }
        ]
      }
    ]
  }
}
```

**Apache — `.htaccess`:**

```apache
Header always set Content-Security-Policy "default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'self'; object-src 'none'; base-uri 'self'"
```

### Test mit Report-Only

```
Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-report
```

Nachdem Sie die Berichte überwacht und die Falsch-Positiven beseitigt haben, veröffentlichen Sie den Header als `Content-Security-Policy`.
