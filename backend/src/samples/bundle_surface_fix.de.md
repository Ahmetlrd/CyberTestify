Dieser Abschnitt enthält bereichsweise Korrekturvorschläge für alle in Ihrer Prüfung der externen Angriffsfläche festgestellten Lücken. Kopieren Sie die für Ihren Server passenden Beispiele (Nginx/Firebase/Apache/DNS).

### SSL/TLS-Konfigurationsaudit

Die folgenden Empfehlungen stärken die TLS-/Verschlüsselungskonfiguration für rest.vulnweb.com.

### 1. HSTS-Header ergänzen

Weist den Browser an, die Website nur über HTTPS aufzurufen (nur anwenden, wenn Ihre Website vollständig auf HTTPS läuft):

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

### Sicherheits-Header & Informationslecks

Die folgenden Empfehlungen dienen der Behebung der auf der Startseite von rest.vulnweb.com festgestellten fehlenden Sicherheits-Header. Zu jedem Header folgt zuerst eine kurze Erläuterung, dann ein Nginx-Beispiel; am Ende finden Sie fertige Blöcke für andere Plattformen (Firebase, Vercel, Next.js, Apache). Kopieren Sie den zu Ihrem Server passenden Block.

### 1. Content-Security-Policy (CSP) hinzufügen

Die wirksamste Browser-Verteidigung gegen XSS und Content-Injection. Beginnen Sie mit einer zur Website passenden Basisrichtlinie und verschärfen Sie sie mit der Zeit:

```nginx
add_header Content-Security-Policy "default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'self'" always;
```

Wenn Sie Drittanbieter-Skripte verwenden (GTM, Analytics, Pixel), fügen Sie die entsprechenden Domains zu `script-src`/`connect-src` hinzu.

### 2. X-Frame-Options hinzufügen

Verhindert, dass Ihre Seite in das iframe einer fremden Website eingebettet und für Clickjacking missbraucht wird:

```nginx
add_header X-Frame-Options "SAMEORIGIN" always;
```

Als moderne Alternative bietet CSP `frame-ancestors 'self'` denselben Schutz.

### 3. X-Content-Type-Options hinzufügen

Verhindert, dass der Browser per MIME-Type-Sniffing Inhalte falsch interpretiert (und das damit verbundene XSS-Risiko):

```nginx
add_header X-Content-Type-Options "nosniff" always;
```

### 4. Strict-Transport-Security (HSTS) hinzufügen

Erzwingt HTTPS und erschwert SSL-Stripping-/MITM-Angriffe. (Nur anwenden, wenn Ihre Website vollständig über HTTPS läuft.)

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

### 5. Referrer-Policy hinzufügen

Reduziert den Informationsabfluss über den `Referer`-Header bei externen Links:

```nginx
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

### 6. Permissions-Policy hinzufügen

Schränkt Browser-APIs (Kamera, Mikrofon, Standort usw.) ein; verhindert unerwünschte Zugriffe durch Drittanbieter-iframes:

```nginx
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
```

### 7. X-XSS-Protection (Defense-in-Depth)

Ein historischer Header für ältere Browser; der eigentliche Schutz liegt in der CSP. Kann optional ergänzt werden:

```nginx
add_header X-XSS-Protection "1; mode=block" always;
```

### Kombinierte Konfiguration — Nginx

In Ihren Server-Block (server { ... }) einfügen, mit `nginx -t` prüfen und anschließend mit `systemctl reload nginx` neu laden:

```nginx
add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'self'" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
```

### Fertige Konfiguration für andere Plattformen

Falls Ihr Server nicht Nginx ist, können Sie dieselben Header mit einem der folgenden fertigen Blöcke hinzufügen.

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

Prüfen Sie nach den Änderungen mit den Browser-Entwicklertools (Tab „Network") oder mit `curl -I https://rest.vulnweb.com`, dass die Header in der Antwort enthalten sind.

### Zugriff auf offenliegende Dateien sperren

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

Am besten legen Sie diese Dateien zudem gar nicht erst in das Web-Root (public).

### DNS- & E-Mail-Sicherheit

Die folgenden Empfehlungen stärken die E-Mail-Authentifizierung der Domain vulnweb.com. Fügen Sie die Einträge über die TXT-Oberfläche Ihres DNS-Anbieters (Cloudflare/GoDaddy/…) hinzu.

### DMARC-Eintrag hinzufügen/verschärfen

Überwachen Sie zunächst mit `p=none`; sobald Sie die Berichte geprüft und Fehlalarme ausgeschlossen haben, wechseln Sie zu `quarantine` → `reject`:

```dns
_dmarc.vulnweb.com.  TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@vulnweb.com; fo=1"
```

### DKIM-Signierung aktivieren

Erzeugen Sie DKIM über das Panel Ihres E-Mail-Anbieters (Google Workspace/Microsoft 365/Versanddienst) und fügen Sie den bereitgestellten TXT-Eintrag unter `selektor._domainkey` hinzu:

```dns
google._domainkey.vulnweb.com.  TXT  "v=DKIM1; k=rsa; p=<vom-Anbieter-bereitgestellter-Schlüssel>"
```

### DNSSEC aktivieren

Aktivieren Sie **DNSSEC** im Panel Ihres DNS-Anbieters; der Anbieter erzeugt den DS-Eintrag, den Sie bei Ihrem Domain-Registrar eintragen. Es signiert die DNS-Antworten und erschwert Cache-Poisoning.

### CORS- & Cookie-Sicherheit

Die folgenden Empfehlungen stärken die CORS- und Cookie-Sicherheit für rest.vulnweb.com.

Ihre CORS- und Cookie-Konfiguration ist nahe an sicheren Voreinstellungen. Behalten Sie beim Hinzufügen neuer Endpunkte das Prinzip der Origin-Allowlist und der Cookie-Flags (Secure/HttpOnly/SameSite) bei.

### CSP-Analyse (Content Security Policy)

Die folgenden Empfehlungen stärken die Content-Security-Policy für rest.vulnweb.com. Testen Sie die CSP zunächst mit dem Header `Content-Security-Policy-Report-Only` und wechseln Sie erst dann zum durchgesetzten (enforce) Header, wenn Sie sicher sind, dass die Website nicht beeinträchtigt wird.

### Basis-CSP (Einstieg)

Erweitern Sie sie, indem Sie Ihre eigenen Drittanbieter-Domains (Analytics, CDN, Schriftarten) zu `script-src`/`connect-src`/`img-src` hinzufügen:

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

Nachdem Sie die Berichte überwacht und Fehlalarme beseitigt haben, veröffentlichen Sie den Header als `Content-Security-Policy`.