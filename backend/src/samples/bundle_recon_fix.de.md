Dieser Abschnitt enthält bereichsweise Behebungsempfehlungen für alle in Ihrer Erkundungsprüfung festgestellten Mängel.

### Subdomain-Takeover — proaktiver Überwachungsleitfaden

Derzeit wurde kein übernehmbares Subdomain festgestellt. Um diesen Zustand **dauerhaft** zu sichern, richten Sie ein Certificate-Transparency-(CT-)Überwachungssystem ein, das neue/unerwartete Subdomain-Zertifikate frühzeitig erkennt:

**1) Kostenlose E-Mail-/Webhook-Benachrichtigung mit certSpotter**

Fügen Sie Ihre Domain (z. B. `nomorelink.com`, inklusive Subdomains) auf `sslmate.com/certspotter` zur Überwachung hinzu; bei Ausstellung eines neuen Zertifikats erhalten Sie eine E-Mail-/Webhook-Benachrichtigung (ein neues Subdomain-Zertifikat kann ein Eintrag sein, den Sie nicht erstellt haben).

**2) Ein einfacher Cronjob, der crt.sh regelmäßig abfragt (auf Ihrem eigenen Server)**

Ein Beispielskript, das täglich die Subdomain-Liste abruft, mit der vorherigen vergleicht und bei einer neu hinzugekommenen Subdomain benachrichtigt:

```bash
#!/usr/bin/env bash
# /etc/cron.daily/ct-watch  (chmod +x)
DOMAIN="ornek.com"
STATE="/var/lib/ct-watch/$DOMAIN.txt"
mkdir -p "$(dirname "$STATE")"; touch "$STATE"
curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" \
  | jq -r ".[].name_value" | tr "[:upper:]" "[:lower:]" | sed "s/^\*\.//" \
  | sort -u > /tmp/ct-now.txt
NEW=$(comm -13 "$STATE" /tmp/ct-now.txt)
if [ -n "$NEW" ]; then
  echo "$NEW" | mail -s "[CT] Yeni alt domain: $DOMAIN" siz@ornek.com
  cp /tmp/ct-now.txt "$STATE"
fi
```

**3) Führen Sie ein Subdomain-Inventar** — dokumentieren Sie, welche Subdomain zu welchem Dienst/Team gehört; entfernen Sie brachliegende (ungenutzte) CNAME-Einträge aus dem DNS, bevor Sie die Cloud-Ressource löschen (die Reihenfolge der Entfernung ist wichtig).

### API- & Swagger-Erkundung — proaktiver Härtungsleitfaden

Es wurde keine öffentlich zugängliche API-Dokumentation gefunden. Um dies dauerhaft zu sichern, stellen Sie Schema-Endpunkte wie Swagger/OpenAPI/ReDoc in der Produktion hinter eine Authentifizierung oder IP-Beschränkung. Wenden Sie das zu Ihrer Plattform passende Beispiel an:

**Nginx — IP-Allowlist + Basic-Auth für `/swagger*`, `/api-docs*`, `/openapi.json`**

```nginx
location ~* ^/(swagger|api-docs|v2/api-docs|v3/api-docs|openapi\.json|redoc) {
    allow 203.0.113.0/24;   # ofis/VPN IP bloğunuz
    deny all;               # geri kalan herkese kapalı
    auth_basic "Restricted";
    auth_basic_user_file /etc/nginx/.htpasswd;  # htpasswd ile oluşturun
    # ... mevcut proxy_pass/try_files yönergeleriniz ...
}
```

**Apache (.htaccess)**

```apache
<LocationMatch "^/(swagger|api-docs|openapi\.json|redoc)">
    AuthType Basic
    AuthName "Restricted"
    AuthUserFile /etc/apache2/.htpasswd
    Require valid-user
    Require ip 203.0.113.0/24
</LocationMatch>
```

**Caddy**

```caddy
@apidocs path /swagger* /api-docs* /openapi.json /redoc*
basic_auth @apidocs {
    admin $2a$14$...   # caddy hash-password ile üretin
}
```

**Zusätzliche Empfehlungen:** Fügen Sie Ihrem OpenAPI-Schema eine globale `security`-Definition hinzu; wenn Sie GraphQL verwenden, deaktivieren Sie Introspection in der Produktion (`introspection: false`).

### CMS & bekannte CVE — proaktiver Aktualitätsleitfaden

Es wurde kein bekanntes CMS erkannt (möglicherweise eine eigene/verschleierte Anwendung). Automatisieren Sie das Aktuellbleiben und die Verfolgung bekannter Schwachstellen:

**1) Wenn Sie WordPress verwenden — automatische Minor- + Sicherheitsupdates**

In `wp-config.php`:

```php
define( 'WP_AUTO_UPDATE_CORE', 'minor' );  // Sicherheits-/Minor-Versionen automatisch
```

Für automatische Plugin-/Theme-Updates (WP-CLI):

```bash
wp plugin auto-updates enable --all
wp theme auto-updates enable --all
```

**2) Fügen Sie Ihrer CI/CD einen kostenlosen Abhängigkeits-Scan (SCA) hinzu**

- **Dependabot** (GitHub, kostenlos): Fügen Sie dem Repository `.github/dependabot.yml` hinzu:

```yaml
version: 2
updates:
  - package-ecosystem: "composer"   # für WordPress/PHP; npm/pip/… werden ebenfalls unterstützt
    directory: "/"
    schedule: { interval: "weekly" }
```

- **npm audit** (Node-Projekte): Fügen Sie Ihrem CI-Schritt `npm audit --audit-level=high` hinzu; bei hohen/kritischen Schwachstellen soll der Build fehlschlagen.

**3) Reduzieren Sie die Versionsoffenlegung** — entfernen/deaktivieren Sie versionsverratende Stellen wie `<meta generator>`, `X-Powered-By`, `/readme.html`, `/CHANGELOG.txt`; so wird die automatische CVE-Zuordnung für Angreifer erschwert.