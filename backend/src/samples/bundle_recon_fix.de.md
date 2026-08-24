Dieser Abschnitt enthält bereichsweise Korrekturvorschläge für alle in Ihrem Reconnaissance-Scan festgestellten Mängel.

### Subdomain-Takeover — Leitfaden für proaktive Überwachung

Derzeit wurde keine übernehmbare Subdomain festgestellt. Um diesen Zustand **dauerhaft** zu erhalten, richten Sie ein Certificate-Transparency-(CT)-Überwachungssystem ein, das neue/unerwartete Subdomain-Zertifikate frühzeitig erkennt:

**1) Kostenlose E-Mail-/Webhook-Benachrichtigung mit certSpotter**

Fügen Sie auf `sslmate.com/certspotter` Ihre Domain (z. B. `ornek.com`, inklusive Subdomains) zur Überwachung hinzu; bei Ausstellung eines neuen Zertifikats erhalten Sie eine E-Mail-/Webhook-Benachrichtigung (ein neues Subdomain-Zertifikat könnte ein Eintrag sein, den Sie nicht erstellt haben).

**2) Ein einfacher Cron, der crt.sh periodisch abfragt (auf Ihrem eigenen Server)**

Beispielskript, das täglich die Subdomain-Liste abruft, mit der vorherigen vergleicht und bei einer neu hinzugekommenen Subdomain warnt:

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

**3) Führen Sie ein Subdomain-Inventar** — dokumentieren Sie, welche Subdomain zu welchem Dienst/Team gehört; entfernen Sie verwaiste (ungenutzte) CNAME-Einträge aus dem DNS, bevor Sie die Cloud-Ressource löschen (die Reihenfolge des Entfernens ist wichtig).

### API- & Swagger-Reconnaissance — Leitfaden für proaktive Härtung

Es wurde keine öffentlich zugängliche API-Dokumentation gefunden. Um dies dauerhaft zu machen, stellen Sie Schema-Endpunkte wie Swagger/OpenAPI/ReDoc in der Produktion hinter Authentifizierung oder IP-Beschränkung. Wenden Sie das für Ihre Plattform passende Beispiel an:

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

**Zusätzliche Empfehlungen:** Fügen Sie Ihrem OpenAPI-Schema eine globale `security`-Definition hinzu; wenn Sie GraphQL verwenden, deaktivieren Sie die Introspection in der Produktion (`introspection: false`).

### CMS & Bekannte CVE — Leitfaden zum proaktiven Aktuellbleiben

Für die erkannte Version wurde kein bekannter CVE gefunden, der die Version ausdrücklich abdeckt. Um diesen Zustand zu erhalten, automatisieren Sie das Updaten und scannen Sie Ihre Abhängigkeiten fortlaufend:

**1) Falls Sie WordPress verwenden — automatische Minor- + Sicherheitsupdates**

In `wp-config.php`:

```php
define( 'WP_AUTO_UPDATE_CORE', 'minor' );  // güvenlik/minor sürümleri otomatik
```

Für automatische Plugin-/Theme-Updates (WP-CLI):

```bash
wp plugin auto-updates enable --all
wp theme auto-updates enable --all
```

**2) Fügen Sie in CI/CD kostenlosen Abhängigkeitsscan (SCA) hinzu**

- **Dependabot** (GitHub, kostenlos): fügen Sie dem Repository `.github/dependabot.yml` hinzu:

```yaml
version: 2
updates:
  - package-ecosystem: "composer"   # WordPress/PHP için; npm/pip/… da desteklenir
    directory: "/"
    schedule: { interval: "weekly" }
```

- **npm audit** (Node-Projekte): fügen Sie Ihrem CI-Schritt `npm audit --audit-level=high` hinzu; bei hohen/kritischen Schwachstellen soll der Build fehlschlagen.

**3) Reduzieren Sie die Versionspreisgabe** — entfernen/deaktivieren Sie versionsverratende Stellen wie `<meta generator>`, `X-Powered-By`, `/readme.html`, `/CHANGELOG.txt`; so wird der automatische CVE-Abgleich für Angreifer schwieriger.
