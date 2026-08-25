Bu bölüm, keşif taramanızda tespit edilen tüm eksiklikler için alan alan düzeltme önerileri içerir.

### Subdomain Takeover — proaktif izleme rehberi

Şu an devralınabilir alt domain tespit edilmedi. Bu durumu **sürekli** korumak için, yeni/beklenmeyen alt domain sertifikalarını erken yakalayacak bir Certificate Transparency (CT) izleme sistemi kurun:

**1) certSpotter ile ücretsiz e-posta/webhook uyarısı**

`sslmate.com/certspotter` üzerinde alan adınızı (ör. `nomorelink.com`, alt domainler dahil) izlemeye ekleyin; yeni sertifika yayınlandığında e-posta/webhook uyarısı alırsınız (yeni bir alt domain sertifikası, sizin oluşturmadığınız bir kayıt olabilir).

**2) crt.sh’i periyodik sorgulayan basit bir cron (kendi sunucunuzda)**

Her gün alt domain listesini çekip bir öncekiyle karşılaştıran, yeni giren alt domainde uyarı veren örnek betik:

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

**3) Alt domain envanteri tutun** — hangi alt domainin hangi servise/ekibe ait olduğunu belgeleyin; boşta kalan (kullanılmayan) CNAME kayıtlarını, bulut kaynağını silmeden önce DNS’ten kaldırın (kaldırma sırası önemlidir).

### API & Swagger Keşfi — proaktif sertleştirme rehberi

Herkese açık API dokümantasyonu bulunamadı. Bunu kalıcı kılmak için, Swagger/OpenAPI/ReDoc gibi şema uçlarını üretimde kimlik doğrulama veya IP kısıtı arkasına alın. Platformunuza uygun örneği uygulayın:

**Nginx — `/swagger*`, `/api-docs*`, `/openapi.json` için IP allowlist + Basic-Auth**

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

**Ek öneriler:** OpenAPI şemanıza global `security` tanımı ekleyin; GraphQL kullanıyorsanız üretimde introspection’ı kapatın (`introspection: false`).

### CMS & Bilinen CVE — proaktif güncel kalma rehberi

Bilinen bir CMS tespit edilmedi (özel/gizlenmiş uygulama olabilir). Güncel kalmayı ve bilinen-zafiyet takibini otomatikleştirin:

**1) WordPress kullanıyorsanız — otomatik minor + güvenlik güncellemesi**

`wp-config.php` içine:

```php
define( 'WP_AUTO_UPDATE_CORE', 'minor' );  // güvenlik/minor sürümleri otomatik
```

Eklenti/tema otomatik güncellemesi için (WP-CLI):

```bash
wp plugin auto-updates enable --all
wp theme auto-updates enable --all
```

**2) CI/CD’ye ücretsiz bağımlılık taraması (SCA) ekleyin**

- **Dependabot** (GitHub, ücretsiz): depoya `.github/dependabot.yml` ekleyin:

```yaml
version: 2
updates:
  - package-ecosystem: "composer"   # WordPress/PHP için; npm/pip/… da desteklenir
    directory: "/"
    schedule: { interval: "weekly" }
```

- **npm audit** (Node projeleri): CI adımınıza `npm audit --audit-level=high` ekleyin; yüksek/kritik açık varsa derleme kırılsın.

**3) Sürüm ifşasını azaltın** — `<meta generator>`, `X-Powered-By`, `/readme.html`, `/CHANGELOG.txt` gibi sürüm sızdıran noktaları kaldırın/kapatın; böylece otomatik CVE eşlemesi saldırganlar için zorlaşır.