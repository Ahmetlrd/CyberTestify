/**
 * (Keşif Paketi — bundle_recon) DETERMINISTIK BIRLESIK RAPOR URETICISI.
 *
 * subdomain_takeover + api_discovery + cms_cve — ucu de KOD-toplanmis kanittan (reconEvidence.ts)
 * uretilir; PentAGI ajani HIC calismaz. CVE bilgisi yalnizca NVD'nin yapisal cevabindan gelir,
 * Turkce rapor cumlesini HER ZAMAN kod yazar. Cikti bundle_surface/bundle_compliance ile ayni
 * bicimde: TEK Yonetici Ozeti + TEK genel risk rozeti (worst-case + birikimli) + Kapsam & Metodoloji
 * + 3 alan (tam envanter/metodoloji tablolari) + Iyi Pratikler (ucretsiz) + TEK "AI Cozum Onerileri"
 * (kilitli). generateBundleReconReport { findings, fixText } | null doner.
 *
 * LOCALE: 'de'/'en' dışı her locale → Türkçe (mevcut davranış BYTE-IDENTICAL korunur). 'de' → Almanca
 * rapor gövdesi (Sie-form, „…" tırnak). 'en' → İngilizce (UK) rapor gövdesi. Kod bloğu (``` fence) içi
 * TR/DE'de AYNIDIR; 'en' branch'inde kod-içi yorumlar İngilizce'ye çevrilir (kod/komut aynı kalır).
 */
import { collectReconEvidence, type ReconEvidence, type SubEvidence, type ApiEvidence, type CmsEvidence, type BannerCve } from './reconEvidence.js';
import { resolveOrigin } from './surfaceEvidence.js';

const RISK_WORD = { low: 'Düşük', medium: 'Orta', 'medium-high': 'Orta-Yüksek', high: 'Yüksek' } as const;
const RISK_WORD_DE = { low: 'Niedrig', medium: 'Mittel', 'medium-high': 'Mittel-Hoch', high: 'Hoch' } as const;
const RISK_WORD_EN = { low: 'Low', medium: 'Medium', 'medium-high': 'Medium-High', high: 'High' } as const;
type Level = 'low' | 'medium' | 'medium-high' | 'high';
function levelRank(l: Level): number { return l === 'high' ? 3 : l === 'medium-high' ? 2 : l === 'medium' ? 1 : 0; }

type Area = { title: string; level: Level; headline: string; body: string; fixText: string; dataUnavailable?: boolean };

function cautionCve(locale: string): string {
  const de = locale === 'de';
  const en = locale === 'en';
  if (en) return '> **Note:** The CVE list below contains known vulnerabilities that were **automatically mapped via the NVD (NIST National Vulnerability Database)** from the detected version; whether they are exploitable for your version is **not verified**, and some may originate from plugins/themes. For a confirmed assessment, an update + targeted verification are recommended.';
  return de
    ? '> **Hinweis:** Die folgende CVE-Liste enthält bekannte Schwachstellen, die anhand der erkannten Version **automatisch über die NVD (NIST National Vulnerability Database) zugeordnet** wurden; ob sie für Ihre Version ausnutzbar sind, ist **nicht verifiziert**, und ein Teil kann von Plugins/Themes stammen. Für eine gesicherte Einschätzung werden ein Update + eine gezielte Verifikation empfohlen.'
    : '> **Not:** Aşağıdaki CVE listesi, tespit edilen sürümle NVD (NIST Ulusal Zafiyet Veritabanı) üzerinden **otomatik eşlenen** bilinen zafiyetlerdir; sürümünüz için sömürülebilir oldukları **doğrulanmamıştır** ve bir kısmı eklenti/tema kaynaklı olabilir. Kesin durum için güncelleme + hedefli doğrulama önerilir.';
}

const SUB_DISPLAY_MAX = 100; // envanterde gosterilecek alt domain ust siniri (collector CNAME kapsami ile hizali)

// ======================================================================================
// "BULGU YOK" AI COZUM ONERILERI — proaktif sertlestirme/izleme rehberi (%100 kod, LLM yok)
// Bulgu bulunmadiginda bile somut, adim-adim, kopyala-yapistir icerik verir (Grok B).
// ======================================================================================
function buildSubMonitoringFix(locale: string = 'tr'): string {
  const de = locale === 'de';
  const en = locale === 'en';
  const t = (trS: string, deS: string, enS?: string) => (de ? deS : en ? (enS ?? trS) : trS);
  return [
    t('### Subdomain Takeover — proaktif izleme rehberi', '### Subdomain-Takeover — proaktiver Überwachungsleitfaden', '### Subdomain Takeover — proactive monitoring guide'),
    '',
    t('Şu an devralınabilir alt domain tespit edilmedi. Bu durumu **sürekli** korumak için, yeni/beklenmeyen alt domain sertifikalarını erken yakalayacak bir Certificate Transparency (CT) izleme sistemi kurun:', 'Derzeit wurde kein übernehmbares Subdomain festgestellt. Um diesen Zustand **dauerhaft** zu sichern, richten Sie ein Certificate-Transparency-(CT-)Überwachungssystem ein, das neue/unerwartete Subdomain-Zertifikate frühzeitig erkennt:', 'No takeover-able subdomain is currently detected. To keep this state **permanently**, set up a Certificate Transparency (CT) monitoring system that catches new/unexpected subdomain certificates early:'),
    '',
    t('**1) certSpotter ile ücretsiz e-posta/webhook uyarısı**', '**1) Kostenlose E-Mail-/Webhook-Benachrichtigung mit certSpotter**', '**1) Free email/webhook alert with certSpotter**'),
    '',
    t('`sslmate.com/certspotter` üzerinde alan adınızı (ör. `nomorelink.com`, alt domainler dahil) izlemeye ekleyin; yeni sertifika yayınlandığında e-posta/webhook uyarısı alırsınız (yeni bir alt domain sertifikası, sizin oluşturmadığınız bir kayıt olabilir).', 'Fügen Sie Ihre Domain (z. B. `nomorelink.com`, inklusive Subdomains) auf `sslmate.com/certspotter` zur Überwachung hinzu; bei Ausstellung eines neuen Zertifikats erhalten Sie eine E-Mail-/Webhook-Benachrichtigung (ein neues Subdomain-Zertifikat kann ein Eintrag sein, den Sie nicht erstellt haben).', 'Add your domain (e.g. `nomorelink.com`, including subdomains) to monitoring on `sslmate.com/certspotter`; when a new certificate is issued you receive an email/webhook alert (a new subdomain certificate may be a record you did not create).'),
    '',
    t('**2) crt.sh’i periyodik sorgulayan basit bir cron (kendi sunucunuzda)**', '**2) Ein einfacher Cronjob, der crt.sh regelmäßig abfragt (auf Ihrem eigenen Server)**', '**2) A simple cron that queries crt.sh periodically (on your own server)**'),
    '',
    t('Her gün alt domain listesini çekip bir öncekiyle karşılaştıran, yeni giren alt domainde uyarı veren örnek betik:', 'Ein Beispielskript, das täglich die Subdomain-Liste abruft, mit der vorherigen vergleicht und bei einer neu hinzugekommenen Subdomain benachrichtigt:', 'An example script that fetches the subdomain list daily, compares it with the previous one, and alerts on a newly added subdomain:'),
    '',
    '```bash',
    '#!/usr/bin/env bash',
    '# /etc/cron.daily/ct-watch  (chmod +x)',
    'DOMAIN="ornek.com"',
    'STATE="/var/lib/ct-watch/$DOMAIN.txt"',
    'mkdir -p "$(dirname "$STATE")"; touch "$STATE"',
    'curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" \\',
    '  | jq -r ".[].name_value" | tr "[:upper:]" "[:lower:]" | sed "s/^\\*\\.//" \\',
    '  | sort -u > /tmp/ct-now.txt',
    'NEW=$(comm -13 "$STATE" /tmp/ct-now.txt)',
    'if [ -n "$NEW" ]; then',
    '  echo "$NEW" | mail -s "[CT] Yeni alt domain: $DOMAIN" siz@ornek.com',
    '  cp /tmp/ct-now.txt "$STATE"',
    'fi',
    '```',
    '',
    t('**3) Alt domain envanteri tutun** — hangi alt domainin hangi servise/ekibe ait olduğunu belgeleyin; boşta kalan (kullanılmayan) CNAME kayıtlarını, bulut kaynağını silmeden önce DNS’ten kaldırın (kaldırma sırası önemlidir).', '**3) Führen Sie ein Subdomain-Inventar** — dokumentieren Sie, welche Subdomain zu welchem Dienst/Team gehört; entfernen Sie brachliegende (ungenutzte) CNAME-Einträge aus dem DNS, bevor Sie die Cloud-Ressource löschen (die Reihenfolge der Entfernung ist wichtig).', '**3) Keep a subdomain inventory** — document which subdomain belongs to which service/team; remove idle (unused) CNAME records from DNS before deleting the cloud resource (the order of removal matters).'),
  ].join('\n');
}

function buildApiHardeningFix(locale: string = 'tr'): string {
  const de = locale === 'de';
  const en = locale === 'en';
  const t = (trS: string, deS: string, enS?: string) => (de ? deS : en ? (enS ?? trS) : trS);
  return [
    t('### API & Swagger Keşfi — proaktif sertleştirme rehberi', '### API- & Swagger-Erkundung — proaktiver Härtungsleitfaden', '### API & Swagger Reconnaissance — proactive hardening guide'),
    '',
    t('Herkese açık API dokümantasyonu bulunamadı. Bunu kalıcı kılmak için, Swagger/OpenAPI/ReDoc gibi şema uçlarını üretimde kimlik doğrulama veya IP kısıtı arkasına alın. Platformunuza uygun örneği uygulayın:', 'Es wurde keine öffentlich zugängliche API-Dokumentation gefunden. Um dies dauerhaft zu sichern, stellen Sie Schema-Endpunkte wie Swagger/OpenAPI/ReDoc in der Produktion hinter eine Authentifizierung oder IP-Beschränkung. Wenden Sie das zu Ihrer Plattform passende Beispiel an:', 'No publicly accessible API documentation was found. To make this permanent, place schema endpoints such as Swagger/OpenAPI/ReDoc behind authentication or an IP restriction in production. Apply the example matching your platform:'),
    '',
    t('**Nginx — `/swagger*`, `/api-docs*`, `/openapi.json` için IP allowlist + Basic-Auth**', '**Nginx — IP-Allowlist + Basic-Auth für `/swagger*`, `/api-docs*`, `/openapi.json`**', '**Nginx — IP allowlist + Basic Auth for `/swagger*`, `/api-docs*`, `/openapi.json`**'),
    '',
    '```nginx',
    'location ~* ^/(swagger|api-docs|v2/api-docs|v3/api-docs|openapi\\.json|redoc) {',
    t('    allow 203.0.113.0/24;   # ofis/VPN IP bloğunuz', '    allow 203.0.113.0/24;   # ofis/VPN IP bloğunuz', '    allow 203.0.113.0/24;   # your office/VPN IP block'),
    t('    deny all;               # geri kalan herkese kapalı', '    deny all;               # geri kalan herkese kapalı', '    deny all;               # closed to everyone else'),
    '    auth_basic "Restricted";',
    t('    auth_basic_user_file /etc/nginx/.htpasswd;  # htpasswd ile oluşturun', '    auth_basic_user_file /etc/nginx/.htpasswd;  # htpasswd ile oluşturun', '    auth_basic_user_file /etc/nginx/.htpasswd;  # create with htpasswd'),
    t('    # ... mevcut proxy_pass/try_files yönergeleriniz ...', '    # ... mevcut proxy_pass/try_files yönergeleriniz ...', '    # ... your existing proxy_pass/try_files directives ...'),
    '}',
    '```',
    '',
    '**Apache (.htaccess)**',
    '',
    '```apache',
    '<LocationMatch "^/(swagger|api-docs|openapi\\.json|redoc)">',
    '    AuthType Basic',
    '    AuthName "Restricted"',
    '    AuthUserFile /etc/apache2/.htpasswd',
    '    Require valid-user',
    '    Require ip 203.0.113.0/24',
    '</LocationMatch>',
    '```',
    '',
    '**Caddy**',
    '',
    '```caddy',
    '@apidocs path /swagger* /api-docs* /openapi.json /redoc*',
    'basic_auth @apidocs {',
    t('    admin $2a$14$...   # caddy hash-password ile üretin', '    admin $2a$14$...   # caddy hash-password ile üretin', '    admin $2a$14$...   # generate with caddy hash-password'),
    '}',
    '```',
    '',
    t('**Ek öneriler:** OpenAPI şemanıza global `security` tanımı ekleyin; GraphQL kullanıyorsanız üretimde introspection’ı kapatın (`introspection: false`).', '**Zusätzliche Empfehlungen:** Fügen Sie Ihrem OpenAPI-Schema eine globale `security`-Definition hinzu; wenn Sie GraphQL verwenden, deaktivieren Sie Introspection in der Produktion (`introspection: false`).', '**Additional recommendations:** Add a global `security` definition to your OpenAPI schema; if you use GraphQL, disable introspection in production (`introspection: false`).'),
  ].join('\n');
}

function buildCmsHardeningFix(detected: boolean, locale: string = 'tr'): string {
  const de = locale === 'de';
  const en = locale === 'en';
  const t = (trS: string, deS: string, enS?: string) => (de ? deS : en ? (enS ?? trS) : trS);
  return [
    t(`### CMS & Bilinen CVE — proaktif güncel kalma rehberi`, '### CMS & bekannte CVE — proaktiver Aktualitätsleitfaden', '### CMS & known CVE — proactive currency guide'),
    '',
    detected
      ? t('Tespit edilen sürüm için, sürümü açıkça kapsayan bilinen CVE bulunamadı. Bu durumu korumak için güncellemeyi otomatikleştirin ve bağımlılıklarınızı sürekli tarayın:', 'Für die erkannte Version wurde keine bekannte CVE gefunden, die die Version ausdrücklich abdeckt. Um diesen Zustand zu sichern, automatisieren Sie Updates und scannen Sie Ihre Abhängigkeiten kontinuierlich:', 'For the detected version, no known CVE explicitly covering the version was found. To maintain this state, automate updates and scan your dependencies continuously:')
      : t('Bilinen bir CMS tespit edilmedi (özel/gizlenmiş uygulama olabilir). Güncel kalmayı ve bilinen-zafiyet takibini otomatikleştirin:', 'Es wurde kein bekanntes CMS erkannt (möglicherweise eine eigene/verschleierte Anwendung). Automatisieren Sie das Aktuellbleiben und die Verfolgung bekannter Schwachstellen:', 'No known CMS was detected (may be a custom/obfuscated application). Automate staying up to date and tracking known vulnerabilities:'),
    '',
    t('**1) WordPress kullanıyorsanız — otomatik minor + güvenlik güncellemesi**', '**1) Wenn Sie WordPress verwenden — automatische Minor- + Sicherheitsupdates**', '**1) If you use WordPress — automatic minor + security updates**'),
    '',
    t('`wp-config.php` içine:', 'In `wp-config.php`:', 'In `wp-config.php`:'),
    '',
    '```php',
    t("define( 'WP_AUTO_UPDATE_CORE', 'minor' );  // güvenlik/minor sürümleri otomatik", "define( 'WP_AUTO_UPDATE_CORE', 'minor' );  // Sicherheits-/Minor-Versionen automatisch", "define( 'WP_AUTO_UPDATE_CORE', 'minor' );  // security/minor versions automatically"),
    '```',
    '',
    t('Eklenti/tema otomatik güncellemesi için (WP-CLI):', 'Für automatische Plugin-/Theme-Updates (WP-CLI):', 'For automatic plugin/theme updates (WP-CLI):'),
    '',
    '```bash',
    'wp plugin auto-updates enable --all',
    'wp theme auto-updates enable --all',
    '```',
    '',
    t('**2) CI/CD’ye ücretsiz bağımlılık taraması (SCA) ekleyin**', '**2) Fügen Sie Ihrer CI/CD einen kostenlosen Abhängigkeits-Scan (SCA) hinzu**', '**2) Add a free dependency scan (SCA) to your CI/CD**'),
    '',
    t('- **Dependabot** (GitHub, ücretsiz): depoya `.github/dependabot.yml` ekleyin:', '- **Dependabot** (GitHub, kostenlos): Fügen Sie dem Repository `.github/dependabot.yml` hinzu:', '- **Dependabot** (GitHub, free): add `.github/dependabot.yml` to the repository:'),
    '',
    '```yaml',
    'version: 2',
    'updates:',
    t('  - package-ecosystem: "composer"   # WordPress/PHP için; npm/pip/… da desteklenir', '  - package-ecosystem: "composer"   # für WordPress/PHP; npm/pip/… werden ebenfalls unterstützt', '  - package-ecosystem: "composer"   # for WordPress/PHP; npm/pip/… are also supported'),
    '    directory: "/"',
    '    schedule: { interval: "weekly" }',
    '```',
    '',
    t('- **npm audit** (Node projeleri): CI adımınıza `npm audit --audit-level=high` ekleyin; yüksek/kritik açık varsa derleme kırılsın.', '- **npm audit** (Node-Projekte): Fügen Sie Ihrem CI-Schritt `npm audit --audit-level=high` hinzu; bei hohen/kritischen Schwachstellen soll der Build fehlschlagen.', '- **npm audit** (Node projects): add `npm audit --audit-level=high` to your CI step; the build should fail on high/critical vulnerabilities.'),
    '',
    t('**3) Sürüm ifşasını azaltın** — `<meta generator>`, `X-Powered-By`, `/readme.html`, `/CHANGELOG.txt` gibi sürüm sızdıran noktaları kaldırın/kapatın; böylece otomatik CVE eşlemesi saldırganlar için zorlaşır.', '**3) Reduzieren Sie die Versionsoffenlegung** — entfernen/deaktivieren Sie versionsverratende Stellen wie `<meta generator>`, `X-Powered-By`, `/readme.html`, `/CHANGELOG.txt`; so wird die automatische CVE-Zuordnung für Angreifer erschwert.', '**3) Reduce version disclosure** — remove/disable version-leaking points such as `<meta generator>`, `X-Powered-By`, `/readme.html`, `/CHANGELOG.txt`; this makes automatic CVE mapping harder for attackers.'),
  ].join('\n');
}

// ======================================================================================
// 1) subdomain_takeover
// ======================================================================================
function buildSubArea(ev: SubEvidence, locale: string = 'tr'): Area {
  const de = locale === 'de';
  const en = locale === 'en';
  const t = (trS: string, deS: string, enS?: string) => (de ? deS : en ? (enS ?? trS) : trS);
  const subTitle = t('Subdomain Takeover Taraması', 'Subdomain-Takeover-Prüfung', 'Subdomain Takeover Scan');
  const scopeLine = t('> Kapsam: Yalnızca pasif kaynaklar (Certificate Transparency logları + gözlemlenebilir DNS). Alt domain brute-force / aktif tarama yapılmamıştır.', '> Umfang: Nur passive Quellen (Certificate-Transparency-Logs + beobachtbares DNS). Es wurde kein Subdomain-Brute-Force / aktiver Scan durchgeführt.', '> Scope: Passive sources only (Certificate Transparency logs + observable DNS). No subdomain brute-force / active scan was performed.');
  // Veri kaynagina ulasilamadi (crt.sh + certSpotter ikisi de erisilemedi) -> "temiz" DEME.
  if (ev.dataSource === 'unavailable') {
    const body = [
      t('> ⚠️ **Veri kaynağına şu an ulaşılamadı.** Alt domain envanteri, Certificate Transparency (CT) log sağlayıcılarından (crt.sh ve yedek certSpotter) toplanır; bu tarama sırasında **her iki kaynak da** geçici olarak yanıt vermedi (kesinti/zaman aşımı/hız sınırı).', '> ⚠️ **Die Datenquelle war derzeit nicht erreichbar.** Das Subdomain-Inventar wird von Certificate-Transparency-(CT-)Log-Anbietern (crt.sh und ersatzweise certSpotter) erhoben; während dieser Prüfung haben **beide Quellen** vorübergehend nicht geantwortet (Ausfall/Zeitüberschreitung/Ratenbegrenzung).', '> ⚠️ **The data source was not reachable at this time.** The subdomain inventory is collected from Certificate Transparency (CT) log providers (crt.sh and, as a fallback, certSpotter); during this scan **both sources** temporarily did not respond (outage/timeout/rate limit).'),
      '',
      t('Bu nedenle bu bölüm için **sonuç üretilemedi** — bu, "alt domain yok/temiz" anlamına **gelmez**. Tarama kısa süre sonra tekrar denendiğinde bu bölüm normal şekilde dolacaktır. CT kaynakları (özellikle crt.sh) zaman zaman kısa kesintiler yaşayabilir.', 'Daher konnte für diesen Abschnitt **kein Ergebnis erzeugt werden** — das bedeutet **nicht** „keine Subdomain/sauber". Wird die Prüfung kurze Zeit später erneut versucht, füllt sich dieser Abschnitt normal. CT-Quellen (insbesondere crt.sh) können gelegentlich kurze Ausfälle haben.', 'For this reason **no result could be produced** for this section — this does **not** mean “no subdomain/clean”. When the scan is retried shortly, this section will fill in normally. CT sources (especially crt.sh) may occasionally have brief outages.'),
      '',
      scopeLine,
    ].join('\n');
    return { title: subTitle, level: 'low', headline: t('Veri kaynağına ulaşılamadı — sonuç üretilemedi', 'Datenquelle nicht erreichbar — kein Ergebnis erzeugt', 'Data source unreachable — no result produced'), body, fixText: buildSubMonitoringFix(locale), dataUnavailable: true };
  }
  const confirmed = ev.dangling.filter((d) => d.confidence === 'confirmed');
  const suspected = ev.dangling.filter((d) => d.confidence === 'suspected');
  let level: Level = 'low';
  if (confirmed.length) level = 'high';
  else if (suspected.length) level = 'medium-high';

  const headline = confirmed.length
    ? t(`${confirmed.length} devralınabilir (dangling) alt domain tespit edildi`, `${confirmed.length} übernehmbare (dangling) Subdomain(s) festgestellt`, `${confirmed.length} takeover-able (dangling) subdomain(s) detected`)
    : suspected.length
      ? t(`${suspected.length} şüpheli alt domain — manuel doğrulama gerekli`, `${suspected.length} verdächtige Subdomain(s) — manuelle Verifikation erforderlich`, `${suspected.length} suspicious subdomain(s) — manual verification required`)
      : ev.total
        ? t(`${ev.total} alt domain envanterlendi; devralınabilir kayıt tespit edilmedi`, `${ev.total} Subdomains inventarisiert; kein übernehmbarer Eintrag festgestellt`, `${ev.total} subdomains inventoried; no takeover-able record detected`)
        : t('Sertifika şeffaflığı kayıtlarında alt domain görülmedi', 'In den Certificate-Transparency-Einträgen wurde keine Subdomain gesehen', 'No subdomain seen in the Certificate Transparency records');

  const lines: string[] = [];
  lines.push(t(`Certificate Transparency (crt.sh / certSpotter) kayıtlarından **${ev.total}** benzersiz alt domain envanterlendi; bunlardan **${ev.resolved}** tanesinin CNAME kaydı çözümlenip devralma (subdomain takeover) açısından incelendi.`, `Aus den Certificate-Transparency-Einträgen (crt.sh / certSpotter) wurden **${ev.total}** eindeutige Subdomains inventarisiert; davon wurde bei **${ev.resolved}** der CNAME-Eintrag aufgelöst und auf Übernahme (Subdomain-Takeover) untersucht.`, `From the Certificate Transparency records (crt.sh / certSpotter), **${ev.total}** unique subdomains were inventoried; of these, the CNAME record of **${ev.resolved}** was resolved and examined for takeover (subdomain takeover).`));
  lines.push('');

  if (confirmed.length || suspected.length) {
    lines.push(t('### Devralınabilir (dangling) alt domainler\n', '### Übernehmbare (dangling) Subdomains\n', '### Takeover-able (dangling) subdomains\n'));
    lines.push(t('| Alt Domain | CNAME Hedefi | Servis | Durum | Açıklama |', '| Subdomain | CNAME-Ziel | Dienst | Status | Beschreibung |', '| Subdomain | CNAME Target | Service | Status | Description |'));
    lines.push('|-----------|--------------|--------|-------|----------|');
    for (const d of [...confirmed, ...suspected]) {
      lines.push(`| ${d.sub} | ${d.cname} | ${d.service} | ${d.confidence === 'confirmed' ? t('⚠️ Doğrulandı', '⚠️ Bestätigt', '⚠️ Verified') : t('Şüpheli', 'Verdächtig', 'Suspicious') } | ${d.note} |`);
    }
    lines.push('');
    lines.push(t('> **Subdomain takeover riski:** Bir alt domain, artık size ait olmayan/terk edilmiş bir bulut kaynağına (CNAME) işaret ediyorsa, saldırgan o kaynağı kendi adına oluşturup alt domaininiz üzerinden içerik yayınlayabilir (oltalama, çerez/oturum çalma, marka istismarı). En yüksek öncelikli keşif bulgusudur.', '> **Subdomain-Takeover-Risiko:** Wenn eine Subdomain auf eine Ihnen nicht mehr gehörende/verlassene Cloud-Ressource (CNAME) zeigt, kann ein Angreifer diese Ressource auf seinen Namen anlegen und über Ihre Subdomain Inhalte veröffentlichen (Phishing, Cookie-/Sitzungsdiebstahl, Markenmissbrauch). Es ist der Erkundungsbefund mit der höchsten Priorität.', '> **Subdomain takeover risk:** If a subdomain points to a cloud resource (CNAME) that no longer belongs to you / has been abandoned, an attacker can create that resource in their own name and publish content via your subdomain (phishing, cookie/session theft, brand abuse). It is the highest-priority reconnaissance finding.'));
    lines.push('');
  } else {
    // Negatif sonucu OLCULU + olumlu cerceve (garanti vermeden).
    lines.push(t('Çözümlenen CNAME kayıtlarında, terk edilmiş bir bulut kaynağına işaret eden **devralınabilir (dangling)** alt domain tespit edilmedi. Bu, dışarıdan görünen alt domain yüzeyinizin şu an için **dar ve kontrollü** göründüğünü gösterir.', 'In den aufgelösten CNAME-Einträgen wurde keine **übernehmbare (dangling)** Subdomain festgestellt, die auf eine verlassene Cloud-Ressource zeigt. Das zeigt, dass Ihre von außen sichtbare Subdomain-Fläche derzeit **schmal und kontrolliert** wirkt.', 'No **takeover-able (dangling)** subdomain pointing to an abandoned cloud resource was detected among the resolved CNAME records. This indicates that your externally visible subdomain surface currently appears **narrow and controlled**.'));
    lines.push('');
  }

  // TAM ENVANTER TABLOSU (yeni fetch yok; collector'in tasidigi CNAME durumlari).
  if (ev.cnames.length) {
    lines.push(t('### Alt domain envanteri (durum tablosu)\n', '### Subdomain-Inventar (Statustabelle)\n', '### Subdomain inventory (status table)\n'));
    lines.push(t('Bulunan alt domainler ve CNAME çözümlemesi sonucu durumları:', 'Gefundene Subdomains und ihre Status nach CNAME-Auflösung:', 'Found subdomains and their status after CNAME resolution:'));
    lines.push('');
    lines.push(t('| Alt Domain | CNAME Hedefi | Durum |', '| Subdomain | CNAME-Ziel | Status |', '| Subdomain | CNAME Target | Status |'));
    lines.push('|-----------|--------------|-------|');
    const stateLabel = (s: string) => s === 'dangling' ? t('⚠️ Devralınabilir', '⚠️ Übernehmbar', '⚠️ Takeover-able') : s === 'suspected' ? t('⚠️ Şüpheli', '⚠️ Verdächtig', '⚠️ Suspicious') : s === 'managed' ? t('Aktif (yönetilen dış servis)', 'Aktiv (verwalteter externer Dienst)', 'Active (managed external service)') : s === 'active' ? t('Aktif (CNAME kaydı var)', 'Aktiv (CNAME-Eintrag vorhanden)', 'Active (CNAME record present)') : t('CNAME kaydı yok (doğrudan A/AAAA)', 'Kein CNAME-Eintrag (direkt A/AAAA)', 'No CNAME record (direct A/AAAA)');
    for (const c of ev.cnames.slice(0, SUB_DISPLAY_MAX)) {
      lines.push(`| ${c.sub} | ${c.cname ?? '—'} | ${stateLabel(c.state)} |`);
    }
    lines.push('');
    if (ev.total > ev.resolved) {
      lines.push(t(`_(+${ev.total - ev.resolved} alt domain daha CT kayıtlarında bulundu; **tamamı envanterlenmiştir**, yalnızca ilk ${ev.resolved} tanesi bu tabloda CNAME durumuyla gösterilmiştir.)_`, `_(+${ev.total - ev.resolved} weitere Subdomains in den CT-Einträgen gefunden; **alle sind inventarisiert**, nur die ersten ${ev.resolved} werden in dieser Tabelle mit CNAME-Status gezeigt.)_`, `_(+${ev.total - ev.resolved} more subdomains found in the CT records; **all are inventoried**, only the first ${ev.resolved} are shown in this table with CNAME status.)_`));
      lines.push('');
    }
  } else if (ev.subdomains.length) {
    lines.push(t('### Alt domain envanteri\n', '### Subdomain-Inventar\n', '### Subdomain inventory\n'));
    lines.push(ev.subdomains.map((s) => `- ${s}`).join('\n'));
    lines.push('');
  }

  if (ev.managedCnames.length) {
    lines.push(t('### Yönetilen dış servis CNAME’leri (bilgi)\n', '### CNAMEs verwalteter externer Dienste (Information)\n', '### Managed external service CNAMEs (information)\n'));
    lines.push(t('Aşağıdaki alt domainler bilinen bir dış servise (CNAME) işaret ediyor ve şu an **canlı** görünüyor — risk değil, envanter bilgisidir:', 'Die folgenden Subdomains zeigen auf einen bekannten externen Dienst (CNAME) und wirken derzeit **aktiv** — kein Risiko, sondern eine Inventarinformation:', 'The following subdomains point to a known external service (CNAME) and currently appear **live** — not a risk, but inventory information:'));
    lines.push('');
    for (const m of ev.managedCnames.slice(0, 20)) lines.push(`- **${m.sub}** → ${m.cname} (${m.service})`);
    lines.push('');
  }

  lines.push(scopeLine);

  const fixText = confirmed.length || suspected.length
    ? t('### Subdomain Takeover — düzeltme\n\n', '### Subdomain-Takeover — Behebung\n\n', '### Subdomain Takeover — remediation\n\n') +
      [...confirmed, ...suspected].map((d) => t(`- **${d.sub}** (${d.service}): Bu alt domain kullanılmıyorsa DNS’ten **CNAME kaydını silin**. Kullanılıyorsa, ${d.service} tarafında kaynağı **yeniden oluşturup sahiplenin** (claim), böylece kayıt boşta kalmaz.`, `- **${d.sub}** (${d.service}): Wenn diese Subdomain nicht genutzt wird, **löschen Sie den CNAME-Eintrag** aus dem DNS. Wird sie genutzt, **legen Sie die Ressource bei ${d.service} neu an und beanspruchen sie** (claim), damit der Eintrag nicht brachliegt.`, `- **${d.sub}** (${d.service}): If this subdomain is not used, **delete the CNAME record** from DNS. If it is used, **re-create and claim the resource** at ${d.service}, so the record does not stay idle.`)).join('\n') +
      t('\n\n- Genel önlem: Kullanılmayan alt domainleri düzenli olarak temizleyin; bulut kaynağı silmeden önce DNS kaydını kaldırın (kaldırma sırası önemli).', '\n\n- Allgemeine Maßnahme: Bereinigen Sie ungenutzte Subdomains regelmäßig; entfernen Sie den DNS-Eintrag, bevor Sie die Cloud-Ressource löschen (die Reihenfolge der Entfernung ist wichtig).', '\n\n- General measure: Clean up unused subdomains regularly; remove the DNS record before deleting the cloud resource (the order of removal matters).')
    : buildSubMonitoringFix(locale);

  return { title: subTitle, level, headline, body: lines.join('\n'), fixText };
}

// ======================================================================================
// 2) api_discovery
// ======================================================================================
function buildApiArea(ev: ApiEvidence, locale: string = 'tr'): Area {
  const de = locale === 'de';
  const en = locale === 'en';
  const t = (trS: string, deS: string, enS?: string) => (de ? deS : en ? (enS ?? trS) : trS);
  const apiTitle = t('API & Swagger Keşfi', 'API- & Swagger-Erkundung', 'API & Swagger Reconnaissance');
  const spec = ev.spec;
  const sensitive = spec?.sensitive ?? [];
  const noAuthSensitive = sensitive.filter((s) => s.noAuth);
  let level: Level = 'low';
  if (noAuthSensitive.length) level = 'high';
  else if (spec && sensitive.length) level = 'medium-high';
  else if (spec || ev.reachable.length) level = 'medium';

  const headline = noAuthSensitive.length
    ? t(`${noAuthSensitive.length} hassas uç nokta kimlik doğrulamasız görünüyor`, `${noAuthSensitive.length} sensible API-Endpunkte wirken ohne Authentifizierung`, `${noAuthSensitive.length} sensitive endpoint(s) appear to be unauthenticated`)
    : spec && sensitive.length
      ? t(`Herkese açık API şeması + ${sensitive.length} hassas uç nokta`, `Öffentlich zugängliches API-Schema + ${sensitive.length} sensible Endpunkte`, `Publicly accessible API schema + ${sensitive.length} sensitive endpoints`)
      : spec
        ? t(`Herkese açık API şeması (${spec.endpointCount} uç nokta)`, `Öffentlich zugängliches API-Schema (${spec.endpointCount} Endpunkte)`, `Publicly accessible API schema (${spec.endpointCount} endpoints)`)
        : ev.reachable.length
          ? t(`${ev.reachable.length} API dokümantasyon noktası herkese açık`, `${ev.reachable.length} API-Dokumentationsstellen öffentlich zugänglich`, `${ev.reachable.length} API documentation locations publicly accessible`)
          : t('Herkese açık API/Swagger dokümantasyonu bulunamadı', 'Keine öffentlich zugängliche API-/Swagger-Dokumentation gefunden', 'No publicly accessible API/Swagger documentation found');

  const lines: string[] = [];
  lines.push(t(`Aşağıdaki **${ev.tried.length}** yaygın API dokümantasyon/keşif yolu GET ile denenmiştir. Hiçbir uç nokta çağrılmamış/istismar edilmemiştir (pasif keşif).`, `Die folgenden **${ev.tried.length}** gängigen API-Dokumentations-/Erkundungspfade wurden per GET geprüft. Kein Endpunkt wurde aufgerufen/ausgenutzt (passive Erkundung).`, `The following **${ev.tried.length}** common API documentation/discovery paths were checked via GET. No endpoint was called/exploited (passive reconnaissance).`));
  lines.push('');

  // DENENEN TUM YOLLAR — tam liste tablosu (metodoloji seffafligi).
  const reachSet = new Map(ev.reachable.map((r) => [r.path, r.kind]));
  lines.push(t('### Denenen yollar (tam liste)\n', '### Geprüfte Pfade (vollständige Liste)\n', '### Paths checked (full list)\n'));
  lines.push(t('| Yol | HTTP | Durum |', '| Pfad | HTTP | Status |', '| Path | HTTP | Status |'));
  lines.push('|-----|------|-------|');
  for (const t2 of ev.tried) {
    const kind = reachSet.get(t2.path);
    const durum = kind
      ? (kind === 'spec' ? t('✓ Bulundu (OpenAPI/Swagger şeması)', '✓ Gefunden (OpenAPI/Swagger-Schema)', '✓ Found (OpenAPI/Swagger schema)') : kind === 'graphql' ? t('✓ Bulundu (GraphQL)', '✓ Gefunden (GraphQL)', '✓ Found (GraphQL)') : t('✓ Bulundu (Swagger/ReDoc arayüzü)', '✓ Gefunden (Swagger/ReDoc-Oberfläche)', '✓ Found (Swagger/ReDoc interface)'))
      : (t2.status === 401 || t2.status === 403) ? t('Erişim reddedildi (korumalı)', 'Zugriff verweigert (geschützt)', 'Access denied (protected)')
        : t2.status === 200 ? t('Yanıt döndü (şema değil)', 'Antwort erhalten (kein Schema)', 'Response returned (not a schema)')
          : t2.status === 0 ? t('Yanıt yok', 'Keine Antwort', 'No response')
            : t('Bulunamadı', 'Nicht gefunden', 'Not found');
    lines.push(`| ${t2.path} | ${t2.status || '—'} | ${durum} |`);
  }
  lines.push('');

  // (BÖLÜM 1 — SİTE HARİTASI BESLEMESİ) Keşfedilen sayfalardan çıkarılan API/idari-görünümlü aday yollar.
  if (ev.minedTried && ev.minedTried.length) {
    const sensFound = ev.minedTried.filter((m) => m.status === 200 && m.sensitive);
    lines.push(t(`### Site haritası + robots.txt'ten türetilen yol adayları (${ev.pagesScanned} sayfadan ${ev.minedTried.length} aday)\n`, `### Aus Sitemap + robots.txt abgeleitete Pfadkandidaten (${ev.minedTried.length} Kandidaten aus ${ev.pagesScanned} Seiten)\n`, `### Path candidates derived from the sitemap + robots.txt (${ev.minedTried.length} candidates from ${ev.pagesScanned} pages)\n`));
    lines.push(t('Sabit liste **dışında**, keşfedilen sayfalardaki link/script/form referansları **ve `/robots.txt` Disallow girdileri**nden çıkarılan API/idari-görünümlü yollar da GET ile **yalnız varlık** açısından denendi (payload/enjeksiyon YOK — Keşif yalnız "bu uç var mı" tespiti yapar; içerik dökülmez):', 'Über die feste Liste **hinaus** wurden auch aus Link-/Skript-/Formularverweisen der entdeckten Seiten **und den `Disallow`-Einträgen der `/robots.txt`** extrahierte API-/administrativ wirkende Pfade per GET **nur auf Existenz** geprüft (KEIN Payload/keine Injektion — die Erkundung stellt nur fest, „ob dieser Endpunkt existiert“; kein Inhalt wird ausgegeben):', 'Beyond the fixed list, API/administrative-looking paths extracted from link/script/form references on the discovered pages **and the `Disallow` entries of `/robots.txt`** were also checked via GET **for existence only** (NO payload/injection — reconnaissance only determines “whether this endpoint exists”; no content is dumped):'));
    lines.push('');
    lines.push(t('| Aday Yol | Kaynak sayfa | HTTP | Not |', '| Kandidatenpfad | Quellseite | HTTP | Hinweis |', '| Candidate Path | Source page | HTTP | Note |'));
    lines.push('|----------|--------------|------|-----|');
    for (const m of ev.minedTried.slice(0, 15)) {
      const not = m.status === 200 ? (m.sensitive ? t('⚠️ mevcut (idari-görünümlü)', '⚠️ vorhanden (administrativ wirkend)', '⚠️ present (administrative-looking)') : t('mevcut', 'vorhanden', 'present')) : (m.status === 401 || m.status === 403) ? t('korumalı (kimlik doğrulama istiyor)', 'geschützt (erfordert Authentifizierung)', 'protected (requires authentication)') : m.status === 0 ? t('yanıt yok', 'keine Antwort', 'no response') : t('yok/404', 'nicht vorhanden/404', 'not present/404');
      lines.push(`| ${m.path} | ${m.source} | ${m.status || '—'} | ${not} |`);
    }
    lines.push('');
    if (sensFound.length) lines.push(t(`> **${sensFound.length}** idari/hassas-görünümlü yol site haritasından keşfedildi ve erişilebilir (HTTP 200). Bu yolların YETKİ kontrolü **Aktif Doğrulama / Tam Pentest** ile doğrulanmalıdır — Keşif yalnız varlığı tespit eder, yetki testi yapmaz.\n`, `> **${sensFound.length}** administrativ/sensibel wirkende Pfade wurden aus der Sitemap entdeckt und sind erreichbar (HTTP 200). Die BERECHTIGUNGSprüfung dieser Pfade sollte mit **Aktive Verifikation / Umfassender Pentest** verifiziert werden — die Erkundung stellt nur die Existenz fest, keine Berechtigungsprüfung.\n`, `> **${sensFound.length}** administrative/sensitive-looking paths were discovered from the sitemap and are accessible (HTTP 200). The AUTHORISATION check of these paths should be verified with **Active Verification / Full Pentest** — reconnaissance only determines existence, not authorisation.\n`));
  }

  if (spec) {
    lines.push(t('### API şeması detayı\n', '### API-Schema-Details\n', '### API schema details\n'));
    lines.push(t(`- Şema yolu: \`${spec.path}\``, `- Schema-Pfad: \`${spec.path}\``, `- Schema path: \`${spec.path}\``));
    if (spec.title) lines.push(t(`- Başlık: ${spec.title}${spec.version ? ` (v${spec.version})` : ''}`, `- Titel: ${spec.title}${spec.version ? ` (v${spec.version})` : ''}`, `- Title: ${spec.title}${spec.version ? ` (v${spec.version})` : ''}`));
    lines.push(t(`- Tanımlı uç nokta sayısı: **${spec.endpointCount}**`, `- Anzahl definierter Endpunkte: **${spec.endpointCount}**`, `- Number of defined endpoints: **${spec.endpointCount}**`));
    lines.push(t(`- Genel kimlik doğrulama tanımı: ${spec.hasGlobalAuth ? 'var (global `security`)' : '⚠️ şemada global `security` tanımı yok'}`, `- Globale Authentifizierungsdefinition: ${spec.hasGlobalAuth ? 'vorhanden (globale `security`)' : '⚠️ keine globale `security`-Definition im Schema'}`, `- Global authentication definition: ${spec.hasGlobalAuth ? 'present (global `security`)' : '⚠️ no global `security` definition in the schema'}`));
    lines.push('');
    if (sensitive.length) {
      const adminLike = sensitive.filter((s) => s.adminLike);
      lines.push(t('#### Hassas uç noktalar\n', '#### Sensible Endpunkte\n', '#### Sensitive endpoints\n'));
      lines.push(t('Yol/işlem adı hassas anahtar kelime içeren uç noktalar (yalnızca şemadan **PASİF okundu**; hiçbiri **çağrılmadı/test edilmedi**):', 'Endpunkte, deren Pfad-/Operationsname ein sensibles Schlüsselwort enthält (nur **PASSIV aus dem Schema gelesen**; keiner wurde **aufgerufen/getestet**):', 'Endpoints whose path/operation name contains a sensitive keyword (read **PASSIVELY from the schema only**; none were **called/tested**):'));
      lines.push('');
      lines.push(t('| Metot | Yol | Kategori | Kimlik doğrulama (şema) |', '| Methode | Pfad | Kategorie | Authentifizierung (Schema) |', '| Method | Path | Category | Authentication (schema) |'));
      lines.push('|-------|-----|----------|--------------------------|');
      for (const s of sensitive.slice(0, 25)) {
        lines.push(`| ${s.method} | ${s.path} | ${s.adminLike ? '🔑 admin/debug/internal' : t('hassas', 'sensibel', 'sensitive') } | ${s.noAuth ? t('⚠️ tanımsız görünüyor', '⚠️ wirkt undefiniert', '⚠️ appears undefined') : t('tanımlı', 'definiert', 'defined')} |`);
      }
      lines.push('');
      if (adminLike.length) lines.push(t(`> **${adminLike.length}** uç nokta *admin/debug/internal* isimli — şemada özellikle dikkat gerektirir.`, `> **${adminLike.length}** Endpunkte heißen *admin/debug/internal* — im Schema besonders aufmerksam zu prüfen.`, `> **${adminLike.length}** endpoints are named *admin/debug/internal* — require particular attention in the schema.`));
      if (noAuthSensitive.length) lines.push(t(`> **${noAuthSensitive.length} hassas uç nokta** şemada kimlik doğrulama tanımı olmadan listeleniyor (spec gözlemi = "auth tanımsız görünüyor" — "auth yok, eriştik" DEĞİL). Bu bir **göstergedir**; gerçek yetki kontrolü **çağrı yapılarak doğrulanmamıştır**.`, `> **${noAuthSensitive.length} sensible Endpunkte** werden im Schema ohne Authentifizierungsdefinition gelistet (Schema-Beobachtung = „Auth wirkt undefiniert" — NICHT „keine Auth, Zugriff erfolgt"). Das ist ein **Indikator**; die tatsächliche Berechtigungsprüfung wurde **nicht durch einen Aufruf verifiziert**.`, `> **${noAuthSensitive.length} sensitive endpoints** are listed in the schema without an authentication definition (schema observation = “auth appears undefined” — NOT “no auth, accessed”). This is an **indicator**; the actual authorisation check was **not verified by making a call**.`));
      lines.push('');
      lines.push(t('> **Sınır (Keşif):** Bu uç noktalar yalnız şemadan pasif okundu; hiçbiri çağrılmadı, auth aktif test edilmedi. Yetki/erişim doğrulaması **Aktif Doğrulama** ve **Tam Kapsamlı Pentest** paketlerinin kapsamındadır — daha derin doğrulama için bu paketler önerilir.', '> **Grenze (Erkundung):** Diese Endpunkte wurden nur passiv aus dem Schema gelesen; keiner wurde aufgerufen, die Auth wurde nicht aktiv getestet. Die Berechtigungs-/Zugriffsverifikation gehört zum Umfang der Pakete **Aktive Verifikation** und **Umfassender Pentest** — für eine tiefere Verifikation werden diese Pakete empfohlen.', '> **Limit (Reconnaissance):** These endpoints were only read passively from the schema; none were called and auth was not actively tested. Authorisation/access verification is within the scope of the **Active Verification** and **Full-Scope Pentest** packages — these packages are recommended for deeper verification.'));
      lines.push('');
    }
  } else {
    // Negatif sonuc — olculu + olumlu cerceve.
    lines.push(t('Denenen yolların hiçbiri herkese açık bir API şeması/arayüzü döndürmedi. Herkese açık API dokümantasyonu bulunmaması, saldırganların API yüzeyinizi dışarıdan kolayca **haritalayamayacağı** anlamına gelir — bu, dış saldırı yüzeyi açısından olumlu bir işarettir.', 'Keiner der geprüften Pfade lieferte ein öffentlich zugängliches API-Schema/-Interface. Das Fehlen öffentlicher API-Dokumentation bedeutet, dass Angreifer Ihre API-Fläche von außen nicht leicht **kartieren** können — das ist im Hinblick auf die externe Angriffsfläche ein positives Zeichen.', 'None of the paths checked returned a publicly accessible API schema/interface. The absence of public API documentation means attackers cannot easily **map** your API surface from outside — this is a positive sign for the external attack surface.'));
    lines.push('');
  }

  lines.push(t('> Kapsam: Yalnızca herkese açık dokümantasyon yolları GET ile denenmiştir; hiçbir uç nokta çağrılmamış/istismar edilmemiştir (pasif keşif).', '> Umfang: Nur öffentlich zugängliche Dokumentationspfade wurden per GET geprüft; kein Endpunkt wurde aufgerufen/ausgenutzt (passive Erkundung).', '> Scope: Only publicly accessible documentation paths were checked via GET; no endpoint was called/exploited (passive reconnaissance).'));

  const fixText = level === 'low'
    ? buildApiHardeningFix(locale)
    : t('### API & Swagger Keşfi — düzeltme\n\n', '### API- & Swagger-Erkundung — Behebung\n\n', '### API & Swagger Reconnaissance — remediation\n\n') + [
        t('- Üretim ortamında Swagger UI / ReDoc / `*/api-docs` / `openapi.json` gibi şema uçlarını **kapatın** veya kimlik doğrulama (IP allowlist / SSO) arkasına alın.', '- Schließen Sie in der Produktion Schema-Endpunkte wie Swagger UI / ReDoc / `*/api-docs` / `openapi.json` **ab** oder stellen Sie sie hinter eine Authentifizierung (IP-Allowlist / SSO).', '- In production, **close** schema endpoints such as Swagger UI / ReDoc / `*/api-docs` / `openapi.json`, or place them behind authentication (IP allowlist / SSO).'),
        spec && !spec.hasGlobalAuth ? t('- API şemanıza global `security` tanımı ekleyin; her hassas uç nokta için kimlik doğrulama/yetki zorunlu olsun.', '- Fügen Sie Ihrem API-Schema eine globale `security`-Definition hinzu; für jeden sensiblen Endpunkt sollen Authentifizierung/Berechtigung verpflichtend sein.', '- Add a global `security` definition to your API schema; make authentication/authorisation mandatory for every sensitive endpoint.') : '',
        noAuthSensitive.length ? t('- Kimlik doğrulaması görünmeyen hassas uç noktaları (admin/user/export/upload vb.) yetkilendirme kontrolünden geçirin; yetkisiz erişimi test edip kapatın.', '- Unterziehen Sie sensible Endpunkte ohne sichtbare Authentifizierung (admin/user/export/upload usw.) einer Berechtigungsprüfung; testen und schließen Sie unbefugten Zugriff.', '- Put sensitive endpoints without visible authentication (admin/user/export/upload, etc.) through an authorisation check; test and close unauthorised access.') : '',
        ev.reachable.some((r) => r.kind === 'graphql') ? t('- GraphQL introspection’ı üretimde kapatın (`introspection: false`).', '- Deaktivieren Sie GraphQL-Introspection in der Produktion (`introspection: false`).', '- Disable GraphQL introspection in production (`introspection: false`).') : '',
      ].filter(Boolean).join('\n');

  return { title: apiTitle, level, headline, body: lines.join('\n'), fixText };
}

// ======================================================================================
// 3) cms_cve
// ======================================================================================
function fingerprintSources(locale: string): string[] {
  const de = locale === 'de';
  const en = locale === 'en';
  if (en)
    return [
      'HTTP response headers (`Server`, `X-Powered-By`, `X-Generator`, `X-Drupal-Cache`, `X-Magento-Cache-Debug`)',
      '`<meta name="generator">` tag',
      'HTML path/pattern traces (`/wp-content/`, `/wp-includes/`, `Drupal.settings`, `/sites/all/`, `option=com_`, `/media/jui/`, `typo3conf`, `Magento_`)',
      'Common version files (WordPress `/readme.html`, Drupal `/CHANGELOG.txt`)',
      'EXISTENCE of known CMS paths (`/wp-login.php`, `/wp-json/`, `/administrator/`, `/user/login`, `/typo3/` — presence/absence check only; NO login/password attempt)',
      'Library/plugin hints (WooCommerce, jQuery version)',
    ];
  return de
    ? [
        'HTTP-Antwort-Header (`Server`, `X-Powered-By`, `X-Generator`, `X-Drupal-Cache`, `X-Magento-Cache-Debug`)',
        '`<meta name="generator">`-Tag',
        'HTML-Pfad-/Musterspuren (`/wp-content/`, `/wp-includes/`, `Drupal.settings`, `/sites/all/`, `option=com_`, `/media/jui/`, `typo3conf`, `Magento_`)',
        'Gängige Versionsdateien (WordPress `/readme.html`, Drupal `/CHANGELOG.txt`)',
        'EXISTENZ bekannter CMS-Pfade (`/wp-login.php`, `/wp-json/`, `/administrator/`, `/user/login`, `/typo3/` — nur Vorhanden/Nicht-Vorhanden-Prüfung; KEIN Login-/Passwortversuch)',
        'Bibliotheks-/Plugin-Hinweise (WooCommerce, jQuery-Version)',
      ]
    : [
        'HTTP yanıt başlıkları (`Server`, `X-Powered-By`, `X-Generator`, `X-Drupal-Cache`, `X-Magento-Cache-Debug`)',
        '`<meta name="generator">` etiketi',
        'HTML yol/kalıp izleri (`/wp-content/`, `/wp-includes/`, `Drupal.settings`, `/sites/all/`, `option=com_`, `/media/jui/`, `typo3conf`, `Magento_`)',
        'Yaygın sürüm dosyaları (WordPress `/readme.html`, Drupal `/CHANGELOG.txt`)',
        'Bilinen CMS yollarının VARLIĞI (`/wp-login.php`, `/wp-json/`, `/administrator/`, `/user/login`, `/typo3/` — yalnız var/yok kontrolü; giriş/parola denemesi YOK)',
        'Kütüphane/eklenti ipuçları (WooCommerce, jQuery sürümü)',
      ];
}

function cveLevel(ev: CmsEvidence): Level {
  if (!ev.cms) return 'low';
  const worst = ev.cves.reduce((m, c) => Math.max(m, c.score), 0);
  const hasCrit = ev.cves.some((c) => c.severity === 'CRITICAL' || c.score >= 9);
  const hasHigh = ev.cves.some((c) => c.severity === 'HIGH' || c.score >= 7);
  const hasMed = ev.cves.some((c) => c.severity === 'MEDIUM' || c.score >= 4);
  if (hasCrit || hasHigh) return 'high';
  // (SÜTUN 0 — TUTARLI RİSK) MEDIUM CVE = 'Orta' (yapay 'Orta-Yüksek' şişirmesi kaldırıldı).
  if (hasMed) return 'medium';
  if (ev.cms && !ev.version) return 'medium'; // CMS var ama surum yok -> guncellik dogrulanamiyor
  if (worst > 0) return 'low'; // yalnız düşük-skor CVE -> Düşük
  return 'low';
}

function buildCmsArea(ev: CmsEvidence, bannerCves: BannerCve[] = [], locale: string = 'tr'): Area {
  const de = locale === 'de';
  const en = locale === 'en';
  const t = (trS: string, deS: string, enS?: string) => (de ? deS : en ? (enS ?? trS) : trS);
  const cmsTitle = t('CMS & Bilinen CVE Taraması', 'CMS- & bekannte-CVE-Prüfung', 'CMS & known CVE Scan');
  // (B.2) Banner (Server/PHP) sürümü CVE'leri de alan seviyesine katkı verir.
  const banHits = bannerCves.filter((b) => b.cveOk && b.cveTotal > 0);
  const banCritHigh = banHits.reduce((n, b) => n + b.cves.filter((c) => c.severity === 'CRITICAL' || c.severity === 'HIGH' || c.score >= 7).length, 0);
  let level = cveLevel(ev);
  if (banCritHigh > 0) level = 'high';
  else if (banHits.length && level === 'low') level = 'medium';
  const critHigh = ev.cves.filter((c) => c.severity === 'CRITICAL' || c.severity === 'HIGH' || c.score >= 7).length;
  const banClause = banHits.length ? t(` · sunucu/yazılım sürümünde ${banHits.reduce((n, b) => n + b.cveTotal, 0)} bilinen CVE`, ` · ${banHits.reduce((n, b) => n + b.cveTotal, 0)} bekannte CVE in der Server-/Software-Version`, ` · ${banHits.reduce((n, b) => n + b.cveTotal, 0)} known CVEs in the server/software version`) : '';

  const headline = (!ev.cms
    ? t('Bilinen bir CMS parmak izi tespit edilmedi', 'Kein bekannter CMS-Fingerabdruck festgestellt', 'No known CMS fingerprint detected')
    : critHigh
      ? t(`${ev.cms}${ev.version ? ` ${ev.version}` : ''} — ${critHigh} yüksek/kritik CVE ile eşleşiyor`, `${ev.cms}${ev.version ? ` ${ev.version}` : ''} — Übereinstimmung mit ${critHigh} hohen/kritischen CVEs`, `${ev.cms}${ev.version ? ` ${ev.version}` : ''} — matches ${critHigh} high/critical CVEs`)
      : ev.cves.length
        ? t(`${ev.cms}${ev.version ? ` ${ev.version}` : ''} — ${ev.cveTotal} bilinen CVE ile eşleşiyor`, `${ev.cms}${ev.version ? ` ${ev.version}` : ''} — Übereinstimmung mit ${ev.cveTotal} bekannten CVEs`, `${ev.cms}${ev.version ? ` ${ev.version}` : ''} — matches ${ev.cveTotal} known CVEs`)
        : ev.version
          ? t(`${ev.cms} ${ev.version} tespit edildi; eşleşen CVE bulunamadı`, `${ev.cms} ${ev.version} erkannt; keine passende CVE gefunden`, `${ev.cms} ${ev.version} detected; no matching CVE found`)
          : t(`${ev.cms} tespit edildi; sürüm belirlenemedi`, `${ev.cms} erkannt; Version nicht bestimmbar`, `${ev.cms} detected; version could not be determined`)) + banClause;

  const lines: string[] = [];
  // Metodoloji — her durumda goster (seffaflik).
  lines.push(t('### İncelenen parmak izi kaynakları\n', '### Untersuchte Fingerabdruck-Quellen\n', '### Fingerprint sources examined\n'));
  lines.push(t('CMS/çatı ve sürüm tespiti için ana sayfa yanıtı üzerinde aşağıdaki pasif sinyallere bakıldı:', 'Zur CMS-/Framework- und Versionserkennung wurden in der Startseiten-Antwort die folgenden passiven Signale betrachtet:', 'For CMS/framework and version detection, the following passive signals in the home page response were examined:'));
  lines.push('');
  lines.push(fingerprintSources(locale).map((s) => `- ${s}`).join('\n'));
  lines.push('');

  if (!ev.cms) {
    lines.push(t('Bu sinyallerin **hiçbiri** bilinen bir CMS/çatı ile eşleşmedi. Bu, özel geliştirilmiş bir uygulama veya CMS izlerini bilinçli olarak gizleyen bir kurulum olabileceğine işaret eder; her iki durum da dışarıdan otomatik CMS/CVE eşlemesini zorlaştırır.', '**Keines** dieser Signale stimmte mit einem bekannten CMS/Framework überein. Das deutet auf eine eigenentwickelte Anwendung oder eine Installation hin, die CMS-Spuren bewusst verbirgt; beides erschwert die automatische CMS-/CVE-Zuordnung von außen.', '**None** of these signals matched a known CMS/framework. This suggests a custom-built application or an installation that deliberately hides CMS traces; either case makes automatic CMS/CVE mapping from outside harder.'));
    lines.push('');
  } else {
    lines.push(t('### Parmak izi sonucu\n', '### Fingerabdruck-Ergebnis\n', '### Fingerprint result\n'));
    lines.push(t(`- Tespit edilen sistem: **${ev.cms}${ev.version ? ` ${ev.version}` : ''}**`, `- Erkanntes System: **${ev.cms}${ev.version ? ` ${ev.version}` : ''}**`, `- Detected system: **${ev.cms}${ev.version ? ` ${ev.version}` : ''}**`));
    lines.push(t(`- Nasıl tespit edildi: ${ev.evidence.join('; ')}`, `- Wie erkannt: ${ev.evidence.join('; ')}`, `- How it was detected: ${ev.evidence.join('; ')}`));
    if (ev.extras.length) lines.push(t(`- Ek gözlemler: ${ev.extras.join(' · ')}`, `- Zusätzliche Beobachtungen: ${ev.extras.join(' · ')}`, `- Additional observations: ${ev.extras.join(' · ')}`));
    if (!ev.version) lines.push(t('- ⚠️ Sürüm belirlenemedi — CVE eşlemesi için sürüm gereklidir; güncellik dışarıdan doğrulanamadı.', '- ⚠️ Version nicht bestimmbar — für die CVE-Zuordnung ist die Version erforderlich; die Aktualität konnte von außen nicht verifiziert werden.', '- ⚠️ Version could not be determined — the version is required for CVE mapping; currency could not be verified from outside.'));
    lines.push('');

    if (ev.cpeQueried) {
      lines.push(t('### Bilinen CVE eşleşmeleri (NVD)\n', '### Bekannte CVE-Übereinstimmungen (NVD)\n', '### Known CVE matches (NVD)\n'));
      if (!ev.cveOk) {
        lines.push(t('NVD (NIST Ulusal Zafiyet Veritabanı) sorgusu bu tarama sırasında yanıt vermedi; CVE eşlemesi yapılamadı. Lütfen sürümünüzü NVD üzerinde manuel doğrulayın.', 'Die Abfrage der NVD (NIST National Vulnerability Database) hat während dieser Prüfung nicht geantwortet; eine CVE-Zuordnung war nicht möglich. Bitte verifizieren Sie Ihre Version manuell in der NVD.', 'The NVD (NIST National Vulnerability Database) query did not respond during this scan; a CVE mapping could not be performed. Please verify your version manually on the NVD.'));
      } else if (ev.cveTotal === 0) {
        lines.push(t(`Tespit edilen sürüm (\`${ev.cpeQueried}\`) için NVD’de, sürümü açıkça kapsayan bilinen bir CVE bulunamadı. Bu, çekirdek sürümünüzün güncel/yamalı olduğuna dair olumlu bir göstergedir; yine de eklenti/tema güncellemelerini ihmal etmeyin.`, `Für die erkannte Version (\`${ev.cpeQueried}\`) wurde in der NVD keine bekannte CVE gefunden, die die Version ausdrücklich abdeckt. Das ist ein positiver Hinweis darauf, dass Ihre Kernversion aktuell/gepatcht ist; vernachlässigen Sie dennoch Plugin-/Theme-Updates nicht.`, `No known CVE explicitly covering the version (\`${ev.cpeQueried}\`) was found in the NVD. This is a positive indication that your core version is up to date/patched; nevertheless, do not neglect plugin/theme updates.`));
      } else {
        lines.push(t(`\`${ev.cpeQueried}\` için NVD’de, sürümü açıkça kapsayan **${ev.cveTotal}** CVE bulundu. En yüksek CVSS skoruna göre ilk ${ev.cves.length} tanesi:`, `Für \`${ev.cpeQueried}\` wurden in der NVD **${ev.cveTotal}** CVEs gefunden, die die Version ausdrücklich abdecken. Die ersten ${ev.cves.length} nach höchstem CVSS-Score:`, `**${ev.cveTotal}** CVEs explicitly covering the version were found in the NVD for \`${ev.cpeQueried}\`. The first ${ev.cves.length} by highest CVSS score:`));
        lines.push('');
        lines.push(t('| CVE | Ciddiyet | CVSS | Özet |', '| CVE | Schweregrad | CVSS | Zusammenfassung |', '| CVE | Severity | CVSS | Summary |'));
        lines.push('|-----|----------|------|------|');
        for (const c of ev.cves) {
          const sev = en
            ? (c.severity === 'CRITICAL' ? 'Critical' : c.severity === 'HIGH' ? 'High' : c.severity === 'MEDIUM' ? 'Medium' : c.severity === 'LOW' ? 'Low' : '—')
            : de
            ? (c.severity === 'CRITICAL' ? 'Kritisch' : c.severity === 'HIGH' ? 'Hoch' : c.severity === 'MEDIUM' ? 'Mittel' : c.severity === 'LOW' ? 'Niedrig' : '—')
            : (c.severity === 'CRITICAL' ? 'Kritik' : c.severity === 'HIGH' ? 'Yüksek' : c.severity === 'MEDIUM' ? 'Orta' : c.severity === 'LOW' ? 'Düşük' : '—');
          lines.push(`| [${c.id}](https://nvd.nist.gov/vuln/detail/${c.id}) | ${sev} | ${c.score || '—'} | ${c.summary.replace(/\|/g, '\\|')} |`);
        }
        lines.push('');
        if (ev.cveTotal > ev.cves.length) lines.push(t(`_(+${ev.cveTotal - ev.cves.length} eşleşme daha; tam liste NVD’de bu sürümle ilişkilendirilmiştir.)_`, `_(+${ev.cveTotal - ev.cves.length} weitere Übereinstimmungen; die vollständige Liste ist in der NVD dieser Version zugeordnet.)_`, `_(+${ev.cveTotal - ev.cves.length} more matches; the full list is associated with this version in the NVD.)_`));
        lines.push('');
        lines.push(cautionCve(locale));
      }
      lines.push('');
    }
  }
  // (B.2) Banner sürümü → bilinen CVE (NVD) — sunucu/yazılım banner'ından çıkan sürüm için CVE listesi.
  // Üç-durum ŞEFFAF: banner yok → gözlenmedi; NVD yanıtsız → sorgulanamadı (temiz değil); eşleşme yok → temiz.
  lines.push(t('### Sunucu/Yazılım Banner Sürümü — Bilinen CVE (NVD)\n', '### Server-/Software-Banner-Version — Bekannte CVE (NVD)\n', '### Server/Software Banner Version — Known CVE (NVD)\n'));
  if (!bannerCves.length) {
    lines.push(t('Sunucu/yazılım banner\'ında (Server / X-Powered-By) sürüm-taşıyan bir imza gözlenmedi — CVE eşlemesi için sürüm gereklidir. (Sürümü gizlemek olumlu bir sertleştirmedir.)', 'Im Server-/Software-Banner (Server / X-Powered-By) wurde keine versionsverratende Signatur beobachtet — für die CVE-Zuordnung ist die Version erforderlich. (Das Verbergen der Version ist eine positive Härtung.)', 'No version-bearing signature was observed in the server/software banner (Server / X-Powered-By) — the version is required for CVE mapping. (Hiding the version is a positive hardening.)'));
  } else {
    lines.push(t(`Banner'dan çıkan sürüm(ler) NVD'ye bağlandı (istismar/doğrulama YOK — yalnız "bu sürüm için bilinen CVE var mı" göstergesi):`, `Die aus dem Banner ermittelte(n) Version(en) wurden mit der NVD abgeglichen (KEINE Ausnutzung/Verifikation — nur der Indikator „gibt es bekannte CVEs für diese Version"):`, `The version(s) derived from the banner were matched against the NVD (NO exploitation/verification — only the "are there known CVEs for this version" indicator):`));
    lines.push('');
    lines.push(t('| Yazılım/Sürüm | NVD sonucu | Örnek CVE |', '| Software/Version | NVD-Ergebnis | Beispiel-CVE |', '| Software/Version | NVD result | Example CVE |'));
    lines.push('|-----|-------|-------|');
    for (const b of bannerCves) {
      const res = !b.cveOk
        ? t('sorgulanamadı (temiz DEĞİL)', 'nicht abfragbar (NICHT sauber)', 'not queryable (NOT clean)')
        : b.cveTotal === 0
          ? t('✅ eşleşen CVE yok', '✅ keine passende CVE', '✅ no matching CVE')
          : t(`⚠️ ${b.cveTotal} bilinen CVE`, `⚠️ ${b.cveTotal} bekannte CVE`, `⚠️ ${b.cveTotal} known CVEs`);
      // (kısıt) Sayısal CVSS EKLENMEZ — yalnız CVE referans linki (nitel bandlar + CWE/CVE kimliği yeterli).
      const sample = b.cves.length ? `[${b.cves[0].id}](https://nvd.nist.gov/vuln/detail/${b.cves[0].id})` : '—';
      lines.push(`| ${b.product} ${b.version} | ${res} | ${sample} |`);
    }
    lines.push('');
    lines.push(cautionCve(locale));
    lines.push('');
  }

  lines.push(t('> Kapsam: Pasif parmak izi + NVD üzerinden bilinen-CVE eşlemesi. Hiçbir CVE **istismar edilmemiş/doğrulanmamıştır**.', '> Umfang: Passiver Fingerabdruck + CVE-Zuordnung über die NVD. Keine CVE wurde **ausgenutzt/verifiziert**.', '> Scope: Passive fingerprint + known-CVE mapping via the NVD. No CVE was **exploited/verified**.'));

  const fixText = !ev.cms
    ? buildCmsHardeningFix(false, locale)
    : (ev.cves.length === 0
      ? buildCmsHardeningFix(true, locale)
      : t('### CMS & Bilinen CVE — düzeltme\n\n', '### CMS & bekannte CVE — Behebung\n\n', '### CMS & known CVE — remediation\n\n') + [
        t(`- **${ev.cms}${ev.version ? ` ${ev.version}` : ''}** kurulumunu en güncel kararlı sürüme yükseltin; otomatik güvenlik güncellemelerini açın.`, `- Aktualisieren Sie die **${ev.cms}${ev.version ? ` ${ev.version}` : ''}**-Installation auf die neueste stabile Version; aktivieren Sie automatische Sicherheitsupdates.`, `- Upgrade the **${ev.cms}${ev.version ? ` ${ev.version}` : ''}** installation to the latest stable version; enable automatic security updates.`),
        ev.cves.length ? t('- Yukarıdaki CVE’leri NVD bağlantılarından inceleyin; güncelleme ile kapananları öncelikli uygulayın, kapanmayanlar için üreticinin azaltıcı önerilerini (WAF kuralı/yapılandırma) uygulayın.', '- Prüfen Sie die obigen CVEs über die NVD-Links; wenden Sie die durch ein Update behobenen vorrangig an und setzen Sie für die verbleibenden die Minderungsempfehlungen des Herstellers (WAF-Regel/Konfiguration) um.', '- Review the CVEs above via the NVD links; apply those closed by an update first, and for the remaining ones apply the vendor’s mitigation recommendations (WAF rule/configuration).') : '',
        t('- Kullanılmayan eklenti/tema/modülleri kaldırın; kalanları güncel tutun (CVE’lerin önemli kısmı eklenti/tema kaynaklıdır).', '- Entfernen Sie ungenutzte Plugins/Themes/Module; halten Sie die verbleibenden aktuell (ein wesentlicher Teil der CVEs stammt von Plugins/Themes).', '- Remove unused plugins/themes/modules; keep the remaining ones up to date (a significant portion of CVEs originate from plugins/themes).'),
        t('- Sürüm/teknoloji ifşasını azaltın: `<meta generator>`, `X-Powered-By`, `/readme.html`, `/CHANGELOG.txt` gibi sürüm sızdıran noktaları kaldırın/kapatın.', '- Reduzieren Sie die Versions-/Technologieoffenlegung: entfernen/deaktivieren Sie versionsverratende Stellen wie `<meta generator>`, `X-Powered-By`, `/readme.html`, `/CHANGELOG.txt`.', '- Reduce version/technology disclosure: remove/disable version-leaking points such as `<meta generator>`, `X-Powered-By`, `/readme.html`, `/CHANGELOG.txt`.'),
      ].filter(Boolean).join('\n'));

  return { title: cmsTitle, level, headline, body: lines.join('\n'), fixText };
}

// ======================================================================================
// SABIT BOLUMLER (bulgu olsa da olmasa da) — %100 kod, LLM yok
// ======================================================================================
function methodologySection(locale: string): string {
  const de = locale === 'de';
  const en = locale === 'en';
  if (en)
    return '## SCOPE & METHODOLOGY\n\n' +
      'This report was generated automatically from externally observable data using **passive** (non-exploitative) techniques across three reconnaissance areas:\n\n' +
      '- **Subdomain Takeover:** Subdomains are collected from Certificate Transparency logs (crt.sh, with certSpotter as a fallback); each is put through DNS/CNAME resolution via Cloudflare DoH and compared against a signature database of known “dangling” (abandoned cloud services).\n' +
      '- **API & Swagger Reconnaissance:** A fixed list of common API documentation paths is checked via GET; any OpenAPI/Swagger schemas found are parsed and sensitive/unauthenticated endpoints are flagged (the endpoints are not called).\n' +
      '- **CMS & known CVE:** CMS and version fingerprinting is derived from HTTP headers, `<meta generator>` and HTML patterns; if the generator is hidden, it is verified via the EXISTENCE of known CMS paths (GET/existence only — no login attempt). The detected version is matched against known CVEs that explicitly cover the version by querying the NVD (NIST National Vulnerability Database); if the version cannot be read, no CVE mapping is performed (no fabricated CVEs).\n\n' +
      '> All data was collected externally, without causing harm to the target. Authentication-protected areas, the internal network and active exploitation are outside the scope of this package.\n';
  return de
    ? '## UMFANG UND METHODIK\n\n' +
      'Dieser Bericht wurde in drei Erkundungsbereichen mit **passiven** (nicht ausnutzenden) Techniken automatisch aus von außen beobachtbaren Daten erzeugt:\n\n' +
      '- **Subdomain-Takeover:** Subdomains werden aus Certificate-Transparency-Logs (crt.sh, ersatzweise certSpotter) erhoben; jede wird per Cloudflare DoH einer DNS-/CNAME-Auflösung unterzogen und mit einer Signaturdatenbank bekannter „dangling" (verlassener Cloud-Dienste) verglichen.\n' +
      '- **API- & Swagger-Erkundung:** Eine feste Liste gängiger API-Dokumentationspfade wird per GET geprüft; gefundene OpenAPI/Swagger-Schemata werden geparst und sensible/nicht authentifizierte Endpunkte markiert (die Endpunkte werden nicht aufgerufen).\n' +
      '- **CMS & bekannte CVE:** Über HTTP-Header, `<meta generator>` und HTML-Muster werden CMS- und Versions-Fingerabdruck ermittelt; ist der Generator verborgen, wird über die EXISTENZ bekannter CMS-Pfade (nur GET/Existenz — kein Login-Versuch) verifiziert. Die erkannte Version wird durch Abfrage der NVD (NIST National Vulnerability Database) mit bekannten CVEs abgeglichen, die die Version ausdrücklich abdecken; ist die Version nicht lesbar, erfolgt keine CVE-Zuordnung (keine erfundenen CVEs).\n\n' +
      '> Alle Daten wurden von außen und ohne Schaden am Ziel erhoben. Authentifizierungspflichtige Bereiche, das interne Netzwerk und aktive Ausnutzung liegen außerhalb des Umfangs dieses Pakets.\n'
    : '## KAPSAM VE METODOLOJİ\n\n' +
      'Bu rapor, üç keşif alanında **pasif** (istismar içermeyen) tekniklerle, dışarıdan gözlemlenebilir verilerden otomatik olarak üretilmiştir:\n\n' +
      '- **Subdomain Takeover:** Alt domainler Certificate Transparency loglarından (crt.sh, yedek olarak certSpotter) toplanır; her biri Cloudflare DoH ile DNS/CNAME çözümlemesinden geçirilir ve bilinen “dangling” (terk edilmiş bulut servisi) imza veritabanıyla karşılaştırılır.\n' +
      '- **API & Swagger Keşfi:** Yaygın API dokümantasyon yollarından oluşan sabit bir liste GET ile denenir; bulunan OpenAPI/Swagger şemaları ayrıştırılır ve hassas/kimlik-doğrulamasız uç noktalar işaretlenir (uç noktalar çağrılmaz).\n' +
      '- **CMS & Bilinen CVE:** HTTP başlıkları, `<meta generator>` ve HTML kalıpları üzerinden CMS ve sürüm parmak izi çıkarılır; generator gizlenmişse bilinen CMS yollarının VARLIĞI (yalnız GET/existence — giriş denemesi yok) ile doğrulanır. Tespit edilen sürüm, NVD (NIST Ulusal Zafiyet Veritabanı) sorgulanarak — sürümü açıkça kapsayan — bilinen CVE’lerle eşlenir; sürüm okunamazsa CVE eşlemesi yapılmaz (uydurma CVE yok).\n\n' +
      '> Tüm veriler dışarıdan, hedefe zarar vermeden toplanmıştır. Kimlik doğrulama gerektiren alanlar, iç ağ ve aktif sömürü bu paketin kapsamı dışındadır.\n';
}

function bestPracticesSection(locale: string): string {
  const de = locale === 'de';
  const en = locale === 'en';
  if (en)
    return '## BEST PRACTICES / RECOMMENDED NEXT STEPS\n\n' +
      'Regardless of the outcome of this scan, the following are recommended lasting practices to keep your attack surface narrow:\n\n' +
      '- **Clean up unused CNAME records regularly** — records pointing to abandoned cloud resources carry a subdomain takeover risk; remove the DNS record before deleting the cloud resource.\n' +
      '- **If you have API documentation (Swagger/OpenAPI),** keep it open only to authenticated access; do not publish it publicly in production.\n' +
      '- **Keep your CMS, plugin and theme versions** up to date via auto-update or regular tracking; stay patched against known CVEs.\n' +
      '- **Detect new/unexpected subdomain certificates early** with Certificate Transparency (CT) log monitoring tools (crt.sh, certSpotter, etc.).\n' +
      '- **Reduce version/technology disclosure** — do not leak unnecessary version information through headers/tags such as `Server`, `X-Powered-By`, `<meta generator>`.\n' +
      '- **Document your subdomain inventory** — knowing which subdomain belongs to which service/team helps you quickly spot idle records.\n';
  return de
    ? '## BEST PRACTICES / EMPFOHLENE NÄCHSTE SCHRITTE\n\n' +
      'Unabhängig vom Ergebnis dieser Prüfung empfohlene dauerhafte Praktiken, um Ihre Angriffsfläche schmal zu halten:\n\n' +
      '- **Bereinigen Sie ungenutzte CNAME-Einträge regelmäßig** — Einträge, die auf verlassene Cloud-Ressourcen zeigen, bergen Subdomain-Takeover-Risiko; entfernen Sie den DNS-Eintrag, bevor Sie die Cloud-Ressource löschen.\n' +
      '- **Falls Sie eine API-Dokumentation (Swagger/OpenAPI) haben,** halten Sie sie nur für authentifizierten Zugriff offen; veröffentlichen Sie sie in der Produktion nicht öffentlich.\n' +
      '- **Halten Sie Ihre CMS-, Plugin- und Theme-Versionen** per Auto-Update oder regelmäßiger Verfolgung aktuell; bleiben Sie gegen bekannte CVEs gepatcht.\n' +
      '- **Erkennen Sie neue/unerwartete Subdomain-Zertifikate frühzeitig** mit Certificate-Transparency-(CT-)Log-Überwachungstools (crt.sh, certSpotter usw.).\n' +
      '- **Reduzieren Sie die Versions-/Technologieoffenlegung** — verraten Sie über Header/Tags wie `Server`, `X-Powered-By`, `<meta generator>` keine unnötigen Versionsinformationen.\n' +
      '- **Dokumentieren Sie Ihr Subdomain-Inventar** — zu wissen, welche Subdomain zu welchem Dienst/Team gehört, hilft Ihnen, brachliegende Einträge schnell zu erkennen.\n'
    : '## İYİ PRATİKLER / ÖNERİLEN SONRAKİ ADIMLAR\n\n' +
      'Bu tarama sonucundan bağımsız olarak, saldırı yüzeyinizi dar tutmak için önerilen kalıcı uygulamalar:\n\n' +
      '- **Kullanılmayan CNAME kayıtlarını düzenli olarak temizleyin** — terk edilmiş bulut kaynaklarına işaret eden kayıtlar subdomain takeover riski taşır; bulut kaynağını silmeden önce DNS kaydını kaldırın.\n' +
      '- **API dokümantasyonunuz (Swagger/OpenAPI) varsa** yalnızca kimlik doğrulamalı erişime açık tutun; üretimde herkese açık yayınlamayın.\n' +
      '- **CMS, eklenti ve tema sürümlerinizi** otomatik güncelleme veya düzenli takiple güncel tutun; bilinen CVE’lere karşı yamalı kalın.\n' +
      '- **Certificate Transparency (CT) log izleme** araçları (crt.sh, certSpotter vb.) ile yeni/beklenmeyen alt domain sertifikalarını erken fark edin.\n' +
      '- **Sürüm/teknoloji ifşasını azaltın** — `Server`, `X-Powered-By`, `<meta generator>` gibi başlık/etiketlerle gereksiz sürüm bilgisi sızdırmayın.\n' +
      '- **Alt domain envanterinizi belgeleyin** — hangi alt domainin hangi servise/ekibe ait olduğunu bilmek, boşta kalan kayıtları hızlıca fark etmenizi sağlar.\n';
}

// ======================================================================================
// BIRLESTIRME
// ======================================================================================
export function combineReconAreas(ev: ReconEvidence, opts?: { httpOnly?: boolean }, locale: string = 'tr'): { findings: string; fixText: string } | null {
  // Ucu de veri toplayamadiysa fallback.
  if (!ev.sub.ok && !ev.api.ok && !ev.cms.ok) return null;
  const httpOnly = opts?.httpOnly ?? false;
  const de = locale === 'de';
  const en = locale === 'en';
  const t = (trS: string, deS: string, enS?: string) => (de ? deS : en ? (enS ?? trS) : trS);
  const RW = en ? RISK_WORD_EN : de ? RISK_WORD_DE : RISK_WORD;

  const areas: Area[] = [buildSubArea(ev.sub, locale), buildApiArea(ev.api, locale), buildCmsArea(ev.cms, ev.bannerCves, locale)];

  // Risk siralamasi YALNIZ veri toplanabilen alanlar uzerinden (veri-kaynagi-basarisiz alan riske
  // dahil edilmez; "temiz" gibi sayilmaz — surface'in null-alan davranisiyla tutarli).
  const available = areas.filter((a) => !a.dataUnavailable);
  const unavailableCount = areas.length - available.length;
  const ranked = available.map((a) => a).sort((x, y) => levelRank(y.level) - levelRank(x.level));
  const baseWorst: Level = ranked.length ? ranked[0].level : 'low';
  const worstArea = ranked.length ? ranked[0] : areas[0];
  // (SÜTUN 0 — TUTARLI RİSK) Birikimli şişirme KALDIRILDI (surface ile tutarlı): genel = en yüksek
  // TEK alanın seviyesi. Gerçek 'Yüksek' yalnız kritik/yüksek CVE veya httpOnly'dan gelir.
  const areaLevel: Level = baseWorst;
  // (HALÜSİNASYON GUARD) https_missing (Yüksek) 3 keşif ALANININ (subdomain/API/CMS) hiçbirine ait
  // DEĞİLDİR — ayrı, bağımsız kontroldür. Eğer genel seviyeyi yükselten etken buysa, "en yüksek risk
  // [alan] alanında" cümlesi TEMİZ bir alanı yüksek riskin kaynağıymış gibi göstermemeli.
  const worstIsHttps = httpOnly && levelRank(areaLevel) < 3;
  const worst: Level = worstIsHttps ? 'high' : areaLevel;
  const scannedNote = unavailableCount ? t(` (${unavailableCount} alanda veri kaynağına ulaşılamadı)`, ` (in ${unavailableCount} Bereichen Datenquelle nicht erreichbar)`, ` (data source unreachable in ${unavailableCount} areas)`) : '';

  const summary: string[] = [];
  summary.push(
    worst === 'low'
      ? t(`- **Genel risk seviyesi: Düşük** — keşif yüzeyiniz ${available.length} alanda incelendi${scannedNote}; devralınabilir alt domain, açık hassas API veya sürümü kapsayan bilinen yüksek CVE öne çıkmadı. Dışarıdan görünen yüzeyiniz şu an için dar ve kontrollü görünüyor.`, `- **Gesamtrisikostufe: Niedrig** — Ihre Erkundungsfläche wurde in ${available.length} Bereichen untersucht${scannedNote}; keine übernehmbare Subdomain, keine offene sensible API und keine die Version abdeckende bekannte hohe CVE traten hervor. Ihre von außen sichtbare Fläche wirkt derzeit schmal und kontrolliert.`, `- **Overall risk level: Low** — your reconnaissance surface was examined across ${available.length} areas${scannedNote}; no takeover-able subdomain, exposed sensitive API or known high CVE covering the version stood out. Your externally visible surface currently appears narrow and controlled.`)
      : worstIsHttps
        ? t(`- **Genel risk seviyesi: Yüksek** — ${available.length} alan incelendi${scannedNote}; en yüksek risk **HTTPS/TLS yapılandırmasında** (HTTPS desteklenmiyor — şifresiz iletişim). Keşif alanlarının (alt domain, API, CMS) en yükseği **${worstArea.title}** (${RISK_WORD[worstArea.level]}); bu alanlarda öne çıkan ayrı bir risk yok.`, `- **Gesamtrisikostufe: Hoch** — ${available.length} Bereiche untersucht${scannedNote}; das höchste Risiko liegt in der **HTTPS/TLS-Konfiguration** (HTTPS wird nicht unterstützt — unverschlüsselte Kommunikation). Der höchste der Erkundungsbereiche (Subdomain, API, CMS) ist **${worstArea.title}** (${RW[worstArea.level]}); in diesen Bereichen tritt kein eigenes Risiko hervor.`, `- **Overall risk level: High** — ${available.length} areas examined${scannedNote}; the highest risk is in the **HTTPS/TLS configuration** (HTTPS not supported — unencrypted communication). The highest of the reconnaissance areas (subdomain, API, CMS) is **${worstArea.title}** (${RISK_WORD_EN[worstArea.level]}); no separate risk stands out in these areas.`)
        : t(`- **Genel risk seviyesi: ${RISK_WORD[worst]}** — ${available.length} alan incelendi${scannedNote}; en yüksek risk **${worstArea.title}** alanında (${worstArea.headline}).`, `- **Gesamtrisikostufe: ${RW[worst]}** — ${available.length} Bereiche untersucht${scannedNote}; das höchste Risiko liegt im Bereich **${worstArea.title}** (${worstArea.headline}).`, `- **Overall risk level: ${RISK_WORD_EN[worst]}** — ${available.length} areas examined${scannedNote}; the highest risk is in the **${worstArea.title}** area (${worstArea.headline}).`),
  );
  if (httpOnly) summary.push(t('- ⚠️ **HTTPS desteklenmiyor:** Hedef HTTPS (443) üzerinden yanıt vermedi; keşif http:// üzerinden yürütüldü. Şifresiz iletişim başlı başına ciddi bir bulgudur (aşağıda).', '- ⚠️ **HTTPS wird nicht unterstützt:** Das Ziel hat nicht über HTTPS (443) geantwortet; die Erkundung wurde über http:// durchgeführt. Unverschlüsselte Kommunikation ist für sich genommen ein ernster Befund (siehe unten).', '- ⚠️ **HTTPS not supported:** The target did not respond over HTTPS (443); reconnaissance was carried out over http://. Unencrypted communication is a serious finding in itself (see below).'));
  for (const a of areas) summary.push(a.dataUnavailable ? t(`- **${a.title}:** ⚠️ incelenemedi (veri kaynağına ulaşılamadı) — "temiz" anlamına gelmez`, `- **${a.title}:** ⚠️ nicht prüfbar (Datenquelle nicht erreichbar) — bedeutet nicht „sauber"`, `- **${a.title}:** ⚠️ not assessable (data source unreachable) — does not mean “clean”`) : `- **${a.title}:** ${RW[a.level]} — ${a.headline}`);
  // (Grok B4) TEMİZ raporlar dahil GERÇEK kapsam sayıları — "ne kadar bakıldığını" şeffaf göster (padding DEĞİL).
  {
    const subPart = ev.sub.dataSource === 'unavailable' ? t('alt domain envanteri: veri kaynağına ulaşılamadı', 'Subdomain-Inventar: Datenquelle nicht erreichbar', 'subdomain inventory: data source unreachable') : t(`${ev.sub.total} alt domain envanterlendi`, `${ev.sub.total} Subdomains inventarisiert`, `${ev.sub.total} subdomains inventoried`);
    const apiPathsTried = (ev.api.tried?.length ?? 0) + (ev.api.minedTried?.length ?? 0);
    const fpLen = fingerprintSources(locale).length;
    summary.push(t(`- **Kapsam (gerçek sayılar):** ${subPart} · ${apiPathsTried} API/Swagger yolu denendi (${ev.api.pagesScanned ?? 1} sayfa tarandı) · ${fpLen}+ pasif CMS/teknoloji sinyali incelendi.`, `- **Umfang (echte Zahlen):** ${subPart} · ${apiPathsTried} API-/Swagger-Pfade geprüft (${ev.api.pagesScanned ?? 1} Seiten gescannt) · ${fpLen}+ passive CMS-/Technologiesignale untersucht.`, `- **Scope (real numbers):** ${subPart} · ${apiPathsTried} API/Swagger paths checked (${ev.api.pagesScanned ?? 1} pages scanned) · ${fpLen}+ passive CMS/technology signals examined.`));
  }
  summary.push(t('- **Önerilen ilk adım:** En yüksek riskli alandan başlayın; her bulgu için adım adım hazır çözümler "AI Çözüm Önerileri" bölümünde sunulur.', '- **Empfohlener erster Schritt:** Beginnen Sie mit dem Bereich mit dem höchsten Risiko; für jeden Befund werden schrittweise fertige Lösungen im Abschnitt „KI-Lösungsvorschläge" bereitgestellt.', '- **Recommended first step:** Start with the highest-risk area; step-by-step ready-made solutions for each finding are provided in the “AI Solution Suggestions” section.'));

  const genelSentence =
    worstIsHttps
      ? t(`Keşif alanlarında (alt domain devralma, açık API, bilinen CVE) öne çıkan bir risk tespit edilmedi; genel değerlendirmeyi Yüksek'e taşıyan etken **şifresiz iletişimdir** (HTTPS desteklenmiyor — yukarıda). Aşağıda her alan ayrı ayrı raporlanmıştır.`, `In den Erkundungsbereichen (Subdomain-Übernahme, offene API, bekannte CVE) wurde kein hervortretendes Risiko festgestellt; der Faktor, der die Gesamtbewertung auf Hoch anhebt, ist die **unverschlüsselte Kommunikation** (HTTPS wird nicht unterstützt — siehe oben). Nachfolgend wird jeder Bereich einzeln berichtet.`, `No prominent risk was detected in the reconnaissance areas (subdomain takeover, exposed API, known CVE); the factor raising the overall assessment to High is **unencrypted communication** (HTTPS not supported — see above). Each area is reported separately below.`)
      : worst === 'high'
        ? t(`En yüksek risk **${worstArea.title}** alanında (${worstArea.headline}) tespit edildi; öncelikli olarak giderilmesi önerilir. Aşağıda her alan ayrı ayrı raporlanmıştır.`, `Das höchste Risiko wurde im Bereich **${worstArea.title}** (${worstArea.headline}) festgestellt; eine vorrangige Behebung wird empfohlen. Nachfolgend wird jeder Bereich einzeln berichtet.`, `The highest risk was detected in the **${worstArea.title}** area (${worstArea.headline}); priority remediation is recommended. Each area is reported separately below.`)
        : worst === 'medium-high'
          ? t(`Öne çıkan alan **${worstArea.title}** (${worstArea.headline}); tek başına yüksek etkili. Öncelikli olarak giderilmesi önerilir. Aşağıda her alan ayrı ayrı raporlanmıştır.`, `Der hervortretende Bereich ist **${worstArea.title}** (${worstArea.headline}); für sich genommen hochwirksam. Eine vorrangige Behebung wird empfohlen. Nachfolgend wird jeder Bereich einzeln berichtet.`, `The prominent area is **${worstArea.title}** (${worstArea.headline}); high impact on its own. Priority remediation is recommended. Each area is reported separately below.`)
          : worst === 'medium'
            ? t(`Öne çıkan alan **${worstArea.title}** (${worstArea.headline}); kısa vadede giderilmesi önerilir. Aşağıda her alan ayrı ayrı raporlanmıştır.`, `Der hervortretende Bereich ist **${worstArea.title}** (${worstArea.headline}); eine kurzfristige Behebung wird empfohlen. Nachfolgend wird jeder Bereich einzeln berichtet.`, `The prominent area is **${worstArea.title}** (${worstArea.headline}); short-term remediation is recommended. Each area is reported separately below.`)
            : t('Dışarıdan görünen alt domain, API ve CMS yüzeyiniz şu an için dar ve kontrollü görünüyor; rapor, tam envanter ve önerilen iyi pratiklerle birlikte her alanı ayrı ayrı belgeler. Aşağıda her alan ayrı ayrı raporlanmıştır.', 'Ihre von außen sichtbare Subdomain-, API- und CMS-Fläche wirkt derzeit schmal und kontrolliert; der Bericht dokumentiert jeden Bereich einzeln, zusammen mit dem vollständigen Inventar und empfohlenen Best Practices. Nachfolgend wird jeder Bereich einzeln berichtet.', 'Your externally visible subdomain, API and CMS surface currently appears narrow and controlled; the report documents each area separately, together with the full inventory and recommended best practices. Each area is reported separately below.');

  const areaSections = areas.map((a) => a.dataUnavailable
    ? `## ${a.title}\n\n**${a.headline}**\n\n${a.body}\n`
    : `## ${a.title}\n\n**${t('Genel risk seviyesi', 'Gesamtrisikostufe', 'Overall risk level')}: ${RW[a.level]} — ${a.headline}**\n\n${a.body}\n`).join('\n');

  // (MERKEZİ FINDINGS -> 2.1 Dağılım + 2.2 Master) http-only https_missing + RİSK TAŞIYAN keşif
  // alanları (dangling subdomain / açık API / bilinen CVE) ŞİDDET-kolonlu TEK tabloda toplanır ki
  // rozet=dağılım=master aynı bulgu setini yansıtsın (madde/bölüm-içi metin master'a girmiyordu).
  const sevWord = (l: Level): string => en
    ? (l === 'high' || l === 'medium-high' ? 'High' : l === 'medium' ? 'Medium' : 'Low')
    : de
    ? (l === 'high' || l === 'medium-high' ? 'Hoch' : l === 'medium' ? 'Mittel' : 'Niedrig')
    : (l === 'high' || l === 'medium-high' ? 'Yüksek' : l === 'medium' ? 'Orta' : 'Düşük');
  const centralRows: string[] = [];
  if (httpOnly) centralRows.push(t(`| HTTPS desteklenmiyor (şifresiz iletişim) | Yüksek | Hedef HTTPS'e yanıt vermiyor; tüm trafik şifresiz (düz metin) taşınıyor — dinlenebilir/değiştirilebilir. Çözüm: geçerli TLS sertifikası + HTTP→HTTPS yönlendirme + HSTS. |`, `| HTTPS wird nicht unterstützt (unverschlüsselte Kommunikation) | Hoch | Das Ziel antwortet nicht über HTTPS; der gesamte Verkehr wird unverschlüsselt (Klartext) übertragen — mitlesbar/veränderbar. Lösung: gültiges TLS-Zertifikat + HTTP→HTTPS-Umleitung + HSTS. |`, `| HTTPS not supported (unencrypted communication) | High | The target does not respond over HTTPS; all traffic is carried unencrypted (plaintext) — interceptable/modifiable. Solution: valid TLS certificate + HTTP→HTTPS redirect + HSTS. |`));
  for (const a of available) {
    if (levelRank(a.level) >= 1) centralRows.push(t(`| ${a.title} — ${a.headline.replace(/\|/g, '\\|')} | ${sevWord(a.level)} | Ayrıntı aşağıdaki “${a.title}” bölümündedir. |`, `| ${a.title} — ${a.headline.replace(/\|/g, '\\|')} | ${sevWord(a.level)} | Details im Abschnitt „${a.title}" unten. |`, `| ${a.title} — ${a.headline.replace(/\|/g, '\\|')} | ${sevWord(a.level)} | See the “${a.title}” section below for details. |`));
  }
  const httpsFindingSection = centralRows.length
    ? `## ${t('TESPİT EDİLEN RİSKLER', 'FESTGESTELLTE RISIKEN', 'IDENTIFIED RISKS')}\n\n| ${t('Bulgu', 'Befund', 'Finding')} | ${t('Şiddet', 'Schweregrad', 'Severity')} | ${t('Açıklama', 'Beschreibung', 'Description')} |\n|-------|--------|----------|\n${centralRows.join('\n')}\n\n`
    : '';

  // (BÖLÜM 2 — POZİTİF GÜVENCE) Keşif çoğu hedefte temiz çıkar; NE denendiğini GERÇEK sayılarla göster.
  const paScanned = ev.api.pagesScanned ?? 1;
  const apiTriedTotal = (ev.api.tried?.length ?? 0) + (ev.api.minedTried?.length ?? 0);
  const minedSensExists = (ev.api.minedTried ?? []).filter((m) => m.status === 200 && m.sensitive).length;
  const subRow = !ev.sub.ok ? t('⚠️ İncelenemedi (veri kaynağına ulaşılamadı — “temiz” DEĞİL)', '⚠️ Nicht prüfbar (Datenquelle nicht erreichbar — NICHT „sauber")', '⚠️ Not assessable (data source unreachable — NOT “clean”)') : ev.sub.dangling.length ? t(`⚠️ ${ev.sub.dangling.length} devralınabilir (dangling) alt domain`, `⚠️ ${ev.sub.dangling.length} übernehmbare (dangling) Subdomains`, `⚠️ ${ev.sub.dangling.length} takeover-able (dangling) subdomains`) : t(`✅ ${ev.sub.total} alt domain kaydı denendi; devralma göstergesi bulunamadı`, `✅ ${ev.sub.total} Subdomain-Einträge geprüft; kein Übernahme-Indikator gefunden`, `✅ ${ev.sub.total} subdomain records checked; no takeover indicator found`);
  const apiRow = !ev.api.ok ? t('⚠️ İncelenemedi', '⚠️ Nicht prüfbar', '⚠️ Not assessable') : ev.api.spec ? t(`⚠️ Herkese açık API şeması bulundu (${ev.api.spec.endpointCount} uç nokta)`, `⚠️ Öffentlich zugängliches API-Schema gefunden (${ev.api.spec.endpointCount} Endpunkte)`, `⚠️ Publicly accessible API schema found (${ev.api.spec.endpointCount} endpoints)`) : ev.api.reachable.length ? t(`⚠️ ${ev.api.reachable.length} API dokümantasyon arayüzü açık`, `⚠️ ${ev.api.reachable.length} API-Dokumentationsoberflächen offen`, `⚠️ ${ev.api.reachable.length} API documentation interfaces open`) : t(`✅ ${apiTriedTotal} yol denendi (${ev.api.tried.length} sabit + ${ev.api.minedTried?.length ?? 0} site-haritası adayı, ${paScanned} sayfadan); herkese açık API şeması bulunamadı`, `✅ ${apiTriedTotal} Pfade geprüft (${ev.api.tried.length} fest + ${ev.api.minedTried?.length ?? 0} Sitemap-Kandidaten, aus ${paScanned} Seiten); kein öffentlich zugängliches API-Schema gefunden`, `✅ ${apiTriedTotal} paths checked (${ev.api.tried.length} fixed + ${ev.api.minedTried?.length ?? 0} sitemap candidates, from ${paScanned} pages); no publicly accessible API schema found`);
  const cmsRow = !ev.cms.ok ? t('⚠️ İncelenemedi', '⚠️ Nicht prüfbar', '⚠️ Not assessable') : ev.cms.cms ? (ev.cms.cveTotal ? t(`⚠️ ${ev.cms.cms}${ev.cms.version ? ' ' + ev.cms.version : ''} — bilinen ${ev.cms.cveTotal} CVE eşleşti`, `⚠️ ${ev.cms.cms}${ev.cms.version ? ' ' + ev.cms.version : ''} — Übereinstimmung mit ${ev.cms.cveTotal} bekannten CVEs`, `⚠️ ${ev.cms.cms}${ev.cms.version ? ' ' + ev.cms.version : ''} — matches ${ev.cms.cveTotal} known CVEs`) : t(`✅ ${ev.cms.cms}${ev.cms.version ? ' ' + ev.cms.version : ''} tespit edildi; sürümü kapsayan bilinen yüksek CVE eşleşmedi`, `✅ ${ev.cms.cms}${ev.cms.version ? ' ' + ev.cms.version : ''} erkannt; keine die Version abdeckende bekannte hohe CVE übereinstimmend`, `✅ ${ev.cms.cms}${ev.cms.version ? ' ' + ev.cms.version : ''} detected; no known high CVE covering the version matched`)) : t(`✅ Bilinen bir CMS/çatı parmak izi tespit edilmedi`, `✅ Kein bekannter CMS-/Framework-Fingerabdruck festgestellt`, `✅ No known CMS/framework fingerprint detected`);
  // (B.2 — POZİTİF GÜVENCE) Sunucu/yazılım banner (Apache/nginx/PHP) → NVD bilinen-CVE — CMS'ten AYRI, temizken bile "denendi".
  const banHits = (ev.bannerCves ?? []).filter((b) => b.cveOk && b.cveTotal > 0);
  const banQueried = (ev.bannerCves ?? []).filter((b) => b.cveOk);
  const banRow = !(ev.bannerCves ?? []).length
    ? t('✅ Sürüm-taşıyan sunucu/yazılım banner’ı gözlenmedi (sürüm gizli — CVE eşlemesi yapılamadı)', '✅ Kein versionsverratender Server-/Software-Banner beobachtet (Version verborgen — keine CVE-Zuordnung)', '✅ No version-bearing server/software banner observed (version hidden — no CVE mapping)')
    : banHits.length
      ? t(`⚠️ Banner sürümünde ${banHits.reduce((n, b) => n + b.cveTotal, 0)} bilinen CVE (${banHits.map((b) => `${b.product} ${b.version}`).join(', ')})`, `⚠️ ${banHits.reduce((n, b) => n + b.cveTotal, 0)} bekannte CVE in Banner-Version (${banHits.map((b) => `${b.product} ${b.version}`).join(', ')})`, `⚠️ ${banHits.reduce((n, b) => n + b.cveTotal, 0)} known CVEs in banner version (${banHits.map((b) => `${b.product} ${b.version}`).join(', ')})`)
      : banQueried.length
        ? t(`✅ ${banQueried.length} banner sürümü NVD’ye soruldu; eşleşen bilinen CVE yok`, `✅ ${banQueried.length} Banner-Version(en) an NVD abgefragt; keine passende bekannte CVE`, `✅ ${banQueried.length} banner version(s) queried against NVD; no matching known CVE`)
        : t('⚠️ Banner sürümü NVD’de sorgulanamadı (“temiz” DEĞİL)', '⚠️ Banner-Version in der NVD nicht abfragbar (NICHT „sauber")', '⚠️ Banner version not queryable in NVD (NOT “clean”)');
  // (B.1 — POZİTİF GÜVENCE) Site haritası + robots.txt Disallow yol keşfi — HER ZAMAN "denendi" göster (temizken bile).
  const minedN = ev.api.minedTried?.length ?? 0;
  const robotsRow = minedSensExists
    ? t(`⚠️ ${minedSensExists} idari-görünümlü yol erişilebilir (yetki testi Aktif Doğrulama kapsamı)`, `⚠️ ${minedSensExists} administrativ wirkende Pfade erreichbar (Berechtigungsprüfung im Umfang der Aktiven Verifikation)`, `⚠️ ${minedSensExists} administrative-looking paths accessible (authorisation testing within Active Verification scope)`)
    : t(`✅ Site haritası + robots.txt Disallow’dan türetilen ${minedN} yol denendi (yalnız varlık); hassas/idari uç bulunamadı`, `✅ ${minedN} aus Sitemap + robots.txt-Disallow abgeleitete Pfade geprüft (nur Existenz); kein sensibler/administrativer Endpunkt gefunden`, `✅ ${minedN} paths derived from the sitemap + robots.txt Disallow tried (existence only); no sensitive/administrative endpoint found`);
  const assuranceSection = en
    ? `## POSITIVE ASSURANCE — RECONNAISSANCE METHODS CHECKED\n\n` +
      `Reconnaissance comes out clean on most healthy targets; this section also makes the “nothing found” result TRANSPARENT — it shows what was ACTUALLY checked (including a **${paScanned}-page** sitemap, home page included):\n\n` +
      `| Reconnaissance Area | Result |\n|-------------|-------|\n| Subdomain Takeover Scan | ${subRow} |\n| API & Swagger Reconnaissance | ${apiRow} |\n| CMS / Framework CVE Match | ${cmsRow} |\n| Server/Software Banner → Known CVE | ${banRow} |\n| Sitemap + robots.txt path reconnaissance | ${robotsRow} |\n\n` +
      `> **Three-state distinction (honesty):** ✅ *No indicator found* = method ran, clean · ⚠️ *Indicator present* = detailed above · ⚠️ *Not assessable* = no data collectable (does NOT mean secure).\n\n` +
      `### What this package assesses — and what it does NOT\n\n` +
      `**ASSESSES (passive reconnaissance — GET only, external sources):** subdomain inventory + takeover (dangling CNAME), publicly accessible API/Swagger/OpenAPI document, CMS/framework and server/software banner (Apache/nginx/PHP) fingerprint + known CVE match (NVD), EXISTENCE determination of API/administrative-looking paths derived from the sitemap + robots.txt Disallow entries — across ${paScanned} pages.\n\n` +
      `**DOES NOT ASSESS:** active injection/IDOR/XSS verification and authorisation testing of discovered endpoints (**Active Verification / Full Pentest** scope), HTTP security header/CORS/cookie/CSP details (**Basic Scan / External Attack Surface** scope), GDPR/PCI/ISO framework mapping (**Compliance** scope). The statement “no indicator found” in an area **DOES NOT PROVE** you are secure — it only shows that no indicator emerged with the passive methods checked.\n\n`
    : de
    ? `## POSITIVE ZUSICHERUNG — GEPRÜFTE ERKUNDUNGSMETHODEN\n\n` +
      `Die Erkundung fällt bei den meisten gesunden Zielen sauber aus; dieser Abschnitt macht auch das Ergebnis „nichts gefunden" TRANSPARENT — er zeigt, was TATSÄCHLICH geprüft wurde (inklusive **${paScanned} Seiten** Sitemap, Startseite eingeschlossen):\n\n` +
      `| Erkundungsbereich | Ergebnis |\n|-------------|-------|\n| Subdomain-Takeover-Prüfung | ${subRow} |\n| API- & Swagger-Erkundung | ${apiRow} |\n| CMS-/Framework-CVE-Abgleich | ${cmsRow} |\n| Server-/Software-Banner → Bekannte CVE | ${banRow} |\n| Sitemap- + robots.txt-Pfaderkundung | ${robotsRow} |\n\n` +
      `> **Drei-Zustands-Unterscheidung (Ehrlichkeit):** ✅ *Kein Indikator gefunden* = Methode lief, sauber · ⚠️ *Indikator vorhanden* = oben im Detail · ⚠️ *Nicht prüfbar* = keine Daten erhebbar (bedeutet NICHT sicher).\n\n` +
      `### Was dieses Paket bewertet — und was NICHT\n\n` +
      `**BEWERTET (passive Erkundung — nur GET, externe Quellen):** Subdomain-Inventar + Übernahme (dangling CNAME), öffentlich zugängliches API-/Swagger-/OpenAPI-Dokument, CMS-/Framework- und Server-/Software-Banner-Fingerabdruck (Apache/nginx/PHP) + bekannte CVE-Übereinstimmung (NVD), EXISTENZ-Feststellung aus Sitemap + robots.txt-Disallow abgeleiteter API-/administrativ wirkender Pfade — über ${paScanned} Seiten.\n\n` +
      `**BEWERTET NICHT:** aktive Injektions-/IDOR-/XSS-Verifikation und Berechtigungsprüfung entdeckter Endpunkte (Umfang **Aktive Verifikation / Umfassender Pentest**), HTTP-Sicherheits-Header-/CORS-/Cookie-/CSP-Details (Umfang **Basis-Scan / Externe Angriffsfläche**), DSGVO/PCI/ISO-Rahmenzuordnung (Umfang **Compliance**). Die Aussage „kein Indikator gefunden" in einem Bereich **BEWEIST NICHT**, dass Sie sicher sind — sie zeigt nur, dass mit den geprüften passiven Methoden kein Indikator auftrat.\n\n`
    : `## POZİTİF GÜVENCE — DENENEN KEŞİF YÖNTEMLERİ\n\n` +
      `Keşif çoğu sağlıklı hedefte temiz çıkar; bu bölüm "bir şey bulunamadı" sonucunu da ŞEFFAF kılar — GERÇEKTEN ne denendiğini gösterir (ana sayfa dâhil **${paScanned} sayfa** site haritası dahil):\n\n` +
      `| Keşif Alanı | Sonuç |\n|-------------|-------|\n| Subdomain-Takeover Taraması | ${subRow} |\n| API & Swagger Keşfi | ${apiRow} |\n| CMS / Framework CVE Eşleşmesi | ${cmsRow} |\n| Sunucu/Yazılım Banner → Bilinen CVE | ${banRow} |\n| Site haritası + robots.txt yol keşfi | ${robotsRow} |\n\n` +
      `> **Üç-durum ayrımı (dürüstlük):** ✅ *Gösterge bulunamadı* = yöntem çalıştı, temiz · ⚠️ *Gösterge var* = yukarıda ayrıntılı · ⚠️ *İncelenemedi* = veri toplanamadı (güvenli anlamına GELMEZ).\n\n` +
      `### Bu paket NE değerlendirir, NE değerlendirmez\n\n` +
      `**DEĞERLENDİRİR (pasif keşif — yalnız GET, dış kaynak):** alt domain envanteri + devralma (dangling CNAME), herkese açık API/Swagger/OpenAPI dokümanı, CMS/çatı ve sunucu/yazılım banner (Apache/nginx/PHP) parmak izi + bilinen CVE eşleşmesi (NVD), site haritası + robots.txt Disallow'dan türeyen API/idari-görünümlü yolların VARLIK tespiti — ${paScanned} sayfa üzerinden.\n\n` +
      `**DEĞERLENDİRMEZ:** aktif enjeksiyon/IDOR/XSS doğrulaması ve keşfedilen uçlara yetki testi (**Aktif Doğrulama / Tam Pentest** kapsamı), HTTP güvenlik başlığı/CORS/çerez/CSP detayı (**Basit Tarama / Dış Yüzey** kapsamı), KVKK/PCI/ISO çerçeve-eşleme (**Uyum** kapsamı). Bir alanda "gösterge bulunamadı" ifadesi **güvenli olduğunuzu KANITLAMAZ** — yalnız denenen pasif yöntemlerle bir gösterge çıkmadığını gösterir.\n\n`;

  const findings =
    `## ${t('YÖNETİCİ ÖZETİ', 'MANAGEMENTZUSAMMENFASSUNG', 'EXECUTIVE SUMMARY')}\n\n${summary.join('\n')}\n\n` +
    `## ${t('GENEL DEĞERLENDİRME', 'GESAMTBEWERTUNG', 'OVERALL ASSESSMENT')}\n\n**${t('Risk Seviyesi', 'Risikostufe', 'Risk Level')}: ${RW[worst]}**\n\n${httpOnly ? t('Bu hedef HTTPS üzerinden yanıt vermiyor; iletişim şifresiz taşınıyor (öncelikli olarak HTTPS’e geçilmelidir). ', 'Dieses Ziel antwortet nicht über HTTPS; die Kommunikation wird unverschlüsselt übertragen (vorrangig sollte auf HTTPS umgestellt werden). ', 'This target does not respond over HTTPS; communication is carried unencrypted (HTTPS should be adopted as a priority). ') : ''}${genelSentence}\n\n` +
    `${httpsFindingSection}${methodologySection(locale)}\n` +
    `${areaSections}\n${assuranceSection}` +
    `${bestPracticesSection(locale)}`;

  const fixText =
    t('Bu bölüm, keşif taramanızda tespit edilen tüm eksiklikler için alan alan düzeltme önerileri içerir.\n\n', 'Dieser Abschnitt enthält bereichsweise Behebungsempfehlungen für alle in Ihrer Erkundungsprüfung festgestellten Mängel.\n\n', 'This section contains area-by-area remediation recommendations for all shortcomings detected in your reconnaissance scan.\n\n') +
    areas.map((a) => a.fixText.trim()).filter(Boolean).join('\n\n');

  return { findings, fixText };
}

export async function generateBundleReconReport(host: string, locale: string = 'tr'): Promise<{ findings: string; fixText: string } | null> {
  // Protokol çözümle (cache'i ısıtır -> reconEvidence collectorları cachedOriginUrl ile http-only'de
  // de çalışır) + http-only ise https_missing bulgusu üret.
  const o = await resolveOrigin(host);
  if (!o.reachable) return unscannableReconReport(host, locale);
  const ev = await collectReconEvidence(host);
  // Hiçbir keşif alanı veri toplayamadıysa -> "İncelenemedi" (null->Düşük fallback DEĞİL).
  return combineReconAreas(ev, { httpOnly: !o.httpsWorks }, locale) ?? unscannableReconReport(host, locale);
}

function unscannableReconReport(host: string, locale: string = 'tr'): { findings: string; fixText: string } {
  const de = locale === 'de';
  const en = locale === 'en';
  const findings = en
    ? `## EXECUTIVE SUMMARY\n\n` +
      `- **Overall risk level: Not assessable** — the reconnaissance scan could not be performed because no connection to the target (${host}) could be established.\n` +
      `- This result does NOT mean the website is SECURE; it only shows that the checks could not be run.\n` +
      `- **Recommended first step:** Verify that the domain is online and reachable, and repeat the scan.\n\n` +
      `## OVERALL ASSESSMENT\n\n**Risk Level: Not assessable**\n\nNo connection could be established to the target’s ports 443 (HTTPS) and 80 (HTTP). This report is NOT a “clean/secure” result; it should be scanned again once access is possible.\n`
    : de
    ? `## MANAGEMENTZUSAMMENFASSUNG\n\n` +
      `- **Gesamtrisikostufe: Nicht prüfbar** — die Erkundungsprüfung konnte nicht durchgeführt werden, da keine Verbindung zum Ziel (${host}) hergestellt werden konnte.\n` +
      `- Dieses Ergebnis bedeutet NICHT, dass die Website SICHER ist; es zeigt lediglich, dass die Kontrollen nicht ausgeführt werden konnten.\n` +
      `- **Empfohlener erster Schritt:** Prüfen Sie, ob die Domain online und erreichbar ist, und wiederholen Sie die Prüfung.\n\n` +
      `## GESAMTBEWERTUNG\n\n**Risikostufe: Nicht prüfbar**\n\nZu den Ports 443 (HTTPS) und 80 (HTTP) des Ziels konnte keine Verbindung hergestellt werden. Dieser Bericht ist KEIN „sauberes/sicheres" Ergebnis; sobald der Zugriff möglich ist, sollte erneut geprüft werden.\n`
    : `## YÖNETİCİ ÖZETİ\n\n` +
      `- **Genel risk seviyesi: İncelenemedi** — hedefe (${host}) bağlanılamadığı için keşif taraması yürütülemedi.\n` +
      `- Bu sonuç sitenin GÜVENLİ olduğu anlamına GELMEZ; yalnızca kontrollerin çalıştırılamadığını gösterir.\n` +
      `- **Önerilen ilk adım:** Alan adının yayında ve erişilebilir olduğunu doğrulayıp taramayı tekrarlayın.\n\n` +
      `## GENEL DEĞERLENDİRME\n\n**Risk Seviyesi: İncelenemedi**\n\nHedefin 443 (HTTPS) ve 80 (HTTP) portlarına bağlantı kurulamadı. Bu rapor bir "temiz/güvenli" sonucu DEĞİLDİR; erişim sağlanınca yeniden taranmalıdır.\n`;
  return { findings, fixText: '' };
}
