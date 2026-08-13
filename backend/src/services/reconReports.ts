/**
 * (Keşif Paketi — bundle_recon) DETERMINISTIK BIRLESIK RAPOR URETICISI.
 *
 * subdomain_takeover + api_discovery + cms_cve — ucu de KOD-toplanmis kanittan (reconEvidence.ts)
 * uretilir; PentAGI ajani HIC calismaz. CVE bilgisi yalnizca NVD'nin yapisal cevabindan gelir,
 * Turkce rapor cumlesini HER ZAMAN kod yazar. Cikti bundle_surface/bundle_compliance ile ayni
 * bicimde: TEK Yonetici Ozeti + TEK genel risk rozeti (worst-case + birikimli) + Kapsam & Metodoloji
 * + 3 alan (tam envanter/metodoloji tablolari) + Iyi Pratikler (ucretsiz) + TEK "AI Cozum Onerileri"
 * (kilitli). generateBundleReconReport { findings, fixText } | null doner.
 */
import { collectReconEvidence, type ReconEvidence, type SubEvidence, type ApiEvidence, type CmsEvidence } from './reconEvidence.js';
import { resolveOrigin } from './surfaceEvidence.js';

const RISK_WORD = { low: 'Düşük', medium: 'Orta', 'medium-high': 'Orta-Yüksek', high: 'Yüksek' } as const;
type Level = 'low' | 'medium' | 'medium-high' | 'high';
function levelRank(l: Level): number { return l === 'high' ? 3 : l === 'medium-high' ? 2 : l === 'medium' ? 1 : 0; }

type Area = { title: string; level: Level; headline: string; body: string; fixText: string; dataUnavailable?: boolean };

const CAUTION_CVE = '> **Not:** Aşağıdaki CVE listesi, tespit edilen sürümle NVD (NIST Ulusal Zafiyet Veritabanı) üzerinden **otomatik eşlenen** bilinen zafiyetlerdir; sürümünüz için sömürülebilir oldukları **doğrulanmamıştır** ve bir kısmı eklenti/tema kaynaklı olabilir. Kesin durum için güncelleme + hedefli doğrulama önerilir.';

const SUB_DISPLAY_MAX = 100; // envanterde gosterilecek alt domain ust siniri (collector CNAME kapsami ile hizali)

// ======================================================================================
// "BULGU YOK" AI COZUM ONERILERI — proaktif sertlestirme/izleme rehberi (%100 kod, LLM yok)
// Bulgu bulunmadiginda bile somut, adim-adim, kopyala-yapistir icerik verir (Grok B).
// ======================================================================================
function buildSubMonitoringFix(): string {
  return [
    '### Subdomain Takeover — proaktif izleme rehberi',
    '',
    'Şu an devralınabilir alt domain tespit edilmedi. Bu durumu **sürekli** korumak için, yeni/beklenmeyen alt domain sertifikalarını erken yakalayacak bir Certificate Transparency (CT) izleme sistemi kurun:',
    '',
    '**1) certSpotter ile ücretsiz e-posta/webhook uyarısı**',
    '',
    '`sslmate.com/certspotter` üzerinde alan adınızı (ör. `nomorelink.com`, alt domainler dahil) izlemeye ekleyin; yeni sertifika yayınlandığında e-posta/webhook uyarısı alırsınız (yeni bir alt domain sertifikası, sizin oluşturmadığınız bir kayıt olabilir).',
    '',
    '**2) crt.sh’i periyodik sorgulayan basit bir cron (kendi sunucunuzda)**',
    '',
    'Her gün alt domain listesini çekip bir öncekiyle karşılaştıran, yeni giren alt domainde uyarı veren örnek betik:',
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
    '**3) Alt domain envanteri tutun** — hangi alt domainin hangi servise/ekibe ait olduğunu belgeleyin; boşta kalan (kullanılmayan) CNAME kayıtlarını, bulut kaynağını silmeden önce DNS’ten kaldırın (kaldırma sırası önemlidir).',
  ].join('\n');
}

function buildApiHardeningFix(): string {
  return [
    '### API & Swagger Keşfi — proaktif sertleştirme rehberi',
    '',
    'Herkese açık API dokümantasyonu bulunamadı. Bunu kalıcı kılmak için, Swagger/OpenAPI/ReDoc gibi şema uçlarını üretimde kimlik doğrulama veya IP kısıtı arkasına alın. Platformunuza uygun örneği uygulayın:',
    '',
    '**Nginx — `/swagger*`, `/api-docs*`, `/openapi.json` için IP allowlist + Basic-Auth**',
    '',
    '```nginx',
    'location ~* ^/(swagger|api-docs|v2/api-docs|v3/api-docs|openapi\\.json|redoc) {',
    '    allow 203.0.113.0/24;   # ofis/VPN IP bloğunuz',
    '    deny all;               # geri kalan herkese kapalı',
    '    auth_basic "Restricted";',
    '    auth_basic_user_file /etc/nginx/.htpasswd;  # htpasswd ile oluşturun',
    '    # ... mevcut proxy_pass/try_files yönergeleriniz ...',
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
    '    admin $2a$14$...   # caddy hash-password ile üretin',
    '}',
    '```',
    '',
    '**Ek öneriler:** OpenAPI şemanıza global `security` tanımı ekleyin; GraphQL kullanıyorsanız üretimde introspection’ı kapatın (`introspection: false`).',
  ].join('\n');
}

function buildCmsHardeningFix(detected: boolean): string {
  return [
    `### CMS & Bilinen CVE — proaktif güncel kalma rehberi`,
    '',
    detected
      ? 'Tespit edilen sürüm için, sürümü açıkça kapsayan bilinen CVE bulunamadı. Bu durumu korumak için güncellemeyi otomatikleştirin ve bağımlılıklarınızı sürekli tarayın:'
      : 'Bilinen bir CMS tespit edilmedi (özel/gizlenmiş uygulama olabilir). Güncel kalmayı ve bilinen-zafiyet takibini otomatikleştirin:',
    '',
    '**1) WordPress kullanıyorsanız — otomatik minor + güvenlik güncellemesi**',
    '',
    '`wp-config.php` içine:',
    '',
    '```php',
    "define( 'WP_AUTO_UPDATE_CORE', 'minor' );  // güvenlik/minor sürümleri otomatik",
    '```',
    '',
    'Eklenti/tema otomatik güncellemesi için (WP-CLI):',
    '',
    '```bash',
    'wp plugin auto-updates enable --all',
    'wp theme auto-updates enable --all',
    '```',
    '',
    '**2) CI/CD’ye ücretsiz bağımlılık taraması (SCA) ekleyin**',
    '',
    '- **Dependabot** (GitHub, ücretsiz): depoya `.github/dependabot.yml` ekleyin:',
    '',
    '```yaml',
    'version: 2',
    'updates:',
    '  - package-ecosystem: "composer"   # WordPress/PHP için; npm/pip/… da desteklenir',
    '    directory: "/"',
    '    schedule: { interval: "weekly" }',
    '```',
    '',
    '- **npm audit** (Node projeleri): CI adımınıza `npm audit --audit-level=high` ekleyin; yüksek/kritik açık varsa derleme kırılsın.',
    '',
    '**3) Sürüm ifşasını azaltın** — `<meta generator>`, `X-Powered-By`, `/readme.html`, `/CHANGELOG.txt` gibi sürüm sızdıran noktaları kaldırın/kapatın; böylece otomatik CVE eşlemesi saldırganlar için zorlaşır.',
  ].join('\n');
}

// ======================================================================================
// 1) subdomain_takeover
// ======================================================================================
function buildSubArea(ev: SubEvidence): Area {
  // Veri kaynagina ulasilamadi (crt.sh + certSpotter ikisi de erisilemedi) -> "temiz" DEME.
  if (ev.dataSource === 'unavailable') {
    const body = [
      '> ⚠️ **Veri kaynağına şu an ulaşılamadı.** Alt domain envanteri, Certificate Transparency (CT) log sağlayıcılarından (crt.sh ve yedek certSpotter) toplanır; bu tarama sırasında **her iki kaynak da** geçici olarak yanıt vermedi (kesinti/zaman aşımı/hız sınırı).',
      '',
      'Bu nedenle bu bölüm için **sonuç üretilemedi** — bu, "alt domain yok/temiz" anlamına **gelmez**. Tarama kısa süre sonra tekrar denendiğinde bu bölüm normal şekilde dolacaktır. CT kaynakları (özellikle crt.sh) zaman zaman kısa kesintiler yaşayabilir.',
      '',
      '> Kapsam: Yalnızca pasif kaynaklar (Certificate Transparency logları + gözlemlenebilir DNS). Alt domain brute-force / aktif tarama yapılmamıştır.',
    ].join('\n');
    return { title: 'Subdomain Takeover Taraması', level: 'low', headline: 'Veri kaynağına ulaşılamadı — sonuç üretilemedi', body, fixText: buildSubMonitoringFix(), dataUnavailable: true };
  }
  const confirmed = ev.dangling.filter((d) => d.confidence === 'confirmed');
  const suspected = ev.dangling.filter((d) => d.confidence === 'suspected');
  let level: Level = 'low';
  if (confirmed.length) level = 'high';
  else if (suspected.length) level = 'medium-high';

  const headline = confirmed.length
    ? `${confirmed.length} devralınabilir (dangling) alt domain tespit edildi`
    : suspected.length
      ? `${suspected.length} şüpheli alt domain — manuel doğrulama gerekli`
      : ev.total
        ? `${ev.total} alt domain envanterlendi; devralınabilir kayıt tespit edilmedi`
        : 'Sertifika şeffaflığı kayıtlarında alt domain görülmedi';

  const lines: string[] = [];
  lines.push(`Certificate Transparency (crt.sh / certSpotter) kayıtlarından **${ev.total}** benzersiz alt domain envanterlendi; bunlardan **${ev.resolved}** tanesinin CNAME kaydı çözümlenip devralma (subdomain takeover) açısından incelendi.`);
  lines.push('');

  if (confirmed.length || suspected.length) {
    lines.push('### Devralınabilir (dangling) alt domainler\n');
    lines.push('| Alt Domain | CNAME Hedefi | Servis | Durum | Açıklama |');
    lines.push('|-----------|--------------|--------|-------|----------|');
    for (const d of [...confirmed, ...suspected]) {
      lines.push(`| ${d.sub} | ${d.cname} | ${d.service} | ${d.confidence === 'confirmed' ? '⚠️ Doğrulandı' : 'Şüpheli' } | ${d.note} |`);
    }
    lines.push('');
    lines.push('> **Subdomain takeover riski:** Bir alt domain, artık size ait olmayan/terk edilmiş bir bulut kaynağına (CNAME) işaret ediyorsa, saldırgan o kaynağı kendi adına oluşturup alt domaininiz üzerinden içerik yayınlayabilir (oltalama, çerez/oturum çalma, marka istismarı). En yüksek öncelikli keşif bulgusudur.');
    lines.push('');
  } else {
    // Negatif sonucu OLCULU + olumlu cerceve (garanti vermeden).
    lines.push('Çözümlenen CNAME kayıtlarında, terk edilmiş bir bulut kaynağına işaret eden **devralınabilir (dangling)** alt domain tespit edilmedi. Bu, dışarıdan görünen alt domain yüzeyinizin şu an için **dar ve kontrollü** göründüğünü gösterir.');
    lines.push('');
  }

  // TAM ENVANTER TABLOSU (yeni fetch yok; collector'in tasidigi CNAME durumlari).
  if (ev.cnames.length) {
    lines.push('### Alt domain envanteri (durum tablosu)\n');
    lines.push('Bulunan alt domainler ve CNAME çözümlemesi sonucu durumları:');
    lines.push('');
    lines.push('| Alt Domain | CNAME Hedefi | Durum |');
    lines.push('|-----------|--------------|-------|');
    const stateLabel = (s: string) => s === 'dangling' ? '⚠️ Devralınabilir' : s === 'suspected' ? '⚠️ Şüpheli' : s === 'managed' ? 'Aktif (yönetilen dış servis)' : s === 'active' ? 'Aktif (CNAME kaydı var)' : 'CNAME kaydı yok (doğrudan A/AAAA)';
    for (const c of ev.cnames.slice(0, SUB_DISPLAY_MAX)) {
      lines.push(`| ${c.sub} | ${c.cname ?? '—'} | ${stateLabel(c.state)} |`);
    }
    lines.push('');
    if (ev.total > ev.resolved) {
      lines.push(`_(+${ev.total - ev.resolved} alt domain daha CT kayıtlarında bulundu; **tamamı envanterlenmiştir**, yalnızca ilk ${ev.resolved} tanesi bu tabloda CNAME durumuyla gösterilmiştir.)_`);
      lines.push('');
    }
  } else if (ev.subdomains.length) {
    lines.push('### Alt domain envanteri\n');
    lines.push(ev.subdomains.map((s) => `- ${s}`).join('\n'));
    lines.push('');
  }

  if (ev.managedCnames.length) {
    lines.push('### Yönetilen dış servis CNAME’leri (bilgi)\n');
    lines.push('Aşağıdaki alt domainler bilinen bir dış servise (CNAME) işaret ediyor ve şu an **canlı** görünüyor — risk değil, envanter bilgisidir:');
    lines.push('');
    for (const m of ev.managedCnames.slice(0, 20)) lines.push(`- **${m.sub}** → ${m.cname} (${m.service})`);
    lines.push('');
  }

  lines.push('> Kapsam: Yalnızca pasif kaynaklar (Certificate Transparency logları + gözlemlenebilir DNS). Alt domain brute-force / aktif tarama yapılmamıştır.');

  const fixText = confirmed.length || suspected.length
    ? '### Subdomain Takeover — düzeltme\n\n' +
      [...confirmed, ...suspected].map((d) => `- **${d.sub}** (${d.service}): Bu alt domain kullanılmıyorsa DNS’ten **CNAME kaydını silin**. Kullanılıyorsa, ${d.service} tarafında kaynağı **yeniden oluşturup sahiplenin** (claim), böylece kayıt boşta kalmaz.`).join('\n') +
      '\n\n- Genel önlem: Kullanılmayan alt domainleri düzenli olarak temizleyin; bulut kaynağı silmeden önce DNS kaydını kaldırın (kaldırma sırası önemli).'
    : buildSubMonitoringFix();

  return { title: 'Subdomain Takeover Taraması', level, headline, body: lines.join('\n'), fixText };
}

// ======================================================================================
// 2) api_discovery
// ======================================================================================
function buildApiArea(ev: ApiEvidence): Area {
  const spec = ev.spec;
  const sensitive = spec?.sensitive ?? [];
  const noAuthSensitive = sensitive.filter((s) => s.noAuth);
  let level: Level = 'low';
  if (noAuthSensitive.length) level = 'high';
  else if (spec && sensitive.length) level = 'medium-high';
  else if (spec || ev.reachable.length) level = 'medium';

  const headline = noAuthSensitive.length
    ? `${noAuthSensitive.length} hassas uç nokta kimlik doğrulamasız görünüyor`
    : spec && sensitive.length
      ? `Herkese açık API şeması + ${sensitive.length} hassas uç nokta`
      : spec
        ? `Herkese açık API şeması (${spec.endpointCount} uç nokta)`
        : ev.reachable.length
          ? `${ev.reachable.length} API dokümantasyon noktası herkese açık`
          : 'Herkese açık API/Swagger dokümantasyonu bulunamadı';

  const lines: string[] = [];
  lines.push(`Aşağıdaki **${ev.tried.length}** yaygın API dokümantasyon/keşif yolu GET ile denenmiştir. Hiçbir uç nokta çağrılmamış/istismar edilmemiştir (pasif keşif).`);
  lines.push('');

  // DENENEN TUM YOLLAR — tam liste tablosu (metodoloji seffafligi).
  const reachSet = new Map(ev.reachable.map((r) => [r.path, r.kind]));
  lines.push('### Denenen yollar (tam liste)\n');
  lines.push('| Yol | HTTP | Durum |');
  lines.push('|-----|------|-------|');
  for (const t of ev.tried) {
    const kind = reachSet.get(t.path);
    const durum = kind
      ? (kind === 'spec' ? '✓ Bulundu (OpenAPI/Swagger şeması)' : kind === 'graphql' ? '✓ Bulundu (GraphQL)' : '✓ Bulundu (Swagger/ReDoc arayüzü)')
      : (t.status === 401 || t.status === 403) ? 'Erişim reddedildi (korumalı)'
        : t.status === 200 ? 'Yanıt döndü (şema değil)'
          : t.status === 0 ? 'Yanıt yok'
            : 'Bulunamadı';
    lines.push(`| ${t.path} | ${t.status || '—'} | ${durum} |`);
  }
  lines.push('');

  if (spec) {
    lines.push('### API şeması detayı\n');
    lines.push(`- Şema yolu: \`${spec.path}\``);
    if (spec.title) lines.push(`- Başlık: ${spec.title}${spec.version ? ` (v${spec.version})` : ''}`);
    lines.push(`- Tanımlı uç nokta sayısı: **${spec.endpointCount}**`);
    lines.push(`- Genel kimlik doğrulama tanımı: ${spec.hasGlobalAuth ? 'var (global `security`)' : '⚠️ şemada global `security` tanımı yok'}`);
    lines.push('');
    if (sensitive.length) {
      lines.push('#### Hassas uç noktalar\n');
      lines.push('Yol/işlem adı hassas anahtar kelime içeren uç noktalar (yalnızca şemadan; **çağrılmamıştır**):');
      lines.push('');
      lines.push('| Metot | Yol | Kimlik doğrulama |');
      lines.push('|-------|-----|------------------|');
      for (const s of sensitive.slice(0, 25)) lines.push(`| ${s.method} | ${s.path} | ${s.noAuth ? '⚠️ tanımsız/yok' : 'tanımlı'} |`);
      lines.push('');
      if (noAuthSensitive.length) lines.push(`> **${noAuthSensitive.length} hassas uç nokta** şemada kimlik doğrulama tanımı olmadan listeleniyor. Bu, yetkisiz erişime açık olabileceklerine dair güçlü bir göstergedir (doğrulama için manuel test gerekir).`);
      lines.push('');
    }
  } else {
    // Negatif sonuc — olculu + olumlu cerceve.
    lines.push('Denenen yolların hiçbiri herkese açık bir API şeması/arayüzü döndürmedi. Herkese açık API dokümantasyonu bulunmaması, saldırganların API yüzeyinizi dışarıdan kolayca **haritalayamayacağı** anlamına gelir — bu, dış saldırı yüzeyi açısından olumlu bir işarettir.');
    lines.push('');
  }

  lines.push('> Kapsam: Yalnızca herkese açık dokümantasyon yolları GET ile denenmiştir; hiçbir uç nokta çağrılmamış/istismar edilmemiştir (pasif keşif).');

  const fixText = level === 'low'
    ? buildApiHardeningFix()
    : '### API & Swagger Keşfi — düzeltme\n\n' + [
        '- Üretim ortamında Swagger UI / ReDoc / `*/api-docs` / `openapi.json` gibi şema uçlarını **kapatın** veya kimlik doğrulama (IP allowlist / SSO) arkasına alın.',
        spec && !spec.hasGlobalAuth ? '- API şemanıza global `security` tanımı ekleyin; her hassas uç nokta için kimlik doğrulama/yetki zorunlu olsun.' : '',
        noAuthSensitive.length ? '- Kimlik doğrulaması görünmeyen hassas uç noktaları (admin/user/export/upload vb.) yetkilendirme kontrolünden geçirin; yetkisiz erişimi test edip kapatın.' : '',
        ev.reachable.some((r) => r.kind === 'graphql') ? '- GraphQL introspection’ı üretimde kapatın (`introspection: false`).' : '',
      ].filter(Boolean).join('\n');

  return { title: 'API & Swagger Keşfi', level, headline, body: lines.join('\n'), fixText };
}

// ======================================================================================
// 3) cms_cve
// ======================================================================================
const FINGERPRINT_SOURCES = [
  'HTTP yanıt başlıkları (`Server`, `X-Powered-By`, `X-Generator`, `X-Drupal-Cache`, `X-Magento-Cache-Debug`)',
  '`<meta name="generator">` etiketi',
  'HTML yol/kalıp izleri (`/wp-content/`, `/wp-includes/`, `Drupal.settings`, `/sites/all/`, `option=com_`, `/media/jui/`, `typo3conf`, `Magento_`)',
  'Yaygın sürüm dosyaları (WordPress `/readme.html`, Drupal `/CHANGELOG.txt`)',
  'Kütüphane/eklenti ipuçları (WooCommerce, jQuery sürümü)',
];

function cveLevel(ev: CmsEvidence): Level {
  if (!ev.cms) return 'low';
  const worst = ev.cves.reduce((m, c) => Math.max(m, c.score), 0);
  const hasCrit = ev.cves.some((c) => c.severity === 'CRITICAL' || c.score >= 9);
  const hasHigh = ev.cves.some((c) => c.severity === 'HIGH' || c.score >= 7);
  const hasMed = ev.cves.some((c) => c.severity === 'MEDIUM' || c.score >= 4);
  if (hasCrit || hasHigh) return 'high';
  if (hasMed || worst > 0) return 'medium-high';
  if (ev.cms && !ev.version) return 'medium'; // CMS var ama surum yok -> guncellik dogrulanamiyor
  return 'low';
}

function buildCmsArea(ev: CmsEvidence): Area {
  const level = cveLevel(ev);
  const critHigh = ev.cves.filter((c) => c.severity === 'CRITICAL' || c.severity === 'HIGH' || c.score >= 7).length;

  const headline = !ev.cms
    ? 'Bilinen bir CMS parmak izi tespit edilmedi'
    : critHigh
      ? `${ev.cms}${ev.version ? ` ${ev.version}` : ''} — ${critHigh} yüksek/kritik CVE ile eşleşiyor`
      : ev.cves.length
        ? `${ev.cms}${ev.version ? ` ${ev.version}` : ''} — ${ev.cveTotal} bilinen CVE ile eşleşiyor`
        : ev.version
          ? `${ev.cms} ${ev.version} tespit edildi; eşleşen CVE bulunamadı`
          : `${ev.cms} tespit edildi; sürüm belirlenemedi`;

  const lines: string[] = [];
  // Metodoloji — her durumda goster (seffaflik).
  lines.push('### İncelenen parmak izi kaynakları\n');
  lines.push('CMS/çatı ve sürüm tespiti için ana sayfa yanıtı üzerinde aşağıdaki pasif sinyallere bakıldı:');
  lines.push('');
  lines.push(FINGERPRINT_SOURCES.map((s) => `- ${s}`).join('\n'));
  lines.push('');

  if (!ev.cms) {
    lines.push('Bu sinyallerin **hiçbiri** bilinen bir CMS/çatı ile eşleşmedi. Bu, özel geliştirilmiş bir uygulama veya CMS izlerini bilinçli olarak gizleyen bir kurulum olabileceğine işaret eder; her iki durum da dışarıdan otomatik CMS/CVE eşlemesini zorlaştırır.');
    lines.push('');
  } else {
    lines.push('### Parmak izi sonucu\n');
    lines.push(`- Tespit edilen sistem: **${ev.cms}${ev.version ? ` ${ev.version}` : ''}**`);
    lines.push(`- Nasıl tespit edildi: ${ev.evidence.join('; ')}`);
    if (ev.extras.length) lines.push(`- Ek gözlemler: ${ev.extras.join(' · ')}`);
    if (!ev.version) lines.push('- ⚠️ Sürüm belirlenemedi — CVE eşlemesi için sürüm gereklidir; güncellik dışarıdan doğrulanamadı.');
    lines.push('');

    if (ev.cpeQueried) {
      lines.push('### Bilinen CVE eşleşmeleri (NVD)\n');
      if (!ev.cveOk) {
        lines.push('NVD (NIST Ulusal Zafiyet Veritabanı) sorgusu bu tarama sırasında yanıt vermedi; CVE eşlemesi yapılamadı. Lütfen sürümünüzü NVD üzerinde manuel doğrulayın.');
      } else if (ev.cveTotal === 0) {
        lines.push(`Tespit edilen sürüm (\`${ev.cpeQueried}\`) için NVD’de, sürümü açıkça kapsayan bilinen bir CVE bulunamadı. Bu, çekirdek sürümünüzün güncel/yamalı olduğuna dair olumlu bir göstergedir; yine de eklenti/tema güncellemelerini ihmal etmeyin.`);
      } else {
        lines.push(`\`${ev.cpeQueried}\` için NVD’de, sürümü açıkça kapsayan **${ev.cveTotal}** CVE bulundu. En yüksek CVSS skoruna göre ilk ${ev.cves.length} tanesi:`);
        lines.push('');
        lines.push('| CVE | Ciddiyet | CVSS | Özet |');
        lines.push('|-----|----------|------|------|');
        for (const c of ev.cves) {
          const sev = c.severity === 'CRITICAL' ? 'Kritik' : c.severity === 'HIGH' ? 'Yüksek' : c.severity === 'MEDIUM' ? 'Orta' : c.severity === 'LOW' ? 'Düşük' : '—';
          lines.push(`| [${c.id}](https://nvd.nist.gov/vuln/detail/${c.id}) | ${sev} | ${c.score || '—'} | ${c.summary.replace(/\|/g, '\\|')} |`);
        }
        lines.push('');
        if (ev.cveTotal > ev.cves.length) lines.push(`_(+${ev.cveTotal - ev.cves.length} eşleşme daha; tam liste NVD’de bu sürümle ilişkilendirilmiştir.)_`);
        lines.push('');
        lines.push(CAUTION_CVE);
      }
      lines.push('');
    }
  }
  lines.push('> Kapsam: Pasif parmak izi + NVD üzerinden bilinen-CVE eşlemesi. Hiçbir CVE **istismar edilmemiş/doğrulanmamıştır**.');

  const fixText = !ev.cms
    ? buildCmsHardeningFix(false)
    : (ev.cves.length === 0
      ? buildCmsHardeningFix(true)
      : '### CMS & Bilinen CVE — düzeltme\n\n' + [
        `- **${ev.cms}${ev.version ? ` ${ev.version}` : ''}** kurulumunu en güncel kararlı sürüme yükseltin; otomatik güvenlik güncellemelerini açın.`,
        ev.cves.length ? '- Yukarıdaki CVE’leri NVD bağlantılarından inceleyin; güncelleme ile kapananları öncelikli uygulayın, kapanmayanlar için üreticinin azaltıcı önerilerini (WAF kuralı/yapılandırma) uygulayın.' : '',
        '- Kullanılmayan eklenti/tema/modülleri kaldırın; kalanları güncel tutun (CVE’lerin önemli kısmı eklenti/tema kaynaklıdır).',
        '- Sürüm/teknoloji ifşasını azaltın: `<meta generator>`, `X-Powered-By`, `/readme.html`, `/CHANGELOG.txt` gibi sürüm sızdıran noktaları kaldırın/kapatın.',
      ].filter(Boolean).join('\n'));

  return { title: 'CMS & Bilinen CVE Taraması', level, headline, body: lines.join('\n'), fixText };
}

// ======================================================================================
// SABIT BOLUMLER (bulgu olsa da olmasa da) — %100 kod, LLM yok
// ======================================================================================
const METHODOLOGY_SECTION =
  '## KAPSAM VE METODOLOJİ\n\n' +
  'Bu rapor, üç keşif alanında **pasif** (istismar içermeyen) tekniklerle, dışarıdan gözlemlenebilir verilerden otomatik olarak üretilmiştir:\n\n' +
  '- **Subdomain Takeover:** Alt domainler Certificate Transparency loglarından (crt.sh, yedek olarak certSpotter) toplanır; her biri Cloudflare DoH ile DNS/CNAME çözümlemesinden geçirilir ve bilinen “dangling” (terk edilmiş bulut servisi) imza veritabanıyla karşılaştırılır.\n' +
  '- **API & Swagger Keşfi:** Yaygın API dokümantasyon yollarından oluşan sabit bir liste GET ile denenir; bulunan OpenAPI/Swagger şemaları ayrıştırılır ve hassas/kimlik-doğrulamasız uç noktalar işaretlenir (uç noktalar çağrılmaz).\n' +
  '- **CMS & Bilinen CVE:** HTTP başlıkları, `<meta generator>` ve HTML kalıpları üzerinden CMS ve sürüm parmak izi çıkarılır; tespit edilen sürüm, NVD (NIST Ulusal Zafiyet Veritabanı) sorgulanarak — sürümü açıkça kapsayan — bilinen CVE’lerle eşlenir.\n\n' +
  '> Tüm veriler dışarıdan, hedefe zarar vermeden toplanmıştır. Kimlik doğrulama gerektiren alanlar, iç ağ ve aktif sömürü bu paketin kapsamı dışındadır.\n';

const BEST_PRACTICES_SECTION =
  '## İYİ PRATİKLER / ÖNERİLEN SONRAKİ ADIMLAR\n\n' +
  'Bu tarama sonucundan bağımsız olarak, saldırı yüzeyinizi dar tutmak için önerilen kalıcı uygulamalar:\n\n' +
  '- **Kullanılmayan CNAME kayıtlarını düzenli olarak temizleyin** — terk edilmiş bulut kaynaklarına işaret eden kayıtlar subdomain takeover riski taşır; bulut kaynağını silmeden önce DNS kaydını kaldırın.\n' +
  '- **API dokümantasyonunuz (Swagger/OpenAPI) varsa** yalnızca kimlik doğrulamalı erişime açık tutun; üretimde herkese açık yayınlamayın.\n' +
  '- **CMS, eklenti ve tema sürümlerinizi** otomatik güncelleme veya düzenli takiple güncel tutun; bilinen CVE’lere karşı yamalı kalın.\n' +
  '- **Certificate Transparency (CT) log izleme** araçları (crt.sh, certSpotter vb.) ile yeni/beklenmeyen alt domain sertifikalarını erken fark edin.\n' +
  '- **Sürüm/teknoloji ifşasını azaltın** — `Server`, `X-Powered-By`, `<meta generator>` gibi başlık/etiketlerle gereksiz sürüm bilgisi sızdırmayın.\n' +
  '- **Alt domain envanterinizi belgeleyin** — hangi alt domainin hangi servise/ekibe ait olduğunu bilmek, boşta kalan kayıtları hızlıca fark etmenizi sağlar.\n';

// ======================================================================================
// BIRLESTIRME
// ======================================================================================
export function combineReconAreas(ev: ReconEvidence, opts?: { httpOnly?: boolean }): { findings: string; fixText: string } | null {
  // Ucu de veri toplayamadiysa fallback.
  if (!ev.sub.ok && !ev.api.ok && !ev.cms.ok) return null;
  const httpOnly = opts?.httpOnly ?? false;

  const areas: Area[] = [buildSubArea(ev.sub), buildApiArea(ev.api), buildCmsArea(ev.cms)];

  // Risk siralamasi YALNIZ veri toplanabilen alanlar uzerinden (veri-kaynagi-basarisiz alan riske
  // dahil edilmez; "temiz" gibi sayilmaz — surface'in null-alan davranisiyla tutarli).
  const available = areas.filter((a) => !a.dataUnavailable);
  const unavailableCount = areas.length - available.length;
  const ranked = available.map((a) => a).sort((x, y) => levelRank(y.level) - levelRank(x.level));
  const baseWorst: Level = ranked.length ? ranked[0].level : 'low';
  const worstArea = ranked.length ? ranked[0] : areas[0];
  // Birikimli risk (surface ile tutarli): en yuksek 'Orta-Yüksek' iken 2+ alan Orta+ ise -> Yüksek.
  const mediumPlus = available.filter((a) => levelRank(a.level) >= 1).length;
  const cumulative = baseWorst === 'medium-high' && mediumPlus >= 2;
  const areaLevel: Level = cumulative ? 'high' : baseWorst;
  // (HALÜSİNASYON GUARD) https_missing (Yüksek) 3 keşif ALANININ (subdomain/API/CMS) hiçbirine ait
  // DEĞİLDİR — ayrı, bağımsız kontroldür. Eğer genel seviyeyi yükselten etken buysa, "en yüksek risk
  // [alan] alanında" cümlesi TEMİZ bir alanı yüksek riskin kaynağıymış gibi göstermemeli.
  const worstIsHttps = httpOnly && levelRank(areaLevel) < 3;
  const worst: Level = worstIsHttps ? 'high' : areaLevel;
  const scannedNote = unavailableCount ? ` (${unavailableCount} alanda veri kaynağına ulaşılamadı)` : '';

  const summary: string[] = [];
  summary.push(
    worst === 'low'
      ? `- **Genel risk seviyesi: Düşük** — keşif yüzeyiniz ${available.length} alanda incelendi${scannedNote}; devralınabilir alt domain, açık hassas API veya sürümü kapsayan bilinen yüksek CVE öne çıkmadı. Dışarıdan görünen yüzeyiniz şu an için dar ve kontrollü görünüyor.`
      : worstIsHttps
        ? `- **Genel risk seviyesi: Yüksek** — ${available.length} alan incelendi${scannedNote}; en yüksek risk **HTTPS/TLS yapılandırmasında** (HTTPS desteklenmiyor — şifresiz iletişim). Keşif alanlarının (alt domain, API, CMS) en yükseği **${worstArea.title}** (${RISK_WORD[worstArea.level]}); bu alanlarda öne çıkan ayrı bir risk yok.`
        : cumulative
          ? `- **Genel risk seviyesi: Yüksek** — ${available.length} alan incelendi${scannedNote}; birden fazla alan aynı anda risk taşıyor (en yükseği **${worstArea.title}** — ${worstArea.headline}).`
          : `- **Genel risk seviyesi: ${RISK_WORD[worst]}** — ${available.length} alan incelendi${scannedNote}; en yüksek risk **${worstArea.title}** alanında (${worstArea.headline}).`,
  );
  if (httpOnly) summary.push('- ⚠️ **HTTPS desteklenmiyor:** Hedef HTTPS (443) üzerinden yanıt vermedi; keşif http:// üzerinden yürütüldü. Şifresiz iletişim başlı başına ciddi bir bulgudur (aşağıda).');
  for (const a of areas) summary.push(a.dataUnavailable ? `- **${a.title}:** ⚠️ incelenemedi (veri kaynağına ulaşılamadı) — "temiz" anlamına gelmez` : `- **${a.title}:** ${RISK_WORD[a.level]} — ${a.headline}`);
  summary.push('- **Önerilen ilk adım:** En yüksek riskli alandan başlayın; her bulgu için adım adım hazır çözümler "AI Çözüm Önerileri" bölümünde sunulur.');

  const genelSentence =
    worstIsHttps
      ? `Keşif alanlarında (alt domain devralma, açık API, bilinen CVE) öne çıkan bir risk tespit edilmedi; genel değerlendirmeyi Yüksek'e taşıyan etken **şifresiz iletişimdir** (HTTPS desteklenmiyor — yukarıda). Aşağıda her alan ayrı ayrı raporlanmıştır.`
      : cumulative
      ? `Birden fazla keşif alanı aynı anda risk taşıyor (en yükseği **${worstArea.title}** — ${worstArea.headline}); birikimli risk nedeniyle genel değerlendirme Yüksek. Aşağıda her alan ayrı ayrı raporlanmıştır.`
      : worst === 'high'
        ? `En yüksek risk **${worstArea.title}** alanında (${worstArea.headline}) tespit edildi; öncelikli olarak giderilmesi önerilir. Aşağıda her alan ayrı ayrı raporlanmıştır.`
        : worst === 'medium-high'
          ? `Öne çıkan alan **${worstArea.title}** (${worstArea.headline}); tek başına yüksek etkili. Öncelikli olarak giderilmesi önerilir. Aşağıda her alan ayrı ayrı raporlanmıştır.`
          : worst === 'medium'
            ? `Öne çıkan alan **${worstArea.title}** (${worstArea.headline}); kısa vadede giderilmesi önerilir. Aşağıda her alan ayrı ayrı raporlanmıştır.`
            : 'Dışarıdan görünen alt domain, API ve CMS yüzeyiniz şu an için dar ve kontrollü görünüyor; rapor, tam envanter ve önerilen iyi pratiklerle birlikte her alanı ayrı ayrı belgeler. Aşağıda her alan ayrı ayrı raporlanmıştır.';

  const areaSections = areas.map((a) => a.dataUnavailable
    ? `## ${a.title}\n\n**${a.headline}**\n\n${a.body}\n`
    : `## ${a.title}\n\n**Genel risk seviyesi: ${RISK_WORD[a.level]} — ${a.headline}**\n\n${a.body}\n`).join('\n');

  // (MERKEZİ FINDINGS -> 2.1 Dağılım + 2.2 Master) http-only https_missing + RİSK TAŞIYAN keşif
  // alanları (dangling subdomain / açık API / bilinen CVE) ŞİDDET-kolonlu TEK tabloda toplanır ki
  // rozet=dağılım=master aynı bulgu setini yansıtsın (madde/bölüm-içi metin master'a girmiyordu).
  const sevWord = (l: Level): string => (l === 'high' || l === 'medium-high' ? 'Yüksek' : l === 'medium' ? 'Orta' : 'Düşük');
  const centralRows: string[] = [];
  if (httpOnly) centralRows.push(`| HTTPS desteklenmiyor (şifresiz iletişim) | Yüksek | Hedef HTTPS'e yanıt vermiyor; tüm trafik şifresiz (düz metin) taşınıyor — dinlenebilir/değiştirilebilir. Çözüm: geçerli TLS sertifikası + HTTP→HTTPS yönlendirme + HSTS. |`);
  for (const a of available) {
    if (levelRank(a.level) >= 1) centralRows.push(`| ${a.title} — ${a.headline.replace(/\|/g, '\\|')} | ${sevWord(a.level)} | Ayrıntı aşağıdaki “${a.title}” bölümündedir. |`);
  }
  const httpsFindingSection = centralRows.length
    ? `## TESPİT EDİLEN RİSKLER\n\n| Bulgu | Şiddet | Açıklama |\n|-------|--------|----------|\n${centralRows.join('\n')}\n\n`
    : '';

  const findings =
    `## YÖNETİCİ ÖZETİ\n\n${summary.join('\n')}\n\n` +
    `## GENEL DEĞERLENDİRME\n\n**Risk Seviyesi: ${RISK_WORD[worst]}**\n\n${httpOnly ? 'Bu hedef HTTPS üzerinden yanıt vermiyor; iletişim şifresiz taşınıyor (öncelikli olarak HTTPS’e geçilmelidir). ' : ''}${genelSentence}\n\n` +
    `${httpsFindingSection}${METHODOLOGY_SECTION}\n` +
    `${areaSections}\n` +
    `${BEST_PRACTICES_SECTION}`;

  const fixText =
    'Bu bölüm, keşif taramanızda tespit edilen tüm eksiklikler için alan alan düzeltme önerileri içerir.\n\n' +
    areas.map((a) => a.fixText.trim()).filter(Boolean).join('\n\n');

  return { findings, fixText };
}

export async function generateBundleReconReport(host: string): Promise<{ findings: string; fixText: string } | null> {
  // Protokol çözümle (cache'i ısıtır -> reconEvidence collectorları cachedOriginUrl ile http-only'de
  // de çalışır) + http-only ise https_missing bulgusu üret.
  const o = await resolveOrigin(host);
  if (!o.reachable) return unscannableReconReport(host);
  const ev = await collectReconEvidence(host);
  // Hiçbir keşif alanı veri toplayamadıysa -> "İncelenemedi" (null->Düşük fallback DEĞİL).
  return combineReconAreas(ev, { httpOnly: !o.httpsWorks }) ?? unscannableReconReport(host);
}

function unscannableReconReport(host: string): { findings: string; fixText: string } {
  const findings =
    `## YÖNETİCİ ÖZETİ\n\n` +
    `- **Genel risk seviyesi: İncelenemedi** — hedefe (${host}) bağlanılamadığı için keşif taraması yürütülemedi.\n` +
    `- Bu sonuç sitenin GÜVENLİ olduğu anlamına GELMEZ; yalnızca kontrollerin çalıştırılamadığını gösterir.\n` +
    `- **Önerilen ilk adım:** Alan adının yayında ve erişilebilir olduğunu doğrulayıp taramayı tekrarlayın.\n\n` +
    `## GENEL DEĞERLENDİRME\n\n**Risk Seviyesi: İncelenemedi**\n\nHedefin 443 (HTTPS) ve 80 (HTTP) portlarına bağlantı kurulamadı. Bu rapor bir "temiz/güvenli" sonucu DEĞİLDİR; erişim sağlanınca yeniden taranmalıdır.\n`;
  return { findings, fixText: '' };
}
