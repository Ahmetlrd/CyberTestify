import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { renderReportPdf } from './pdf.js';
import { getPackageDef, localizedPackage } from './scanPackages.js';
import { getBundle } from './bundles.js';
import { config } from '../config.js';

// (LANSMAN KAMPANYASI) Örnek raporlarda "AI Çözüm Önerileri" bölümü de AÇIK gösterilir (temsili içerik).
// Kampanya bitince kilitlenir (fixMarkdown verilmez -> mevcut "kilitli" upsell'e döner).
const SAMPLE_FIX_MD: Record<string, string> = {
  ssl_tls: [
    '> Aşağıdaki adımlar örnek/temsilidir. Gerçek raporunuzda her bulguya özel, panoya kopyalanabilir çözümler yer alır.',
    '',
    '### 1) Eksik güvenlik başlıklarını ekleyin (Nginx)',
    '```nginx',
    'add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;',
    'add_header X-Content-Type-Options "nosniff" always;',
    'add_header X-Frame-Options "SAMEORIGIN" always;',
    'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
    '```',
    '',
    '### 2) TLS yapılandırmasını sıkılaştırın',
    '- Yalnızca TLS 1.2 ve 1.3’e izin verin; TLS 1.0/1.1’i kapatın.',
    '- Zayıf şifre paketlerini (RC4, 3DES) devre dışı bırakın; ileri gizlilik (ECDHE) tercih edin.',
    '',
    '### 3) İçerik Güvenlik Politikası (CSP) tanımlayın',
    '```nginx',
    `add_header Content-Security-Policy "default-src 'self'; object-src 'none'; frame-ancestors 'self'" always;`,
    '```',
  ].join('\n'),
  basit_tarama: [
    '> Aşağıdaki adımlar örnek/temsilidir. Gerçek raporunuzda her bulguya özel, panoya kopyalanabilir çözümler yer alır.',
    '',
    '### 1) X-Frame-Options ekleyin (clickjacking koruması)',
    '```nginx',
    'add_header X-Frame-Options "SAMEORIGIN" always;',
    '```',
    '',
    '### 2) X-Content-Type-Options ekleyin (MIME-sniffing koruması)',
    '```nginx',
    'add_header X-Content-Type-Options "nosniff" always;',
    '```',
    '',
    '### 3) Content-Security-Policy tanımlayın',
    'Sitenize uygun temel bir politikayla başlayın, sonra sıkılaştırın:',
    '```nginx',
    `add_header Content-Security-Policy "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'" always;`,
    '```',
    '',
    '### 4) Referrer-Policy ekleyin',
    '```nginx',
    'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
    '```',
    '',
    '### 5) Sürüm ifşasını ve hassas dosyaları kapatın',
    '```nginx',
    'server_tokens off;',
    'location ~ /\\.(git|env|svn) { deny all; }',
    '```',
    '',
    'Değişikliklerden sonra `nginx -t` ile doğrulayıp yeniden yükleyin (`systemctl reload nginx`).',
  ].join('\n'),
  kvkk_hazirlik: [
    '> Aşağıdaki adımlar örnek/temsilidir ve hukuki danışmanlık değildir.',
    '',
    '### Hazırlık adımları',
    '- Aydınlatma metni ve açık rıza akışlarını gözden geçirin; veri işleme envanterini güncelleyin.',
    '- Çerez/izleme bildirimini ve tercihlerini netleştirin.',
    '- Yurt dışı veri aktarımlarını KVKK m.9 kapsamında belgeleyin.',
    '- E-posta kimlik doğrulama kayıtlarını (SPF/DMARC) tamamlayın (spoofing riskini azaltır).',
  ].join('\n'),
  recon: [
    '> Aşağıdaki adımlar örnek/temsilidir. Gerçek raporunuzda her keşif bulgusuna özel çözümler yer alır.',
    '',
    '### 1) Açık API dokümantasyonunu kapatın/koruyun',
    '- Üretimde Swagger/OpenAPI arayüzünü devre dışı bırakın veya kimlik doğrulaması arkasına alın.',
    '```nginx',
    'location /swagger { deny all; return 404; }',
    '```',
    '',
    '### 2) Hazırlık/eski alt alanları izole edin',
    '- `staging.*` ve `old.*` alt alanlarını IP allowlist ya da temel kimlik doğrulamayla sınırlayın; kullanılmayanları kaldırın.',
    '',
    '### 3) CMS sürüm ifşasını gizleyin ve güncelleyin',
    '- WordPress ve eklentileri güncel tutun; sürüm meta etiketini kaldırın.',
    '```',
    "remove_action('wp_head', 'wp_generator');",
    '```',
  ].join('\n'),
  active_verify: [
    '> Aşağıdaki adımlar örnek/temsilidir. Gerçek raporunuzda her bulguya özel, panoya kopyalanabilir çözümler yer alır.',
    '',
    '### 1) SQL enjeksiyonunu kökten kapatın (parametreli sorgu)',
    '- Kullanıcı girdisini asla sorguya birleştirmeyin; hazır ifade (prepared statement) kullanın.',
    '```sql',
    '-- YANLIŞ:  "... WHERE username = \'" + input + "\'"',
    '-- DOĞRU:   WHERE username = ?   (parametre olarak bağlayın)',
    '```',
    '',
    '### 2) Yansıyan XSS için çıktı kodlaması',
    '- Kullanıcı girdisini yansıtırken bağlama uygun kodlama (HTML entity) uygulayın; CSP ekleyin.',
    '',
    '### 3) IDOR — sunucu tarafı yetki kontrolü',
    '- Her nesne erişiminde kaydın oturum sahibine ait olduğunu SUNUCUDA doğrulayın (yalnız kimliğe güvenmeyin).',
    '',
    '### 4) Oturum çerezi bayrakları + CORS',
    '- Çerezlere `HttpOnly; Secure; SameSite=Lax` ekleyin; CORS politikasını yalnız güvenilen origin\'lerle sınırlayın.',
  ].join('\n'),
  full_pentest: [
    '> Aşağıdaki adımlar örnek/temsilidir. Gerçek raporunuzda her bulguya özel çözümler yer alır.',
    '',
    '### 1) Forced browsing — fonksiyon seviyesi yetki kontrolü',
    '- Yönetici uç noktalarında rol kontrolünü SUNUCUDA zorunlu kılın (arayüzde gizlemek yetmez).',
    '```',
    'if (!user.hasRole("admin")) return res.status(403).end();',
    '```',
    '',
    '### 2) Authenticated SQL enjeksiyonu',
    '- Tüm veritabanı erişimlerinde parametreli sorgu; ORM kullanıyorsanız ham SQL birleştirmeden kaçının.',
    '',
    '### 3) Sunucu tarafında oturum geçersiz kılma (logout)',
    '- Çıkışta oturumu SUNUCUDA sonlandırın (yalnız çerez silmek yetmez).',
    '```',
    'req.session.destroy();  // veya oturum kaydını store\'dan sil',
    '```',
    '',
    '### 4) Öncelik',
    '- Önce Yüksek: forced browsing + SQLi; ardından oturum geçersiz kılma (düşük maliyetli hızlı kazanım).',
  ].join('\n'),
};

/**
 * (1) ORNEK RAPOR (sample report) — satin almadan once "rapor nasil gorunuyor?"
 * On-hazirlanmis, ANONIM (ornek-site.com) statik markdown ornekleri (src/samples/*.md)
 * mevcut PDF pipeline'indan gecirilip PDF olarak sunulur. Ek LLM/PentAGI maliyeti YOK.
 * Ilk istekte render edilip BELLEKTE cache'lenir; sonraki istekler aninda doner.
 * Not: ssl_tls gercek bir taramadan anonimlestirilerek; basit_tarama/kvkk temsili.
 */

const __dirname = dirname(fileURLToPath(import.meta.url));
const SAMPLES_DIR = join(__dirname, '..', 'samples');

// Kendi ornegi olan paketler; digerleri DEFAULT'a duser (buton her kartta calisir).
const SAMPLE_KEYS = ['ssl_tls', 'basit_tarama', 'kvkk_hazirlik'];
const DEFAULT_SAMPLE = 'ssl_tls';

// BUNDLE (kombine paket) → temsili ornek markdown'i. Satis modeli yalniz-paket oldugundan
// ornek rapor da PAKET/BUNDLE bazinda sunulur (tek tek kontrol DEGIL). PDF basligi bundle
// adini gosterir; icerik temsili bir uye ciktisidir.
const BUNDLE_SAMPLE: Record<string, string> = {
  bundle_surface: 'ssl_tls', // Dış Yüzey = SSL/TLS + yapılandırma içeriği (doğru)
  bundle_recon: 'recon', // Keşif = subdomain/API/CMS keşfi
  bundle_compliance: 'kvkk_hazirlik', // Uyum = KVKK hazırlık
  bundle_active_verify: 'active_verify', // Aktif Doğrulama = enjeksiyon/IDOR göstergeleri
  bundle_full_pentest: 'full_pentest', // Tam Kapsamlı = authenticated bulgular
};

// (issue #4) Örnek raporun ÜST KUTU risk seviyesi — GÖVDEDEKİ gerçek riskle birebir.
// Keşif=Orta, Aktif Doğrulama=Yüksek, Tam Kapsamlı=Yüksek (bug buradaydı: hepsi "Düşük" görünüyordu).
const SAMPLE_RISK: Record<string, { level: 'high' | 'medium' | 'low' }> = {
  ssl_tls: { level: 'medium' },
  basit_tarama: { level: 'medium' },
  kvkk_hazirlik: { level: 'low' }, // uyum hazırlığı — güvenlik açığı değil, iyileştirme alanları
  recon: { level: 'medium' },
  active_verify: { level: 'high' },
  full_pentest: { level: 'high' },
};

// (GERÇEK ÇIKTI ÖRNEKLERİ) İstek paketKey → deterministik motorun GERÇEK taramasından üretilmiş
// örnek gövde. Dosyalar SAMPLES_DIR/<fileKey>.md + <fileKey>_fix.md. hostname örnek hedeftir.
// Buraya eklenen her paket, temsili markdown yerine gerçek-rapor formatını gösterir.
const REAL_SAMPLES: Record<string, { fileKey: string; hostname: string }> = {
  basit_tarama: { fileKey: 'basit_tarama', hostname: 'testasp.vulnweb.com' },
  bundle_surface: { fileKey: 'bundle_surface', hostname: 'rest.vulnweb.com' },
  bundle_recon: { fileKey: 'bundle_recon', hostname: 'rest.vulnweb.com' }, // gerçek tarama — herkese açık test hedefi (anonimleştirme gerekmez; robots.txt + banner CVE dahil)
  bundle_compliance: { fileKey: 'bundle_compliance', hostname: 'ornek.com' }, // gerçek tarama (anonimleştirildi)
  bundle_active_verify: { fileKey: 'bundle_active_verify', hostname: 'ornek.com' }, // gerçek aktif tarama (kendi fixture'ımız; gövde host-agnostik -> kapakta ornek.com)
  bundle_full_pentest: { fileKey: 'bundle_full_pentest', hostname: 'ornek.com' }, // gerçek pentest çıktısı — BİLEREK zafiyetli test uygulaması (anonimleştirildi: ornek.com; Faz 0–5 tüm kontroller görünür; sample-notice ile işaretli)
};

const pdfCache = new Map<string, Buffer>();

function sampleKeyFor(packageKey: string): string {
  return SAMPLE_KEYS.includes(packageKey) ? packageKey : DEFAULT_SAMPLE;
}

// (de LANSMANI) Almanca örnek gövde: <fileKey>.de.md varsa onu OKU; yoksa TR gövdeye düş
// (chrome yine Almanca render edilir). Böylece Almanca sample .md dosyaları eklendikçe otomatik devreye girer.
function readSampleMd(fileKey: string, locale: 'tr' | 'en' | 'de'): string {
  if (locale === 'de' || locale === 'en') {
    try { return readFileSync(join(SAMPLES_DIR, `${fileKey}.${locale}.md`), 'utf-8'); } catch { /* yok -> TR fallback */ }
  }
  return readFileSync(join(SAMPLES_DIR, `${fileKey}.md`), 'utf-8');
}
function readSampleFixMd(fileKey: string, locale: 'tr' | 'en' | 'de'): string {
  if (locale === 'de' || locale === 'en') {
    try { return readFileSync(join(SAMPLES_DIR, `${fileKey}_fix.${locale}.md`), 'utf-8'); } catch { /* yok -> TR fallback */ }
  }
  return readFileSync(join(SAMPLES_DIR, `${fileKey}_fix.md`), 'utf-8');
}
function bundleName(b: { displayName: string; displayNameEn: string; displayNameDe: string }, locale: 'tr' | 'en' | 'de'): string {
  return locale === 'de' ? b.displayNameDe : locale === 'en' ? b.displayNameEn : b.displayName;
}

export async function getSampleReportPdf(packageKey: string, locale: 'tr' | 'en' | 'de' = 'tr'): Promise<Buffer> {
  const de = locale === 'de', en = locale === 'en';
  // Istenen anahtar (paket veya bundle) + locale bazinda cache — ayni ornek md'yi paylassalar bile
  // baslik (packageName) farkli olabilir, o yuzden REQUEST anahtari+locale ile cache'leriz.
  const cacheKey = `${packageKey}|${locale}`;
  const cached = pdfCache.get(cacheKey);
  if (cached) return cached;

  // (GERÇEK ÇIKTI ÖRNEKLERİ) Bu paketlerin örneği, deterministik motorun GERÇEK bir taramadan
  // ürettiği gövdedir (uydurma değil); müşteri ana sayfada BİREBİR gerçek rapor formatını görür.
  // Bu yüzden assessOverride VERİLMEZ (reorganize + master tablo + 2.3 Detaylı Bulgular + pozitif
  // güvence gerçek-rapor yolundan üretilir) ve fix dosyadan okunur. Dosyalar: <key>.md + <key>_fix.md.
  const real = REAL_SAMPLES[packageKey];
  const bundle = getBundle(packageKey);

  let md: string;
  let packageName: string;
  let fixMarkdown: string | null;
  let assessOverride: { level: 'high' | 'medium' | 'low' } | undefined;
  let hostname: string;
  let metaPackageKey: string | undefined;

  if (real) {
    md = readSampleMd(real.fileKey, locale);
    packageName = bundle
      ? bundleName(bundle, locale)
      : localizedPackage(getPackageDef(real.fileKey as Parameters<typeof getPackageDef>[0]), locale).displayName;
    fixMarkdown = config.aiFixFreeCampaign
      ? readSampleFixMd(real.fileKey, locale)
      : null;
    assessOverride = undefined; // gerçek gövde -> risk zaten parse edilir
    hostname = real.hostname;
    metaPackageKey = packageKey;
  } else {
    const sampleKey = bundle ? BUNDLE_SAMPLE[packageKey] ?? DEFAULT_SAMPLE : sampleKeyFor(packageKey);
    md = readSampleMd(sampleKey, locale);
    packageName = bundle
      ? bundleName(bundle, locale)
      : localizedPackage(getPackageDef(sampleKey as Parameters<typeof getPackageDef>[0]), locale).displayName;
    // (LANSMAN KAMPANYASI) örnek raporda AI Çözüm Önerileri bölümü AÇIK (temsili içerik). Kapanınca kilitli.
    fixMarkdown = config.aiFixFreeCampaign ? (SAMPLE_FIX_MD[sampleKey] ?? SAMPLE_FIX_MD[DEFAULT_SAMPLE]) : null;
    // (issue #4) Üst "Genel Değerlendirme" kutusu = GÖVDEDEKİ gerçek risk. Statik örnek gövdesinin
    // risk ifadesi severity-parse'a takılmayabildiğinden her örneğe AÇIK seviye veriyoruz (tutarlılık).
    assessOverride = SAMPLE_RISK[sampleKey] ?? SAMPLE_RISK[DEFAULT_SAMPLE];
    hostname = 'ornek-site.com';
    metaPackageKey = undefined;
  }

  // (Rapor No benzersizliği) Aynı örnek hostu (ornek.com) paylaşan paketler farklı Rapor No alsın diye
  // createdAt'e paket-bazlı sabit bir dakika ofseti eklenir. Tarih PDF'te GİZLİ (hideDate) — ofset yalnız
  // reportIdentifiers hash'ini değiştirir; görünmez ama her örneğe benzersiz CT-ÖRNEK-XXXX verir. STABİL.
  const seedMin = [...packageKey].reduce((a, c) => a + c.charCodeAt(0), 0) % 720;
  const sampleCreatedAt = new Date(Date.parse('2026-08-15T10:00:00.000Z') + seedMin * 60_000);
  // (ORNEK PDF — DÜRÜSTLÜK) Tam Kapsamlı örneği, BİLEREK zafiyetli bırakılmış bir test uygulamasından
  // alınmıştır (bulgu sayısı/şiddeti gerçek sitelerde çok değişir) — bunu raporun başında açıkça belirt.
  const sampleNotice = packageKey === 'bundle_full_pentest'
    ? (de
        ? 'Dieser Beispielbericht stammt aus einer absichtlich verwundbar belassenen Testanwendung. Bei echten Websites variieren Anzahl und Schweregrad der Befunde je nach Architektur des Ziels erheblich.'
        : en
        ? 'This sample report is taken from an intentionally vulnerable test application. On real websites the number and severity of findings vary considerably depending on the target\'s architecture.'
        : 'Bu örnek rapor, bilerek zafiyetli bırakılmış bir test uygulamasından alınmıştır. Gerçek sitelerde bulgu sayısı ve şiddeti hedefin mimarisine göre önemli ölçüde değişir.')
    : null;
  const pdf = await renderReportPdf(
    md,
    {
      hostname,
      packageName,
      createdAt: sampleCreatedAt, // sabit ornek zamani (stabil cikti; PDF'te tarih GOSTERILMEZ)
      locale,
      packageKey: metaPackageKey,
    },
    { fixMarkdown, assessOverride, hideDate: true, sampleNotice }, // (ORNEK PDF) tarih HIC gosterilmez
  );
  pdfCache.set(cacheKey, pdf);
  return pdf;
}
