import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { renderReportPdf } from './pdf.js';
import { getPackageDef } from './scanPackages.js';
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
    '> Aşağıdaki adımlar örnek/temsilidir. Gerçek raporunuzda her bulguya özel çözümler yer alır.',
    '',
    '### Öncelikli düzeltmeler',
    '- Eksik güvenlik başlıklarını ekleyin (HSTS, X-Content-Type-Options, X-Frame-Options).',
    '- Sunucu/teknoloji sürüm bilgisini yanıt başlıklarından gizleyin.',
    '- Açıkta kalan hassas dosya/dizinleri (`.git`, `.env`, yedekler) erişime kapatın.',
    '',
    '```nginx',
    'server_tokens off;',
    'location ~ /\\.(git|env|svn) { deny all; }',
    '```',
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
  bundle_surface: 'ssl_tls',
  bundle_recon: 'ssl_tls',
  bundle_compliance: 'kvkk_hazirlik',
  bundle_active_verify: 'ssl_tls',
  bundle_full_pentest: 'ssl_tls',
};

const pdfCache = new Map<string, Buffer>();

function sampleKeyFor(packageKey: string): string {
  return SAMPLE_KEYS.includes(packageKey) ? packageKey : DEFAULT_SAMPLE;
}

export async function getSampleReportPdf(packageKey: string): Promise<Buffer> {
  // Istenen anahtar (paket veya bundle) bazinda cache — ayni ornek md'yi paylassalar bile
  // baslik (packageName) farkli olabilir, o yuzden REQUEST anahtariyla cache'leriz.
  const cached = pdfCache.get(packageKey);
  if (cached) return cached;

  const bundle = getBundle(packageKey);
  const sampleKey = bundle ? BUNDLE_SAMPLE[packageKey] ?? DEFAULT_SAMPLE : sampleKeyFor(packageKey);
  const md = readFileSync(join(SAMPLES_DIR, `${sampleKey}.md`), 'utf-8');
  const packageName = bundle
    ? bundle.displayName
    : getPackageDef(sampleKey as Parameters<typeof getPackageDef>[0]).displayName;

  // (LANSMAN KAMPANYASI) örnek raporda AI Çözüm Önerileri bölümü AÇIK (temsili içerik). Kapanınca kilitli.
  const fixMarkdown = config.aiFixFreeCampaign ? (SAMPLE_FIX_MD[sampleKey] ?? SAMPLE_FIX_MD[DEFAULT_SAMPLE]) : null;
  const pdf = await renderReportPdf(
    md,
    {
      hostname: 'ornek-site.com',
      packageName,
      createdAt: new Date('2026-01-15T10:00:00.000Z'), // sabit ornek tarihi (stabil cikti)
      locale: 'tr',
    },
    { fixMarkdown },
  );
  pdfCache.set(packageKey, pdf);
  return pdf;
}
