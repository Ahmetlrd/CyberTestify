import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { renderReportPdf } from './pdf.js';
import { getPackageDef } from './scanPackages.js';
import { getBundle } from './bundles.js';

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

  const pdf = await renderReportPdf(md, {
    hostname: 'ornek-site.com',
    packageName,
    createdAt: new Date('2026-01-15T10:00:00.000Z'), // sabit ornek tarihi (stabil cikti)
    locale: 'tr',
  });
  pdfCache.set(packageKey, pdf);
  return pdf;
}
