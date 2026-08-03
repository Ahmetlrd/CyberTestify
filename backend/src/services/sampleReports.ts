import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { renderReportPdf } from './pdf.js';
import { getPackageDef } from './scanPackages.js';

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

const pdfCache = new Map<string, Buffer>();

function sampleKeyFor(packageKey: string): string {
  return SAMPLE_KEYS.includes(packageKey) ? packageKey : DEFAULT_SAMPLE;
}

export async function getSampleReportPdf(packageKey: string): Promise<Buffer> {
  const key = sampleKeyFor(packageKey);
  const cached = pdfCache.get(key);
  if (cached) return cached;

  const md = readFileSync(join(SAMPLES_DIR, `${key}.md`), 'utf-8');
  const def = getPackageDef(key as Parameters<typeof getPackageDef>[0]);
  const pdf = await renderReportPdf(md, {
    hostname: 'ornek-site.com',
    packageName: def.displayName,
    createdAt: new Date('2026-01-15T10:00:00.000Z'), // sabit ornek tarihi (stabil cikti)
    locale: 'tr',
  });
  pdfCache.set(key, pdf);
  return pdf;
}
