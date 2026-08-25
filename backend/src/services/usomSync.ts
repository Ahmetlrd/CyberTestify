/**
 * (Keşif — USOM/SGB Bildirim Eşlemesi · OTOMATIK SENKRON) Kamuya açık USOM/SGB YAPISAL akışından
 * (siberguvenlik.gov.tr/api/incident — JSON, SPA sayfası DEĞİL) bildirimleri çekip `UsomAdvisory`
 * tablosuna IDEMPOTENT upsert eder. worker.ts günde bir tetikler (tarama kritik yolunun DIŞINDA).
 *
 * DÜRÜSTLÜK BARİYERİ: LLM YOK. İmza (matchKind/matchKey) yalnız DETERMİNİSTİK bir ürün→imza
 * allowlist'inden türetilir; bilinmeyen ürün → imzasız (kind:'none') → kataloglanır ama SAHTE EŞLEŞME
 * ÜRETMEZ (dış-gözlemlenebilir alt küme dürüstlüğü). Sürüm aralığı güvenilir çıkarılamadığından BOŞ
 * bırakılır → üç-durumun "sürüm doğrulanamadı" dalı. "Kesin etkileniyorsunuz" hiçbir koşulda üretilmez.
 * CVE yalnız bildirim metninden regex ile (olgusal) alınır. TR-no/başlık/kaynak-URL düşük risklidir → otomatik girer.
 *
 * ERİŞİLEMEZLİK: akış erişilemez/format bozuksa senkron sessizce başarısız olur, ÖNCEKİ katalog korunur,
 * hata loglanır. Rapor her zaman (statik seed + son başarılı DB) üzerinden çalışır; tarama BLOKLANMAZ.
 */
import { prisma } from '../db.js';
import { USOM_CATALOG, type UsomAdvisory, type UsomMatch } from './usomCatalog.js';

// (YAPILANDIRMA) Senkron aralığı — worker günde bir çalıştırır; feed'den çekilecek sayfa sayısı (20/sayfa).
export const USOM_SYNC_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24 saat
const USOM_FEED_URL = 'https://siberguvenlik.gov.tr/api/incident';
const USOM_SYNC_PAGES = 3;        // en yeni ~60 bildirim (katalog birikimlidir — upsert asla silmez)
const FETCH_TIMEOUT_MS = 15_000;

// (DETERMİNİSTİK ALLOWLIST) Yalnız recon parmak-izinin GERÇEKTEN tespit edebildiği ürünler eşlenir.
// Apache: httpd DIŞI Apache projeleri (banner'da görünmez) HARİÇ tutulur → yanlış eşleşme yok.
const APACHE_NON_HTTPD = /superset|inlong|tomcat|struts|kafka|solr|activemq|camel|cordova|log4j|hadoop|spark|airflow|ofbiz|shiro|dubbo|guacamole|\bjames\b|jmeter|nifi|zookeeper|commons|\bmaven\b|groovy|velocity|xerces|httpcomponents|\bmina\b|\bcxf\b|wicket|myfaces|tapestry|\bhive\b|\bflink\b|druid|pulsar|ranger|ambari|iotdb|linkis|seatunnel|dolphinscheduler/i;

// Başlık/etiketten DETERMİNİSTİK imza. Karşılığı yoksa {kind:'none'} (eşlenmez ama kataloglanır).
export function signatureFromTitle(title: string, tags?: string | null): UsomMatch {
  const s = `${title} ${tags ?? ''}`;
  if (/wordpress/i.test(s)) return { kind: 'cms', cms: 'WordPress' };
  if (/joomla/i.test(s)) return { kind: 'cms', cms: 'Joomla' };
  if (/drupal/i.test(s)) return { kind: 'cms', cms: 'Drupal' };
  if (/typo3/i.test(s)) return { kind: 'cms', cms: 'TYPO3' };
  if (/magento/i.test(s)) return { kind: 'cms', cms: 'Magento' };
  if (/prestashop/i.test(s)) return { kind: 'cms', cms: 'PrestaShop' };
  if (/\bnginx\b/i.test(s)) return { kind: 'banner', product: 'nginx' };
  if (/\bapache\b/i.test(s) && !APACHE_NON_HTTPD.test(s)) return { kind: 'banner', product: 'Apache httpd' };
  if (/\bphp\b/i.test(s) && !/phpmyadmin|phpbb|phpunit|phpstorm/i.test(s)) return { kind: 'banner', product: 'PHP' };
  return { kind: 'none' };
}

const cveFrom = (html: string): string | null => {
  const m = [...html.matchAll(/CVE-\d{4}-\d{4,7}/gi)].map((x) => x[0].toUpperCase());
  return m.length ? [...new Set(m)].slice(0, 3).join(', ') : null;
};

type IncidentModel = { slug?: string; title?: string; desc?: string; date?: string; tags?: string | null };

async function fetchPage(page: number): Promise<IncidentModel[]> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(`${USOM_FEED_URL}?page=${page}`, { signal: ctrl.signal, headers: { accept: 'application/json', 'user-agent': 'CyberTestify-UsomSync/1.0' } });
    if (!res.ok) return [];
    const j = (await res.json()) as { models?: IncidentModel[] };
    return Array.isArray(j.models) ? j.models : [];
  } catch {
    return [];
  } finally {
    clearTimeout(timer);
  }
}

/** Zamanlanmış senkron: feed → deterministik imza → idempotent upsert. Hata → önceki katalog korunur. */
export async function syncUsomCatalog(): Promise<{ ok: boolean; fetched: number; upserted: number }> {
  let fetched = 0;
  let upserted = 0;
  for (let p = 1; p <= USOM_SYNC_PAGES; p++) {
    const models = await fetchPage(p);
    if (!models.length) { if (p === 1) return { ok: false, fetched, upserted }; break; } // ilk sayfa boşsa erişilemez say
    fetched += models.length;
    for (const m of models) {
      const slug = (m.slug ?? '').trim();
      const trNo = slug.toUpperCase();
      if (!/^TR-\d{2}-\d{3,6}$/.test(trNo) || !m.title) continue;
      const sig = signatureFromTitle(m.title, m.tags);
      const publishedAt = m.date ? new Date(m.date.replace(' ', 'T')) : null;
      const data = {
        title: m.title.trim(),
        url: `https://www.usom.gov.tr/bildirim/${slug.toLowerCase()}`,
        publishedAt: publishedAt && !isNaN(publishedAt.getTime()) ? publishedAt : null,
        matchKind: sig.kind,
        matchKey: sig.kind === 'banner' ? sig.product : sig.kind === 'cms' ? sig.cms : null,
        cve: cveFrom(m.desc ?? ''),
        versionLt: null, // güvenilir çıkarılamıyor → "sürüm doğrulanamadı"
        syncedAt: new Date(),
      };
      await prisma.usomAdvisory.upsert({ where: { trNo }, create: { trNo, ...data }, update: data }).then(() => { upserted++; }).catch(() => {});
    }
  }
  return { ok: true, fetched, upserted };
}

/** Statik seed (baseline) + DB (senkron) birleşik katalog — DB kazanır (taze). Rapor bunu okur. */
export async function loadUsomCatalog(): Promise<UsomAdvisory[]> {
  const rows = await prisma.usomAdvisory.findMany().catch(() => [] as Array<{ trNo: string; title: string; url: string; matchKind: string; matchKey: string | null; cve: string | null; versionLt: string | null }>);
  const byTr = new Map<string, UsomAdvisory>();
  for (const a of USOM_CATALOG) byTr.set(a.tr, a); // statik baseline
  for (const r of rows) {
    const match: UsomMatch = r.matchKind === 'banner' && r.matchKey ? { kind: 'banner', product: r.matchKey }
      : r.matchKind === 'cms' && r.matchKey ? { kind: 'cms', cms: r.matchKey }
      : { kind: 'none' };
    byTr.set(r.trNo, { tr: r.trNo, title: r.title, url: r.url, match, cve: r.cve ?? undefined, versionLt: r.versionLt ?? undefined });
  }
  return [...byTr.values()];
}

/** Kataloğun son başarılı senkron tarihi (rapordaki olgusal "son güncelleme" bilgisi için). */
export async function usomLastSyncAt(): Promise<Date | null> {
  const r = await prisma.usomAdvisory.aggregate({ _max: { syncedAt: true } }).catch(() => null);
  return r?._max.syncedAt ?? null;
}
