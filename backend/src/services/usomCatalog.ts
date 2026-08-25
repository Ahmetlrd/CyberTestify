/**
 * (Keşif Paketi — USOM/SGB Bildirim Eşlemesi · YALNIZCA /tr) T.C. Siber Güvenlik Başkanlığı'nın
 * (USOM/SGB) KAMUYA AÇIK yayımladığı güvenlik bildirimleriyle, mevcut Keşif parmak-izini (CMS/banner)
 * DETERMİNİSTİK eşler. Yeni tarama motoru YOK — var olan keşif sinyali ikinci bir katalogla karşılaştırılır.
 *
 * MARKA/HUKUK: Bu bağımsız bir eşleme hizmetidir; SGB/USOM ile resmî bir bağı, onayı veya yetkilendirmesi
 * YOKTUR. "Resmî/ulusal/zorunlu tarama" veya "SGB onaylı" DEĞİLDİR. Yalnız kamuya açık bildirim
 * başlıklarıyla dış-yüzey eşlemesi yapar; "kesin etkileniyorsunuz" ASLA denmez.
 *
 * VERİ DÜRÜSTLÜĞÜ: Katalog GERÇEK TR-xx bildirimleriyle seed edilmiştir (uydurma bildirim/CVE YOK).
 * Yalnız aramayla DOĞRULANAN alanlar (TR no · başlık · ürün kategorisi · kaynak URL) doldurulur;
 * dışarıdan doğrulanamayan sürüm aralığı/CVE BOŞ bırakılır → eşleşme "sürüm doğrulanamadı" durumunda
 * kalır (aşırı-iddia yok). `versionLt`/`cve` yalnız güvenilir şekilde doğrulanınca eklenmelidir.
 *
 * KATALOG GÜNCELLEME (elle/yarı-otomatik): yeni bildirim çıkınca (usom.gov.tr/bildirim ·
 * siberguvenlik.gov.tr/guvenlik-bildirimleri) GERÇEK TR no + başlık + ürün + kaynak URL ile aşağıya
 * satır ekleyin; dışarıdan gözlemlenebilir ürünlerde (Apache httpd / nginx / PHP banner, WordPress/
 * Joomla/Drupal CMS) `match` doldurulur, değilse `{kind:'none'}` (kataloglanır ama eşlenmez). Reklam
 * "taze bildirim" temelliyse ilgili TR-xx satırı reklam yayındayken burada bulunmalıdır.
 */

export type UsomMatch =
  | { kind: 'banner'; product: string } // recon bannerCves product'ı ile eşleşir (ör. 'Apache httpd')
  | { kind: 'cms'; cms: string }         // recon cms.cms ile eşleşir (ör. 'WordPress')
  | { kind: 'none' };                    // dışarıdan gözlemlenemez → kataloglanır, eşlenmez

export type UsomAdvisory = {
  tr: string;          // GERÇEK bildirim no (TR-YY-NNNN)
  title: string;       // GERÇEK bildirim başlığı
  match: UsomMatch;    // dış-yüzey eşleme imzası
  versionLt?: string;  // (opsiyonel) tespit edilen sürüm bundan KÜÇÜKSE "aralıkta olabilir" — yalnız doğrulanınca
  cve?: string;        // (opsiyonel) yalnız doğrulanınca
  url: string;         // GERÇEK kaynak URL
};

// GERÇEK USOM/SGB bildirimleri (kamuya açık). Sürüm aralığı/CVE dışarıdan doğrulanamadığından
// bilerek boş — bu, üç-durum dürüstlüğünün "sürüm doğrulanamadı" dalını üretir (uydurma yok).
export const USOM_CATALOG: UsomAdvisory[] = [
  // — Dışarıdan gözlemlenebilir (banner/CMS ile eşlenebilir) —
  { tr: 'TR-24-1843', title: 'Apache Çoklu Ürün Güvenlik Bildirimi', match: { kind: 'banner', product: 'Apache httpd' }, url: 'https://www.usom.gov.tr/bildirim/tr-24-1843' },
  { tr: 'TR-23-0072', title: 'Apache Zafiyeti', match: { kind: 'banner', product: 'Apache httpd' }, url: 'https://www.usom.gov.tr/bildirim/tr-23-0072' },
  { tr: 'TR-25-0035', title: 'WordPress Eklenti Güvenlik Bildirimi', match: { kind: 'cms', cms: 'WordPress' }, url: 'https://www.usom.gov.tr/bildirim/tr-25-0035' },
  { tr: 'TR-25-0127', title: 'WordPress Eklenti Güvenlik Bildirimi', match: { kind: 'cms', cms: 'WordPress' }, url: 'https://www.usom.gov.tr/bildirim/tr-25-0127' },
  { tr: 'TR-25-0130', title: 'WordPress Eklenti Güvenlik Bildirimi', match: { kind: 'cms', cms: 'WordPress' }, url: 'https://www.usom.gov.tr/bildirim/tr-25-0130' },
  // — Kataloglu ama dışarıdan gözlemlenemez (dürüstlük: katalog > eşlenebilir alt küme) —
  { tr: 'TR-24-0728', title: 'Apache Superset Güvenlik Bildirimi', match: { kind: 'none' }, url: 'https://www.usom.gov.tr/bildirim/tr-24-0728' },
  { tr: 'TR-24-0009', title: 'Apache InLong Zafiyeti', match: { kind: 'none' }, url: 'https://www.usom.gov.tr/bildirim/tr-24-0009' },
  { tr: 'TR-24-0610', title: 'Fortinet Güvenlik Bildirimi', match: { kind: 'none' }, url: 'https://www.usom.gov.tr/bildirim/tr-24-0610' },
  { tr: 'TR-24-1530', title: 'Google Chrome Güvenlik Bildirimi', match: { kind: 'none' }, url: 'https://www.usom.gov.tr/bildirim/tr-24-1530' },
  { tr: 'TR-25-0254', title: 'Dolusoft Yazılım - Omaspot Güvenlik Bildirimi', match: { kind: 'none' }, url: 'https://www.usom.gov.tr/bildirim/tr-25-0254' },
];

export type UsomHit = { adv: UsomAdvisory; state: 'range' | 'unverified'; observedVersion?: string };

function vNums(v: string): number[] { return v.split(/[^0-9]+/).filter(Boolean).map(Number); }
function vLt(a: string, b: string): boolean {
  const A = vNums(a), B = vNums(b);
  for (let i = 0; i < Math.max(A.length, B.length); i++) { const x = A[i] ?? 0, y = B[i] ?? 0; if (x !== y) return x < y; }
  return false;
}

// Dış-yüzey gözlemlenebilir bildirim sayısı (eşlenebilir alt küme — dürüstlük metni için).
export const observableCount = (catalog: UsomAdvisory[] = USOM_CATALOG): number =>
  catalog.filter((a) => a.match.kind !== 'none').length;
export const USOM_OBSERVABLE_COUNT = observableCount(USOM_CATALOG);

/**
 * Mevcut Keşif parmak-izini (CMS + banner) katalogla eşler. İstismar/sürüm-tahmini YOK — yalnız
 * "bu ürün/teknoloji dışarıdan görüldü mü" + (doğrulanmış aralık VARSA) sürüm karşılaştırması.
 * `catalog` verilmezse statik seed kullanılır (otomatik-senkron loadUsomCatalog ile birleşiği geçer).
 */
export function matchUsom(fp: {
  cms?: { cms?: string; version?: string };
  banners: Array<{ product: string; version: string }>;
}, catalog: UsomAdvisory[] = USOM_CATALOG): UsomHit[] {
  const hits: UsomHit[] = [];
  for (const adv of catalog) {
    if (adv.match.kind === 'banner') {
      const wantProduct = adv.match.product;
      const b = fp.banners.find((x) => x.product === wantProduct);
      if (!b) continue;
      const inRange = adv.versionLt && b.version ? vLt(b.version, adv.versionLt) : false;
      hits.push({ adv, state: inRange ? 'range' : 'unverified', observedVersion: b.version });
    } else if (adv.match.kind === 'cms') {
      if (!fp.cms?.cms || fp.cms.cms !== adv.match.cms) continue;
      const inRange = adv.versionLt && fp.cms.version ? vLt(fp.cms.version, adv.versionLt) : false;
      hits.push({ adv, state: inRange ? 'range' : 'unverified', observedVersion: fp.cms.version });
    }
    // kind === 'none' → dışarıdan eşlenemez, atla.
  }
  return hits;
}
