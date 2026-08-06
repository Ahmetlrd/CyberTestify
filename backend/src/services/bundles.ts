import { getPricing } from './pricing.js';

/**
 * KOMBINE PAKETLER (bundle) — mevcut TEKIL paketleri SILMEDEN/gizlemeden, birden fazla
 * kontrolu birlikte isteyen musteriye daha uygun fiyatli EK secenek sunar. Her bundle,
 * uye tekil paketlerin `key`'lerini referans eder; satin alinca her uye kendi MEVCUT
 * promptu/guard'iyla ayri bir tarama olarak calisir (kod/prompt TEKRARI YOK — orchestrator
 * her uye siparisi icin ilgili paketin promptTemplate'ini kullanir).
 *
 * Fiyat: uye tekil paketlerin bolgesel toplamindan discountPct kadar indirimli. Fiyatlar
 * PLACEHOLDER (Vedat onayi bekliyor) — tekil fiyatlar da placeholder oldugu icin turetilmis.
 */
export interface ComboBundle {
  key: string;
  displayName: string; // TR
  displayNameEn: string;
  description: string; // TR
  descriptionEn: string;
  category: 'passive' | 'active-light' | 'compliance';
  discountPct: number;
  /**
   * NIHAI indirimli fiyat (TR, kurus). Vedat tarafindan sabitlenen yuvarlak fiyat; verilmisse
   * discountPct'ten TURETME YERINE bu kullanilir (bkz bundlePrice). Uye order tutarlari bu
   * TOPLAMA tam bolunur (bkz bundleMemberAmounts). TR disi bolgeler henuz canli degil → orada
   * discountPct'e dusulur.
   */
  finalPriceMinorUnitTr?: number;
  /** UI'da "Popüler" cercevesi/rozeti (pazarlama vurgusu). */
  popular?: boolean;
  /** true ise "Yakında" — listelenir ama satin ALINAMAZ (createBundleOrder reddeder). */
  comingSoon?: boolean;
  /** Sabit uyeler. */
  memberKeys: string[];
  /** (KULLANIMDAN KALDIRILDI) Onceden Uyum paketi modul secimi; artik tum uyeler sabit dahil. */
  selectable?: boolean;
  selectableKeys?: string[];
  /** Bu key SADECE TR bolgesinde gorunur (ör. kvkk_hazirlik). TR disi bolgede uyeden ELENIR. */
  trOnlyKeys?: string[];
}

export const COMBO_BUNDLES: ComboBundle[] = [
  {
    key: 'bundle_surface',
    displayName: 'Dış Yüzey & Yapılandırma Paketi',
    displayNameEn: 'External Surface & Configuration Bundle',
    description:
      'Dış yüzeyinizin yapılandırma güvenliğini birlikte inceleyen paket: SSL/TLS, güvenlik başlıkları, DNS/e-posta, CORS ve CSP. Tekil toplamdan indirimli.',
    descriptionEn:
      'Reviews your external configuration posture together: SSL/TLS, security headers, DNS/email, CORS and CSP. Discounted vs buying separately.',
    category: 'passive',
    discountPct: 22,
    finalPriceMinorUnitTr: 399900, // 3.999 TL (Vedat — nihai indirimli, yuvarlak)
    popular: true, // en genis giris paketi → "Popüler"
    memberKeys: ['ssl_tls', 'header_leak', 'dns_email', 'cors_cookie', 'csp_analiz'],
  },
  {
    key: 'bundle_recon',
    displayName: 'Keşif Paketi',
    displayNameEn: 'Discovery Bundle',
    description:
      'Saldırı yüzeyinizi keşfeden paket: subdomain takeover taraması, API/Swagger keşfi ve CMS/bilinen-CVE tespiti. Tekil toplamdan indirimli.',
    descriptionEn:
      'Maps your attack surface: subdomain takeover scan, API/Swagger discovery and CMS/known-CVE detection. Discounted vs buying separately.',
    category: 'passive',
    discountPct: 20,
    finalPriceMinorUnitTr: 449900, // 4.499 TL (Vedat — nihai, yuvarlak)
    memberKeys: ['subdomain_takeover', 'api_discovery', 'cms_cve'],
  },
  {
    key: 'bundle_compliance',
    displayName: 'Uyum Paketi',
    displayNameEn: 'Compliance Bundle',
    description:
      'KVKK, PCI-DSS ve ISO 27001 ön-uyum kontrollerinin üçü birden tek pakette. Dışarıdan gözlemlenebilir hazırlık eksiklerini ilgili ilkelerle eşler (resmî denetim/uyum beyanı değildir). Tekil toplamdan indirimli.',
    descriptionEn:
      'PCI-DSS and ISO 27001 readiness checks together in one package (KVKK included in Turkey). Maps externally observable gaps to the relevant principles (not an official audit or statement of compliance). Discounted vs the single-item total.',
    category: 'compliance',
    discountPct: 20,
    finalPriceMinorUnitTr: 799900, // 7.999 TL (Vedat — nihai, yuvarlak; TR = 3 modul dahil)
    // Modul secimi KALDIRILDI — uyeler SABIT (uyum kontrolleri hep birlikte). KVKK yalniz TR.
    memberKeys: ['kvkk_hazirlik', 'pci_hazirlik', 'iso27001_hazirlik'],
    trOnlyKeys: ['kvkk_hazirlik'],
  },
  {
    key: 'bundle_active_verify',
    displayName: 'Aktif Doğrulama Paketi',
    displayNameEn: 'Active Verification Bundle',
    description:
      'Yedi aktif-hafif zafiyet doğrulama kontrolünün tümü tek pakette: Enjeksiyon, IDOR, SSRF, Dosya Yükleme, İş Mantığı, Race/Mass-Assignment ve RCE. Zafiyeti kanıtlar, istismar etmez; tek yetkilendirme beyanı yeterli. Tekil toplamdan belirgin indirimli.',
    descriptionEn:
      'All seven active-light verification checks in one bundle: Injection, IDOR, SSRF, File Upload, Business Logic, Race/Mass-Assignment and RCE. Proves presence, never exploits; a single authorization declaration covers all. Strongly discounted vs buying separately.',
    category: 'active-light',
    discountPct: 25,
    comingSoon: true,
    memberKeys: [
      'injection_verify',
      'idor_verify',
      'ssrf_verify',
      'file_upload_verify',
      'business_logic_verify',
      'race_massassign_verify',
      'rce_verify',
    ],
  },
  {
    key: 'bundle_full_pentest',
    displayName: 'Tam Kapsamlı Pentest Paketi',
    displayNameEn: 'Full-Scope Pentest Bundle',
    description:
      'Kimlik doğrulamalı (login’li) tarama + tam otonom çok-adımlı pentest bir arada. Aktif-hafif sınırlar korunur (istismar/exfil/DoS yok); yetkilendirme beyanı gerekir. Tekil toplamdan indirimli.',
    descriptionEn:
      'Authenticated (logged-in) scan + fully autonomous multi-step pentest together. Active-light limits preserved (no exploit/exfil/DoS); authorization declaration required. Discounted vs buying separately.',
    category: 'active-light',
    discountPct: 20,
    comingSoon: true,
    memberKeys: ['authenticated_scan', 'autonomous_pentest'],
  },
];

export function getBundle(key: string): ComboBundle | undefined {
  return COMBO_BUNDLES.find((b) => b.key === key);
}

/**
 * Bir bundle'in bolgesel uyeleri: sabit memberKeys, ya da selectable ise verilen
 * secim (selectedKeys) ile selectableKeys kesisimi. trOnly kisitli uyeler TR disi
 * bolgede ELENIR (ör. KVKK yalniz TR).
 */
export function resolveMembers(bundle: ComboBundle, region: string, selectedKeys?: string[]): string[] {
  let members: string[];
  if (bundle.selectable) {
    const pool = bundle.selectableKeys ?? [];
    const chosen = (selectedKeys ?? []).filter((k) => pool.includes(k));
    members = chosen.length ? chosen : pool; // secim yoksa tum havuz (onizleme)
  } else {
    members = [...bundle.memberKeys];
  }
  if (region !== 'tr' && bundle.trOnlyKeys?.length) {
    members = members.filter((k) => !bundle.trOnlyKeys!.includes(k));
  }
  return members;
}

/**
 * Bundle bolgesel fiyati. originalMinorUnit = uye tekil fiyatlarin toplami (referans/anchor).
 * amountMinorUnit = NIHAI fiyat: TR'de finalPriceMinorUnitTr verilmisse O; yoksa (TR disi /
 * fiyat tanimsizsa) toplam * (1 - indirim). effectiveDiscountPct gercek indirimi yansitir.
 */
export function bundlePrice(
  bundle: ComboBundle,
  region: string,
  selectedKeys?: string[],
): { memberKeys: string[]; originalMinorUnit: number; amountMinorUnit: number; currency: string; discountPct: number } {
  const memberKeys = resolveMembers(bundle, region, selectedKeys);
  const prices = memberKeys.map((k) => getPricing(k, region));
  const originalMinorUnit = prices.reduce((sum, p) => sum + p.amountMinorUnit, 0);
  const currency = prices[0]?.currency ?? getPricing('basit_tarama', region).currency;
  const amountMinorUnit =
    region === 'tr' && bundle.finalPriceMinorUnitTr != null
      ? bundle.finalPriceMinorUnitTr
      : Math.round(originalMinorUnit * (1 - bundle.discountPct / 100));
  const effectiveDiscountPct =
    originalMinorUnit > 0 ? Math.max(0, Math.round((1 - amountMinorUnit / originalMinorUnit) * 100)) : 0;
  return { memberKeys, originalMinorUnit, amountMinorUnit, currency, discountPct: effectiveDiscountPct };
}

/**
 * Uye order tutarlari: NIHAI bundle tutarini (amountMinorUnit) uyelere uye-tekil-fiyat
 * ORANINDA dagitir; TAM bolunme icin son uye kalan kurusu yuklenir (yuvarlama artigi). Boylece
 * uye order tutarlari TOPLAMI == bundle nihai fiyati == iyzico'ya gonderilen tutar (callback
 * bunu dogrular). Tekil fiyat toplami 0 ise esit boler.
 */
export function bundleMemberAmounts(
  bundle: ComboBundle,
  region: string,
  selectedKeys?: string[],
): Array<{ key: string; amountMinorUnit: number }> {
  const { memberKeys, originalMinorUnit, amountMinorUnit } = bundlePrice(bundle, region, selectedKeys);
  const singles = memberKeys.map((k) => getPricing(k, region).amountMinorUnit);
  const out: Array<{ key: string; amountMinorUnit: number }> = [];
  let assigned = 0;
  for (let i = 0; i < memberKeys.length; i++) {
    let share: number;
    if (i === memberKeys.length - 1) {
      share = amountMinorUnit - assigned; // son uye kalani alir → toplam TAM eslesir
    } else {
      share = originalMinorUnit > 0
        ? Math.round((amountMinorUnit * singles[i]) / originalMinorUnit)
        : Math.round(amountMinorUnit / memberKeys.length);
      assigned += share;
    }
    out.push({ key: memberKeys[i], amountMinorUnit: share });
  }
  return out;
}

// --- SATIS MODELI: yalniz bundle (kombine paket) ------------------------------
// Karar: tekil ("tek basina") paket satisi KAPALI — SADECE basit_tarama tekil satilir.
// Tum tekil taramalar en az bir bundle icinde mevcut (basit_tarama HARIC). Asagidaki
// "bundle uyesi mi" kontrolu bundle tanimlarindan TURETILIR (elle liste tutulmaz; bundle
// uyeleri degisirse otomatik dogru kalir). basit_tarama hicbir bundle'da olmadigindan
// dogal olarak ACIK kalir. comingSoon paketler de uye olabilir — onlar zaten ayrica bloklu.

/** Sabit memberKeys + selectable havuz dahil, TUM bundle uyesi paket anahtarlari. */
export function bundleMemberKeySet(): Set<string> {
  const s = new Set<string>();
  for (const b of COMBO_BUNDLES) {
    for (const k of b.memberKeys) s.add(k);
    for (const k of b.selectableKeys ?? []) s.add(k);
  }
  return s;
}

/** Bu paket bir bundle'da yer aliyor mu? (yer aliyorsa TEK BASINA satilamaz). */
export function isBundleOnlyPackage(key: string): boolean {
  return bundleMemberKeySet().has(key);
}

/** Bu paketi iceren ILK bundle'in gosterim adi (locale'e gore) — kullaniciya mesaj icin. */
export function primaryBundleForPackage(key: string, locale: 'tr' | 'en'): string | null {
  const b = COMBO_BUNDLES.find((bb) => bb.memberKeys.includes(key) || (bb.selectableKeys ?? []).includes(key));
  if (!b) return null;
  return locale === 'en' ? b.displayNameEn : b.displayName;
}
