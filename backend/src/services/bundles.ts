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
  /** true ise "Yakında" — listelenir ama satin ALINAMAZ (createBundleOrder reddeder). */
  comingSoon?: boolean;
  /** Sabit uyeler (Uyum paketi haric). */
  memberKeys: string[];
  /** true ise musteri checkout'ta uyeleri SECER (Uyum paketi: 1/2/3 modul). */
  selectable?: boolean;
  /** selectable ise secilebilir modul havuzu. */
  selectableKeys?: string[];
  /** Bu key SADECE TR bolgesinde secilebilir/gorunur (ör. kvkk_hazirlik). */
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
    memberKeys: ['subdomain_takeover', 'api_discovery', 'cms_cve'],
  },
  {
    key: 'bundle_compliance',
    displayName: 'Uyum Paketi',
    displayNameEn: 'Compliance Bundle',
    description:
      'İstediğiniz uyum modüllerini birlikte seçin (KVKK / PCI-DSS / ISO 27001 — tek, ikili veya üçü birden). Seçtiğiniz modül sayısına göre indirimli fiyat. (Her modül tek tek de alınabilir.)',
    descriptionEn:
      'Pick the compliance modules you need together (PCI-DSS / ISO 27001 — one, two, or all). Discount scales with the number of modules. (Each module can still be bought individually.)',
    category: 'compliance',
    discountPct: 20,
    memberKeys: [],
    selectable: true,
    selectableKeys: ['kvkk_hazirlik', 'pci_hazirlik', 'iso27001_hazirlik'],
    trOnlyKeys: ['kvkk_hazirlik'], // KVKK yalniz TR
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

/** Bundle bolgesel fiyati: uye tekil fiyatlar toplami * (1 - indirim). */
export function bundlePrice(
  bundle: ComboBundle,
  region: string,
  selectedKeys?: string[],
): { memberKeys: string[]; originalMinorUnit: number; amountMinorUnit: number; currency: string; discountPct: number } {
  const memberKeys = resolveMembers(bundle, region, selectedKeys);
  const prices = memberKeys.map((k) => getPricing(k, region));
  const originalMinorUnit = prices.reduce((sum, p) => sum + p.amountMinorUnit, 0);
  const currency = prices[0]?.currency ?? getPricing('basit_tarama', region).currency;
  const amountMinorUnit = Math.round(originalMinorUnit * (1 - bundle.discountPct / 100));
  return { memberKeys, originalMinorUnit, amountMinorUnit, currency, discountPct: bundle.discountPct };
}
