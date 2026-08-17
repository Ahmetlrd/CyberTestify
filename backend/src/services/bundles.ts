import { getPricing, PRICE_OVERRIDE_MINOR } from './pricing.js';

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
  /**
   * "Ustu cizili" referans (anchor) fiyat (TR, kurus) — PAZARLAMA. Verilmisse UI'da orijinal
   * olarak BU gosterilir (uye tekil toplami DEGIL) ve indirim % = round((1 - final/anchor)*100)
   * yuvarlak cikacak sekilde secilir (ör. 5699 -> 3999 = %30). Uye order tutarlarinin
   * dagitimi bundan ETKILENMEZ (gercek uye tekil fiyatlarina gore bolunur; bkz bundleMemberAmounts).
   */
  anchorOriginalMinorUnitTr?: number;
  /** UI'da "Popüler" cercevesi/rozeti (pazarlama vurgusu). */
  popular?: boolean;
  /** UI'da "Amiral Gemisi/Premium" cercevesi/rozeti — en kapsamli paket (Tam Kapsamlı Pentest). */
  flagship?: boolean;
  /** true ise "Yakında" — listelenir ama satin ALINAMAZ (createBundleOrder reddeder). */
  comingSoon?: boolean;
  /**
   * true ise SABIT fiyat YOK; UI "Kuruma özel teklif / İletişime geçin" gosterir (self-servis DEGIL).
   * Yalniz VITRIN placeholder'i (uyesiz olabilir). comingSoon ile birlikte kullanilir.
   */
  contactOnly?: boolean;
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
    anchorOriginalMinorUnitTr: 569900, // 5.699 → 3.999 = %30 (pazarlama anchor)
    popular: true, // en genis giris paketi → "Popüler"
    memberKeys: ['ssl_tls', 'header_leak', 'dns_email', 'cors_cookie', 'csp_analiz'],
  },
  {
    key: 'bundle_recon',
    displayName: 'Keşif Paketi',
    displayNameEn: 'Discovery Bundle',
    description:
      'Dış saldırı yüzeyinizi haritalayan ve sahipsiz/ifşa olmuş varlıkları tespit eden derin keşif paketi.',
    descriptionEn:
      'A deep discovery bundle that maps your external attack surface and detects abandoned/exposed assets.',
    category: 'passive',
    discountPct: 20,
    finalPriceMinorUnitTr: 449900, // 4.499 TL (Vedat — nihai, yuvarlak)
    anchorOriginalMinorUnitTr: 529900, // 5.299 → 4.499 = %15 (pazarlama anchor)
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
    anchorOriginalMinorUnitTr: 999900, // 9.999 → 7.999 = %20 (pazarlama anchor)
    // Modul secimi KALDIRILDI — uyeler SABIT (uyum kontrolleri hep birlikte). KVKK yalniz TR.
    memberKeys: ['kvkk_hazirlik', 'pci_hazirlik', 'iso27001_hazirlik'],
    trOnlyKeys: ['kvkk_hazirlik'],
  },
  {
    key: 'bundle_active_verify',
    displayName: 'Aktif Doğrulama Paketi',
    displayNameEn: 'Active Verification Bundle',
    description:
      'Yedi aktif-hafif zafiyet doğrulama kontrolünün tümü tek pakette: Enjeksiyon, IDOR, SSRF, Dosya Yükleme, İş Mantığı, Race/Mass-Assignment ve RCE. Zafiyeti kanıtlar, istismar etmez; tek yetkilendirme beyanı yeterli. Tekil toplamdan belirgin indirimli. ' +
      'Kapsam: Bu paket kimlik doğrulaması gerektirmeyen (login olmadan test edilebilen) yüzeyde çalışır. Login sonrası ortaya çıkan derin yetkilendirme/iş mantığı zafiyetleri bu paketin kapsamı dışındadır; sonuçlar hedefin yapısına göre değişir.',
    descriptionEn:
      'All seven active-light verification checks in one bundle: Injection, IDOR, SSRF, File Upload, Business Logic, Race/Mass-Assignment and RCE. Proves presence, never exploits; a single authorization declaration covers all. Strongly discounted vs buying separately. ' +
      'Scope: this bundle tests the unauthenticated (no-login) surface. Deep authorization/business-logic vulnerabilities that only appear after login are out of scope; results depend on the target’s structure.',
    category: 'active-light',
    discountPct: 25,
    finalPriceMinorUnitTr: 999900,        // 9.999 TL (Vedat — indirildi; uye order tutarlari buna bolunur)
    anchorOriginalMinorUnitTr: 1299900,   // 12.999 TL (ustu cizili referans: 12.999 → 9.999 = %23)
    comingSoon: false,
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
      'Sağladığınız **TEST hesabıyla login sonrası derin, deterministik güvenlik taraması**: authenticated enjeksiyon/IDOR, yetki & oturum, client-side/JS, API (OWASP API Top 10), CORS & güvenlik başlıkları, TLS, yapılandırma ifşaları ve e-posta/DNS. **İstismar edilmez**; sonuçlar hedefin yüzeyine göre değişir.',
    descriptionEn:
      'A **deep, deterministic security scan after login** with a TEST account you provide: authenticated injection/IDOR, authorization & session, client-side/JS, API (OWASP API Top 10), CORS & security headers, TLS, configuration exposure and email/DNS. **No exploitation**; results vary with the target’s surface.',
    category: 'active-light',
    discountPct: 20,
    finalPriceMinorUnitTr: 2299900, // 22.999 TL (FAZ E — nihai sabit fiyat; üye order tutarları buna bölünür)
    comingSoon: false,              // (FAZ E) LANSMAN
    flagship: true,                 // amiral gemisi — premium çerçeve/rozet
    memberKeys: ['authenticated_scan', 'autonomous_pentest'],
  },
  {
    // (VITRIN — 7. kart) SADECE pazarlama placeholder'i: comingSoon (satin ALINAMAZ) + contactOnly
    // (sabit fiyat YOK -> "Kuruma özel teklif"). Arka plan mantigi/flow/odeme/scan motoru YOK; uyesiz.
    // Amac: ileride kurulacak premium, gercek-otonom-PentAGI, yetkili kurumsal hizmeti simdiden vitrine koymak.
    key: 'bundle_elite_autonomous',
    displayName: 'Elit Otonom Pentest (Kurumsal)',
    displayNameEn: 'Elite Autonomous Pentest (Enterprise)',
    description:
      'Sitenizin/uygulamanızın tüm güvenlik açıklarını, gerçek bir saldırgandan önce en derin ve kapsamlı şekilde tespit eder ve kanıtlarız — otonom yapay zekâ ajanı (PentAGI) tam kapasiteyle çalışır. ' +
      '**“Kanıtla, istismar etme” ilkesi:** açıklar kanıtlanır; verileriniz çekilmez, sisteminiz zarar görmez veya kesintiye uğratılmaz. ' +
      '**Yetkili, insan-onaylı** bir değerlendirmedir: kapsam ve yetkilendirme önceden birlikte belirlenir. ' +
      '**Fiyatlandırma:** kuruma özel teklif (self-servis değildir).',
    descriptionEn:
      'Finds and proves every security weakness across your site/application — the deepest, most comprehensive assessment, before a real attacker does; the autonomous AI agent (PentAGI) runs at full capacity. ' +
      '**“Prove, don’t exploit” principle:** weaknesses are proven; your data is never extracted and your system is never damaged or disrupted. ' +
      '**Authorized, human-approved** engagement: scope and authorization are agreed in advance. ' +
      '**Pricing:** custom enterprise quote (not self-service).',
    category: 'active-light',
    discountPct: 0,
    comingSoon: true,               // VITRIN — satin ALINAMAZ
    contactOnly: true,              // sabit fiyat yok -> "Kuruma özel teklif"
    memberKeys: [],                 // uyesiz vitrin karti (arka plan mantigi YOK)
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
  const singlesSum = prices.reduce((sum, p) => sum + p.amountMinorUnit, 0);
  const currency = prices[0]?.currency ?? getPricing('basit_tarama', region).currency;
  const amountMinorUnit =
    PRICE_OVERRIDE_MINOR != null
      ? PRICE_OVERRIDE_MINOR
      : region === 'tr' && bundle.finalPriceMinorUnitTr != null
      ? bundle.finalPriceMinorUnitTr
      : Math.round(singlesSum * (1 - bundle.discountPct / 100));
  // GOSTERILEN "orijinal" (ustu cizili): pazarlama anchor'i varsa O; yoksa uye tekil toplami.
  // Test override'da anchor da esitlenir -> sahte "%100 indirim" gorunmez.
  const originalMinorUnit =
    PRICE_OVERRIDE_MINOR != null
      ? PRICE_OVERRIDE_MINOR
      : region === 'tr' && bundle.anchorOriginalMinorUnitTr != null
      ? bundle.anchorOriginalMinorUnitTr
      : singlesSum;
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
  const { memberKeys, amountMinorUnit } = bundlePrice(bundle, region, selectedKeys);
  const singles = memberKeys.map((k) => getPricing(k, region).amountMinorUnit);
  // Dagitim tabani GERCEK uye tekil fiyatlari toplamidir (gosterim anchor'i DEGIL) — boylece
  // pazarlama anchor'i degisse bile uye tutarlari makul kalir; toplam nihai fiyata TAM boluner.
  const singlesSum = singles.reduce((s, x) => s + x, 0);
  const out: Array<{ key: string; amountMinorUnit: number }> = [];
  let assigned = 0;
  for (let i = 0; i < memberKeys.length; i++) {
    let share: number;
    if (i === memberKeys.length - 1) {
      share = amountMinorUnit - assigned; // son uye kalani alir → toplam TAM eslesir
    } else {
      share = singlesSum > 0
        ? Math.round((amountMinorUnit * singles[i]) / singlesSum)
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
