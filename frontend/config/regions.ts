/**
 * Çok-bölgeli (multi-region) yapılandırma. Yeni bölge eklemek = buraya tek bir
 * RegionConfig eklemek + i18n sözlüğünde dilini sağlamak. Kod tabanının hiçbir
 * yerinde `if (region === 'tr')` gibi dağınık kontrol OLMAMALI — her şey bu
 * config'ten okunur.
 *
 * DÜRÜSTLÜK: Bu altyapı TEKNİK bir hazırlıktır; bir bölgede gerçekten satışa
 * hazır olmak, o bölge için ayrı hukuki/vergi/ödeme çalışması gerektirir
 * (bkz HANDOFF.md → çok-bölge notu).
 */

export const REGION_CODES = ['tr', 'us', 'ae', 'de'] as const;
export type RegionCode = (typeof REGION_CODES)[number];

export const DEFAULT_REGION: RegionCode = 'tr';

export type Lang = 'tr' | 'en' | 'de';

export interface RegionConfig {
  code: RegionCode;
  label: string; // insan-okur bölge adı
  flag: string;
  locale: string; // Intl locale (para/tarih biçimi)
  lang: Lang; // hangi sözlük
  dir: 'ltr' | 'rtl'; // RTL (Arapça) için hazır; şimdilik hepsi ltr
  // Aşağıdakiler string: yeni bölge eklemek için TİP değiştirmek gerekmez —
  // yalnızca bu dosyaya bir RegionConfig eklemek yeterli (genişleyebilirlik).
  currency: string; // ISO 4217 (TRY/USD/AED/EUR…) — Intl ile biçimlenir
  paymentProvider: string; // backend factory bu ada göre seçer (fallback: iyzico)
  invoicingMethod: string; // backend factory (fallback: earsiv)
  supportEmail: string;
  companyLegalName: string;
  legalReady: boolean; // hukuki metinler bu bölge için hazır mı (tr: evet)
}

export const REGIONS: Record<RegionCode, RegionConfig> = {
  tr: {
    code: 'tr',
    label: 'Türkiye',
    flag: '🇹🇷',
    locale: 'tr-TR',
    lang: 'tr',
    dir: 'ltr',
    currency: 'TRY',
    paymentProvider: 'iyzico',
    invoicingMethod: 'earsiv',
    supportEmail: 'support@cybertestify.com',
    companyLegalName: 'CyberTestify',
    legalReady: true,
  },
  us: {
    code: 'us',
    label: 'United States',
    flag: '🇺🇸',
    locale: 'en-US',
    lang: 'en',
    dir: 'ltr',
    currency: 'USD',
    paymentProvider: 'stripe',
    invoicingMethod: 'us_receipt',
    supportEmail: 'support@cybertestify.com',
    companyLegalName: '[Legal Entity — US]',
    legalReady: false,
  },
  ae: {
    code: 'ae',
    label: 'United Arab Emirates',
    flag: '🇦🇪',
    locale: 'en-AE',
    lang: 'en',
    dir: 'ltr',
    currency: 'AED',
    paymentProvider: 'stripe',
    invoicingMethod: 'uae_vat',
    supportEmail: 'support@cybertestify.com',
    companyLegalName: '[Legal Entity — UAE]',
    legalReady: false,
  },
  // (Almanya lansmanı — FAZ 1) Altyapı hazır ama /de HENÜZ GÖRÜNMEZ (VISIBLE_REGION_CODES'a
  // eklenmedi) — site %100 Almanca olana kadar gerçek ziyaretçiye açılmaz (kabul kriteri: /de'de
  // Türkçe sızmasın). GEÇİCİ olarak lang:'en' → Almanca sözlük (DICTS.de) Faz 2'de yazılınca 'de'
  // olur; locale:'de-DE' şimdiden doğru → fiyat/sayı Alman formatında (€1.234,56). Ödeme: iyzico+EUR
  // (kullanıcı kararı). companyLegalName Impressum ile doldurulacak (kullanıcıdan gerçek bilgi).
  de: {
    code: 'de',
    label: 'Deutschland',
    flag: '🇩🇪',
    locale: 'de-DE',
    lang: 'de', // Almanca Dict hazır (i18n.ts DICTS.de) → site kabuğu/landing/paketler Almanca
    dir: 'ltr',
    currency: 'EUR',
    paymentProvider: 'iyzico', // kullanıcı kararı: /de → iyzico + EUR (Paddle/Stripe değil)
    invoicingMethod: 'de_vat',
    supportEmail: 'support@cybertestify.com',
    companyLegalName: '[Impressum — DE: kullanıcı sağlayacak]',
    legalReady: true, // Almanca yasal TASLAKLAR yayında (Impressum/Datenschutz/AGB/Widerruf) — avukat onayı önerilir
  },
};

export function isRegionCode(v: string | undefined | null): v is RegionCode {
  return !!v && (REGION_CODES as readonly string[]).includes(v);
}

// GÖRÜNÜR BÖLGELER: tr + de (Almanya lansmanı — 2026-08-24 public çıkış: site/checkout/rapor/
// e-posta uçtan uca Almanca, iyzico+EUR, Alman legal sayfaları hazır). us/ae config'i ve tüm
// çok-bölge altyapısı DURUYOR — görünürlük kapalı. Bölge açmak için: bu listeye ekle + ilgili
// REGIONS[...].legalReady'yi true yap. Kod SİLİNMEDİ.
export const VISIBLE_REGION_CODES: readonly RegionCode[] = ['tr', 'de'];
export function isVisibleRegion(v: string | undefined | null): v is RegionCode {
  return isRegionCode(v) && VISIBLE_REGION_CODES.includes(v);
}

export function getRegion(code: string | undefined | null): RegionConfig {
  return isRegionCode(code) ? REGIONS[code] : REGIONS[DEFAULT_REGION];
}
