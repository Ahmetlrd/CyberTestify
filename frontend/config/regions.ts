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

export const REGION_CODES = ['tr', 'us', 'ae'] as const;
export type RegionCode = (typeof REGION_CODES)[number];

export const DEFAULT_REGION: RegionCode = 'tr';

export type Lang = 'tr' | 'en';

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
    supportEmail: 'destek@cybertestify.com',
    companyLegalName: '[Ticari Unvan — TR]',
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
};

export function isRegionCode(v: string | undefined | null): v is RegionCode {
  return !!v && (REGION_CODES as readonly string[]).includes(v);
}

export function getRegion(code: string | undefined | null): RegionConfig {
  return isRegionCode(code) ? REGIONS[code] : REGIONS[DEFAULT_REGION];
}
