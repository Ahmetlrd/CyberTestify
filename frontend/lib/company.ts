/**
 * Marka/iletisim bilgileri. Footer, hukuki sayfalar ve checkout sozlesmeleri buradan okur.
 *
 * NOT: Tuzel kisilik kimlik alanlari (unvan, adres, MERSIS, vergi no, ticaret sicil, telefon,
 * KEP) siteden kaldirilmistir — musteri istegi (2026-08-12). Bu alanlar client bundle'ina
 * sizmamasi icin objeden de cikarilmistir. Yalniz marka adi + destek e-postasi kalir.
 * (Mesafeli satis/on bilgilendirme icin saticinin tanitici bilgi yukumlulugu bilinerek
 * atlanmistir; iyzico/mevzuat teyidi musterinin sorumlulugundadir.)
 */
export const COMPANY = {
  brand: 'CyberTestify',
  domain: 'cybertestify.com',
  email: 'support@cybertestify.com',
  // Hukuki metinlerin surumu — backend config.legalVersion ile ayni tutulmali.
  legalVersion: '2026-08-03',
  lastUpdated: '12.08.2026',
};
