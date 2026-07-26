/**
 * Isletme/sirket bilgileri. ETBIS, footer imprint ve hukuki sayfalar buradan
 * okur. Sirket (sahis/limited) kurulunca placeholder'lar GERCEK degerlerle
 * doldurulmali — 6563 s. Kanun ve TKHK geregi bu bilgiler sitede zorunludur.
 */
export const COMPANY = {
  brand: 'CyberTestify',
  domain: 'cybertestify.com',
  legalName: '[Ticari Unvan — sirket kurulunca doldurun]',
  mersisNo: '[MERSIS No]',
  taxOffice: '[Vergi Dairesi]',
  taxNo: '[Vergi Kimlik No]',
  address: '[Acik Adres]',
  phone: '[Telefon]',
  email: 'destek@cybertestify.com',
  kep: '[KEP Adresi]',
  // ETBIS kaydindan sonra alinan dogrulama karekodu footer'a eklenecek (zorunlu).
  etbisRegistered: false,
  // Hukuki metinlerin surumu — backend config.legalVersion ile ayni tutulmali.
  legalVersion: '2026-07-26',
  lastUpdated: '26.07.2026',
};
