/**
 * Isletme/sirket bilgileri. Footer imprint, hukuki sayfalar ve checkout sozlesmeleri
 * buradan okur. Resmi belgelerle (Ticaret Sicil, Mersis, Vergi Dairesi) BIREBIR uyumlu
 * olmalidir — 6563 s. Kanun ve TKHK geregi sitede zorunludur (iyzico basvurusu da bekler).
 *
 * Teyit: 2026-08-03 (Vedat onayladi).
 */
export const COMPANY = {
  brand: 'CyberTestify',
  domain: 'cybertestify.com',
  legalName: 'Entar6 Enerji ve Tarım Sanayi ve Ticaret Limited Şirketi',
  mersisNo: '0336057157700015',
  taxOffice: 'Gevhernesibe',
  taxNo: '3360571577',
  ticaretSicilNo: '42498',
  address: 'Sahabiye Mah. Prof. Fevzi Fevzioğlu Cd. No:19 Kocasinan / Kayseri',
  phone: '0352 222 22 21',
  email: 'support@cybertestify.com',
  kep: '', // KEP adresi alininca doldurulacak (bos ise footer'da gosterilmez).
  // ETBIS kaydindan sonra alinan dogrulama karekodu footer'a eklenecek (zorunlu).
  etbisRegistered: false,
  // Hukuki metinlerin surumu — backend config.legalVersion ile ayni tutulmali.
  legalVersion: '2026-08-03',
  lastUpdated: '03.08.2026',
};
