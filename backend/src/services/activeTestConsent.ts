import { prisma } from '../db.js';

/**
 * (Faz 3) Active-light paketler icin ZORUNLU yetkilendirme/onay mekanizmasi.
 *
 * Active-light tarama, zafiyeti DOGRULAMAK icin sinirli/zararsiz AKTIF test istekleri
 * gonderir (bkz securityProfile). Bu, pasif taramanin otesinde ek bir yasal riziko
 * tasidigindan, siparis oncesi AYRI bir onay beyani ZORUNLUDUR: yasal ad + risk kabul.
 *
 * Metin VERSIYONLU tutulur (ileride degisebilir; hangi versiyonun kabul edildigi
 * ispat icin kaydedilir). Beyan elektronik imza YERINE gecer — kriptografik e-imza DEGIL.
 */

export const ACTIVE_TEST_CONSENT_VERSION = '2026-08-03';

// Risk kabul checkbox metni (SADE — Faz 3 v2).
export const ACTIVE_TEST_RISK_ACK =
  'Bu paketin aktif / kanıt-amaçlı test unsurları içerdiğini okudum, anladım ve riski kabul ediyorum; ' +
  'taramaya konu alan adının sahibi/yetkilisi olduğumu beyan ederim.';

export interface ActiveTestScope {
  does: string[];
  doesNot: string[];
}

// Paket-bazli "ne yapar / ne YAPMAZ" — hem UI hem onay PDF'inde gosterilir.
const SCOPE: Record<string, ActiveTestScope> = {
  injection_verify: {
    does: [
      'Herkese açık giriş noktalarını (form alanları, URL parametreleri) tespit eder.',
      'Her birine ZARARSIZ, standart, KANIT-amaçlı test payload’ları gönderir (ör. tek tırnak, basit script etiketi).',
      'Zafiyetin YALNIZCA varlığını hata mesajı / zaman farkı / payload yansıması gibi kanıtlarla raporlar.',
    ],
    doesNot: [
      'Gerçek veri ÇEKMEZ — veritabanı içeriğini dökmez/enumerate etmez (sqlmap yalnız tespit modunda).',
      'Veri SİLMEZ / DEĞİŞTİRMEZ, kayıt oluşturmaz.',
      'Kimlik doğrulamayı bypass etmeyi denemez, oturum çalmaz.',
      'Yük/DoS/flood üretmez.',
    ],
  },
  idor_verify: {
    does: [
      'Tahmin edilebilir kaynak kimlikleri (ör. /api/user/123) olup olmadığını tespit eder.',
      'Kimliği değiştirip erişim davranışının değişip değişmediğini (yetkisiz erişim izi) doğrular.',
      'Yalnızca “bu uç yetkisiz erişime açık görünüyor” gözlemini raporlar.',
    ],
    doesNot: [
      'Erişilen gerçek/hassas veriyi RAPORA YAZMAZ, göstermez, saklamaz.',
      'Veri DEĞİŞTİRMEZ / SİLMEZ.',
      'Kimlik doğrulamayı bypass etmeyi denemez.',
      'Toplu veri çekme / dışa aktarma yapmaz.',
    ],
  },
};

const DEFAULT_SCOPE: ActiveTestScope = {
  does: ['Zafiyetin VARLIĞINI doğrulamak için sınırlı, zararsız aktif test istekleri gönderir.'],
  doesNot: ['Gerçek veri çekmez, veri silmez/değiştirmez, kimlik doğrulama bypass denemez, DoS üretmez.'],
};

export function activeTestScope(packageKey: string): ActiveTestScope {
  return SCOPE[packageKey] ?? DEFAULT_SCOPE;
}

export interface ActiveTestConsentInput {
  riskAccepted?: boolean;
}

// SADELESTIRILMIS (Faz 3 v2): tek checkbox yeterli. Ek alan (yasal ad/sirket) YOK; beyan
// eden hesaptan (fullName/email) OTOMATIK doldurulur. Tamlik kontrolu = risk kutusu isaretli mi.
export function validateConsentInput(input: ActiveTestConsentInput | undefined): { ok: true } | { ok: false; error: string } {
  if (!input || input.riskAccepted !== true) {
    return { ok: false, error: 'Aktif test için risk kabul kutusunu işaretlemelisiniz.' };
  }
  return { ok: true };
}

// active-light siparisin gecerli bir consent kaydi VAR mi? (guard — defense-in-depth)
export async function hasValidActiveTestConsent(orderId: string): Promise<boolean> {
  const c = await prisma.activeTestConsent.findUnique({ where: { orderId } });
  return !!c && c.riskAccepted === true;
}
