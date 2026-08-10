/**
 * (Tam Kapsamlı Pentest — FAZ A) TEST hesabı kimlik bilgisi güvenli saklama/kullanma/silme.
 *
 * İlke: müşterinin verdiği test hesabı kimlik bilgisi DB'de PLAINTEXT DURMAZ. `encryptSecret`
 * (AES-256-GCM, sunucu pepper'ından türetilen anahtar; bkz crypto.ts) ile şifrelenir. Kullanım
 * ömrü KISA:
 *   - store:   sipariş oluşturulunca şifreli yazılır (TestCredential.ciphertext).
 *   - consume: orchestrator flow'a geçirmeden önce çözer + AYNI ANDA siler (ciphertext=null, purgedAt).
 *   - purge:   flow hiç başlamasa/patlasa bile 1 saatten eski tüm ciphertext'i null'layan güvenlik ağı.
 * Kimlik bilgisi ASLA loglanmaz (bkz credentialRedaction.ts + orchestrator).
 *
 * label: v1 yalnız 'primary' kullanır; 'secondary' ileride cross-account IDOR için (mimari kapalı değil).
 */
import { prisma } from '../db.js';
import { encryptSecret, decryptSecret } from './crypto.js';

export type TestCredentialInput = { username: string; password: string };
export type CredentialLabel = 'primary' | 'secondary';

// Kimlik bilgisinin ne kadar süre şifreli kalabileceği üst sınırı (flow başlamasa bile purge edilir).
export const CREDENTIAL_MAX_AGE_MS = 60 * 60 * 1000; // 1 saat

/** Sipariş için şifreli test kimlik bilgisi yaz (varsa üzerine yaz — idempotent upsert). */
export async function storeTestCredential(
  orderId: string,
  creds: TestCredentialInput,
  label: CredentialLabel = 'primary',
): Promise<void> {
  const ciphertext = encryptSecret(JSON.stringify(creds));
  await prisma.testCredential.upsert({
    where: { orderId_label: { orderId, label } },
    update: { ciphertext, purgedAt: null, createdAt: new Date() },
    create: { orderId, label, ciphertext },
  });
}

/**
 * Kimlik bilgisini ÇÖZ ve AYNI ANDA SİL (tek kullanım). Yoksa/zaten silinmişse null.
 * Çözme başarısız olursa da ciphertext temizlenir (kalıntı bırakma).
 */
export async function consumeTestCredential(
  orderId: string,
  label: CredentialLabel = 'primary',
): Promise<TestCredentialInput | null> {
  const row = await prisma.testCredential.findUnique({ where: { orderId_label: { orderId, label } } });
  if (!row || !row.ciphertext) return null;
  let creds: TestCredentialInput | null = null;
  try {
    creds = JSON.parse(decryptSecret(row.ciphertext)) as TestCredentialInput;
  } catch {
    creds = null;
  }
  // Her durumda ciphertext'i sil (kullanıldı ya da çözülemedi — plaintext kaynağı kalmasın).
  await prisma.testCredential.update({ where: { id: row.id }, data: { ciphertext: null, purgedAt: new Date() } });
  return creds;
}

/** Bir siparişin var olan test kimlik bilgisi etiketleri (şifre GÖSTERMEDEN — yalnız varlık bilgisi). */
export async function hasTestCredential(orderId: string, label: CredentialLabel = 'primary'): Promise<boolean> {
  const row = await prisma.testCredential.findUnique({
    where: { orderId_label: { orderId, label } },
    select: { ciphertext: true },
  });
  return !!row?.ciphertext;
}

/**
 * PURGE GÜVENLİK AĞI: CREDENTIAL_MAX_AGE_MS'ten eski, hâlâ ciphertext taşıyan tüm kayıtları null'la.
 * Flow hiç başlamasa/patlasa bile kimlik bilgisi kalıcı kalmasın. Silinen kayıt sayısını döndürür.
 */
export async function purgeExpiredCredentials(now: Date = new Date()): Promise<number> {
  const cutoff = new Date(now.getTime() - CREDENTIAL_MAX_AGE_MS);
  const res = await prisma.testCredential.updateMany({
    where: { ciphertext: { not: null }, createdAt: { lt: cutoff } },
    data: { ciphertext: null, purgedAt: now },
  });
  if (res.count > 0) console.log(`[worker] ${res.count} adet süresi dolmuş test kimlik bilgisi temizlendi (ciphertext null).`);
  return res.count;
}
