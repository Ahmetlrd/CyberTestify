import crypto from 'node:crypto';

/**
 * Rapor sifreleme yardimcilari.
 *
 * Tasarim: her rapor, o musteriye ozel, sadece bir kez gosterilen bir
 * parola/anahtardan turetilen bir AES-256-GCM anahtariyla sifrelenir.
 * Anahtarin kendisi bizim veritabanimizda TUTULMAZ — sadece sifreli blob,
 * IV, authTag ve tuz (salt) tutulur. Boylece kendi DB admin'imiz bile
 * musterinin raporunu goremez; "arka plandaki anahtar her seye hakim"
 * sorununu kendi tarafimizda tekrarlamamis oluyoruz.
 */

const SCRYPT_KEYLEN = 32; // AES-256

export function generateReportAccessSecret(): string {
  // Musteriye e-posta ile (rapor linkinden AYRI bir kanaldan) gonderilecek,
  // tek seferlik goruntulenen erisim parolasi.
  return crypto.randomBytes(24).toString('base64url');
}

export function encryptReport(plaintext: Buffer, accessSecret: string) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(accessSecret, salt, SCRYPT_KEYLEN);
  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return { encryptedBlob: encrypted, iv, authTag, keyDerivationSalt: salt };
}

export function decryptReport(params: {
  encryptedBlob: Buffer;
  iv: Buffer;
  authTag: Buffer;
  keyDerivationSalt: Buffer;
  accessSecret: string;
}): Buffer {
  const key = crypto.scryptSync(params.accessSecret, params.keyDerivationSalt, SCRYPT_KEYLEN);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, params.iv);
  decipher.setAuthTag(params.authTag);
  return Buffer.concat([decipher.update(params.encryptedBlob), decipher.final()]);
}
