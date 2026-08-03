import crypto from 'node:crypto';
import { config } from '../config.js';

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

/**
 * (Faz 3 — authenticated_scan) Sunucu-anahtarli gizli sifreleme: test hesabi kimlik
 * bilgileri (kullanici/sifre) DB'de PLAINTEXT durmasin. Anahtar sunucu pepper'indan
 * turetilir (REPORT_ENCRYPTION_PEPPER). Kullanim omru KISA: flow'a gecirilip HEMEN silinir,
 * asla loglanmaz. base64(iv|tag|ciphertext) doner.
 */
function secretKey(): Buffer {
  return crypto.scryptSync(config.reportEncryptionPepper, 'cred-enc-v1', SCRYPT_KEYLEN);
}

export function encryptSecret(plaintext: string): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', secretKey(), iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ct]).toString('base64');
}

export function decryptSecret(blob: string): string {
  const b = Buffer.from(blob, 'base64');
  const iv = b.subarray(0, 12), tag = b.subarray(12, 28), ct = b.subarray(28);
  const d = crypto.createDecipheriv('aes-256-gcm', secretKey(), iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]).toString('utf8');
}

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
