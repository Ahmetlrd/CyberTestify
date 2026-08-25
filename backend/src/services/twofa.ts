/**
 * (2FA — TOTP çekirdeği, RFC 6238) Ücretsiz, açık standart. otplib (v12) + qrcode.
 * SMS/ücretli sağlayıcı YOK. TOTP secret + recovery kodları at-rest ŞİFRELİ (encryptSecret,
 * AES-256-GCM); recovery kodları ayrıca SHA-256 HASH'li (düz kod DB'de asla durmaz).
 * Admin'de ZORUNLU, müşteride OPT-IN — bu modül ortak çekirdektir (rota-bağımsız).
 */
import { authenticator } from 'otplib';
import QRCode from 'qrcode';
import crypto from 'node:crypto';
import { encryptSecret, decryptSecret } from './crypto.js';

// Kod doğrulamada ±1 zaman-adımı (saat kayması toleransı) — güvenli, yaygın değer.
authenticator.options = { window: 1 };

const ISSUER = 'CyberTestify';

// Brute-force: ard arda N yanlış kodda geçici kilit.
export const TWOFA_MAX_FAILED = 5;
export const TWOFA_LOCK_MS = 15 * 60 * 1000; // 15 dk
export const RECOVERY_CODE_COUNT = 10;

export type StoredRecovery = { h: string; used: boolean };

/** Yeni base32 TOTP secret (düz — saklamadan ÖNCE encryptForStore ile şifrelenmeli). */
export function newTotpSecret(): string {
  return authenticator.generateSecret();
}

/** otpauth:// URI — authenticator app'in QR/manuel-anahtar kurulumu için. */
export function totpKeyUri(accountLabel: string, secret: string): string {
  return authenticator.keyuri(accountLabel, ISSUER, secret);
}

/** QR'ı PNG data-URL olarak üret (enrollment ekranında <img src>). */
export function qrDataUrl(otpauthUri: string): Promise<string> {
  return QRCode.toDataURL(otpauthUri, { margin: 1, width: 220 });
}

/** 6 haneli TOTP kodunu doğrula (±1 pencere). secret DÜZ metin (çağıran çözer). */
export function verifyTotp(secret: string, token: string): boolean {
  const t = (token ?? '').replace(/\s+/g, '');
  if (!/^\d{6}$/.test(t)) return false;
  try { return authenticator.verify({ token: t, secret }); } catch { return false; }
}

// ——— At-rest şifreleme sarmalayıcıları (secret) ———
export const encryptForStore = (plain: string): string => encryptSecret(plain);
export const decryptFromStore = (blob: string): string => decryptSecret(blob);

// ——— Kurtarma (recovery) kodları ———
const hashCode = (code: string): string =>
  crypto.createHash('sha256').update(code.replace(/[\s-]/g, '').toLowerCase()).digest('hex');

/** N tek-kullanımlık kurtarma kodu üret. Döner: kullanıcıya BİR KEZ gösterilecek düz kodlar +
 *  DB'ye yazılacak ŞİFRELİ (hash'li) blob. Düz kodlar asla saklanmaz. */
export function generateRecoveryCodes(): { plain: string[]; encryptedBlob: string } {
  const plain: string[] = [];
  for (let i = 0; i < RECOVERY_CODE_COUNT; i++) {
    const raw = crypto.randomBytes(5).toString('hex'); // 10 hex
    plain.push(`${raw.slice(0, 5)}-${raw.slice(5)}`);
  }
  const stored: StoredRecovery[] = plain.map((c) => ({ h: hashCode(c), used: false }));
  return { plain, encryptedBlob: encryptSecret(JSON.stringify(stored)) };
}

/** Kurtarma kodunu doğrula + TÜKET (tek kullanım). Döner: eşleşti mi + güncel blob (kullanıldı işaretli). */
export function consumeRecoveryCode(encryptedBlob: string | null, code: string): { ok: boolean; newBlob?: string } {
  if (!encryptedBlob) return { ok: false };
  let stored: StoredRecovery[];
  try { stored = JSON.parse(decryptSecret(encryptedBlob)) as StoredRecovery[]; } catch { return { ok: false }; }
  const h = hashCode(code);
  const idx = stored.findIndex((s) => s.h === h && !s.used);
  if (idx === -1) return { ok: false };
  stored[idx].used = true;
  return { ok: true, newBlob: encryptSecret(JSON.stringify(stored)) };
}

/** Kalan (kullanılmamış) kurtarma kodu sayısı — kullanıcıya "N kod kaldı" göstermek için. */
export function remainingRecoveryCount(encryptedBlob: string | null): number {
  if (!encryptedBlob) return 0;
  try { return (JSON.parse(decryptSecret(encryptedBlob)) as StoredRecovery[]).filter((s) => !s.used).length; } catch { return 0; }
}

// ——— Brute-force kilidi ———
export const isLocked = (lockedUntil: Date | null): boolean => !!lockedUntil && lockedUntil.getTime() > Date.now();
/** Yanlış koddan sonraki kilit durumunu hesapla (çağıran DB'ye yazar). */
export function nextLockState(currentFailed: number): { failed: number; lockedUntil: Date | null } {
  const failed = currentFailed + 1;
  return failed >= TWOFA_MAX_FAILED ? { failed: 0, lockedUntil: new Date(Date.now() + TWOFA_LOCK_MS) } : { failed, lockedUntil: null };
}
