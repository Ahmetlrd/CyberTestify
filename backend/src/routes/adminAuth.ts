import { Router, type Request } from 'express';
import { z } from 'zod';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { prisma } from '../db.js';
import { config } from '../config.js';
import {
  newTotpSecret, totpKeyUri, qrDataUrl, verifyTotp, encryptForStore, decryptFromStore,
  generateRecoveryCodes, consumeRecoveryCode, isLocked, nextLockState,
} from '../services/twofa.js';

// Admin giris — MUSTERI auth'undan AYRI. REGISTER ENDPOINT'I YOK: admin yalnizca
// CLI/DB ile eklenir (prisma/createAdmin.ts). Herkese acik "admin ol" formu yok.
//
// (2FA — ZORUNLU) Admin girisi iki adimli: (1) mail+sifre → stage token, (2) TOTP kodu → tam token.
// 2FA hic kurulmamissa ilk adim 'enroll' stage token verir; admin QR okutup onaylayinca
// kurtarma kodlari + tam token alir. Telefon+kurtarma kaybinda SUNUCU-TARAFI sifirlama:
// `npx tsx prisma/resetAdmin2fa.ts <email>` (panelden DEGIL — bkz o dosyanin basi).
export const adminAuthRouter = Router();

const loginSchema = z.object({ email: z.string().email(), password: z.string().min(8) });
const STAGE_TTL = '10m';

type StagePayload = { sub: string; typ: 'admin-2fa'; stage: 'verify' | 'enroll' };
function signStage(sub: string, stage: 'verify' | 'enroll'): string {
  return jwt.sign({ sub, typ: 'admin-2fa', stage } satisfies StagePayload, config.adminJwtSecret, { expiresIn: STAGE_TTL });
}
function signFull(sub: string): string {
  return jwt.sign({ sub, typ: 'admin' }, config.adminJwtSecret, { expiresIn: '12h' });
}
// Enrollment endpoint'leri: enroll-stage token VEYA tam admin token kabul eder.
function adminIdFromHeader(req: Request, allowStages: Array<'verify' | 'enroll'>): { id: string; viaStage: boolean } | null {
  const h = req.headers.authorization;
  if (!h?.startsWith('Bearer ')) return null;
  try {
    const p = jwt.verify(h.slice(7), config.adminJwtSecret) as { sub: string; typ?: string; stage?: string };
    if (p.typ === 'admin') return { id: p.sub, viaStage: false };
    if (p.typ === 'admin-2fa' && p.stage && allowStages.includes(p.stage as 'verify' | 'enroll')) return { id: p.sub, viaStage: true };
    return null;
  } catch { return null; }
}

// ——— Adim 1: mail + sifre ———
adminAuthRouter.post('/login', async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Gecersiz giris bilgisi.' });

  const admin = await prisma.adminUser.findUnique({ where: { email: parsed.data.email } });
  // Sabit-zaman benzeri davranis: kullanici yoksa da bcrypt.compare calistir.
  const ok = admin
    ? await bcrypt.compare(parsed.data.password, admin.passwordHash)
    : await bcrypt.compare(parsed.data.password, '$2a$12$0000000000000000000000000000000000000000000000000000');
  if (!admin || !ok) return res.status(401).json({ error: 'E-posta veya sifre hatali.' });

  // (2FA ZORUNLU) Sifre dogru → 2. faktore gec. Tam token BURADA verilmez.
  if (admin.twofaEnabled) return res.json({ twofaRequired: true, stageToken: signStage(admin.id, 'verify') });
  // Henuz 2FA kurmamis → zorunlu enrollment stage'ine yonlendir.
  return res.json({ enrollmentRequired: true, stageToken: signStage(admin.id, 'enroll') });
});

// ——— Adim 2: TOTP (veya kurtarma) kodu → tam token ———
const verifySchema = z.object({ stageToken: z.string(), code: z.string().min(6).max(20) });
adminAuthRouter.post('/login/2fa', async (req, res) => {
  const parsed = verifySchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Gecersiz istek.' });
  let sub: string;
  try {
    const p = jwt.verify(parsed.data.stageToken, config.adminJwtSecret) as StagePayload;
    if (p.typ !== 'admin-2fa' || p.stage !== 'verify') throw new Error('stage');
    sub = p.sub;
  } catch { return res.status(401).json({ error: 'Oturum suresi doldu; tekrar giris yapin.' }); }

  const admin = await prisma.adminUser.findUnique({ where: { id: sub } });
  if (!admin || !admin.twofaEnabled || !admin.totpSecret) return res.status(401).json({ error: 'Gecersiz oturum.' });
  if (isLocked(admin.twofaLockedUntil)) return res.status(429).json({ error: 'Cok fazla hatali kod. Lutfen birkac dakika sonra tekrar deneyin.' });

  const code = parsed.data.code.trim();
  const secret = decryptFromStore(admin.totpSecret);
  let pass = verifyTotp(secret, code);
  let recoveryBlob: string | undefined;
  if (!pass) {
    const rc = consumeRecoveryCode(admin.twofaRecoveryCodes, code);
    if (rc.ok) { pass = true; recoveryBlob = rc.newBlob; }
  }
  if (!pass) {
    const ls = nextLockState(admin.twofaFailedAttempts);
    await prisma.adminUser.update({ where: { id: admin.id }, data: { twofaFailedAttempts: ls.failed, twofaLockedUntil: ls.lockedUntil } });
    return res.status(401).json({ error: ls.lockedUntil ? 'Cok fazla hatali kod; hesap gecici olarak kilitlendi.' : 'Kod hatali.' });
  }
  await prisma.adminUser.update({
    where: { id: admin.id },
    data: { twofaFailedAttempts: 0, twofaLockedUntil: null, lastLoginAt: new Date(), ...(recoveryBlob ? { twofaRecoveryCodes: recoveryBlob } : {}) },
  });
  res.json({ token: signFull(admin.id), email: admin.email });
});

// ——— Enrollment: QR + manuel anahtar üret (pending secret sakla) ———
adminAuthRouter.get('/2fa/setup', async (req, res) => {
  const who = adminIdFromHeader(req, ['enroll']);
  if (!who) return res.status(401).json({ error: 'Yetkisiz.' });
  const admin = await prisma.adminUser.findUnique({ where: { id: who.id } });
  if (!admin) return res.status(401).json({ error: 'Yetkisiz.' });
  const secret = newTotpSecret();
  await prisma.adminUser.update({ where: { id: admin.id }, data: { totpSecret: encryptForStore(secret) } }); // pending (twofaEnabled hala false)
  const uri = totpKeyUri(admin.email, secret);
  res.json({ otpauthUri: uri, qrDataUrl: await qrDataUrl(uri), manualKey: secret });
});

// ——— Enrollment onay: kod dogrula → 2FA aktif + kurtarma kodlari + tam token ———
const enableSchema = z.object({ code: z.string().length(6) });
adminAuthRouter.post('/2fa/enable', async (req, res) => {
  const who = adminIdFromHeader(req, ['enroll']);
  if (!who) return res.status(401).json({ error: 'Yetkisiz.' });
  const parsed = enableSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Kod 6 haneli olmali.' });
  const admin = await prisma.adminUser.findUnique({ where: { id: who.id } });
  if (!admin || !admin.totpSecret) return res.status(400).json({ error: 'Once QR olusturun (setup).' });
  if (admin.twofaEnabled) return res.status(400).json({ error: '2FA zaten etkin.' });
  if (!verifyTotp(decryptFromStore(admin.totpSecret), parsed.data.code)) return res.status(401).json({ error: 'Kod hatali; authenticator uygulamanizdaki 6 haneli kodu girin.' });

  const rec = generateRecoveryCodes();
  await prisma.adminUser.update({
    where: { id: admin.id },
    data: { twofaEnabled: true, twofaConfirmedAt: new Date(), twofaRecoveryCodes: rec.encryptedBlob, twofaFailedAttempts: 0, twofaLockedUntil: null, lastLoginAt: new Date() },
  });
  // Enrollment enroll-stage ile yapildi → kullaniciya tam oturum ver (tekrar giris istemeden).
  res.json({ token: signFull(admin.id), email: admin.email, recoveryCodes: rec.plain });
});
