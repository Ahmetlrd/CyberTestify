/**
 * (2FA — Müşteri tarafı, OPT-IN) Login 2. adımı + hesap ayarları (etkinleştir/kapat) + nudge.
 * Tüm kullanıcıya-görünen mesajlar M(loc, tr, de, en) ile üç dilde. TOTP secret + recovery
 * kodları at-rest şifreli (twofa.ts). 2FA'sız müşteri hiç etkilenmez (regresyonsuz).
 */
import { Router, type Request } from 'express';
import { z } from 'zod';
import jwt from 'jsonwebtoken';
import { prisma } from '../db.js';
import { config } from '../config.js';
import { requireAuth } from '../middleware/auth.js';
import {
  newTotpSecret, totpKeyUri, qrDataUrl, verifyTotp, encryptForStore, decryptFromStore,
  generateRecoveryCodes, consumeRecoveryCode, remainingRecoveryCount, isLocked, nextLockState,
} from '../services/twofa.js';

export const twofaRouter = Router();

const loc = (req: Request): string => { const r = typeof (req.body as any)?.region === 'string' ? (req.body as any).region : (req.query.region as string) || 'tr'; return r === 'de' ? 'de' : r === 'en' ? 'en' : 'tr'; };
const M = (l: string, tr: string, de: string, en: string): string => (l === 'de' ? de : l === 'en' ? en : tr);
const NUDGE_REMIND_MS = 3 * 24 * 60 * 60 * 1000; // "sonra hatirlat" → 3 gun

// ——— Login 2. adım: stage token + kod → tam müşteri token'ı ———
const verifySchema = z.object({ stageToken: z.string(), code: z.string().min(6).max(20), region: z.string().optional() });
twofaRouter.post('/login-verify', async (req, res) => {
  const l = loc(req);
  const parsed = verifySchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: M(l, 'Geçersiz istek.', 'Ungültige Anfrage.', 'Invalid request.') });
  let sub: string;
  try {
    const p = jwt.verify(parsed.data.stageToken, config.jwtSecret) as { sub: string; typ?: string };
    if (p.typ !== 'cust-2fa') throw new Error('typ');
    sub = p.sub;
  } catch { return res.status(401).json({ error: M(l, 'Oturum süresi doldu; tekrar giriş yapın.', 'Sitzung abgelaufen; bitte erneut anmelden.', 'Session expired; please log in again.') }); }

  const c = await prisma.customer.findUnique({ where: { id: sub } });
  if (!c || !c.twofaEnabled || !c.totpSecret) return res.status(401).json({ error: M(l, 'Geçersiz oturum.', 'Ungültige Sitzung.', 'Invalid session.') });
  if (isLocked(c.twofaLockedUntil)) return res.status(429).json({ error: M(l, 'Çok fazla hatalı kod. Lütfen birkaç dakika sonra tekrar deneyin.', 'Zu viele falsche Codes. Bitte versuchen Sie es in einigen Minuten erneut.', 'Too many incorrect codes. Please try again in a few minutes.') });

  const code = parsed.data.code.trim();
  let pass = verifyTotp(decryptFromStore(c.totpSecret), code);
  let recoveryBlob: string | undefined;
  if (!pass) { const rc = consumeRecoveryCode(c.twofaRecoveryCodes, code); if (rc.ok) { pass = true; recoveryBlob = rc.newBlob; } }
  if (!pass) {
    const ls = nextLockState(c.twofaFailedAttempts);
    await prisma.customer.update({ where: { id: c.id }, data: { twofaFailedAttempts: ls.failed, twofaLockedUntil: ls.lockedUntil } });
    return res.status(401).json({ error: ls.lockedUntil ? M(l, 'Çok fazla hatalı kod; hesap geçici olarak kilitlendi.', 'Zu viele falsche Codes; Konto vorübergehend gesperrt.', 'Too many incorrect codes; account temporarily locked.') : M(l, 'Kod hatalı.', 'Code ist falsch.', 'The code is incorrect.') });
  }
  await prisma.customer.update({ where: { id: c.id }, data: { twofaFailedAttempts: 0, twofaLockedUntil: null, ...(recoveryBlob ? { twofaRecoveryCodes: recoveryBlob } : {}) } });
  res.json({ token: jwt.sign({ sub: c.id }, config.jwtSecret, { expiresIn: '7d' }) });
});

// ——— Durum ———
twofaRouter.get('/status', requireAuth, async (req, res) => {
  const c = await prisma.customer.findUnique({ where: { id: req.customerId! } });
  if (!c) return res.status(404).json({ error: 'not found' });
  res.json({ enabled: c.twofaEnabled, remainingRecoveryCodes: c.twofaEnabled ? remainingRecoveryCount(c.twofaRecoveryCodes) : 0 });
});

// ——— Etkinleştirme adım 1: QR + manuel anahtar ———
twofaRouter.post('/setup', requireAuth, async (req, res) => {
  const l = loc(req);
  const c = await prisma.customer.findUnique({ where: { id: req.customerId! } });
  if (!c) return res.status(404).json({ error: 'not found' });
  if (c.twofaEnabled) return res.status(400).json({ error: M(l, '2FA zaten etkin.', '2FA ist bereits aktiv.', '2FA is already enabled.') });
  const secret = newTotpSecret();
  await prisma.customer.update({ where: { id: c.id }, data: { totpSecret: encryptForStore(secret) } }); // pending
  const uri = totpKeyUri(c.email, secret);
  res.json({ otpauthUri: uri, qrDataUrl: await qrDataUrl(uri), manualKey: secret });
});

// ——— Etkinleştirme adım 2: kod doğrula → aktif + kurtarma kodları ———
const codeSchema = z.object({ code: z.string().length(6), region: z.string().optional() });
twofaRouter.post('/enable', requireAuth, async (req, res) => {
  const l = loc(req);
  const parsed = codeSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: M(l, 'Kod 6 haneli olmalı.', 'Der Code muss 6-stellig sein.', 'The code must be 6 digits.') });
  const c = await prisma.customer.findUnique({ where: { id: req.customerId! } });
  if (!c || !c.totpSecret) return res.status(400).json({ error: M(l, 'Önce QR oluşturun.', 'Erstellen Sie zuerst den QR-Code.', 'Generate the QR code first.') });
  if (c.twofaEnabled) return res.status(400).json({ error: M(l, '2FA zaten etkin.', '2FA ist bereits aktiv.', '2FA is already enabled.') });
  if (!verifyTotp(decryptFromStore(c.totpSecret), parsed.data.code)) return res.status(401).json({ error: M(l, 'Kod hatalı; authenticator uygulamanızdaki 6 haneli kodu girin.', 'Code ist falsch; geben Sie den 6-stelligen Code aus Ihrer Authenticator-App ein.', 'The code is incorrect; enter the 6-digit code from your authenticator app.') });
  const rec = generateRecoveryCodes();
  await prisma.customer.update({ where: { id: c.id }, data: { twofaEnabled: true, twofaConfirmedAt: new Date(), twofaRecoveryCodes: rec.encryptedBlob, twofaFailedAttempts: 0, twofaLockedUntil: null } });
  res.json({ enabled: true, recoveryCodes: rec.plain });
});

// ——— Kapatma: mevcut kod (TOTP veya kurtarma) doğrula → kapat ———
twofaRouter.post('/disable', requireAuth, async (req, res) => {
  const l = loc(req);
  const parsed = z.object({ code: z.string().min(6).max(20), region: z.string().optional() }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: M(l, 'Geçersiz kod.', 'Ungültiger Code.', 'Invalid code.') });
  const c = await prisma.customer.findUnique({ where: { id: req.customerId! } });
  if (!c || !c.twofaEnabled || !c.totpSecret) return res.status(400).json({ error: M(l, '2FA zaten kapalı.', '2FA ist bereits deaktiviert.', '2FA is already disabled.') });
  if (isLocked(c.twofaLockedUntil)) return res.status(429).json({ error: M(l, 'Çok fazla hatalı deneme; birkaç dakika sonra tekrar deneyin.', 'Zu viele Fehlversuche; versuchen Sie es in einigen Minuten erneut.', 'Too many failed attempts; try again in a few minutes.') });
  const code = parsed.data.code.trim();
  let ok = verifyTotp(decryptFromStore(c.totpSecret), code);
  if (!ok) ok = consumeRecoveryCode(c.twofaRecoveryCodes, code).ok;
  if (!ok) {
    const ls = nextLockState(c.twofaFailedAttempts);
    await prisma.customer.update({ where: { id: c.id }, data: { twofaFailedAttempts: ls.failed, twofaLockedUntil: ls.lockedUntil } });
    return res.status(401).json({ error: M(l, 'Kod hatalı.', 'Code ist falsch.', 'The code is incorrect.') });
  }
  await prisma.customer.update({ where: { id: c.id }, data: { twofaEnabled: false, twofaConfirmedAt: null, totpSecret: null, twofaRecoveryCodes: null, twofaFailedAttempts: 0, twofaLockedUntil: null } });
  res.json({ enabled: false });
});

// ——— Nudge: göster/gizle durumu + tercih (kalıcı) ———
twofaRouter.get('/nudge', requireAuth, async (req, res) => {
  const c = await prisma.customer.findUnique({ where: { id: req.customerId! } });
  if (!c) return res.status(404).json({ error: 'not found' });
  const show = !c.twofaEnabled && !c.twofaNudgeDismissedAt && (!c.twofaNudgeRemindAfter || c.twofaNudgeRemindAfter.getTime() <= Date.now());
  res.json({ show });
});
twofaRouter.post('/nudge/dismiss', requireAuth, async (req, res) => {
  await prisma.customer.update({ where: { id: req.customerId! }, data: { twofaNudgeDismissedAt: new Date() } }); // kalici sustur
  res.json({ ok: true });
});
twofaRouter.post('/nudge/remind', requireAuth, async (req, res) => {
  await prisma.customer.update({ where: { id: req.customerId! }, data: { twofaNudgeRemindAfter: new Date(Date.now() + NUDGE_REMIND_MS) } });
  res.json({ ok: true });
});
