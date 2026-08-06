import { Router } from 'express';
import { z } from 'zod';
import crypto from 'node:crypto';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { prisma } from '../db.js';
import { config } from '../config.js';
import { sendPasswordReset, sendEmailVerification } from '../services/mailer.js';
import { requireAuth } from '../middleware/auth.js';

export const authRouter = Router();

// E-posta dogrulama kodu uretir (6 hane), hash'ini + 15dk gecerlilik kaydeder ve mail atar.
const sha256 = (s: string) => crypto.createHash('sha256').update(s).digest('hex');
async function issueEmailVerification(customerId: string, email: string): Promise<void> {
  const code = String(crypto.randomInt(0, 1_000_000)).padStart(6, '0'); // 000000-999999
  await prisma.customer.update({
    where: { id: customerId },
    data: { emailVerifyCodeHash: sha256(code), emailVerifyCodeExpiry: new Date(Date.now() + 15 * 60 * 1000) },
  });
  await sendEmailVerification(email, code); // mailer no-throw
}

const credsSchema = z.object({ email: z.string().email(), password: z.string().min(8) });

const registerSchema = credsSchema.extend({
  // Kullanim Kosullari + KVKK Aydinlatma metninin okundugunun teyidi (zorunlu).
  termsAccepted: z.literal(true, {
    errorMap: () => ({ message: 'Kullanim Kosullari ve KVKK Aydinlatma Metni onaylanmalidir.' }),
  }),
});

authRouter.post('/register', async (req, res) => {
  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });

  const passwordHash = await bcrypt.hash(parsed.data.password, 12);
  let customer;
  try {
    customer = await prisma.customer.create({
      data: {
        email: parsed.data.email,
        passwordHash,
        termsAcceptedAt: new Date(),
        termsVersion: config.legalVersion,
      },
    });
  } catch (err: any) {
    // Prisma P2002: e-posta ZATEN kayitli.
    if (err?.code === 'P2002') {
      // UX: girilen sifre o hesabin GERCEK sifresiyle eslesiyorsa, kullaniciyi
      // surtunmeden DOGRUDAN giris yaptir (login akisiyla ayni token). Bu yol da
      // /auth authLimiter'i altinda (login ile ayni) -> enumeration/brute-force korumasi geçerli.
      const existing = await prisma.customer.findUnique({ where: { email: parsed.data.email } });
      if (existing && (await bcrypt.compare(parsed.data.password, existing.passwordHash))) {
        // Mevcut hesap — dogrulama akisi ETKILEMEZ (eski hesaplar migration ile verified).
        const token = jwt.sign({ sub: existing.id }, config.jwtSecret, { expiresIn: '7d' });
        return res.json({ token, autoLogin: true, emailVerified: existing.emailVerified });
      }
      // Sifre yanlis -> mevcut dostane mesaj (degistirilmedi).
      return res.status(409).json({ error: 'Bu e-posta ile zaten bir hesap var. Lutfen giris yapin.' });
    }
    throw err;
  }

  // YENI hesap — emailVerified=false (schema varsayilani). 6 haneli dogrulama kodu gonder.
  await issueEmailVerification(customer.id, customer.email);
  const token = jwt.sign({ sub: customer.id }, config.jwtSecret, { expiresIn: '7d' });
  res.json({ token, emailVerified: false });
});

authRouter.post('/login', async (req, res) => {
  const parsed = credsSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });

  const customer = await prisma.customer.findUnique({ where: { email: parsed.data.email } });
  if (!customer || !(await bcrypt.compare(parsed.data.password, customer.passwordHash))) {
    return res.status(401).json({ error: 'E-posta veya sifre hatali.' });
  }

  const token = jwt.sign({ sub: customer.id }, config.jwtSecret, { expiresIn: '7d' });
  res.json({ token });
});

// --- (A) Sifre sifirlama ------------------------------------------------------
// Her iki endpoint de '/auth' altinda oldugu icin authLimiter (rate-limit) korumasindadir
// → brute-force / spam-mail engellenir. Enumeration korumasi: forgot HER ZAMAN 200 doner.

const emailSchema = z.object({ email: z.string().email() });
const resetSchema = z.object({ token: z.string().min(20), password: z.string().min(8) });

authRouter.post('/forgot-password', async (req, res) => {
  const parsed = emailSchema.safeParse(req.body);
  // E-posta ENUMERATION korumasi: hesap var/yok fark etmeksizin ayni generic yanit.
  if (parsed.success) {
    const customer = await prisma.customer.findUnique({ where: { email: parsed.data.email } });
    if (customer) {
      const rawToken = crypto.randomBytes(32).toString('hex'); // duz token yalnizca mailde
      const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex'); // DB'de yalnizca hash
      const resetTokenExpiry = new Date(Date.now() + 60 * 60 * 1000); // 1 saat
      await prisma.customer.update({ where: { id: customer.id }, data: { resetTokenHash: tokenHash, resetTokenExpiry } });
      const url = `${config.frontendUrl}/reset-password?token=${rawToken}`;
      await sendPasswordReset(customer.email, url); // mailer no-throw; hata akisi bozmaz
    }
  }
  return res.json({ ok: true });
});

authRouter.post('/reset-password', async (req, res) => {
  const parsed = resetSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Geçersiz istek. Şifre en az 8 karakter olmalıdır.' });
  const tokenHash = crypto.createHash('sha256').update(parsed.data.token).digest('hex');
  const customer = await prisma.customer.findFirst({
    where: { resetTokenHash: tokenHash, resetTokenExpiry: { gt: new Date() } },
  });
  if (!customer) return res.status(400).json({ error: 'Bağlantı geçersiz veya süresi dolmuş. Lütfen yeniden sıfırlama talep edin.' });
  const passwordHash = await bcrypt.hash(parsed.data.password, 12);
  await prisma.customer.update({
    where: { id: customer.id },
    data: { passwordHash, resetTokenHash: null, resetTokenExpiry: null }, // token TEK KULLANIMLIK
  });
  // Surtunmesiz: yeni sifreyle otomatik giris token'i.
  const token = jwt.sign({ sub: customer.id }, config.jwtSecret, { expiresIn: '7d' });
  return res.json({ ok: true, token });
});

// --- (0) E-posta dogrulama -----------------------------------------------------
// Hepsi '/auth' altinda → authLimiter (rate-limit). verify/resend requireAuth ister
// (kayit sonrasi kullanicinin token'i vardir; dashboard erisimi kisitlanmaz, yalniz
// satin alma emailVerified sart — bkz orders.ts).

authRouter.get('/me', requireAuth, async (req, res) => {
  const c = await prisma.customer.findUnique({ where: { id: req.customerId! }, select: { email: true, emailVerified: true } });
  if (!c) return res.status(404).json({ error: 'Hesap bulunamadı.' });
  res.json(c);
});

const codeSchema = z.object({ code: z.string().regex(/^\d{6}$/) });

authRouter.post('/verify-email', requireAuth, async (req, res) => {
  const parsed = codeSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Kod 6 haneli olmalıdır.' });
  const c = await prisma.customer.findUnique({ where: { id: req.customerId! } });
  if (!c) return res.status(404).json({ error: 'Hesap bulunamadı.' });
  if (c.emailVerified) return res.json({ ok: true, emailVerified: true }); // zaten dogrulanmis
  if (!c.emailVerifyCodeHash || !c.emailVerifyCodeExpiry || c.emailVerifyCodeExpiry < new Date()) {
    return res.status(400).json({ error: 'Kodun süresi dolmuş. Lütfen yeni kod isteyin.' });
  }
  if (sha256(parsed.data.code) !== c.emailVerifyCodeHash) {
    return res.status(400).json({ error: 'Kod hatalı. Lütfen tekrar deneyin.' });
  }
  await prisma.customer.update({
    where: { id: c.id },
    data: { emailVerified: true, emailVerifyCodeHash: null, emailVerifyCodeExpiry: null },
  });
  res.json({ ok: true, emailVerified: true });
});

authRouter.post('/resend-verification', requireAuth, async (req, res) => {
  const c = await prisma.customer.findUnique({ where: { id: req.customerId! }, select: { id: true, email: true, emailVerified: true } });
  if (!c) return res.status(404).json({ error: 'Hesap bulunamadı.' });
  if (c.emailVerified) return res.json({ ok: true, emailVerified: true });
  await issueEmailVerification(c.id, c.email);
  res.json({ ok: true });
});
