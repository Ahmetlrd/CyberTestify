import { Router } from 'express';
import { z } from 'zod';
import crypto from 'node:crypto';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { prisma } from '../db.js';
import { config } from '../config.js';
import { sendPasswordReset } from '../services/mailer.js';

export const authRouter = Router();

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
        const token = jwt.sign({ sub: existing.id }, config.jwtSecret, { expiresIn: '7d' });
        return res.json({ token, autoLogin: true });
      }
      // Sifre yanlis -> mevcut dostane mesaj (degistirilmedi).
      return res.status(409).json({ error: 'Bu e-posta ile zaten bir hesap var. Lutfen giris yapin.' });
    }
    throw err;
  }

  const token = jwt.sign({ sub: customer.id }, config.jwtSecret, { expiresIn: '7d' });
  res.json({ token });
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
