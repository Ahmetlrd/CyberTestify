import { Router } from 'express';
import { z } from 'zod';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { prisma } from '../db.js';
import { config } from '../config.js';

// Admin giris — MUSTERI auth'undan AYRI. REGISTER ENDPOINT'I YOK: admin yalnizca
// CLI/DB ile eklenir (prisma/createAdmin.ts). Herkese acik "admin ol" formu yok.
export const adminAuthRouter = Router();

const loginSchema = z.object({ email: z.string().email(), password: z.string().min(8) });

adminAuthRouter.post('/login', async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Gecersiz giris bilgisi.' });

  const admin = await prisma.adminUser.findUnique({ where: { email: parsed.data.email } });
  // Sabit-zaman benzeri davranis: kullanici yoksa da bcrypt.compare calistir.
  const ok = admin
    ? await bcrypt.compare(parsed.data.password, admin.passwordHash)
    : await bcrypt.compare(parsed.data.password, '$2a$12$0000000000000000000000000000000000000000000000000000');
  if (!admin || !ok) {
    return res.status(401).json({ error: 'E-posta veya sifre hatali.' });
  }

  // TODO(2FA): admin.totpSecret dolu ise burada TOTP kodu dogrulanmali (otplib).
  // Su an 2FA login'de ZORUNLU DEGIL — bkz HANDOFF.md.

  await prisma.adminUser.update({ where: { id: admin.id }, data: { lastLoginAt: new Date() } });
  const token = jwt.sign({ sub: admin.id, typ: 'admin' }, config.adminJwtSecret, { expiresIn: '12h' });
  res.json({ token, email: admin.email });
});
