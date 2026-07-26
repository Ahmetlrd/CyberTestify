import { Router } from 'express';
import { z } from 'zod';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { prisma } from '../db.js';
import { config } from '../config.js';

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
  const customer = await prisma.customer.create({
    data: {
      email: parsed.data.email,
      passwordHash,
      termsAcceptedAt: new Date(),
      termsVersion: config.legalVersion,
    },
  });

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
