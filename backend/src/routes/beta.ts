import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import { config } from '../config.js';
import { zodError } from '../httpErrors.js';
import { requireBeta, BETA_TOKEN_SCOPE } from '../middleware/beta.js';
import { suggestPricingForHost } from '../services/pricingModel.js';

export const betaRouter = Router();

// ————————————————————————————————————————————————————————————————————————
// OTONOM AI RED TEAM — 3b-i BETA KAPISI (backend-zorlamalı; kod front-end'de YOK).
// Bu fazda GERÇEK PentAGI koşusu TETİKLENMEZ — /start yalnız "Hazırlanıyor" stub'ı döner.
// ————————————————————————————————————————————————————————————————————————

// Beta kodu doğrulama = kaba-kuvvet birinci hedefi → ÇOK sıkı limit (dk başına 5/IP).
const betaUnlockLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Çok fazla deneme. Lütfen biraz bekleyip tekrar deneyin.' },
});

/** Sabit-zamanlı karşılaştırma (timing yan-kanalı ile kod tahminini zorlaştırır). */
function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

const unlockSchema = z.object({ code: z.string().min(1, 'Kod girin.').max(128) });

// POST /beta/unlock — kodu SUNUCUDA doğrula; geçerliyse imzalı 'rt-beta' grant token'ı ver.
// Kod ekrana/loga BASILMAZ. Boş yapılandırma = FAIL-CLOSED (kimse açamaz).
betaRouter.post('/unlock', betaUnlockLimiter, (req, res) => {
  const parsed = unlockSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: zodError(parsed.error) });

  if (!config.betaAccessCode || config.betaAccessCode.trim() === '') {
    // Yapılandırılmamış → gate kapalı (fail-closed). Kodun varlığını sızdırmadan "Yakında".
    return res.status(503).json({ error: 'Bu özellik yakında etkinleşecek.' });
  }
  if (!safeEqual(parsed.data.code, config.betaAccessCode)) {
    return res.status(401).json({ error: 'Kod geçersiz.' });
  }
  const betaToken = jwt.sign({ scope: BETA_TOKEN_SCOPE }, config.jwtSecret, { expiresIn: '30d' });
  return res.json({ ok: true, betaToken, expiresInDays: 30 });
});

// —— Aşağıdaki uçlar requireBeta ARKASINDA (geçerli grant token şart) ——

const estimateSchema = z.object({ domain: z.string().min(3).max(255) });

/** Public alan adı + SSRF/iç-ağ reddi (instant.ts ile aynı disiplin). */
function normalizeHost(raw: string): string | null {
  const u = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
  let host: string;
  try { host = new URL(u).hostname.toLowerCase(); } catch { return null; }
  if (!/^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(host)) return null;
  if (
    host === 'localhost' ||
    /(^|\.)local$/i.test(host) ||
    /^(127\.|10\.|0\.|169\.254\.|192\.168\.)/.test(host) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(host) ||
    /^metadata\./i.test(host)
  ) return null;
  return host;
}

// POST /beta/estimate — PASİF kompleksite (Faz-4, mevcut cache'li corpus) → fiyat BANDI ÖNERİSİ.
// Ekstra aktif tarama/saldırı YOK. PentAGI YOK. Fiyatlar "öneri, garanti değil" (placeholder).
betaRouter.post('/estimate', requireBeta, async (req, res) => {
  const parsed = estimateSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: zodError(parsed.error) });
  const host = normalizeHost(parsed.data.domain);
  if (!host) return res.status(400).json({ error: 'Geçerli, herkese açık bir alan adı girin (ör. example.com).' });
  try {
    const { signals, suggestion } = await suggestPricingForHost(host);
    return res.json({ host, signals, suggestion });
  } catch {
    return res.status(200).json({ host, signals: null, suggestion: null, note: 'Pasif sinyal çıkarılamadı; öneri gösterilemiyor.' });
  }
});

// Ortam + sahiplik/onay şeması. S3 (agresif) + prod → EK açık onay zorunlu.
const startSchema = z.object({
  domain: z.string().min(3).max(255),
  level: z.enum(['S1', 'S2', 'S3']),
  environment: z.enum(['test', 'staging', 'prod']),
  ownershipConfirmed: z.literal(true, { errorMap: () => ({ message: 'Hedefin sahibi/yetkilisi olduğunuzu onaylamalısınız.' }) }),
  riskAccepted: z.literal(true, { errorMap: () => ({ message: 'Riskleri ve deterministik-olmadığını kabul etmelisiniz.' }) }),
  prodElevatedAccepted: z.boolean().optional(),
});

// POST /beta/start — 3b-i STUB. GERÇEK KOŞU YOK. Sahiplik/onay HARD-GATE sunucuda doğrulanır;
// S3+prod ek-onay zorunlu; her şey geçerliyse "Hazırlanıyor" stub'ı döner (3b-ii'de bağlanacak).
betaRouter.post('/start', requireBeta, (req, res) => {
  const parsed = startSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: zodError(parsed.error) });
  const { level, environment, prodElevatedAccepted } = parsed.data;
  if (level === 'S3' && environment === 'prod' && prodElevatedAccepted !== true) {
    return res.status(400).json({ error: 'Prod + Agresif (S3) için ek yüksek-risk onayı zorunludur (test/staging önerilir).' });
  }
  // Bilerek: hiçbir tarama/orkestrasyon başlatılmaz. Yalnız akış ispatı.
  return res.json({
    status: 'preparing',
    started: false,
    message: 'Hazırlanıyor — otonom orkestrasyon yakında etkinleşecek (3b-ii). Bu aşamada gerçek koşu başlatılmaz.',
  });
});
