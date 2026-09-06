import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import { config } from '../config.js';
import { prisma } from '../db.js';
import { zodError } from '../httpErrors.js';
import { requireBeta, BETA_TOKEN_SCOPE } from '../middleware/beta.js';
import { suggestPricingForHost, s1PriceForHost } from '../services/pricingModel.js';
import { foldTurkishDomainChars } from '../services/verification.js';

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
  const raw2 = foldTurkishDomainChars(raw.trim());
  const u = /^https?:\/\//i.test(raw2) ? raw2 : `https://${raw2}`;
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

// (P0-A) POST /beta/s1-price — S1 KARMAŞIKLIK-BAZLI NET FİYAT (ödeme ekranı ÖNCESİ). Ucuz pasif
// ön-kontrol (cache'li corpus; PentAGI/droplet ÇALIŞMAZ). 750/1500/2500 ₺, tavan 2500 hiç aşılmaz.
// Fiyat müşteriye ödemeden ÖNCE gösterilir → sürpriz fatura yok.
betaRouter.post('/s1-price', requireBeta, async (req, res) => {
  const parsed = estimateSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: zodError(parsed.error) });
  const host = normalizeHost(parsed.data.domain);
  if (!host) return res.status(400).json({ error: 'Geçerli, herkese açık bir alan adı girin (ör. example.com).' });
  try {
    const p = await s1PriceForHost(host);
    return res.json({
      host, level: 'S1', currency: p.currency, priceTL: p.priceTL,
      tier: p.tier, reason: p.reason, estEndpoints: p.estEndpoints,
      note: 'Fiyat, hedefin ölçülen karmaşıklığına göre belirlenir ve ödeme öncesi sabittir (sürpriz fatura yok). Üst sınır 2.500 ₺.',
    });
  } catch {
    // Ön-kontrol başarısızsa güvenli tarafta kal: en düşük kademe (müşteri lehine), asla tavan.
    return res.json({
      host, level: 'S1', currency: 'TL', priceTL: 750,
      tier: { key: 'basit', label: 'Basit', desc: 'Ön-kontrol yapılamadı — en düşük kademe uygulandı' },
      reason: 'pasif ön-kontrol sinyali çıkarılamadı; müşteri lehine en düşük kademe', estEndpoints: 0,
      note: 'Fiyat ödeme öncesi sabittir. Üst sınır 2.500 ₺.',
    });
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

/** Opsiyonel: Authorization Bearer (kullanıcı JWT'si) varsa customerId çıkar (non-fatal). */
function optionalCustomerId(req: import('express').Request): string | null {
  const h = req.header('authorization');
  if (!h?.startsWith('Bearer ')) return null;
  try {
    return (jwt.verify(h.slice(7), config.jwtSecret) as { sub?: string }).sub ?? null;
  } catch {
    return null;
  }
}

// POST /beta/start — 3b-ii: gated tetik → İŞ KAYDI (idempotent, started:true, audit).
// Sahiplik/risk HARD-GATE + S3+prod ek-onay sunucuda doğrulanır. İş 'queued' olur; orkestrasyon
// runner'ı (provision→egress→cap'li kampanya→binder→rapor→teardown) işler. Bu uç GERÇEK koşuyu
// KENDİ başlatmaz (runner ayrı, DO token + hedef ile operatör-tetikli) — kazara provision olmasın.
betaRouter.post('/start', requireBeta, async (req, res) => {
  const parsed = startSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: zodError(parsed.error) });
  const { domain, level, environment, ownershipConfirmed, riskAccepted, prodElevatedAccepted } = parsed.data;
  if (level === 'S3' && environment === 'prod' && prodElevatedAccepted !== true) {
    return res.status(400).json({ error: 'Prod + Agresif (S3) için ek yüksek-risk onayı zorunludur (test/staging önerilir).' });
  }
  const host = normalizeHost(domain);
  if (!host) return res.status(400).json({ error: 'Geçerli, herkese açık bir alan adı girin (ör. example.com).' });

  const consentIp = req.ip ?? null;
  const customerId = optionalCustomerId(req);
  const now = new Date();
  const dateBucket = now.toISOString().slice(0, 10); // gün bazlı — aynı gün aynı hedef tekrar = aynı iş
  const idempotencyKey = crypto
    .createHash('sha256')
    .update([host, level, environment, consentIp ?? '', customerId ?? '', dateBucket].join('|'))
    .digest('hex');

  // (P0-A) S1'de fiyat ön-kontrolünü iş kaydına GÖM (divergence: ön-kontrol tahmini vs gerçek koşu kapsamı).
  // Best-effort — fiyatlandırma/ödeme akışına dokunmaz, yalnız ileride heuristik iyileştirmek için iz bırakır.
  let s1EstimateLog: any = null;
  if (level === 'S1') {
    try {
      const p = await s1PriceForHost(host);
      s1EstimateLog = { at: now.toISOString(), phase: 'pricing', message: `S1 ön-kontrol: ${p.tier.label} · ${p.priceTL} ₺ (${p.reason})`, s1Estimate: { tier: p.tier.key, priceTL: p.priceTL, estEndpoints: p.estEndpoints, signals: p.signals } };
    } catch { /* ön-kontrol başarısızsa iş yine kuyruğa girer */ }
  }

  const job = await prisma.redTeamJob.upsert({
    where: { idempotencyKey },
    update: {}, // idempotent: aynı istek yeni iş AÇMAZ
    create: {
      idempotencyKey,
      customerId,
      domain: host,
      level,
      environment,
      ownershipConfirmed,
      riskAccepted,
      prodElevatedAccepted: prodElevatedAccepted ?? false,
      consentIp,
      status: 'queued',
      startedAt: now,
      log: [
        {
          at: now.toISOString(),
          phase: 'queued',
          message: 'gated tetik: beta-grant + sahiplik + risk onayı doğrulandı; iş kuyruğa alındı',
        },
        ...(s1EstimateLog ? [s1EstimateLog] : []),
      ],
    },
  });

  return res.json({
    status: job.status,
    started: true,
    jobId: job.id,
    message:
      'İş kuyruğa alındı. Otonom orkestrasyon (izole droplet + cap + kanıt-bağlayıcı) runner tarafından işlenecek.',
  });
});

// GET /beta/job/:id — iş durumu (secret/log-detay dönmez; panel polling için).
betaRouter.get('/job/:id', requireBeta, async (req, res) => {
  const job = await prisma.redTeamJob.findUnique({
    where: { id: req.params.id },
    select: {
      id: true, status: true, domain: true, level: true, environment: true,
      createdAt: true, startedAt: true, finishedAt: true,
      llmCalls: true, costUsd: true, reportJson: true, error: true,
    },
  });
  if (!job) return res.status(404).json({ error: 'İş bulunamadı.' });
  return res.json(job);
});
