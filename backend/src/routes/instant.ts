import { Router } from 'express';
import { z } from 'zod';
import { runInstantScan } from '../services/instantScan.js';
import { verifyTurnstile } from '../services/turnstile.js';

/**
 * (ÜCRETSİZ ANLIK ÖN-TARAMA) PUBLIC endpoint — herkes bir URL girebilir. Bu yüzden:
 *  - SADECE pasif (runInstantScan pasif-only; aktif prob YOK).
 *  - Bot/DDoS-by-proxy koruması: Turnstile token doğrulama + honeypot + tek-eşzamanlı-tarama/IP.
 *  - Rate-limit server.ts'te (instantLimiter) uygulanır (bu router'ın ÖNÜNDE).
 *  - İç/özel IP hedefleri REDDEDİLİR (SSRF / iç ağ taraması önleme).
 */
export const instantRouter = Router();

const schema = z.object({
  url: z.string().min(3).max(255),
  turnstileToken: z.string().max(4000).optional(),
  website: z.string().max(200).optional(), // HONEYPOT — insan görmez; doluysa bot.
});

// Aynı IP'den ANLIK OLARAK yalnız 1 tarama (altyapıyı DDoS aracı yapmaya izin verme).
const inFlight = new Set<string>();

function normalizeHost(raw: string): string | null {
  let u = raw.trim();
  if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
  let host: string;
  try {
    host = new URL(u).hostname.toLowerCase();
  } catch {
    return null;
  }
  // Geçerli public alan adı (TLD'li). IP/hostname-only reddedilir.
  if (!/^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(host)) return null;
  // İç/özel/loopback/link-local hedefleri ENGELLE (SSRF + iç ağ taraması önleme).
  if (
    host === 'localhost' ||
    /(^|\.)local$/i.test(host) ||
    /^(127\.|10\.|0\.|169\.254\.|192\.168\.)/.test(host) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(host) ||
    /^metadata\./i.test(host)
  ) {
    return null;
  }
  return host;
}

instantRouter.post('/', async (req, res) => {
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Geçerli bir alan adı girin (ör. example.com).' });
  const { url, turnstileToken, website } = parsed.data;

  // HONEYPOT: gizli alan doluysa bot → sessizce reddet.
  if (website && website.trim()) return res.status(400).json({ error: 'Doğrulama başarısız.' });

  const ip = (req.ip || 'unknown').toString();

  // İNSAN DOĞRULAMASI (Turnstile) — token geçerli değilse tarama ÇALIŞMAZ.
  if (!(await verifyTurnstile(turnstileToken, ip))) {
    return res.status(403).json({ error: 'İnsan doğrulaması gerekli. Lütfen doğrulama kutusunu tamamlayın.' });
  }

  const host = normalizeHost(url);
  if (!host) return res.status(400).json({ error: 'Geçerli, herkese açık bir alan adı girin (ör. example.com).' });

  if (inFlight.has(ip)) return res.status(429).json({ error: 'Zaten bir tarama çalışıyor. Lütfen bitmesini bekleyin.' });
  inFlight.add(ip);
  try {
    const result = await runInstantScan(host);
    return res.json({ host, ...result });
  } catch {
    return res.status(500).json({ error: 'Tarama şu an tamamlanamadı. Lütfen tekrar deneyin.' });
  } finally {
    inFlight.delete(ip);
  }
});
