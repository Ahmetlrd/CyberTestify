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
  region: z.string().max(8).optional(), // (çok-bölge) hata mesajı dili için (tr/de/en)
});

// (çok-bölge) kullanıcıya dönen hata metni bölgeye göre — tr/de/en.
function im(region: string | undefined, tr: string, de: string, en: string): string {
  return region === 'de' ? de : region === 'en' ? en : tr;
}

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
  const rg = typeof req.body?.region === 'string' ? req.body.region : undefined;
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: im(rg, 'Geçerli bir alan adı girin (ör. example.com).', 'Geben Sie eine gültige Domain ein (z. B. example.com).', 'Enter a valid domain (e.g. example.com).') });
  const { url, turnstileToken, website, region } = parsed.data;

  // HONEYPOT: gizli alan doluysa bot → sessizce reddet.
  if (website && website.trim()) return res.status(400).json({ error: im(region, 'Doğrulama başarısız.', 'Verifizierung fehlgeschlagen.', 'Verification failed.') });

  const ip = (req.ip || 'unknown').toString();

  // İNSAN DOĞRULAMASI (Turnstile) — token geçerli değilse tarama ÇALIŞMAZ.
  if (!(await verifyTurnstile(turnstileToken, ip))) {
    return res.status(403).json({ error: im(region, 'İnsan doğrulaması gerekli. Lütfen doğrulama kutusunu tamamlayın.', 'Menschliche Verifizierung erforderlich. Bitte schließen Sie die Verifizierungsbox ab.', 'Human verification required. Please complete the verification box.') });
  }

  const host = normalizeHost(url);
  if (!host) return res.status(400).json({ error: im(region, 'Geçerli, herkese açık bir alan adı girin (ör. example.com).', 'Geben Sie eine gültige, öffentliche Domain ein (z. B. example.com).', 'Enter a valid, public domain (e.g. example.com).') });

  if (inFlight.has(ip)) return res.status(429).json({ error: im(region, 'Zaten bir tarama çalışıyor. Lütfen bitmesini bekleyin.', 'Es läuft bereits ein Scan. Bitte warten Sie, bis er abgeschlossen ist.', 'A scan is already running. Please wait for it to finish.') });
  inFlight.add(ip);
  try {
    const lang: 'tr' | 'de' | 'en' = region === 'de' ? 'de' : region === 'en' ? 'en' : 'tr';
    const result = await runInstantScan(host, lang);
    return res.json({ host, ...result });
  } catch {
    return res.status(500).json({ error: im(region, 'Tarama şu an tamamlanamadı. Lütfen tekrar deneyin.', 'Der Scan konnte derzeit nicht abgeschlossen werden. Bitte versuchen Sie es erneut.', 'The scan could not be completed right now. Please try again.') });
  } finally {
    inFlight.delete(ip);
  }
});
