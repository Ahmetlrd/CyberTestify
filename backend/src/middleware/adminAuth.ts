import type { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config.js';

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      adminId?: string;
    }
  }
}

/**
 * Admin oturum dogrulamasi — MUSTERI auth'undan (middleware/auth.ts) TAMAMEN AYRI.
 * Ayri secret (adminJwtSecret) + payload'ta `typ:'admin'` isareti. Musteri token'i
 * (jwtSecret ile imzali, typ yok) burada IKI kez basarisiz olur: (1) imza farkli
 * secret'la dogrulanamaz, (2) typ !== 'admin'.
 */
const HALF_TTL_SEC = 3.5 * 24 * 60 * 60; // 7 gunluk omrun yarisi

export function requireAdmin(req: Request, res: Response, next: NextFunction) {
  const header = req.header('authorization');
  if (!header?.startsWith('Bearer ')) return res.status(401).json({ error: 'Admin oturumu yok.' });
  try {
    const payload = jwt.verify(header.slice(7), config.adminJwtSecret) as { sub: string; typ?: string; exp?: number };
    if (payload.typ !== 'admin') return res.status(401).json({ error: 'Gecersiz admin oturumu.' });
    req.adminId = payload.sub;
    // (KAYAN OTURUM) Token'in yarisindan fazlasi tukendiyse YENISINI ver; istemci bunu saklar.
    // Boylece panel aktif kullanildikca oturum DUSMEZ; gercek hareketsizlik TTL'i asarsa 2FA'ya duser.
    // Basligi tarayicinin okuyabilmesi icin CORS exposedHeaders'a eklendi (bkz server.ts).
    try {
      const now = Math.floor(Date.now() / 1000);
      const remaining = (payload.exp ?? 0) - now;
      if (remaining > 0 && remaining < HALF_TTL_SEC) {
        res.setHeader('X-Admin-Token-Refresh', jwt.sign({ sub: payload.sub, typ: 'admin' }, config.adminJwtSecret, { expiresIn: '7d' }));
      }
    } catch { /* yenileme basarisizsa mevcut oturum aynen devam eder */ }
    next();
  } catch {
    res.status(401).json({ error: 'Gecersiz veya suresi dolmus admin oturumu.' });
  }
}

/**
 * Opsiyonel IP allowlist. ADMIN_IP_ALLOWLIST bos ise kisitlama uygulanmaz (Vedat
 * henuz sabit IP'sini bilmiyor olabilir). `trust proxy` ayarli oldugu icin req.ip
 * gercek istemci IP'sidir (Caddy arkasinda). IPv6-mapped IPv4 (::ffff:1.2.3.4)
 * normalize edilir.
 */
export function adminIpAllowlist(req: Request, res: Response, next: NextFunction) {
  if (config.adminIpAllowlist.length === 0) return next();
  const ip = (req.ip ?? '').replace(/^::ffff:/, '');
  if (config.adminIpAllowlist.includes(ip)) return next();
  console.warn(`[admin][IP-BLOCK] Izin verilmeyen IP'den admin erisimi: ${ip}`);
  return res.status(403).json({ error: 'Bu IP adresinden admin erisimi kapali.' });
}
