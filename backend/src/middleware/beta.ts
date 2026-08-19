import type { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config.js';

/** Beta grant token'ının kapsamı — kullanıcı JWT'siyle karışmasın diye ayrı. */
export const BETA_TOKEN_SCOPE = 'rt-beta';

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      betaUnlocked?: boolean;
    }
  }
}

/**
 * Otonom Red Team paneli endpoint'lerini korur. Panel yalnız SUNUCU-imzalı, 'rt-beta'
 * kapsamlı bir grant token'ı ile açılır (client'ta bir flag'i çevirmek YETMEZ; token
 * jwtSecret olmadan üretilemez). Başlık: `X-Beta-Token: <token>`.
 */
export function requireBeta(req: Request, res: Response, next: NextFunction) {
  const token = req.header('x-beta-token');
  if (!token) return res.status(403).json({ error: 'Beta erişimi gerekli.' });
  try {
    const payload = jwt.verify(token, config.jwtSecret) as { scope?: string };
    if (payload.scope !== BETA_TOKEN_SCOPE) return res.status(403).json({ error: 'Beta erişimi gerekli.' });
    req.betaUnlocked = true;
    next();
  } catch {
    res.status(403).json({ error: 'Beta oturumu geçersiz veya süresi dolmuş.' });
  }
}
