import type { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config.js';

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      customerId?: string;
    }
  }
}

// (çok-bölge) kullanıcıya dönen 401 metni bölgeye göre — tr/de/en.
function aLoc(req: Request): string {
  const r = typeof (req.body as any)?.region === 'string' ? (req.body as any).region : (typeof req.query?.region === 'string' ? (req.query.region as string) : 'tr');
  return r === 'de' ? 'de' : r === 'en' ? 'en' : 'tr';
}
const M = (loc: string, tr: string, de: string, en: string): string => (loc === 'de' ? de : loc === 'en' ? en : tr);

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const header = req.header('authorization');
  if (!header?.startsWith('Bearer ')) return res.status(401).json({ error: M(aLoc(req), 'Oturum açılmamış.', 'Nicht angemeldet.', 'Not signed in.') });

  try {
    const payload = jwt.verify(header.slice(7), config.jwtSecret) as { sub: string };
    req.customerId = payload.sub;
    next();
  } catch {
    res.status(401).json({ error: M(aLoc(req), 'Geçersiz veya süresi dolmuş oturum.', 'Sitzung ungültig oder abgelaufen.', 'Session invalid or expired.') });
  }
}
