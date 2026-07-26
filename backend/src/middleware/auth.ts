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

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const header = req.header('authorization');
  if (!header?.startsWith('Bearer ')) return res.status(401).json({ error: 'Oturum acilmamis.' });

  try {
    const payload = jwt.verify(header.slice(7), config.jwtSecret) as { sub: string };
    req.customerId = payload.sub;
    next();
  } catch {
    res.status(401).json({ error: 'Gecersiz veya suresi dolmus oturum.' });
  }
}
