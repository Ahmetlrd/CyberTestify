import { config } from '../config.js';

/**
 * (BOT KORUMASI) Cloudflare Turnstile token doğrulaması — birden çok uçta (instant-scan, register…)
 * paylaşılır. secret yoksa doğrulama atlanır (VARSAYILANDA test-secret set olduğundan normalde çalışır).
 * Fail-closed: doğrulanamayan token reddedilir.
 */
export async function verifyTurnstile(token: string | undefined, ip: string): Promise<boolean> {
  if (!config.turnstile.secretKey) return true;
  if (!token) return false;
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 10_000);
    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ secret: config.turnstile.secretKey, response: token, remoteip: ip }),
      signal: ctrl.signal,
    });
    clearTimeout(t);
    const j = (await r.json()) as { success?: boolean };
    return !!j.success;
  } catch {
    return false;
  }
}
