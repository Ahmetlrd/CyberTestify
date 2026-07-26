import { config } from '../config.js';

/**
 * Egress proxy (Seviye 1 kapsam kilidi) saglikli mi? Backend/worker, YENI bir
 * tarama baslatmadan ONCE bunu kontrol eder; proxy ayakta degilse tarama
 * baslatilmaz (sessiz basarisizlik yerine ACIK red — bkz orchestrator).
 */
export async function checkEgressProxyHealth(timeoutMs = 2000): Promise<boolean> {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    const res = await fetch(`${config.egressProxyUrl}/health`, { signal: ctrl.signal });
    clearTimeout(t);
    if (!res.ok) return false;
    const body = (await res.json().catch(() => ({}))) as { ok?: boolean };
    return body.ok === true;
  } catch {
    return false;
  }
}
