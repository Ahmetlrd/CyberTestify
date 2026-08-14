// ============================================================================
// TARAMA LOG SİSTEMİ (GÖZLEMLENEBİLİRLİK) — best-effort, asenkron, additive
// ----------------------------------------------------------------------------
// Her taramanın adım-adım YAPILANDIRILMIŞ (structured) logunu tutar. AsyncLocalStorage
// ile "geçerli tarama"ya bağlanır -> collector/prob kodları imza değiştirmeden logScanStep()
// çağırır. TARAMAYI ASLA DURDURMAZ: bağlam yoksa no-op; DB yazımı hatası yutulur (best-effort).
// Bellekte biriktirir, tarama sonunda TEK batch insert eder (istek başına DB yazımı YOK -> perf).
// Response body TAM loglanmaz; hassas header/query değerleri maskelenir.
// ============================================================================
import { AsyncLocalStorage } from 'node:async_hooks';
import { prisma } from '../db.js';

export type ScanLogEntry = {
  step: string;
  level?: 'info' | 'warn' | 'error' | 'circuit_breaker';
  method?: string;
  url?: string;
  status?: number;
  durationMs?: number;
  sizeBytes?: number;
  rule?: string;
  severity?: string;
  summary?: string;
};
type ScanLogCtx = { orderId: string; flowId: string; buffer: (ScanLogEntry & { seq: number; ts: Date })[]; seq: number; dropped: number };

const als = new AsyncLocalStorage<ScanLogCtx>();
const MAX_ENTRIES = 4000; // runaway bellek koruması (tek tarama)

// Taramanın tamamını log bağlamıyla sar; bitince (başarı/hata) TEK batch flush eder.
export async function runWithScanLog<T>(orderId: string, flowId: string, fn: () => Promise<T>): Promise<T> {
  const ctx: ScanLogCtx = { orderId, flowId, buffer: [], seq: 0, dropped: 0 };
  return als.run(ctx, async () => {
    try {
      return await fn();
    } finally {
      await flush(ctx);
    }
  });
}

// GEÇERLİ tarama bağlamına bir adım yaz (best-effort). Bağlam yoksa (bağımsız çağrı) sessizce yok sayılır.
export function logScanStep(entry: ScanLogEntry): void {
  const ctx = als.getStore();
  if (!ctx) return;
  if (ctx.buffer.length >= MAX_ENTRIES) { ctx.dropped++; return; }
  ctx.buffer.push({ ...entry, level: entry.level ?? 'info', seq: ctx.seq++, ts: new Date() });
}

// Şu an bir tarama log bağlamı aktif mi? (koşullu ağır hesaplamalardan kaçınmak için)
export function scanLogActive(): boolean { return als.getStore() !== undefined; }

async function flush(ctx: ScanLogCtx): Promise<void> {
  if (ctx.dropped > 0) {
    ctx.buffer.push({ step: 'Log', level: 'warn', summary: `Log üst sınırına (${MAX_ENTRIES}) ulaşıldı; ${ctx.dropped} adım kaydedilmedi.`, seq: ctx.seq++, ts: new Date() });
  }
  if (!ctx.buffer.length) return;
  try {
    // (BEST-EFFORT) DB yazımı hata verse bile TARAMA/RAPOR akışı ETKİLENMEZ — yalnız loglanır.
    await prisma.scanLog.createMany({
      data: ctx.buffer.map((e) => ({
        orderId: ctx.orderId, seq: e.seq, ts: e.ts, step: e.step.slice(0, 200), level: e.level ?? 'info',
        method: e.method ?? null, url: e.url ? maskSensitive(e.url).slice(0, 500) : null,
        status: e.status ?? null, durationMs: e.durationMs ?? null, sizeBytes: e.sizeBytes ?? null,
        rule: e.rule ?? null, severity: e.severity ?? null, summary: e.summary ? e.summary.slice(0, 500) : null,
      })),
    });
  } catch (err) {
    console.warn(`[scan-log] flush başarısız (best-effort, tarama etkilenmedi) order=${ctx.orderId}: ${String((err as Error)?.message ?? err).slice(0, 120)}`);
  }
}

// URL query'sindeki HASSAS parametre değerlerini maskele (token/key/secret/password/auth/sig/session).
// Hedefin kendi sitesi olsa da olası kimlik/oturum sızıntısını loglamamak için son 4 hariç ***.
const SENSITIVE_PARAM_RE = /^(token|access_token|api_?key|key|secret|password|passwd|pwd|auth|authorization|sig|signature|sid|session|sessionid|jwt|code|otp)$/i;
export function maskSensitive(url: string): string {
  try {
    const u = new URL(url, url.startsWith('http') ? undefined : 'http://x');
    let changed = false;
    u.searchParams.forEach((v, k) => {
      if (SENSITIVE_PARAM_RE.test(k) && v.length > 0) { u.searchParams.set(k, maskValue(v)); changed = true; }
    });
    return changed ? u.toString() : url;
  } catch {
    return url;
  }
}
// Header değerini (Authorization/Cookie) maskele: son 4 karakter hariç ***.
export function maskValue(v: string): string {
  if (v.length <= 4) return '***';
  return '***' + v.slice(-4);
}

// (RETENTION) Belirtilen günden eski log kayıtlarını sil (sonsuza kadar biriktirme). Best-effort;
// worker günde bir kez çağırır (kendi guard'ıyla). Silinen satır sayısını döner.
export async function purgeOldScanLogs(days = 60): Promise<number> {
  const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
  try {
    const r = await prisma.scanLog.deleteMany({ where: { createdAt: { lt: cutoff } } });
    if (r.count > 0) console.log(`[scan-log][retention] ${days} günden eski ${r.count} log satırı silindi.`);
    return r.count;
  } catch (err) {
    console.warn(`[scan-log][retention] temizlik hatası (yok sayıldı): ${String((err as Error)?.message ?? err).slice(0, 120)}`);
    return 0;
  }
}
