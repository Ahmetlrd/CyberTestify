import { Router } from 'express';
import { z } from 'zod';
import { runInstantScan } from '../services/instantScan.js';
import { verifyTurnstile } from '../services/turnstile.js';
import { prisma } from '../db.js';
import { generateBasitReport } from '../services/basitReport.js';
import { renderReportPdf } from '../services/pdf.js';
import { getPackageDef, localizedPackage } from '../services/scanPackages.js';

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

// (ANA SAYFA — GERÇEK BASİT TARAMA) Ücretsiz test artık teaser skoru + TAM Basit Tarama'yı birlikte koşar
// (gerçek süre, gerçekçi). Üretilen rapor markdown'ı logId ile kısa süre bellekte tutulur → "Raporu Gör"
// adımı YENİDEN taramaz, yalnız PDF'e çevirir (hız + tutarlılık). TTL 20dk; en fazla 200 kayıt (bellek koruması).
type CachedReport = { md: string; fix: string; host: string; exp: number };
const reportCache = new Map<string, CachedReport>();
const REPORT_TTL_MS = 20 * 60 * 1000;
function cacheReport(logId: string, r: CachedReport): void {
  if (reportCache.size > 200) { const now = Date.now(); for (const [k, v] of reportCache) if (v.exp < now) reportCache.delete(k); }
  if (reportCache.size > 200) reportCache.delete(reportCache.keys().next().value as string);
  reportCache.set(logId, r);
}

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
    // (ÜCRETSİZ TARAMA LOGU) Girilen alan adı + sonucu admin panelinde görünsün (lead/abuse takibi).
    // Best-effort: hata taramayı ASLA bozmaz. Yalnız teknik alan; müşteri/rapor verisi yok.
    let logId: string | undefined;
    try {
      const row = await prisma.instantScanLog.create({
        data: {
          host, status: result.status, region: lang, ip,
          score: result.status === 'ok' ? result.score : null,
          grade: result.status === 'ok' ? result.grade : null,
          findings: result.status === 'ok' ? result.total : null,
          httpStatus: result.status === 'access_error' ? result.httpStatus : null,
        },
        select: { id: true },
      });
      logId = row.id;
    } catch { /* log best-effort */ }
    // (GERÇEK BASİT TARAMA) 'ok' ise TAM Basit Tarama raporunu ŞİMDİ üret (gerçek çok-sayfa tarama → gerçek
    // süre) ve logId ile cache'le. "Raporu Gör" adımı bunu kullanır (yeniden taramaz). Best-effort; hata
    // teaser'ı bozmaz (o durumda rapor adımı yeniden üretir).
    if (result.status === 'ok' && logId) {
      try {
        const rep = await generateBasitReport(host, lang);
        if (rep) cacheReport(logId, { md: rep.findings, fix: rep.fixText, host, exp: Date.now() + REPORT_TTL_MS });
      } catch { /* rapor adımında yeniden denenir */ }
    }
    return res.json({ host, ...result, logId });
  } catch {
    return res.status(500).json({ error: im(region, 'Tarama şu an tamamlanamadı. Lütfen tekrar deneyin.', 'Der Scan konnte derzeit nicht abgeschlossen werden. Bitte versuchen Sie es erneut.', 'The scan could not be completed right now. Please try again.') });
  } finally {
    inFlight.delete(ip);
  }
});


// (ANA SAYFA LEAD — TAM RAPOR) Ziyaretçi e-postasını verince Basit Tarama raporunu GERÇEK-ZAMANLI üretip
// PDF döndürür. Bu YALNIZCA ana sayfa ücretsiz akışıdır: ÖDEME/KAYIT/ADMIN-ONAYI YOKTUR (rapor pasif dış
// gözlemden üretilir, hassas veri barındırmaz). AI Çözüm Önerileri eklentisi KİLİTLİ kalır (ücretli upsell).
// e-posta admin logunda (InstantScanLog) domain yanına yazılır. instantLimiter (6/dk/IP) router'da geçerli.
const reportSchema = z.object({
  logId: z.string().uuid().optional(),
  url: z.string().min(3).max(255),
  email: z.string().email().max(200),
  region: z.string().max(8).optional(),
});

instantRouter.post('/report', async (req, res) => {
  const rg = typeof req.body?.region === 'string' ? req.body.region : undefined;
  const parsed = reportSchema.safeParse(req.body);
  if (!parsed.success) {
    const emailErr = parsed.error.issues.some((i) => i.path[0] === 'email');
    return res.status(400).json({ error: im(rg, emailErr ? 'Geçerli bir e-posta adresi girin.' : 'Geçersiz istek.', emailErr ? 'Bitte geben Sie eine gültige E-Mail-Adresse ein.' : 'Ungültige Anfrage.', emailErr ? 'Enter a valid e-mail address.' : 'Invalid request.') });
  }
  const { logId, url, email, region } = parsed.data;
  const lang: 'tr' | 'de' | 'en' = region === 'de' ? 'de' : region === 'en' ? 'en' : 'tr';
  const host = normalizeHost(url);
  if (!host) return res.status(400).json({ error: im(region, 'Geçerli, herkese açık bir alan adı girin.', 'Geben Sie eine gültige, öffentliche Domain ein.', 'Enter a valid, public domain.') });

  const ip = (req.ip || 'unknown').toString();
  // (LEAD) e-postayı admin logunda domain yanına yaz — best-effort, hata raporu engellemez.
  try {
    if (logId) await prisma.instantScanLog.update({ where: { id: logId }, data: { email: email.toLowerCase() } });
    else {
      const recent = await prisma.instantScanLog.findFirst({ where: { host, ip }, orderBy: { createdAt: 'desc' }, select: { id: true } });
      if (recent) await prisma.instantScanLog.update({ where: { id: recent.id }, data: { email: email.toLowerCase() } });
      else await prisma.instantScanLog.create({ data: { host, status: 'ok', region: lang, ip, email: email.toLowerCase() } });
    }
  } catch { /* best-effort */ }

  try {
    // (CACHE) Tarama sırasında üretilen rapor varsa YENİDEN TARAMA — yalnız PDF'e çevir. Yoksa (süresi
    // dolmuş/farklı IP) taze üret.
    const cached = logId ? reportCache.get(logId) : undefined;
    let md: string, fix: string;
    if (cached && cached.host === host && cached.exp > Date.now()) { md = cached.md; fix = cached.fix; }
    else {
      const report = await generateBasitReport(host, lang);
      if (!report) return res.status(422).json({ error: im(region, 'Rapor şu an üretilemedi. Lütfen tekrar deneyin.', 'Der Bericht konnte derzeit nicht erstellt werden. Bitte erneut versuchen.', 'The report could not be generated right now. Please try again.') });
      md = report.findings; fix = report.fixText;
    }
    const packageName = localizedPackage(getPackageDef('basit_tarama'), lang).displayName;
    // AI Çözüm Önerileri (fixText) KİLİTLİ — ücretli eklenti; ücretsiz raporda teaser olarak kilitli görünür.
    const pdf = await renderReportPdf(
      md,
      { hostname: host, packageName, packageKey: 'basit_tarama', createdAt: new Date(), locale: lang },
      { fixMarkdown: fix, fixLocked: true },
    );
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('X-Robots-Tag', 'noindex, nofollow');
    res.setHeader('Content-Disposition', `attachment; filename="cybertestify-basit-tarama-${host}.pdf"`);
    return res.send(pdf);
  } catch {
    return res.status(500).json({ error: im(region, 'Rapor şu an oluşturulamadı. Lütfen tekrar deneyin.', 'Der Bericht konnte derzeit nicht erstellt werden. Bitte erneut versuchen.', 'The report could not be created right now. Please try again.') });
  }
});
