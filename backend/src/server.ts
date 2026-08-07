import express from 'express';
import 'express-async-errors'; // async handler'lardaki throw'lari hata middleware'ine yonlendirir
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import type { Request, Response, NextFunction } from 'express';
import { config, validateScopeLockConfig } from './config.js';
import { checkEgressProxyHealth } from './services/egressHealth.js';
import { authRouter } from './routes/auth.js';
import { domainsRouter } from './routes/domains.js';
import { ordersRouter } from './routes/orders.js';
import { paymentsRouter } from './routes/payments.js';
import { webhooksRouter } from './routes/webhooks.js';
import { reportsRouter } from './routes/reports.js';
import { blogRouter } from './routes/blog.js';
import { creditsRouter } from './routes/credits.js';
import { internalRouter } from './routes/internal.js';
import { schedulesRouter } from './routes/schedules.js';
import { adminAuthRouter } from './routes/adminAuth.js';
import { adminRouter } from './routes/admin.js';
import { requireAdmin, adminIpAllowlist } from './middleware/adminAuth.js';
import cors from 'cors';

// Fail-fast: kapsam kilidi konfigurasyonu eksik/gecersizse hemen dur.
validateScopeLockConfig();

const app = express();

// Ters proxy (nginx/Cloudflare) arkasinda dogru istemci IP'si icin. Prod'da
// proxy sayisina gore ayarlanir; dev'de zararsiz.
app.set('trust proxy', 1);

// Guvenlik basliklari (CSP, HSTS vb.). API oldugu icin varsayilan yeterli.
app.use(helmet());

// Izin verilen origin'ler. ONEMLI: cybertestify.com (apex) VE app.cybertestify.com AYNI
// uygulamayi paralel sunuyor (yonlendirme YOK) — kullanici hangi domain'den girerse girsin
// API cagrilari CORS'a takilmamali. Bu yuzden apex + TUM alt alan adlarini (app./www./admin.)
// tek regex ile kabul ederiz; ayrica FRONTEND_URL/ADMIN_URL ve localhost (dev) izinli.
const staticOrigins = new Set(
  [config.frontendUrl, ...config.adminUrl.split(',')].map((s) => s.trim()).filter(Boolean),
);
const CYBERTESTIFY_ORIGIN = /^https:\/\/([a-z0-9-]+\.)?cybertestify\.com$/i;
const LOCALHOST_ORIGIN = /^http:\/\/localhost(:\d+)?$/i;
app.use(
  cors({
    origin: (origin, cb) => {
      // Origin yoksa (ayni-origin istek, curl, server-to-server) izin ver.
      if (!origin) return cb(null, true);
      if (staticOrigins.has(origin) || CYBERTESTIFY_ORIGIN.test(origin) || LOCALHOST_ORIGIN.test(origin)) {
        return cb(null, true);
      }
      return cb(null, false);
    },
    credentials: true,
  }),
);

// Webhook route'u RAW body istiyor (imza dogrulamasi icin) — bu yuzden
// genel json() middleware'inden ONCE, sadece bu path icin ozel isleniyor.
app.use('/webhooks', express.raw({ type: '*/*' }), (req, _res, next) => {
  (req as any).rawBody = req.body.toString('utf-8');
  next();
});
app.use('/webhooks', webhooksRouter);

app.use(express.json({ limit: '256kb' }));

// --- Rate limiting -------------------------------------------------------
// Kayit/giris: kaba kuvvet ve otomatik sahte hesap acilmasina karsi siki limit.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 dk
  max: 20, // IP basina 15 dk'da 20 deneme
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Cok fazla deneme. Lutfen bir sure sonra tekrar deneyin.' },
});
// Genel API: siparis/domain/rapor gibi islemleri asiri kullanimdan koru. NOT:
// panel (dashboard/verify) durum icin periyodik polling yapar; pencere+tavan buna
// gore ayarli (aksi halde normal kullanimda "cok fazla istek" ile kilitleniyordu).
const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 dk
  max: 300, // dk basina 300 istek (polling + normal kullanim icin rahat, abuse'a karsi hala kapali)
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Cok fazla istek. Lutfen bir sure sonra tekrar deneyin.' },
});

app.use('/auth', authLimiter, authRouter);
app.use('/domains', apiLimiter, domainsRouter);
app.use('/orders', apiLimiter, ordersRouter);
app.use('/payments', paymentsRouter);
app.use('/reports', apiLimiter, reportsRouter);
app.use('/blog', apiLimiter, blogRouter); // PUBLIC blog (yalniz published; auth yok)
app.use('/credits', apiLimiter, creditsRouter);
app.use('/schedules', apiLimiter, schedulesRouter);

// --- Ic yonetim paneli (admin) — MUSTERI sisteminden TAMAMEN AYRI ---------
// Opsiyonel IP allowlist (bos ise kisitlama yok) hepsine uygulanir. Login ayri
// (register YOK) + siki authLimiter; veri endpoint'leri requireAdmin arkasinda.
// '/admin/auth' once mount edilir ki '/admin' requireAdmin login'i engellemesin.
app.use('/admin/auth', adminIpAllowlist, authLimiter, adminAuthRouter);
app.use('/admin', adminIpAllowlist, apiLimiter, requireAdmin, adminRouter);

// Ic ag endpoint'leri (egress proxy icin) — CORS/rate-limit yok, secret korumali.
app.use('/internal', internalRouter);

app.get('/health', (_req, res) => res.json({ ok: true }));

// Global hata yakalayici — async handler'lardaki throw'lar ( or. Prisma
// findFirstOrThrow "kayit yok") burada yakalanir; process COKMEZ ve istemciye
// duzgun JSON doner. (express-async-errors sayesinde async throw'lar buraya gelir.)
// eslint-disable-next-line @typescript-eslint/no-unused-vars
app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
  if (err?.code === 'P2025') {
    return res.status(404).json({ error: 'Kayit bulunamadi.' });
  }
  console.error('[server] Beklenmeyen hata:', err?.message ?? err);
  res.status(500).json({ error: 'Sunucu hatasi.' });
});

// Beklenmeyen reddedilen promise'ler process'i dusurmesin (savunma amacli).
process.on('unhandledRejection', (reason) => {
  console.error('[server] unhandledRejection:', reason);
});

app.listen(config.port, () => {
  console.log(`[server] Backend ${config.port} portunda calisiyor.`);
  console.log('[server] Not: tarama durumlarini islemek icin ayri process olarak `npm run worker` da calistirilmali.');
  // Acilista egress proxy (Seviye 1 kapsam kilidi) sagligini kontrol et. Ayakta
  // degilse backend YINE de calisir (crash-loop yaratma) ama LOUD uyarir; yeni
  // tarama baslatma zaten orchestrator'da reddedilir.
  checkEgressProxyHealth().then((ok) => {
    if (ok) console.log('[server] Egress proxy (kapsam kilidi) SAGLIKLI.');
    else
      console.warn(
        '[server] ⚠️  UYARI: Egress proxy (kapsam kilidi) AYAKTA DEGIL! ' +
          '`npm run egress-proxy` calistirin. Proxy ayaga kalkana kadar YENI tarama baslatilamaz.',
      );
  });
});
