import './tlsBypass.js'; // EN BAŞTA: bad-cert hedeflere fetch() TypeError ile düşmesin (kapsam ön-kontrolü dahil)
import express from 'express';
import 'express-async-errors'; // async handler'lardaki throw'lari hata middleware'ine yonlendirir
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import type { Request, Response, NextFunction } from 'express';
import { config, validateScopeLockConfig } from './config.js';
import { checkEgressProxyHealth } from './services/egressHealth.js';
import { authRouter } from './routes/auth.js';
import { twofaRouter } from './routes/twofa.js';
import { domainsRouter } from './routes/domains.js';
import { instantRouter } from './routes/instant.js';
import { ordersRouter } from './routes/orders.js';
import { paymentsRouter } from './routes/payments.js';
import { webhooksRouter } from './routes/webhooks.js';
import { reportsRouter } from './routes/reports.js';
import { blogRouter } from './routes/blog.js';
import { internalRouter } from './routes/internal.js';
import { schedulesRouter } from './routes/schedules.js';
import { adminAuthRouter } from './routes/adminAuth.js';
import { adminRouter } from './routes/admin.js';
import { betaRouter } from './routes/beta.js';
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

// Izin verilen origin'ler: apex (cybertestify.com) + gecerli alt alan adlari (www./admin.).
// NOT: app.cybertestify.com ARTIK YOK (Caddy'de kaldirildi) — regex generic oldugu icin ayrica
// islem gerekmez; app. host'undan istek gelmez. FRONTEND_URL/ADMIN_URL ve localhost (dev) de izinli.
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

// (BLOG GÖRSEL YÜKLEME) base64 görsel gövdesi 256kb'ı aşabilir → bu path için ÖNCE büyük-limitli parser
// (req._body set eder, global parser bu path'te tekrar parse etmez). Diğer tüm path'ler 256kb'da kalır.
app.use('/admin/blog-images', express.json({ limit: '6mb' }));
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

// (ÜCRETSİZ ANLIK ÖN-TARAMA) Public + ücretsiz → bot/DDoS-by-proxy için birinci hedef. SIKI limit
// (dk başına 6/IP). Router içinde ayrıca Turnstile + honeypot + tek-eşzamanlı-tarama/IP var.
const instantLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 6,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Çok fazla tarama isteği. Lütfen biraz bekleyip tekrar deneyin.' },
});

app.use('/auth', authLimiter, authRouter);
// (2FA musteri) login-verify + ayarlar + nudge. apiLimiter (300/dk) — status/nudge sayfa yuklemede
// cagirilir; kod brute-force'u zaten HESAP-BAZLI kilit korur (5 yanlis → 15 dk), IP-limit sekonder.
app.use('/twofa', apiLimiter, twofaRouter);
app.use('/domains', apiLimiter, domainsRouter);
app.use('/instant-scan', instantLimiter, instantRouter);
app.use('/orders', apiLimiter, ordersRouter);
app.use('/payments', paymentsRouter);
app.use('/reports', apiLimiter, reportsRouter);
app.use('/blog', apiLimiter, blogRouter); // PUBLIC blog (yalniz published; auth yok)
app.use('/schedules', apiLimiter, schedulesRouter);
// (OTONOM AI RED TEAM — 3b beta kapısı) /unlock kendi sıkı limiter'ını router içinde uygular.
app.use('/beta', apiLimiter, betaRouter);

// --- Ic yonetim paneli (admin) — MUSTERI sisteminden TAMAMEN AYRI ---------
// Opsiyonel IP allowlist (bos ise kisitlama yok) hepsine uygulanir. Login ayri
// (register YOK) + siki authLimiter; veri endpoint'leri requireAdmin arkasinda.
// '/admin/auth' once mount edilir ki '/admin' requireAdmin login'i engellemesin.
app.use('/admin/auth', adminIpAllowlist, authLimiter, adminAuthRouter);
app.use('/admin', adminIpAllowlist, apiLimiter, requireAdmin, adminRouter);

// Ic ag endpoint'leri (egress proxy icin) — CORS/rate-limit yok, secret korumali.
app.use('/internal', internalRouter);

// --- OOB echo (kontrollu gecikme) — SSRF zaman-tabanli tespiti icin ------------------
// ssrf_verify, hedefteki bir "sunucu-tarafli fetch" parametresine BU URL'i verir. Hedef bu
// URL'i sunucu tarafinda cekerse, endpoint ~5sn bekledigi icin HEDEFIN yaniti da gecikir ->
// worker bu gecikmeyi olcup SSRF'i DOLAYLI (orta guven) kanitlar. Endpoint hicbir sey yapmaz,
// veri tutmaz; sadece bekleyip 200 doner. PUBLIC (hedef sunucu cagirir, secret veremez).
const echoLimiter = rateLimit({ windowMs: 60 * 1000, max: 120, standardHeaders: true, legacyHeaders: false });
app.all('/oob/echo/:token', echoLimiter, async (req, res) => {
  const token = String(req.params.token || '');
  if (!/^[a-f0-9]{8,64}$/i.test(token)) return res.status(400).type('text/plain').send('bad token');
  await new Promise((r) => setTimeout(r, 5000)); // kontrollu, sabit gecikme (SSRF sinyali)
  res.status(200).type('text/plain').send('ok');
});

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
