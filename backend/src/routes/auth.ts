import { Router } from 'express';
import { z, type ZodError } from 'zod';
import { zodError } from '../httpErrors.js';
import crypto from 'node:crypto';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { prisma } from '../db.js';
import { config } from '../config.js';
import { sendPasswordReset, sendEmailVerification } from '../services/mailer.js';
import { requireAuth } from '../middleware/auth.js';
import { verifyTurnstile } from '../services/turnstile.js';

export const authRouter = Router();

// (çok-bölge) kullanıcıya dönen hata metni bölgeye göre — tr/de/en.
// (DUZELTME) Onceden YALNIZ req.body.region okunuyordu; GET uclarinin (ornek: /auth/me) govdesi
// olmadigi icin dil HER ZAMAN 'tr'ye dusuyor, /de /en kullanicisina Turkce hata gidiyordu.
// Sirasiyla: govde -> query -> X-Region basligi (istemci her istekte gonderir) -> Accept-Language.
const aLoc = (req: { body?: any; query?: any; headers?: any }): string => {
  const pick = (v: unknown) => (typeof v === 'string' && v ? v : '');
  const hdr = req.headers ? pick(req.headers['x-region']) : '';
  const al = req.headers ? pick(req.headers['accept-language']).slice(0, 2).toLowerCase() : '';
  const r = pick(req.body?.region) || pick(req.query?.region) || hdr || al || 'tr';
  return r === 'de' ? 'de' : r === 'en' ? 'en' : 'tr';
};
const M = (loc: string, tr: string, de: string, en: string): string => (loc === 'de' ? de : loc === 'en' ? en : tr);

// (ÇOK-DİLLİ VALIDASYON) Zod şemalarındaki mesajlar Türkçe sabittir; login/register 400 yanıtı locale'e
// göre çevrilir (aksi halde /de-/en kullanıcı Türkçe "Şifre en az 8 karakter..." görüyordu). İlk hatalı
// alana göre M() ile çevrilir.
function authValidationError(err: ZodError, loc: string): string {
  const field = String(err.issues[0]?.path?.[0] ?? '');
  if (field === 'email') return M(loc, 'Geçerli bir e-posta adresi girin.', 'Bitte geben Sie eine gültige E-Mail-Adresse ein.', 'Enter a valid e-mail address.');
  if (field === 'password') return M(loc, 'Şifre en az 8 karakter olmalıdır.', 'Das Passwort muss mindestens 8 Zeichen lang sein.', 'The password must be at least 8 characters.');
  if (field === 'termsAccepted') return M(loc, 'Kullanım Koşulları ve KVKK Aydınlatma Metni onaylanmalıdır.', 'Die Nutzungsbedingungen und die Datenschutzerklärung müssen akzeptiert werden.', 'You must accept the Terms of Use and the Privacy Notice.');
  return M(loc, 'Girdiğiniz bilgiler geçersiz. Lütfen kontrol edip tekrar deneyin.', 'Die eingegebenen Daten sind ungültig. Bitte überprüfen Sie sie und versuchen Sie es erneut.', 'The information you entered is invalid. Please check it and try again.');
}

// E-posta dogrulama kodu uretir (6 hane), hash'ini + 15dk gecerlilik kaydeder ve mail atar.
const sha256 = (s: string) => crypto.createHash('sha256').update(s).digest('hex');
async function issueEmailVerification(customerId: string, email: string): Promise<void> {
  const code = String(crypto.randomInt(0, 1_000_000)).padStart(6, '0'); // 000000-999999
  await prisma.customer.update({
    where: { id: customerId },
    data: { emailVerifyCodeHash: sha256(code), emailVerifyCodeExpiry: new Date(Date.now() + 15 * 60 * 1000) },
  });
  await sendEmailVerification(email, code); // mailer no-throw
}

const credsSchema = z.object({
  email: z.string().email('Geçerli bir e-posta adresi girin.'),
  password: z.string().min(8, 'Şifre en az 8 karakter olmalıdır.'),
});

const registerSchema = credsSchema.extend({
  // Kullanim Kosullari + KVKK Aydinlatma metninin okundugunun teyidi (zorunlu).
  termsAccepted: z.literal(true, {
    errorMap: () => ({ message: 'Kullanim Kosullari ve KVKK Aydinlatma Metni onaylanmalidir.' }),
  }),
  turnstileToken: z.string().max(4000).optional(), // (BOT) fake-hesap botlarina karsi Turnstile.
});

authRouter.post('/register', async (req, res) => {
  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: authValidationError(parsed.error, aLoc(req)) });

  // (BOT KORUMASI) fake/otomatik hesap acilmasina karsi insan dogrulamasi (authLimiter'a EK).
  if (!(await verifyTurnstile(parsed.data.turnstileToken, (req.ip || '').toString()))) {
    return res.status(403).json({ error: M(aLoc(req), 'İnsan doğrulaması gerekli. Lütfen doğrulama kutusunu tamamlayın.', 'Menschliche Verifizierung erforderlich. Bitte schließen Sie die Verifizierungsbox ab.', 'Human verification required. Please complete the verification box.') });
  }

  const passwordHash = await bcrypt.hash(parsed.data.password, 12);
  let customer;
  try {
    customer = await prisma.customer.create({
      data: {
        email: parsed.data.email,
        passwordHash,
        termsAcceptedAt: new Date(),
        termsVersion: config.legalVersion,
      },
    });
  } catch (err: any) {
    // Prisma P2002: e-posta ZATEN kayitli.
    if (err?.code === 'P2002') {
      // UX: girilen sifre o hesabin GERCEK sifresiyle eslesiyorsa, kullaniciyi
      // surtunmeden DOGRUDAN giris yaptir (login akisiyla ayni token). Bu yol da
      // /auth authLimiter'i altinda (login ile ayni) -> enumeration/brute-force korumasi geçerli.
      const existing = await prisma.customer.findUnique({ where: { email: parsed.data.email } });
      if (existing && (await bcrypt.compare(parsed.data.password, existing.passwordHash))) {
        // Mevcut hesap — dogrulama akisi ETKILEMEZ (eski hesaplar migration ile verified).
        const token = jwt.sign({ sub: existing.id }, config.jwtSecret, { expiresIn: '90d' });
        return res.json({ token, autoLogin: true, emailVerified: existing.emailVerified });
      }
      // Sifre yanlis -> mevcut dostane mesaj (degistirilmedi).
      return res.status(409).json({ error: M(aLoc(req), 'Bu e-posta ile zaten bir hesap var. Lütfen giriş yapın.', 'Mit dieser E-Mail existiert bereits ein Konto. Bitte melden Sie sich an.', 'An account with this e-mail already exists. Please log in.') });
    }
    throw err;
  }

  // YENI hesap — emailVerified=false (schema varsayilani). 6 haneli dogrulama kodu gonder.
  await issueEmailVerification(customer.id, customer.email);
  const token = jwt.sign({ sub: customer.id }, config.jwtSecret, { expiresIn: '90d' });
  res.json({ token, emailVerified: false });
});

authRouter.post('/login', async (req, res) => {
  const parsed = credsSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: authValidationError(parsed.error, aLoc(req)) });

  const customer = await prisma.customer.findUnique({ where: { email: parsed.data.email } });
  if (!customer || !(await bcrypt.compare(parsed.data.password, customer.passwordHash))) {
    return res.status(401).json({ error: M(aLoc(req), 'E-posta veya şifre hatalı.', 'E-Mail oder Passwort ist falsch.', 'E-mail or password is incorrect.') });
  }

  // (2FA — OPT-IN) Musteri 2FA'yi actiysa: sifre dogru → ikinci faktore gec (tam token BURADA verilmez).
  // 2FA kapali musteri BUGUNKU gibi girer (regresyonsuz).
  if (customer.twofaEnabled) {
    const stageToken = jwt.sign({ sub: customer.id, typ: 'cust-2fa' }, config.jwtSecret, { expiresIn: '10m' });
    return res.json({ twofaRequired: true, stageToken });
  }

  const token = jwt.sign({ sub: customer.id }, config.jwtSecret, { expiresIn: '90d' });
  res.json({ token });
});

// --- (A) Sifre sifirlama ------------------------------------------------------
// Her iki endpoint de '/auth' altinda oldugu icin authLimiter (rate-limit) korumasindadir
// → brute-force / spam-mail engellenir. Enumeration korumasi: forgot HER ZAMAN 200 doner.

const emailSchema = z.object({ email: z.string().email('Geçerli bir e-posta adresi girin.') });
const resetSchema = z.object({ token: z.string().min(20, 'Sıfırlama bağlantısı geçersiz veya süresi dolmuş.'), password: z.string().min(8, 'Şifre en az 8 karakter olmalıdır.') });

authRouter.post('/forgot-password', async (req, res) => {
  const parsed = emailSchema.safeParse(req.body);
  // E-posta ENUMERATION korumasi: hesap var/yok fark etmeksizin ayni generic yanit.
  if (parsed.success) {
    const customer = await prisma.customer.findUnique({ where: { email: parsed.data.email } });
    if (customer) {
      const rawToken = crypto.randomBytes(32).toString('hex'); // duz token yalnizca mailde
      const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex'); // DB'de yalnizca hash
      const resetTokenExpiry = new Date(Date.now() + 60 * 60 * 1000); // 1 saat
      await prisma.customer.update({ where: { id: customer.id }, data: { resetTokenHash: tokenHash, resetTokenExpiry } });
      const url = `${config.frontendUrl}/reset-password?token=${rawToken}`;
      await sendPasswordReset(customer.email, url); // mailer no-throw; hata akisi bozmaz
    }
  }
  return res.json({ ok: true });
});

authRouter.post('/reset-password', async (req, res) => {
  const parsed = resetSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: M(aLoc(req), 'Geçersiz istek. Şifre en az 8 karakter olmalıdır.', 'Ungültige Anfrage. Das Passwort muss mindestens 8 Zeichen lang sein.', 'Invalid request. The password must be at least 8 characters.') });
  const tokenHash = crypto.createHash('sha256').update(parsed.data.token).digest('hex');
  const customer = await prisma.customer.findFirst({
    where: { resetTokenHash: tokenHash, resetTokenExpiry: { gt: new Date() } },
  });
  if (!customer) return res.status(400).json({ error: M(aLoc(req), 'Bağlantı geçersiz veya süresi dolmuş. Lütfen yeniden sıfırlama talep edin.', 'Der Link ist ungültig oder abgelaufen. Bitte fordern Sie eine neue Zurücksetzung an.', 'The link is invalid or has expired. Please request a new reset.') });
  const passwordHash = await bcrypt.hash(parsed.data.password, 12);
  await prisma.customer.update({
    where: { id: customer.id },
    data: { passwordHash, resetTokenHash: null, resetTokenExpiry: null }, // token TEK KULLANIMLIK
  });
  // Surtunmesiz: yeni sifreyle otomatik giris token'i.
  const token = jwt.sign({ sub: customer.id }, config.jwtSecret, { expiresIn: '90d' });
  return res.json({ ok: true, token });
});

// --- (0) E-posta dogrulama -----------------------------------------------------
// Hepsi '/auth' altinda → authLimiter (rate-limit). verify/resend requireAuth ister
// (kayit sonrasi kullanicinin token'i vardir; dashboard erisimi kisitlanmaz, yalniz
// satin alma emailVerified sart — bkz orders.ts).

authRouter.get('/me', requireAuth, async (req, res) => {
  const c = await prisma.customer.findUnique({ where: { id: req.customerId! }, select: { email: true, emailVerified: true } });
  // (DUZELTME) Token gecerli ama hesap silinmis/yok = OLU OTURUM. 404 dondurulunce istemci bunu
  // "kimlik hatasi" saymiyor, olu token'i SILMIYOR ve kullanici /profile'da kilitli kaliyordu.
  // 401 dogru semantik: api.ts token'i temizler, kullanici giris ekranina duser.
  if (!c) return res.status(401).json({ sessionInvalid: true, error: M(aLoc(req), 'Oturumunuz artık geçerli değil. Lütfen tekrar giriş yapın.', 'Ihre Sitzung ist nicht mehr gültig. Bitte melden Sie sich erneut an.', 'Your session is no longer valid. Please sign in again.') });
  res.json(c);
});

const codeSchema = z.object({ code: z.string().regex(/^\d{6}$/, '6 haneli doğrulama kodunu girin.') });

authRouter.post('/verify-email', requireAuth, async (req, res) => {
  const parsed = codeSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: M(aLoc(req), 'Kod 6 haneli olmalıdır.', 'Der Code muss 6-stellig sein.', 'The code must be 6 digits.') });
  const c = await prisma.customer.findUnique({ where: { id: req.customerId! } });
  // (DUZELTME) Token gecerli ama hesap silinmis/yok = OLU OTURUM. 404 dondurulunce istemci bunu
  // "kimlik hatasi" saymiyor, olu token'i SILMIYOR ve kullanici /profile'da kilitli kaliyordu.
  // 401 dogru semantik: api.ts token'i temizler, kullanici giris ekranina duser.
  if (!c) return res.status(401).json({ sessionInvalid: true, error: M(aLoc(req), 'Oturumunuz artık geçerli değil. Lütfen tekrar giriş yapın.', 'Ihre Sitzung ist nicht mehr gültig. Bitte melden Sie sich erneut an.', 'Your session is no longer valid. Please sign in again.') });
  if (c.emailVerified) return res.json({ ok: true, emailVerified: true }); // zaten dogrulanmis
  if (!c.emailVerifyCodeHash || !c.emailVerifyCodeExpiry || c.emailVerifyCodeExpiry < new Date()) {
    return res.status(400).json({ error: M(aLoc(req), 'Kodun süresi dolmuş. Lütfen yeni kod isteyin.', 'Der Code ist abgelaufen. Bitte fordern Sie einen neuen Code an.', 'The code has expired. Please request a new code.') });
  }
  if (sha256(parsed.data.code) !== c.emailVerifyCodeHash) {
    return res.status(400).json({ error: M(aLoc(req), 'Kod hatalı. Lütfen tekrar deneyin.', 'Der Code ist falsch. Bitte versuchen Sie es erneut.', 'The code is incorrect. Please try again.') });
  }
  await prisma.customer.update({
    where: { id: c.id },
    data: { emailVerified: true, emailVerifyCodeHash: null, emailVerifyCodeExpiry: null },
  });
  res.json({ ok: true, emailVerified: true });
});

authRouter.post('/resend-verification', requireAuth, async (req, res) => {
  const c = await prisma.customer.findUnique({ where: { id: req.customerId! }, select: { id: true, email: true, emailVerified: true } });
  // (DUZELTME) Token gecerli ama hesap silinmis/yok = OLU OTURUM. 404 dondurulunce istemci bunu
  // "kimlik hatasi" saymiyor, olu token'i SILMIYOR ve kullanici /profile'da kilitli kaliyordu.
  // 401 dogru semantik: api.ts token'i temizler, kullanici giris ekranina duser.
  if (!c) return res.status(401).json({ sessionInvalid: true, error: M(aLoc(req), 'Oturumunuz artık geçerli değil. Lütfen tekrar giriş yapın.', 'Ihre Sitzung ist nicht mehr gültig. Bitte melden Sie sich erneut an.', 'Your session is no longer valid. Please sign in again.') });
  if (c.emailVerified) return res.json({ ok: true, emailVerified: true });
  await issueEmailVerification(c.id, c.email);
  res.json({ ok: true });
});

// --- Google OAuth ("Google ile devam et") — Authorization Code akisi -----------
// /google/start → Google consent → /google/callback (backend, secret ile code exchange)
// → hesap eslestir/olustur → bizim JWT'yi frontend'e FRAGMENT ile ilet (log/referrer'a sizmaz).
// GOOGLE_CLIENT_ID yoksa akis kapalidir (frontend butonu da gizli).

authRouter.get('/google/start', (req, res) => {
  if (!config.google.clientId) return res.status(503).send('Google girişi yapılandırılmadı.');
  const next = typeof req.query.next === 'string' ? req.query.next : '/verify';
  // state: imzali + kisa omurlu (CSRF); 'next' hedefini de tasir (stateless).
  const state = jwt.sign({ next, n: crypto.randomBytes(8).toString('hex') }, config.jwtSecret, { expiresIn: '10m' });
  const params = new URLSearchParams({
    client_id: config.google.clientId,
    redirect_uri: config.google.redirectUri,
    response_type: 'code',
    scope: 'openid email profile',
    state,
    prompt: 'select_account',
  });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`);
});

authRouter.get('/google/callback', async (req, res) => {
  const fail = () => res.redirect(`${config.frontendUrl}/login?error=google`);
  try {
    const code = typeof req.query.code === 'string' ? req.query.code : '';
    const stateRaw = typeof req.query.state === 'string' ? req.query.state : '';
    if (!code || !stateRaw) return fail();
    let next = '/verify';
    try {
      const s = jwt.verify(stateRaw, config.jwtSecret) as { next?: string };
      if (typeof s.next === 'string' && s.next.startsWith('/')) next = s.next; // yalniz ic yol
    } catch {
      return fail();
    }

    // code → token exchange (client_secret sunucuda; asla frontend'e/log'a gitmez).
    const tokenResp = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: config.google.clientId,
        client_secret: config.google.clientSecret,
        redirect_uri: config.google.redirectUri,
        grant_type: 'authorization_code',
      }).toString(),
    });
    if (!tokenResp.ok) {
      console.error('[google] token exchange basarisiz:', tokenResp.status);
      return fail();
    }
    const tok = (await tokenResp.json()) as { access_token?: string };
    if (!tok.access_token) return fail();

    const uiResp = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { authorization: `Bearer ${tok.access_token}` },
    });
    if (!uiResp.ok) return fail();
    const ui = (await uiResp.json()) as { sub?: string; email?: string; email_verified?: boolean; name?: string };
    const email = (ui.email ?? '').trim().toLowerCase();
    if (!email || !ui.sub) return fail();

    // HESAP ESLESTIRME: e-posta zaten varsa BAGLA (sifre korunur); yoksa YENI hesap.
    let customer = await prisma.customer.findUnique({ where: { email } });
    if (customer) {
      const data: Record<string, unknown> = {};
      if (!customer.googleId) data.googleId = ui.sub; // bu hesaba Google ile de giris baglanti
      if (!customer.emailVerified) data.emailVerified = true; // Google e-postayi dogruladi
      if (!customer.fullName && ui.name) data.fullName = ui.name;
      if (Object.keys(data).length) customer = await prisma.customer.update({ where: { id: customer.id }, data });
    } else {
      // Sifresiz (Google-only) hesap: kullanicinin bilmedigi rastgele hash (sifreyle giris yapamaz;
      // isterse ileride "sifremi unuttum" ile belirleyebilir). Google giris => emailVerified true,
      // dogrulama-kodu akisina HIC girmez. Google girisi Kullanim Kosullari kabulu sayilir.
      const randomHash = await bcrypt.hash(crypto.randomBytes(24).toString('hex'), 12);
      customer = await prisma.customer.create({
        data: {
          email,
          passwordHash: randomHash,
          googleId: ui.sub,
          emailVerified: ui.email_verified !== false,
          fullName: ui.name ?? null,
          termsAcceptedAt: new Date(),
          termsVersion: config.legalVersion,
        },
      });
    }

    // (2FA — OPT-IN) Google girisi de 2. faktore tabidir: 2FA acıksa tam token yerine stage token
    // ile 2FA kod ekranina yonlendir (frontend google/done twofa=1'i algilar).
    if (customer.twofaEnabled) {
      const stageToken = jwt.sign({ sub: customer.id, typ: 'cust-2fa' }, config.jwtSecret, { expiresIn: '10m' });
      return res.redirect(`${config.frontendUrl}/auth/google/done#twofa=1&stageToken=${stageToken}&next=${encodeURIComponent(next)}`);
    }
    const token = jwt.sign({ sub: customer.id }, config.jwtSecret, { expiresIn: '90d' });
    // Token'i FRAGMENT ile frontend origin'ine tasi (localStorage orada). Query DEGIL → sunucu
    // loglarina / Referer'a sizmaz. Kucuk bir sayfa token'i saklayip 'next'e yonlendirir.
    return res.redirect(`${config.frontendUrl}/auth/google/done#token=${token}&next=${encodeURIComponent(next)}`);
  } catch (err) {
    console.error('[google] callback hata:', err);
    return fail();
  }
});
