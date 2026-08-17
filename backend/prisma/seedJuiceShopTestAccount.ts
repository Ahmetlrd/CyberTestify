/**
 * (Tam Kapsamlı Pentest — FAZ B) test.cybertestify.com (OWASP Juice Shop) için SABİT test hesapları seed'i.
 *
 * Neden: FAZ B login otomasyonunu uçtan uca test etmek için deterministik, sabit hesaplar gerekir.
 * Juice Shop verisi container recreate olunca sıfırlanır (SQLite imaj içi) — bu script idempotent:
 * her hesap için önce login dener; olmazsa Juice Shop'un kendi kayıt API'siyle (POST /api/Users) oluşturur.
 *
 * ÇALIŞTIR (container recreate sonrası tekrar çalıştırılabilir):
 *   docker exec cybertestify-api npx tsx prisma/seedJuiceShopTestAccount.ts
 * Opsiyonel override: -e JUICE_TEST_EMAIL=... -e JUICE_TEST_PASSWORD=... (yalnız ilk/birincil hesabı ezer)
 *
 * NOT: Bu bir DB seed'i DEĞİL; harici test hedefine (kendi barındırdığımız Juice Shop) yazar.
 */
const HOST = process.env.JUICE_TEST_HOST || 'test.cybertestify.com';
const base = `https://${HOST}`;

// Seed edilecek test hesapları. Birincisi otomasyonun varsayılanı (güçlü şifre); ikincisi hatırlaması
// kolay (e-posta = şifre) — kullanıcının /order test-hesabı alanına elle girebileceği pratik hesap.
const ACCOUNTS: Array<{ email: string; password: string }> = [
  { email: process.env.JUICE_TEST_EMAIL || 'pentest-fixture@cybertestify.com', password: process.env.JUICE_TEST_PASSWORD || 'CyberTestify!Fixture#2026' },
  { email: 'test@cybertestify.com', password: 'test@cybertestify.com' },
];

async function tryLogin(email: string, password: string): Promise<boolean> {
  try {
    const res = await fetch(`${base}/rest/user/login`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    if (res.status !== 200) return false;
    const j: any = await res.json().catch(() => ({}));
    return typeof j?.authentication?.token === 'string' && j.authentication.token.length > 20;
  } catch { return false; }
}

async function register(email: string, password: string): Promise<boolean> {
  try {
    const res = await fetch(`${base}/api/Users`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email, password, passwordRepeat: password, securityQuestion: { id: 1 }, securityAnswer: 'cybertestify' }),
    });
    return res.status === 200 || res.status === 201;
  } catch { return false; }
}

async function ensureAccount(email: string, password: string): Promise<boolean> {
  if (await tryLogin(email, password)) { console.log(`[seed] ${email}: zaten var ve giriş yapabiliyor — atlandı.`); return true; }
  console.log(`[seed] ${email}: giriş yapılamadı; hesap oluşturuluyor (POST /api/Users)...`);
  const created = await register(email, password);
  console.log(`[seed] ${email}: oluşturma isteği ${created ? 'OK' : 'BAŞARISIZ (zaten var olabilir)'}`);
  const ok = await tryLogin(email, password);
  console.log(`[seed] ${email}: doğrulama (login) ${ok ? 'BAŞARILI ✓' : 'BAŞARISIZ ✗'}`);
  return ok;
}

(async () => {
  console.log(`[seed] Juice Shop test hesapları @ ${HOST} (şifreler gösterilmez)`);
  let allOk = true;
  for (const a of ACCOUNTS) allOk = (await ensureAccount(a.email, a.password)) && allOk;
  if (!allOk) process.exit(1);
})();
