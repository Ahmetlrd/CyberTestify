/**
 * (Tam Kapsamlı Pentest — FAZ B) test.cybertestify.com (OWASP Juice Shop) için SABİT test hesabı seed'i.
 *
 * Neden: FAZ B login otomasyonunu uçtan uca test etmek için deterministik, sabit bir hesap gerekir.
 * Juice Shop verisi container recreate olunca sıfırlanır (SQLite imaj içi) — bu script idempotent:
 * önce login dener; olmazsa Juice Shop'un kendi kayıt API'siyle (POST /api/Users) oluşturur.
 *
 * ÇALIŞTIR (container recreate sonrası tekrar çalıştırılabilir):
 *   docker exec cybertestify-api npx tsx prisma/seedJuiceShopTestAccount.ts
 * Opsiyonel override: -e JUICE_TEST_EMAIL=... -e JUICE_TEST_PASSWORD=...
 *
 * NOT: Bu bir DB seed'i DEĞİL; harici test hedefine (kendi barındırdığımız Juice Shop) yazar.
 */
const HOST = process.env.JUICE_TEST_HOST || 'test.cybertestify.com';
const EMAIL = process.env.JUICE_TEST_EMAIL || 'pentest-fixture@cybertestify.com';
const PASSWORD = process.env.JUICE_TEST_PASSWORD || 'CyberTestify!Fixture#2026';
const base = `https://${HOST}`;

async function tryLogin(): Promise<boolean> {
  try {
    const res = await fetch(`${base}/rest/user/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: EMAIL, password: PASSWORD }),
    });
    if (res.status !== 200) return false;
    const j: any = await res.json().catch(() => ({}));
    return typeof j?.authentication?.token === 'string' && j.authentication.token.length > 20;
  } catch { return false; }
}

async function register(): Promise<boolean> {
  try {
    const res = await fetch(`${base}/api/Users`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: EMAIL, password: PASSWORD, passwordRepeat: PASSWORD, securityQuestion: { id: 1 }, securityAnswer: 'cybertestify' }),
    });
    return res.status === 200 || res.status === 201;
  } catch { return false; }
}

(async () => {
  console.log(`[seed] Juice Shop test hesabı: ${EMAIL} @ ${HOST} (şifre gösterilmez)`);
  if (await tryLogin()) { console.log('[seed] Hesap zaten var ve giriş yapabiliyor — atlandı.'); return; }
  console.log('[seed] Giriş yapılamadı; hesap oluşturuluyor (POST /api/Users)...');
  const created = await register();
  console.log(`[seed] Oluşturma isteği: ${created ? 'OK' : 'BAŞARISIZ (zaten var olabilir)'}`);
  // Doğrula
  const ok = await tryLogin();
  console.log(`[seed] Doğrulama (login): ${ok ? 'BAŞARILI ✓ token alındı' : 'BAŞARISIZ ✗'}`);
  if (!ok) process.exit(1);
})();
