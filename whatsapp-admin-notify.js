console.log("🚀 [LOG 1] CyberTestify admin-bildirim botu tetiklendi, paketler yükleniyor...");
const { Client, LocalAuth } = require('whatsapp-web.js');
const qrcode = require('qrcode-terminal');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
console.log("📦 [LOG 2] WhatsApp kütüphaneleri hafızaya alındı. (Firebase GEREKMİYOR — veri Postgres'ten okunuyor.)");

// ============================ AYARLAR ============================
// Yakalanan CyberTestify WhatsApp Grubu ID'si
const groupChatId = process.env.WHATSAPP_GROUP_ID || '120363428559293377@g.us';

// CyberTestify Postgres container'ı + DB/kullanıcı adı.
const DB_CONTAINER = process.env.DB_CONTAINER || 'cybertestify-db';
const DB_NAME = process.env.DB_NAME || 'cybertestify';
const DB_USER = process.env.DB_USER || 'cyber';

// Bot cybertestify sunucusundan FARKLI bir makinede çalışıyorsa SSH adresi.
const DB_SSH = process.env.DB_SSH || '';
const DOCKER_BIN = process.env.DOCKER_BIN || '';

// Kaç saniyede bir DB yoklanacak.
const POLL_INTERVAL_MS = Number(process.env.POLL_INTERVAL_MS || 8000);

// İlk açılışta birikmiş raporlar atılsın mı? (false = hayır, sadece yeniler)
const NOTIFY_EXISTING_ON_FIRST_RUN = String(process.env.NOTIFY_EXISTING_ON_FIRST_RUN || 'false') === 'true';

// Bildirilenlerin kalıcı hafızası
const STATE_FILE = path.join(__dirname, 'notified-admin-reports.json');
// =================================================================

// System Chromium path tespiti
function resolveChromiumBin() {
  if (process.env.PUPPETEER_EXECUTABLE_PATH) return process.env.PUPPETEER_EXECUTABLE_PATH;
  const candidates = [
    '/usr/bin/chromium-browser',
    '/usr/bin/chromium',
    '/usr/bin/google-chrome-stable',
    '/usr/bin/google-chrome'
  ];
  for (const c of candidates) {
    try { if (fs.existsSync(c)) return c; } catch (e) { }
  }
  return undefined;
}

// Paket anahtarı -> Türkçe ad
const PACKAGE_NAMES = {
  basit_tarama: 'Basit Tarama',
  ssl_tls: 'SSL/TLS Denetimi',
  header_leak: 'Güvenlik Başlıkları & Bilgi Sızıntısı',
  dns_email: 'DNS & E-posta Güvenliği',
  cms_cve: 'CMS & Bilinen CVE',
  pci_hazirlik: 'PCI-DSS Hazırlık',
  kvkk_hazirlik: 'KVKK Ön Uyum',
  iso27001_hazirlik: 'ISO 27001 Hazırlık',
  cors_cookie: 'CORS & Cookie Güvenliği',
  csp_analiz: 'CSP Analizi',
  subdomain_takeover: 'Subdomain Takeover',
  api_discovery: 'API & Swagger Keşfi',
  injection_verify: 'Zafiyet Doğrulama — Injection',
  idor_verify: 'Zafiyet Doğrulama — IDOR',
  ssrf_verify: 'Zafiyet Doğrulama — SSRF',
  file_upload_verify: 'Zafiyet Doğrulama — Dosya Yükleme',
  business_logic_verify: 'Zafiyet Doğrulama — İş Mantığı',
  race_massassign_verify: 'Zafiyet Doğrulama — Race/Mass Assignment',
  rce_verify: 'Zafiyet Doğrulama — RCE',
  authenticated_scan: 'Authenticated Tarama',
  autonomous_pentest: 'AI Destekli Analiz',
  bundle_surface: 'Dış Yüzey Paketi',
  bundle_recon: 'Keşif Paketi',
  bundle_compliance: 'Uyum Paketi',
  bundle_active_verify: 'Aktif Doğrulama Paketi',
  bundle_full_pentest: 'Tam Kapsamlı Pentest',
};
const prettyPackage = (key) => PACKAGE_NAMES[key] || key || 'Bilinmeyen Paket';

// Kalıcı hafıza
let notified = new Set();
let firstRun = !fs.existsSync(STATE_FILE);
try {
  if (!firstRun) notified = new Set(JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')));
} catch (e) {
  console.warn('⚠️ Durum dosyası okunamadı, sıfırdan başlanıyor:', e.message);
  firstRun = true;
}
function saveState() {
  try { fs.writeFileSync(STATE_FILE, JSON.stringify([...notified]), 'utf8'); }
  catch (e) { console.error('❌ Durum dosyası yazılamadı:', e.message); }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Ban koruması (4-9 sn bekleme)
async function sendSecureMessage(chatId, message) {
  const randomDelay = Math.floor(Math.random() * (9000 - 4000 + 1)) + 4000;
  console.log(`[GÜVENLİK] WhatsApp ban koruması devrede. ${randomDelay / 1000} saniye bekleniyor...`);
  await sleep(randomDelay);
  await client.sendMessage(chatId, message);
}

// Postgres sorgusu
const PENDING_SQL = `
SELECT o.id,
       d.hostname,
       c.email,
       p.key,
       to_char((o."createdAt" AT TIME ZONE 'UTC') AT TIME ZONE 'Europe/Istanbul', 'DD.MM.YYYY HH24:MI')
FROM "Order" o
JOIN "Domain" d      ON d.id = o."domainId"
JOIN "Customer" c    ON c.id = o."customerId"
JOIN "ScanPackage" p ON p.id = o."packageId"
WHERE o.status = 'awaiting_admin_review'
ORDER BY o."createdAt" ASC;`.trim();

function resolveDockerBin() {
  if (DOCKER_BIN) return DOCKER_BIN;
  for (const c of ['/usr/bin/docker', '/usr/local/bin/docker', '/opt/homebrew/bin/docker']) {
    try { if (fs.existsSync(c)) return c; } catch (e) { }
  }
  return 'docker';
}

function fetchPending() {
  return new Promise((resolve, reject) => {
    const psqlArgs = ['exec', '-i', DB_CONTAINER, 'psql', '-U', DB_USER, '-d', DB_NAME, '-t', '-A', '-f', '-'];
    const cmd = DB_SSH ? 'ssh' : resolveDockerBin();
    const sshOpts = [
      '-o', 'BatchMode=yes',
      '-o', 'StrictHostKeyChecking=accept-new',
      '-o', 'ConnectTimeout=10',
      ...(process.env.DB_SSH_KEY ? ['-i', process.env.DB_SSH_KEY] : []),
      ...(process.env.DB_SSH_PORT ? ['-p', process.env.DB_SSH_PORT] : []),
    ];
    const args = DB_SSH ? [...sshOpts, DB_SSH, 'docker', ...psqlArgs] : psqlArgs;

    const child = spawn(cmd, args, { timeout: 20000 });
    let out = '', errout = '';
    child.on('error', (e) => reject(e));
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (errout += d));
    child.on('close', (code) => {
      if (code !== 0) return reject(new Error(errout.trim() || `psql çıkış kodu ${code}`));
      const rows = out
        .split('\n')
        .map((l) => l.trim())
        .filter(Boolean)
        .map((line) => {
          const [id, hostname, email, key, createdAt] = line.split('|');
          return { id, hostname, email, key, createdAt };
        })
        .filter((r) => r.id);
      resolve(rows);
    });
    child.stdin.write(PENDING_SQL + '\n');
    child.stdin.end();
  });
}

// Polling döngüsü
let isProcessing = false;
let lastDbError = null;
async function poll() {
  if (isProcessing) return;
  isProcessing = true;
  try {
    const pending = await fetchPending();
    const pendingIds = new Set(pending.map((r) => r.id));

    if (firstRun && !NOTIFY_EXISTING_ON_FIRST_RUN) {
      pending.forEach((r) => notified.add(r.id));
      firstRun = false;
      saveState();
      console.log(`🌱 [İLK AÇILIŞ] ${pending.length} adet bekleyen rapor atlandı.`);
      return;
    }
    firstRun = false;

    for (const r of pending) {
      if (notified.has(r.id)) continue;
      notified.add(r.id);
      saveState();

      const message =
        `*CyberTestify — Admin Onayı Bekleyen Rapor!*\n\n` +
        `*Hedef:* ${r.hostname}\n` +
        `*Paket:* ${prettyPackage(r.key)}\n` +
        `*Müşteri:* ${r.email}\n` +
        `*Sipariş Zamanı:* ${r.createdAt}\n\n` +
        `_Admin panelinden inceleyip müşteriye açman gerekiyor._`;

      try {
        await sendSecureMessage(groupChatId, message);
        console.log(`🚀 [BİLDİRİM SENT] ${r.hostname} WhatsApp grubuna gönderildi.`);
      } catch (err) {
        notified.delete(r.id);
        saveState();
        console.error('⚠️ WhatsApp mesaj hatası:', err.message);
      }
    }

    let pruned = false;
    for (const id of notified) if (!pendingIds.has(id)) { notified.delete(id); pruned = true; }
    if (pruned) saveState();
  } catch (err) {
    const msg = err.code === 'ENOENT' ? `'${DB_SSH ? 'ssh' : 'docker'}' komutu bulunamadı.` : err.message;
    if (msg !== lastDbError) {
      console.error('❌ DB yoklama hatası:', msg);
      lastDbError = msg;
    }
  } finally {
    isProcessing = false;
  }
}

// ============================ WHATSAPP İSTEMCİSİ ============================
const chromePath = resolveChromiumBin();
const client = new Client({
  authStrategy: new LocalAuth(),
  puppeteer: {
    headless: true,
    executablePath: chromePath,
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-accelerated-2d-canvas',
      '--no-first-run',
      '--no-zygote',
      '--single-process',
      '--disable-gpu'
    ],
  },
});

client.on('qr', (qr) => {
  console.log('📱 [LOG 4] QR Kod üretildi. Terminali genişletip taratın.');
  qrcode.generate(qr, { small: true });
});

let pollTimer = null;
client.on('ready', async () => {
  console.log('✅ [SİSTEM] WhatsApp Bot hazır!');
  console.log(`🎯 Hedef Grup ID: ${groupChatId}`);

  if (!pollTimer) {
    await poll();
    pollTimer = setInterval(poll, POLL_INTERVAL_MS);
  }
});

client.on('disconnected', async (reason) => {
  console.log(`⚠️ Bağlantı koptu (${reason}). Yeniden başlatılıyor...`);
  try {
    await client.initialize();
  } catch (err) {
    process.exit(1);
  }
});

client.initialize();