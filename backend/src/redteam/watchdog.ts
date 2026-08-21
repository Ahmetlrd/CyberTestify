/**
 * (RED TEAM — D1/D2/D3/D5 BAĞIMSIZ ALTYAPI WATCHDOG) Orchestrator'ın ANA event-loop'undan/SÜRECİNDEN
 * TAMAMEN AYRI bir OS SÜRECİ olarak çalışır (runner.ts tarafından `detached: true` + `.unref()` ile
 * spawn edilir). KENDİ saatini tutar (spawn anından itibaren) — ana döngü/SSH/docker HERHANGİ BİR
 * yerde asılı kalsa BİLE (3. KEZ tekrarlanan gerçek olay: subtask 9/9 bitti, pipeline campaign/
 * hardening'de 30+ dakika asılı kaldı, panel maliyeti $1.31 gösterirken gerçek harcama $7+'ydi) bu
 * süreç bağımsız çalışmaya devam eder ve cap+60sn'de droplet'i DOĞRUDAN DigitalOcean API ile (SSH'a
 * muhtaç OLMADAN) yok eder.
 *
 * hardkill.ts'in ORTAK çekirdeğini kullanır (rapor-yakala → DOĞRUDAN DO API imha → doğrula) — elle
 * kill-switch butonuyla AYNI, tek, test edilmiş mekanizma (D1: kill-switch de bu modülü kullanır).
 *
 * D3 — Maliyet: iç sayaca (RedTeamJob.costUsd, orchestrator'ın puller'ı yazar) GÜVENMEZ; PentAGI
 * Postgres'inden (msgchains) BAĞIMSIZ okuma yapar ve sapma varsa AYRICA loglar.
 *
 * GÜVENLİK: her dış çağrı (SSH/DO API) KESİN timeout'lu — watchdog'un KENDİSİ asla asılmamalı.
 * SECRET: DO token/DB bağlantısı yalnız process.env'den (parent spawn env'ini inherit eder) — argv/
 * log'a YAZILMAZ. maskSecrets tüm loglarda.
 */
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { prisma } from '../db.js';
import { hardkill } from './hardkill.js';
import { maskSecrets } from './puller.js';

const execFileAsync = promisify(execFile);

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : undefined;
}

const JOB_ID = arg('job-id');
const DROPLET_IP = arg('droplet-ip') ?? null;
const DROPLET_ID = arg('droplet-id') ?? null;
const CAP_SEC = Number(arg('cap-sec') ?? '600');
const CAP_COST = Number(arg('cap-cost') ?? '2');
const TARGET = arg('target') ?? '';
const TARGET_IP = arg('target-ip') ?? '';
const LEVEL = (arg('level') ?? 'S1') as 'S1' | 'S2' | 'S3';
const ENVIRONMENT = (arg('environment') ?? 'test') as 'test' | 'staging' | 'prod';
const SCRIPTS_DIR = arg('scripts-dir') ?? 'infra/pentagi-isolated';
const KEY_PATH = arg('key-path') ?? 'infra/pentagi-isolated/id_pentagi';

const HARD_LIMIT_SEC = CAP_SEC + 60; // D2: "cap+60sn'de ... zorla destroy" — kesin, koşulsuz üst sınır

function log(msg: string): void {
  // eslint-disable-next-line no-console
  console.log(`[watchdog ${new Date().toISOString()}] ${maskSecrets(msg)}`);
}

/** D3: GERÇEK harcamayı PentAGI Postgres'inden (msgchains) BAĞIMSIZ oku — iç sayaca güvenme. */
async function readRealCost(): Promise<number | null> {
  if (!DROPLET_IP) return null;
  try {
    const { stdout } = await execFileAsync(
      'ssh',
      ['-i', KEY_PATH, '-o', 'ConnectTimeout=8', '-o', 'StrictHostKeyChecking=no', '-o', 'BatchMode=yes',
        `root@${DROPLET_IP}`, 'docker exec pgvector psql -U postgres -d pentagidb -tAc "SELECT COALESCE(SUM(usage_cost_in+usage_cost_out),0)::numeric(12,4) FROM msgchains;" 2>/dev/null'],
      { timeout: 10_000 },
    );
    const n = Number(stdout.trim());
    return Number.isFinite(n) ? n : null;
  } catch {
    return null;
  }
}

async function triggerHardkill(reason: string): Promise<void> {
  log(`HARDKILL tetiklendi: ${reason}`);
  const result = await hardkill({
    dropletIp: DROPLET_IP, dropletId: DROPLET_ID, scriptsDir: SCRIPTS_DIR, keyPath: KEY_PATH,
    target: TARGET, targetIp: TARGET_IP, level: LEVEL, environment: ENVIRONMENT, reason,
  });
  if (JOB_ID) {
    await prisma.redTeamJob.update({
      where: { id: JOB_ID },
      data: {
        status: 'aborted', phase: 'teardown', finishedAt: new Date(),
        error: `watchdog-hardkill: ${reason}${result.destroyError ? ` (imha hatası: ${result.destroyError})` : ''}`,
        ...(result.liveCost != null ? { costUsd: result.liveCost } : {}),
        ...(result.report ? { reportJson: result.report as any } : {}),
        ...(result.rawFlow ? { rawFlowJson: result.rawFlow as any } : {}),
        ...(result.transcript ? { transcriptJson: result.transcript as any } : {}),
      },
    }).catch((e) => log(`DB yazımı başarısız: ${String(e)}`));
  }
  log(`HARDKILL tamam — rapor ${result.report ? `ÜRETİLDİ (kanıtlı ${result.report.counts.kanitli}, belirsiz ${result.report.counts.belirsiz})` : 'üretilemedi'}, imha=${result.destroyRequested ? (result.destroyError ?? 'OK') : 'İSTENMEDİ'}, doğrulama=${result.verified}`);
}

async function main(): Promise<void> {
  if (!JOB_ID || !DROPLET_IP) {
    log('eksik zorunlu argüman (job-id/droplet-ip) — watchdog başlatılamadı, çıkılıyor');
    return;
  }
  log(`başlatıldı — job=${JOB_ID} droplet=${DROPLET_IP} cap=${CAP_SEC}s (sert sınır +60s=${HARD_LIMIT_SEC}s) capCost=$${CAP_COST}`);
  const t0 = Date.now(); // KENDİ SAATİ — ana döngüden/orchestrator'dan TAMAMEN bağımsız

  // eslint-disable-next-line no-constant-condition
  while (true) {
    await new Promise((r) => setTimeout(r, 5000));
    const elapsed = (Date.now() - t0) / 1000;

    try {
      const job = await prisma.redTeamJob.findUnique({ where: { id: JOB_ID }, select: { status: true, costUsd: true } });
      if (job && ['completed', 'failed', 'torn_down', 'aborted'].includes(job.status)) {
        log(`job zaten sonlanmış (status=${job.status}) — watchdog sessizce çıkıyor`);
        return;
      }
      // D3: gerçek harcamayı BAĞIMSIZ oku; iç sayaçtan sapma varsa AYRICA logla (kanıt).
      const liveCost = await readRealCost();
      if (liveCost != null) {
        const cached = job?.costUsd ?? null;
        if (cached != null && Math.abs(liveCost - cached) > Math.max(0.3, cached * 0.5)) {
          log(`⚠ SAPMA TESPİT EDİLDİ: iç sayaç $${cached.toFixed(4)} vs BAĞIMSIZ okunan GERÇEK harcama $${liveCost.toFixed(4)} — iç sayaç güvenilmez olduğunun kanıtı`);
        }
        if (liveCost >= CAP_COST) {
          await triggerHardkill(`MALİYET cap aşıldı (bağımsız okunan gerçek harcama $${liveCost.toFixed(4)} >= cap $${CAP_COST})`);
          return;
        }
      }
    } catch (e) {
      log(`DB kontrolü başarısız (devam ediliyor, watchdog bunun için durmaz): ${String(e)}`);
    }

    if (elapsed >= CAP_SEC) {
      await triggerHardkill(`SÜRE cap (${CAP_SEC}s) — watchdog kendi bağımsız saatiyle tetiklendi (ana orchestrator döngüsü yanıt veriyor mu vermiyor mu ÖNEMLİ DEĞİL)`);
      return;
    }
    if (elapsed >= HARD_LIMIT_SEC) {
      await triggerHardkill(`kesin süre sınırı (cap+60s=${HARD_LIMIT_SEC}s) aşıldı — son çare`);
      return;
    }
  }
}

main().catch((e) => { log(`FATAL (beklenmeyen hata): ${String(e)}`); process.exit(1); });
