/**
 * (OTONOM RED TEAM — CANLI RUNNER) runPipeline'ı GERÇEK exec + onStep ile çalıştırır.
 * Faz-farkında exec: provision/teardown = prod host'ta LOKAL (DO token process.env'den, ARGA/LOG'A
 * yazılmaz); droplet fazları (setup/harden/verify/campaign/bind) = SSH kontrol-kanalı (droplet IP
 * provision sonrası state.json'dan). onStep → persistStep (faz+log DB'ye). Campaign sırasında puller
 * döngüsü (canlı ilerleme/maliyet). teardown finally (orchestrator'da).
 *
 * SECRET: DO token yalnız child env'e geçer (process.env), ASLA arg/log/string'e yazılmaz. LLM anahtarı
 * droplet'e SSH-stdin ile akıtılır (dosyaya, chmod 600), değeri LOG'lanmaz. maskSecrets tüm loglarda.
 *
 * `dryRun`: hiçbir DO/SSH komutu çalışmaz — zincir + persist yolu doğrulanır (maliyet YOK).
 */
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { prisma } from '../db.js';
import { runPipeline, LEVEL_CFG, type ExecFn, type Level, type Env } from './orchestrator.js';
import { makeSshExec, redteamKeyPath } from './controlChannel.js';
import { persistStep, persistPull } from './observability.js';
import { pullOnce, maskSecrets } from './puller.js';
import { nodeResolver } from './targetGuard.js';

const execFileAsync = promisify(execFile);

/** Infra scriptleri kökü (prod: /opt/cybertestify/app/infra/pentagi-isolated). */
function scriptsDir(): string {
  return process.env.REDTEAM_SCRIPTS_DIR ?? 'infra/pentagi-isolated';
}

/** Prod host'ta LOKAL komut (provision/teardown). DO token child ENV'den (arga/log'a KONMAZ). */
const localExec: ExecFn = async (cmd, args) => {
  // Yorum-argümanları (# ile başlayan meta) at — bunlar orchestrator'ın plan notları.
  const realArgs = args.filter((a) => !a.startsWith('#'));
  try {
    const { stdout, stderr } = await execFileAsync(cmd, realArgs, {
      timeout: 240_000,
      maxBuffer: 8 * 1024 * 1024,
      env: process.env, // DIGITAL_OCEAN_API_KEY buradan gelir; string'e YAZILMAZ
    });
    return { code: 0, stdout, stderr };
  } catch (e: any) {
    // Hata detayını GÖRÜNÜR yap: provision.sh ilerlemeyi stdout'a basar, gerçek hata stderr'de olabilir
    // — ikisini birleştir ki panelde "neden patladı" görünsün (maskeleme persistStep'te uygulanır).
    const combined = [(e?.stdout ?? '').toString(), (e?.stderr ?? '').toString(), e?.stderr ? '' : String(e?.message ?? e)]
      .filter(Boolean).join('\n').trim();
    return { code: typeof e?.code === 'number' ? e.code : 1, stdout: e?.stdout ?? '', stderr: combined };
  }
};

/** LLM anahtarını droplet'e SSH-STDIN ile akıt (dosyaya; değeri ARG/LOG'a KONMAZ). setup öncesi. */
async function deliverLlmKeyToDroplet(ip: string): Promise<void> {
  const key = process.env.LLM_API_KEY ?? process.env.ANTHROPIC_API_KEY ?? process.env.ADVISORY_LLM_API_KEY; // env-only; asla loglanmaz
  if (!key) throw new Error('LLM anahtarı env yok (LLM_API_KEY/ANTHROPIC_API_KEY)');
  await new Promise<void>((resolve, reject) => {
    const p = spawn(
      'ssh',
      ['-i', redteamKeyPath(), '-o', 'StrictHostKeyChecking=no', '-o', 'BatchMode=yes', `root@${ip}`,
        'mkdir -p /opt/pentagi-run && cat > /opt/pentagi-run/llmkey && chmod 600 /opt/pentagi-run/llmkey'],
      { stdio: ['pipe', 'ignore', 'pipe'] },
    );
    let err = '';
    p.stderr.on('data', (d) => (err += d));
    p.on('error', reject);
    p.on('close', (c) => (c === 0 ? resolve() : reject(new Error(`llmkey aktarım exit ${c} ${err.slice(0, 120)}`))));
    p.stdin.write(key); // stdin ile akar — arg/log'da DEĞİL
    p.stdin.end();
  });
}

const SSH_OPTS = ['-o', 'StrictHostKeyChecking=no', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10'];
const DROPLET_DIR = '/opt/pentagi-run';

/**
 * Droplet SSH-HAZIR olana kadar bekle (boot + sshd). Tek-seferde deneme yerine poll+backoff.
 * "Connection refused/timeout" boot sırasında normaldir; sshd cevap verince (exit 0) döner.
 */
async function waitForSsh(ip: string, maxMs = 180_000): Promise<boolean> {
  const start = Date.now();
  let delay = 5000;
  while (Date.now() - start < maxMs) {
    try {
      await execFileAsync('ssh', ['-i', redteamKeyPath(), ...SSH_OPTS, `root@${ip}`, 'true'], { timeout: 12_000 });
      return true; // sshd cevap verdi
    } catch {
      await new Promise((r) => setTimeout(r, delay));
      delay = Math.min(delay + 3000, 12_000); // 5→8→11→12s backoff
    }
  }
  return false;
}

/** Droplet-scripts'i droplet'e KOPYALA (scp) + çalıştırılabilir yap. provision sonrası bir kez. */
async function pushDropletScripts(ip: string): Promise<void> {
  const dir = scriptsDir();
  await execFileAsync('ssh', ['-i', redteamKeyPath(), ...SSH_OPTS, `root@${ip}`, `mkdir -p ${DROPLET_DIR}`], { timeout: 20_000 });
  await execFileAsync('scp', ['-i', redteamKeyPath(), ...SSH_OPTS, '-r', `${dir}/droplet-scripts/.`, `root@${ip}:${DROPLET_DIR}/`], { timeout: 90_000 });
  await execFileAsync('ssh', ['-i', redteamKeyPath(), ...SSH_OPTS, `root@${ip}`, `chmod +x ${DROPLET_DIR}/*.sh ${DROPLET_DIR}/*.py 2>/dev/null || true`], { timeout: 15_000 });
}

/** state.json'dan droplet public IP'sini oku (provision sonrası). */
async function readDropletIp(): Promise<string | null> {
  try {
    const { stdout } = await execFileAsync('cat', [`${scriptsDir()}/state.json`], { timeout: 8000 });
    const j = JSON.parse(stdout);
    return j.public_ip ?? j.publicIp ?? j.ip ?? null;
  } catch {
    return null;
  }
}

/**
 * Bir RedTeamJob'u uçtan uca çalıştırır. Admin trigger'dan (arka planda) çağrılır.
 */
export async function runJob(jobId: string, opts: { dryRun: boolean }): Promise<void> {
  const job = await prisma.redTeamJob.findUnique({ where: { id: jobId } });
  if (!job) return;

  const level = job.level as Level;
  const cap = {
    capSec: job.capSecOverride ?? LEVEL_CFG[level].capSec,
    capCalls: job.capCallsOverride ?? LEVEL_CFG[level].capCalls,
    capCostUsd: job.capCostOverride ?? LEVEL_CFG[level].capCostUsd,
  };

  let dropletIp: string | null = job.dropletIp ?? null;
  let pullTimer: NodeJS.Timeout | null = null;

  // Faz-farkında exec: provision/teardown LOKAL (prod host); droplet fazları SSH (droplet path'e rewrite).
  const exec: ExecFn = async (cmd, args) => {
    if (/\/(provision|teardown)\.sh$/.test(cmd)) return localExec(cmd, args);
    if (!dropletIp) return { code: 1, stdout: '', stderr: 'droplet IP yok (provision başarısız?)' };
    const realArgs = args.filter((a) => !a.startsWith('#'));
    // container path (${scriptsDir}/droplet-scripts/X) → droplet path (/opt/pentagi-run/X)
    const dropletCmd = cmd.replace(/.*\/droplet-scripts\//, `${DROPLET_DIR}/`);
    return makeSshExec(dropletIp)([dropletCmd, ...realArgs].join(' '));
  };

  const onStep = async (s: Parameters<NonNullable<Parameters<typeof runPipeline>[0]['onStep']>>[0]) => {
    // provision bittiğinde droplet IP'yi yakala + kaydet + LLM anahtarını akıt
    if (s.phase === 'provision' && s.ok && !opts.dryRun && !dropletIp) {
      dropletIp = await readDropletIp();
      if (dropletIp) {
        await prisma.redTeamJob.update({ where: { id: jobId }, data: { dropletIp } });
        // Droplet YENİ boot etti — sshd hazır olana kadar BEKLE (tek-seferde deneme yok).
        await persistStep(jobId, { phase: 'setup', ok: true, detail: `droplet ${dropletIp} açıldı — SSH (sshd) hazır bekleniyor…` });
        const sshReady = await waitForSsh(dropletIp);
        if (!sshReady) {
          await persistStep(jobId, { phase: 'setup', ok: false, detail: 'SSH ~3 dk içinde hazır olmadı (droplet boot/firewall?) — teardown edilecek' });
          throw new Error('SSH hazır olmadı');
        }
        await persistStep(jobId, { phase: 'setup', ok: true, detail: 'SSH hazır — scriptler ve LLM anahtarı aktarılıyor' });
        try {
          await pushDropletScripts(dropletIp); // droplet-scripts'i droplet'e kopyala + chmod
          await deliverLlmKeyToDroplet(dropletIp); // LLM anahtarı SSH-stdin ile (log'da değil)
        } catch (e) {
          await persistStep(jobId, { phase: 'setup', ok: false, detail: 'script/anahtar aktarımı başarısız: ' + maskSecrets((e as Error).message) });
          throw e;
        }
      }
    }
    // durum makinesini fazdan türet
    const statusByPhase: Record<string, string> = {
      provision: 'provisioning', setup: 'provisioning', harden: 'hardening', verify: 'hardening',
      campaign: 'running', bind: 'binding', report: 'reporting', teardown: 'torn_down',
    };
    await prisma.redTeamJob.update({ where: { id: jobId }, data: { status: statusByPhase[s.phase] ?? undefined, phase: s.phase } }).catch(() => {});
    await persistStep(jobId, s);

    // campaign başında puller döngüsünü başlat (canlı ilerleme/maliyet/per-model)
    if (s.phase === 'campaign' && s.ok && !opts.dryRun && dropletIp && !pullTimer) {
      const ip = dropletIp;
      pullTimer = setInterval(async () => {
        try { await persistPull(jobId, await pullOnce(makeSshExec(ip), { targetIp: job.targetIp }), 'campaign'); } catch { /* yoksay */ }
      }, 5000);
    }
  };

  try {
    await prisma.redTeamJob.update({ where: { id: jobId }, data: { status: opts.dryRun ? 'queued' : 'provisioning', startedAt: new Date() } });
    const result = await runPipeline({
      job: {
        id: job.id, domain: job.domain, level, environment: job.environment as Env,
        ownershipConfirmed: job.ownershipConfirmed, riskAccepted: job.riskAccepted, prodElevatedAccepted: job.prodElevatedAccepted,
      },
      scriptsDir: scriptsDir(), keyPath: redteamKeyPath(),
      dryRun: opts.dryRun, doTokenPresent: !!process.env.DIGITAL_OCEAN_API_KEY,
      exec, resolver: nodeResolver, cap, onStep,
    });

    if (pullTimer) { clearInterval(pullTimer); pullTimer = null; }

    await prisma.redTeamJob.update({
      where: { id: jobId },
      data: {
        status: result.ok ? 'completed' : 'failed',
        phase: result.ok ? 'teardown' : job.phase,
        finishedAt: new Date(),
        error: result.error ?? null,
        ...(result.report ? { reportJson: result.report as any, costUsd: (result.report.meta as any).costUsd ?? job.costUsd } : {}),
      },
    });
  } catch (e) {
    if (pullTimer) clearInterval(pullTimer);
    await prisma.redTeamJob.update({
      where: { id: jobId },
      data: { status: 'failed', finishedAt: new Date(), error: maskSecrets((e as Error).message).slice(0, 500) },
    }).catch(() => {});
  }
}
