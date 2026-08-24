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
import { makeSshExec, redteamKeyPath, EPHEMERAL_SSH_HOSTKEY_OPTS } from './controlChannel.js';
import { persistStep, persistPull } from './observability.js';
import { pullOnce, maskSecrets } from './puller.js';
import { renderTranscript } from './transcript.js';
import { nodeResolver } from './targetGuard.js';
import { storeRedTeamCustomerReport } from '../services/redteamOrderReport.js';
import { sendReportReady } from '../services/mailer.js';

const execFileAsync = promisify(execFile);

/** Infra scriptleri kökü (prod: /opt/cybertestify/app/infra/pentagi-isolated). */
export function scriptsDir(): string {
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
      ['-i', redteamKeyPath(), ...EPHEMERAL_SSH_HOSTKEY_OPTS, '-o', 'BatchMode=yes', `root@${ip}`,
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

const SSH_OPTS = [...EPHEMERAL_SSH_HOSTKEY_OPTS, '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
  '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=8']; // keepalive: uzun komutta oturum düşmesin
const DROPLET_DIR = '/opt/pentagi-run';

/**
 * cloud-init'i KISA-RECONNECT poll ile bekle (her SSH kısa → kopma birikmez). "running" bittiğinde döner.
 * Uzun tek-SSH `cloud-init status --wait` yerine bu — bağlantı düşse de wait ilerler.
 */
async function waitCloudInit(ip: string, maxMs = 240_000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < maxMs) {
    try {
      const { stdout } = await execFileAsync('ssh', ['-i', redteamKeyPath(), ...SSH_OPTS, `root@${ip}`,
        'cloud-init status 2>/dev/null || echo "status: done"'], { timeout: 15_000 });
      if (!/status:\s*running/i.test(stdout)) return; // done/disabled/error/notrun → devam
    } catch { /* kopma normal — kısa bekle, tekrar dene */ }
    await new Promise((r) => setTimeout(r, 8000));
  }
}

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

/** state.json'dan droplet public IP + ID'sini oku (provision sonrası). */
async function readDropletInfo(): Promise<{ ip: string | null; id: string | null }> {
  try {
    const { stdout } = await execFileAsync('cat', [`${scriptsDir()}/state.json`], { timeout: 8000 });
    const j = JSON.parse(stdout);
    return { ip: j.public_ip ?? j.publicIp ?? j.ip ?? null, id: j.droplet_id ?? j.dropletId ?? null };
  } catch {
    return { ip: null, id: null };
  }
}

/**
 * (D2 — BAĞIMSIZ ALTYAPI WATCHDOG) watchdog.ts'i AYRI, DETACHED bir OS süreci olarak başlatır —
 * bu Node sürecinin event-loop'undan/kendisinden TAMAMEN kopuktur (unref edilir; parent hang/crash
 * olsa da watchdog kendi başına çalışmaya devam eder). Kanıtlanmış 3-kez-tekrarlanan hatanın
 * (cap/süre kontrolü ana döngü içinde yaşayıp o döngüyle birlikte tıkanması) YAPISAL çözümüdür.
 * DO token/DB bağlantısı yalnız ENV'den (process.env inherit) — argv'ye YAZILMAZ.
 */
function spawnWatchdog(params: {
  jobId: string; dropletIp: string; dropletId: string | null; capSec: number; capCostUsd: number;
  target: string; targetIp: string; level: string; environment: string;
}): void {
  const args = ['tsx', 'src/redteam/watchdog.ts',
    '--job-id', params.jobId, '--droplet-ip', params.dropletIp,
    '--cap-sec', String(params.capSec), '--cap-cost', String(params.capCostUsd),
    '--target', params.target, '--target-ip', params.targetIp,
    '--level', params.level, '--environment', params.environment,
    '--scripts-dir', scriptsDir(), '--key-path', redteamKeyPath()];
  if (params.dropletId) args.push('--droplet-id', params.dropletId);
  const child = spawn('npx', args, { detached: true, stdio: 'ignore', env: process.env });
  child.unref(); // parent'ın exit'i/hang'i watchdog'u ETKİLEMEZ — bağımsız yaşar
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
  let capturedTargetIp: string | null = job.targetIp ?? null; // guard fazından yakalanır (watchdog için gerekli)
  let watchdogSpawned = false;

  // Faz-farkında exec: provision/teardown LOKAL (prod host); droplet fazları SSH (droplet path'e rewrite).
  const exec: ExecFn = async (cmd, args) => {
    if (/\/(provision|teardown)\.sh$/.test(cmd)) return localExec(cmd, args);
    if (!dropletIp) return { code: 1, stdout: '', stderr: 'droplet IP yok (provision başarısız?)' };
    const realArgs = args.filter((a) => !a.startsWith('#'));
    // container path (${scriptsDir}/droplet-scripts/X) → droplet path (/opt/pentagi-run/X)
    const dropletCmd = cmd.replace(/.*\/droplet-scripts\//, `${DROPLET_DIR}/`);
    const full = [dropletCmd, ...realArgs].join(' ');
    let r = await makeSshExec(dropletIp)(full);
    // exit 255 = SSH bağlantı kopması (komut hatası değil). setup-pentagi.sh İDEMPOTENT → reconnect+retry.
    // campaign/bind RETRY EDİLMEZ (createFlow tekrarı = ikinci flow). Yalnız setup.
    const isSetup = /setup-pentagi\.sh/.test(cmd);
    let tries = 0;
    while (r.code === 255 && isSetup && tries < 2) {
      tries++;
      await new Promise((res) => setTimeout(res, 8000));
      r = await makeSshExec(dropletIp)(full);
    }
    return r;
  };

  const onStep = async (s: Parameters<NonNullable<Parameters<typeof runPipeline>[0]['onStep']>>[0]) => {
    // guard fazının detail metninden pinlenen hedef IP'sini yakala (watchdog'un binder çağrısı için gerekli).
    if (s.phase === 'guard' && s.ok && !opts.dryRun && !capturedTargetIp) {
      const m = /\(birincil ([^)]+)\)/.exec(s.detail);
      if (m) {
        capturedTargetIp = m[1];
        await prisma.redTeamJob.update({ where: { id: jobId }, data: { targetIp: capturedTargetIp } }).catch(() => {});
      }
    }
    // provision bittiğinde droplet IP'yi yakala + kaydet + LLM anahtarını akıt
    if (s.phase === 'provision' && s.ok && !opts.dryRun && !dropletIp) {
      const info = await readDropletInfo();
      dropletIp = info.ip;
      if (dropletIp) {
        // (KILL-SWITCH GÜVENLİĞİ) dropletId JOB'A ÖZGÜ kaydedilir — state.json TÜM job'lar arası
        // PAYLAŞIMLI tek dosyadır; kill-switch/watchdog yanlış (başka bir eşzamanlı job'un) droplet'ine
        // gitmesin diye bu job'un GERÇEK droplet ID'si DB'ye yazılır (kill-switch olayının bir parçası).
        await prisma.redTeamJob.update({ where: { id: jobId }, data: { dropletIp, dropletId: info.id } });
        // (WATCHDOG ZAMANLAMA DÜZELTMESİ) Watchdog ARTIK provision/setup'ta DEĞİL, CAMPAIGN başında
        // spawn edilir (aşağıda phase==='campaign'). Kanıtlanmış hata: setup ~8dk sürüyor; watchdog
        // provision'da spawn edilince 600s cap AJAN çalışmadan setup'ta tükeniyor, ajan ~48sn sonra
        // öldürülüyordu (0 artefakt). Cap = AJAN süresi olmalı. Setup, SSH-timeout'ları + droplet-içi
        // D1 self-destruct backstop'u ile zaten korunur — bu aralıkta Node-watchdog'a gerek yok.
        // Droplet YENİ boot etti — sshd hazır olana kadar BEKLE (tek-seferde deneme yok).
        await persistStep(jobId, { phase: 'setup', ok: true, detail: `droplet ${dropletIp} açıldı — SSH (sshd) hazır bekleniyor…` });
        const sshReady = await waitForSsh(dropletIp);
        if (!sshReady) {
          await persistStep(jobId, { phase: 'setup', ok: false, detail: 'SSH ~3 dk içinde hazır olmadı (droplet boot/firewall?) — teardown edilecek' });
          throw new Error('SSH hazır olmadı');
        }
        await persistStep(jobId, { phase: 'setup', ok: true, detail: 'SSH hazır — cloud-init (ilk-boot) bekleniyor (kısa-reconnect poll)…' });
        await waitCloudInit(dropletIp); // uzun tek-SSH yerine kısa poll → oturum düşse de ilerler
        await persistStep(jobId, { phase: 'setup', ok: true, detail: 'cloud-init tamam — scriptler ve LLM anahtarı aktarılıyor' });
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
    // (D2 GÜVENCESİ) status='aborted' İSE bu ana döngü onStep'i ARTIK ÜZERİNE YAZMASIN — watchdog
    // zaten hardkill uyguladıysa (rapor + status), ana döngü SONRADAN uyanırsa (SSH timeout'tan) o
    // sonucu EZMESİN. Atomik where-guard (ekstra okuma gerekmez; koşul tutmazsa no-op).
    await prisma.redTeamJob.updateMany({ where: { id: jobId, status: { not: 'aborted' } }, data: { status: statusByPhase[s.phase] ?? undefined, phase: s.phase } }).catch(() => {});
    await persistStep(jobId, s);

    // (WATCHDOG — CAMPAIGN BAŞINDA) Cap saatini AJAN başladığında başlat (setup ~8dk'yı SAYMA). İlk
    // campaign onStep'te spawn et — dropletIp + hedef IP bu noktada hazır; cap=capSec artık gerçek ajan bütçesi.
    if (s.phase === 'campaign' && s.ok && !opts.dryRun && !watchdogSpawned && dropletIp && capturedTargetIp) {
      watchdogSpawned = true;
      const dId = (await prisma.redTeamJob.findUnique({ where: { id: jobId }, select: { dropletId: true } }))?.dropletId ?? null;
      spawnWatchdog({
        jobId, dropletIp, dropletId: dId, capSec: cap.capSec, capCostUsd: cap.capCostUsd,
        target: job.domain, targetIp: capturedTargetIp, level: job.level, environment: job.environment,
      });
      await persistStep(jobId, { phase: 'campaign', ok: true, detail: `bağımsız watchdog başlatıldı (cap ${cap.capSec}s +60s sert sınır; SAAT ajan başlangıcından — setup süresi sayılmaz)` });
    }

    // verify verdikt'ini job'a yaz (panel egress kartı) — 'izolasyon: hedef-erişilir=✓ · CyberTestify-BLOCKED=✓'
    if (s.phase === 'verify' && !opts.dryRun && /izolasyon:/.test(s.detail)) {
      await prisma.redTeamJob.update({
        where: { id: jobId },
        data: { egressTargetOk: /hedef-erişilir=✓/.test(s.detail), egressCyberBlocked: /CyberTestify-BLOCKED=✓/.test(s.detail) },
      }).catch(() => {});
    }

    // Puller döngüsünü VERIFY sonrası başlat → campaign (senkron/blocking) sürerken CANLI pull (ilerleme/
    // maliyet/per-model panele akar). Egress zaten verify'da doğrulandı → pull'da tekrar probe ETME (yük).
    if (s.phase === 'verify' && s.ok && !opts.dryRun && dropletIp && !pullTimer) {
      const ip = dropletIp;
      pullTimer = setInterval(async () => {
        try { await persistPull(jobId, await pullOnce(makeSshExec(ip), {}), 'campaign'); } catch { /* yoksay */ }
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

    // Raporun meta'sına GERÇEK maliyet/çağrı (puller'ın DB'ye yazdığı canlı değerler) enjekte et.
    const live = await prisma.redTeamJob.findUnique({ where: { id: jobId }, select: { costUsd: true, llmCalls: true, startedAt: true, level: true, log: true } });
    // SÜRE: gerçek başlangıç→bitiş (panelde 0s kalmasın; rapor meta'sına da geçir).
    const finishedAt = new Date();
    const elapsedSec = live?.startedAt ? Math.max(0, Math.round((finishedAt.getTime() - live.startedAt.getTime()) / 1000)) : null;
    // (MALİYET TEK KAYNAK) GERÇEK harcama = orchestrator'ın koşu-sonu msgchains okuması (result.liveCostUsd).
    // puller'ın canlı sayacı cost'u async yazıldığı için 0 kalabiliyordu ($0 gösterip arkada para yakma
    // güven sorununun köküydü). Öncelik: msgchains gerçek harcaması → yoksa puller değeri.
    const realCost = result.liveCostUsd != null ? result.liveCostUsd : (live?.costUsd ?? null);
    let reportJson: any = result.report ?? null;
    if (reportJson) {
      // (P0-5) elapsedSec = GERÇEK toplam wall-clock (startedAt→finishedAt, TEK kaynak); agentSec =
      // orchestrator'ın ölçtüğü yalnız-ajan süresi. İkisi rapora AYRI yazılır ("1120s>600s" dürüstçe açıklanır).
      reportJson = { ...reportJson, meta: { ...reportJson.meta, costUsd: realCost, llmCalls: live?.llmCalls ?? null, elapsedSec, agentSec: result.agentSec ?? reportJson.meta?.agentSec ?? null } };
    }

    // (P0-A/4) DIVERGENCE: fiyat ön-kontrolünün tahmin ettiği kapsam vs S1'in GERÇEK ölçtüğü kapsam.
    // Büyük sapma (ör. "basit" denen sitede çok daha fazla uç keşfi) admin log'a düşer — GELECEKTE
    // heuristiği iyileştirmek için, fiyatı geri ödemeyle DEĞİL. Yalnız iç kayıt; müşteri fiyatı sabit kaldı.
    try {
      const est = (Array.isArray(live?.log) ? (live!.log as any[]) : []).map((e) => e?.s1Estimate).find(Boolean);
      const actualEndpoints = reportJson?.tried?.endpointCount ?? reportJson?.tried?.endpoints?.length ?? null;
      if (est && actualEndpoints != null && Number.isFinite(est.estEndpoints)) {
        const diff = Math.abs(actualEndpoints - est.estEndpoints);
        const big = diff >= 8 || (est.estEndpoints > 0 && diff / est.estEndpoints >= 1.5);
        if (big) {
          await persistStep(jobId, { phase: 'report', ok: true, detail: `FİYAT DIVERGENCE (iç not, müşteri fiyatı SABİT): ön-kontrol ~${est.estEndpoints} uç (${est.tier}) tahmin etti, gerçek koşu ${actualEndpoints} uç ölçtü — heuristik gözden geçirilebilir` });
        }
      }
    } catch { /* divergence loglama best-effort — koşuyu etkilemez */ }

    // ŞEFFAFLIK + RETENTION: teardown droplet'i imha etmeden ÖNCE çekilen ham veri + karar-izi + transkript.
    // rawFlow binder --dump-raw'da redact()'li; binderTrace ham → maskSecrets (savunma). transcript rawFlow'dan türer.
    const rawFlow: any = result.rawFlow ?? null;
    const binderTrace = result.binderTrace
      ? maskSecrets(result.binderTrace).trim().split('\n').map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean)
      : null;
    const transcript = rawFlow ? renderTranscript(rawFlow) : null;

    // (D2 GÜVENCESİ) watchdog zaten 'aborted' yazdıysa (hardkill + rapor), ana döngünün GEÇ gelen
    // sonucu bunu EZMESİN — atomik where-guard.
    await prisma.redTeamJob.updateMany({
      where: { id: jobId, status: { not: 'aborted' } },
      data: {
        status: result.ok ? 'completed' : 'failed',
        phase: result.ok ? 'teardown' : job.phase,
        finishedAt,
        ...(elapsedSec != null ? { elapsedSec } : {}),
        ...(realCost != null ? { costUsd: realCost } : {}), // GERÇEK harcama panele de yazılır (TEK kaynak)
        error: result.error ?? null,
        ...(reportJson ? { reportJson } : {}),
        ...(rawFlow ? { rawFlowJson: rawFlow } : {}),
        ...(binderTrace ? { binderTraceJson: binderTrace as any } : {}),
        ...(transcript ? { transcriptJson: transcript as any } : {}),
      },
    });

    // (YARIŞ DÜZELTMESİ) Koşu KILL-SWITCH/watchdog ile ABORTED olduysa: runner'ın runJob'u yok edilen
    // droplet'e SSH deneyip "Permission denied" ile ok:false döner ve BURADA order'ı yanlışlıkla
    // scan_failed'e çekerdi. Kill/watchdog akışı order'ı KENDİSİ yönetir (aşağıda kill endpoint). Job
    // GÜNCEL durumu 'aborted' ise order'a HİÇ DOKUNMA — geç-tamamlanma order'ı EZMESİN.
    const curStatus = (await prisma.redTeamJob.findUnique({ where: { id: jobId }, select: { status: true } }))?.status;
    if (curStatus === 'aborted') {
      console.log(`[redteam-s1] job ${jobId} aborted (kill/watchdog) → runner order'a dokunmuyor (kill akışı sahiplendi)`);
    } else if (job.orderId && reportJson) {
      try {
        const incomplete = !result.ok;
        const { accessSecret, gated } = await storeRedTeamCustomerReport(job.orderId, reportJson, {
          incomplete,
          incompleteReason: incomplete ? (result.error ?? 'Koşu erken durdu/başarısız — rapor kısmi olabilir.') : null,
        });
        // Kapı KAPALIYSA rapor hemen açık → "hazır" e-postası burada. AÇIKSA e-posta admin onayında gider.
        if (!gated) await sendReportReady(job.orderId, accessSecret).catch((e) => console.error('[redteam-s1] mail hata:', (e as Error).message));
        console.log(`[redteam-s1] order ${job.orderId} raporu köprülendi → ${gated ? 'awaiting_admin_review (admin onayı bekliyor)' : 'scan_completed (kapı kapalı)'}`);
      } catch (e) {
        console.error('[redteam-s1] Order rapor köprüleme hatası:', (e as Error).message);
      }
    } else if (job.orderId && !reportJson) {
      // Rapor HİÇ üretilemedi (total başarısızlık) → sipariş scan_running'de ASILI kalmasın; müşteri
      // başarısızlığı görsün (iade/yeniden-deneme admin'de). Kısmi rapor varsa yukarıda köprülendi.
      await prisma.order.updateMany({
        where: { id: job.orderId, status: { notIn: ['scan_completed', 'awaiting_admin_review'] } },
        data: { status: 'scan_failed', failureReason: (result.error ?? 'S1 taraması rapor üretemedi.').slice(0, 300) },
      }).catch((e) => console.error('[redteam-s1] scan_failed işaretleme hatası:', (e as Error).message));
    }
  } catch (e) {
    if (pullTimer) clearInterval(pullTimer);
    await prisma.redTeamJob.updateMany({
      where: { id: jobId, status: { not: 'aborted' } },
      data: { status: 'failed', finishedAt: new Date(), error: maskSecrets((e as Error).message).slice(0, 500) },
    }).catch(() => {});
  }
}
