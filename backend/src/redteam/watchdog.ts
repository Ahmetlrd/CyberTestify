/**
 * (RED TEAM — D1/D2/D3/D5 BAĞIMSIZ ALTYAPI WATCHDOG) Orchestrator'ın ANA event-loop'undan/SÜRECİNDEN
 * TAMAMEN AYRI bir OS SÜRECİ olarak çalışır (runner.ts tarafından `detached: true` + `.unref()` ile
 * spawn edilir). KENDİ saatini tutar (spawn anından itibaren) — ana döngü/SSH/docker HERHANGİ BİR
 * yerde asılı kalsa BİLE (3. KEZ tekrarlanan gerçek olay: subtask 9/9 bitti, pipeline campaign/
 * hardening'de 30+ dakika asılı kaldı, panel maliyeti $1.31 gösterirken gerçek harcama $7+'ydi) bu
 * süreç bağımsız çalışmaya devam eder ve cap+60sn'de droplet'i DOĞRUDAN DigitalOcean API ile (SSH'a
 * muhtaç OLMADAN) yok eder.
 *
 * D5 — İKİ AŞAMALI (asla "önce yok et" değil):
 *   Aşama-1 (yumuşak, cap dolduğu AN): yeni ajan/LLM çağrısı gitmesin diye Anthropic egress'i SSH ile
 *     keser (harcama anında durur, droplet henüz YOK edilmez), sonra DB'ye CANLI akmış artefaktlardan
 *     binder + rapor üretir (yeni LLM çağrısı GEREKMEZ — offline re-bind ile aynı mekanizma).
 *   Aşama-2 (sert, rapor bitince ya da en fazla 60sn sonra): droplet DOĞRUDAN DO API ile imha edilir.
 *
 * D3 — Maliyet: iç sayaca (RedTeamJob.costUsd, orchestrator'ın puller'ı yazar) GÜVENMEZ; PentAGI
 * Postgres'inden (msgchains) BAĞIMSIZ okuma yapar ve sapma varsa AYRICA loglar (iç sayacın da bozuk
 * olduğunun kanıtı).
 *
 * GÜVENLİK: her dış çağrı (SSH/DO API) KESİN timeout'lu — watchdog'un KENDİSİ asla asılmamalı.
 * SECRET: DO token/DB bağlantısı yalnız process.env'den (parent spawn env'ini inherit eder) — argv/
 * log'a YAZILMAZ. maskSecrets tüm loglarda.
 */
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile } from 'node:fs/promises';
import { prisma } from '../db.js';
import { buildRedTeamReport, type BinderOutput, type RedTeamReport } from './report.js';
import { renderTranscript } from './transcript.js';
import { maskSecrets } from './puller.js';

const execFileAsync = promisify(execFile);

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : undefined;
}

const JOB_ID = arg('job-id');
const DROPLET_IP = arg('droplet-ip');
const CAP_SEC = Number(arg('cap-sec') ?? '600');
const CAP_COST = Number(arg('cap-cost') ?? '2');
const TARGET = arg('target') ?? '';
const TARGET_IP = arg('target-ip') ?? '';
const LEVEL = (arg('level') ?? 'S1') as 'S1' | 'S2' | 'S3';
const ENVIRONMENT = (arg('environment') ?? 'test') as 'test' | 'staging' | 'prod';
const SCRIPTS_DIR = arg('scripts-dir') ?? 'infra/pentagi-isolated';
const KEY_PATH = arg('key-path') ?? 'infra/pentagi-isolated/id_pentagi';

const HARD_LIMIT_SEC = CAP_SEC + 60; // D2: "cap+60sn'de ... zorla destroy" — kesin, koşulsuz üst sınır
const REPORT_GRACE_SEC = 60; // D5: yumuşak durdurmadan sonra rapor üretimine tanınan EK süre

function log(msg: string): void {
  // eslint-disable-next-line no-console
  console.log(`[watchdog ${new Date().toISOString()}] ${maskSecrets(msg)}`);
}

/** SSH çağrısı — KESİN timeout'lu (watchdog'un kendisi asla asılmamalı). Hata → null (best-effort). */
async function sshTry(cmd: string, timeoutMs: number): Promise<string | null> {
  if (!DROPLET_IP) return null;
  try {
    const { stdout } = await execFileAsync(
      'ssh',
      ['-i', KEY_PATH, '-o', 'ConnectTimeout=8', '-o', 'StrictHostKeyChecking=no', '-o', 'BatchMode=yes',
        `root@${DROPLET_IP}`, cmd],
      { timeout: timeoutMs, maxBuffer: 8 * 1024 * 1024 },
    );
    return stdout;
  } catch (e: any) {
    log(`SSH başarısız (limit ${timeoutMs}ms): ${String(e?.message ?? e).slice(0, 200)}`);
    return null;
  }
}

/** D3: GERÇEK harcamayı PentAGI Postgres'inden (msgchains) BAĞIMSIZ oku — iç sayaca güvenme. */
async function readRealCost(): Promise<number | null> {
  const out = await sshTry(
    `docker exec pgvector psql -U postgres -d pentagidb -tAc "SELECT COALESCE(SUM(usage_cost_in+usage_cost_out),0)::numeric(12,4) FROM msgchains;" 2>/dev/null`,
    10_000,
  );
  if (out == null) return null;
  const n = Number(out.trim());
  return Number.isFinite(n) ? n : null;
}

/** Aşama-1 (yumuşak): egress kes (harcama DURUR) + eldeki veriden binder+rapor üret + DB'ye yaz. */
async function softStop(reason: string): Promise<void> {
  log(`AŞAMA-1 (yumuşak durdurma): ${reason}`);
  // (i) Harcamayı DERHAL durdur: Anthropic (443/80) egress'ini SSH ile kes — droplet henüz YOK EDİLMEZ.
  const cut = await sshTry(
    'iptables -I DOCKER-USER 1 -p tcp --dport 443 -j DROP 2>/dev/null; ' +
    'iptables -I DOCKER-USER 1 -p tcp --dport 80 -j DROP 2>/dev/null; echo egress-kesildi',
    15_000,
  );
  log(`egress kesme sonucu: ${cut ? cut.trim() : 'SSH başarısız (droplet zaten erişilemez olabilir)'}`);

  // (ii) Flow id oku + binder'ı ÇALIŞTIR (yeni ajan/LLM çağrısı GEREKMEZ — dump-raw + json, anlık).
  const flowId = (await sshTry('cat /opt/pentagi-run/flow_id 2>/dev/null', 8_000))?.trim();
  let rawFlow: unknown = null;
  let binderOutput: BinderOutput | null = null;
  if (flowId) {
    const binderArgs = `--flow ${flowId} --target ${JSON.stringify(TARGET)} --target-ip ${JSON.stringify(TARGET_IP)}`;
    const dumpOut = await sshTry(`python3 /opt/pentagi-run/binder.py ${binderArgs} --dump-raw 2>/dev/null`, 25_000);
    if (dumpOut?.trim()) { try { rawFlow = JSON.parse(dumpOut); } catch { /* parse hatası -> rawFlow null kalır */ } }
    const jsonOut = await sshTry(`python3 /opt/pentagi-run/binder.py ${binderArgs} --json 2>/dev/null`, 25_000);
    if (jsonOut?.trim()) { try { binderOutput = JSON.parse(jsonOut) as BinderOutput; } catch { /* yoksay */ } }
  } else {
    log('flow_id okunamadı (SSH başarısız/campaign hiç başlamamış) — rapor üretilemeyecek, yalnız job durumu güncellenecek');
  }

  const liveCost = await readRealCost();
  let reportJson: RedTeamReport | null = null;
  if (binderOutput) {
    const rep = buildRedTeamReport(binderOutput, {
      target: TARGET, level: LEVEL, environment: ENVIRONMENT,
      generatedAt: new Date().toISOString(), costUsd: liveCost, llmCalls: null,
    });
    reportJson = {
      ...rep,
      // (P0-2 dürüstlüğü BOZULMAZ) Yarım kalan istek/yanıt çiftleri zaten kanıt sayılmaz (binder eler) —
      // burada yalnız ŞEFFAF bir not eklenir, risk/bulgu mantığı DEĞİŞMEZ.
      stoppedReason: `${reason} — koşu watchdog tarafından ZORLA durduruldu. Bu ana kadar toplanan ${binderOutput.artifactCount} ` +
        `ham artefaktın deterministik analizinden üretilen dürüst bir rapordur; yarıda kalan istek/yanıt çiftleri kanıt sayılmaz (elenir).`,
    };
  }
  const transcript = rawFlow ? renderTranscript(rawFlow as any) : null;

  if (!JOB_ID) return;
  await prisma.redTeamJob.update({
    where: { id: JOB_ID },
    data: {
      status: 'aborted', phase: 'teardown',
      error: `watchdog: ${reason}`,
      ...(liveCost != null ? { costUsd: liveCost } : {}),
      ...(reportJson ? { reportJson: reportJson as any } : {}),
      ...(rawFlow ? { rawFlowJson: rawFlow as any } : {}),
      ...(transcript ? { transcriptJson: transcript as any } : {}),
    },
  }).catch((e) => log(`DB yazımı başarısız (aşama-1): ${String(e)}`));
  log(`AŞAMA-1 tamam — rapor ${reportJson ? `ÜRETİLDİ (kanıtlı ${reportJson.counts.kanitli}, belirsiz ${reportJson.counts.belirsiz})` : 'üretilemedi (flow/binder verisi yok)'}, gerçek maliyet=${liveCost ?? '?'}`);
}

/** Aşama-2 (sert): droplet'i DOĞRUDAN DO API ile imha et — SSH'a bağımlı DEĞİL (droplet erişilemez olsa da çalışır). */
async function hardDestroy(reason: string): Promise<void> {
  log(`AŞAMA-2 (sert imha): ${reason}`);
  const token = process.env.DIGITAL_OCEAN_API_KEY;
  let destroyed = false;
  if (token) {
    try {
      const raw = await readFile(`${SCRIPTS_DIR}/state.json`, 'utf8').catch(() => '{}');
      const state = JSON.parse(raw || '{}') as { droplet_id?: string };
      if (state.droplet_id) {
        const res = await fetch(`https://api.digitalocean.com/v2/droplets/${state.droplet_id}`, {
          method: 'DELETE',
          headers: { Authorization: `Bearer ${token}` },
          signal: AbortSignal.timeout(15_000),
        });
        destroyed = res.ok || res.status === 404;
      } else {
        log('state.json içinde droplet_id yok — DO API destroy atlandı (D1 droplet-içi self-destruct BACKSTOP olarak devreye girecek)');
      }
    } catch (e) {
      log(`DO API destroy hatası: ${String(e)} — D1 droplet-içi self-destruct BACKSTOP olarak devreye girecek`);
    }
  } else {
    log('DIGITAL_OCEAN_API_KEY env yok — DO API destroy atlandı (D1 backstop devrede)');
  }
  if (JOB_ID) {
    await prisma.redTeamJob.update({
      where: { id: JOB_ID },
      data: { status: 'aborted', phase: 'teardown', finishedAt: new Date(), error: `watchdog-hardkill: ${reason}` },
    }).catch(() => {});
  }
  log(`AŞAMA-2 tamam — droplet ${destroyed ? 'İMHA EDİLDİ (DO API)' : 'imha DENENDİ, sonuç belirsiz (D1 droplet-içi self-destruct nihai backstop)'}`);
}

async function main(): Promise<void> {
  if (!JOB_ID || !DROPLET_IP) {
    log(`eksik zorunlu argüman (job-id/droplet-ip) — watchdog başlatılamadı, çıkılıyor`);
    return;
  }
  log(`başlatıldı — job=${JOB_ID} droplet=${DROPLET_IP} cap=${CAP_SEC}s (sert sınır +60s=${HARD_LIMIT_SEC}s) capCost=$${CAP_COST}`);
  const t0 = Date.now(); // KENDİ SAATİ — ana döngüden/orchestrator'dan TAMAMEN bağımsız
  let softStopDone = false;
  let softStopAt: number | null = null;

  // eslint-disable-next-line no-constant-condition
  while (true) {
    await new Promise((r) => setTimeout(r, 5000));
    const elapsed = (Date.now() - t0) / 1000;

    try {
      const job = await prisma.redTeamJob.findUnique({ where: { id: JOB_ID }, select: { status: true, costUsd: true } });
      if (job && ['completed', 'failed', 'torn_down', 'aborted'].includes(job.status)) {
        log(`job zaten normal sonlanmış (status=${job.status}) — watchdog sessizce çıkıyor`);
        return;
      }

      // D3: gerçek harcamayı BAĞIMSIZ oku; iç sayaçtan sapma varsa AYRICA logla (kanıt).
      if (!softStopDone) {
        const liveCost = await readRealCost();
        if (liveCost != null) {
          const cached = job?.costUsd ?? null;
          if (cached != null && Math.abs(liveCost - cached) > Math.max(0.3, cached * 0.5)) {
            log(`⚠ SAPMA TESPİT EDİLDİ: iç sayaç $${cached.toFixed(4)} vs BAĞIMSIZ okunan GERÇEK harcama $${liveCost.toFixed(4)} — iç sayaç güvenilmez olduğunun kanıtı`);
          } else {
            log(`gerçek harcama (bağımsız okuma): $${liveCost.toFixed(4)} (iç sayaç: ${cached != null ? '$' + cached.toFixed(4) : '?'})`);
          }
          if (liveCost >= CAP_COST) {
            softStopDone = true; softStopAt = Date.now();
            await softStop(`MALİYET cap aşıldı (bağımsız okunan gerçek harcama $${liveCost.toFixed(4)} >= cap $${CAP_COST})`);
          }
        }
      }
    } catch (e) {
      log(`DB kontrolü başarısız (devam ediliyor, watchdog bunun için durmaz): ${String(e)}`);
    }

    if (!softStopDone && elapsed >= CAP_SEC) {
      softStopDone = true; softStopAt = Date.now();
      await softStop(`SÜRE cap (${CAP_SEC}s) — watchdog kendi bağımsız saatiyle tetiklendi (ana orchestrator döngüsü yanıt veriyor mu vermiyor mu ÖNEMLİ DEĞİL)`);
    }

    const graceExceeded = softStopAt != null && (Date.now() - softStopAt) / 1000 >= REPORT_GRACE_SEC;
    if (elapsed >= HARD_LIMIT_SEC || graceExceeded) {
      await hardDestroy(
        elapsed >= HARD_LIMIT_SEC
          ? `kesin süre sınırı (cap+60s=${HARD_LIMIT_SEC}s) aşıldı`
          : `yumuşak durdurmadan sonraki ${REPORT_GRACE_SEC}s ek süre doldu`,
      );
      return;
    }
  }
}

main().catch((e) => { log(`FATAL (beklenmeyen hata): ${String(e)}`); process.exit(1); });
