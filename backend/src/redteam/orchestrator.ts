/**
 * (OTONOM AI RED TEAM — 3b-ii) ORKESTRASYON PIPELINE.
 * Gated iş kaydından → efemer izole droplet + cap'li PentAGI + binder + rapor + teardown.
 *
 * EMNİYET (pazarlıksız, kod içinde zorlanır):
 *  - Koşu YALNIZ sahiplik + risk onayı (+ S3/prod ek-onay) varsa başlar.
 *  - Hedef CyberTestify prod (164.92.223.208 / 10.0.0.0/8) ya da özel/metadata ise REDDEDİLİR.
 *  - Egress: yalnız Anthropic + yetkili hedef IP; ampirik doğrulama (hedef erişilir + CyberTestify
 *    BLOCKED) geçmezse kampanya BAŞLAMAZ.
 *  - Cap (3a sağlam sürüm): token/süre tavanı → Anthropic-egress-KES + finishFlow + worker-kill.
 *  - teardown HER durumda (finally) — boşta maliyet sıfır.
 *  - DO token yalnız ENV'den (exec ortamına verilir); bu modül token'ı LOG'a/karara koymaz.
 *
 * `dryRun`: hiçbir DO/SSH komutu çalıştırılmaz; plan + guard'lar doğrulanır (DB'siz smoke-test).
 * `exec` enjekte edilebilir → gerçek child_process yerine mock ile test edilir.
 */

import { buildRedTeamReport, type BinderOutput, type RedTeamReport } from './report.js';

export type Level = 'S1' | 'S2' | 'S3';
export type Env = 'test' | 'staging' | 'prod';

export type RedTeamJobInput = {
  id: string;
  domain: string;
  targetIp: string | null; // yetkili hedef IP (allow-target için); yoksa guard reddeder (canlıda)
  level: Level;
  environment: Env;
  ownershipConfirmed: boolean;
  riskAccepted: boolean;
  prodElevatedAccepted: boolean;
};

export type Phase =
  | 'guard' | 'provision' | 'setup' | 'harden' | 'verify' | 'campaign' | 'bind' | 'report' | 'teardown';

export type StepLog = { phase: Phase; command?: string; ok: boolean; detail: string };

export type ExecResult = { code: number; stdout: string; stderr: string };
export type ExecFn = (cmd: string, args: string[]) => Promise<ExecResult>;

export type OrchestratorCtx = {
  job: RedTeamJobInput;
  scriptsDir: string; // infra/pentagi-isolated (provision.sh, teardown.sh, ...)
  keyPath: string; // id_pentagi (gitignored; canlıda prod host'a konur)
  dryRun: boolean;
  doTokenPresent: boolean; // çağıran env'de DIGITAL_OCEAN_API_KEY var mı diye bakar (değeri buraya GELMEZ)
  exec: ExecFn;
  onStep?: (s: StepLog) => void | Promise<void>;
};

// Seviyeye göre SAĞLAM cap (ilk gelen HARD STOP) + droplet boyutu + saldırganlık profili.
export const LEVEL_CFG: Record<Level, { capSec: number; capCalls: number; capCostUsd: number; size: string; profile: string }> = {
  S1: { capSec: 180, capCalls: 8, capCostUsd: 0.5, size: 's-2vcpu-4gb', profile: 'pasif + hafif aktif göstergeler (düşük risk)' },
  S2: { capSec: 300, capCalls: 15, capCostUsd: 1.0, size: 's-4vcpu-8gb', profile: 'aktif doğrulama + sınırlı sömürü denemesi (dengeli)' },
  S3: { capSec: 420, capCalls: 25, capCostUsd: 1.5, size: 's-4vcpu-8gb', profile: 'geniş sömürü yüzeyi, zincirleme denemeler (agresif)' },
};

// Hedef IP guard: CyberTestify prod (public + VPC) + özel/metadata REDDEDİLİR.
const CT_PUBLIC = '164.92.223.208';
export function isForbiddenTargetIp(ip: string): boolean {
  if (ip === CT_PUBLIC) return true;
  if (/^10\./.test(ip)) return true; // CyberTestify VPC + tüm 10/8
  if (/^127\./.test(ip) || /^0\./.test(ip) || /^169\.254\./.test(ip) || /^192\.168\./.test(ip)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(ip)) return true;
  return false;
}

function levelPrompt(job: RedTeamJobInput): string {
  const p = LEVEL_CFG[job.level].profile;
  return (
    `You are testing an AUTHORIZED target the operator owns: ${job.domain} (${job.targetIp}). ` +
    `Aggressiveness profile (${job.level}): ${p}. Bind every finding to concrete evidence. ` +
    `Do NOT touch any other host. Stop after confirming findings.`
  );
}

/**
 * Pipeline'ı çalıştırır. dryRun'da exec ÇAĞRILMAZ (plan + guard doğrulanır). Gerçekte her faz
 * exec ile ilgili infra script'ini çalıştırır; teardown finally'de garanti.
 */
export async function runPipeline(ctx: OrchestratorCtx): Promise<{
  ok: boolean;
  steps: StepLog[];
  report?: RedTeamReport;
  error?: string;
}> {
  const steps: StepLog[] = [];
  const { job } = ctx;
  const cfg = LEVEL_CFG[job.level];
  let provisioned = false;
  let report: RedTeamReport | undefined;

  const record = async (s: StepLog) => {
    steps.push(s);
    if (ctx.onStep) await ctx.onStep(s);
  };
  const run = async (phase: Phase, cmd: string, args: string[]): Promise<ExecResult> => {
    const command = [cmd, ...args].join(' ');
    if (ctx.dryRun) {
      await record({ phase, command, ok: true, detail: '[dry-run] çalıştırılmadı' });
      return { code: 0, stdout: '', stderr: '' };
    }
    const r = await ctx.exec(cmd, args);
    await record({ phase, command, ok: r.code === 0, detail: r.code === 0 ? 'ok' : `exit ${r.code}: ${r.stderr.slice(0, 200)}` });
    if (r.code !== 0) throw new Error(`${phase} başarısız: ${command}`);
    return r;
  };

  try {
    // ——— 1) GUARD (pazarlıksız) ———
    const consentsOk =
      job.ownershipConfirmed &&
      job.riskAccepted &&
      (!(job.level === 'S3' && job.environment === 'prod') || job.prodElevatedAccepted);
    if (!consentsOk) throw new Error('reddedildi: sahiplik/risk (veya S3+prod ek-) onayı eksik');
    if (!job.targetIp) throw new Error('reddedildi: yetkili hedef IP yok (allow-target için zorunlu)');
    if (isForbiddenTargetIp(job.targetIp)) throw new Error(`reddedildi: yasak hedef IP (${job.targetIp}) — CyberTestify/özel/metadata`);
    if (!ctx.dryRun && !ctx.doTokenPresent) throw new Error('reddedildi: DO token env yok (provision imkânsız)');
    await record({ phase: 'guard', ok: true, detail: `onaylar + hedef (${job.targetIp}) doğrulandı; cap ${cfg.capSec}s/${cfg.capCalls}/$${cfg.capCostUsd}` });

    // ——— 2) PROVISION (efemer izole droplet; boyut seviyeye göre) ———
    await run('provision', `${ctx.scriptsDir}/provision.sh`, [`# SIZE=${cfg.size}`]);
    provisioned = true;

    // ——— 3) SETUP (PentAGI + hedef-erişimi + API-token bootstrap) ———
    await run('setup', `${ctx.scriptsDir}/droplet-scripts/setup-pentagi.sh`, []);

    // ——— 4) HARDEN egress: Anthropic AÇ + yalnız yetkili hedef IP ———
    await run('harden', `${ctx.scriptsDir}/droplet-scripts/egress-harden-docker.sh`, []);
    await run('harden', `${ctx.scriptsDir}/droplet-scripts/allow-target.sh`, [job.targetIp]);

    // ——— 5) VERIFY isolation (AMPİRİK): hedef erişilir + CyberTestify BLOCKED. Geçmezse ABORT ———
    const v = await run('verify', `${ctx.scriptsDir}/droplet-scripts/verify-egress.sh`, [job.targetIp]);
    if (!ctx.dryRun && !/TARGET_OK.*CYBERTESTIFY_BLOCKED/s.test(v.stdout)) {
      throw new Error('izolasyon doğrulaması BAŞARISIZ — kampanya iptal (hedef erişilemez ya da CyberTestify açık)');
    }

    // ——— 6) CAMPAIGN (cap'li; seviyeye göre profil/prompt) ———
    await run('campaign', `${ctx.scriptsDir}/droplet-scripts/launch_cap.py`, [
      `# CAP_SEC=${cfg.capSec} CAP_CALLS=${cfg.capCalls} CAP_COST=${cfg.capCostUsd}`,
      `# CAMPAIGN_PROMPT=${JSON.stringify(levelPrompt(job))}`,
    ]);

    // ——— 7) BIND (PentAGI Postgres → 3-katman JSON; ham artefakta bağlı) ———
    const b = await run('bind', `${ctx.scriptsDir}/droplet-scripts/binder.py`, ['--flow', '<flowId>', '--json']);
    const binderOutput: BinderOutput = ctx.dryRun
      ? { artifactCount: 0, claimCount: 0, summary: { kanitli: 0, belirsiz: 0, hayalet: 0 }, overallRisk: 'temiz', findings: [] }
      : (JSON.parse(b.stdout) as BinderOutput);

    // ——— 8) REPORT (deterministik render; şişirme yok) ———
    report = buildRedTeamReport(binderOutput, {
      target: job.domain,
      level: job.level,
      environment: job.environment,
      generatedAt: ctx.dryRun ? '<dry-run>' : new Date().toISOString(),
    });
    await record({ phase: 'report', ok: true, detail: `rapor: kanıtlı ${report.counts.kanitli} · belirsiz ${report.counts.belirsiz} · elenen ${report.eliminated} · risk ${report.overallRisk}` });

    return { ok: true, steps, report };
  } catch (e) {
    await record({ phase: 'guard', ok: false, detail: (e as Error).message });
    return { ok: false, steps, error: (e as Error).message, report };
  } finally {
    // ——— 9) TEARDOWN — HER durumda (provision olduysa). Boşta maliyet sıfır. ———
    if (provisioned) {
      try {
        await run('teardown', `${ctx.scriptsDir}/teardown.sh`, []);
      } catch {
        await record({ phase: 'teardown', ok: false, detail: 'teardown DENENDİ ama hata — droplet ELLE kontrol edilmeli' });
      }
    }
  }
}
