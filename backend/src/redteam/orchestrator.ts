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
import { resolveAndPin, nodeResolver, type Resolver } from './targetGuard.js';

export type Level = 'S1' | 'S2' | 'S3';
export type Env = 'test' | 'staging' | 'prod';

export type RedTeamJobInput = {
  id: string;
  domain: string; // hedef (domain ya da IP) — guard ÇÖZER + PINLER; saldırı yalnız pinlenen IP'ye
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
  resolver?: Resolver; // hedef çözme (varsayılan nodeResolver; unit-test'te mock)
  cap?: { capSec: number; capCalls: number; capCostUsd: number }; // panelden ayar (yoksa seviye varsayılanı)
  onStep?: (s: StepLog) => void | Promise<void>;
};

// Seviyeye göre SAĞLAM cap (ilk gelen HARD STOP) + droplet boyutu + saldırganlık profili.
export const LEVEL_CFG: Record<Level, { capSec: number; capCalls: number; capCostUsd: number; size: string; profile: string }> = {
  // (KALİBRASYON) cap GERÇEK msgchains harcamasına bağlı; S1 $0.5/180s çok sıkıydı (ajan kanıt saklamadan
  // kesiliyordu). Gerçekçi: S1 ~10dk/30çağrı/$2. Kalıcı fiyat değil — test-kalibrasyon.
  S1: { capSec: 600, capCalls: 30, capCostUsd: 2.0, size: 's-2vcpu-4gb', profile: 'pasif + hafif aktif göstergeler (düşük risk)' },
  S2: { capSec: 720, capCalls: 40, capCostUsd: 3.0, size: 's-4vcpu-8gb', profile: 'aktif doğrulama + sınırlı sömürü denemesi (dengeli)' },
  S3: { capSec: 900, capCalls: 55, capCostUsd: 4.0, size: 's-4vcpu-8gb', profile: 'geniş sömürü yüzeyi, zincirleme denemeler (agresif)' },
};

// Hedef IP yasak-aralık kontrolü artık targetGuard.ts'te (IPv4+IPv6, çok-IP, çöz+pinle).

function levelPrompt(job: RedTeamJobInput, pinnedIp: string): string {
  const p = LEVEL_CFG[job.level].profile;
  const d = job.domain;
  return (
    `You are an authorized penetration tester. Target application: https://${d}/ (the operator owns it). ` +
    // Pinlenen IP'ye bağlan AMA Host/SNI = domain gönder → doğru vhost GERÇEK uygulamayı sunar.
    `Connect ONLY to the pinned IP ${pinnedIp}, but ALWAYS send Host: ${d} and SNI ${d} ` +
    `(e.g. curl -sk --resolve ${d}:443:${pinnedIp} --resolve ${d}:80:${pinnedIp} "https://${d}/..."). ` +
    `Do NOT re-resolve the domain and do NOT touch any other host. ` +
    // (P1) İzole ortamda erişilemeyen araçlar — bunlara zaman/bütçe HARCAMA (bu koşuda ajan 11 dk'yı
    // web_search/browser/memorist'te yaktı, asıl XSS payload'ını hiç göndermedi).
    `ENVIRONMENT LIMITS — web_search, browser, and memorist/vector-DB are NOT reachable here; DO NOT use them ` +
    `(they only waste budget and return nothing). Do NOT rely on any remembered "known vulnerabilities" list — ` +
    `report ONLY what you directly observe in real request/response pairs you capture with curl. ` +
    // (P1) XSS-ÖNCE: keşiften ÖNCE, ilk 2 dakikada canlı marker testi + TAM yanıt kaydı.
    `FIRST ACTIONS (do these BEFORE any recon, within the first 2 minutes) — send a reflected-XSS probe with the ` +
    `UNIQUE marker zqxmarker9173 to the real search endpoints. ALWAYS use "curl -sk -i" (the -i flag INCLUDES ` +
    `the HTTP status line + headers) and SAVE THE FULL RESPONSE (status line, headers, AND body):\n` +
    `  curl -sk -i --resolve ${d}:443:${pinnedIp} "https://${d}/bank/searchpage.jsp?searchStr=zqxmarker9173<script>alert(1)</script>"\n` +
    `  curl -sk -i --resolve ${d}:443:${pinnedIp} "https://${d}/search.jsp?query=zqxmarker9173<script>alert(1)</script>"\n` +
    `Then verify whether zqxmarker9173 appears UNENCODED (literal <script>, NOT &lt;script&gt;) in the response BODY ` +
    `(the part AFTER the headers). A 4xx/5xx status means the request was REJECTED — that is NOT a finding. ` +
    // (P1) minimum canlı checklist — hepsi curl ile, gerçek hedefte.
    `Then a MINIMAL LIVE checklist via curl only: homepage, login page, at least one parameterized form, one more ` +
    `marker-XSS reflection point, and one light SQLi probe (a single quote ' or ' OR 1=1) observing the response body. ` +
    `Aggressiveness (${job.level}): ${p}. ` +
    `EVIDENCE RULES (mandatory) — for EVERY request print the FULL curl command AND the FULL response (status line + body) ` +
    `to the terminal; the report is built ONLY from these captured request/response pairs, NOT from your prose, plans, or ` +
    `subtask lists. Every finding MUST reference a concrete captured request/response. Keep testing REAL endpoints until ` +
    `the budget cap — do NOT stop early, and do NOT spend time on web_search/browser/memorist.`
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
  rawFlow?: unknown;      // RETENTION: binder --dump-raw (transkript + offline re-bind kaynağı)
  binderTrace?: string;   // binder --trace (artefakt-bazlı karar izi, JSONL)
  error?: string;
}> {
  const steps: StepLog[] = [];
  const { job } = ctx;
  const cfg = { ...LEVEL_CFG[job.level], ...(ctx.cap ?? {}) };
  let provisioned = false;
  let report: RedTeamReport | undefined;
  let rawFlow: unknown;
  let binderTrace: string | undefined;

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
    // Hata detayının SONUNU göster (patlama noktası genellikle çıktının sonundadır).
    await record({ phase, command, ok: r.code === 0, detail: r.code === 0 ? 'ok' : `exit ${r.code}: …${(r.stderr || r.stdout || '').slice(-2000)}` });
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
    if (!ctx.dryRun && !ctx.doTokenPresent) throw new Error('reddedildi: DO token env yok (provision imkânsız)');

    // HEDEFİ ÇÖZ + PINLE (domain ise TÜM A+AAAA). Yasak IP'ye çözülürse (çok-IP: HERHANGİ biri)
    // TÜM hedef reddedilir. Bundan sonra egress/saldırı YALNIZ pinlenen IP'ye — domain bir daha
    // çözülmez (DNS-rebinding engeli).
    const pin = await resolveAndPin(job.domain, ctx.resolver ?? nodeResolver);
    if (!pin.ok) throw new Error(`reddedildi: ${pin.reason}`);
    const pinnedIps = pin.pinnedIps;
    const primaryIp = pin.family.v4[0] ?? pinnedIps[0]; // saldırı/doğrulama için birincil
    await record({
      phase: 'guard',
      ok: true,
      detail: `onaylar + hedef ÇÖZÜLDÜ+PİNLENDİ [${pinnedIps.join(', ')}] (birincil ${primaryIp}); cap ${cfg.capSec}s/${cfg.capCalls}/$${cfg.capCostUsd}`,
    });

    // ——— 2) PROVISION (efemer izole droplet; boyut seviyeye göre) ———
    // provisioned=true'yu provision DENENMEDEN ÖNCE set et: provision yarım droplet bırakıp patlarsa
    // teardown-finally yine çalışsın (orphan droplet kalmasın). teardown state/name'den temizler.
    provisioned = true;
    await run('provision', `${ctx.scriptsDir}/provision.sh`, [`# SIZE=${cfg.size}`]);

    // ——— 3) SETUP (PentAGI + hedef-erişimi + API-token bootstrap) ———
    // cap.capSec argüman olarak geçer: setup EN BAŞINDA droplet-içi BAĞIMSIZ self-destruct kurar
    // (D1 — orchestrator/Node'dan TAMAMEN AYRI; ana döngü asılı kalsa BİLE droplet kendi kendini yok eder).
    await run('setup', `${ctx.scriptsDir}/droplet-scripts/setup-pentagi.sh`, [String(cfg.capSec)]);

    // ——— 4) HARDEN egress: Anthropic AÇ + YALNIZ pinlenen hedef IP('ler) ———
    await run('harden', `${ctx.scriptsDir}/droplet-scripts/egress-harden-docker.sh`, []);
    for (const ip of pinnedIps) {
      await run('harden', `${ctx.scriptsDir}/droplet-scripts/allow-target.sh`, [ip]);
    }

    // ——— 5) VERIFY isolation (AMPİRİK): PİNLENEN hedef erişilir + CyberTestify BLOCKED. Geçmezse ABORT ———
    // İki koşulu AYRI değerlendir + logla (muğlak "erişilemez YA DA açık" yerine hangisi tuttu).
    const v = await run('verify', `${ctx.scriptsDir}/droplet-scripts/verify-egress.sh`, [primaryIp]);
    if (!ctx.dryRun) {
      const targetOk = /TARGET_OK/.test(v.stdout);
      const ctBlocked = /CYBERTESTIFY_BLOCKED/.test(v.stdout);
      await record({
        phase: 'verify',
        ok: targetOk && ctBlocked,
        detail: `izolasyon: hedef-erişilir=${targetOk ? '✓' : '✗'} · CyberTestify-BLOCKED=${ctBlocked ? '✓' : '✗'}`,
      });
      if (!(targetOk && ctBlocked)) {
        const why = !ctBlocked
          ? 'CyberTestify AÇIK — CİDDİ izolasyon hatası (egress-harden bozuk); kampanya İPTAL'
          : 'yetkili hedefe egress/erişim yok; kampanya İPTAL';
        throw new Error(`izolasyon BAŞARISIZ: hedef-erişilir=${targetOk ? '✓' : '✗'}, CyberTestify-BLOCKED=${ctBlocked ? '✓' : '✗'} → ${why}`);
      }
    }

    // ——— 6) CAMPAIGN (cap'li; seviyeye göre profil/prompt; saldırı YALNIZ pinlenen IP'ye) ———
    // KRİTİK: görev launch_cap.py'ye GERÇEK arg olarak geçer (base64 → tek token, shell-güvenli). ÖNCE
    // `# CAMPAIGN_PROMPT=...` idi ama runner '#'-argümanlarını ATIYORDU → env hiç ulaşmıyordu → launch_cap
    // gömülü juiceshop:3000 default'una düşüyordu (ajan bir saat juiceshop arıyordu, 0-kanıtlı kök-nedeni).
    const promptB64 = Buffer.from(levelPrompt(job, primaryIp), 'utf8').toString('base64');
    await run('campaign', `${ctx.scriptsDir}/droplet-scripts/launch_cap.py`, [
      '--prompt-b64', promptB64,
      '--cap-sec', String(cfg.capSec), '--cap-calls', String(cfg.capCalls), '--cap-cost', String(cfg.capCostUsd),
      '--target', job.domain, // D2/D3 kapısı: flow görevi hedefi içermeli, juiceshop içermemeli
    ]);

    // ——— 7) BIND (PentAGI Postgres → 3-katman JSON; ham artefakta bağlı) ———
    // GERÇEK flow id: launch_cap.py onu /opt/pentagi-run/flow_id'e yazdı → droplet'te $(cat ...) ile oku
    // (placeholder <flowId> DEĞİL; bash onu redirect sanıyordu).
    // --target/--target-ip: PROVENANCE kuralı (hedef-dışı host referanslayan bulgu elenir).
    const b = await run('bind', `${ctx.scriptsDir}/droplet-scripts/binder.py`, [
      '--flow', '$(cat /opt/pentagi-run/flow_id)', '--target', job.domain, '--target-ip', primaryIp, '--json',
    ]);
    const binderOutput: BinderOutput = ctx.dryRun
      ? { artifactCount: 0, claimCount: 0, summary: { kanitli: 0, belirsiz: 0, hayalet: 0 }, overallRisk: 'temiz', findings: [] }
      : (JSON.parse(b.stdout) as BinderOutput);

    // ——— 7b) ŞEFFAFLIK + RETENTION: droplet DURURKEN ham veri + karar-izini çek (best-effort; teardown
    // sonrası transkript/re-bind için). run() DEĞİL ctx.exec: retention başarısızlığı raporu bloklamasın.
    if (!ctx.dryRun) {
      const binderArgs = ['--flow', '$(cat /opt/pentagi-run/flow_id)', '--target', job.domain, '--target-ip', primaryIp];
      const binderBin = `${ctx.scriptsDir}/droplet-scripts/binder.py`;
      try {
        const dr = await ctx.exec(binderBin, [...binderArgs, '--dump-raw']);
        if (dr.code === 0 && dr.stdout.trim()) rawFlow = JSON.parse(dr.stdout);
      } catch { /* retention best-effort */ }
      try {
        const tr = await ctx.exec(binderBin, [...binderArgs, '--trace']);
        if (tr.code === 0 && tr.stdout.trim()) binderTrace = tr.stdout;
      } catch { /* best-effort */ }
      const art = (rawFlow as { artifacts?: unknown[] } | undefined)?.artifacts?.length ?? 0;
      await record({ phase: 'bind', ok: true, detail: `retention: ham-veri ${rawFlow ? `✓ (${art} artefakt)` : '—'} · karar-izi ${binderTrace ? '✓' : '—'}` });
    }

    // ——— 8) REPORT (deterministik render; şişirme yok) ———
    report = buildRedTeamReport(binderOutput, {
      target: job.domain,
      level: job.level,
      environment: job.environment,
      generatedAt: ctx.dryRun ? '<dry-run>' : new Date().toISOString(),
    });
    await record({ phase: 'report', ok: true, detail: `rapor: kanıtlı ${report.counts.kanitli} · belirsiz ${report.counts.belirsiz} · elenen ${report.eliminated} · risk ${report.overallRisk}` });

    return { ok: true, steps, report, rawFlow, binderTrace };
  } catch (e) {
    await record({ phase: 'guard', ok: false, detail: (e as Error).message });
    return { ok: false, steps, error: (e as Error).message, report, rawFlow, binderTrace };
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
