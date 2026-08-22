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

export type StepLog = { phase: Phase; command?: string; ok: boolean; detail: string; atMs?: number; sinceStartSec?: number };

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
const DROPLET_RUN = '/opt/pentagi-run';  // droplet'te script/veri dizini (runner ile aynı sabit)
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

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
    // (P1) XSS-ÖNCE + ŞARTLI ENCODE-RETRY: her uç için ham→encode retry döngüsü BAĞIMSIZ, plandan ÖNCE.
    `FIRST ACTIONS (do these BEFORE any recon/plan, within the first 2 minutes) — for EACH of the two search ` +
    `endpoints below run an INDEPENDENT reflected-XSS probe. ALWAYS use "curl -sk -i" (-i INCLUDES the HTTP ` +
    `status line + headers) and SAVE THE FULL RESPONSE (status line, headers, AND body). First the RAW <script>:\n` +
    `  curl -sk -i --resolve ${d}:443:${pinnedIp} "https://${d}/bank/searchpage.jsp?searchStr=zqxmarker9173<script>alert(1)</script>"\n` +
    `  curl -sk -i --resolve ${d}:443:${pinnedIp} "https://${d}/search.jsp?query=zqxmarker9173<script>alert(1)</script>"\n` +
    `CONDITIONAL ENCODE-RETRY (CRITICAL): if a RAW-<script> probe returns a TRANSPORT-LEVEL rejection ` +
    `(400/403/406 — the server/parser refused the request LINE, the app never processed the value), do NOT treat ` +
    `that as "no finding". IMMEDIATELY, in the SAME minute and BEFORE any plan step, RE-SEND the SAME parameter ` +
    `with a URL-ENCODED payload (%3Cscript%3E…%3C%2Fscript%3E) using curl -G --data-urlencode:\n` +
    `  curl -sk -i -G --resolve ${d}:443:${pinnedIp} "https://${d}/bank/searchpage.jsp" --data-urlencode "searchStr=zqxmarker9173<script>alert(1)</script>"\n` +
    `  curl -sk -i -G --resolve ${d}:443:${pinnedIp} "https://${d}/search.jsp" --data-urlencode "query=zqxmarker9173<script>alert(1)</script>"\n` +
    `Each endpoint runs its OWN raw→encode-retry loop INDEPENDENTLY — one must NOT block the other, and you must ` +
    `NOT defer the encode-retry to the end of the plan. Then verify whether zqxmarker9173 appears UNENCODED ` +
    `(literal <script>, NOT &lt;script&gt;) in the response BODY (the part AFTER the headers) of a 2xx response ` +
    `(that is a KANITLI reflected XSS). Only if BOTH the raw AND the encoded attempt return 4xx/5xx for an ` +
    `endpoint may you conclude "no finding" there. ` +
    // (P0-1) ZORUNLU canlı checklist — numaralı adımlar; TEK bulgu bulmak koşuyu BİTİRMEZ.
    `MANDATORY LIVE CHECKLIST (curl only, real target) — you MUST complete ALL of steps 1-3 for BOTH endpoints ` +
    `even if you already confirmed one reflected XSS; finding ONE issue does NOT complete the run:\n` +
    `  STEP 1 — reflected-XSS marker probe WITH encode-retry (the two endpoints above, each its own raw→encoded loop).\n` +
    `  STEP 2 — light SQLi probe on at least one parameterized endpoint: append a single quote ' then ' OR 1=1 and ` +
    `capture the FULL response body; look for a SQL error string OR a clear behavioral difference vs the baseline.\n` +
    `  STEP 3 — a SECOND distinct reflected-XSS reflection point (a different parameter/page than STEP 1), same marker method.\n` +
    `(Cookie security flags and Server/version information-disclosure are extracted DETERMINISTICALLY by the platform from ` +
    `the responses you already captured — you do NOT need to assess them yourself; just make sure your STEP 1-3 requests ` +
    `use "curl -sk -i" so the full headers, including Set-Cookie and Server, are captured.) ` +
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
  liveCostUsd?: number | null; // GERÇEK Anthropic harcaması (msgchains) — TEK kaynak (puller sayacı değil)
  agentSec?: number | null;    // (P0-5) yalnız ajan (campaign) süresi — infra hariç
  error?: string;
}> {
  const steps: StepLog[] = [];
  const { job } = ctx;
  const cfg = { ...LEVEL_CFG[job.level], ...(ctx.cap ?? {}) };
  let provisioned = false;
  let report: RedTeamReport | undefined;
  let rawFlow: unknown;
  let binderTrace: string | undefined;
  let liveCostUsd: number | null = null;
  let agentSec: number | null = null;   // (P0-5) YALNIZ campaign (ajan) süresi — infra süresinden AYRI

  // (P0-5) Faz-geçiş zaman damgaları: her adıma mutlak ms + koşu-başından geçen saniye ekle. dryRun'da
  // Date sabit değil ama orchestrator Node'da çalışır (binder/report saf; onlar saat okumaz). Böylece
  // "1120s > 600s" gibi süre farkı, self-report'a GÜVENMEDEN gerçek faz damgalarından açıklanır.
  const runStartMs = Date.now();
  const record = async (s: StepLog) => {
    const now = Date.now();
    const stamped: StepLog = { ...s, atMs: now, sinceStartSec: Math.round((now - runStartMs) / 1000) };
    steps.push(stamped);
    if (ctx.onStep) await ctx.onStep(stamped);
  };
  // (D2 — GERÇEK HATAYI GİZLEME) Log satırı 2000 karakterde kırpılıyor; campaign komutu ~1.6KB base64
  // --prompt-b64 taşıdığı için GERÇEK hata (exit kodu + stderr) kırpılıp KAYBOLUYORDU. Uzun argümanları
  // (özellikle base64 prompt) kısaltarak GÖSTER — böylece exit+stderr her zaman log'a sığar/görünür.
  const displayCmd = (cmd: string, args: string[]): string =>
    [cmd, ...args.map((a) => (a.length > 100 ? `${a.slice(0, 24)}…(${a.length}b)` : a))].join(' ');
  const run = async (phase: Phase, cmd: string, args: string[]): Promise<ExecResult> => {
    const command = displayCmd(cmd, args);
    if (ctx.dryRun) {
      await record({ phase, command, ok: true, detail: '[dry-run] çalıştırılmadı' });
      return { code: 0, stdout: '', stderr: '' };
    }
    const r = await ctx.exec(cmd, args);
    // Hata detayının SONUNU göster (patlama noktası genellikle çıktının sonundadır). Komut kısaltıldığı
    // için stderr artık 2000-karakter log tavanına RAHAT sığar. stderr boşsa stdout'u göster (launch_cap
    // "API hazır olmadı"/"FATAL ..." gibi tanısal mesajları stdout'a basar).
    await record({ phase, command, ok: r.code === 0, detail: r.code === 0 ? 'ok' : `exit ${r.code}: ${(r.stderr || r.stdout || '(çıktı yok)').slice(-1500)}` });
    if (r.code !== 0) throw new Error(`${phase} başarısız (exit ${r.code}): ${(r.stderr || r.stdout || '').slice(-300)}`);
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
    // KARARI ÇIKIŞ KODUNDAN DEĞİL, BASILAN SONUÇTAN VER: verify-egress.sh iki GEREKLİ kontrolü (TARGET_OK
    // + CYBERTESTIFY_BLOCKED) stdout'a basar; ama SON (bilgi-amaçlı metadata) docker-run'ı zaman zaman SSH
    // oturumunu düşürüp exit 255 döndürüyordu → run() bunu "verify başarısız" sanıp gerekli kontroller GEÇMİŞ
    // olsa BİLE koşuyu iptal ediyordu. Artık ctx.exec ile çağırıp (throw YOK) çıktının TAMAMINI logla, kararı
    // parse edilen sonuçtan ver. Betik de artık deterministik exit veriyor; bu, transport 255'e karşı emniyet.
    if (!ctx.dryRun) {
      const v = await ctx.exec(`${ctx.scriptsDir}/droplet-scripts/verify-egress.sh`, [primaryIp]);
      const out = `${v.stdout || ''}\n${v.stderr || ''}`;
      const targetOk = /TARGET_OK/.test(out);
      const ctBlocked = /CYBERTESTIFY_BLOCKED/.test(out);
      // (D2) verify-egress'in TÜM çıktısı log'a — bir daha "exit N ama neden" körlüğü olmasın.
      await record({ phase: 'verify', command: `verify-egress.sh ${primaryIp} (exit ${v.code})`, ok: v.code === 0,
        detail: out.trim().replace(/\n+/g, ' · ').slice(0, 1500) || '(çıktı yok)' });
      await record({
        phase: 'verify', ok: targetOk && ctBlocked,
        detail: `izolasyon: hedef-erişilir=${targetOk ? '✓' : '✗'} · CyberTestify-BLOCKED=${ctBlocked ? '✓' : '✗'}${v.code !== 0 ? ` (betik exit ${v.code} — karar çıktıdan verildi)` : ''}`,
      });
      if (!(targetOk && ctBlocked)) {
        const why = !ctBlocked
          ? 'CyberTestify AÇIK — CİDDİ izolasyon hatası (egress-harden bozuk); kampanya İPTAL'
          : 'yetkili hedefe egress/erişim yok (çıktı: ' + out.trim().slice(-200) + '); kampanya İPTAL';
        throw new Error(`izolasyon BAŞARISIZ: hedef-erişilir=${targetOk ? '✓' : '✗'}, CyberTestify-BLOCKED=${ctBlocked ? '✓' : '✗'} → ${why}`);
      }
    } else {
      await record({ phase: 'verify', command: 'verify-egress.sh', ok: true, detail: '[dry-run] çalıştırılmadı' });
    }

    // ——— 6) CAMPAIGN (DETACHED + poll) — uzun-ömürlü TEK SSH KIRILGAN'dı ———
    // KÖK NEDEN (kanıtlanmış): campaign, launch_cap.py'yi ~600s süren TEK bir SSH komutu olarak çalıştırıyordu.
    // Ajan başlayınca docker konteyner/iptables churn'ü bu uzun-ömürlü SSH oturumunu düşürüp exit 255
    // veriyordu → launch_cap SIGHUP ile ölüyor → 0 artefakt. (Puller'ın KISA per-poll SSH'ları aynı anda
    // ÇALIŞIYORDU — llmCalls=1 yakalandı.) ÇÖZÜM: launch_cap'i droplet'te setsid ile DETACHED başlat (SSH
    // oturumundan KOP), çıktıyı campaign.log'a yaz, bitince exit kodunu campaign.done'a yaz; orchestrator
    // KISA SSH'larla poll'lar. SSH düşse bile bir sonraki poll yeniden bağlanır; launch_cap ölmez.
    const promptB64 = Buffer.from(levelPrompt(job, primaryIp), 'utf8').toString('base64');
    const capArgs = `--prompt-b64 ${promptB64} --cap-sec ${cfg.capSec} --cap-calls ${cfg.capCalls} --cap-cost ${cfg.capCostUsd} --target ${job.domain}`;
    if (!ctx.dryRun) {
      const startCmd =
        `rm -f ${DROPLET_RUN}/campaign.done ${DROPLET_RUN}/campaign.log 2>/dev/null; ` +
        `setsid sh -c 'python3 ${DROPLET_RUN}/launch_cap.py ${capArgs} > ${DROPLET_RUN}/campaign.log 2>&1; echo $? > ${DROPLET_RUN}/campaign.done' </dev/null >/dev/null 2>&1 & echo CAMPAIGN_STARTED`;
      const started = await ctx.exec(startCmd, []);
      if (!/CAMPAIGN_STARTED/.test(started.stdout)) {
        throw new Error(`campaign başlatılamadı: ${(started.stderr || started.stdout || '(çıktı yok)').slice(-300)}`);
      }
      const campaignStartMs = Date.now();   // (P0-5) ajan-süresi ölçümü BURADA başlar (infra hariç)
      await record({ phase: 'campaign', command: `launch_cap.py (detached, cap ${cfg.capSec}s)`, ok: true, detail: 'ajan arka planda başlatıldı — tamamlanması KISA-SSH poll ile bekleniyor (uzun-SSH kırılganlığı giderildi)' });

      // Poll: campaign.done belirene kadar KISA SSH ile bekle. Süre tavanı capSec+150 (launch_cap kendi
      // cap'inde biter; watchdog cap+60'ta nihai backstop). Poll'daki SSH düşmeleri ölümcül DEĞİL — atla.
      const pollDeadline = Date.now() + (cfg.capSec + 150) * 1000;
      let campExit: string | null = null;
      while (Date.now() < pollDeadline) {
        await sleep(8000);
        const d = await ctx.exec(`cat ${DROPLET_RUN}/campaign.done 2>/dev/null`, []);
        if (d.code === 0 && d.stdout.trim() !== '') { campExit = d.stdout.trim(); break; }
      }
      agentSec = Math.round((Date.now() - campaignStartMs) / 1000);   // (P0-5) GERÇEK ajan süresi
      const tail = await ctx.exec(`tail -n 6 ${DROPLET_RUN}/campaign.log 2>/dev/null`, []);
      await record({
        phase: 'campaign', ok: campExit === '0' || campExit === null,
        detail: `launch_cap ${campExit === null ? 'poll zaman aşımı (watchdog devrede)' : `bitti (exit ${campExit})`} · ajan-süresi ${agentSec}s (cap ${cfg.capSec}s) — ${(tail.stdout || '').trim().replace(/\n+/g, ' · ').slice(-760)}`,
      });
      // NOT: campaign non-zero exit'te BILE bind'e devam edilir — o ana kadar üretilmiş artefaktlar
      // (varsa) rapora bağlansın; boşsa dürüst boş rapor. (Eski davranış: abort → hiç rapor yok.)
    } else {
      await record({ phase: 'campaign', command: 'launch_cap.py', ok: true, detail: '[dry-run] çalıştırılmadı' });
    }

    // ——— 7) BIND (PentAGI Postgres → 3-katman JSON; ham artefakta bağlı) ———
    // GERÇEK flow id: launch_cap.py onu /opt/pentagi-run/flow_id'e yazdı → droplet'te $(cat ...) ile oku
    // (placeholder <flowId> DEĞİL; bash onu redirect sanıyordu).
    // --target/--target-ip: PROVENANCE kuralı (hedef-dışı host referanslayan bulgu elenir).
    // bind RESİLİENT: run() değil ctx.exec — binder hata verse/flow boş olsa BİLE abort ETME, dürüst boş
    // rapor üret (campaign kısmen çalışmış olabilir; eldeki artefaktlar bağlansın).
    let binderOutput: BinderOutput = { artifactCount: 0, claimCount: 0, summary: { kanitli: 0, belirsiz: 0, hayalet: 0 }, overallRisk: 'temiz', findings: [] };
    if (!ctx.dryRun) {
      const b = await ctx.exec(`${ctx.scriptsDir}/droplet-scripts/binder.py`,
        ['--flow', '$(cat /opt/pentagi-run/flow_id)', '--target', job.domain, '--target-ip', primaryIp, '--json']);
      try { if (b.stdout.trim()) binderOutput = JSON.parse(b.stdout) as BinderOutput; }
      catch { await record({ phase: 'bind', ok: false, detail: `binder çıktısı ayrıştırılamadı (boş rapor): ${(b.stderr || b.stdout || '').slice(-300)}` }); }
    }

    // ——— 7b) ŞEFFAFLIK + RETENTION + GERÇEK MALİYET: droplet DURURKEN ham veri + karar-izi + GERÇEK
    // Anthropic harcaması (msgchains) çekilir. Maliyet TEK GERÇEK KAYNAKtan (msgchains) okunur — puller'ın
    // canlı sayacı (cost async yazıldığı için) 0 kalsa BİLE, burada koşu-sonu gerçek harcama yakalanır.
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
      try {
        const c = await ctx.exec(`docker exec pgvector psql -U postgres -d pentagidb -tAc "SELECT COALESCE(SUM(usage_cost_in+usage_cost_out),0)::numeric(12,4) FROM msgchains;" 2>/dev/null`, []);
        const n = Number((c.stdout || '').trim());
        if (Number.isFinite(n) && n >= 0) liveCostUsd = n;
      } catch { /* best-effort */ }
      const art = (rawFlow as { artifacts?: unknown[] } | undefined)?.artifacts?.length ?? 0;
      await record({ phase: 'bind', ok: true, detail: `retention: ham-veri ${rawFlow ? `✓ (${art} artefakt)` : '—'} · karar-izi ${binderTrace ? '✓' : '—'} · gerçek maliyet ${liveCostUsd != null ? `$${liveCostUsd.toFixed(4)}` : '—'}` });

      // (TEŞHİS) Ajan hiç subtask üretmediyse PentAGI'nin KENDİ container log'unu yakala — agent-loop neden
      // başlamadı görünür olsun (maskSecrets persistStep'te uygulanır). Yalnız 0 artefaktta çek (gürültü yok).
      if (art === 0) {
        try {
          const plog = await ctx.exec(`docker logs pentagi --tail 40 2>&1 | grep -iE 'error|panic|fatal|exception|refus|denied|worker|flow|agent' | tail -20`, []);
          const txt = (plog.stdout || plog.stderr || '').trim();
          await record({ phase: 'bind', ok: false, detail: `0 artefakt — PentAGI container log (agent-loop tanısı): ${txt ? txt.replace(/\n+/g, ' · ').slice(-1200) : '(ilgili satır yok)'}` });
        } catch { /* best-effort */ }
      }
    }

    // ——— 8) REPORT (deterministik render; şişirme yok) ———
    const totalSec = Math.round((Date.now() - runStartMs) / 1000);   // (P0-5) toplam wall-clock (infra dahil)
    report = buildRedTeamReport(binderOutput, {
      target: job.domain,
      level: job.level,
      environment: job.environment,
      generatedAt: ctx.dryRun ? '<dry-run>' : new Date().toISOString(),
      costUsd: liveCostUsd, // GERÇEK msgchains harcaması → rapor/panel TEK kaynaktan
      agentSec,             // (P0-5) yalnız ajan süresi
      elapsedSec: totalSec, // (P0-5) toplam süre (provision+setup+campaign+bind+report) — runner override edebilir
    });
    // (P0-5) Süre farkını DÜRÜSTÇE açıkla: ajan-süresi cap'i aşamaz; toplam süre infra fazlarını da içerir.
    await record({ phase: 'report', ok: true, detail: `rapor: kanıtlı ${report.counts.kanitli} · belirsiz ${report.counts.belirsiz} · elenen ${report.eliminated} · risk ${report.overallRisk} · süre: ajan ${agentSec ?? '?'}s / toplam ${totalSec}s (fark = infra: provision+setup+bind+teardown)` });

    return { ok: true, steps, report, rawFlow, binderTrace, liveCostUsd, agentSec };
  } catch (e) {
    await record({ phase: 'guard', ok: false, detail: (e as Error).message });
    return { ok: false, steps, error: (e as Error).message, report, rawFlow, binderTrace, liveCostUsd, agentSec };
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
