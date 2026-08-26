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
  // (P0-7 ÖLÇÜLÜ ARTIŞ) 600→900s (15dk, alt sınır — agresif sıçrama YOK), $2→$2.50 küçük kontrollü artış;
  // çağrı tavanı 30 aynen (13 çağrı kullanıldı, darboğaz değildi). Watchdog(cap+60)/self-destruct(cap+1200)
  // formülleri capSec'e GÖRECELİ olduğundan otomatik orantılı ölçeklenir — mimari değişmez, sadece taban.
  S1: { capSec: 900, capCalls: 30, capCostUsd: 2.5, size: 's-2vcpu-4gb', profile: 'pasif + hafif aktif göstergeler (düşük risk)' },
  S2: { capSec: 720, capCalls: 40, capCostUsd: 3.0, size: 's-4vcpu-8gb', profile: 'aktif doğrulama + sınırlı sömürü denemesi (dengeli)' },
  S3: { capSec: 900, capCalls: 55, capCostUsd: 4.0, size: 's-4vcpu-8gb', profile: 'geniş sömürü yüzeyi, zincirleme denemeler (agresif)' },
};

// Hedef IP yasak-aralık kontrolü artık targetGuard.ts'te (IPv4+IPv6, çok-IP, çöz+pinle).
const DROPLET_RUN = '/opt/pentagi-run';  // droplet'te script/veri dizini (runner ile aynı sabit)
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

function levelPrompt(job: RedTeamJobInput, pinnedIp: string): string {
  const p = LEVEL_CFG[job.level].profile;
  const d = job.domain;
  // (P4 ASILI-HEDEF KÖK NEDEN — FIX#4) Ajanın KENDİ curl'lerinde --max-time yoktu; yavaş/asılı hedefte
  // (ör. testasp datacenter IP'sinden) baseline curl sonsuza asıldı → ajan 30s hareketsiz → watchdog
  // koşuyu ÖLDÜRDÜ → keşif/prob hiç çalışamadı → boş "Temiz". Bu yüzden HER curl bounded olmalı.
  const ct = `curl -sk -i --connect-timeout 10 --max-time 25`;
  return (
    `You are an authorized penetration tester. Target application: https://${d}/ (the operator owns it). ` +
    // Pinlenen IP'ye bağlan AMA Host/SNI = domain gönder → doğru vhost GERÇEK uygulamayı sunar.
    `Connect ONLY to the pinned IP ${pinnedIp}, but ALWAYS send Host: ${d} and SNI ${d} ` +
    `(e.g. curl -sk --connect-timeout 10 --max-time 25 --resolve ${d}:443:${pinnedIp} --resolve ${d}:80:${pinnedIp} "https://${d}/..."). ` +
    `Do NOT re-resolve the domain and do NOT touch any other host. ` +
    // (P4/FIX#4) ZORUNLU TIMEOUT — timeout'suz tek bir asılı curl TÜM koşuyu 30s-hareketsizlik hard-stop'una sürükler.
    `MANDATORY TIMEOUTS — EVERY curl you run MUST include "--connect-timeout 10 --max-time 25" (baseline homepage ` +
    `fetch, discovery/robots/sitemap fetches, and ALL XSS/SQLi probes — NO exception). NEVER run a curl WITHOUT ` +
    `--max-time: a single hung request (a slow/rate-limited target) with no timeout stalls you, and after 30s of ` +
    `inactivity the run is force-stopped before discovery even begins. A curl that times out is FINE — it returns ` +
    `promptly and you move on to the next endpoint; a curl with no --max-time is NOT fine. ` +
    // (P1) İzole ortamda erişilemeyen araçlar — bunlara zaman/bütçe HARCAMA (bu koşuda ajan 11 dk'yı
    // web_search/browser/memorist'te yaktı, asıl XSS payload'ını hiç göndermedi).
    `ENVIRONMENT LIMITS — web_search, browser, and memorist/vector-DB are NOT reachable here; DO NOT use them ` +
    `(they only waste budget and return nothing). Do NOT rely on any remembered "known vulnerabilities" list — ` +
    `report ONLY what you directly observe in real request/response pairs you capture with curl. ` +
    // (P3 HEDEF-ÖZEL KEŞİF — ASIL KÖK NEDEN) Hardcoded testfire path'leri (bank/searchpage.jsp, search.jsp)
    // HER hedefte "zorunlu ilk aksiyon" olarak deneniyordu → testasp (ASP/IIS) gibi hedeflerde o path 404 →
    // yansıma yok → yanlış "Temiz". Artık prob'lardan ÖNCE hedefin GERÇEK giriş noktaları keşfedilir; prob'lar
    // keşfedilen uç'lara atılır. Hardcoded liste yalnız keşif HİÇ sonuç vermezse son-çare fallback.
    `TARGET-SPECIFIC DISCOVERY FIRST (do this BEFORE any XSS/SQLi probe, in the first ~2-3 minutes) — the target's ` +
    `real entry points are NOT known in advance and DIFFER per stack (ASP/.asp, JSP/.jsp, PHP/.php); do NOT assume any ` +
    `preset path exists. (a) Fetch the homepage and 3-6 internal pages with "${ct} --resolve ${d}:443:${pinnedIp} ...", ` +
    `printing the FULL response to STDOUT. (b) From the captured HTML extract THIS target's OWN entry points: <a href> ` +
    `links (ESPECIALLY those carrying a "?param=" query string), <form action=...> targets together with their ` +
    `<input name=...> field names, and any URL that carries a parameter. (c) Also fetch /robots.txt and /sitemap.xml if ` +
    `present and harvest paths from them. (d) Read the "Server" response header and the page extensions to prefer ` +
    `stack-appropriate parameterized endpoints. Build a SHORT list of THIS target's real parameterized entry points ` +
    `(path + parameter name) — these, NOT any preset path, are what you probe next. ` +
    // (P2 KANIT-YAKALAMA — FIX#2) Gövde STDOUT'ta olmalı; -o/-w/> YASAK (dosyaya yazılan gövde platforma görünmez).
    `EVIDENCE CAPTURE (applies to EVERY request): ALWAYS use "${ct}" (-i INCLUDES the HTTP status line + headers, ` +
    `and the timeouts keep a slow endpoint from stalling the run) ` +
    `and let the FULL RESPONSE (status line, headers, AND body) PRINT TO THE TERMINAL (stdout). NEVER use -o/--output, ` +
    `NEVER redirect with ">", and NEVER use -w/--write-out as a substitute for the body — a response saved to a FILE is ` +
    `INVISIBLE to the platform (it reads ONLY your terminal stdout) and counts as NO evidence. ` +
    // (P0-1) ZORUNLU canlı checklist — KEŞFEDİLEN uç'lara; TEK bulgu bulmak koşuyu BİTİRMEZ.
    `MANDATORY LIVE CHECKLIST (curl only, real target) — run these against the DISCOVERED entry points above; you MUST ` +
    `complete ALL of steps 1-3 even if you already confirmed one reflected XSS (finding ONE issue does NOT complete the run):\n` +
    `  STEP 1 — reflected-XSS marker probe on EACH discovered parameterized entry point. First send the RAW <script> ` +
    `directly in the query (for a discovered PATH with parameter PARAM):\n` +
    `    ${ct} --resolve ${d}:443:${pinnedIp} "https://${d}/<discovered-path>?<discovered-param>=zqxmarker9173<script>alert(1)</script>"\n` +
    `  CONDITIONAL ENCODE-RETRY (CRITICAL): if the RAW probe returns a TRANSPORT-LEVEL rejection (400/403/406 — the ` +
    `server/parser refused the request LINE, the app never processed the value), do NOT call it "no finding"; IMMEDIATELY ` +
    `re-send the SAME parameter URL-ENCODED (%3Cscript%3E…%3C%2Fscript%3E) with curl -G --data-urlencode:\n` +
    `    ${ct} -G --resolve ${d}:443:${pinnedIp} "https://${d}/<discovered-path>" --data-urlencode "<discovered-param>=zqxmarker9173<script>alert(1)</script>"\n` +
    `  Each endpoint runs its OWN raw→encode-retry loop INDEPENDENTLY. Then verify whether zqxmarker9173 appears UNENCODED ` +
    `(literal <script>, NOT &lt;script&gt;) in the response BODY (the part AFTER the headers) of a 2xx response ` +
    `(that is a KANITLI reflected XSS). Conclude "no finding" for an endpoint ONLY if BOTH the raw AND the encoded attempt return 4xx/5xx.\n` +
    `  STEP 2 — light SQLi probe on at least one DISCOVERED parameterized endpoint: append a single quote ' then ' OR 1=1 and ` +
    `capture the FULL response body; look for a SQL error string OR a clear behavioral difference vs the baseline.\n` +
    `  STEP 3 — a SECOND distinct reflected-XSS reflection point (a different DISCOVERED parameter/page than STEP 1), same marker method.\n` +
    `FALLBACK — ONLY IF DISCOVERY FINDS NO PARAMETERIZED ENDPOINT AT ALL, then (and only then) try these common cross-stack ` +
    `search paths as a last resort: /Search.asp?tfSearch= (ASP/IIS), /bank/searchpage.jsp?searchStr= and /search.jsp?query= ` +
    `(JSP), /search.php?q= (PHP) — but the target's OWN discovered endpoints ALWAYS take priority over this list. ` +
    `(Cookie security flags and Server/version information-disclosure are extracted DETERMINISTICALLY by the platform from ` +
    `the responses you already captured — you do NOT need to assess them yourself; just make sure your STEP 1-3 requests ` +
    `use "${ct}" so the full headers, including Set-Cookie and Server, are captured.) ` +
    `Aggressiveness (${job.level}): ${p}. ` +
    `EVIDENCE RULES (mandatory) — for EVERY request print the FULL curl command AND the FULL response (status line + body) ` +
    `to the terminal STDOUT (never with -o/--output, never with ">", never -w instead of the body — a body saved to a file is ` +
    `INVISIBLE and counts as NO evidence); the report is built ONLY from these captured request/response pairs, NOT from your prose, plans, or ` +
    `subtask lists. Every finding MUST reference a concrete captured request/response. Keep testing REAL endpoints until ` +
    `the budget cap — do NOT stop early, and do NOT spend time on web_search/browser/memorist.`
  );
}

// ————————————————————— (P0-1b) DETERMİNİSTİK CHECKLIST HARD-GATE ————————————————————————
// Ajanın erken durması (STEP1 XSS bulunca STEP2 SQLi/STEP3 2. yansımayı atlaması) checklist kapsamını
// DÜŞÜREMESİN. Ajanın GERÇEKTEN dokunduğu parametreli uç-noktaları rawFlow'dan keşfedip, kampanya
// SONRASI orkestratör bu uç-noktalara SQLi + 2. XSS probunu DETERMİNİSTİK atar ($0 LLM). Sonuçlar
// binder'a --extra ile verilir → aynı kanıt barıyla sınıflanır (imza varsa kanıtlı, yoksa "denendi").
export type ProbeTarget = { path: string; param?: string };
export function discoverProbeTargets(rawFlow: unknown): ProbeTarget[] {
  const arts = ((rawFlow as { artifacts?: Array<{ command?: string }> } | undefined)?.artifacts) ?? [];
  const seen = new Map<string, ProbeTarget>();
  for (const a of arts) {
    const cmd = a?.command ?? '';
    const um = /https?:\/\/[^/\s"']+(\/[^\s"'?\\]*)(?:\?([^\s"'\\]*))?/.exec(cmd);
    if (!um) continue;
    const path = um[1];
    // statik varlık / kök / dosya-sistemi yolu → prob hedefi değil.
    if (!path || path === '/' || /\.(png|jpe?g|gif|svg|ico|css|js|woff2?|map)$/i.test(path) || /^\/(root|work|tmp|etc|var|opt)\b/.test(path)) continue;
    let param: string | undefined;
    const dm = /--data-urlencode\s+["']?([A-Za-z0-9_.\-]+)=/.exec(cmd);
    if (dm) param = dm[1];
    else if (um[2]) { const q = /^([A-Za-z0-9_.\-]+)=/.exec(um[2]); if (q) param = q[1]; }
    const key = `${path}|${param ?? ''}`;
    if (!seen.has(key)) seen.set(key, { path, param });
  }
  // Parametreli uç-noktaları öne al (SQLi/XSS probu için param gerekli); en çok 3 hedef.
  return [...seen.values()].sort((x, y) => (y.param ? 1 : 0) - (x.param ? 1 : 0)).slice(0, 3);
}

// (P0-8) Login formu SQLi için aday path'ler: ajanın gerçekten dokunduğu login-benzeri path'ler
// (rawFlow'dan) + yaygın varsayılanlar. run_probes.py bunları GET'leyip parola-alanlı formu bulunca
// action'a SQLi POST atar — "arama kutusuna tırnak" login testi SAYILMAZ.
const LOGIN_DEFAULTS = ['/login.jsp', '/doLogin', '/login', '/signin', '/auth/login', '/account/login', '/user/login'];
export function discoverLoginCandidates(rawFlow: unknown): string[] {
  const arts = ((rawFlow as { artifacts?: Array<{ command?: string }> } | undefined)?.artifacts) ?? [];
  const found = new Set<string>();
  for (const a of arts) {
    const cmd = a?.command ?? '';
    const um = /https?:\/\/[^/\s"']+(\/[^\s"'?\\]*)/.exec(cmd);
    const path = um?.[1];
    if (path && /(login|signin|logon|doLogin|authenticate|auth\b)/i.test(path)) found.add(path);
  }
  // Keşfedilenler önce, sonra varsayılanlar (tekrarsız). run_probes ilk çalışan login formunda durur.
  return [...found, ...LOGIN_DEFAULTS.filter((d) => !found.has(d))].slice(0, 8);
}

export type ProbePlan = { probes: Array<{ path?: string; param?: string; payload: string; family: 'sqli' | 'xss' | 'login_sqli'; candidates?: string[] }> };
export function buildProbePlan(targets: ProbeTarget[], loginCandidates: string[] = []): ProbePlan {
  const probes: ProbePlan['probes'] = [];
  // (P0-8) STEP2 zorunlu alt-adımı: LOGIN FORMU SQLi — parametreli GET probundan ÖNCE, öncelikli.
  if (loginCandidates.length) {
    probes.push({ family: 'login_sqli', payload: `' OR '1'='1`, candidates: loginCandidates });
  }
  for (const t of targets) {
    if (!t.param) continue;                       // SQLi/XSS probu parametre ister
    probes.push({ path: t.path, param: t.param, payload: `' OR '1'='1`, family: 'sqli' });         // STEP2 (param)
    probes.push({ path: t.path, param: t.param, payload: `zqxprobemarker7788<script>alert(1)</script>`, family: 'xss' }); // STEP3 (2. yansıma)
  }
  return { probes };
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

    // ——— 7) POST-CAMPAIGN: retention(dump-raw) → (P0-1b) deterministik checklist prob geçişi → bind ———
    // Sıra ÖNEMLİ: önce ham veri çekilir (hem retention hem prob-keşfi kaynağı), sonra ajanın atladığı
    // checklist adımları ($0 LLM) deterministik olarak koşturulur, EN SON binder bunları --extra ile birleştirir.
    // GERÇEK flow id: launch_cap.py onu /opt/pentagi-run/flow_id'e yazdı → droplet'te $(cat ...) ile oku.
    // --target/--target-ip: PROVENANCE kuralı (hedef-dışı host referanslayan bulgu elenir).
    let binderOutput: BinderOutput = { artifactCount: 0, claimCount: 0, summary: { kanitli: 0, belirsiz: 0, hayalet: 0 }, overallRisk: 'temiz', findings: [] };
    const binderArgs = ['--flow', '$(cat /opt/pentagi-run/flow_id)', '--target', job.domain, '--target-ip', primaryIp];
    const binderBin = `${ctx.scriptsDir}/droplet-scripts/binder.py`;
    let extraFlag: string[] = [];
    if (!ctx.dryRun) {
      // (7a) RETENTION dump-raw — ham claims+artifacts (redakteli). Prob keşfi de bundan beslenir.
      try {
        const dr = await ctx.exec(binderBin, [...binderArgs, '--dump-raw']);
        if (dr.code === 0 && dr.stdout.trim()) rawFlow = JSON.parse(dr.stdout);
      } catch { /* retention best-effort */ }

      // (7b) P0-1b HARD-GATE: ajanın dokunduğu parametreli uç-noktalara SQLi(STEP2) + 2. XSS(STEP3)
      // probunu DETERMİNİSTİK at. Ajan erken durmuş olsa bile checklist ailesi ≥2 garanti (imza yoksa
      // "denendi, imza yok" olarak Pozitif Güvence'ye sayılır). Best-effort: hata koşuyu BOZMAZ.
      try {
        const targets = discoverProbeTargets(rawFlow);
        const loginCandidates = discoverLoginCandidates(rawFlow);   // (P0-8) login formu SQLi adayları
        const plan = buildProbePlan(targets, loginCandidates);
        if (plan.probes.length > 0) {
          const planB64 = Buffer.from(JSON.stringify(plan), 'utf8').toString('base64');
          await ctx.exec(`bash -lc 'echo ${planB64} | base64 -d > ${DROPLET_RUN}/probe_plan.json'`, []);
          const pr = await ctx.exec(`${ctx.scriptsDir}/droplet-scripts/run_probes.py`,
            ['--plan', `${DROPLET_RUN}/probe_plan.json`, '--target', job.domain, '--target-ip', primaryIp, '--out', `${DROPLET_RUN}/extra_probes.json`]);
          if (/PROBES_DONE/.test(pr.stdout)) {
            extraFlag = ['--extra', `${DROPLET_RUN}/extra_probes.json`];
            const fams = [...new Set(plan.probes.map((p) => p.family))].join('+');
            const loginNote = plan.probes.some((p) => p.family === 'login_sqli') ? ` · login-formu SQLi aday: ${loginCandidates.slice(0, 4).join(', ')}` : '';
            await record({ phase: 'campaign', ok: true, detail: `checklist HARD-GATE: ${plan.probes.length} deterministik prob çalıştı (${fams}) — param uç: ${targets.filter((t) => t.param).map((t) => t.path).join(', ') || '—'}${loginNote} · ajan erken dursa bile STEP2(login+param)/STEP3 kapsandı` });
          } else {
            await record({ phase: 'campaign', ok: true, detail: `checklist HARD-GATE: prob motoru çıktı vermedi (${(pr.stderr || pr.stdout || '').slice(-200)}) — yalnız ajan artefaktlarıyla devam` });
          }
        } else {
          await record({ phase: 'campaign', ok: true, detail: 'checklist HARD-GATE: parametreli uç-nokta keşfedilemedi (ajan hiç parametre denemedi) — STEP2/STEP3 için deterministik prob atlanamadı, dürüstçe not edildi' });
        }
      } catch { /* prob geçişi best-effort — asla koşuyu bozma */ }

      // (7c) BIND — ajan artefaktları + deterministik problar (--extra) birlikte sınıflanır. RESİLİENT.
      const b = await ctx.exec(binderBin, [...binderArgs, ...extraFlag, '--json']);
      try { if (b.stdout.trim()) binderOutput = JSON.parse(b.stdout) as BinderOutput; }
      catch { await record({ phase: 'bind', ok: false, detail: `binder çıktısı ayrıştırılamadı (boş rapor): ${(b.stderr || b.stdout || '').slice(-300)}` }); }

      // (7d) karar-izi (--extra dahil, trace bind ile tutarlı olsun) + GERÇEK maliyet (msgchains).
      try {
        const tr = await ctx.exec(binderBin, [...binderArgs, ...extraFlag, '--trace']);
        if (tr.code === 0 && tr.stdout.trim()) binderTrace = tr.stdout;
      } catch { /* best-effort */ }
      try {
        const c = await ctx.exec(`docker exec pgvector psql -U postgres -d pentagidb -tAc "SELECT COALESCE(SUM(usage_cost_in+usage_cost_out),0)::numeric(12,4) FROM msgchains;" 2>/dev/null`, []);
        const n = Number((c.stdout || '').trim());
        if (Number.isFinite(n) && n >= 0) liveCostUsd = n;
      } catch { /* best-effort */ }
      const art = (rawFlow as { artifacts?: unknown[] } | undefined)?.artifacts?.length ?? 0;
      const fam = binderOutput.tried?.families?.length ?? 0;
      await record({ phase: 'bind', ok: true, detail: `retention: ham-veri ${rawFlow ? `✓ (${art} artefakt)` : '—'} · karar-izi ${binderTrace ? '✓' : '—'} · teknik ailesi ${fam} · gerçek maliyet ${liveCostUsd != null ? `$${liveCostUsd.toFixed(4)}` : '—'}` });

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
    // (P2/FIX#4 — DÜRÜST SAĞLIK NOTU) Hedef HİÇ geçerli HTTP yanıtı vermediyse (tüm curl'ler boş/timeout →
    // hiçbir artefaktta "HTTP/x" durum satırı yok) rapor "kanıtlı yok = Temiz = güvenli" yanılgısına düşmesin.
    // overallRisk DEĞİŞMEZ (binder hesaplar); yalnız şeffaf uyarı. Yanıt-veren hedefte (anyHttp) hiç tetiklenmez.
    try {
      const arts = (rawFlow as { artifacts?: Array<{ rawText?: string }> } | undefined)?.artifacts ?? [];
      const anyHttp = arts.some((a) => /HTTP\/\d/.test(a?.rawText ?? ''));
      if (report && !anyHttp && report.counts.kanitli === 0) {
        report.healthNote = 'Hedef bu koşuda geçerli bir HTTP yanıtı vermedi (yavaş/kısıtlı/asılı — istekler zaman ' +
          'aşımına uğradı). Test edilebilir yüzey ALINAMADI; "kanıtlı bulgu yok / Temiz" ifadesi "hedef güvenli" ' +
          'anlamına GELMEZ. Hedefe yanıt veren bir ağ konumundan taramayı tekrarlayın.';
      }
    } catch { /* sağlık notu best-effort — raporu asla bozma */ }
    // (P0-5) Süre farkını DÜRÜSTÇE açıkla: ajan-süresi cap'i aşamaz; toplam süre infra fazlarını da içerir.
    await record({ phase: 'report', ok: true, detail: `rapor: kanıtlı ${report.counts.kanitli} · belirsiz ${report.counts.belirsiz} · elenen ${report.eliminated} · risk ${report.overallRisk}${report.healthNote ? ' · ⚠ hedef-yanıtsız' : ''} · süre: ajan ${agentSec ?? '?'}s / toplam ${totalSec}s (fark = infra: provision+setup+bind+teardown)` });

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
