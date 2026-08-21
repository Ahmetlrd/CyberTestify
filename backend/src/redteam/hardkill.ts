/**
 * (RED TEAM — ORTAK HARDKILL ÇEKİRDEĞİ) DirectDO-API tabanlı, orchestrator'ın kendi (tıkanabilir)
 * sürecine BAĞIMLI OLMAYAN durdurma mekanizması. HEM watchdog.ts'in otomatik cap-tetiklemesi HEM
 * admin panelin elle KILL-SWITCH butonu bunu kullanır — TEK, test edilmiş, tutarlı mekanizma.
 *
 * KÖK NEDEN (elle kill-switch olayı): eski `/redteam-jobs/:id/kill` yalnız SSH ile kill-switch.sh
 * çalıştırıyordu — bu hem SSH'ın (900_000ms timeout!) kendisi tıkanabilirse asılı kalabiliyordu, HEM
 * DE kill-switch.sh'in `docker ps --filter label=pentagi-agent` süzgeci muhtemelen HİÇBİR konteynerle
 * eşleşmiyordu (PentAGI'nin kendi compose'unda böyle bir etiket doğrulanmamıştı) — yani script "ok"
 * dönse bile GERÇEKTE hiçbir şeyi durdurmuyor olabilirdi. VE hiçbir zaman DigitalOcean API'sine
 * droplet'i doğrudan durdurma/imha isteği GİTMİYORDU — tek gerçek durdurma yolu SSH+script'e bağlıydı.
 *
 * BU MODÜL: (1) DOĞRUDAN DO API ile droplet'i imha eder (SSH/orchestrator'a bağımlı DEĞİL), (2) imha
 * ÖNCESİ best-effort + KESİN kısa timeout'lu SSH ile eldeki veriden rapor yakalamaya çalışır (rapor
 * yok edilmesin), (3) imha SONRASI DO API'den droplet'in GERÇEKTEN gittiğini doğrular — sahte-başarı
 * YOK, her adımın gerçek sonucu döner.
 */
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile } from 'node:fs/promises';
import { buildRedTeamReport, type BinderOutput, type RedTeamReport } from './report.js';
import { renderTranscript } from './transcript.js';
import { maskSecrets } from './puller.js';

const execFileAsync = promisify(execFile);

export type HardkillParams = {
  dropletIp: string | null;
  dropletId: string | null;   // job.dropletId (job-özgü — state.json paylaşımlı dosyadan DEĞİL, eşzamanlı-job güvenli)
  scriptsDir: string;
  keyPath: string;
  target: string;
  targetIp: string;
  level: 'S1' | 'S2' | 'S3';
  environment: 'test' | 'staging' | 'prod';
  reason: string;
};

export type HardkillResult = {
  destroyRequested: boolean;
  destroyError: string | null;   // null = hata yok; dolu ise UI'a AÇIKÇA gösterilecek gerçek hata
  verified: 'destroyed' | 'unverified' | 'skipped';
  report: RedTeamReport | null;
  rawFlow: unknown;
  transcript: unknown;
  liveCost: number | null;
};

async function sshTry(ip: string, keyPath: string, cmd: string, timeoutMs: number): Promise<string | null> {
  try {
    const { stdout } = await execFileAsync(
      'ssh',
      ['-i', keyPath, '-o', 'ConnectTimeout=6', '-o', 'StrictHostKeyChecking=no', '-o', 'BatchMode=yes',
        `root@${ip}`, cmd],
      { timeout: timeoutMs, maxBuffer: 8 * 1024 * 1024 },
    );
    return stdout;
  } catch (e: any) {
    return null; // best-effort — çağıran taraf durumu loglar
  }
}

/** Best-effort (KESİN kısa timeout'lu): egress kes + eldeki veriden binder/rapor + gerçek maliyet oku. */
async function captureBestEffort(p: HardkillParams): Promise<{ report: RedTeamReport | null; rawFlow: unknown; transcript: unknown; liveCost: number | null }> {
  if (!p.dropletIp) return { report: null, rawFlow: null, transcript: null, liveCost: null };
  // (i) harcamayı DERHAL durdur — best-effort, sonucunu BEKLEMEDEN devam edilebilir olmalı ama kısa timeout'lu.
  await sshTry(p.dropletIp, p.keyPath,
    'iptables -I DOCKER-USER 1 -p tcp --dport 443 -j DROP 2>/dev/null; iptables -I DOCKER-USER 1 -p tcp --dport 80 -j DROP 2>/dev/null; echo ok',
    10_000);
  const flowId = (await sshTry(p.dropletIp, p.keyPath, 'cat /opt/pentagi-run/flow_id 2>/dev/null', 6_000))?.trim();
  let rawFlow: unknown = null;
  let binderOutput: BinderOutput | null = null;
  if (flowId) {
    const args = `--flow ${flowId} --target ${JSON.stringify(p.target)} --target-ip ${JSON.stringify(p.targetIp)}`;
    const dumpOut = await sshTry(p.dropletIp, p.keyPath, `python3 /opt/pentagi-run/binder.py ${args} --dump-raw 2>/dev/null`, 20_000);
    if (dumpOut?.trim()) { try { rawFlow = JSON.parse(dumpOut); } catch { /* yoksay */ } }
    const jsonOut = await sshTry(p.dropletIp, p.keyPath, `python3 /opt/pentagi-run/binder.py ${args} --json 2>/dev/null`, 20_000);
    if (jsonOut?.trim()) { try { binderOutput = JSON.parse(jsonOut) as BinderOutput; } catch { /* yoksay */ } }
  }
  const costOut = await sshTry(p.dropletIp, p.keyPath,
    'docker exec pgvector psql -U postgres -d pentagidb -tAc "SELECT COALESCE(SUM(usage_cost_in+usage_cost_out),0)::numeric(12,4) FROM msgchains;" 2>/dev/null',
    10_000);
  const liveCost = costOut != null && Number.isFinite(Number(costOut.trim())) ? Number(costOut.trim()) : null;

  let report: RedTeamReport | null = null;
  if (binderOutput) {
    const rep = buildRedTeamReport(binderOutput, {
      target: p.target, level: p.level, environment: p.environment,
      generatedAt: new Date().toISOString(), costUsd: liveCost, llmCalls: null,
    });
    report = { ...rep, stoppedReason: `${p.reason} — koşu ELLE (kill-switch) durduruldu. Bu ana kadar toplanan ${binderOutput.artifactCount} ham artefaktın deterministik analizinden üretilen dürüst bir rapordur; yarıda kalan istek/yanıt çiftleri kanıt sayılmaz (elenir).` };
  }
  const transcript = rawFlow ? renderTranscript(rawFlow as any) : null;
  return { report, rawFlow, transcript, liveCost };
}

/** DOĞRUDAN DO API ile droplet imha — SSH'a/orchestrator'a BAĞIMLI DEĞİL. Gerçek hatayı DÖNER (yutmaz). */
async function destroyDirect(p: HardkillParams): Promise<{ requested: boolean; error: string | null; dropletId: string | null }> {
  const token = process.env.DIGITAL_OCEAN_API_KEY;
  if (!token) return { requested: false, error: 'DIGITAL_OCEAN_API_KEY env yok — DO API çağrılamadı', dropletId: null };

  // Öncelik: job'a özgü dropletId (eşzamanlı-job güvenli). Yoksa (eski job) state.json fallback — ama
  // state.json TÜM job'lar arası PAYLAŞIMLI tek dosyadır; yalnız job'un KENDİ dropletIp'i state.json'daki
  // public_ip ile eşleşiyorsa güvenle kullanılır (yanlış droplet'e gitme riskini keser).
  let dropletId = p.dropletId;
  if (!dropletId && p.dropletIp) {
    try {
      const raw = await readFile(`${p.scriptsDir}/state.json`, 'utf8');
      const st = JSON.parse(raw) as { droplet_id?: string; public_ip?: string };
      if (st.droplet_id && st.public_ip === p.dropletIp) dropletId = st.droplet_id;
    } catch { /* state.json yok/okunamadı */ }
  }
  if (!dropletId) return { requested: false, error: 'droplet_id bulunamadı (job.dropletId yok VE state.json eşleşmedi) — hangi droplet olduğu GÜVENLE belirlenemedi, yanlış droplet\'e gitme riskini önlemek için DURDU', dropletId: null };

  try {
    const res = await fetch(`https://api.digitalocean.com/v2/droplets/${dropletId}`, {
      method: 'DELETE', headers: { Authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(15_000),
    });
    if (res.ok || res.status === 404) return { requested: true, error: null, dropletId };
    const body = await res.text().catch(() => '');
    return { requested: true, error: `DO API HTTP ${res.status}: ${body.slice(0, 300)}`, dropletId };
  } catch (e: any) {
    return { requested: true, error: `DO API çağrısı başarısız: ${maskSecrets(String(e?.message ?? e))}`, dropletId };
  }
}

/** D3: droplet GERÇEKTEN gitti mi? DO API'den (SSH'a bağımlı DEĞİL) doğrula. */
async function verifyGone(dropletId: string): Promise<'destroyed' | 'unverified'> {
  const token = process.env.DIGITAL_OCEAN_API_KEY;
  if (!token) return 'unverified';
  for (let i = 0; i < 4; i++) {
    try {
      const res = await fetch(`https://api.digitalocean.com/v2/droplets/${dropletId}`, {
        headers: { Authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(10_000),
      });
      if (res.status === 404) return 'destroyed';
    } catch { /* devam et, tekrar dene */ }
    await new Promise((r) => setTimeout(r, 3000));
  }
  return 'unverified';
}

/**
 * TEK giriş noktası: rapor-yakala (best-effort, kısa timeout) → DOĞRUDAN DO API imha → doğrula.
 * Sıra ÖNEMLİ: önce harcamayı durdur + veriyi kurtar, SONRA imha (D5 ilkesi) — ama toplam süre
 * makul (SSH adımları kısa timeout'lu; imha SSH'ı beklemez, kendi başına DOĞRUDAN çalışır).
 */
type CaptureResult = { report: RedTeamReport | null; rawFlow: unknown; transcript: unknown; liveCost: number | null };
const EMPTY_CAPTURE: CaptureResult = { report: null, rawFlow: null, transcript: null, liveCost: null };

/** captureBestEffort'ın kendi iç timeout'ları toplansa BİLE (~66s) bir üst GENEL tavan — imha
 * asla rapor-yakalamaya bağımlı/onu bekleyerek asılı KALMASIN (destroy her koşulda hızlı çağrılır). */
async function captureWithCeiling(p: HardkillParams, ceilingMs = 75_000): Promise<CaptureResult> {
  return Promise.race([
    captureBestEffort(p),
    new Promise<CaptureResult>((resolve) => setTimeout(() => resolve(EMPTY_CAPTURE), ceilingMs)),
  ]);
}

export async function hardkill(p: HardkillParams): Promise<HardkillResult> {
  const captured = await captureWithCeiling(p);
  const destroy = await destroyDirect(p);
  const verified = destroy.requested && destroy.dropletId && !destroy.error ? await verifyGone(destroy.dropletId) : 'skipped';
  return {
    destroyRequested: destroy.requested,
    destroyError: destroy.error,
    verified: destroy.error ? 'unverified' : (verified as 'destroyed' | 'unverified' | 'skipped'),
    report: captured.report, rawFlow: captured.rawFlow, transcript: captured.transcript, liveCost: captured.liveCost,
  };
}
