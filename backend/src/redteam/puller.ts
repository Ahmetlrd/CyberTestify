/**
 * (OTONOM AI RED TEAM — 3b-ii GÖZLEMLENEBİLİRLİK) İzolasyon-koruyan PULL.
 * KRİTİK: droplet → CyberTestify PUSH YOK. Prod backend, orchestrator'ın zaten kullandığı SSH
 * KONTROL-KANALINDAN (prod → droplet, outbound) periyodik READ-ONLY komutlar çalıştırıp veriyi
 * ÇEKER. Droplet CyberTestify'a HİÇ bağlanmaz; egress hedef-only kalır.
 *
 * Saf + enjekte edilebilir: `exec(remoteCmd)` gerçekte `ssh -i id_pentagi root@<ip> '<cmd>'`
 * çalıştırır; unit-test'te mock verilir (canlı koşu/DO/token GEREKMEZ).
 *
 * SECRET HİJYENİ: çekilen TÜM metin maskeSecrets'ten geçer — token/anahtar panele/DB'ye YAZILMAZ.
 */

export type RemoteExec = (remoteCmd: string) => Promise<{ code: number; stdout: string; stderr: string }>;

// ————————————————————— SECRET MASKELEME —————————————————————
const SECRET_PATTERNS: Array<[RegExp, string]> = [
  [/sk-ant-[A-Za-z0-9_-]{8,}/g, 'sk-ant-***'],
  [/dop_v1_[A-Za-z0-9]{16,}/g, 'dop_v1_***'],
  [/AKIA[0-9A-Z]{16}/g, 'AKIA***'],
  [/eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}/g, 'JWT.***'], // JWT (beta/token)
  [/Bearer\s+[A-Za-z0-9._-]{10,}/gi, 'Bearer ***'],
  [/(X-Beta-Token|Authorization|api[_-]?key|secret|password|COOKIE_SIGNING_SALT)\s*[:=]\s*["']?[A-Za-z0-9._\-/+]{8,}/gi, '$1=***'],
  [/\b[a-f0-9]{40,}\b/gi, '***hex***'], // uzun hex (hash/anahtar)
];
export function maskSecrets(text: string): string {
  let out = String(text ?? '');
  for (const [re, rep] of SECRET_PATTERNS) out = out.replace(re, rep);
  return out;
}

// ————————————————————— READ-ONLY UZAK KOMUTLAR (droplet'te çalışır) —————————————————————
export const REMOTE = {
  // PentAGI ilerlemesi: son flow status | msgchain(çağrı) | maliyet | toolcall — tek satır.
  progress:
    `docker exec pgvector psql -U postgres -d pentagidb -tAc ` +
    `"SELECT COALESCE((SELECT status FROM flows ORDER BY id DESC LIMIT 1),'-')||'|'||` +
    `(SELECT count(*) FROM msgchains)||'|'||` +
    `COALESCE((SELECT SUM(usage_cost_in+usage_cost_out)::numeric(12,4) FROM msgchains),0)||'|'||` +
    `(SELECT count(*) FROM toolcalls);" 2>/dev/null`,
  // Model başına: model | çağrı | maliyet (canlı breakdown)
  perModel:
    `docker exec pgvector psql -U postgres -d pentagidb -tAc ` +
    `"SELECT COALESCE(model,'?')||':'||count(*)||':'||COALESCE(SUM(usage_cost_in+usage_cost_out),0)::numeric(12,4) ` +
    `FROM msgchains GROUP BY model;" 2>/dev/null`,
  // CANLI TRANSKRİPT: ajanın son araç-çağrıları (ad + istek/args + yanıt/result kesiti). İç newline'lar
  // translate ile boşluğa çevrilir → her DB satırı tek log satırı. maskSecrets pullOnce'ta uygulanır.
  transcriptTail:
    `docker exec pgvector psql -U postgres -d pentagidb -tAc ` +
    `"SELECT 'T'||id||'|'||coalesce(name,'')||'|'||left(translate(coalesce(args::text,''),E'\\n\\r\\t','   '),140)` +
    `||'|'||left(translate(coalesce(result,''),E'\\n\\r\\t','   '),240) FROM toolcalls ORDER BY id DESC LIMIT 5;" 2>/dev/null`,
  // Ajanın son adım-sonuçları/iddiaları (subtasks) — "ne düşündü/buldu".
  subtaskTail:
    `docker exec pgvector psql -U postgres -d pentagidb -tAc ` +
    `"SELECT 'S'||id||'|'||left(translate(coalesce(title,''),E'\\n\\r\\t','   '),80)||'|'||left(translate(coalesce(result,''),E'\\n\\r\\t','   '),220) ` +
    `FROM subtasks ORDER BY id DESC LIMIT 3;" 2>/dev/null`,
  campaignTail: `tail -n 3 /opt/pentagi-run/campaign.log 2>/dev/null`,
  auditTail: `tail -n 8 /opt/pentagi-run/audit/*.log 2>/dev/null`,
  // egress ampirik gate (throwaway konteyner): TARGET_OK / CYBERTESTIFY_BLOCKED / METADATA_BLOCKED
  verifyEgress: (ip: string) => `bash /opt/pentagi-run/verify-egress.sh ${ip} 2>/dev/null`,
};

export type PullLive = {
  pentagiStatus?: string;
  llmCalls?: number;
  costUsd?: number;
  toolCalls?: number;
  egressTargetOk?: boolean;
  egressCyberBlocked?: boolean;
  modelUsage?: Array<{ model: string; calls: number; costUsd: number }>;
};
export type PullLogLine = { source: string; level: 'info' | 'warn' | 'error'; message: string };
export type PullResult = { live: PullLive; logs: PullLogLine[] };

function n(s: string | undefined): number | undefined {
  const v = Number((s ?? '').trim());
  return Number.isFinite(v) ? v : undefined;
}

/**
 * Bir kez pull: SSH kontrol-kanalından ilerleme + cap + audit + egress çeker, MASKELER, yapısal
 * live + log satırları döner. DB yazmaz (persist ayrı — test edilebilir). Egress ip verilmezse
 * egress kontrolü atlanır.
 */
export async function pullOnce(exec: RemoteExec, opts: { targetIp?: string | null } = {}): Promise<PullResult> {
  const live: PullLive = {};
  const logs: PullLogLine[] = [];
  const safe = async (label: string, cmd: string): Promise<string | null> => {
    try {
      const r = await exec(cmd);
      return r.code === 0 ? maskSecrets(r.stdout) : null;
    } catch (e) {
      logs.push({ source: 'puller', level: 'warn', message: `${label} pull hatası: ${maskSecrets((e as Error).message)}` });
      return null;
    }
  };

  // 1) PentAGI ilerleme
  const prog = await safe('progress', REMOTE.progress);
  if (prog) {
    const [st, calls, cost, tools] = prog.trim().split('|');
    live.pentagiStatus = st;
    live.llmCalls = n(calls);
    live.costUsd = n(cost);
    live.toolCalls = n(tools);
    logs.push({ source: 'pentagi', level: 'info', message: `flow=${st} çağrı=${calls} maliyet=$${cost} toolcall=${tools}` });
  }

  // 1b) Model başına breakdown (canlı)
  const pm = await safe('perModel', REMOTE.perModel);
  if (pm && pm.trim()) {
    const rows = pm.trim().split('\n').map((l) => {
      const [model, calls, cost] = l.split(':');
      return { model: (model || '?').trim(), calls: Number(calls) || 0, costUsd: Number(cost) || 0 };
    }).filter((r) => r.model);
    if (rows.length) {
      live.modelUsage = rows;
      // (ÖLÇÜM DÜZELTME) llmCalls/costUsd bazen REMOTE.progress'ten null geliyordu (sorgu başarısız),
      // ama per-model GROUP BY çalışıyor → sayaçları per-model TOPLAMINDAN türet (panel "model dağılımı"
      // ile TUTARLI + gerçek harcamayı gösterir, 0 değil).
      const sc = rows.reduce((a, m) => a + m.calls, 0);
      const su = rows.reduce((a, m) => a + m.costUsd, 0);
      if (live.llmCalls == null || sc > live.llmCalls) live.llmCalls = sc;
      if (live.costUsd == null || su > (live.costUsd ?? 0)) live.costUsd = su;
      // (ŞEFFAFLIK) model dağılımı artık canlı-log'u KAPLAMAZ — modelUsage panelde "model dağılımı"
      // kartında zaten görünür. Ana akışı GERÇEK ajan transkripti kaplasın (aşağıda).
    }
  }

  // 1c) CANLI AJAN TRANSKRİPTİ — model-spam yerine gerçek araç akışı (rol/komut/istek/yanıt-kesiti).
  const tx = await safe('transcript', REMOTE.transcriptTail);
  if (tx && tx.trim()) {
    for (const line of tx.trim().split('\n').reverse()) { // eskiden→yeniye
      const p = line.split('|');
      if (p.length < 2) continue;
      const name = (p[1] || 'araç').trim();
      const req = (p[2] || '').trim();
      const res = p.slice(3).join('|').trim();
      const marker = /zqx[a-z0-9]*marker/i.test(req + res) ? ' ⟨marker⟩' : '';
      logs.push({ source: 'ajan', level: 'info', message: `[${name}]${marker} ${req}${res ? '  →  ' + res.slice(0, 220) : ''}`.trim() });
    }
  }
  const stx = await safe('subtask', REMOTE.subtaskTail);
  if (stx && stx.trim()) {
    for (const line of stx.trim().split('\n').reverse()) {
      const p = line.split('|');
      const title = (p[1] || '').trim();
      const res = p.slice(2).join('|').trim();
      if (title || res) logs.push({ source: 'ajan-sonuç', level: 'info', message: `${title ? title + ': ' : ''}${res.slice(0, 220)}`.trim() });
    }
  }

  // 2) Cap / kampanya kuyruğu (son satırlar)
  const camp = await safe('campaign', REMOTE.campaignTail);
  if (camp && camp.trim()) {
    for (const line of camp.trim().split('\n').slice(-3)) {
      logs.push({ source: 'cap', level: /HARD STOP|cap/i.test(line) ? 'warn' : 'info', message: line.trim() });
    }
  }

  // 3) Audit (PROBE/CLASSIFY)
  const audit = await safe('audit', REMOTE.auditTail);
  if (audit && audit.trim()) {
    for (const line of audit.trim().split('\n').slice(-6)) {
      if (line.trim()) logs.push({ source: 'audit', level: 'info', message: line.trim() });
    }
  }

  // 4) Egress ampirik gate
  if (opts.targetIp) {
    const eg = await safe('egress', REMOTE.verifyEgress(opts.targetIp));
    if (eg) {
      live.egressTargetOk = /TARGET_OK/.test(eg);
      live.egressCyberBlocked = /CYBERTESTIFY_BLOCKED/.test(eg);
      const ok = live.egressTargetOk && live.egressCyberBlocked;
      logs.push({
        source: 'egress',
        level: ok ? 'info' : 'error',
        message: `hedef=${live.egressTargetOk ? 'erişilir' : 'ERİŞİLEMEZ'} · CyberTestify=${live.egressCyberBlocked ? 'BLOCKED' : 'AÇIK!!'}`,
      });
    }
  }

  return { live, logs };
}

// ————————————————————— KILL-SWITCH (kontrol-kanalından) —————————————————————
export const KILL_SWITCH_CMD = 'bash /opt/pentagi-run/kill-switch.sh 2>&1';
/** Kontrol-kanalından kill-switch.sh çalıştırır (ajan durdur + egress kes). Çıktı maskeli döner. */
export async function triggerKillSwitch(exec: RemoteExec): Promise<{ ok: boolean; output: string }> {
  try {
    const r = await exec(KILL_SWITCH_CMD);
    return { ok: r.code === 0, output: maskSecrets(r.stdout + (r.stderr ? '\n' + r.stderr : '')) };
  } catch (e) {
    return { ok: false, output: maskSecrets((e as Error).message) };
  }
}
