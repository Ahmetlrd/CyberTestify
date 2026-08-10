/**
 * (Aktif Doğrulama — İş Mantığı + Race/Mass-Assignment) SINIRLI, SIKI-KONTROLLÜ PentAGI AJAN KULLANIMI.
 *
 * Ajan SADECE keşfedilen yüzeyi (form/API) analiz eder ve iş-mantığı/mass-assignment açısından ilginç
 * girişleri SEÇER + hangi ZARARSIZ GÖZLEMSEL probun mantıklı olduğuna dair YAPILANDIRILMIŞ JSON döndürür.
 * Ajan:
 *  - ASLA serbest metin/Türkçe yazmaz (yalnız JSON; Türkçe rapor metnini backend şablonları üretir).
 *  - ASLA doğrudan HTTP isteği atmaz — sadece "şu inputPoint'i gözlemle" ÖNERİSİ verir; backend bunu
 *    kendi GÜVENLİ (GET-only, tek-deneme, circuit breaker) fonksiyonlarından geçirir.
 *  - inputPoint'i keşfedilen listeden BİREBİR seçmek zorundadır (uydurma hedef reddedilir — güvenlik).
 * Ajan çağrısı başarısız/timeout olursa -> null döner, kontrol mevcut deterministik davranışa DÜŞER.
 */
import { createFlow, getFlowStatus, getFlowLogs, deleteFlow } from '../pentagi/client.js';

const PROVIDER = process.env.PENTAGI_PROVIDER ?? 'cybertestify-anthropic';
const AGENT_TIMEOUT_MS = 100_000;   // ajan icin toplam sure ust siniri (asilirsa fallback)
const AGENT_POLL_MS = 6_000;
const MAX_SUGGESTIONS = 5;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export type AgentSuggestion = {
  check: 'business_logic' | 'race_massassign';
  inputPoint: string;   // keşfedilen listeden BİREBİR
  technique: string;    // kisa etiket (rapor icin backend sablonuna hint)
  confidence: 'high' | 'medium' | 'low';
  severity: 'high' | 'medium' | 'low';
  sideEffectRisk: 'none' | 'possible' | 'confirmed';
};

const CHECK_SET = new Set(['business_logic', 'race_massassign']);
const LEVEL_SET = new Set(['high', 'medium', 'low']);
const SIDE_SET = new Set(['none', 'possible', 'confirmed']);
// evidence/technique alanlarinda gercek-veri/sir sizintisi kontrolu (savunma katmani).
const LEAK_RE = /(password|passwd|BEGIN [A-Z ]*PRIVATE KEY|eyJ[A-Za-z0-9_-]{10,}|\b\d{16}\b|"token"\s*:|sk-[A-Za-z0-9]{16,})/i;

/**
 * Ajan ciktisindan JSON'u ayikla + SIKI dogrula. SAF fonksiyon (testlenebilir).
 * allowedInputs verilirse inputPoint bunlardan biri OLMALIDIR (uydurma hedef -> ele).
 */
export function parseAgentSuggestions(raw: string, allowedInputs?: Set<string>): AgentSuggestion[] | null {
  if (!raw) return null;
  // JSON blogunu bul: ```json ... ``` VEYA ilk {...findings...}
  let jsonText: string | null = null;
  const fence = raw.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence && /findings/.test(fence[1])) jsonText = fence[1];
  if (!jsonText) {
    const i = raw.indexOf('{');
    const j = raw.lastIndexOf('}');
    if (i >= 0 && j > i) jsonText = raw.slice(i, j + 1);
  }
  if (!jsonText) return null;
  let doc: any;
  try { doc = JSON.parse(jsonText); } catch { return null; }
  if (!doc || !Array.isArray(doc.findings)) return null;
  const out: AgentSuggestion[] = [];
  for (const f of doc.findings) {
    if (!f || typeof f !== 'object') continue;
    if (!CHECK_SET.has(f.check)) continue;
    if (typeof f.inputPoint !== 'string' || !f.inputPoint.trim()) continue;
    if (allowedInputs && !allowedInputs.has(f.inputPoint.trim())) continue; // GUVENLIK: uydurma hedef ele
    if (!LEVEL_SET.has(f.confidence) || !LEVEL_SET.has(f.severity) || !SIDE_SET.has(f.sideEffectRisk)) continue;
    const technique = typeof f.technique === 'string' ? f.technique.slice(0, 80) : '';
    // Sizinti savunmasi: teknik/evidence gercek veri/sir icermemeli.
    if (LEAK_RE.test(technique) || LEAK_RE.test(String(f.evidence ?? ''))) continue;
    out.push({
      check: f.check, inputPoint: f.inputPoint.trim(), technique,
      confidence: f.confidence, severity: f.severity, sideEffectRisk: f.sideEffectRisk,
    });
    if (out.length >= MAX_SUGGESTIONS) break;
  }
  return out;
}

function buildPrompt(surfaceJson: string): string {
  return [
    'You are a web application security ANALYST assisting an automated scanner. You are given the discovered',
    'attack surface (forms and read-only API endpoints) of a target as JSON.',
    '',
    'TASK: Identify which inputs are interesting for BUSINESS LOGIC or MASS-ASSIGNMENT/RACE testing',
    '(price/quantity/amount/discount fields; multi-step flows; role/privilege/isAdmin fields;',
    'coupon/basket/order-like endpoints). For each, propose a single HARMLESS, READ-ONLY (GET) OBSERVATION.',
    '',
    'STRICT OUTPUT RULES (follow EXACTLY):',
    '- Output ONLY a single JSON object. No prose, no explanation, no markdown, no comments.',
    '- Schema: {"findings":[{"check":"business_logic"|"race_massassign","inputPoint":"<verbatim from the list>",',
    '  "technique":"<short label, max 8 words>","confidence":"high|medium|low","severity":"high|medium|low",',
    '  "sideEffectRisk":"none|possible|confirmed"}]}',
    '- inputPoint MUST be copied VERBATIM from the provided list. Do NOT invent endpoints.',
    '- At most 5 findings. If nothing is interesting, output {"findings":[]}.',
    '- Do NOT run any tools. Do NOT make any network request. Just analyze the given JSON, output the JSON',
    '  result, then FINISH immediately.',
    '',
    'Discovered surface:',
    surfaceJson,
  ].join('\n');
}

function extractText(logs: Awaited<ReturnType<typeof getFlowLogs>>): string {
  const parts: string[] = [];
  for (const t of logs.tasks ?? []) {
    if (t.result) parts.push(t.result);
    for (const s of t.subtasks ?? []) if (s.result) parts.push(s.result);
  }
  for (const m of logs.messageLogs ?? []) { if (m.result) parts.push(m.result); if (m.message) parts.push(m.message); }
  return parts.join('\n');
}

// TEST hook — mevcut createFlow zincirini stub'lamak icin.
let _override: ((host: string, surface: unknown) => Promise<AgentSuggestion[] | null>) | null = null;
export function __setAgentAdvisorForTest(fn: ((host: string, surface: unknown) => Promise<AgentSuggestion[] | null>) | null): void { _override = fn; }

/** Ajanı çalıştır, yapılandırılmış öneri listesini döndür. Her hata/timeout -> null (fallback). */
export async function requestAgentScenarios(
  host: string,
  surface: { inputs: Array<{ method: string; action: string; param: string }>; forms: string[]; apiWrites: string[] },
): Promise<AgentSuggestion[] | null> {
  if (_override) return _override(host, surface);
  // Keşfedilen inputPoint etiketleri (ajan bunlardan BİREBİR secmeli).
  const inputLabels = surface.inputs.slice(0, 40).map((i) => `${i.method} ${i.action}?${i.param}`);
  const allowed = new Set<string>([...inputLabels, ...surface.forms, ...surface.apiWrites]);
  const surfaceJson = JSON.stringify({ inputs: inputLabels, forms: surface.forms.slice(0, 20), stateChangingApis: surface.apiWrites.slice(0, 20) });
  if (allowed.size === 0) return [];

  let flowId: string | null = null;
  try {
    const flow = await createFlow(PROVIDER, buildPrompt(surfaceJson));
    flowId = String(flow.id);
    const deadline = Date.now() + AGENT_TIMEOUT_MS;
    while (Date.now() < deadline) {
      await sleep(AGENT_POLL_MS);
      let logs;
      try { logs = await getFlowLogs(flowId); } catch { continue; }
      const text = extractText(logs);
      if (/findings/.test(text)) {
        const parsed = parseAgentSuggestions(text, allowed);
        if (parsed) return parsed;
      }
      let status = '';
      try { status = (await getFlowStatus(flowId)).status; } catch { /* yoksay */ }
      if (status === 'finished' || status === 'failed') {
        const parsed = parseAgentSuggestions(extractText(await getFlowLogs(flowId).catch(() => ({ tasks: [], messageLogs: [], screenshots: [] } as any))), allowed);
        return parsed; // null olabilir -> fallback
      }
    }
    return null; // timeout -> fallback
  } catch {
    return null;
  } finally {
    if (flowId) await deleteFlow(flowId).catch(() => {}); // temizlik (best-effort)
  }
}
