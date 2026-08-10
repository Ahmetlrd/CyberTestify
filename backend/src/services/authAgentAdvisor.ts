/**
 * (Tam Kapsamlı Pentest — FAZ D) SINIRLI/KONTROLLÜ OTONOM AJAN KATMANI — yalnız ADVISORY (JSON).
 *
 * Yetki yükseltme + çok-adımlı iş mantığı için: ajan, keşfedilen AUTHENTICATED yüzeyi analiz eder ve
 * hangi girişin mantıklı bir test senaryosu olduğuna dair YAPILANDIRILMIŞ JSON döndürür. Ajan:
 *  - ASLA serbest metin/Türkçe yazmaz (yalnız JSON; rapor metnini backend şablonu üretir).
 *  - ASLA doğrudan HTTP atmaz — backend öneriyi kendi GÜVENLİ (authenticated-light) fonksiyonundan geçirir.
 *  - inputPoint'i keşfedilen listeden BİREBİR seçer (uydurma hedef reddedilir).
 * DÜŞÜK bütçe/timeout: autonomous_pentest'ten (90 tool-call) çok daha düşük (25 tool-call, 60 sn). Bütçe/
 * süre aşımı ya da hata -> null -> kontrol deterministik FAZ C sinyaline DÜŞER (paket çökmez).
 */
import { createFlow, getFlowStatus, getFlowLogs, getToolCallCount, stopFlow, deleteFlow } from '../pentagi/client.js';
import { SAFETY_AUTHENTICATED_EN } from './scanPackages.js';

const PROVIDER = process.env.PENTAGI_PROVIDER ?? 'cybertestify-anthropic';
const AUTH_AGENT_TIMEOUT_MS = 60_000;   // autonomous'tan (~90 tc) DÜŞÜK — risk/adım oranı yüksek
const AUTH_AGENT_POLL_MS = 6_000;
export const AUTH_AGENT_MAX_TOOLCALLS = 25; // düşük tool-call tavanı (aşılırsa stopFlow + fallback)
const MAX_SUGGESTIONS = 4;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export type AuthAgentSuggestion = {
  check: 'privilege_escalation' | 'business_logic_multistep';
  inputPoint: string;   // keşfedilen listeden BİREBİR
  technique: string;
  confidence: 'high' | 'medium' | 'low';
  severity: 'high' | 'medium' | 'low';
  sideEffectRisk: 'none' | 'possible' | 'confirmed';
};

const CHECK_SET = new Set(['privilege_escalation', 'business_logic_multistep']);
const LEVEL_SET = new Set(['high', 'medium', 'low']);
const SIDE_SET = new Set(['none', 'possible', 'confirmed']);
const LEAK_RE = /(password|passwd|BEGIN [A-Z ]*PRIVATE KEY|eyJ[A-Za-z0-9_-]{10,}|\b\d{16}\b|"token"\s*:|sk-[A-Za-z0-9]{16,})/i;

/** Ajan çıktısından JSON'u ayıkla + SIKI doğrula. SAF fonksiyon (testlenebilir). */
export function parseAuthAgentSuggestions(raw: string, allowedInputs?: Set<string>): AuthAgentSuggestion[] | null {
  if (!raw) return null;
  let jsonText: string | null = null;
  const fence = raw.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence && /findings/.test(fence[1])) jsonText = fence[1];
  if (!jsonText) { const i = raw.indexOf('{'); const j = raw.lastIndexOf('}'); if (i >= 0 && j > i) jsonText = raw.slice(i, j + 1); }
  if (!jsonText) return null;
  let doc: any;
  try { doc = JSON.parse(jsonText); } catch { return null; }
  if (!doc || !Array.isArray(doc.findings)) return null;
  const out: AuthAgentSuggestion[] = [];
  for (const f of doc.findings) {
    if (!f || typeof f !== 'object') continue;
    if (!CHECK_SET.has(f.check)) continue;
    if (typeof f.inputPoint !== 'string' || !f.inputPoint.trim()) continue;
    if (allowedInputs && !allowedInputs.has(f.inputPoint.trim())) continue; // GUVENLIK: uydurma hedef ele
    if (!LEVEL_SET.has(f.confidence) || !LEVEL_SET.has(f.severity) || !SIDE_SET.has(f.sideEffectRisk)) continue;
    const technique = typeof f.technique === 'string' ? f.technique.slice(0, 80) : '';
    if (LEAK_RE.test(technique) || LEAK_RE.test(String(f.evidence ?? ''))) continue;
    out.push({ check: f.check, inputPoint: f.inputPoint.trim(), technique, confidence: f.confidence, severity: f.severity, sideEffectRisk: f.sideEffectRisk });
    if (out.length >= MAX_SUGGESTIONS) break;
  }
  return out;
}

function buildPrompt(surfaceJson: string): string {
  return [
    'You are an application security ANALYST assisting an automated AUTHENTICATED scanner. You are given the',
    'discovered LOGGED-IN attack surface (forms and read-only API endpoints) of a target as JSON.',
    '',
    'TASK: Identify inputs interesting for (1) PRIVILEGE ESCALATION (role/isAdmin/privilege/group fields on',
    'a registration/profile-like form or API) or (2) MULTI-STEP BUSINESS LOGIC (client-controllable price/',
    'quantity/amount/discount/coupon fields; multi-step cart/checkout flows). For each, propose a single',
    'HARMLESS OBSERVATION the BACKEND can run.',
    '',
    'STRICT OUTPUT RULES (follow EXACTLY):',
    '- Output ONLY a single JSON object. No prose, no explanation, no markdown, no comments.',
    '- Schema: {"findings":[{"check":"privilege_escalation"|"business_logic_multistep",',
    '  "inputPoint":"<verbatim from the list>","technique":"<short label, max 8 words>",',
    '  "confidence":"high|medium|low","severity":"high|medium|low","sideEffectRisk":"none|possible|confirmed"}]}',
    '- inputPoint MUST be copied VERBATIM from the provided list. Do NOT invent endpoints.',
    '- At most 4 findings. If nothing is interesting, output {"findings":[]}.',
    '- Do NOT run any tools. Do NOT make any network request. Analyze the JSON, output the JSON, then FINISH.',
    '',
    SAFETY_AUTHENTICATED_EN,
    '',
    'Discovered authenticated surface:',
    surfaceJson,
  ].join('\n');
}

function extractText(logs: Awaited<ReturnType<typeof getFlowLogs>>): string {
  const parts: string[] = [];
  for (const t of logs.tasks ?? []) { if (t.result) parts.push(t.result); for (const s of t.subtasks ?? []) if (s.result) parts.push(s.result); }
  for (const m of logs.messageLogs ?? []) { if (m.result) parts.push(m.result); if (m.message) parts.push(m.message); }
  return parts.join('\n');
}

// TEST hook — createFlow zincirini stub'lamak icin.
let _override: ((host: string, surface: unknown) => Promise<AuthAgentSuggestion[] | null>) | null = null;
export function __setAuthAgentAdvisorForTest(fn: ((host: string, surface: unknown) => Promise<AuthAgentSuggestion[] | null>) | null): void { _override = fn; }

/** Ajanı çalıştır (DÜŞÜK bütçe/timeout). Öneri listesi döndürür; her hata/timeout/tavan -> null (fallback). */
export async function requestAuthAgentScenarios(
  host: string,
  surface: { inputs: Array<{ method: string; action: string; param: string }>; forms: string[]; apiWrites: string[] },
): Promise<AuthAgentSuggestion[] | null> {
  if (_override) return _override(host, surface);
  const inputLabels = surface.inputs.slice(0, 40).map((i) => `${i.method} ${i.action}?${i.param}`);
  const allowed = new Set<string>([...inputLabels, ...surface.forms, ...surface.apiWrites]);
  const surfaceJson = JSON.stringify({ inputs: inputLabels, forms: surface.forms.slice(0, 20), stateChangingApis: surface.apiWrites.slice(0, 20) });
  if (allowed.size === 0) return [];

  let flowId: string | null = null;
  try {
    const flow = await createFlow(PROVIDER, buildPrompt(surfaceJson));
    flowId = String(flow.id);
    const deadline = Date.now() + AUTH_AGENT_TIMEOUT_MS;
    while (Date.now() < deadline) {
      await sleep(AUTH_AGENT_POLL_MS);
      // DÜŞÜK tool-call tavanı — ajan tool kullanmaya kalkarsa (advisory olmalı) DURDUR + fallback.
      try { if ((await getToolCallCount(flowId)) > AUTH_AGENT_MAX_TOOLCALLS) { await stopFlow(flowId).catch(() => {}); return null; } } catch { /* yoksay */ }
      let logs;
      try { logs = await getFlowLogs(flowId); } catch { continue; }
      const text = extractText(logs);
      if (/findings/.test(text)) { const parsed = parseAuthAgentSuggestions(text, allowed); if (parsed) return parsed; }
      let status = '';
      try { status = (await getFlowStatus(flowId)).status; } catch { /* yoksay */ }
      if (status === 'finished' || status === 'failed') {
        return parseAuthAgentSuggestions(extractText(await getFlowLogs(flowId).catch(() => ({ tasks: [], messageLogs: [], screenshots: [] } as any))), allowed);
      }
    }
    return null; // timeout -> fallback
  } catch {
    return null;
  } finally {
    if (flowId) await deleteFlow(flowId).catch(() => {});
  }
}
