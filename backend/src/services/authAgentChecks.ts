/**
 * (Tam Kapsamlı Pentest — FAZ D) AJAN-KATMANI KONTROLLERİ: yetki yükseltme + çok-adımlı iş mantığı.
 *
 * Ajan (authAgentAdvisor) YALNIZ yapılandırılmış JSON önerir; DOĞRUDAN HTTP ATMAZ. Backend, öneriyi
 * kendi GÜVENLİ fonksiyonundan geçirip GERÇEKTEN uygular — ama:
 *  - AUTH_WRITE_BLOCKLIST: hesap-durumu değiştiren / checkout hedeflerine ASLA yazma (backend-birincil,
 *    Go authenticated-light profili defense-in-depth).
 *  - Yetki yükseltme: tek, gözlemsel mass-assignment probu (role/isAdmin eklenince kabul mü) — gerçek
 *    yükseltme TAMAMLANMAZ, oturum dışına çıkılmaz, retry YOK.
 *  - Çok-adımlı iş mantığı: yalnız GET-gözlem (adım-atlama + istemci-değiştirilebilir fiyat alanı) —
 *    sepete/forma kadar; ödeme/checkout TAMAMLAMA YOK.
 *  - Ajan null/timeout/tavan -> deterministik FAZ C sinyaline DÜŞER (paket çökmez).
 */
import { randomBytes } from 'node:crypto';
import { ProbeCtx, discoverSurface, domFormLabel, type ActiveCheckEvidence, type VFinding, type Surface } from './activeVerifyEvidence.js';
import { type AuthSession, applyAuthHeaders } from './authSession.js';
import { requestAuthAgentScenarios, type AuthAgentSuggestion } from './authAgentAdvisor.js';

// Backend-birincil güvenlik: hesap-durumu değiştiren / tamamlama hedeflerine ASLA yazma
// (Go authLightBlockedPaths ile AYNI aile; ajan bir bu tür hedef önerse bile backend UYGULAMAZ).
export const AUTH_WRITE_BLOCKLIST_RE = /(change[-_/]?password|reset[-_/]?password|update[-_/]?password|password[-_/]?(change|update|reset)|delete[-_/]?account|account[-_/]?delet|remove[-_/]?account|close[-_/]?account|deregister|change[-_/]?email|update[-_/]?email|email[-_/]?(change|update)|pay(ment)?|checkout|charge|billing|order[-_/]?(complete|confirm|place)|purchase|subscribe|refund)/i;
const STEP_SKIP_RE = /\/(success|completed?|confirm(ation)?|thank[-_]?you|tesekkur|onay|basarili|receipt|invoice)\b/i;
// (İŞ 2) DOM'da açığa çıkan yetki-alanı (priv) ve fiyat/kupon alanı (biz submit ETMEDEN gözlemleriz).
const DOMFORM_PRIV_NAME_RE = /^(role|roles|isadmin|is[_-]?admin|admin|privilege|privileges|priv|usergroup|user[_-]?group|group|grade|accesslevel|access[_-]?level|perm|permission|permissions)$/i;
const DOMFORM_PRICE_NAME_RE = /^(price|amount|total|cost|fiyat|tutar|qty|quantity|adet|discount|indirim|coupon|kupon|miktar|balance|credit|bakiye)$/i;

/** (İŞ 2) domForm'da istemciye AÇIĞA ÇIKMIŞ bir yetki alanı (role/isAdmin/...) var mı? SALT-OKUNUR gözlem. */
function domFormPrivObservation(dom: { url: string; fields: string[]; interesting: string[] }): VFinding | null {
  const priv = dom.interesting.filter((f) => DOMFORM_PRIV_NAME_RE.test(f));
  if (!priv.length) return null; // yetki alanı DOM'da açığa çıkmamış -> gösterge yok (dürüst)
  let ip = dom.url; try { const u = new URL(dom.url); ip = `${u.pathname}${u.hash}` || dom.url; } catch { /* yoksay */ }
  return {
    check: 'privilege_escalation', inputPoint: ip, vulnerable: true,
    technique: `client-exposed privilege field (${priv.join(', ')})`,
    evidence: `Kayıt/profil formunda istemciye açık bir yetki alanı gözlemlendi: \`${priv.join('`, `')}\`. Sunucu bu alanı yok saymıyorsa mass-assignment ile yetki yükseltme riski. **Form SUBMIT EDİLMEDİ** — bu salt-okunur bir DOM gözlemidir; kesin doğrulama manuel test gerektirir.`,
    confidence: 'low', severity: 'medium', sideEffectRisk: 'none',
  };
}
const PRICE_FIELD_RE = /name=["'](price|amount|total|cost|fiyat|tutar|qty|quantity|adet|miktar|discount|indirim|coupon|kupon)["']/i;
const rand = () => randomBytes(8).toString('hex');

function absUrl(host: string, raw: string): string | null {
  try { const u = raw.startsWith('http') ? new URL(raw) : new URL(raw, `https://${host}/`); return u.hostname.toLowerCase() === host.toLowerCase() ? u.toString() : null; } catch { return null; }
}

// Ajan önerileri host başına TEK createFlow ile alınır (iki kontrol PAYLAŞIR). Cache.
const AUTH_AGENT_CACHE = new Map<string, { at: number; p: Promise<AuthAgentSuggestion[] | null> }>();
function getScenarios(host: string, surf: Surface): Promise<AuthAgentSuggestion[] | null> {
  const c = AUTH_AGENT_CACHE.get(host);
  if (c && Date.now() - c.at < 180_000) return c.p;
  // (İŞ 2) domForms = SALT-OKUNUR DOM'dan okunan SPA form-alani gruplari — ajana aday olarak sunulur.
  const forms = [...(surf.massAssignForm ? [surf.massAssignForm.action] : []), ...surf.uploadForms.map((f) => f.action), ...surf.domForms.map(domFormLabel)];
  const p = requestAuthAgentScenarios(host, { inputs: surf.inputs.map((i) => ({ method: i.method, action: i.action, param: i.param })), forms, apiWrites: surf.apiWrites, apiReads: surf.apiReads }).catch(() => null);
  AUTH_AGENT_CACHE.set(host, { at: Date.now(), p });
  return p;
}
export function __resetAuthAgentCache(host?: string): void { if (host) AUTH_AGENT_CACHE.delete(host); else AUTH_AGENT_CACHE.clear(); }

// ======================================================================================
// D.1 — YETKİ YÜKSELTME (privilege escalation) DOĞRULAMA
// ======================================================================================
async function massAssignObservation(ctx: ProbeCtx, host: string, action: string, fields: string[]): Promise<VFinding | null> {
  // BACKEND-BİRİNCİL GUARD: hesap-değiştiren/checkout hedefine ASLA yazma.
  if (AUTH_WRITE_BLOCKLIST_RE.test(action)) return null;
  const usp = new URLSearchParams();
  for (const f of fields) usp.set(f, /email/i.test(f) ? `cybertestify-probe+${rand()}@example.com` : 'cybertestify-test');
  usp.set('role', 'admin'); usp.set('isAdmin', 'true'); usp.set('is_admin', 'true');
  const r = await ctx.fetchOnce(action, { method: 'POST', body: usp.toString(), contentType: 'application/x-www-form-urlencoded' }); // tek deneme, retry YOK
  if (r && (r.status === 200 || r.status === 201 || r.status === 302) && !/(error|hata|invalid|geçersiz|reddedil|not allowed|zorunlu|required)/i.test(r.text.slice(0, 3000))) {
    return {
      check: 'privilege_escalation', inputPoint: new URL(action).pathname, vulnerable: true,
      technique: 'mass-assignment (role/isAdmin ek alan)',
      evidence: `Kayıt/profil benzeri forma fazladan \`role/isAdmin\` alanları eklendiğinde istek açık bir reddedilme olmadan kabul edildi (HTTP ${r.status}). Yetki yükseltme GÖSTERGESİ; gerçek yükseltme DOĞRULANMADI (tamamlama yapılmadı, yükseltilmiş yetkiyle tekrar giriş yapılmadı, oturum dışına çıkılmadı).`,
      confidence: 'low', severity: 'medium', sideEffectRisk: 'possible',
    };
  }
  return null;
}

export async function collectPrivilegeEscalationEvidence(host: string, session: AuthSession): Promise<ActiveCheckEvidence> {
  const surf = await discoverSurface(host, session);
  if (!surf.ok) return { ok: false, pagesScanned: 0, inputsFound: 0, probesSent: 0, findings: [], stopped: null, notes: ['Hedef ana sayfası çekilemedi.'] };
  const ctx = new ProbeCtx();
  ctx.authHeaders = applyAuthHeaders({}, session);
  const findings: VFinding[] = [];
  const notes: string[] = [];
  let agentUsed = false;

  const scenarios = await getScenarios(host, surf).catch(() => null);
  if (scenarios !== null) {
    agentUsed = true;
    // Ajanın seçtiği priv-esc hedeflerini uygula:
    //  (a) domForm seçimi (İŞ 2) -> SALT-OKUNUR gözlem (submit YOK; yalnız DOM'da açığa çıkan yetki alanı).
    //  (b) klasik form action (gerçek POST ucu) -> GÜVENLİ tek-deneme mass-assignment gözlemi.
    for (const s of scenarios.filter((x) => x.check === 'privilege_escalation').slice(0, 3)) {
      if (ctx.stopped) break;
      const dom = surf.domForms.find((d) => s.inputPoint.includes(d.url));
      if (dom) { const f = domFormPrivObservation(dom); if (f) findings.push(f); continue; } // salt-okunur, istek YOK
      const action = absUrl(host, s.inputPoint.replace(/^\w+\s+/, '').split('?')[0]);
      if (!action || AUTH_WRITE_BLOCKLIST_RE.test(action)) continue; // guard
      const fields = surf.massAssignForm && surf.massAssignForm.action === action ? surf.massAssignForm.fields : ['email', 'username'];
      const f = await massAssignObservation(ctx, host, action, fields);
      if (f) { f.technique = 'AI advisory seçti + backend güvenli uyguladı: ' + f.technique; findings.push(f); }
    }
    notes.push('Bu kontrol, keşfedilen authenticated yüzey üzerinde **yapay zekâ destekli advisory (tek LLM çağrısı) ile analiz edilmiştir** (advisory yalnız yapılandırılmış JSON öneri üretir; tüm istekler backend’in güvenli, authenticated-light fonksiyonlarından geçer; advisory doğrudan HTTP atmaz).');
  } else {
    // FALLBACK (advisory anahtarı yok / timeout / hata) -> deterministik: bilinen mass-assignment formu +
    // (İŞ 2) DOM'da açığa çıkan yetki alanları (salt-okunur), advisory muhakemesi olmadan.
    notes.push('AI advisory (LLM) analizi tamamlanamadı (anahtar yok/timeout/hata) — bu kontrol **deterministik göstergeyle sınırlıdır** (keşfedilen kayıt/profil formu + DOM yetki alanları, advisory muhakemesi olmadan).');
    if (surf.massAssignForm) {
      const f = await massAssignObservation(ctx, host, surf.massAssignForm.action, surf.massAssignForm.fields);
      if (f) findings.push(f);
    }
    for (const dom of surf.domForms) { const f = domFormPrivObservation(dom); if (f) findings.push(f); }
  }
  if (ctx.stopped) notes.push(ctx.stopped);
  if (!findings.length && !surf.massAssignForm && !surf.domForms.length) notes.push('Uygun (tamamlama/ödeme dışı) bir kayıt/profil formu bulunamadı — yetki yükseltme gözlemi için hedef yok.');
  return { ok: true, pagesScanned: surf.pagesScanned, inputsFound: surf.massAssignForm ? 1 : 0, probesSent: ctx.sent, findings, stopped: ctx.stopped, notes, agentUsed };
}

// ======================================================================================
// D.2 — ÇOK-ADIMLI İŞ MANTIĞI (GET-only gözlem; ödeme/checkout TAMAMLAMA YOK)
// ======================================================================================
export async function collectMultiStepBusinessLogicEvidence(host: string, session: AuthSession): Promise<ActiveCheckEvidence> {
  const surf = await discoverSurface(host, session);
  if (!surf.ok) return { ok: false, pagesScanned: 0, inputsFound: 0, probesSent: 0, findings: [], stopped: null, notes: ['Hedef ana sayfası çekilemedi.'] };
  const ctx = new ProbeCtx();
  ctx.authHeaders = applyAuthHeaders({}, session);
  const findings: VFinding[] = [];
  const notes: string[] = [];
  let agentUsed = false;

  // (a) İstemci-değiştirilebilir fiyat/miktar/kupon alanı — GÖZLEM (istek yok).
  const html = surf.homeHtml;
  const hiddenPrice = html.match(new RegExp(`<input[^>]*type=["']hidden["'][^>]*${PRICE_FIELD_RE.source}`, 'i')) || html.match(new RegExp(`<input[^>]*${PRICE_FIELD_RE.source}[^>]*type=["']hidden["']`, 'i'));
  if (hiddenPrice) {
    findings.push({ check: 'business_logic_multistep', inputPoint: 'form (hidden price/qty/coupon)', vulnerable: true, technique: 'observation (client-controllable amount)', evidence: 'Formda gizli (hidden) bir fiyat/miktar/kupon alanı gözlemlendi; istemci tarafında değiştirilebilir. Sunucu-taraflı doğrulama yoksa fiyat manipülasyonu riski (kesin doğrulama sepet/ödeme adımı gerektirir — TAMAMLANMADI).', confidence: 'low', severity: 'low', sideEffectRisk: 'none' });
  }
  // (İŞ 2) SALT-OKUNUR DOM'da açığa çıkan fiyat/miktar/kupon alanı (SPA formları — submit YOK).
  const seenPriceIp = new Set<string>();
  for (const dom of surf.domForms) {
    const price = dom.interesting.filter((f) => /^(price|amount|total|cost|fiyat|tutar|qty|quantity|adet|discount|indirim|coupon|kupon|miktar|balance|credit|bakiye)$/i.test(f));
    if (!price.length) continue;
    let ip = dom.url; try { const u = new URL(dom.url); ip = `${u.pathname}${u.hash}` || dom.url; } catch { /* yoksay */ }
    if (seenPriceIp.has(ip)) continue; seenPriceIp.add(ip);
    findings.push({ check: 'business_logic_multistep', inputPoint: ip, vulnerable: true, technique: `client-exposed amount field (${price.join(', ')})`, evidence: `Formda istemciye açık bir fiyat/miktar/kupon alanı gözlemlendi: \`${price.join('`, `')}\`. İstemci tarafında değiştirilebilir; sunucu-taraflı doğrulama yoksa fiyat manipülasyonu riski. **Form SUBMIT EDİLMEDİ** — salt-okunur DOM gözlemi.`, confidence: 'low', severity: 'low', sideEffectRisk: 'none' });
  }

  // (b) Adım-atlama adayları (success/confirm sayfaları) + ajan seçimi.
  const stepLinks = new Set<string>();
  for (const m of html.matchAll(/href\s*=\s*["']([^"']+)["']/gi)) { const a = absUrl(host, m[1].replace(/&amp;/g, '&')); if (a && STEP_SKIP_RE.test(a)) stepLinks.add(a); }
  for (const e of surf.idEndpoints) { if (STEP_SKIP_RE.test(e.url)) stepLinks.add(e.url); }

  const scenarios = await getScenarios(host, surf).catch(() => null);
  const agentPicks: string[] = [];
  if (scenarios !== null) {
    agentUsed = true;
    for (const s of scenarios.filter((x) => x.check === 'business_logic_multistep').slice(0, 4)) {
      const a = absUrl(host, s.inputPoint.replace(/^\w+\s+/, '').split('?')[0]);
      if (a && !AUTH_WRITE_BLOCKLIST_RE.test(a)) agentPicks.push(a);
    }
    notes.push('Bu kontrol, keşfedilen authenticated yüzey üzerinde **yapay zekâ destekli advisory (tek LLM çağrısı) ile analiz edilmiştir** (advisory yalnız JSON öneri üretir; backend YALNIZ GET-gözlem yapar; ödeme/checkout TAMAMLANMAZ; advisory doğrudan HTTP atmaz).');
  } else {
    notes.push('AI advisory (LLM) analizi tamamlanamadı (anahtar yok/timeout/hata) — bu kontrol **deterministik göstergeyle sınırlıdır** (gözlemsel adım-atlama/fiyat alanı, advisory muhakemesi olmadan).');
  }

  // GET-only gözlem: adım-atlama (ön koşul olmadan erişilebilir "onay" sayfası mı).
  const targets = [...new Set([...agentPicks, ...stepLinks])].slice(0, 4);
  for (const url of targets) {
    if (ctx.stopped) break;
    if (AUTH_WRITE_BLOCKLIST_RE.test(url)) continue;
    const r = await ctx.fetchOnce(url); // GET — state değiştirmez
    if (r && r.status === 200 && !/oturum|login|giriş yap|unauthorized|403|yetkisiz/i.test(r.text.slice(0, 2000))) {
      findings.push({ check: 'business_logic_multistep', inputPoint: new URL(url).pathname, vulnerable: true, technique: 'observation (step-skip, GET only)', evidence: `Bir "başarılı/onay" adımı sayfası (${new URL(url).pathname}) ön koşul olmadan doğrudan GET ile erişilebilir göründü — çok-adımlı iş mantığı (adım-atlama) göstergesi; kesin doğrulama manuel test gerektirir (ödeme TAMAMLANMADI).`, confidence: 'low', severity: 'low', sideEffectRisk: 'none' });
    }
  }

  if (ctx.stopped) notes.push(ctx.stopped);
  if (!findings.length) notes.push('Gözlemlenebilir bir istemci-tarafı fiyat/miktar alanı veya doğrudan erişilebilir "onay" adımı bulunamadı.');
  return { ok: true, pagesScanned: surf.pagesScanned, inputsFound: (hiddenPrice ? 1 : 0) + targets.length, probesSent: ctx.sent, findings, stopped: ctx.stopped, notes, agentUsed };
}
