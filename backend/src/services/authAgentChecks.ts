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
import { cachedOriginUrl } from './surfaceEvidence.js';
import { ProbeCtx, discoverSurface, domFormLabel, formCategory, forbiddenFormReason, type ActiveCheckEvidence, type VFinding, type Surface } from './activeVerifyEvidence.js';
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
  try { const u = raw.startsWith('http') ? new URL(raw) : new URL(raw, `${cachedOriginUrl(host)}/`); return u.hostname.toLowerCase() === host.toLowerCase() ? u.toString() : null; } catch { return null; }
}

export type AgentStatus = 'analyzed' | 'no_candidate' | 'unavailable' | 'disabled';
// (PentAGI/advisory DENEY) Authenticated advisory VARSAYILAN KAPALI. AUTH_ADVISOR_HOSTS env'i virgülle
// ayrılmış host allowlist'i; boş/tanımsız -> HER hedefte KAPALI (yalnız deterministik). Ölçüm: authenticated
// senaryoda advisory 0 yeni doğrulanmış kanıt üretti (bkz deney) -> kapalı bırakıldı (compliance: uzak LLM'e
// authenticated yüzey verisi göndermeme + maliyet/gürültü yok). Belirli bir hedefte açmak için env'e ekle.
function authAdvisorAllowed(host: string): boolean {
  const allow = (process.env.AUTH_ADVISOR_HOSTS ?? '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  return allow.includes(host.toLowerCase());
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

// Ajana gidebilecek aday yüzey sayısı (requestAuthAgentScenarios'un allowed-set'iyle AYNI kaynaklar).
// 0 ise advisory ÇAĞRILMAZ (kısa devre) -> "aday yok"; >0 ise advisory GERÇEKTEN çağrılır.
function candidateCount(surf: Surface): number {
  return surf.inputs.length + (surf.massAssignForm ? 1 : 0) + surf.uploadForms.length + surf.domForms.length + surf.apiWrites.length + surf.apiReads.length;
}
// advisory'nin gerçekten çalışıp çalışmadığını 3 duruma ayır (rapor bunu net gösterir).
function deriveAgentStatus(surf: Surface, scenarios: AuthAgentSuggestion[] | null): AgentStatus {
  if (scenarios === null) return 'unavailable';          // LLM çağrıldı ama tamamlanamadı (anahtar/timeout/hata)
  if (candidateCount(surf) === 0) return 'no_candidate'; // aday yoktu -> LLM hiç çağrılmadı (kısa devre [])
  return 'analyzed';                                      // aday vardı -> LLM gerçekten çağrıldı
}

// ======================================================================================
// D.1 — YETKİ YÜKSELTME (privilege escalation) DOĞRULAMA
// ======================================================================================
async function massAssignObservation(ctx: ProbeCtx, host: string, action: string, fields: string[]): Promise<VFinding | null> {
  // BACKEND-BİRİNCİL GUARD: hesap-değiştiren/checkout hedefine ASLA yazma.
  if (AUTH_WRITE_BLOCKLIST_RE.test(action)) return null;
  // (İş 3) Aktif Doğrulama'daki formCategory sınıflandırıcısıyla AYNI kapı: YASAK tür (kayıt/iletişim/
  // parola-sıfırlama/ödeme/abonelik) ve login/arama formlarına gerçek POST ATMA — kalıcı yan etki / anlamsız.
  if (forbiddenFormReason(action, fields)) return null;
  const cat0 = formCategory(action, fields);
  if (cat0 === 'login' || cat0 === 'search') return null;
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

  // (İş 3) DETERMİNİSTİK PROB — advisory'DEN BAĞIMSIZ, HER ZAMAN çalışır. Bulgu KANITI advisory'ye DEĞİL
  // gerçek gözleme dayanır; advisory yalnızca ek aday önerir (yardımcı/ikincil bağlam).
  let detProbed = false;               // güvenle test edilebilir GERÇEK bir yüzey bulundu mu
  const probedActions = new Set<string>();
  //  (a) keşfedilen mass-assignment (kayıt/profil-benzeri) formu — YASAK/login/arama değilse tek gözlemsel probe.
  if (surf.massAssignForm) {
    const { action, fields } = surf.massAssignForm;
    let p = action; try { p = new URL(action).pathname; } catch { /* ham */ }
    const forb = forbiddenFormReason(action, fields); const cat = formCategory(action, fields);
    if (forb) notes.push(`Mass-assignment adayı form (${p}) YASAK türe girdiğinden gerçek POST'tan hariç tutuldu: ${forb}. Bu kontrol için güvenle test edilebilir bir yetki formu değildir.`);
    else if (cat === 'login' || cat === 'search') notes.push(`Aday form (${p}, ${cat}) yetki-yükseltme/over-posting hedefi değildir — atlandı.`);
    else { detProbed = true; probedActions.add(action); const f = await massAssignObservation(ctx, host, action, fields); if (f) findings.push(f); }
  }
  //  (b) DOM'da açığa çıkmış yetki alanları (salt-okunur gözlem; İSTEK YOK) — her zaman.
  for (const dom of surf.domForms) { const f = domFormPrivObservation(dom); if (f && !findings.some((x) => x.inputPoint === f.inputPoint)) { findings.push(f); detProbed = true; } }

  // (YARDIMCI/İKİNCİL) advisory — ek aday seçerse deterministik güvenli probe'dan geçirilir. Kanıt DEĞİL.
  const advisorOn = authAdvisorAllowed(host); // (deney) advisory VARSAYILAN KAPALI — yalnız izin verilen hedeflerde
  const scenarios = advisorOn ? await getScenarios(host, surf).catch(() => null) : null;
  const agentStatus: AgentStatus = advisorOn ? deriveAgentStatus(surf, scenarios) : 'disabled';
  console.log(`[advisory] priv-esc host=${host} candidates=${candidateCount(surf)} agentStatus=${agentStatus} scenarios=${scenarios === null ? 'null' : scenarios.length}`);
  if (scenarios !== null) {
    for (const s of scenarios.filter((x) => x.check === 'privilege_escalation').slice(0, 3)) {
      if (ctx.stopped) break;
      const dom = surf.domForms.find((d) => s.inputPoint.includes(d.url));
      if (dom) { const f = domFormPrivObservation(dom); if (f && !findings.some((x) => x.inputPoint === f.inputPoint)) { findings.push(f); detProbed = true; } continue; }
      const action = absUrl(host, s.inputPoint.replace(/^\w+\s+/, '').split('?')[0]);
      if (!action || probedActions.has(action)) continue;
      const fields = surf.massAssignForm && surf.massAssignForm.action === action ? surf.massAssignForm.fields : ['email', 'username'];
      probedActions.add(action);
      const f = await massAssignObservation(ctx, host, action, fields); // içi YASAK/login/arama guard'lı
      if (f) { f.technique = 'AI advisory seçti + backend güvenli uyguladı: ' + f.technique; findings.push(f); detProbed = true; }
    }
  }

  // (DÜRÜSTLÜK) "denedi, temiz" ≠ "uygun yüzey yok". Advisory tek başına kanıt sayılmaz.
  if (!detProbed) {
    notes.push('Yetki-yükseltme için GÜVENLE test edilebilir (YASAK olmayan; kayıt/profil/ayar tipi) bir form/uç bu hedefte bulunamadı — bu kontrol **İncelenemedi** (deterministik prob için uygun authenticated yüzey yok). Not: bazı açıklar (API’de gizli `role` kabulü vb.) UI/DOM’da görünmez; kesin sonuç manuel test gerektirir.');
  } else if (!findings.length) {
    notes.push('Keşfedilen authenticated form(lar)a gözlemsel mass-assignment probu (`role/isAdmin` ek alan) gönderildi; sunucu açık bir reddetme ile karşıladı — yetki-yükseltme göstergesi **bulunamadı** (deterministik sonuç — advisory değil, gerçek gözlem).');
  }
  if (scenarios !== null && agentStatus === 'analyzed') notes.push('AI advisory bu yüzeyi ayrıca analiz etti (yardımcı bağlam; nihai karar deterministik prob/gözleme dayanır — advisory tek başına kanıt sunulmaz).');
  if (ctx.stopped) notes.push(ctx.stopped);
  // (DÜRÜSTLÜK) inputsFound = GERÇEKTEN deterministik test edilen yüzey. detProbed yoksa 0 -> rapor "İncelenemedi".
  const inputsFound = detProbed ? ((surf.massAssignForm ? 1 : 0) + surf.domForms.length) : 0;
  return { ok: true, pagesScanned: surf.pagesScanned, inputsFound, probesSent: ctx.sent, findings, stopped: ctx.stopped, notes, agentUsed: scenarios !== null, agentStatus };
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

  const advisorOn = authAdvisorAllowed(host); // (deney) advisory VARSAYILAN KAPALI — yalnız izin verilen hedeflerde
  const scenarios = advisorOn ? await getScenarios(host, surf).catch(() => null) : null;
  const agentStatus: AgentStatus = advisorOn ? deriveAgentStatus(surf, scenarios) : 'disabled';
  console.log(`[advisory] multistep host=${host} candidates=${candidateCount(surf)} agentStatus=${agentStatus} scenarios=${scenarios === null ? 'null' : scenarios.length}`);
  const agentPicks: string[] = [];
  if (scenarios !== null) {
    for (const s of scenarios.filter((x) => x.check === 'business_logic_multistep').slice(0, 4)) {
      const a = absUrl(host, s.inputPoint.replace(/^\w+\s+/, '').split('?')[0]);
      if (a && !AUTH_WRITE_BLOCKLIST_RE.test(a)) agentPicks.push(a);
    }
    if (agentStatus === 'analyzed') {
      notes.push('Bu kontrol, keşfedilen authenticated yüzey üzerinde **yapay zekâ destekli advisory (tek LLM çağrısı) ile analiz edilmiştir** (advisory yalnız JSON öneri üretir; backend YALNIZ GET-gözlem yapar; ödeme/checkout TAMAMLANMAZ; advisory doğrudan HTTP atmaz).');
    } else { // no_candidate
      notes.push('Bu hedefte pasif keşifle gözlemlenebilir bir çok-adımlı iş-mantığı giriş noktası (istemci-tarafı fiyat/miktar/kupon alanı, ön-koşulsuz "onay" adımı) bulunamadığından advisory çalıştırılmadı. İş mantığı zafiyetleri bağlama özeldir; kesin sonuç manuel test gerektirir.');
    }
  } else if (agentStatus === 'disabled') {
    notes.push('Bu kontrol **deterministik olarak** çalıştırıldı (gözlemsel adım-atlama + istemci-değiştirilebilir fiyat/miktar/kupon alanı). AI advisory katmanı **varsayılan olarak devre dışıdır** (deneyde ek doğrulanmış kanıt üretmediği için).');
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
  if (!findings.length && agentStatus === 'analyzed') notes.push('Yapay zekâ destekli advisory bu yüzeyi analiz etti; uygulanabilir bir çok-adımlı iş-mantığı vektörü tespit edilmedi (temiz sonuç — uydurma bulgu yok).');
  const inputsFound = (hiddenPrice ? 1 : 0) + targets.length + surf.domForms.length;
  return { ok: true, pagesScanned: surf.pagesScanned, inputsFound, probesSent: ctx.sent, findings, stopped: ctx.stopped, notes, agentUsed: scenarios !== null, agentStatus };
}
