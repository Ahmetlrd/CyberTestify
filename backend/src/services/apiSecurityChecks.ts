/**
 * (Tam Kapsamlı Pentest — Faz 3-B) API GÜVENLİĞİ DERİNLİĞİ (OWASP API Security Top 10 2023 + WSTG-APIT).
 * 5 kontrol; hepsi read-only/gözlemsel — veri değiştirme/mutasyon/DoS YOK.
 *
 * SÜTUN 0 — GERÇEK API PROVENANCE (bu modülde en kritik): Kontroller ancak hedefte GERÇEK, KEŞFEDİLMİŞ
 * (aynı-origin JS/HTML'den mined + JSON dönen, SPA catch-all shell OLMAYAN) REST/GraphQL API varsa
 * çalışır. Firebase/istemci-SDK SPA'da (nomorelink) veya SPA-catch-all 200 dönen sahte "/api" uçlarında
 * GERÇEK API YOK → "Kapsam dışı — uygulanabilir API bulunamadı". Tahmin/eğitim-verisi endpoint'i başka
 * hedefte bulgu olamaz (yalnız bu hedefte gözlemlenen + JSON dönen uç).
 *
 *   F1 BOLA/BFLA (API1/API5) — nesne/fonksiyon-seviyesi yetki: ZATEN "Authenticated IDOR" + "Forced
 *      Browsing" bölümlerinde OWASP API1/API5 kapsamında değerlendirilir → burada ÇAPRAZ-REFERANS (çift
 *      bulgu/tutarsızlık önlemek için burada TEKRAR probe EDİLMEZ).
 *   F2 Aşırı veri ifşası / BOPLA (API3) · F3 rate-limit (API4) · F4 shadow/deprecated sürüm (API9)
 *      · F5 GraphQL introspection (APIT-99).
 */
import { createHash } from 'node:crypto';
import { fetchClientCorpus } from './jsAnalysis.js';
import { cachedOriginUrl, resolveOrigin } from './surfaceEvidence.js';
import { applyAuthHeaders, type AuthSession } from './authSession.js';
import { logScanStep } from './scanLogger.js';
import type { ActiveCheckEvidence, VFinding } from './activeVerifyEvidence.js';

const md5 = (s: string) => createHash('md5').update(s).digest('hex');
const REQ_TIMEOUT = 12_000;
const MIN_DELAY = 250;
let lastAt = 0;

type Probe = { status: number; text: string; headers: Headers; ms: number };
async function probe(url: string, opts: { method?: string; headers?: Record<string, string>; body?: string; label: string; noDelay?: boolean }): Promise<Probe | null> {
  if (!opts.noDelay) { const w = MIN_DELAY - (Date.now() - lastAt); if (w > 0) await new Promise((r) => setTimeout(r, w)); }
  lastAt = Date.now();
  const ctrl = new AbortController(); const timer = setTimeout(() => ctrl.abort(), REQ_TIMEOUT); const t0 = Date.now();
  try {
    const res = await fetch(url, { method: opts.method ?? 'GET', body: opts.body, redirect: 'manual', signal: ctrl.signal, headers: { 'user-agent': 'CyberTestify-API/1.0', accept: 'application/json,*/*', ...(opts.headers ?? {}) } });
    const buf = Buffer.from(await res.arrayBuffer());
    logScanStep({ step: 'API Güvenliği Derinliği', method: opts.method ?? 'GET', url, status: res.status, durationMs: Date.now() - t0, sizeBytes: buf.length });
    return { status: res.status, text: buf.subarray(0, 200_000).toString('utf-8'), headers: res.headers, ms: Date.now() - t0 };
  } catch { logScanStep({ step: 'API Güvenliği Derinliği', method: opts.method ?? 'GET', url, status: 0, level: 'warn', durationMs: Date.now() - t0 }); return null; }
  finally { clearTimeout(timer); }
}
const isJson = (p: Probe) => /json/i.test(p.headers.get('content-type') ?? '') || /^\s*[[{]/.test(p.text.trim());

// Aynı-origin JS/HTML'den API yolu madenciliği (fetch/axios/url literalleri). Asset/gürültü elenir.
const API_MINE_RE = /["'`](\/(?:rest|api|v\d+|graphql|products?|users?|orders?|accounts?|customers?|items?|invoices?|categories|search|profile|me|admin)[\w/.?=&-]*)["'`]/gi;
export function mineApiPaths(text: string): string[] {
  const out = new Set<string>();
  for (const m of text.matchAll(API_MINE_RE)) {
    const p = m[1].split('#')[0];
    if (/\.(js|css|png|jpe?g|svg|gif|webp|ico|woff2?|map|json)$/i.test(p.split('?')[0])) continue; // asset
    if (p.length > 120) continue;
    out.add(p);
  }
  return [...out].slice(0, 20);
}

// F2: aşırı veri / BOPLA — yanıtta hassas/aşırı alan adları (değer REDAKTE).
const SENSITIVE_FIELD_RE = /"(password|passwordHash|pwd|hash|salt|ssn|tckn|creditcard|cardnumber|cvv|secret|privatekey|api[_-]?key|access[_-]?token|refresh[_-]?token|otpsecret|totpsecret)"\s*:/i;
const OVEREXPOSED_FIELD_RE = /"(isadmin|is_admin|role|roles|isdeleted|deletedat|internalid|internal_id|_id|adminflag)"\s*:/i;

export async function collectApiSecurityEvidence(host: string, session: AuthSession): Promise<ActiveCheckEvidence> {
  const findings: VFinding[] = []; const notes: string[] = [];
  await resolveOrigin(host).catch(() => null);
  const origin = cachedOriginUrl(host);
  const corpus = await fetchClientCorpus(host);
  if (!corpus.reachable) return { ok: true, pagesScanned: 0, inputsFound: 0, probesSent: 1, findings, stopped: null, notes: ['Ana sayfa çekilemedi — API güvenliği bu hedef için **kapsam dışıdır**.'] };
  const shellHash = md5(corpus.homeHtml);
  const authHeaders = applyAuthHeaders({}, session);
  let probes = 1;

  // ---- GERÇEK API KEŞFİ: aynı-origin mined yol + JSON dönen + SPA shell OLMAYAN ----
  const corpusText = corpus.homeHtml + '\n' + corpus.sameOriginJs.map((f) => f.body).join('\n') + '\n' + corpus.inlineScripts.join('\n');
  const candidates = mineApiPaths(corpusText);
  const realApi: Array<{ path: string; body: string }> = [];
  for (const p of candidates) {
    if (realApi.length >= 8) break;
    let u: string; try { u = new URL(p, `${origin}/`).toString(); } catch { continue; }
    if (new URL(u).hostname.toLowerCase() !== host.toLowerCase()) continue;
    const r = await probe(u, { headers: authHeaders, label: `API keşif ${p}` }); probes++;
    if (!r || r.status >= 400 || !r.text) continue;
    if (md5(r.text) === shellHash) continue;   // SPA catch-all -> gerçek API değil
    if (!isJson(r)) continue;                   // JSON değil -> gerçek REST API değil
    realApi.push({ path: new URL(u).pathname, body: r.text });
  }

  // ---- GraphQL keşfi (read-only) ----
  let graphqlUrl: string | null = null;
  for (const g of ['/graphql', '/api/graphql', '/v1/graphql', '/query']) {
    if (!/graphql|query/i.test(corpusText) && g !== '/graphql') continue;
    const u = new URL(g, `${origin}/`).toString();
    const r = await probe(u, { method: 'POST', headers: { ...authHeaders, 'content-type': 'application/json' }, body: JSON.stringify({ query: '{__typename}' }), label: `GraphQL keşif ${g}` }); probes++;
    // Gerçek GraphQL yanıtı: JSON + ({data:{__typename}} çözümü) VEYA GraphQL-biçimli errors dizisi.
    // "Cannot POST /graphql" gibi 404/HTML gövdesi ("graphql" substring) KABUL EDİLMEZ (yanlış-pozitif).
    if (r && md5(r.text) !== shellHash && isJson(r) &&
        (/"__typename"\s*:/.test(r.text) || (/"errors"\s*:\s*\[/.test(r.text) && /"(message|locations|extensions)"\s*:/.test(r.text)))) { graphqlUrl = u; break; }
  }

  // ---- SÜTUN 0 SCOPING: gerçek API yoksa TÜM bölüm kapsam dışı (hayalet-bulgu önleme) ----
  if (realApi.length === 0 && !graphqlUrl) {
    return { ok: true, pagesScanned: 1, inputsFound: 0, probesSent: probes, findings: [], stopped: null,
      notes: [`Aynı-origin, JSON dönen (SPA catch-all shell OLMAYAN) gerçek bir sunucu REST/GraphQL API ucu bu hedefte gözlemlenmedi (istemci-SDK/Firebase/SPA) — API güvenliği kontrolleri bu hedef için **kapsam dışıdır**.`] };
  }

  // ---- F1: BOLA/BFLA çapraz-referans (tekrar probe YOK) ----
  notes.push('BOLA/BFLA (OWASP API1/API5 — nesne/fonksiyon-seviyesi yetki) **Authenticated IDOR** ve **Forced Browsing** bölümlerinde değerlendirilmiştir (çift bulgu önlemek için burada tekrar probe edilmedi).');

  // ---- F2: AŞIRI VERİ İFŞASI / BOPLA (API3) — gerçek API yanıtlarında hassas/aşırı alan ----
  for (const api of realApi) {
    const sens = api.body.match(SENSITIVE_FIELD_RE);
    const over = api.body.match(OVEREXPOSED_FIELD_RE);
    if (sens) findings.push({
      check: 'excessive_data_exposure', inputPoint: api.path, vulnerable: true, technique: 'aşırı veri ifşası / BOPLA (API3) — yanıt alan gözlemi',
      evidence: `API yanıtı (\`${api.path}\`) **hassas alan** içeriyor (\`${sens[1]}\`) — değer REDAKTE. İstemciye gönderilen yanıt gerekenden fazla/hassas veri ifşa ediyor (parola-hash/sır/token vb.). Sunucuda alan-allowlist (response DTO) uygulanmalı.`,
      confidence: 'high', severity: 'high', sideEffectRisk: 'none',
    });
    else if (over) findings.push({
      check: 'excessive_data_exposure', inputPoint: api.path, vulnerable: true, technique: 'aşırı veri ifşası / BOPLA (API3) — yanıt alan gözlemi',
      evidence: `API yanıtı (\`${api.path}\`) UI'nin ihtiyaç duymadığı iç/aşırı alan içeriyor (\`${over[1]}\`) — iç ID/rol/durum alanları istemciye sızıyor (gösterge). Yanıtı yalnız gereken alanlarla sınırlayın (allowlist DTO).`,
      confidence: 'medium', severity: 'medium', sideEffectRisk: 'none',
    });
  }

  // ---- F3: API RATE-LIMIT (API4) — MODEST burst (DoS DEĞİL), 429/header gözlemi ----
  if (realApi.length) {
    const target = new URL(realApi[0].path, `${origin}/`).toString();
    let limited = false; let stopped = false; const times: number[] = [];
    for (let i = 0; i < 10; i++) {
      const r = await probe(target, { headers: authHeaders, label: `F3 rate-limit burst#${i + 1}`, noDelay: true }); probes++;
      if (!r) { stopped = true; break; }
      times.push(r.ms);
      if (r.status === 429 || r.headers.get('retry-after') || /ratelimit-remaining|x-rate-limit/i.test([...r.headers.keys()].join(','))) { limited = true; break; }
      if (r.status >= 500 || (times.length > 2 && r.ms > times[0] * 4 && r.ms > 2000)) { stopped = true; break; } // hedefi yorma — dur
    }
    if (limited) notes.push('API rate-limit gözlemlendi (429 / rate-limit başlığı) — olumlu.');
    else if (!stopped) findings.push({
      check: 'no_rate_limit', inputPoint: new URL(realApi[0].path, origin).pathname, vulnerable: true, technique: 'API rate-limit / kısıtlanmamış tüketim gözlemi (modest burst — DoS değil)',
      evidence: `Bir API ucuna (\`${new URL(realApi[0].path, origin).pathname}\`) art arda ${times.length} istek sonrası **429 veya rate-limit başlığı gözlenmedi** — kısıtlanmamış kaynak tüketimi (API4) göstergesi (brute-force/scraping/DoS'a açık olabilir). Hedef yorulmadı (modest burst). Rate-limit + kota önerilir.`,
      confidence: 'medium', severity: 'medium', sideEffectRisk: 'none',
    });
  }

  // ---- F4: SHADOW / DEPRECATED SÜRÜM (API9) — sürüm uçları erişilebilir mi (SPA shell = gerçek değil) ----
  const versionsSeen: string[] = [];
  for (const v of ['/api/v1', '/api/v2', '/api/v3', '/v1', '/v2', '/v3']) {
    const u = new URL(v, `${origin}/`).toString();
    const r = await probe(u, { headers: authHeaders, label: `F4 sürüm ${v}` }); probes++;
    if (!r || r.status >= 400 || !r.text) continue;
    if (md5(r.text) === shellHash || !isJson(r)) continue; // SPA shell / JSON değil -> gerçek sürüm ucu değil
    versionsSeen.push(v);
  }
  if (versionsSeen.length >= 2) findings.push({
    check: 'shadow_api_version', inputPoint: versionsSeen.join(', '), vulnerable: true, technique: 'shadow / deprecated API sürümü gözlemi (güvenli GET)',
    evidence: `Birden fazla API sürüm ucu aynı anda erişilebilir (\`${versionsSeen.join('`, `')}\`) — eski/gölge sürümler yamasız kalıp saldırı yüzeyini genişletebilir (API9). Kullanılmayan sürümleri kapatın/kaldırın. Gösterge.`,
    confidence: 'medium', severity: 'medium', sideEffectRisk: 'none',
  });

  // ---- F5: GRAPHQL INTROSPECTION (APIT-99) — read-only introspection (mutasyon YOK) ----
  if (graphqlUrl) {
    const introspect = JSON.stringify({ query: '{__schema{types{name}}}' });
    const r = await probe(graphqlUrl, { method: 'POST', headers: { ...authHeaders, 'content-type': 'application/json' }, body: introspect, label: 'F5 GraphQL introspection' }); probes++;
    if (r && r.status < 400 && /"__schema"|"types"\s*:\s*\[/.test(r.text)) findings.push({
      check: 'graphql_introspection', inputPoint: new URL(graphqlUrl).pathname, vulnerable: true, technique: 'GraphQL introspection açıklığı (read-only sorgu; mutasyon YOK)',
      evidence: `GraphQL ucu (\`${new URL(graphqlUrl).pathname}\`) **introspection açık** — tüm şema (tipler/alanlar/mutasyonlar) dışarıya ifşa oluyor, saldırı yüzeyini haritalar. Üretimde introspection kapatılmalı. (Yalnız şema sorgulandı; veri değiştirilmedi.)`,
      confidence: 'high', severity: 'medium', sideEffectRisk: 'none',
    });
    else notes.push('GraphQL ucu gözlemlendi ancak introspection kapalı/erişilemez görünüyor (olumlu).');
  }

  notes.push(`Keşfedilen gerçek API ucu: **${realApi.length}**${graphqlUrl ? ' + GraphQL' : ''} (aynı-origin, JSON, SPA-shell olmayan). Denenen: **${probes}** güvenli prob (yalnız GET + read-only introspection; mutasyon/veri-değiştirme/DoS YOK).`);
  return { ok: true, pagesScanned: 1, inputsFound: realApi.length + (graphqlUrl ? 1 : 0), probesSent: probes, findings, stopped: null, notes };
}
