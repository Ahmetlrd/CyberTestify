/**
 * (Tam Kapsamlı Pentest — Faz 1-B) CLIENT-SIDE STATİK ANALİZ. 6 DETERMİNİSTİK kontrol; hepsi PASİF
 * (JS/HTML statik ayrıştırma) + tek güvenli redirect prob (open redirect). Faz 1-A ile AYNI corpus'u
 * (fetchClientCorpus) paylaşır → çift fetch yok. SÜTUN 0: her bulgu gerçek gözleme dayanır.
 *
 *   1) DOM-based XSS sink analizi (statik — GÖSTERGE, kanıtlanmış XSS değil)
 *   2) postMessage / güvensiz message handler (origin doğrulaması yok)
 *   3) Browser storage'a hassas veri (localStorage/sessionStorage setItem — statik)
 *   4) Eksik SRI (harici script/style'da integrity yok)
 *   5) Reverse tabnabbing (target=_blank + rel=noopener/noreferrer yok)
 *   6) Open redirect (tek güvenli prob — redirect'i TAKİP ETMEDEN Location gözlemi)
 */
import { fetchClientCorpus } from './jsAnalysis.js';
import { cachedOriginUrl } from './surfaceEvidence.js';
import { logScanStep } from './scanLogger.js';
import type { ActiveCheckEvidence, VFinding } from './activeVerifyEvidence.js';

const MAX_REDIRECT_PROBES = 8;
const PROBE_TARGET = 'https://ct-oredir-probe.example.com/x'; // zararsız HARİCİ hedef (gözlem için)

// --- 1) DOM-XSS: sink + kullanıcı-kontrollü kaynak ---
const SINKS: Array<{ id: string; re: RegExp }> = [
  { id: '.innerHTML=', re: /\.(?:inner|outer)HTML\s*=/ },
  { id: 'document.write', re: /document\.write(?:ln)?\s*\(/ },
  { id: 'eval(', re: /\beval\s*\(/ },
  { id: 'setTimeout/Interval("…")', re: /\bset(?:Timeout|Interval)\s*\(\s*['"`]/ },
  { id: '.html(', re: /\.html\s*\(/ },
  { id: 'insertAdjacentHTML', re: /insertAdjacentHTML\s*\(/ },
  { id: 'location=/assign/replace', re: /(?:\bwindow\.location|\blocation\.href|\blocation)\s*=|location\.(?:assign|replace)\s*\(/ },
];
const SOURCES: Array<{ id: string; re: RegExp }> = [
  { id: 'location.hash', re: /location\.hash/ },
  { id: 'location.search', re: /location\.search/ },
  { id: 'document.URL', re: /document\.(?:URL|documentURI)/ },
  { id: 'document.referrer', re: /document\.referrer/ },
  { id: 'window.name', re: /window\.name/ },
];
const SENSITIVE_KEY_RE = /(token|jwt|auth|session|passw(or)?d|secret|api[_-]?key|credential|bearer|access[_-]?token|refresh[_-]?token|ssn|tckn|kimlik)/i;
// Not: geniş liste güvenli — aday sadece PROB için; bulgu YALNIZ gerçek harici yönlendirme gözlenirse.
const REDIRECT_PARAM_RE = /^(url|redirect|redirect_uri|redirect_url|redir|next|return|return_url|returnurl|returnto|dest|destination|continue|continue_url|goto|target|forward|to|link|callback|out|u|r)$/i;

async function probeRedirectLocation(url: string): Promise<{ status: number; location: string | null; body: string } | null> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 12_000);
  const t0 = Date.now();
  try {
    const res = await fetch(url, { redirect: 'manual', signal: ctrl.signal, headers: { 'user-agent': 'CyberTestify-ClientSide/1.0' } });
    const buf = Buffer.from(await res.arrayBuffer());
    const body = buf.subarray(0, 4000).toString('utf-8');
    logScanStep({ step: 'Client-Side Statik Analiz', method: 'GET', url, status: res.status, durationMs: Date.now() - t0, summary: 'open-redirect gözlem probu (takip YOK)' });
    return { status: res.status, location: res.headers.get('location'), body };
  } catch {
    logScanStep({ step: 'Client-Side Statik Analiz', method: 'GET', url, status: 0, level: 'warn', durationMs: Date.now() - t0, summary: 'redirect probu başarısız' });
    return null;
  } finally { clearTimeout(timer); }
}

const isExternalTo = (u: string, host: string): boolean => { try { return new URL(u, `https://${host}/`).hostname.toLowerCase() !== host.toLowerCase(); } catch { return false; } };

export async function collectClientSideEvidence(host: string, de: boolean = false): Promise<ActiveCheckEvidence> {
  const t = (trS: string, deS: string) => (de ? deS : trS);
  const findings: VFinding[] = [];
  const notes: string[] = [];
  const c = await fetchClientCorpus(host);
  if (!c.reachable) {
    return { ok: true, pagesScanned: 0, inputsFound: 0, probesSent: 1, findings, stopped: null,
      notes: [t('Ana sayfa HTML çekilemedi — client-side statik analiz bu hedef için **kapsam dışıdır**.', 'Startseiten-HTML konnte nicht abgerufen werden — die clientseitige statische Analyse ist für dieses Ziel **außerhalb des Geltungsbereichs**.')] };
  }

  const jsBlobs: Array<{ name: string; body: string }> = [
    ...c.inlineScripts.map((b, i) => ({ name: `inline-script#${i + 1}`, body: b })),
    ...c.sameOriginJs.map((f) => ({ name: shortName(f.url), body: f.body })),
  ];

  // 1) DOM-XSS sink↔source (AYNI SATIRDA birlikte → gösterge). Dedup file+sink+source, cap 6.
  const domSeen = new Set<string>();
  outer: for (const blob of jsBlobs) {
    for (const rawLine of blob.body.split(/\r?\n/)) {
      const line = rawLine.length > 600 ? rawLine.slice(0, 600) : rawLine;
      const sink = SINKS.find((s) => s.re.test(line));
      if (!sink) continue;
      const source = SOURCES.find((s) => s.re.test(line));
      if (!source) continue;
      const key = `${blob.name}|${sink.id}|${source.id}`;
      if (domSeen.has(key)) continue;
      domSeen.add(key);
      findings.push({
        check: 'dom_xss_sink', inputPoint: `${blob.name} · ${sink.id}`, vulnerable: true,
        technique: 'statik DOM-XSS sink↔kaynak eşleşmesi (gösterge)',
        evidence: `\`${blob.name}\` içinde AYNI ifadede tehlikeli sink (\`${sink.id}\`) ile kullanıcı-kontrollü kaynak (\`${source.id}\`) birlikte görüldü — olası DOM-based XSS **GÖSTERGESİ**. Bu STATİK bir eşleşmedir; **kanıtlanmış XSS DEĞİL**, dinamik doğrulama gerekir (yanlış-pozitif olabilir).`,
        confidence: 'low', severity: 'low', sideEffectRisk: 'none',
      });
      if (domSeen.size >= 6) break outer;
    }
  }

  // 2) postMessage: message handler'da origin doğrulaması yok. Dedup file, cap 4.
  const pmSeen = new Set<string>();
  for (const blob of jsBlobs) {
    for (const m of blob.body.matchAll(/addEventListener\s*\(\s*['"`]message['"`]|\.onmessage\s*=/g)) {
      const around = blob.body.slice(m.index ?? 0, (m.index ?? 0) + 700);
      if (/\.origin\b/.test(around)) continue; // origin kontrolü var → güvenli
      if (pmSeen.has(blob.name)) continue;
      pmSeen.add(blob.name);
      findings.push({
        check: 'insecure_postmessage', inputPoint: `${blob.name} · message handler`, vulnerable: true,
        technique: 'web messaging (postMessage) origin doğrulaması analizi',
        evidence: `\`${blob.name}\` içinde bir \`message\` olay dinleyicisi **event.origin doğrulaması olmadan** işlem yapıyor gibi görünüyor — güvensiz cross-origin mesaj işleme göstergesi. Gönderen origin'i allowlist ile doğrulanmalı.`,
        confidence: 'medium', severity: 'medium', sideEffectRisk: 'none',
      });
      if (pmSeen.size >= 4) break;
    }
  }

  // 3) Browser storage'a hassas veri (statik setItem). Dedup file+key, cap 6.
  const stSeen = new Set<string>();
  for (const blob of jsBlobs) {
    for (const m of blob.body.matchAll(/(local|session)Storage\s*\.\s*setItem\s*\(\s*['"`]([^'"`]{1,60})['"`]/gi)) {
      const key = m[2];
      if (!SENSITIVE_KEY_RE.test(key)) continue;
      const dk = `${blob.name}|${key}`;
      if (stSeen.has(dk)) continue;
      stSeen.add(dk);
      findings.push({
        check: 'sensitive_storage', inputPoint: `${blob.name} · ${m[1]}Storage['${key}']`, vulnerable: true,
        technique: 'browser storage statik hassas-veri analizi',
        evidence: `\`${blob.name}\` içinde \`${m[1]}Storage.setItem('${key}', …)\` — hassas veri (oturum/kimlik göstergesi) istemci depolamasına yazılıyor (değer gösterilmez). localStorage/sessionStorage XSS ile okunabilir; oturum verisi için HttpOnly çerez tercih edilmelidir.`,
        confidence: 'medium', severity: 'medium', sideEffectRisk: 'none',
      });
      if (stSeen.size >= 6) break;
    }
  }

  // 4) Eksik SRI: harici script/style'da integrity yok. Dedup url, cap 10.
  const sriTargets = [...c.scriptTags, ...c.styleTags].filter((t) => t.external && !t.hasIntegrity);
  for (const t of sriTargets.slice(0, 10)) {
    findings.push({
      check: 'missing_sri', inputPoint: shortName(t.url), vulnerable: true,
      technique: 'Subresource Integrity (SRI) statik kontrolü',
      evidence: `Harici kaynak \`${t.url}\` **integrity (SRI) attribute'u olmadan** yükleniyor — CDN/tedarik-zinciri ele geçirilirse değiştirilmiş kod çalışabilir. \`integrity=\"sha384-…\" crossorigin=\"anonymous\"\` eklenmeli.`,
      confidence: 'high', severity: 'low', sideEffectRisk: 'none',
    });
  }

  // 5) Reverse tabnabbing: target=_blank + rel yok (harici). Dedup href, cap 8.
  const tabTargets = c.blankLinks.filter((l) => l.external && !l.hasRelSafe);
  const tabSeen = new Set<string>();
  for (const l of tabTargets) {
    if (tabSeen.has(l.href)) continue; tabSeen.add(l.href);
    findings.push({
      check: 'reverse_tabnabbing', inputPoint: l.href, vulnerable: true,
      technique: 'reverse tabnabbing (target=_blank) statik kontrolü',
      evidence: `\`target="_blank"\` ile açılan harici bağlantı (\`${l.href}\`) **rel="noopener"/"noreferrer" olmadan** — açılan sayfa \`window.opener\` ile bu sekmeyi başka yere yönlendirebilir (reverse tabnabbing). \`rel="noopener noreferrer"\` eklenmeli.`,
      confidence: 'high', severity: 'low', sideEffectRisk: 'none',
    });
    if (tabSeen.size >= 8) break;
  }

  // 6) Open redirect: HTML'de GÖZLENEN redirect-parametreli URL'lere tek güvenli prob (takip YOK).
  const candidates = discoverRedirectCandidates(c.homeHtml, host).slice(0, MAX_REDIRECT_PROBES);
  let redirectProbes = 0;
  for (const cnd of candidates) {
    redirectProbes++;
    const r = await probeRedirectLocation(cnd.url);
    if (!r) continue;
    const loc = r.location ?? '';
    const bodyRedirect = r.body.match(/(?:location\.(?:href|replace|assign)\s*[=(]\s*['"`]|http-equiv=["']refresh["'][^>]*url=)([^'"`\s>]+)/i)?.[1] ?? '';
    const hitLoc = loc && /ct-oredir-probe\.example\.com/i.test(loc) && isExternalTo(loc, host);
    const hitBody = bodyRedirect && /ct-oredir-probe\.example\.com/i.test(bodyRedirect);
    if (hitLoc || hitBody) {
      findings.push({
        check: 'open_redirect', inputPoint: `${cnd.path}?${cnd.param}=`, vulnerable: true,
        technique: 'açık yönlendirme (open redirect) — tek güvenli gözlem probu (redirect TAKİP EDİLMEDİ)',
        evidence: `\`${cnd.path}\` uç noktası, \`${cnd.param}\` parametresine verilen HARİCİ bir URL'e yönlendiriyor (${hitLoc ? 'sunucu Location başlığı' : 'istemci-tarafı yönlendirme'} harici domaine işaret etti). Doğrulanmamış yönlendirme kimlik-avı/oturum-çalma için kullanılabilir. Redirect hedefleri allowlist ile sınırlanmalı.`,
        confidence: 'high', severity: 'medium', sideEffectRisk: 'none',
      });
    }
  }

  // --- POZİTİF GÜVENCE (gerçek sayılar) ---
  notes.push(t(`Statik ayrıştırıldı: **${c.sameOriginJs.length}** same-origin JS + **${c.inlineScripts.length}** inline script; **${sriTargets.length}** harici kaynak SRI için, **${c.blankLinks.length}** \`target=_blank\` link tabnabbing için kontrol edildi; **${redirectProbes}** redirect-parametresi güvenli probla denendi (redirect TAKİP EDİLMEDİ).`, `Statisch geparst: **${c.sameOriginJs.length}** Same-Origin-JS + **${c.inlineScripts.length}** Inline-Skripte; **${sriTargets.length}** externe Ressourcen auf SRI, **${c.blankLinks.length}** \`target=_blank\`-Links auf Tabnabbing geprüft; **${redirectProbes}** Redirect-Parameter mit sicherer Probe getestet (Redirect NICHT verfolgt).`));
  notes.push(t('DOM-XSS eşleşmeleri STATİK **göstergedir** (kanıtlanmış XSS değil); yüksek yanlış-pozitif potansiyeli taşır ve dinamik doğrulama gerektirir.', 'DOM-XSS-Treffer sind ein STATISCHER **Indikator** (kein nachgewiesenes XSS); sie bergen ein hohes Falsch-Positiv-Potenzial und erfordern eine dynamische Verifizierung.'));
  if (!candidates.length) notes.push(t('HTML’de gözlemlenen bir yönlendirme (redirect) parametresi bulunamadı — open redirect probu **kapsam dışı**.', 'Im HTML wurde kein beobachteter Redirect-Parameter gefunden — die Open-Redirect-Probe ist **außerhalb des Geltungsbereichs**.'));

  const inputs = jsBlobs.length + sriTargets.length + c.blankLinks.length + candidates.length;
  return { ok: true, pagesScanned: 1, inputsFound: inputs, probesSent: c.fetches + redirectProbes, findings, stopped: null, notes };
}

function shortName(u: string): string { try { return new URL(u).pathname.split('/').pop() || u; } catch { return u; } }

// HTML'deki href/action URL'lerinde GÖZLENEN redirect-parametrelerini bul (uydurma yok).
function discoverRedirectCandidates(html: string, host: string): Array<{ url: string; path: string; param: string }> {
  const out: Array<{ url: string; path: string; param: string }> = [];
  const seen = new Set<string>();
  for (const m of html.matchAll(/(?:href|action)\s*=\s*["']([^"']*\?[^"']+)["']/gi)) {
    let abs: URL;
    try { abs = new URL(m[1].replace(/&amp;/g, '&'), `${cachedOriginUrl(host)}/`); } catch { continue; }
    if (abs.hostname.toLowerCase() !== host.toLowerCase()) continue; // yalnız same-origin uçları prob et
    for (const [param] of abs.searchParams) {
      if (!REDIRECT_PARAM_RE.test(param)) continue;
      const dedup = `${abs.pathname}|${param.toLowerCase()}`;
      if (seen.has(dedup)) continue;
      seen.add(dedup);
      const probe = new URL(abs.toString());
      probe.searchParams.set(param, PROBE_TARGET);
      out.push({ url: probe.toString(), path: abs.pathname, param });
    }
  }
  return out;
}
