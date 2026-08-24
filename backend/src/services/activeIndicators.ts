/**
 * (Aktif Doğrulama Faz 6 + Tam Kapsamlı Faz 8) GÜVENLİ AKTİF GÖSTERGELER.
 * session YOKSA → login'siz (Aktif Doğrulama). session VARSA → AUTHENTICATED (Tam Kapsamlı, login sonrası
 * yüzey + Faz 7 SPA-keşif + auth-kapılı uçlar). Aynı 6 gösterge; hepsi READ-ONLY / non-destructive.
 * Kırmızı çizgiler (Faz 6 ile birebir): veri yazma/yükleme/komut/time-based/state YOK; gerçek istismar YOK.
 * PROVENANCE (Sütun 0): yalnız hedefte GERÇEKTEN gözlenen (discoverSurface, login-sonrası) GET param;
 * uydurma yok. LFI yalnız imza (içerik REDAKTE); SSTI yalnız aritmetik; HPP salt gözlem.
 *
 *   A1/B1 LFI · A2/B2 Open redirect · A3/B3 HPP · A5/B5 SSTI
 *   A4/B4 boolean-SQLi → Enjeksiyon (SQLi/XSS) bölümünde (çapraz-ref, çift-CT yok)
 *   A6/B6 dosya yükleme → login'siz: Dosya Yükleme Doğrulama'ya çapraz-ref; authenticated: gözlem notu
 */
import { discoverSurface, type InputPoint } from './activeVerifyEvidence.js';
import type { ActiveCheckEvidence, VFinding } from './activeVerifyEvidence.js';
import { applyAuthHeaders, type AuthSession } from './authSession.js';
import { logScanStep } from './scanLogger.js';

const REQ_TIMEOUT = 10_000;
const MIN_DELAY = 200;
let lastAt = 0;

type Resp = { status: number; text: string; len: number; headers: Headers };
async function get(url: string, label: string, headers: Record<string, string> = {}): Promise<Resp | null> {
  const w = MIN_DELAY - (Date.now() - lastAt); if (w > 0) await new Promise((r) => setTimeout(r, w));
  lastAt = Date.now();
  const ctrl = new AbortController(); const t = setTimeout(() => ctrl.abort(), REQ_TIMEOUT); const t0 = Date.now();
  try {
    const res = await fetch(url, { redirect: 'manual', signal: ctrl.signal, headers: { 'user-agent': 'CyberTestify-ActiveIndicator/1.0', accept: 'text/html,application/json,*/*', ...headers } });
    const buf = Buffer.from(await res.arrayBuffer());
    const text = buf.subarray(0, 200_000).toString('utf-8');
    logScanStep({ step: 'Güvenli Aktif Göstergeler', method: 'GET', url, status: res.status, durationMs: Date.now() - t0, sizeBytes: buf.length });
    return { status: res.status, text, len: buf.length, headers: res.headers };
  } catch { logScanStep({ step: 'Güvenli Aktif Göstergeler', method: 'GET', url, status: 0, level: 'warn', durationMs: Date.now() - t0 }); return null; }
  finally { clearTimeout(t); }
}

function buildUrl(ip: InputPoint, value: string): string {
  const u = new URL(ip.action);
  for (const [k, v] of Object.entries(ip.params)) u.searchParams.set(k, k === ip.param ? value : (v || '1'));
  return u.toString();
}
function buildUrlDup(ip: InputPoint, values: string[]): string {
  const u = new URL(ip.action);
  for (const [k, v] of Object.entries(ip.params)) if (k !== ip.param) u.searchParams.set(k, v || '1');
  for (const val of values) u.searchParams.append(ip.param, val);
  return u.toString();
}
const short = (s: string) => (s.length > 60 ? s.slice(0, 60) + '…' : s);
const epLabel = (ip: InputPoint) => { try { return `${new URL(ip.action).pathname}?${ip.param}=`; } catch { return `${ip.action}?${ip.param}=`; } };

const FILE_PARAM_RE = /^(file|page|doc|document|include|inc|path|tmpl|template|view|load|read|download|dir|folder|filename|filepath|src|f)$/i;
const REDIRECT_PARAM_RE = /^(url|next|redirect|redirect_uri|redir|return|returnurl|return_to|dest|destination|continue|to|goto|target|forward|out|link|u)$/i;
const LFI_SIGN_RE = /root:x:0:0:|\[fonts\]\s*[\r\n]|\[extensions\]\s*[\r\n]|for 16-bit app support|<\?php[\s\S]{0,60}(include|require|\$_(GET|POST|REQUEST|SERVER))/i;
const CANARY = 'https://cybertestify-redirect-probe.example/ct';
const FILE_PAYLOADS_SHALLOW = ['../../etc/passwd', '..\\..\\windows\\win.ini'];
const FILE_PAYLOADS_DEEP = ['../../../../../../../../etc/passwd', '..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd', '....//....//....//....//....//etc/passwd', '..\\..\\..\\..\\..\\..\\..\\windows\\win.ini', '/etc/passwd'];

export async function collectActiveIndicatorsEvidence(host: string, session?: AuthSession, de: boolean = false): Promise<ActiveCheckEvidence> {
  const t = (trS: string, deS: string) => (de ? deS : trS);
  const findings: VFinding[] = []; const notes: string[] = [];
  const authed = !!session;
  const H: Record<string, string> = session ? (applyAuthHeaders({}, session) as Record<string, string>) : {};
  const surf = await discoverSurface(host, session).catch(() => null);
  if (!surf || !surf.ok) return { ok: true, pagesScanned: 0, inputsFound: 0, probesSent: 1, findings, stopped: null, notes: [t('Hedef yüzeyi keşfedilemedi — güvenli aktif göstergeler bu hedef için **kapsam dışıdır**.', 'Die Zieloberfläche konnte nicht erkundet werden — die sicheren aktiven Indikatoren sind für dieses Ziel **außerhalb des Geltungsbereichs**.')] };
  const getParams = surf.inputs.filter((ip) => ip.method === 'GET' && ip.source === 'url');
  const inputsFound = getParams.length + surf.uploadForms.length;
  let probes = 0;

  if (getParams.length === 0 && surf.uploadForms.length === 0) {
    return { ok: true, pagesScanned: surf.pagesScanned, inputsFound: 0, probesSent: 1, findings, stopped: null,
      notes: [`${authed ? t('Login-sonrası', 'Nach dem Login') : t('Gözlemlenebilir', 'Beobachtbare')}${t(' enjekte-edilebilir bir yüzey (GET parametresi / yükleme formu) bu hedefte bulunamadı — güvenli aktif göstergeler **kapsam dışıdır** (iyi-yapılandırılmış/SPA sitelerde beklenen sonuç).', ' injizierbare Oberfläche (GET-Parameter / Upload-Formular) wurde bei diesem Ziel nicht gefunden — die sicheren aktiven Indikatoren sind **außerhalb des Geltungsbereichs** (bei gut konfigurierten/SPA-Websites das erwartete Ergebnis).')}`] };
  }

  // ── A1/B1 LFI (kademeli; yalnız imza = bulgu) ──
  const lfiSeen = new Set<string>();
  for (const ip of getParams.filter((p) => FILE_PARAM_RE.test(p.param)).slice(0, 6)) {
    if (lfiSeen.has(ip.param)) continue; lfiSeen.add(ip.param);
    const base = await get(buildUrl(ip, ip.params[ip.param] || 'index'), `LFI base ${ip.param}`, H); probes++;
    let hit = false; let signal = false;
    for (const p of FILE_PAYLOADS_SHALLOW) {
      const r = await get(buildUrl(ip, p), `LFI shallow ${ip.param}`, H); probes++;
      if (!r) continue;
      if (LFI_SIGN_RE.test(r.text)) { hit = true; break; }
      if (base && (r.status !== base.status || Math.abs(r.len - base.len) > Math.max(40, base.len * 0.05))) signal = true;
    }
    if (!hit && signal) {
      for (const p of FILE_PAYLOADS_DEEP) {
        const r = await get(buildUrl(ip, p), `LFI deep ${ip.param}`, H); probes++;
        if (r && LFI_SIGN_RE.test(r.text)) { hit = true; break; }
      }
    }
    if (hit) findings.push({ check: 'lfi', inputPoint: epLabel(ip), vulnerable: true, technique: `${t('yol geçişi / LFI (path traversal) — kademeli güvenli prob', 'Pfad-Traversierung / LFI (path traversal) — gestufter sicherer Prob')}${authed ? ' (authenticated)' : ''}`, evidence: t(`\`${ip.param}\` parametresine yol-geçişi payload'ı gönderildiğinde yanıtta **bilinen sistem dosyası imzası** (ör. \`root:x:0:0:\` / \`[fonts]\`) gözlendi — sunucu dosya sistemine LFI/path-traversal göstergesi. Dosya içeriği **REDAKTE** (çekilmedi/saklanmadı). Girdi dosya yoluna konmamalı; allowlist + kök-dizin hapsi uygulanmalı.`, `Als an den Parameter \`${ip.param}\` ein Path-Traversal-Payload gesendet wurde, wurde in der Antwort eine **bekannte Systemdatei-Signatur** (z. B. \`root:x:0:0:\` / \`[fonts]\`) beobachtet — Indikator für LFI/Path-Traversal auf dem Server-Dateisystem. Der Dateiinhalt ist **REDIGIERT** (nicht abgerufen/gespeichert). Eingaben sollten nicht in einen Dateipfad übernommen werden; eine Allowlist + Einsperrung im Wurzelverzeichnis sollten angewendet werden.`), confidence: 'high', severity: 'high', sideEffectRisk: 'none' });
  }

  // ── A2/B2 Open redirect (kanarya; redirect TAKİP EDİLMEZ) ──
  const orSeen = new Set<string>();
  for (const ip of getParams.filter((p) => REDIRECT_PARAM_RE.test(p.param)).slice(0, 8)) {
    if (orSeen.has(ip.param)) continue; orSeen.add(ip.param);
    const r = await get(buildUrl(ip, CANARY), `open-redirect ${ip.param}`, H); probes++;
    if (!r) continue;
    const loc = r.headers.get('location') ?? '';
    const metaRefresh = /<meta[^>]+http-equiv=["']?refresh["']?[^>]+url=([^"'>\s]+)/i.exec(r.text)?.[1] ?? '';
    const reflectsCanary = (s: string) => /cybertestify-redirect-probe\.example/i.test(s);
    if ((r.status >= 300 && r.status < 400 && reflectsCanary(loc)) || reflectsCanary(metaRefresh)) {
      findings.push({ check: 'open_redirect', inputPoint: epLabel(ip), vulnerable: true, technique: `${t('açık yönlendirme (open redirect) — zararsız kanarya gözlemi (redirect TAKİP EDİLMEDİ)', 'Offene Weiterleitung (open redirect) — harmlose Kanarienvogel-Beobachtung (Weiterleitung NICHT gefolgt)')}${authed ? ' (authenticated)' : ''}`, evidence: t(`\`${ip.param}\` parametresine verilen **harici kanarya** URL'i yanıtın \`Location\`/meta-refresh hedefine **yansıdı** — açık yönlendirme göstergesi (phishing/oturum-token sızıntısı yüzeyi). Yönlendirme hedefleri sunucuda allowlist ile sınırlanmalı. Yönlendirme TAKİP EDİLMEDİ.`, `Die dem Parameter \`${ip.param}\` übergebene **externe Kanarienvogel**-URL wurde im \`Location\`-/meta-refresh-Ziel der Antwort **widergespiegelt** — Indikator für eine offene Weiterleitung (Angriffsfläche für Phishing/Sitzungs-Token-Leck). Weiterleitungsziele sollten serverseitig per Allowlist eingeschränkt werden. Der Weiterleitung wurde NICHT gefolgt.`), confidence: 'high', severity: 'medium', sideEffectRisk: 'none' });
    }
  }

  // ── A3/B3 HPP (gözlemsel; yalnız net concat) ──
  const hppSeen = new Set<string>();
  for (const ip of getParams.slice(0, 6)) {
    if (hppSeen.has(ip.param)) continue; hppSeen.add(ip.param);
    const single = await get(buildUrl(ip, 'CTPPA'), `HPP single ${ip.param}`, H); probes++;
    const dbl = await get(buildUrlDup(ip, ['CTPPA', 'CTPPB']), `HPP dup ${ip.param}`, H); probes++;
    if (!single || !dbl) continue;
    const both = /CTPPA\s*[,;| ]?\s*CTPPB|CTPPACTPPB/.test(dbl.text);
    const onlyB = dbl.text.includes('CTPPB') && !dbl.text.includes('CTPPA') && single.text.includes('CTPPA');
    if (both) findings.push({ check: 'hpp', inputPoint: epLabel(ip), vulnerable: true, technique: `${t('HTTP parametre kirliliği (HPP) — tekrarlı parametre işleniş gözlemi (veri gönderilmedi)', 'HTTP-Parameter-Pollution (HPP) — Beobachtung der Verarbeitung wiederholter Parameter (keine Daten gesendet)')}${authed ? ' (authenticated)' : ''}`, evidence: t(`\`${ip.param}\` iki kez gönderildiğinde (\`?${ip.param}=A&${ip.param}=B\`) sunucu **her iki değeri birleştirerek** işledi — HTTP Parameter Pollution göstergesi (filtre atlatma/mantık sapması yüzeyi). Parametreler tek-değere normalize edilmeli. Salt gözlem.`, `Als \`${ip.param}\` zweimal gesendet wurde (\`?${ip.param}=A&${ip.param}=B\`), verarbeitete der Server **beide Werte zusammengefügt** — Indikator für HTTP Parameter Pollution (Angriffsfläche für Filterumgehung/Logikabweichung). Parameter sollten auf einen einzigen Wert normalisiert werden. Reine Beobachtung.`), confidence: 'medium', severity: 'low', sideEffectRisk: 'none' });
    else if (onlyB) notes.push(t(`HPP: \`${ip.param}\` tekrarında son-değer (last-wins) ayrıştırma gözlendi — tek başına zafiyet değil, bilgilendirici.`, `HPP: Bei der Wiederholung von \`${ip.param}\` wurde eine Last-Wins-Verarbeitung (letzter Wert) beobachtet — allein keine Schwachstelle, informativ.`));
  }

  // ── A5/B5 SSTI (yalnız aritmetik) ──
  const SSTI_PROBES: Array<[string, string]> = [['{{1234*3}}', '3702'], ['${1234*3}', '3702'], ['#{1234*3}', '3702']];
  const sstiSeen = new Set<string>();
  for (const ip of getParams.slice(0, 6)) {
    if (sstiSeen.has(ip.param)) continue; sstiSeen.add(ip.param);
    const mark = 'CTSSTI' + (ip.param.length) + 'Z';
    const refl = await get(buildUrl(ip, mark), `SSTI reflect ${ip.param}`, H); probes++;
    if (!refl || !refl.text.includes(mark)) continue;
    let done = false;
    for (const [payload, expect] of SSTI_PROBES) {
      if (done) break;
      const r = await get(buildUrl(ip, payload), `SSTI ${ip.param}`, H); probes++;
      if (r && r.text.includes(expect) && !r.text.includes(payload)) {
        findings.push({ check: 'ssti', inputPoint: epLabel(ip), vulnerable: true, technique: `${t('şablon enjeksiyonu (SSTI) — yalnız aritmetik gösterge (kod/komut YOK)', 'Template-Injection (SSTI) — nur arithmetischer Indikator (KEIN Code/Befehl)')}${authed ? ' (authenticated)' : ''}`, evidence: t(`\`${ip.param}\` parametresine yalnız aritmetik ifade (\`${short(payload)}\`) gönderildiğinde çıktıda **değerlendirilmiş sonuç** (\`${expect}\`) belirdi (ifade ham geçmedi) — sunucu-taraflı şablon enjeksiyonu (SSTI) göstergesi. Yalnız aritmetik denendi; kod/komut çalıştırılmadı. Girdi şablona interpolasyonla konmamalı.`, `Als an den Parameter \`${ip.param}\` nur ein arithmetischer Ausdruck (\`${short(payload)}\`) gesendet wurde, erschien in der Ausgabe das **ausgewertete Ergebnis** (\`${expect}\`) (der Ausdruck wurde nicht roh durchgereicht) — Indikator für serverseitige Template-Injection (SSTI). Es wurde nur Arithmetik versucht; es wurde kein Code/Befehl ausgeführt. Eingaben sollten nicht per Interpolation in das Template übernommen werden.`), confidence: 'high', severity: 'medium', sideEffectRisk: 'none' });
        done = true;
      }
    }
  }

  // ── A4/B4 boolean-SQLi + A6/B6 upload → çapraz-referans / gözlem ──
  notes.push(`${t('Boolean-tabanlı SQL Enjeksiyonu **', 'Boolean-basierte SQL-Injection wird im Abschnitt **')}${authed ? t('Authenticated Enjeksiyon (SQLi/XSS)', 'Authentifizierte Injektion (SQLi/XSS)') : t('Enjeksiyon (SQLi/XSS) Doğrulama', 'Injektion (SQLi/XSS)-Verifizierung')}${t('** bölümünde katı yanlış-pozitif kalkanıyla değerlendirilir (burada tekrar edilmez).', '** mit einem strengen Falsch-Positiv-Schutz bewertet (hier nicht wiederholt).')}`);
  if (surf.uploadForms.length) {
    notes.push(authed
      ? t(`Login-sonrası **${surf.uploadForms.length}** dosya yükleme noktası gözlendi; **gerçek dosya YÜKLENMEDİ** (konfig gözlemi — güvenli). Sunucu-taraflı tip/boyut doğrulaması manuel test gerektirir.`, `Nach dem Login wurden **${surf.uploadForms.length}** Datei-Upload-Punkte beobachtet; **es wurde KEINE echte Datei hochgeladen** (Konfigurationsbeobachtung — sicher). Die serverseitige Typ-/Größenvalidierung erfordert einen manuellen Test.`)
      : t(`Dosya yükleme yüzeyi (**${surf.uploadForms.length}** form) **Dosya Yükleme Doğrulama** bölümünde değerlendirilir (gerçek dosya yüklenmeden).`, `Die Datei-Upload-Oberfläche (**${surf.uploadForms.length}** Formular(e)) wird im Abschnitt **Datei-Upload-Verifizierung** bewertet (ohne dass eine echte Datei hochgeladen wird).`));
  }

  notes.push(`${t('Denenen: **', 'Durchgeführt: **')}${probes}${t('** güvenli read-only prob', '** sichere schreibgeschützte Probes')}${authed ? t(' (login-sonrası oturumla)', ' (mit der Sitzung nach dem Login)') : ''}${t(' (yalnız GET; yükleme/komut/time-based YOK). LFI yalnız imza — içerik REDAKTE; open-redirect kanaryası TAKİP EDİLMEDİ; SSTI yalnız aritmetik; HPP salt gözlem. Test edilen GET parametresi: **', ' (nur GET; kein Upload/Befehl/time-based). LFI nur Signatur — Inhalt REDIGIERT; der Open-Redirect-Kanarienvogel wurde NICHT verfolgt; SSTI nur Arithmetik; HPP reine Beobachtung. Getestete GET-Parameter: **')}${getParams.length}**${authed ? t(' (Faz 7 SPA-keşif + auth-kapılı uçlar dâhil)', ' (inkl. Phase-7-SPA-Erkundung + auth-geschützte Endpunkte)') : ''}.`);
  return { ok: true, pagesScanned: surf.pagesScanned, inputsFound, probesSent: probes, findings, stopped: null, notes };
}
