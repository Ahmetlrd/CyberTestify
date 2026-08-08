/**
 * (Dış Yüzey & Yapılandırma) ORTAK KOD-TABANLI KANIT TOPLAMA — ajana GUVENMEZ.
 *
 * bundle_surface uyeleri (ssl_tls, header_leak, dns_email, cors_cookie, csp_analiz) icin
 * veriyi BACKEND KENDISI toplar (basit_tarama ile ayni kanitlanmis yaklasim): HTTP guvenlik
 * basliklari + Set-Cookie + CSP + CORS (Origin ile probe) + TLS sertifikasi/protokol/cipher +
 * DNS/e-posta (SPF/DKIM/DMARC/DNSSEC — Cloudflare DoH ile) + acikta kalan hassas dosyalar.
 * Rapor metnini KOD yazar; ajan ciktisina hic bakilmaz -> formattan bagimsiz, her zaman tutarli.
 *
 * Her kontrol ASLA throw ETMEZ (izole); ulasilamayan veri "tespit edilemedi" olur.
 */
import tls from 'node:tls';
import { classifyExposedFile } from './passiveExtras.js';

const HTTP_TIMEOUT_MS = 9000;
const TLS_TIMEOUT_MS = 8000;
const DOH_TIMEOUT_MS = 8000;
const MAX_HTML = 1_500_000;

// Kayitli/apex alan adi — cok-parcali TLS'ler icin sade heuristik (co.uk vb. kabaca desteklenir).
const TWO_LEVEL_TLDS = new Set(['co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'com.tr', 'org.tr', 'net.tr', 'gov.tr', 'com.au', 'co.nz', 'co.jp']);
export function apexDomain(host: string): string {
  const p = host.toLowerCase().replace(/\.$/, '').split('.');
  if (p.length <= 2) return p.join('.');
  const lastTwo = p.slice(-2).join('.');
  if (TWO_LEVEL_TLDS.has(lastTwo)) return p.slice(-3).join('.');
  return lastTwo;
}

// ---- HTTP: basliklar + Set-Cookie + HTML ------------------------------------------
export type HttpEvidence = {
  ok: boolean;
  status?: number;
  headers: Map<string, string>; // lowercased
  setCookies: string[];         // ham Set-Cookie satirlari
  html: string;
  contentType: string;
};

export async function collectHttp(host: string): Promise<HttpEvidence> {
  const headers = new Map<string, string>();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), HTTP_TIMEOUT_MS);
  try {
    const res = await fetch(`https://${host}/`, {
      signal: ctrl.signal,
      redirect: 'follow',
      headers: { 'user-agent': 'CyberTestify-PassiveCheck/1.0', accept: 'text/html,*/*' },
    });
    res.headers.forEach((v, k) => headers.set(k.toLowerCase(), v));
    let setCookies: string[] = [];
    try {
      const gsc = (res.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie;
      if (typeof gsc === 'function') setCookies = gsc.call(res.headers);
      else if (headers.has('set-cookie')) setCookies = [headers.get('set-cookie')!];
    } catch { /* yoksa bos */ }
    let html = '';
    try {
      const buf = Buffer.from(await res.arrayBuffer());
      html = (buf.length > MAX_HTML ? buf.subarray(0, MAX_HTML) : buf).toString('utf-8');
    } catch { /* govde okunamadi */ }
    return { ok: true, status: res.status, headers, setCookies, html, contentType: headers.get('content-type') ?? '' };
  } catch {
    return { ok: false, headers, setCookies: [], html: '', contentType: '' };
  } finally {
    clearTimeout(timer);
  }
}

// ---- CORS: Origin ile probe -------------------------------------------------------
export type CorsEvidence = { ok: boolean; testedOrigin: string; acao?: string; acac?: string; reflected: boolean; wildcard: boolean };
const CORS_PROBE_ORIGIN = 'https://cybertestify-cors-probe.example';

export async function collectCors(host: string): Promise<CorsEvidence> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), HTTP_TIMEOUT_MS);
  try {
    const res = await fetch(`https://${host}/`, {
      signal: ctrl.signal,
      redirect: 'manual',
      headers: { 'user-agent': 'CyberTestify-PassiveCheck/1.0', origin: CORS_PROBE_ORIGIN },
    });
    const acao = res.headers.get('access-control-allow-origin') ?? undefined;
    const acac = res.headers.get('access-control-allow-credentials') ?? undefined;
    return {
      ok: true,
      testedOrigin: CORS_PROBE_ORIGIN,
      acao,
      acac,
      reflected: acao === CORS_PROBE_ORIGIN,
      wildcard: acao === '*',
    };
  } catch {
    return { ok: false, testedOrigin: CORS_PROBE_ORIGIN, reflected: false, wildcard: false };
  } finally {
    clearTimeout(timer);
  }
}

// ---- TLS: sertifika + protokol + cipher + zayif surum tespiti ----------------------
export type TlsEvidence = {
  found: boolean;
  cn?: string;
  san: string[];
  issuer?: string;
  notAfter?: string;
  daysLeft?: number;
  protocol?: string;
  cipher?: string;
  hostnameMatch?: boolean;
  weakProtocols: string[]; // desteklenen eski surumler (TLSv1, TLSv1.1)
};

function hostMatches(host: string, cn: string | undefined, san: string[]): boolean {
  const names = [cn, ...san].filter(Boolean) as string[];
  const h = host.toLowerCase();
  return names.some((n) => {
    const name = n.toLowerCase().trim();
    if (name === h) return true;
    if (name.startsWith('*.')) {
      const base = name.slice(2);
      const hp = h.split('.');
      return hp.length >= 2 && hp.slice(1).join('.') === base;
    }
    return false;
  });
}

function tlsHandshake(host: string, opts: tls.ConnectionOptions): Promise<tls.TLSSocket | null> {
  return new Promise((resolve) => {
    let done = false;
    const d = (v: tls.TLSSocket | null) => { if (!done) { done = true; resolve(v); } };
    try {
      const s = tls.connect({ host, port: 443, servername: host, rejectUnauthorized: false, timeout: TLS_TIMEOUT_MS, ...opts }, () => d(s));
      s.on('error', () => d(null));
      s.on('timeout', () => { s.destroy(); d(null); });
    } catch { d(null); }
  });
}

async function probeVersion(host: string, version: 'TLSv1' | 'TLSv1.1'): Promise<boolean> {
  try {
    const s = await tlsHandshake(host, { minVersion: version, maxVersion: version });
    if (s) { s.end(); return true; }
    return false;
  } catch {
    return false; // surum yerelde devre disi ise "desteklenmiyor/bilinmiyor" -> weak sayma
  }
}

export async function collectTls(host: string): Promise<TlsEvidence> {
  const s = await tlsHandshake(host, {});
  if (!s) return { found: false, san: [], weakProtocols: [] };
  const cert = s.getPeerCertificate();
  const protocol = s.getProtocol() ?? undefined;
  const cipher = s.getCipher()?.name;
  const cn = (cert?.subject as { CN?: string } | undefined)?.CN;
  const san = (cert?.subjectaltname ?? '').split(',').map((x) => x.trim().replace(/^DNS:/i, '')).filter(Boolean);
  const iss = cert?.issuer as { O?: string; CN?: string } | undefined;
  const issuer = [iss?.O, iss?.CN].filter(Boolean).join(' — ') || undefined;
  const notAfter = cert?.valid_to;
  let daysLeft: number | undefined;
  if (notAfter) {
    const exp = new Date(notAfter);
    if (!isNaN(exp.getTime())) daysLeft = Math.round((exp.getTime() - Date.now()) / 86400000);
  }
  const hostnameMatch = cn || san.length ? hostMatches(host, cn, san) : undefined;
  s.end();
  // Zayif surum probe'lari (paralel).
  const [v10, v11] = await Promise.all([probeVersion(host, 'TLSv1'), probeVersion(host, 'TLSv1.1')]);
  const weakProtocols = [v10 ? 'TLS 1.0' : '', v11 ? 'TLS 1.1' : ''].filter(Boolean);
  return { found: !!(cn || notAfter), cn, san, issuer, notAfter, daysLeft, protocol, cipher, hostnameMatch, weakProtocols };
}

// ---- DNS / e-posta: Cloudflare DoH -------------------------------------------------
export type DnsEvidence = {
  ok: boolean;
  spf?: { record: string; all: '-all' | '~all' | '+all' | '?all' | 'yok' };
  dmarc?: { record: string; policy: 'none' | 'quarantine' | 'reject' | 'yok' };
  dkim?: { found: boolean; selector?: string };
  dnssec?: boolean;
  mxCount: number;
};

async function doh(name: string, type: string): Promise<{ answers: string[]; ad: boolean } | null> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), DOH_TIMEOUT_MS);
  try {
    const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`, {
      signal: ctrl.signal,
      headers: { accept: 'application/dns-json' },
    });
    if (!res.ok) return null;
    const j = (await res.json()) as { AD?: boolean; Answer?: Array<{ data?: string }> };
    const answers = (j.Answer ?? []).map((a) => String(a.data ?? '').replace(/^"|"$/g, '').replace(/"\s+"/g, ''));
    return { answers, ad: !!j.AD };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

const DKIM_SELECTORS = ['default', 'google', 'selector1', 'selector2', 'k1', 'mail', 's1', 'dkim'];

export async function collectDns(host: string): Promise<DnsEvidence> {
  const apex = apexDomain(host);
  const [txt, dmarcTxt, dnskey, mx] = await Promise.all([
    doh(apex, 'TXT'),
    doh(`_dmarc.${apex}`, 'TXT'),
    doh(apex, 'DNSKEY'),
    doh(apex, 'MX'),
  ]);
  if (!txt && !dmarcTxt && !dnskey && !mx) return { ok: false, mxCount: 0 };

  // SPF
  let spf: DnsEvidence['spf'];
  const spfRec = (txt?.answers ?? []).find((a) => /^v=spf1/i.test(a.trim()));
  if (spfRec) {
    const all = /[-]all/i.test(spfRec) ? '-all' : /~all/i.test(spfRec) ? '~all' : /\+all/i.test(spfRec) ? '+all' : /\?all/i.test(spfRec) ? '?all' : 'yok';
    spf = { record: spfRec.trim().slice(0, 300), all };
  } else {
    spf = { record: '', all: 'yok' };
  }

  // DMARC
  let dmarc: DnsEvidence['dmarc'];
  const dmarcRec = (dmarcTxt?.answers ?? []).find((a) => /v=DMARC1/i.test(a));
  if (dmarcRec) {
    const p = dmarcRec.match(/\bp\s*=\s*(none|quarantine|reject)/i)?.[1]?.toLowerCase() as 'none' | 'quarantine' | 'reject' | undefined;
    dmarc = { record: dmarcRec.trim().slice(0, 300), policy: p ?? 'none' };
  } else {
    dmarc = { record: '', policy: 'yok' };
  }

  // DKIM (yaygin selector'lari dene)
  let dkim: DnsEvidence['dkim'] = { found: false };
  for (const sel of DKIM_SELECTORS) {
    const r = await doh(`${sel}._domainkey.${apex}`, 'TXT');
    if (r && r.answers.some((a) => /v=DKIM1|(^|;)\s*p\s*=/i.test(a))) { dkim = { found: true, selector: sel }; break; }
  }

  // DNSSEC: DNSKEY kaydi VEYA herhangi bir cevabin AD (authenticated data) bayragi
  const dnssec = !!(dnskey?.answers.length) || !!txt?.ad || !!dmarcTxt?.ad || !!dnskey?.ad;

  const mxCount = (mx?.answers ?? []).length;
  return { ok: true, spf, dmarc, dkim, dnssec, mxCount };
}

// ---- Acikta kalan hassas dosyalar (header_leak) -----------------------------------
export type ExposedFileResult = { path: string; exposed: boolean; reason: string };
const EXPOSED_CANDIDATES = ['/.git/config', '/.env', '/.git/HEAD', '/backup.zip', '/.DS_Store', '/wp-config.php.bak'];

async function safeGetForExpose(url: string): Promise<{ ok: boolean; status: number; text: string; contentType: string }> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), HTTP_TIMEOUT_MS);
  try {
    const res = await fetch(url, { signal: ctrl.signal, redirect: 'follow', headers: { 'user-agent': 'CyberTestify-PassiveCheck/1.0' } });
    const buf = Buffer.from(await res.arrayBuffer());
    const text = (buf.length > 20000 ? buf.subarray(0, 20000) : buf).toString('utf-8');
    return { ok: res.ok, status: res.status, text, contentType: res.headers.get('content-type') ?? '' };
  } catch {
    return { ok: false, status: 0, text: '', contentType: '' };
  } finally {
    clearTimeout(timer);
  }
}

export async function collectExposedFiles(host: string, homepageHtml: string): Promise<ExposedFileResult[]> {
  const out: ExposedFileResult[] = [];
  for (const path of EXPOSED_CANDIDATES) {
    const fetched = await safeGetForExpose(`https://${host}${path}`);
    const { verdict, reason } = classifyExposedFile(path, fetched, homepageHtml);
    out.push({ path, exposed: verdict === 'exposed', reason });
  }
  return out;
}
