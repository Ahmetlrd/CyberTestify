/**
 * (Tam Kapsamlı Pentest — Faz 3-C) E-POSTA & DNS DERİNLİĞİ (anti-spoofing + DNS bütünlüğü).
 * 7 kontrol; hepsi PASİF DNS/TXT sorgusu + TEK güvenli HTTPS GET (MTA-STS politika dosyası).
 * SIFIR saldırı, SIFIR state değişimi, %100 deterministik.
 *
 * SÜTUN 0 — provenance: Kayıtlar hedefin GERÇEK org-alanından okunur. Alt-alan (test.cybertestify.com)
 * için DMARC ORGANİZASYONEL ALAN (cybertestify.com) seviyesinde değerlendirilir (DMARC org-domain +
 * sp= alt-alan kuralı). Yalnız DNS'in GERÇEKTEN döndürdüğü kayıt bulgu olur — uydurma/tahmin YOK.
 * "YOK" da bulgudur ama dürüst: e-posta göndermeyen alanda eksik DMARC/SPF şişirilmez (MX nüansı).
 *
 * NOT: Diğer 5 paketteki TEMEL SPF/DKIM/DMARC-varlık kontrolüne DOKUNULMAZ — bu modül yalnız 6. pakete
 * DERİNLİK katar (politika-gücü, DKIM seçici keşfi, MTA-STS, TLS-RPT, DNSSEC, SPF-arama, CAA/BIMI).
 */
import { promises as dns } from 'node:dns';
import dgram from 'node:dgram';
import { logScanStep } from './scanLogger.js';
import type { ActiveCheckEvidence, VFinding } from './activeVerifyEvidence.js';

// ---- Kayıt-edilebilir (org) alan: DMARC org-domain kuralı için ----
const MULTI_SUFFIX = new Set(['co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'com.tr', 'org.tr', 'net.tr', 'gov.tr', 'edu.tr', 'k12.tr', 'com.au', 'com.br', 'co.jp', 'co.nz', 'co.za', 'com.mx']);
export function getOrgDomain(host: string): string {
  const labels = host.split('.').filter(Boolean);
  if (labels.length <= 2) return labels.join('.');
  const last2 = labels.slice(-2).join('.');
  if (MULTI_SUFFIX.has(last2)) return labels.slice(-3).join('.');
  return last2;
}

async function txt(name: string): Promise<string[]> {
  try { const r = await dns.resolveTxt(name); return r.map((chunks) => chunks.join('')); }
  catch { return []; }
}
async function hasMx(name: string): Promise<boolean> {
  try { const r = await dns.resolveMx(name); return r.length > 0; } catch { return false; }
}

// ---- DNSSEC: doğrulayan çözümleyiciye (1.1.1.1) DNSKEY sorgusu + AD bayrağı (yalnız gözlem) ----
export async function queryDnssec(name: string): Promise<{ ok: boolean; ad: boolean; answers: number }> {
  return new Promise((resolve) => {
    const sock = dgram.createSocket('udp4');
    let settled = false;
    const finish = (v: { ok: boolean; ad: boolean; answers: number }) => { if (settled) return; settled = true; try { sock.close(); } catch {} resolve(v); };
    // Header: RD set (0x0120). EDNS0 OPT (DO bit) additional -> ARCOUNT=1.
    const header = Buffer.from([0x27, 0x11, 0x01, 0x20, 0, 1, 0, 0, 0, 0, 0, 1]);
    const q: number[] = [];
    for (const label of name.split('.').filter(Boolean)) { q.push(label.length); for (const ch of Buffer.from(label)) q.push(ch); }
    q.push(0); q.push(0, 48); q.push(0, 1); // QTYPE=DNSKEY(48) QCLASS=IN
    // OPT: name=root(0), type=41, class=4096(udp), ttl=0x00008000(DO=1), rdlen=0
    const opt = [0, 0, 41, 0x10, 0x00, 0x00, 0x00, 0x80, 0x00, 0, 0];
    const msg = Buffer.concat([header, Buffer.from(q), Buffer.from(opt)]);
    sock.on('message', (m) => {
      const rcode = m[3] & 0x0f; const ad = (m[3] & 0x20) !== 0; const ancount = (m[6] << 8) | m[7];
      finish({ ok: rcode === 0, ad, answers: ancount });
    });
    sock.on('error', () => finish({ ok: false, ad: false, answers: 0 }));
    sock.send(msg, 53, '1.1.1.1');
    setTimeout(() => finish({ ok: false, ad: false, answers: 0 }), 4000);
  });
}

// ---- DMARC ayrıştırma ----
export function parseDmarc(record: string): { p?: string; sp?: string; pct?: number; adkim?: string; aspf?: string; hasRua: boolean } {
  const kv: Record<string, string> = {};
  for (const part of record.split(';')) { const [k, v] = part.split('='); if (k && v !== undefined) kv[k.trim().toLowerCase()] = v.trim(); }
  return { p: kv.p, sp: kv.sp, pct: kv.pct ? parseInt(kv.pct, 10) : undefined, adkim: kv.adkim, aspf: kv.aspf, hasRua: !!kv.rua };
}
// ---- SPF: all-mekanizması + üst-seviye DNS-arama sayısı ----
export function parseSpf(record: string): { all?: '-' | '~' | '?' | '+'; lookups: number } {
  let all: '-' | '~' | '?' | '+' | undefined;
  const m = record.match(/([-~?+])all\b/i); if (m) all = m[1] as any;
  // Token-bazlı say: her DNS-arama mekanizması (include/redirect/a/mx/ptr/exists) bir kez.
  let lookups = 0;
  for (const tok of record.split(/\s+/)) {
    if (/^[+\-~?]?(include:|redirect=|exists:|ptr\b|a$|a:|mx$|mx:)/i.test(tok)) lookups++;
  }
  return { all, lookups };
}

const DKIM_SELECTORS = ['default', 'google', 'selector1', 'selector2', 'k1', 'mail', 'dkim', 's1', 's2', 'mandrill', 'mxvault'];

export async function collectEmailDnsEvidence(host: string): Promise<ActiveCheckEvidence> {
  const findings: VFinding[] = []; const notes: string[] = [];
  const org = getOrgDomain(host);
  let queries = 0;
  const push = (f: Partial<VFinding> & { check: string; evidence: string; severity: VFinding['severity'] }) =>
    findings.push({ inputPoint: org, vulnerable: true, technique: 'pasif DNS/TXT gözlemi', confidence: 'high', sideEffectRisk: 'none', ...f } as VFinding);

  const mail = await hasMx(org); queries++;
  const mailNuance = mail ? '' : ' (bu alanda MX yok — e-posta göndermeyen alan olabilir; şiddet gösterge düzeyinde)';
  const dl = (base: VFinding['severity']): VFinding['severity'] => (mail ? base : 'low'); // mail yoksa düşür

  // ---- G1: DMARC (org-domain kuralı: önce alt-alan, yoksa org-alan) ----
  let dmarcRec = ''; let dmarcLevel = '';
  const subDmarc = host !== org ? await txt(`_dmarc.${host}`) : []; queries++;
  const subHit = subDmarc.find((r) => /v=dmarc1/i.test(r));
  if (subHit) { dmarcRec = subHit; dmarcLevel = `alt-alan (${host})`; }
  else { const orgD = await txt(`_dmarc.${org}`); queries++; const oh = orgD.find((r) => /v=dmarc1/i.test(r)); if (oh) { dmarcRec = oh; dmarcLevel = `org-alan (${org})`; } }
  if (!dmarcRec) {
    push({ check: 'dmarc_missing', severity: dl('medium'), evidence: `\`${org}\` için DMARC kaydı (_dmarc TXT) **gözlenmedi** — alan adına yapılan e-posta spoofing'i alıcıda politikayla reddedilemez (gösterge)${mailNuance}. En az \`p=quarantine\`/\`reject\` önerilir.` });
  } else {
    const d = parseDmarc(dmarcRec);
    notes.push(`DMARC ${dmarcLevel}: \`${dmarcRec}\``);
    if (d.p === 'reject' && (d.pct === undefined || d.pct === 100)) notes.push('DMARC **p=reject + pct=100** — güçlü anti-spoofing politikası (olumlu).');
    else if (d.p === 'none') push({ check: 'dmarc_policy_weak', severity: dl('medium'), evidence: `DMARC **p=none** (${dmarcLevel}) — yalnız izleme; spoofing e-postaları alıcıda engellenmiyor (gösterge)${mailNuance}. \`p=quarantine\`→\`reject\` kademeli sıkılaştırma önerilir.` });
    else if (d.p === 'quarantine' || (d.pct !== undefined && d.pct < 100)) push({ check: 'dmarc_policy_partial', severity: 'low', evidence: `DMARC **p=${d.p ?? '?'}${d.pct !== undefined ? `, pct=${d.pct}` : ''}** (${dmarcLevel}) — kısmi uygulama; \`p=reject, pct=100\`'e yükseltilebilir (gösterge).` });
    if (host !== org && d.sp === 'none') push({ check: 'dmarc_subdomain_open', severity: dl('medium'), evidence: `Org-alan DMARC **sp=none** — alt-alanlar (\`${host}\` dahil) DMARC korumasız (gösterge)${mailNuance}.` });
    if (!d.hasRua) notes.push('DMARC \`rua=\` raporlaması yok — spoofing denemeleri görünmez (olgunluk göstergesi).');
  }

  // ---- G2: SPF derinliği ----
  const apexTxt = await txt(org); queries++;
  const spfRec = apexTxt.find((r) => /^v=spf1/i.test(r.trim()));
  if (!spfRec) push({ check: 'spf_missing', severity: dl('medium'), evidence: `\`${org}\` için SPF kaydı (v=spf1 TXT) **gözlenmedi** — yetkili gönderen sunucular tanımsız (gösterge)${mailNuance}.` });
  else {
    const s = parseSpf(spfRec); notes.push(`SPF: \`${spfRec}\``);
    if (s.all === '+') push({ check: 'spf_permissive', severity: 'high', evidence: `SPF **+all** — HERKES bu alan adına e-posta gönderebilir (spoofing'e tamamen açık). \`-all\` (hardfail) olmalı.` });
    else if (s.all === '?') push({ check: 'spf_neutral', severity: dl('medium'), evidence: `SPF **?all** (neutral) — yetkisiz göndereni açıkça reddetmiyor (gösterge)${mailNuance}. \`-all\` önerilir.` });
    else if (s.all === '~') notes.push('SPF **~all** (softfail) — kabul edilebilir; kesin koruma için \`-all\` düşünülebilir.');
    else if (s.all === '-') notes.push('SPF **-all** (hardfail) — güçlü SPF politikası (olumlu).');
    if (s.lookups > 10) push({ check: 'spf_too_many_lookups', severity: 'medium', evidence: `SPF üst-seviye DNS-arama mekanizması sayısı **${s.lookups}** — RFC 7208 sınırı 10; aşımda **PermError** ile SPF geçersiz kalabilir (gösterge; tam özyineli genişletme yapılmadı).` });
  }

  // ---- G3: DKIM seçici keşfi (pasif) ----
  const foundSelectors: string[] = []; let weakKey = false; let revoked = false;
  for (const sel of DKIM_SELECTORS) {
    const rec = (await txt(`${sel}._domainkey.${org}`)).find((r) => /v=dkim1|(^|;)\s*p=/i.test(r)); queries++;
    if (!rec) continue;
    foundSelectors.push(sel);
    const pm = rec.match(/(?:^|;)\s*p=([A-Za-z0-9+/=]*)/i);
    if (pm && pm[1].trim() === '') revoked = true;
    else if (pm && pm[1].length < 250) weakKey = true; // ~1024-bit RSA (yaklaşık)
  }
  if (foundSelectors.length === 0) notes.push('DKIM: yaygın seçicilerde (default/google/selector1…) kayıt **gözlenmedi** — kesin yokluk DEĞİL; özel seçici kullanılıyor olabilir (dürüst).');
  else {
    notes.push(`DKIM seçici bulundu: **${foundSelectors.join(', ')}** (${foundSelectors.length}).`);
    if (revoked) push({ check: 'dkim_revoked', severity: 'low', evidence: `Bir DKIM seçicisinde \`p=\` **boş** — iptal edilmiş/devre-dışı anahtar (gösterge).` });
    if (weakKey) push({ check: 'dkim_weak_key', severity: 'low', evidence: `Bir DKIM seçicisinde anahtar **~1024-bit** görünüyor (yaklaşık) — 2048-bit önerilir (gösterge).` });
  }

  // ---- G4: MTA-STS (TXT + tek güvenli GET) ----
  const stsTxt = (await txt(`_mta-sts.${org}`)).find((r) => /v=stsv1/i.test(r)); queries++;
  if (!stsTxt) notes.push('MTA-STS: \`_mta-sts\` TXT gözlenmedi — SMTP MITM/downgrade koruması yok (düşük/olgunluk göstergesi).');
  else {
    let mode = ''; const url = `https://mta-sts.${org}/.well-known/mta-sts.txt`;
    try {
      const ctrl = new AbortController(); const t = setTimeout(() => ctrl.abort(), 10_000); const t0 = Date.now();
      const res = await fetch(url, { redirect: 'manual', signal: ctrl.signal, headers: { 'user-agent': 'CyberTestify-DNS/1.0' } }); clearTimeout(t);
      const body = (await res.text()).slice(0, 4000);
      logScanStep({ step: 'E-posta & DNS Derinliği', method: 'GET', url, status: res.status, durationMs: Date.now() - t0 });
      const mm = body.match(/mode\s*:\s*(enforce|testing|none)/i); mode = mm ? mm[1].toLowerCase() : '';
    } catch { logScanStep({ step: 'E-posta & DNS Derinliği', method: 'GET', url, status: 0, level: 'warn' }); }
    if (mode === 'enforce') notes.push('MTA-STS **mode=enforce** — SMTP downgrade koruması etkin (olumlu).');
    else push({ check: 'mta_sts_weak', severity: 'low', evidence: `MTA-STS politikası **mode=${mode || 'okunamadı/none'}** — \`enforce\` değil; SMTP MITM/downgrade'e karşı zorlayıcı koruma yok (gösterge).` });
  }

  // ---- G5: TLS-RPT ----
  const tlsRpt = (await txt(`_smtp._tls.${org}`)).find((r) => /v=tlsrptv1/i.test(r)); queries++;
  if (tlsRpt) notes.push('TLS-RPT etkin — SMTP TLS hataları raporlanıyor (olumlu/olgunluk).');
  else notes.push('TLS-RPT (\`_smtp._tls\` TXT) gözlenmedi — SMTP TLS teslim sorunları raporlanmıyor (bilgilendirici).');

  // ---- G6: DNSSEC (yalnız gözlem — AD bayrağı) ----
  const sec = await queryDnssec(org); queries++;
  if (sec.ok && sec.ad && sec.answers > 0) notes.push('DNSSEC: alan **imzalı ve doğrulandı** (AD bayrağı) — DNS bütünlüğü korumalı (olumlu).');
  else push({ check: 'dnssec_missing', severity: 'low', evidence: `DNSSEC gözlenmedi (\`${org}\` imzasız/doğrulanamadı — AD bayrağı yok) — DNS-spoofing/cache-poisoning'e karşı imzasız (gösterge; yalnız gözlem, çözümleyici saldırısı yapılmadı).` });

  // ---- G7: CAA + BIMI (bilgilendirici) ----
  let caa: any[] = []; try { caa = await dns.resolveCaa(org); } catch { caa = []; } queries++;
  if (caa.length === 0) push({ check: 'caa_missing', severity: 'low', evidence: `CAA kaydı **gözlenmedi** — herhangi bir CA \`${org}\` için sertifika verebilir (yanlış-verilme riski göstergesi). CAA ile yetkili CA'lar kısıtlanabilir.` });
  else notes.push(`CAA kaydı mevcut (${caa.length}) — sertifika verme kısıtlı (olumlu).`);
  const bimi = (await txt(`default._bimi.${org}`)).find((r) => /v=bimi1/i.test(r)); queries++;
  notes.push(bimi ? 'BIMI kaydı mevcut — marka göstergesi (olgunluk).' : 'BIMI (\`default._bimi\` TXT) gözlenmedi — bilgilendirici, güvenlik etkisi yok.');

  notes.push(`Sorgulanan org-alan: **${org}**${host !== org ? ` (hedef alt-alan: ${host})` : ''}. Toplam **${queries}** pasif DNS sorgusu + en fazla 1 güvenli MTA-STS GET. Saldırı/state-değişimi/çözümleyici-saldırısı YOK.`);
  return { ok: true, pagesScanned: 0, inputsFound: queries, probesSent: queries, findings, stopped: null, notes };
}
