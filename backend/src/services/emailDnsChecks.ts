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

export async function collectEmailDnsEvidence(host: string, locale: string = 'tr'): Promise<ActiveCheckEvidence> {
  const de = locale === 'de', en = locale === 'en';
  const t = (trS: string, deS: string, enS?: string) => (de ? deS : en ? (enS ?? trS) : trS);
  const findings: VFinding[] = []; const notes: string[] = [];
  const org = getOrgDomain(host);
  let queries = 0;
  const push = (f: Partial<VFinding> & { check: string; evidence: string; severity: VFinding['severity'] }) =>
    findings.push({ inputPoint: org, vulnerable: true, technique: (en ? 'passive DNS/TXT observation' : de ? 'passive DNS/TXT-Beobachtung' : 'pasif DNS/TXT gözlemi'), confidence: 'high', sideEffectRisk: 'none', ...f } as VFinding);

  const mail = await hasMx(org); queries++;
  const mailNuance = mail ? '' : (en ? ' (no MX on this domain — may be a non-mail-sending domain; severity at indicator level)' : de ? ' (kein MX auf dieser Domain — möglicherweise eine nicht-mailversendende Domain; Schweregrad auf Indikatorebene)' : ' (bu alanda MX yok — e-posta göndermeyen alan olabilir; şiddet gösterge düzeyinde)');
  const dl = (base: VFinding['severity']): VFinding['severity'] => (mail ? base : 'low'); // mail yoksa düşür

  // ---- G1: DMARC (org-domain kuralı: önce alt-alan, yoksa org-alan) ----
  let dmarcRec = ''; let dmarcLevel = '';
  const subDmarc = host !== org ? await txt(`_dmarc.${host}`) : []; queries++;
  const subHit = subDmarc.find((r) => /v=dmarc1/i.test(r));
  if (subHit) { dmarcRec = subHit; dmarcLevel = t(`alt-alan (${host})`, `Subdomain (${host})`, `subdomain (${host})`); }
  else { const orgD = await txt(`_dmarc.${org}`); queries++; const oh = orgD.find((r) => /v=dmarc1/i.test(r)); if (oh) { dmarcRec = oh; dmarcLevel = t(`org-alan (${org})`, `Organisationsdomäne (${org})`, `organization domain (${org})`); } }
  if (!dmarcRec) {
    push({ check: 'dmarc_missing', severity: dl('medium'), evidence: (en ? `No DMARC record (_dmarc TXT) was **observed** for \`${org}\` — e-mail spoofing of the domain cannot be rejected by policy at the recipient (an indicator)${mailNuance}. At least \`p=quarantine\`/\`reject\` is recommended.` : de ? `Für \`${org}\` wurde **kein** DMARC-Eintrag (_dmarc TXT) beobachtet — E-Mail-Spoofing der Domain kann beim Empfänger nicht per Richtlinie abgewiesen werden (ein Indikator)${mailNuance}. Mindestens \`p=quarantine\`/\`reject\` wird empfohlen.` : `\`${org}\` için DMARC kaydı (_dmarc TXT) **gözlenmedi** — alan adına yapılan e-posta spoofing'i alıcıda politikayla reddedilemez (gösterge)${mailNuance}. En az \`p=quarantine\`/\`reject\` önerilir.`) });
  } else {
    const d = parseDmarc(dmarcRec);
    notes.push(`DMARC ${dmarcLevel}: \`${dmarcRec}\``);
    if (d.p === 'reject' && (d.pct === undefined || d.pct === 100)) notes.push(t('DMARC **p=reject + pct=100** — güçlü anti-spoofing politikası (olumlu).', 'DMARC **p=reject + pct=100** — starke Anti-Spoofing-Richtlinie (positiv).', 'DMARC **p=reject + pct=100** — a strong anti-spoofing policy (positive).'));
    else if (d.p === 'none') push({ check: 'dmarc_policy_weak', severity: dl('medium'), evidence: (en ? `DMARC **p=none** (${dmarcLevel}) — monitoring only; spoofing e-mails are not blocked at the recipient (an indicator)${mailNuance}. A gradual tightening \`p=quarantine\`→\`reject\` is recommended.` : de ? `DMARC **p=none** (${dmarcLevel}) — nur Überwachung; Spoofing-E-Mails werden beim Empfänger nicht blockiert (ein Indikator)${mailNuance}. Eine schrittweise Verschärfung \`p=quarantine\`→\`reject\` wird empfohlen.` : `DMARC **p=none** (${dmarcLevel}) — yalnız izleme; spoofing e-postaları alıcıda engellenmiyor (gösterge)${mailNuance}. \`p=quarantine\`→\`reject\` kademeli sıkılaştırma önerilir.`) });
    else if (d.p === 'quarantine' || (d.pct !== undefined && d.pct < 100)) push({ check: 'dmarc_policy_partial', severity: 'low', evidence: (en ? `DMARC **p=${d.p ?? '?'}${d.pct !== undefined ? `, pct=${d.pct}` : ''}** (${dmarcLevel}) — partial enforcement; can be raised to \`p=reject, pct=100\` (an indicator).` : de ? `DMARC **p=${d.p ?? '?'}${d.pct !== undefined ? `, pct=${d.pct}` : ''}** (${dmarcLevel}) — teilweise Durchsetzung; kann auf \`p=reject, pct=100\` angehoben werden (ein Indikator).` : `DMARC **p=${d.p ?? '?'}${d.pct !== undefined ? `, pct=${d.pct}` : ''}** (${dmarcLevel}) — kısmi uygulama; \`p=reject, pct=100\`'e yükseltilebilir (gösterge).`) });
    if (host !== org && d.sp === 'none') push({ check: 'dmarc_subdomain_open', severity: dl('medium'), evidence: (en ? `Organization-domain DMARC **sp=none** — subdomains (including \`${host}\`) are unprotected by DMARC (an indicator)${mailNuance}.` : de ? `Organisationsdomänen-DMARC **sp=none** — Subdomains (einschließlich \`${host}\`) sind durch DMARC ungeschützt (ein Indikator)${mailNuance}.` : `Org-alan DMARC **sp=none** — alt-alanlar (\`${host}\` dahil) DMARC korumasız (gösterge)${mailNuance}.`) });
    if (!d.hasRua) notes.push(t('DMARC \`rua=\` raporlaması yok — spoofing denemeleri görünmez (olgunluk göstergesi).', 'Keine DMARC-\`rua=\`-Berichterstattung — Spoofing-Versuche bleiben unsichtbar (Reifegrad-Indikator).', 'No DMARC \`rua=\` reporting — spoofing attempts remain invisible (a maturity indicator).'));
  }

  // ---- G2: SPF derinliği ----
  const apexTxt = await txt(org); queries++;
  const spfRec = apexTxt.find((r) => /^v=spf1/i.test(r.trim()));
  if (!spfRec) push({ check: 'spf_missing', severity: dl('medium'), evidence: (en ? `No SPF record (v=spf1 TXT) was **observed** for \`${org}\` — authorized sending servers are undefined (an indicator)${mailNuance}.` : de ? `Für \`${org}\` wurde **kein** SPF-Eintrag (v=spf1 TXT) beobachtet — autorisierte Sendeserver sind nicht definiert (ein Indikator)${mailNuance}.` : `\`${org}\` için SPF kaydı (v=spf1 TXT) **gözlenmedi** — yetkili gönderen sunucular tanımsız (gösterge)${mailNuance}.`) });
  else {
    const s = parseSpf(spfRec); notes.push(`SPF: \`${spfRec}\``);
    if (s.all === '+') push({ check: 'spf_permissive', severity: 'high', evidence: (en ? `SPF **+all** — ANYONE can send e-mail as this domain (fully open to spoofing). It should be \`-all\` (hardfail).` : de ? `SPF **+all** — JEDER kann E-Mails als diese Domain senden (vollständig offen für Spoofing). Es sollte \`-all\` (Hardfail) sein.` : `SPF **+all** — HERKES bu alan adına e-posta gönderebilir (spoofing'e tamamen açık). \`-all\` (hardfail) olmalı.`) });
    else if (s.all === '?') push({ check: 'spf_neutral', severity: dl('medium'), evidence: (en ? `SPF **?all** (neutral) — does not explicitly reject an unauthorized sender (an indicator)${mailNuance}. \`-all\` is recommended.` : de ? `SPF **?all** (neutral) — weist einen unautorisierten Sender nicht explizit ab (ein Indikator)${mailNuance}. \`-all\` wird empfohlen.` : `SPF **?all** (neutral) — yetkisiz göndereni açıkça reddetmiyor (gösterge)${mailNuance}. \`-all\` önerilir.`) });
    else if (s.all === '~') notes.push(t('SPF **~all** (softfail) — kabul edilebilir; kesin koruma için \`-all\` düşünülebilir.', 'SPF **~all** (softfail) — akzeptabel; für strikten Schutz kann \`-all\` erwogen werden.', 'SPF **~all** (softfail) — acceptable; \`-all\` can be considered for strict protection.'));
    else if (s.all === '-') notes.push(t('SPF **-all** (hardfail) — güçlü SPF politikası (olumlu).', 'SPF **-all** (hardfail) — starke SPF-Richtlinie (positiv).', 'SPF **-all** (hardfail) — a strong SPF policy (positive).'));
    if (s.lookups > 10) push({ check: 'spf_too_many_lookups', severity: 'medium', evidence: (en ? `SPF top-level DNS-lookup mechanism count is **${s.lookups}** — the RFC 7208 limit is 10; exceeding it can invalidate SPF with a **PermError** (an indicator; full recursive expansion was not performed).` : de ? `Die Anzahl der SPF-Top-Level-DNS-Lookup-Mechanismen beträgt **${s.lookups}** — das RFC-7208-Limit ist 10; ein Überschreiten kann SPF mit einem **PermError** ungültig machen (ein Indikator; keine vollständige rekursive Expansion durchgeführt).` : `SPF üst-seviye DNS-arama mekanizması sayısı **${s.lookups}** — RFC 7208 sınırı 10; aşımda **PermError** ile SPF geçersiz kalabilir (gösterge; tam özyineli genişletme yapılmadı).`) });
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
  if (foundSelectors.length === 0) notes.push(t('DKIM: yaygın seçicilerde (default/google/selector1…) kayıt **gözlenmedi** — kesin yokluk DEĞİL; özel seçici kullanılıyor olabilir (dürüst).', 'DKIM: Bei den gängigen Selektoren (default/google/selector1…) wurde **kein Eintrag beobachtet** — KEIN sicheres Fehlen; möglicherweise wird ein eigener Selektor verwendet (ehrlich).', 'DKIM: no record was **observed** at common selectors (default/google/selector1…) — NOT a definitive absence; a custom selector may be in use (honest).'));
  else {
    notes.push(t(`DKIM seçici bulundu: **${foundSelectors.join(', ')}** (${foundSelectors.length}).`, `DKIM-Selektor(en) gefunden: **${foundSelectors.join(', ')}** (${foundSelectors.length}).`, `DKIM selector(s) found: **${foundSelectors.join(', ')}** (${foundSelectors.length}).`));
    if (revoked) push({ check: 'dkim_revoked', severity: 'low', evidence: (en ? `A DKIM selector has an **empty** \`p=\` — a revoked/disabled key (an indicator).` : de ? `Ein DKIM-Selektor hat ein **leeres** \`p=\` — ein widerrufener/deaktivierter Schlüssel (ein Indikator).` : `Bir DKIM seçicisinde \`p=\` **boş** — iptal edilmiş/devre-dışı anahtar (gösterge).`) });
    if (weakKey) push({ check: 'dkim_weak_key', severity: 'low', evidence: (en ? `A DKIM selector's key appears to be **~1024-bit** (approx.) — 2048-bit is recommended (an indicator).` : de ? `Der Schlüssel eines DKIM-Selektors erscheint **~1024-Bit** (ca.) — 2048-Bit wird empfohlen (ein Indikator).` : `Bir DKIM seçicisinde anahtar **~1024-bit** görünüyor (yaklaşık) — 2048-bit önerilir (gösterge).`) });
  }

  // ---- G4: MTA-STS (TXT + tek güvenli GET) ----
  const stsTxt = (await txt(`_mta-sts.${org}`)).find((r) => /v=stsv1/i.test(r)); queries++;
  if (!stsTxt) notes.push(t('MTA-STS: \`_mta-sts\` TXT gözlenmedi — SMTP MITM/downgrade koruması yok (düşük/olgunluk göstergesi).', 'MTA-STS: \`_mta-sts\`-TXT nicht beobachtet — kein Schutz gegen SMTP-MITM/Downgrade (niedrig/Reifegrad-Indikator).', 'MTA-STS: no \`_mta-sts\` TXT observed — no SMTP MITM/downgrade protection (a low/maturity indicator).'));
  else {
    let mode = ''; const url = `https://mta-sts.${org}/.well-known/mta-sts.txt`;
    try {
      const ctrl = new AbortController(); const t = setTimeout(() => ctrl.abort(), 10_000); const t0 = Date.now();
      const res = await fetch(url, { redirect: 'manual', signal: ctrl.signal, headers: { 'user-agent': 'CyberTestify-DNS/1.0' } }); clearTimeout(t);
      const body = (await res.text()).slice(0, 4000);
      logScanStep({ step: 'E-posta & DNS Derinliği', method: 'GET', url, status: res.status, durationMs: Date.now() - t0 });
      const mm = body.match(/mode\s*:\s*(enforce|testing|none)/i); mode = mm ? mm[1].toLowerCase() : '';
    } catch { logScanStep({ step: 'E-posta & DNS Derinliği', method: 'GET', url, status: 0, level: 'warn' }); }
    if (mode === 'enforce') notes.push(t('MTA-STS **mode=enforce** — SMTP downgrade koruması etkin (olumlu).', 'MTA-STS **mode=enforce** — Schutz gegen SMTP-Downgrade aktiv (positiv).', 'MTA-STS **mode=enforce** — SMTP downgrade protection is active (positive).'));
    else push({ check: 'mta_sts_weak', severity: 'low', evidence: (en ? `MTA-STS policy **mode=${mode || 'unreadable/none'}** — not \`enforce\`; no enforcing protection against SMTP MITM/downgrade (an indicator).` : de ? `MTA-STS-Richtlinie **mode=${mode || 'unreadable/none'}** — nicht \`enforce\`; kein erzwingender Schutz gegen SMTP-MITM/Downgrade (ein Indikator).` : `MTA-STS politikası **mode=${mode || 'okunamadı/none'}** — \`enforce\` değil; SMTP MITM/downgrade'e karşı zorlayıcı koruma yok (gösterge).`) });
  }

  // ---- G5: TLS-RPT ----
  const tlsRpt = (await txt(`_smtp._tls.${org}`)).find((r) => /v=tlsrptv1/i.test(r)); queries++;
  if (tlsRpt) notes.push(t('TLS-RPT etkin — SMTP TLS hataları raporlanıyor (olumlu/olgunluk).', 'TLS-RPT aktiv — SMTP-TLS-Fehler werden gemeldet (positiv/Reifegrad).', 'TLS-RPT enabled — SMTP TLS errors are reported (positive/maturity).'));
  else notes.push(t('TLS-RPT (\`_smtp._tls\` TXT) gözlenmedi — SMTP TLS teslim sorunları raporlanmıyor (bilgilendirici).', 'TLS-RPT (\`_smtp._tls\`-TXT) nicht beobachtet — SMTP-TLS-Zustellungsprobleme werden nicht gemeldet (informativ).', 'TLS-RPT (\`_smtp._tls\` TXT) not observed — SMTP TLS delivery problems are not reported (informational).'));

  // ---- G6: DNSSEC (yalnız gözlem — AD bayrağı) ----
  const sec = await queryDnssec(org); queries++;
  if (sec.ok && sec.ad && sec.answers > 0) notes.push(t('DNSSEC: alan **imzalı ve doğrulandı** (AD bayrağı) — DNS bütünlüğü korumalı (olumlu).', 'DNSSEC: Die Domäne ist **signiert und validiert** (AD-Flag) — DNS-Integrität geschützt (positiv).', 'DNSSEC: the domain is **signed and validated** (AD flag) — DNS integrity is protected (positive).'));
  else push({ check: 'dnssec_missing', severity: 'low', evidence: (en ? `DNSSEC was not observed (\`${org}\` unsigned/could not be validated — no AD flag) — unsigned against DNS spoofing/cache poisoning (an indicator; observation only, no resolver attack was performed).` : de ? `DNSSEC wurde nicht beobachtet (\`${org}\` unsigniert/konnte nicht validiert werden — kein AD-Flag) — ungeschützt gegen DNS-Spoofing/Cache-Poisoning (ein Indikator; nur Beobachtung, kein Resolver-Angriff durchgeführt).` : `DNSSEC gözlenmedi (\`${org}\` imzasız/doğrulanamadı — AD bayrağı yok) — DNS-spoofing/cache-poisoning'e karşı imzasız (gösterge; yalnız gözlem, çözümleyici saldırısı yapılmadı).`) });

  // ---- G7: CAA + BIMI (bilgilendirici) ----
  let caa: any[] = []; try { caa = await dns.resolveCaa(org); } catch { caa = []; } queries++;
  if (caa.length === 0) push({ check: 'caa_missing', severity: 'low', evidence: (en ? `No CAA record was **observed** — any CA can issue a certificate for \`${org}\` (a mis-issuance risk indicator). CAA can restrict authorized CAs.` : de ? `Es wurde **kein** CAA-Eintrag beobachtet — jede CA kann ein Zertifikat für \`${org}\` ausstellen (ein Fehlausstellungs-Risiko-Indikator). CAA kann autorisierte CAs einschränken.` : `CAA kaydı **gözlenmedi** — herhangi bir CA \`${org}\` için sertifika verebilir (yanlış-verilme riski göstergesi). CAA ile yetkili CA'lar kısıtlanabilir.`) });
  else notes.push(t(`CAA kaydı mevcut (${caa.length}) — sertifika verme kısıtlı (olumlu).`, `CAA-Eintrag vorhanden (${caa.length}) — Zertifikatsausstellung eingeschränkt (positiv).`, `CAA record present (${caa.length}) — certificate issuance is restricted (positive).`));
  const bimi = (await txt(`default._bimi.${org}`)).find((r) => /v=bimi1/i.test(r)); queries++;
  notes.push(bimi ? t('BIMI kaydı mevcut — marka göstergesi (olgunluk).', 'BIMI-Eintrag vorhanden — Marken-Indikator (Reifegrad).', 'BIMI record present — a brand indicator (maturity).') : t('BIMI (\`default._bimi\` TXT) gözlenmedi — bilgilendirici, güvenlik etkisi yok.', 'BIMI (\`default._bimi\`-TXT) nicht beobachtet — informativ, keine Sicherheitsauswirkung.', 'BIMI (\`default._bimi\` TXT) not observed — informational, no security impact.'));

  notes.push(t(`Sorgulanan org-alan: **${org}**${host !== org ? ` (hedef alt-alan: ${host})` : ''}. Toplam **${queries}** pasif DNS sorgusu + en fazla 1 güvenli MTA-STS GET. Saldırı/state-değişimi/çözümleyici-saldırısı YOK.`, `Abgefragte Organisationsdomäne: **${org}**${host !== org ? ` (Ziel-Subdomain: ${host})` : ''}. Insgesamt **${queries}** passive DNS-Abfragen + höchstens 1 sicherer MTA-STS-GET. KEIN Angriff/Zustandsänderung/Resolver-Angriff.`, `Queried organization domain: **${org}**${host !== org ? ` (target subdomain: ${host})` : ''}. A total of **${queries}** passive DNS queries + at most 1 safe MTA-STS GET. NO attack/state-change/resolver-attack.`));
  return { ok: true, pagesScanned: 0, inputsFound: queries, probesSent: queries, findings, stopped: null, notes };
}
