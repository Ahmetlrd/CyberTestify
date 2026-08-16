/**
 * (basit_tarama) DETERMINISTIK RAPOR — veriyi KENDI KODUMUZLA toplar, ajana GUVENMEZ.
 *
 * Neden ajan ciktisini PARSE ETMIYORUZ: PentAGI ajani hem raporu (surec dili / meta-ozet /
 * tutarsiz risk) hem de KOMUT FORMATINI ongorulemez sekilde uretiyor (curl -I vs curl -v vs
 * Python script + JSON...). Ciktisini parse etmek surekli koklebek-vurmaca. Cozum: basit_tarama
 * TAMAMEN pasif bir ana-sayfa kontrolu oldugundan, veriyi (HTTP guvenlik basliklari + TLS
 * sertifikasi + HTML/teknoloji) backend KENDISI dogrudan ceker (Ek Pasif Kontroller ile ayni
 * yaklasim) ve raporu KOD yazar. Boylece rapor formattan BAGIMSIZ, HER ZAMAN tutarli/profesyonel.
 * Ek LLM/maliyet YOK. Hedef, sahipligi dogrulanmis alan adi -> kapsam icindedir.
 */
import tls from 'node:tls';
import { buildHeaderFixSuggestions } from './fixSuggestions.js';
import { resolveOrigin, collectPages } from './surfaceEvidence.js';
import { detectOutdatedSoftware } from './techEol.js';

const FETCH_TIMEOUT_MS = 9000;
const TLS_TIMEOUT_MS = 8000;
const MAX_HTML = 1_500_000;

export type Evidence = {
  ok: boolean;
  status?: number;
  headers: Map<string, string>; // lowercased
  html: string;
  tls: TlsInfo;
  httpsWorks: boolean;   // 443 açık mı (false + reachable => https_missing bulgusu)
  reachable: boolean;    // hedefe hiç ulaşıldı mı (false => "İncelenemedi", ASLA "temiz")
  scheme: 'https' | 'http' | null;
};

type TlsInfo = {
  found: boolean;
  cn?: string;
  san: string[];
  issuer?: string;
  notAfter?: string;
  daysLeft?: number;
  protocol?: string;
  cipher?: string;
  hostnameMatch?: boolean;
};

// --- TLS sertifikasini node:tls ile dogrudan al (openssl parse yok) -----------------
function fetchTls(host: string): Promise<TlsInfo> {
  return new Promise((resolve) => {
    let settled = false;
    const done = (v: TlsInfo) => { if (!settled) { settled = true; resolve(v); } };
    try {
      const socket = tls.connect(
        { host, port: 443, servername: host, timeout: TLS_TIMEOUT_MS, rejectUnauthorized: false },
        () => {
          const cert = socket.getPeerCertificate();
          const protocol = socket.getProtocol() ?? undefined;
          const cipher = socket.getCipher()?.name;
          const cn: string | undefined = (cert?.subject as { CN?: string } | undefined)?.CN;
          const san = (cert?.subjectaltname ?? '')
            .split(',')
            .map((s) => s.trim().replace(/^DNS:/i, ''))
            .filter(Boolean);
          const iss = cert?.issuer as { O?: string; CN?: string } | undefined;
          const issuer = [iss?.O, iss?.CN].filter(Boolean).join(' — ') || undefined;
          const notAfter = cert?.valid_to;
          let daysLeft: number | undefined;
          if (notAfter) {
            const exp = new Date(notAfter);
            if (!isNaN(exp.getTime())) daysLeft = Math.round((exp.getTime() - Date.now()) / 86400000);
          }
          const hostnameMatch = cn || san.length ? hostMatches(host, cn, san) : undefined;
          socket.end();
          done({ found: !!(cn || notAfter), cn, san, issuer, notAfter, daysLeft, protocol, cipher, hostnameMatch });
        },
      );
      socket.on('error', () => done({ found: false, san: [] }));
      socket.on('timeout', () => { socket.destroy(); done({ found: false, san: [] }); });
    } catch {
      done({ found: false, san: [] });
    }
  });
}

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

// --- HTTP basliklari + HTML'i dogrudan cek (ÇÖZÜLEN protokol üzerinden: https→http fallback) ---
async function fetchHome(origin: string): Promise<{ ok: boolean; status?: number; headers: Map<string, string>; html: string }> {
  const headers = new Map<string, string>();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(`${origin}/`, {
      signal: ctrl.signal,
      redirect: 'follow',
      headers: { 'user-agent': 'CyberTestify-PassiveCheck/1.0', accept: 'text/html,*/*' },
    });
    res.headers.forEach((v, k) => headers.set(k.toLowerCase(), v));
    let html = '';
    try {
      const buf = Buffer.from(await res.arrayBuffer());
      html = (buf.length > MAX_HTML ? buf.subarray(0, MAX_HTML) : buf).toString('utf-8');
    } catch { /* govde okunamadi -> yalniz basliklar */ }
    return { ok: true, status: res.status, headers, html };
  } catch {
    return { ok: false, headers, html: '' };
  } finally {
    clearTimeout(timer);
  }
}

export async function collectEvidence(host: string): Promise<Evidence> {
  const o = await resolveOrigin(host); // https tercihli; 443 kapalıysa http; ikisi de yoksa reachable=false
  const [home, tlsInfo] = await Promise.all([
    o.reachable ? fetchHome(o.origin) : Promise.resolve({ ok: false, status: undefined as number | undefined, headers: new Map<string, string>(), html: '' }),
    fetchTls(host),
  ]);
  return { ok: home.ok, status: home.status, headers: home.headers, html: home.html, tls: tlsInfo, httpsWorks: o.httpsWorks, reachable: o.reachable, scheme: o.scheme };
}

// --- Teknoloji / bilgi ifsasi -------------------------------------------------------
export function detectTech(headers: Map<string, string>, html: string): { tech: string[]; disclosure: string[] } {
  const tech: string[] = [];
  const disclosure: string[] = [];
  const add = (arr: string[], v: string) => { if (v && !arr.includes(v)) arr.push(v); };

  const server = headers.get('server');
  if (server) add(tech, `Sunucu: ${server}`);
  const via = headers.get('via');
  const servedBy = headers.get('x-served-by') || headers.get('x-cache');
  if (/fastly/i.test(server ?? '') || /fastly/i.test(via ?? '') || /cache-/i.test(servedBy ?? '')) add(tech, 'CDN: Fastly');
  if (headers.get('cf-ray') || /cloudflare/i.test(server ?? '')) add(tech, 'CDN: Cloudflare');
  if (headers.get('x-vercel-id')) add(tech, 'Barındırma: Vercel');
  const xpb = headers.get('x-powered-by');
  if (xpb) add(tech, `X-Powered-By: ${xpb}`);
  if (/h3/i.test(headers.get('alt-svc') ?? '')) add(tech, 'HTTP/3 desteği (Alt-Svc)');

  const H = html || '';
  if (/firebaseapp\.com|firestore\.googleapis\.com|firebasestorage/i.test(H)) add(tech, 'Google Firebase / Firestore');
  if (/googletagmanager\.com|GTM-[A-Z0-9]+/i.test(H)) add(tech, 'Google Tag Manager');
  if (/gtag\/js|google-analytics\.com|\bG-[A-Z0-9]{6,}\b/.test(H)) add(tech, 'Google Analytics');
  if (/connect\.facebook\.net|fbq\(/i.test(H)) add(tech, 'Facebook Pixel');
  if (/clarity\.ms|clarity\("/i.test(H)) add(tech, 'Microsoft Clarity');
  if (/\/assets\/index-[\w-]+\.js/i.test(H)) add(tech, 'Vite tabanlı SPA');
  if (/data-reactroot|id="root"|react(?:-dom)?[.@]/i.test(H)) add(tech, 'React');

  const gtm = H.match(/GTM-[A-Z0-9]+/i)?.[0];
  if (gtm) add(disclosure, `Google Tag Manager ID: ${gtm}`);
  const ga = H.match(/\bG-[A-Z0-9]{6,}\b/)?.[0];
  if (ga) add(disclosure, `Google Analytics ID: ${ga}`);
  const fb = H.match(/fbq\('init',\s*'(\d+)'/)?.[1] || H.match(/facebook\.com\/tr\?id=(\d+)/)?.[1];
  if (fb) add(disclosure, `Facebook Pixel ID: ${fb}`);
  const fbProj = H.match(/([a-z0-9-]+)\.firebaseapp\.com/i)?.[1];
  if (fbProj) add(disclosure, `Firebase proje kimliği: ${fbProj}`);

  return { tech, disclosure };
}

// --- Risk (assessBasit ile AYNI kural) ----------------------------------------------
const SEC_KEYS = ['csp', 'xfo', 'xcto', 'hsts', 'referrer', 'permissions'] as const;
type SecKey = (typeof SEC_KEYS)[number];

// KALIBRE: "Yüksek" YALNIZ gercek/aciak bir sorunda (TLS suresi dolmus VEYA hostname
// uyusmazligi — ziyaretçiye dogrudan tarayıcı uyarisi). Salt eksik guvenlik basligi
// (savunma-derinligi bosluklari) panik dili olan "Yüksek" degil "Orta"dir. Yalniz 1-2
// onemsiz baslik eksikse "Düşük". (Grok geri bildirimi: baslik eksikligini abartma.)
function riskLevel(absent: Set<SecKey>, tls: TlsInfo): 'low' | 'medium' | 'high' {
  if (tls.found && (tls.hostnameMatch === false || (tls.daysLeft != null && tls.daysLeft < 0))) return 'high';
  const crit = absent.has('csp') || absent.has('xfo');
  if (crit || absent.size >= 3) return 'medium';
  return 'low';
}

const HEADER_ROWS: Array<{ key: SecKey | 'ctype' | 'xxss'; header: string; hdr: string; presentNote: string; absentNote: string }> = [
  { key: 'hsts', header: 'Strict-Transport-Security', hdr: 'strict-transport-security', presentNote: 'HTTPS zorunlu tutuluyor; SSL-stripping/MITM saldırılarına karşı koruma sağlıyor.', absentNote: 'HTTPS zorunluluğu tarayıcıya bildirilmiyor; ilk isteklerde SSL-stripping/MITM riski var.' },
  { key: 'csp', header: 'Content-Security-Policy', hdr: 'content-security-policy', presentNote: 'Kaynak yükleme politikası tanımlı; XSS/enjeksiyon yüzeyi daralıyor.', absentNote: 'Tarayıcı hangi kaynakların yükleneceğini kısıtlayamıyor; XSS ve içerik enjeksiyonuna karşı temel savunma yok.' },
  { key: 'xfo', header: 'X-Frame-Options', hdr: 'x-frame-options', presentNote: 'Sayfa yabancı iframe’lere gömülemiyor; clickjacking engelli.', absentNote: 'Sayfa başka bir sitenin iframe’ine gömülebilir; clickjacking ile kullanıcı kandırılabilir.' },
  { key: 'xcto', header: 'X-Content-Type-Options', hdr: 'x-content-type-options', presentNote: 'MIME-sniffing kapalı; içerik beyan edilen türde işleniyor.', absentNote: 'Tarayıcı içerik türünü tahmin edebilir (MIME-sniffing); yüklenen dosyalar script gibi çalıştırılabilir.' },
  { key: 'referrer', header: 'Referrer-Policy', hdr: 'referrer-policy', presentNote: 'Referrer paylaşımı sınırlandırılmış.', absentNote: 'Dış bağlantılara tam URL (Referer) gönderilir; oturum/gizlilik bilgisi sızabilir.' },
  { key: 'permissions', header: 'Permissions-Policy', hdr: 'permissions-policy', presentNote: 'Tarayıcı API’leri (kamera/mikrofon/konum) kısıtlı.', absentNote: 'Kamera/mikrofon/konum gibi hassas API’ler kısıtlanmamış; üçüncü taraf içerik kötüye kullanabilir.' },
  { key: 'xxss', header: 'X-XSS-Protection', hdr: 'x-xss-protection', presentNote: 'Eski tarayıcı XSS filtresi tanımlı (savunma derinliği).', absentNote: 'Eski tarayıcı XSS filtresi ayarlı değil (modern tarayıcılarda kritik değildir; asıl koruma CSP’dir).' },
  { key: 'ctype', header: 'Content-Type', hdr: 'content-type', presentNote: '', absentNote: 'Content-Type belirtilmemiş; tarayıcı içerik türünü tahmin etmek zorunda kalır.' },
];

const RISK_WORD = { low: 'Düşük', medium: 'Orta', high: 'Yüksek' } as const;

/**
 * basit_tarama raporunu KOD-toplanmis kanittan uretir. Ana sayfaya ulasilamazsa null doner.
 */
export async function generateBasitReport(hostname: string): Promise<{ findings: string; fixText: string } | null> {
  const ev = await collectEvidence(hostname);

  // (DÜRÜSTLÜK — c durumu) HEDEFE HİÇ ULAŞILAMADI: ne https(443) ne http ne TLS yanıt verdi.
  // Bu KESİNLİKLE "temiz"/"düşük risk" DEĞİL, "İncelenemedi"dir (assessBasit nötr amber rozet basar).
  if (!ev.reachable && !ev.tls.found) {
    const findings =
      `## YÖNETİCİ ÖZETİ\n\n` +
      `- **Genel risk seviyesi: İncelenemedi** — hedefe (${hostname}) bağlanılamadığı için tarama yürütülemedi.\n` +
      `- Bu sonuç sitenin GÜVENLİ olduğu anlamına GELMEZ; yalnızca kontrollerin çalıştırılamadığını gösterir.\n` +
      `- **Önerilen ilk adım:** Alan adının yayında ve dışarıdan erişilebilir olduğunu doğrulayıp taramayı tekrarlayın.\n\n` +
      `## GENEL DEĞERLENDİRME\n\n**Risk Seviyesi: İncelenemedi**\n\n` +
      `Hedefin 443 (HTTPS) ve 80 (HTTP) portlarına bağlantı kurulamadı (zaman aşımı veya bağlantı reddi). Bu nedenle güvenlik başlıkları ve TLS gibi pasif kontroller çalıştırılamadı. Alan adı doğru ve yayında ise bir güvenlik duvarı/erişim kısıtı taramayı engelliyor olabilir.\n\n` +
      `## TARAMA DURUMU\n\nBu tarama **tamamlanamadı**: hedefe ulaşılamadı ve hiçbir kontrol veri toplayamadı. Bu rapor bir "temiz/güvenli" sonucu **DEĞİLDİR**; erişim sağlanınca yeniden taranmalıdır.\n`;
    return { findings, fixText: '' };
  }

  const { tech, disclosure } = detectTech(ev.headers, ev.html);
  const isSpa = tech.some((t) => /Vite|React|SPA/i.test(t));
  const httpOnly = ev.reachable && !ev.httpsWorks; // https yok, http var -> https_missing bulgusu

  const absent = new Set<SecKey>();
  for (const k of SEC_KEYS) {
    const row = HEADER_ROWS.find((r) => r.key === k)!;
    if (!ev.headers.has(row.hdr)) absent.add(k);
  }
  // (BÖLÜM 1 — ÇOK-SAYFA KAPSAMI) AYNI kontrolleri (güvenlik başlıkları + sürüm imzası) ana sayfa
  // DIŞINDA keşfedilen sayfalarda da uygula. PAKET FARKLILAŞMASI KORUNUR: HÂLÂ yalnız header/TLS/
  // sürüm imzası — CORS/çerez/CSP/DNS/hassas-dosya EKLENMEZ (bunlar Dış Yüzey'e özeldir). Yalnız
  // GET-çekme; hiçbir prob/payload gönderilmez.
  const pages = await collectPages(hostname, 12);
  const pageCount = Math.max(1, pages.length);
  const allTech = new Set<string>(tech);
  const headerAbsentCount = new Map<SecKey, number>(); // kaç sayfada eksik
  for (const pg of pages) {
    for (const k of SEC_KEYS) { const row = HEADER_ROWS.find((r) => r.key === k)!; if (!pg.headers.has(row.hdr)) headerAbsentCount.set(k, (headerAbsentCount.get(k) ?? 0) + 1); }
    detectTech(pg.headers, pg.html).tech.forEach((t) => allTech.add(t));
  }
  // Sayfaya-ÖZGÜ sapma: ana sayfada MEVCUT ama bazı alt sayfalarda EKSİK kritik başlık(lar).
  const perPageMissing: string[] = [];
  if (pageCount > 1) {
    for (const k of ['csp', 'xfo'] as SecKey[]) {
      const row = HEADER_ROWS.find((r) => r.key === k)!;
      const absentOn = headerAbsentCount.get(k) ?? 0;
      if (ev.headers.has(row.hdr) && absentOn > 0) perPageMissing.push(`${row.header} (${absentOn}/${pageCount} sayfada)`);
    }
  }
  const cov = (k: SecKey) => (pageCount > 1 ? ` (${headerAbsentCount.get(k) ?? pageCount}/${pageCount} taranan sayfada eksik)` : '');

  // http-only (şifresiz iletişim) TEK BAŞINA ciddi bir bulgudur -> genel risk en az Yüksek.
  // (HATA 4) EOL/eski yazılım imzası -> GERÇEK bulgu (bilgi metni değil). Sürüm imzasından türer.
  // ÇOK-SAYFA: sürüm imzası birden fazla sayfanın BİRLEŞİMİNDEN (bir sürüm yalnız alt sayfada olabilir).
  const eolRisks = detectOutdatedSoftware([...allTech]);
  const eolRank = eolRisks.some((r) => r.sev === 'Yüksek') ? 2 : eolRisks.some((r) => r.sev === 'Orta') ? 1 : 0;
  const baseLevel = httpOnly ? 'high' : riskLevel(absent, ev.tls);
  const level: 'low' | 'medium' | 'high' =
    eolRank > ({ low: 0, medium: 1, high: 2 } as const)[baseLevel] ? (eolRank === 2 ? 'high' : 'medium') : baseLevel;
  const missingSec = SEC_KEYS.filter((k) => absent.has(k)).map((k) => HEADER_ROWS.find((r) => r.key === k)!.header);

  // Tablo
  const tableRows = HEADER_ROWS.map((r) => {
    const present = ev.headers.has(r.hdr);
    let note = present ? r.presentNote : r.absentNote;
    if (r.key === 'ctype' && present) note = ev.headers.get('content-type') ?? 'Belirtilmiş.';
    // CSP/SPA baglami: somut deger katar (Grok: "CSP eksikligi SPA'da XSS riskini artirir")
    if (r.key === 'csp' && !present && isSpa) note += ' Bu site bir SPA (JavaScript ağırlıklı) olduğundan CSP eksikliği XSS etkisini belirgin şekilde büyütür.';
    return `| ${r.header} | ${present ? 'Var' : 'Yok'} | ${note} |`;
  }).join('\n');

  // TLS
  let tlsSection: string;
  const tlsInf = ev.tls;
  if (!tlsInf.found) {
    tlsSection = httpOnly
      ? `⚠️ Bu hedef **HTTPS (443) üzerinden yanıt vermedi**; geçerli bir TLS sertifikası bulunamadı. Site yalnızca **şifresiz HTTP** üzerinden yayında (bkz. Tespit Edilen Riskler → “HTTPS desteklenmiyor”). Aşağıdaki başlık kontrolleri http:// üzerinden yürütülmüştür.`
      : 'TLS sertifika bilgisi elde edilemedi (443 portuna güvenli bağlantı kurulamadı).';
  } else {
    const l: string[] = [];
    l.push(`- **Geçerlilik:** ${tlsInf.daysLeft != null ? (tlsInf.daysLeft >= 0 ? `Geçerli, ${tlsInf.daysLeft} gün kaldı` : `SÜRESİ DOLMUŞ (${Math.abs(tlsInf.daysLeft)} gün önce)`) : 'Belirlenemedi'}${tlsInf.notAfter ? ` (bitiş: ${tlsInf.notAfter})` : ''}`);
    if (tlsInf.hostnameMatch === false) l.push(`- **Hostname eşleşmesi:** ⚠️ Sertifika ${hostname} ile eşleşmiyor${tlsInf.cn ? ` (sertifika sahibi: ${tlsInf.cn})` : ''}${tlsInf.san.length ? `; kapsanan adlar: ${tlsInf.san.slice(0, 6).join(', ')}` : ''}. Tarayıcı güvenlik uyarısı verebilir.`);
    else if (tlsInf.hostnameMatch === true) {
      const multi = tlsInf.cn && tlsInf.cn.toLowerCase() !== hostname.toLowerCase();
      l.push(`- **Hostname eşleşmesi:** Uyumlu${multi ? ` (çok alanlı sertifika; ${hostname} kapsanıyor)` : ''}.`);
    }
    if (tlsInf.issuer) l.push(`- **Veren (issuer):** ${tlsInf.issuer}`);
    if (tlsInf.protocol) l.push(`- **TLS sürümü:** ${tlsInf.protocol}${/TLSv1\.[01]$/.test(tlsInf.protocol) ? ' — ⚠️ eski/zayıf sürüm, TLS 1.2+ önerilir' : ''}`);
    if (tlsInf.cipher) l.push(`- **Cipher:** ${tlsInf.cipher}`);
    if (tlsInf.daysLeft != null && tlsInf.daysLeft >= 0 && tlsInf.daysLeft < 45) l.push('- ⚠️ **Uyarı:** Sertifika 45 günden kısa sürede sona eriyor; kesinti yaşamamak için yenilemeyi planlayın.');
    tlsSection = l.join('\n');
  }

  // Teknoloji
  const techSection = tech.length ? tech.map((t) => `- ${t}`).join('\n') : '- Yanıt başlıkları ve ana sayfa HTML’inde belirgin bir teknoloji imzası pasif olarak gözlemlenmedi.';

  // Riskler — MASTER TABLO + ZAFİYET DAĞILIMINA girmesi için ŞİDDET KOLONLU tablo (bullet değil).
  // parseFindings (pdf.ts) yalnız şiddet-kolonlu tabloları sayar; böylece https_missing/eksik başlıklar
  // "Temiz" değil GERÇEK bulgu olarak dağılıma/master'a düşer.
  const risks: Array<{ bulgu: string; sev: string; aciklama: string }> = [];
  if (httpOnly) risks.push({ bulgu: 'HTTPS desteklenmiyor (şifresiz iletişim)', sev: 'Yüksek', aciklama: `Site HTTPS'e yanıt vermiyor; sayfaya gelen/giden tüm trafik şifresiz (düz metin) taşınıyor — aynı ağdaki bir saldırgan trafiği dinleyebilir, oturum/şifre çalabilir veya içeriği değiştirebilir. Tarama http:// üzerinden yürütüldü.` });
  if (tlsInf.hostnameMatch === false) risks.push({ bulgu: 'TLS hostname uyuşmazlığı', sev: 'Yüksek', aciklama: `Sertifika ${hostname} adına düzenlenmemiş; ziyaretçiler tarayıcı güvenlik uyarısıyla karşılaşabilir ve siteye güven azalır.` });
  if (tlsInf.daysLeft != null && tlsInf.daysLeft < 0) risks.push({ bulgu: 'TLS sertifikası süresi dolmuş', sev: 'Yüksek', aciklama: 'Site tarayıcılarca güvensiz kabul edilir; ziyaretçi kaybına yol açar.' });
  for (const e of eolRisks) risks.push({ bulgu: e.bulgu, sev: e.sev, aciklama: e.aciklama });
  const keyOf = (headerName: string): SecKey | undefined => HEADER_ROWS.find((r) => r.header === headerName)?.key as SecKey | undefined;
  const covFor = (headerNames: string[]): string => {
    if (pageCount <= 1) return '';
    const counts = headerNames.map((h) => { const k = keyOf(h); return k ? headerAbsentCount.get(k) ?? pageCount : pageCount; });
    const n = Math.max(...counts);
    return ` Taranan ${pageCount} benzersiz sayfanın ${n === pageCount ? 'TAMAMINDA' : `${n}/${pageCount}'sinde`} eksik.`;
  };
  const critList: string[] = missingSec.filter((h) => h === 'Content-Security-Policy' || h === 'X-Frame-Options');
  if (critList.length) {
    const spaNote = isSpa && critList.includes('Content-Security-Policy') ? ' Site JavaScript ağırlıklı bir SPA olduğundan CSP eksikliği XSS etkisini büyütür; önceliklendirilmesi önerilir.' : '';
    risks.push({ bulgu: `Kritik güvenlik başlıkları eksik (${critList.join(', ')})`, sev: 'Orta', aciklama: `XSS ve/veya clickjacking saldırılarına karşı tarayıcı seviyesinde savunma bulunmuyor.${covFor(critList)}${spaNote}` });
  }
  const otherMissing = missingSec.filter((h) => !critList.includes(h));
  if (otherMissing.length) risks.push({ bulgu: `Ek güvenlik başlıkları eksik (${otherMissing.join(', ')})`, sev: 'Orta', aciklama: `Savunma derinliği zayıf; tek tek düşük etkili olsa da birlikte saldırı yüzeyini genişletir.${covFor(otherMissing)}` });
  // (BÖLÜM 1) SAYFAYA-ÖZGÜ tutarsızlık: ana sayfada MEVCUT bir kritik başlık bazı alt sayfalarda EKSİK.
  if (perPageMissing.length) risks.push({ bulgu: 'Sayfaya özgü güvenlik başlığı tutarsızlığı', sev: 'Orta', aciklama: `Ana sayfada mevcut olan bir/birkaç kritik başlık bazı iç sayfalarda gönderilmiyor: ${perPageMissing.join(', ')}. Başlık politikası tüm yollarda tutarlı uygulanmalı (ör. sunucu bloğu genelinde, tek uç noktada değil).` });
  if (disclosure.length) risks.push({ bulgu: 'Üçüncü taraf servis kimlikleri', sev: 'Bilgilendirme', aciklama: `Ana sayfada ${disclosure.join('; ')} açıkça görülüyor. İstismar edilebilir açık değildir; yalnızca dış servis bağımlılıklarına dair farkındalık amacıyla listelenmiştir.` });

  const riskSection = risks.length
    ? `| Bulgu | Şiddet | Açıklama |\n|-------|--------|----------|\n${risks.map((r) => `| ${r.bulgu} | ${r.sev} | ${r.aciklama.replace(/\|/g, '\\|')} |`).join('\n')}`
    : 'Belirgin bir güvenlik riski öne çıkmadı; rapor yalnızca küçük iyileştirme fırsatlarını listeler.';

  // Yonetici ozeti
  const tlsProblem = tlsInf.hostnameMatch === false ? 'TLS sertifikası bu alan adıyla eşleşmiyor' : tlsInf.daysLeft != null && tlsInf.daysLeft < 0 ? 'TLS sertifikasının süresi dolmuş' : '';
  // EOL, seviyeyi sürükleyen etkense (TLS/başlık sorunu yokken) badge gerekçesi EOL'i söylemeli.
  const eolDrives = eolRank > ({ low: 0, medium: 1, high: 2 } as const)[baseLevel];
  const riskReason =
    httpOnly
      ? 'site HTTPS desteklemiyor; iletişim şifresiz (düz metin) taşınıyor — dinlenebilir/değiştirilebilir. Öncelikli olarak HTTPS’e geçilmelidir.'
      : eolDrives
        ? 'eski/desteksiz yazılım sürümü ifşa ediliyor (aşağıdaki bulgu tablosunda); bilinen güvenlik açıkları yamasız kalabilir — güncel, desteklenen sürüme yükseltilmelidir.'
        : level === 'high'
          ? (tlsProblem ? `${tlsProblem} — ziyaretçilere doğrudan tarayıcı güvenlik uyarısı gösterebilir.` : 'öncelikli giderilmesi gereken yüksek etkili bir bulgu tespit edildi (aşağıda).')
          : level === 'medium'
            ? 'öncelikli giderilmesi önerilen önemli güvenlik başlığı eksiklikleri var; taşıma güvenliği (TLS) sağlam.'
            : 'ciddi/kritik bir açık öne çıkmadı; yalnızca küçük iyileştirme fırsatları var.';
  const bullets: string[] = [];
  bullets.push(`- **Genel risk seviyesi: ${RISK_WORD[level]}** — ${riskReason}`);
  if (httpOnly) bullets.push('- ⚠️ Bu hedef HTTPS (443) üzerinden yanıt vermedi; tarama **http:// üzerinden** yürütüldü. HTTPS eksikliği başlı başına bir bulgudur (aşağıda).');
  if (missingSec.length) bullets.push(`- ${missingSec.length}/6 önemli güvenlik başlığı eksik: ${missingSec.join(', ')}.`);
  if (pageCount > 1) bullets.push(`- **Kapsam:** Güvenlik başlığı ve sürüm imzası kontrolleri, ana sayfa dâhil **${pageCount} benzersiz sayfada** yürütüldü (tek sayfa değil).`);
  else bullets.push('- Önerilen güvenlik başlıklarının tamamı mevcut.');
  if (tlsInf.found) {
    const tlsState =
      tlsInf.hostnameMatch === false
        ? '⚠️ sertifika hostname uyuşmazlığı (bkz. Kontrol Özeti)'
        : tlsInf.daysLeft != null && tlsInf.daysLeft < 0
        ? `⚠️ sertifika SÜRESİ DOLMUŞ (${Math.abs(tlsInf.daysLeft)} gün önce — bkz. Kontrol Özeti)`
        : tlsInf.daysLeft != null && tlsInf.daysLeft >= 0
        ? `sertifikası geçerli (${tlsInf.daysLeft} gün)`
        : 'sertifika geçerlilik durumu belirlenemedi';
    bullets.push(`- TLS ${tlsState}${tlsInf.protocol ? `, ${tlsInf.protocol}` : ''}.`);
  }
  bullets.push('- **Önerilen ilk adım:** ' + (httpOnly ? 'Geçerli bir TLS sertifikası kurup tüm trafiği HTTPS’e taşıyın; ' : 'Eksik HTTP güvenlik başlıklarını sunucu yapılandırmasına ekleyin; ') + 'adım adım hazır komutlar "AI Çözüm Önerileri" eklentisinde sunulur.');

  const genel =
    httpOnly
      ? 'Bu hedef HTTPS üzerinden yanıt vermiyor; iletişim şifresiz (düz metin) HTTP ile yürüyor. Bu, aynı ağdaki bir saldırganın trafiği dinlemesine/değiştirmesine ve oturum/şifre çalmasına olanak tanıyan ciddi bir eksiktir; modern tarayıcılar siteyi "Güvenli değil" olarak işaretler. Öncelik, geçerli bir TLS sertifikasıyla HTTPS’e geçmek ve HTTP→HTTPS yönlendirmesi + HSTS eklemektir. Diğer başlık kontrolleri http:// üzerinden yürütülmüştür.'
      : level === 'high'
        ? 'Ziyaretçilere doğrudan güvenlik uyarısı gösterebilecek bir TLS sertifikası sorunu tespit edildi; acilen giderilmesi önerilir. Ayrıca eksik güvenlik başlıkları savunma derinliğini zayıflatıyor.'
        : level === 'medium'
          ? 'Öncelikli giderilmesi önerilen önemli güvenlik başlığı eksiklikleri var; taşıma güvenliği (TLS/HTTPS) genel olarak sağlam. Eksik başlıklar tek başına siteyi ele geçirmez ancak XSS/clickjacking gibi saldırıların başarı şansını artırır ve düşük maliyetli sunucu ayarlarıyla kapatılabilir.'
          : 'Ciddi/kritik bir güvenlik açığı öne çıkmadı; rapor öncelikle savunma derinliğini artıracak küçük iyileştirme fırsatlarını listeler.';

  // (TUTARLILIK — disclaimer) Diğer 3 pasif paketle AYNI konumda (Yönetici Özeti'nin hemen altında).
  const disclaimer =
    `> **Kapsam ve sınır:** Bu paket **pasif, GET-tabanlı** bir dış gözlemdir; hiçbir aktif istismar veya prob denenmemiştir. Bir alanda "bulgu yok" ifadesi, aktif test yapılmadığı için **güvenli olduğunu KANITLAMAZ** — yalnızca dışarıdan gözlemlenen yapılandırmanın temiz olduğunu gösterir.\n\n`;

  // (BÖLÜM 2 — POZİTİF GÜVENCE) Diğer 3 pakete ÖLÇEKLİ: yalnız header/TLS/sürüm alanları, üç-durum.
  // "Sorun bulunamadı"yı da şeffaf kıl — SADECE gerçek veriden. Kapsam GENİŞLEMEZ (yeni tür eklenmez).
  const hdrState = missingSec.length
    ? `⚠️ Bulgu var (${missingSec.length}/6 önerilen başlık eksik — yukarıda detaylı)`
    : `✅ Sorun bulunmadı (6/6 önerilen başlık mevcut)`;
  const tlsAssState = httpOnly
    ? '⚠️ Bulgu var (HTTPS yanıt vermedi — şifresiz iletişim)'
    : !tlsInf.found
      ? '⚠️ İncelenemedi (443’e güvenli bağlantı kurulamadı — “temiz” DEĞİL)'
      : tlsInf.hostnameMatch === false || (tlsInf.daysLeft != null && tlsInf.daysLeft < 0)
        ? '⚠️ Bulgu var (sertifika sorunu — yukarıda detaylı)'
        : '✅ Sorun bulunmadı (geçerli sertifika, hostname uyumlu)';
  const verAssState = eolRisks.length
    ? '⚠️ Bulgu var (eski/desteksiz sürüm imzası — yukarıda detaylı)'
    : '✅ Sorun bulunmadı (bilinen eski/EOL sürüm imzası saptanmadı)';
  const assuranceSection =
    `## POZİTİF GÜVENCE — KONTROL EDİLEN ALANLAR\n\n` +
    `Bulgu çıkmayan alanlar da dâhil, Basit Tarama kontrolleri ana sayfa dâhil **${pageCount} benzersiz sayfada** gerçekten çalıştırıldı. Aşağıdaki tablo, "sorun bulunamadı" sonuçlarını da şeffaf biçimde gösterir:\n\n` +
    `| Kontrol Alanı | Sonuç |\n|---------------|-------|\n` +
    `| HTTP güvenlik başlıkları (${pageCount} sayfada) | ${hdrState} |\n` +
    `| TLS / sertifika | ${tlsAssState} |\n` +
    `| Sunucu/yazılım sürüm imzası (${pageCount} sayfada) | ${verAssState} |\n\n` +
    `> **Üç-durum ayrımı (dürüstlük):** ✅ *Sorun bulunmadı* = kontrol çalıştı, temiz çıktı · ⚠️ *Bulgu var* = yukarıda detaylı · ⚠️ *İncelenemedi* = veri toplanamadı (güvenli anlamına GELMEZ).\n\n` +
    `### Bu paket NE kontrol EDER, NE ETMEZ\n\n` +
    `**EDER (pasif — yalnız GET ile sayfa çekme, hiçbir prob/payload gönderilmez):** HTTP güvenlik başlıkları, TLS/sertifika durumu (geçerlilik · hostname · TLS sürümü), sunucu-yazılım sürüm imzası ve bilinen eski/EOL sürüm tespiti — keşfedilen ${pageCount} sayfada.\n\n` +
    `**ETMEZ:** CORS politikası, çerez bayrağı detayı, Content-Security-Policy analizi, DNS/e-posta kayıtları (SPF/DKIM/DMARC) ve açıkta hassas dosya taraması **Dış Yüzey** paketindedir; KVKK/PCI/ISO çerçeve-eşlemesi **Uyum** paketinde; subdomain/API/CVE keşfi **Keşif** paketinde; aktif zafiyet doğrulaması (SQLi/XSS/IDOR prob’u) **Aktif Doğrulama** ve **Tam Kapsamlı Pentest** paketlerinde ele alınır. Bu rapor pasif gözleme dayanır; "bulgu yok", aktif istismar denenmediği için **güvenli olduğunu KANITLAMAZ**.\n\n`;

  const findings =
    `## YÖNETİCİ ÖZETİ\n\n${bullets.join('\n')}\n\n` +
    disclaimer +
    `## GENEL DEĞERLENDİRME\n\n**Risk Seviyesi: ${RISK_WORD[level]}**\n\n${genel}\n\n` +
    `## HTTP GÜVENLİK BAŞLIKLARI\n\n| Başlık | Durum | Açıklama |\n|--------|-------|----------|\n${tableRows}\n\n` +
    `## TLS SERTİFİKA DURUMU\n\n${tlsSection}\n\n` +
    `## SUNUCU / TEKNOLOJİ İMZASI\n\n${techSection}\n\n` +
    `## TESPİT EDİLEN RİSKLER\n\n${riskSection}\n\n` +
    assuranceSection;

  const fixText = buildHeaderFixSuggestions(findings, hostname);
  return { findings, fixText };
}
