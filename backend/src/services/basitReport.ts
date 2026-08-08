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

const FETCH_TIMEOUT_MS = 9000;
const TLS_TIMEOUT_MS = 8000;
const MAX_HTML = 1_500_000;

type Evidence = {
  ok: boolean;
  status?: number;
  headers: Map<string, string>; // lowercased
  html: string;
  tls: TlsInfo;
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

// --- HTTP basliklari + HTML'i dogrudan cek ------------------------------------------
async function fetchHome(host: string): Promise<{ ok: boolean; status?: number; headers: Map<string, string>; html: string }> {
  const headers = new Map<string, string>();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(`https://${host}/`, {
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

async function collectEvidence(host: string): Promise<Evidence> {
  const [home, tlsInfo] = await Promise.all([fetchHome(host), fetchTls(host)]);
  return { ok: home.ok, status: home.status, headers: home.headers, html: home.html, tls: tlsInfo };
}

// --- Teknoloji / bilgi ifsasi -------------------------------------------------------
function detectTech(headers: Map<string, string>, html: string): { tech: string[]; disclosure: string[] } {
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

function riskLevel(absent: Set<SecKey>): 'low' | 'medium' | 'high' {
  const critMissing = (absent.has('csp') ? 1 : 0) + (absent.has('xfo') ? 1 : 0);
  const otherAbsent = [...absent].filter((k) => k !== 'csp' && k !== 'xfo').length;
  if (critMissing === 2 && otherAbsent > 2) return 'high';
  if (critMissing >= 1) return 'medium';
  if (otherAbsent >= 3) return 'medium';
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
  if (!ev.ok && !ev.tls.found) return null; // ne HTTP ne TLS -> kanit yok, fallback

  const { tech, disclosure } = detectTech(ev.headers, ev.html);
  const isSpa = tech.some((t) => /Vite|React|SPA/i.test(t));

  const absent = new Set<SecKey>();
  for (const k of SEC_KEYS) {
    const row = HEADER_ROWS.find((r) => r.key === k)!;
    if (!ev.headers.has(row.hdr)) absent.add(k);
  }
  const level = riskLevel(absent);
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
    tlsSection = 'TLS sertifika bilgisi elde edilemedi (443 portuna güvenli bağlantı kurulamadı).';
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

  // Riskler (siddet genel seviyeyle tutarli)
  const riskItems: string[] = [];
  if (tlsInf.hostnameMatch === false) riskItems.push(`- **Yüksek — TLS hostname uyuşmazlığı:** Sertifika ${hostname} adına düzenlenmemiş. Ziyaretçiler tarayıcı güvenlik uyarısıyla karşılaşabilir ve siteye güveni azalır.`);
  if (tlsInf.daysLeft != null && tlsInf.daysLeft < 0) riskItems.push('- **Yüksek — Sertifika süresi dolmuş:** Site tarayıcılarca güvensiz kabul edilir; ziyaretçi kaybına yol açar.');
  const critList: string[] = missingSec.filter((h) => h === 'Content-Security-Policy' || h === 'X-Frame-Options');
  if (critList.length) {
    const sev = critList.length === 2 ? 'Yüksek' : 'Orta';
    const spaNote = isSpa && critList.includes('Content-Security-Policy') ? ' Site JavaScript ağırlıklı bir SPA olduğundan XSS riski daha da kritiktir.' : '';
    riskItems.push(`- **${sev} — Kritik güvenlik başlıkları eksik (${critList.join(', ')}):** XSS ve/veya clickjacking saldırılarına karşı tarayıcı seviyesinde savunma bulunmuyor.${spaNote}`);
  }
  const otherMissing = missingSec.filter((h) => !critList.includes(h));
  if (otherMissing.length) riskItems.push(`- **Orta — Ek güvenlik başlıkları eksik (${otherMissing.join(', ')}):** Savunma derinliği zayıf; tek tek düşük etkili olsa da birlikte saldırı yüzeyini genişletir.`);
  if (disclosure.length) riskItems.push(`- **Bilgilendirme — Üçüncü taraf servis kimlikleri:** Ana sayfada ${disclosure.join('; ')} açıkça görülüyor. Bunlar istismar edilebilir açık değildir; yalnızca dış servis bağımlılıklarına dair farkındalık amacıyla listelenmiştir.`);
  if (!riskItems.length) riskItems.push('- Belirgin bir güvenlik riski öne çıkmadı; rapor yalnızca küçük iyileştirme fırsatlarını listeler.');

  // Yonetici ozeti
  const bullets: string[] = [];
  bullets.push(`- **Genel risk seviyesi: ${RISK_WORD[level]}** — ${level === 'high' ? 'birden fazla kritik başlık ve/veya sertifika sorunu tespit edildi.' : level === 'medium' ? 'giderilmesi önerilen önemli güvenlik başlığı eksiklikleri var; taşıma güvenliği (TLS) genelde sağlam.' : 'ciddi/kritik bir açık öne çıkmadı.'}`);
  if (missingSec.length) bullets.push(`- ${missingSec.length}/6 önemli güvenlik başlığı eksik: ${missingSec.join(', ')}.`);
  else bullets.push('- Önerilen güvenlik başlıklarının tamamı mevcut.');
  if (tlsInf.found) bullets.push(`- TLS ${tlsInf.hostnameMatch === false ? '⚠️ hostname uyuşmazlığı' : tlsInf.daysLeft != null && tlsInf.daysLeft >= 0 ? `geçerli (${tlsInf.daysLeft} gün)` : 'geçerli'}${tlsInf.protocol ? `, ${tlsInf.protocol}` : ''}.`);
  bullets.push('- **Önerilen ilk adım:** Eksik HTTP güvenlik başlıklarını sunucu yapılandırmasına ekleyin (hazır komutlar için "AI Çözüm Önerileri" bölümüne bakın).');

  const genel =
    level === 'high'
      ? 'Öncelikli ele alınması gereken kritik güvenlik başlığı eksiklikleri ve/veya sertifika sorunları var. Bunlar tek başına siteyi ele geçirmez ancak XSS/clickjacking gibi saldırıların başarı şansını belirgin şekilde artırır.'
      : level === 'medium'
        ? 'Kısa vadede giderilmesi önerilen önemli güvenlik başlığı eksiklikleri var; taşıma güvenliği (TLS/HTTPS) genel olarak sağlam. Eksik başlıklar düşük maliyetli sunucu ayarlarıyla kapatılabilir.'
        : 'Ciddi/kritik bir güvenlik açığı öne çıkmadı; rapor öncelikle savunma derinliğini artıracak küçük iyileştirme fırsatlarını listeler.';

  const findings =
    `## YÖNETİCİ ÖZETİ\n\n${bullets.join('\n')}\n\n` +
    `## GENEL DEĞERLENDİRME\n\n**Risk Seviyesi: ${RISK_WORD[level]}**\n\n${genel}\n\n` +
    `## HTTP GÜVENLİK BAŞLIKLARI\n\n| Başlık | Durum | Açıklama |\n|--------|-------|----------|\n${tableRows}\n\n` +
    `## TLS SERTİFİKA DURUMU\n\n${tlsSection}\n\n` +
    `## SUNUCU / TEKNOLOJİ İMZASI\n\n${techSection}\n\n` +
    `## TESPİT EDİLEN RİSKLER\n\n${riskItems.join('\n')}\n`;

  const fixText = buildHeaderFixSuggestions(findings, hostname);
  return { findings, fixText };
}
