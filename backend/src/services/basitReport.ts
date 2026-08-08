/**
 * (basit_tarama) DETERMINISTIK RAPOR URETICI — ajanin anlatisina GUVENMEZ.
 *
 * Neden: PentAGI ajani bu kucuk/sabit pasif kontrol listesi icin temiz nihai raporu
 * GUVENILIR sekilde uretemiyor (erken durma, surec dili, "raporun tarifi" vb. tekrarlayan
 * bozulmalar). Oysa veri toplama (curl -I, openssl s_client, HTML cekme) calisiyor. Bu modul
 * ajanin topladigi HAM cikti'yi (toolCallLogs.result) parse edip raporu KOD ile yazar:
 * HTTP guvenlik basliklari tablosu + TLS + teknoloji imzasi + risk + yonetici ozeti. Boylece
 * rapor HER ZAMAN tutarli/profesyonel olur; LLM anlatisindan kaynakli bozulma sinifi biter.
 * Ek LLM/maliyet YOK — yalniz zaten toplanmis veriyi bicimlendirir.
 *
 * Yetersiz kanit (ajan curl calistirmamis) -> null doner; cagiran taraf eski ajan/ham-kanit
 * yoluna duser.
 */
import { buildHeaderFixSuggestions } from './fixSuggestions.js';

export type ToolCallLog = { name?: string | null; args?: string | null; result?: string | null };

type HeaderMap = Map<string, string>; // lowercased header name -> value

// --- HTTP baslik blok(lar)ini ayikla -------------------------------------------------
// Bir curl -I / -i ciktisinda birden fazla HTTP yaniti (301 redirect + 200) olabilir.
// Her blogu (status + headerlar) cikar; EN COK taninan basliga sahip 2xx blogu sec (asil
// homepage yaniti — redirect degil).
function extractHeaderBlocks(text: string): Array<{ status: number; headers: HeaderMap }> {
  const blocks: Array<{ status: number; headers: HeaderMap }> = [];
  const lines = text.split(/\r?\n/);
  let cur: { status: number; headers: HeaderMap } | null = null;
  for (const raw of lines) {
    const line = raw.replace(/\s+$/, '');
    const statusM = line.match(/^HTTP\/[\d.]+\s+(\d{3})/i);
    if (statusM) {
      if (cur) blocks.push(cur);
      cur = { status: Number(statusM[1]), headers: new Map() };
      continue;
    }
    if (!cur) continue;
    const hm = line.match(/^([A-Za-z][A-Za-z0-9-]*)\s*:\s?(.*)$/);
    if (hm) {
      cur.headers.set(hm[1].toLowerCase(), hm[2].trim());
    } else if (line.trim() === '') {
      // bos satir blogu bitirir (govde baslayabilir)
      blocks.push(cur);
      cur = null;
    }
    // header-di$i satir (govde) -> gormezden gel; bir sonraki HTTP/ blok resetler
  }
  if (cur) blocks.push(cur);
  return blocks.filter((b) => b.headers.size > 0);
}

// Tum loglardan en iyi HTTP baslik setini (asil homepage 200 yaniti) sec.
function collectHeaders(logs: ToolCallLog[]): HeaderMap | null {
  const all: Array<{ status: number; headers: HeaderMap }> = [];
  for (const l of logs) {
    const r = l.result ?? '';
    if (!/HTTP\/[\d.]+\s+\d{3}/i.test(r)) continue;
    all.push(...extractHeaderBlocks(r));
  }
  if (!all.length) return null;
  const twoxx = all.filter((b) => b.status >= 200 && b.status < 300);
  const pool = twoxx.length ? twoxx : all;
  pool.sort((a, b) => b.headers.size - a.headers.size);
  return pool[0].headers;
}

// --- TLS sertifika ------------------------------------------------------------------
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

function hostMatches(host: string, cn: string | undefined, san: string[]): boolean {
  const names = [cn, ...san].filter(Boolean) as string[];
  const h = host.toLowerCase();
  return names.some((n) => {
    const name = n.toLowerCase().trim();
    if (name === h) return true;
    if (name.startsWith('*.')) {
      const base = name.slice(2);
      // wildcard yalniz tek seviye: sub.example.com, example.com'un *.example.com'u ile eslesir
      const hParts = h.split('.');
      return hParts.length >= 2 && hParts.slice(1).join('.') === base;
    }
    return false;
  });
}

function parseTls(logs: ToolCallLog[], hostname: string): TlsInfo {
  const chunks = logs
    .map((l) => l.result ?? '')
    .filter((r) => /notAfter=|-----BEGIN CERTIFICATE-----|Certificate chain|subject=|Protocol\s*:|Cipher\s*:|Verify return code/i.test(r));
  const text = chunks.join('\n');
  if (!text.trim()) return { found: false, san: [] };

  const notAfter = text.match(/notAfter=(.+)/i)?.[1]?.trim();
  const subjectLine = text.match(/subject=([^\n]+)/i)?.[1] ?? '';
  const cn = subjectLine.match(/CN\s*=\s*([^,\/\n]+)/i)?.[1]?.trim();
  const issuerLine = text.match(/issuer=([^\n]+)/i)?.[1] ?? '';
  const issuerO = issuerLine.match(/O\s*=\s*([^,\/\n]+)/i)?.[1]?.trim();
  const issuerCN = issuerLine.match(/CN\s*=\s*([^,\/\n]+)/i)?.[1]?.trim();
  const issuer = [issuerO, issuerCN].filter(Boolean).join(' — ') || undefined;
  const san = Array.from(text.matchAll(/DNS:([^\s,]+)/gi)).map((m) => m[1]);
  const protocol = text.match(/Protocol\s*:\s*(\S+)/i)?.[1] || text.match(/(TLSv1\.[0-3])/)?.[1];
  const cipher = text.match(/Cipher\s*:\s*(\S+)/i)?.[1] || text.match(/Cipher is\s+(\S+)/i)?.[1];

  let daysLeft: number | undefined;
  if (notAfter) {
    const exp = new Date(notAfter);
    if (!isNaN(exp.getTime())) daysLeft = Math.round((exp.getTime() - Date.now()) / 86400000);
  }
  const hostnameMatch = cn || san.length ? hostMatches(hostname, cn, san) : undefined;
  return { found: true, cn, san, issuer, notAfter, daysLeft, protocol, cipher, hostnameMatch };
}

// --- Teknoloji / bilgi ifsasi -------------------------------------------------------
function detectTech(headers: HeaderMap | null, html: string): { tech: string[]; disclosure: string[] } {
  const tech: string[] = [];
  const disclosure: string[] = [];
  const add = (arr: string[], v: string) => { if (v && !arr.includes(v)) arr.push(v); };

  if (headers) {
    const server = headers.get('server');
    if (server) add(tech, `Sunucu: ${server}`);
    const via = headers.get('via');
    const servedBy = headers.get('x-served-by') || headers.get('x-cache');
    if (/fastly/i.test(server ?? '') || /fastly/i.test(via ?? '') || /cache-/i.test(servedBy ?? '')) add(tech, 'CDN: Fastly');
    if (headers.get('cf-ray') || /cloudflare/i.test(server ?? '')) add(tech, 'CDN: Cloudflare');
    if (headers.get('x-vercel-id')) add(tech, 'Barındırma: Vercel');
    const xpb = headers.get('x-powered-by');
    if (xpb) add(tech, `X-Powered-By: ${xpb}`);
    const altsvc = headers.get('alt-svc');
    if (/h3/i.test(altsvc ?? '')) add(tech, 'HTTP/3 desteği (Alt-Svc)');
  }

  const H = html || '';
  if (/firebaseapp\.com|firestore\.googleapis\.com|firebasestorage/i.test(H)) add(tech, 'Google Firebase / Firestore');
  if (/googletagmanager\.com|GTM-[A-Z0-9]+/i.test(H)) add(tech, 'Google Tag Manager');
  if (/gtag\/js|google-analytics\.com|\bG-[A-Z0-9]{6,}\b/.test(H)) add(tech, 'Google Analytics');
  if (/connect\.facebook\.net|fbq\(/i.test(H)) add(tech, 'Facebook Pixel');
  if (/clarity\.ms|clarity\("/i.test(H)) add(tech, 'Microsoft Clarity');
  if (/\/assets\/index-[\w-]+\.js/i.test(H)) add(tech, 'Vite tabanlı SPA');
  if (/data-reactroot|react(?:-dom)?[.@]/i.test(H)) add(tech, 'React');

  // Bilgi ifsasi (dusuk/bilgilendirme): ID'ler + preconnect alanlari
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

// --- Risk (assessBasit ile AYNI kural — rozet ile tutarli) --------------------------
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

// Tablo satirlari + aciklamalar
const HEADER_ROWS: Array<{ key: SecKey | 'ctype' | 'xxss'; header: string; hdrName: string; presentNote: string; absentNote: string }> = [
  { key: 'hsts', header: 'Strict-Transport-Security', hdrName: 'strict-transport-security', presentNote: 'HTTPS zorunlu; SSL-stripping/MITM’e karşı koruma sağlar.', absentNote: 'HTTPS zorunluluğu yok; SSL-stripping/MITM riskini artırır.' },
  { key: 'csp', header: 'Content-Security-Policy', hdrName: 'content-security-policy', presentNote: 'XSS/içerik enjeksiyonu azaltma katmanı aktif.', absentNote: 'XSS ve içerik enjeksiyonuna karşı tarayıcı savunması yok.' },
  { key: 'xfo', header: 'X-Frame-Options', hdrName: 'x-frame-options', presentNote: 'Clickjacking koruması mevcut.', absentNote: 'Clickjacking’e açık; sayfa iframe’e gömülebilir.' },
  { key: 'xcto', header: 'X-Content-Type-Options', hdrName: 'x-content-type-options', presentNote: 'MIME-sniffing engelli.', absentNote: 'MIME-sniffing mümkün; içerik yanlış yorumlanabilir.' },
  { key: 'referrer', header: 'Referrer-Policy', hdrName: 'referrer-policy', presentNote: 'Referrer sızıntısı kontrol altında.', absentNote: 'Referrer bilgisi dış kaynaklara sızabilir.' },
  { key: 'permissions', header: 'Permissions-Policy', hdrName: 'permissions-policy', presentNote: 'Tarayıcı API’leri (kamera/mikrofon/konum) kısıtlı.', absentNote: 'Kamera/mikrofon/konum vb. API’ler kısıtlanmamış.' },
  { key: 'xxss', header: 'X-XSS-Protection', hdrName: 'x-xss-protection', presentNote: 'Eski tarayıcı XSS filtresi açık (savunma derinliği).', absentNote: 'Eski tarayıcı XSS filtresi ayarlı değil (modern tarayıcılarda kritik değildir).' },
  { key: 'ctype', header: 'Content-Type', hdrName: 'content-type', presentNote: '', absentNote: 'Content-Type belirtilmemiş.' },
];

const RISK_WORD = { low: 'Düşük', medium: 'Orta', high: 'Yüksek' } as const;

/**
 * Ham toolCallLogs'tan basit_tarama raporunu (findings markdown) + fix onerilerini uretir.
 * Yeterli kanit (en az HTTP basliklari) yoksa null doner.
 */
export function buildBasitReportFromEvidence(
  logs: ToolCallLog[],
  hostname: string,
): { findings: string; fixText: string } | null {
  const headers = collectHeaders(logs);
  if (!headers) return null; // HTTP basligi yok -> deterministik rapor uretilemez

  const html = logs.map((l) => l.result ?? '').find((r) => /<!doctype html|<html[\s>]/i.test(r)) ?? '';
  const tls = parseTls(logs, hostname);
  const { tech, disclosure } = detectTech(headers, html);

  // Baslik var/yok
  const absent = new Set<SecKey>();
  for (const k of SEC_KEYS) {
    const row = HEADER_ROWS.find((r) => r.key === k)!;
    if (!headers.has(row.hdrName)) absent.add(k);
  }
  const level = riskLevel(absent);
  const missingSec = SEC_KEYS.filter((k) => absent.has(k)).map((k) => HEADER_ROWS.find((r) => r.key === k)!.header);

  // --- Tablo ---
  const tableRows = HEADER_ROWS.map((r) => {
    const present = headers.has(r.hdrName);
    const durum = present ? 'Var' : 'Yok';
    let note = present ? r.presentNote : r.absentNote;
    if (r.key === 'ctype' && present) note = headers.get('content-type') ?? 'Belirtilmiş.';
    return `| ${r.header} | ${durum} | ${note} |`;
  }).join('\n');

  // --- TLS bolumu ---
  let tlsSection: string;
  if (!tls.found) {
    tlsSection = 'TLS sertifika verisi bu taramada elde edilemedi.';
  } else {
    const lines: string[] = [];
    lines.push(`- **Geçerlilik:** ${tls.daysLeft != null ? (tls.daysLeft >= 0 ? `Geçerli, ${tls.daysLeft} gün kaldı` : `SÜRESİ DOLMUŞ (${Math.abs(tls.daysLeft)} gün önce)`) : 'Belirlenemedi'}${tls.notAfter ? ` (bitiş: ${tls.notAfter})` : ''}`);
    if (tls.hostnameMatch === false) lines.push(`- **Hostname eşleşmesi:** ⚠️ Sertifika ${hostname} ile eşleşmiyor${tls.cn ? ` (sertifika sahibi: ${tls.cn})` : ''}${tls.san.length ? `; kapsanan adlar: ${tls.san.slice(0, 6).join(', ')}` : ''}.`);
    else if (tls.hostnameMatch === true) {
      const multi = tls.cn && tls.cn.toLowerCase() !== hostname.toLowerCase();
      lines.push(`- **Hostname eşleşmesi:** Uyumlu${multi ? ` (çok alanlı sertifika; ${hostname} SAN listesinde kapsanıyor)` : ''}.`);
    }
    if (tls.issuer) lines.push(`- **Veren (issuer):** ${tls.issuer}`);
    if (tls.protocol) lines.push(`- **TLS sürümü:** ${tls.protocol}`);
    if (tls.cipher) lines.push(`- **Cipher:** ${tls.cipher}`);
    if (tls.daysLeft != null && tls.daysLeft < 45 && tls.daysLeft >= 0) lines.push('- ⚠️ **Uyarı:** Sertifika 45 günden kısa sürede sona eriyor; yenileme planlanmalı.');
    tlsSection = lines.join('\n');
  }

  // --- Teknoloji ---
  const techSection = tech.length ? tech.map((t) => `- ${t}`).join('\n') : '- Yanıt başlıkları ve ana sayfa HTML’inde belirgin bir teknoloji imzası pasif olarak gözlemlenmedi.';

  // --- Riskler ---
  const riskItems: string[] = [];
  if (tls.hostnameMatch === false) riskItems.push(`- **Yüksek:** TLS sertifikası hostname uyuşmazlığı — sertifika ${hostname} adına düzenlenmemiş. Tarayıcı uyarısı ve güven kaybı riski.`);
  if (tls.daysLeft != null && tls.daysLeft < 0) riskItems.push('- **Yüksek:** TLS sertifikasının süresi dolmuş; site güvenli kabul edilmez.');
  const critList: string[] = missingSec.filter((h) => h === 'Content-Security-Policy' || h === 'X-Frame-Options');
  // Siddet, genel risk seviyesiyle TUTARLI: iki kritik baslik birden eksikse Yüksek, biri eksikse Orta.
  if (critList.length) {
    const sev = critList.length === 2 ? 'Yüksek' : 'Orta';
    riskItems.push(`- **${sev}:** Kritik güvenlik başlıkları eksik (${critList.join(', ')}) — XSS/clickjacking’e karşı savunma zayıf.`);
  }
  const otherMissing = missingSec.filter((h) => !critList.includes(h));
  if (otherMissing.length) riskItems.push(`- **Orta:** Ek güvenlik başlıkları eksik (${otherMissing.join(', ')}).`);
  if (disclosure.length) riskItems.push(`- **Bilgilendirme:** Ana sayfada gözlemlenen üçüncü taraf/servis kimlikleri: ${disclosure.join('; ')}. Bunlar istismar edilebilir bir açık değildir; farkındalık amacıyla listelenmiştir.`);
  if (!riskItems.length) riskItems.push('- Belirgin bir güvenlik riski öne çıkmadı; rapor yalnızca küçük iyileştirme fırsatlarını listeler.');

  // --- Yonetici ozeti ---
  const summaryBullets: string[] = [];
  summaryBullets.push(`- **Genel risk seviyesi: ${RISK_WORD[level]}** — ${level === 'high' ? 'birden fazla kritik başlık ve/veya sertifika sorunu tespit edildi.' : level === 'medium' ? 'giderilmesi önerilen önemli güvenlik başlığı eksiklikleri var.' : 'ciddi/kritik bir açık öne çıkmadı.'}`);
  if (missingSec.length) summaryBullets.push(`- ${missingSec.length}/6 önemli güvenlik başlığı eksik (${missingSec.slice(0, 4).join(', ')}${missingSec.length > 4 ? '…' : ''}).`);
  else summaryBullets.push('- Önemli güvenlik başlıklarının tamamı mevcut.');
  if (tls.found) summaryBullets.push(`- TLS: ${tls.hostnameMatch === false ? 'hostname uyuşmazlığı ⚠️' : tls.daysLeft != null && tls.daysLeft >= 0 ? `geçerli (${tls.daysLeft} gün)` : 'geçerli'}${tls.protocol ? `, ${tls.protocol}` : ''}.`);
  summaryBullets.push('- **Önerilen ilk adım:** Eksik HTTP güvenlik başlıklarını ekleyin (ayrıntı için "AI Çözüm Önerileri" bölümü).');

  const genelSentence =
    level === 'high'
      ? 'Öncelikli olarak ele alınması gereken kritik güvenlik başlığı eksiklikleri ve/veya sertifika sorunları tespit edildi.'
      : level === 'medium'
        ? 'Kısa vadede giderilmesi önerilen önemli güvenlik başlığı eksiklikleri tespit edildi; taşıma güvenliği (TLS) genel olarak sağlam.'
        : 'Ciddi/kritik bir güvenlik açığı öne çıkmadı; rapor iyileştirme fırsatlarını listeler.';

  const findings =
    `## YÖNETİCİ ÖZETİ\n\n${summaryBullets.join('\n')}\n\n` +
    `## GENEL DEĞERLENDİRME\n\n**Risk Seviyesi: ${RISK_WORD[level]}**\n\n${genelSentence}\n\n` +
    `## HTTP GÜVENLİK BAŞLIKLARI\n\n| Başlık | Durum | Açıklama |\n|--------|-------|----------|\n${tableRows}\n\n` +
    `## TLS SERTİFİKA DURUMU\n\n${tlsSection}\n\n` +
    `## SUNUCU / TEKNOLOJİ İMZASI\n\n${techSection}\n\n` +
    `## TESPİT EDİLEN RİSKLER\n\n${riskItems.join('\n')}\n`;

  const fixText = buildHeaderFixSuggestions(findings, hostname);
  return { findings, fixText };
}
