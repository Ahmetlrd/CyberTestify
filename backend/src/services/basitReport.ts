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

const HEADER_ROWS: Array<{ key: SecKey | 'ctype' | 'xxss'; header: string; hdr: string; presentNote: string; absentNote: string; presentDe: string; absentDe: string }> = [
  { key: 'hsts', header: 'Strict-Transport-Security', hdr: 'strict-transport-security', presentNote: 'HTTPS zorunlu tutuluyor; SSL-stripping/MITM saldırılarına karşı koruma sağlıyor.', absentNote: 'HTTPS zorunluluğu tarayıcıya bildirilmiyor; ilk isteklerde SSL-stripping/MITM riski var.', presentDe: 'HTTPS wird erzwungen; Schutz gegen SSL-Stripping-/MITM-Angriffe.', absentDe: 'Die HTTPS-Pflicht wird dem Browser nicht mitgeteilt; bei Erstanfragen besteht SSL-Stripping-/MITM-Risiko.' },
  { key: 'csp', header: 'Content-Security-Policy', hdr: 'content-security-policy', presentNote: 'Kaynak yükleme politikası tanımlı; XSS/enjeksiyon yüzeyi daralıyor.', absentNote: 'Tarayıcı hangi kaynakların yükleneceğini kısıtlayamıyor; XSS ve içerik enjeksiyonuna karşı temel savunma yok.', presentDe: 'Eine Ressourcen-Ladepolitik ist definiert; die XSS-/Injektionsfläche wird verkleinert.', absentDe: 'Der Browser kann nicht einschränken, welche Ressourcen geladen werden; keine grundlegende Verteidigung gegen XSS und Content-Injection.' },
  { key: 'xfo', header: 'X-Frame-Options', hdr: 'x-frame-options', presentNote: 'Sayfa yabancı iframe’lere gömülemiyor; clickjacking engelli.', absentNote: 'Sayfa başka bir sitenin iframe’ine gömülebilir; clickjacking ile kullanıcı kandırılabilir.', presentDe: 'Die Seite kann nicht in fremde iframes eingebettet werden; Clickjacking wird verhindert.', absentDe: 'Die Seite kann in das iframe einer fremden Website eingebettet werden; Nutzer können per Clickjacking getäuscht werden.' },
  { key: 'xcto', header: 'X-Content-Type-Options', hdr: 'x-content-type-options', presentNote: 'MIME-sniffing kapalı; içerik beyan edilen türde işleniyor.', absentNote: 'Tarayıcı içerik türünü tahmin edebilir (MIME-sniffing); yüklenen dosyalar script gibi çalıştırılabilir.', presentDe: 'MIME-Sniffing ist deaktiviert; Inhalte werden im deklarierten Typ verarbeitet.', absentDe: 'Der Browser kann den Inhaltstyp erraten (MIME-Sniffing); hochgeladene Dateien könnten wie Skripte ausgeführt werden.' },
  { key: 'referrer', header: 'Referrer-Policy', hdr: 'referrer-policy', presentNote: 'Referrer paylaşımı sınırlandırılmış.', absentNote: 'Dış bağlantılara tam URL (Referer) gönderilir; oturum/gizlilik bilgisi sızabilir.', presentDe: 'Die Referrer-Weitergabe ist eingeschränkt.', absentDe: 'An externe Links wird die vollständige URL (Referer) gesendet; Sitzungs-/Datenschutzinformationen können abfließen.' },
  { key: 'permissions', header: 'Permissions-Policy', hdr: 'permissions-policy', presentNote: 'Tarayıcı API’leri (kamera/mikrofon/konum) kısıtlı.', absentNote: 'Kamera/mikrofon/konum gibi hassas API’ler kısıtlanmamış; üçüncü taraf içerik kötüye kullanabilir.', presentDe: 'Browser-APIs (Kamera/Mikrofon/Standort) sind eingeschränkt.', absentDe: 'Sensible APIs wie Kamera/Mikrofon/Standort sind nicht eingeschränkt; Drittinhalte könnten sie missbrauchen.' },
  { key: 'xxss', header: 'X-XSS-Protection', hdr: 'x-xss-protection', presentNote: 'Eski tarayıcı XSS filtresi tanımlı (savunma derinliği).', absentNote: 'Eski tarayıcı XSS filtresi ayarlı değil (modern tarayıcılarda kritik değildir; asıl koruma CSP’dir).', presentDe: 'Der Legacy-XSS-Filter älterer Browser ist gesetzt (Defense-in-Depth).', absentDe: 'Der Legacy-XSS-Filter älterer Browser ist nicht gesetzt (in modernen Browsern unkritisch; der eigentliche Schutz ist CSP).' },
  { key: 'ctype', header: 'Content-Type', hdr: 'content-type', presentNote: '', absentNote: 'Content-Type belirtilmemiş; tarayıcı içerik türünü tahmin etmek zorunda kalır.', presentDe: '', absentDe: 'Content-Type ist nicht angegeben; der Browser muss den Inhaltstyp erraten.' },
];

const RISK_WORD = { low: 'Düşük', medium: 'Orta', high: 'Yüksek' } as const;
const RISK_WORD_DE = { low: 'Niedrig', medium: 'Mittel', high: 'Hoch' } as const;
// Bulgu tablosundaki şiddet kelimesini locale'e çevir (makine-değer TR kalır; yalnız görüntü).
const SEV_DE: Record<string, string> = { 'Kritik': 'Kritisch', 'Yüksek': 'Hoch', 'Orta': 'Mittel', 'Düşük': 'Niedrig', 'Bilgilendirme': 'Hinweis' };

/**
 * basit_tarama raporunu KOD-toplanmis kanittan uretir. Ana sayfaya ulasilamazsa null doner.
 */
export async function generateBasitReport(hostname: string, locale: string = 'tr'): Promise<{ findings: string; fixText: string } | null> {
  const de = locale === 'de'; // 'de' dışı her locale → Türkçe (mevcut davranış korunur)
  const t = (trS: string, deS: string) => (de ? deS : trS);
  const ev = await collectEvidence(hostname);

  // (DÜRÜSTLÜK — c durumu) HEDEFE HİÇ ULAŞILAMADI: ne https(443) ne http ne TLS yanıt verdi.
  // Bu KESİNLİKLE "temiz"/"düşük risk" DEĞİL, "İncelenemedi"dir (assessBasit nötr amber rozet basar).
  if (!ev.reachable && !ev.tls.found) {
    const findings = de
      ? `## MANAGEMENTZUSAMMENFASSUNG\n\n` +
        `- **Gesamtrisikostufe: Nicht prüfbar** — die Prüfung konnte nicht durchgeführt werden, da keine Verbindung zum Ziel (${hostname}) hergestellt werden konnte.\n` +
        `- Dieses Ergebnis bedeutet NICHT, dass die Website SICHER ist; es zeigt lediglich, dass die Kontrollen nicht ausgeführt werden konnten.\n` +
        `- **Empfohlener erster Schritt:** Prüfen Sie, ob die Domain online und von außen erreichbar ist, und wiederholen Sie die Prüfung.\n\n` +
        `## GESAMTBEWERTUNG\n\n**Risikostufe: Nicht prüfbar**\n\n` +
        `Zu den Ports 443 (HTTPS) und 80 (HTTP) des Ziels konnte keine Verbindung hergestellt werden (Zeitüberschreitung oder Verbindungsablehnung). Passive Kontrollen wie Sicherheits-Header und TLS konnten daher nicht ausgeführt werden. Ist die Domain korrekt und online, blockiert möglicherweise eine Firewall/Zugriffsbeschränkung die Prüfung.\n\n` +
        `## PRÜFSTATUS\n\nDiese Prüfung wurde **nicht abgeschlossen**: Das Ziel war nicht erreichbar und keine Kontrolle konnte Daten erheben. Dieser Bericht ist **KEIN** „sauberes/sicheres" Ergebnis; sobald der Zugriff möglich ist, sollte erneut geprüft werden.\n`
      : `## YÖNETİCİ ÖZETİ\n\n` +
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
      if (ev.headers.has(row.hdr) && absentOn > 0) perPageMissing.push(`${row.header} (${t(`${absentOn}/${pageCount} sayfada`, `auf ${absentOn}/${pageCount} Seiten`)})`);
    }
  }
  const cov = (k: SecKey) => (pageCount > 1 ? t(` (${headerAbsentCount.get(k) ?? pageCount}/${pageCount} taranan sayfada eksik)`, ` (fehlt auf ${headerAbsentCount.get(k) ?? pageCount}/${pageCount} geprüften Seiten)`) : '');

  // http-only (şifresiz iletişim) TEK BAŞINA ciddi bir bulgudur -> genel risk en az Yüksek.
  // (HATA 4) EOL/eski yazılım imzası -> GERÇEK bulgu (bilgi metni değil). Sürüm imzasından türer.
  // ÇOK-SAYFA: sürüm imzası birden fazla sayfanın BİRLEŞİMİNDEN (bir sürüm yalnız alt sayfada olabilir).
  const eolRisks = detectOutdatedSoftware([...allTech], locale);
  const eolRank = eolRisks.some((r) => r.sev === 'Yüksek') ? 2 : eolRisks.some((r) => r.sev === 'Orta') ? 1 : 0;
  const baseLevel = httpOnly ? 'high' : riskLevel(absent, ev.tls);
  const level: 'low' | 'medium' | 'high' =
    eolRank > ({ low: 0, medium: 1, high: 2 } as const)[baseLevel] ? (eolRank === 2 ? 'high' : 'medium') : baseLevel;
  const missingSec = SEC_KEYS.filter((k) => absent.has(k)).map((k) => HEADER_ROWS.find((r) => r.key === k)!.header);

  // Tablo
  const tableRows = HEADER_ROWS.map((r) => {
    const present = ev.headers.has(r.hdr);
    let note = present ? t(r.presentNote, r.presentDe) : t(r.absentNote, r.absentDe);
    if (r.key === 'ctype' && present) note = ev.headers.get('content-type') ?? t('Belirtilmiş.', 'Angegeben.');
    // CSP/SPA baglami: somut deger katar (Grok: "CSP eksikligi SPA'da XSS riskini artirir")
    if (r.key === 'csp' && !present && isSpa) note += t(' Bu site bir SPA (JavaScript ağırlıklı) olduğundan CSP eksikliği XSS etkisini belirgin şekilde büyütür.', ' Da diese Website eine SPA (JavaScript-lastig) ist, vergrößert das Fehlen einer CSP die XSS-Auswirkung deutlich.');
    return `| ${r.header} | ${present ? t('Var', 'Vorhanden') : t('Yok', 'Fehlt')} | ${note} |`;
  }).join('\n');

  // TLS
  let tlsSection: string;
  const tlsInf = ev.tls;
  if (!tlsInf.found) {
    tlsSection = httpOnly
      ? t(
          `⚠️ Bu hedef **HTTPS (443) üzerinden yanıt vermedi**; geçerli bir TLS sertifikası bulunamadı. Site yalnızca **şifresiz HTTP** üzerinden yayında (bkz. Tespit Edilen Riskler → “HTTPS desteklenmiyor”). Aşağıdaki başlık kontrolleri http:// üzerinden yürütülmüştür.`,
          `⚠️ Dieses Ziel **hat nicht über HTTPS (443) geantwortet**; es wurde kein gültiges TLS-Zertifikat gefunden. Die Website ist nur über **unverschlüsseltes HTTP** erreichbar (siehe Festgestellte Risiken → „HTTPS wird nicht unterstützt"). Die nachfolgenden Header-Kontrollen wurden über http:// durchgeführt.`,
        )
      : t('TLS sertifika bilgisi elde edilemedi (443 portuna güvenli bağlantı kurulamadı).', 'Es konnten keine TLS-Zertifikatsinformationen ermittelt werden (keine sichere Verbindung zu Port 443 möglich).');
  } else {
    const l: string[] = [];
    l.push(`- **${t('Geçerlilik', 'Gültigkeit')}:** ${tlsInf.daysLeft != null ? (tlsInf.daysLeft >= 0 ? t(`Geçerli, ${tlsInf.daysLeft} gün kaldı`, `Gültig, noch ${tlsInf.daysLeft} Tage`) : t(`SÜRESİ DOLMUŞ (${Math.abs(tlsInf.daysLeft)} gün önce)`, `ABGELAUFEN (vor ${Math.abs(tlsInf.daysLeft)} Tagen)`)) : t('Belirlenemedi', 'Nicht ermittelbar')}${tlsInf.notAfter ? t(` (bitiş: ${tlsInf.notAfter})`, ` (Ablauf: ${tlsInf.notAfter})`) : ''}`);
    if (tlsInf.hostnameMatch === false) l.push(t(
      `- **Hostname eşleşmesi:** ⚠️ Sertifika ${hostname} ile eşleşmiyor${tlsInf.cn ? ` (sertifika sahibi: ${tlsInf.cn})` : ''}${tlsInf.san.length ? `; kapsanan adlar: ${tlsInf.san.slice(0, 6).join(', ')}` : ''}. Tarayıcı güvenlik uyarısı verebilir.`,
      `- **Hostname-Abgleich:** ⚠️ Das Zertifikat stimmt nicht mit ${hostname} überein${tlsInf.cn ? ` (Zertifikatsinhaber: ${tlsInf.cn})` : ''}${tlsInf.san.length ? `; abgedeckte Namen: ${tlsInf.san.slice(0, 6).join(', ')}` : ''}. Browser können eine Sicherheitswarnung anzeigen.`,
    ));
    else if (tlsInf.hostnameMatch === true) {
      const multi = tlsInf.cn && tlsInf.cn.toLowerCase() !== hostname.toLowerCase();
      l.push(t(
        `- **Hostname eşleşmesi:** Uyumlu${multi ? ` (çok alanlı sertifika; ${hostname} kapsanıyor)` : ''}.`,
        `- **Hostname-Abgleich:** Übereinstimmend${multi ? ` (Multi-Domain-Zertifikat; ${hostname} ist abgedeckt)` : ''}.`,
      ));
    }
    if (tlsInf.issuer) l.push(`- **${t('Veren (issuer)', 'Aussteller (Issuer)')}:** ${tlsInf.issuer}`);
    if (tlsInf.protocol) l.push(`- **${t('TLS sürümü', 'TLS-Version')}:** ${tlsInf.protocol}${/TLSv1\.[01]$/.test(tlsInf.protocol) ? t(' — ⚠️ eski/zayıf sürüm, TLS 1.2+ önerilir', ' — ⚠️ veraltete/schwache Version, TLS 1.2+ empfohlen') : ''}`);
    if (tlsInf.cipher) l.push(`- **Cipher:** ${tlsInf.cipher}`);
    if (tlsInf.daysLeft != null && tlsInf.daysLeft >= 0 && tlsInf.daysLeft < 45) l.push(t('- ⚠️ **Uyarı:** Sertifika 45 günden kısa sürede sona eriyor; kesinti yaşamamak için yenilemeyi planlayın.', '- ⚠️ **Warnung:** Das Zertifikat läuft in weniger als 45 Tagen ab; planen Sie die Erneuerung, um Ausfälle zu vermeiden.'));
    tlsSection = l.join('\n');
  }

  // Teknoloji — de: etiket önekleri çevrilir (detectTech Türkçe önek üretir)
  const deTechLabel = (s: string) => s
    .replace(/^Sunucu: /, 'Server: ')
    .replace(/^Barındırma: /, 'Hosting: ')
    .replace(/^HTTP\/3 desteği \(Alt-Svc\)$/, 'HTTP/3-Unterstützung (Alt-Svc)')
    .replace(/ tabanlı SPA$/, '-basierte SPA');
  const techSection = tech.length
    ? tech.map((x) => `- ${de ? deTechLabel(x) : x}`).join('\n')
    : t('- Yanıt başlıkları ve ana sayfa HTML’inde belirgin bir teknoloji imzası pasif olarak gözlemlenmedi.', '- In den Antwort-Headern und im HTML der Startseite wurde passiv keine eindeutige Technologiesignatur beobachtet.');

  // Riskler — MASTER TABLO + ZAFİYET DAĞILIMINA girmesi için ŞİDDET KOLONLU tablo (bullet değil).
  // parseFindings (pdf.ts) yalnız şiddet-kolonlu tabloları sayar; böylece https_missing/eksik başlıklar
  // "Temiz" değil GERÇEK bulgu olarak dağılıma/master'a düşer.
  const risks: Array<{ bulgu: string; sev: string; aciklama: string }> = [];
  if (httpOnly) risks.push({ bulgu: t('HTTPS desteklenmiyor (şifresiz iletişim)', 'HTTPS wird nicht unterstützt (unverschlüsselte Kommunikation)'), sev: 'Yüksek', aciklama: t(`Site HTTPS'e yanıt vermiyor; sayfaya gelen/giden tüm trafik şifresiz (düz metin) taşınıyor — aynı ağdaki bir saldırgan trafiği dinleyebilir, oturum/şifre çalabilir veya içeriği değiştirebilir. Tarama http:// üzerinden yürütüldü.`, `Die Website antwortet nicht über HTTPS; der gesamte ein- und ausgehende Datenverkehr wird unverschlüsselt (Klartext) übertragen — ein Angreifer im selben Netzwerk kann den Verkehr mitlesen, Sitzungen/Passwörter stehlen oder Inhalte verändern. Die Prüfung wurde über http:// durchgeführt.`) });
  if (tlsInf.hostnameMatch === false) risks.push({ bulgu: t('TLS hostname uyuşmazlığı', 'TLS-Hostname-Abweichung'), sev: 'Yüksek', aciklama: t(`Sertifika ${hostname} adına düzenlenmemiş; ziyaretçiler tarayıcı güvenlik uyarısıyla karşılaşabilir ve siteye güven azalır.`, `Das Zertifikat ist nicht auf ${hostname} ausgestellt; Besucher können auf eine Browser-Sicherheitswarnung stoßen und das Vertrauen in die Website sinkt.`) });
  if (tlsInf.daysLeft != null && tlsInf.daysLeft < 0) risks.push({ bulgu: t('TLS sertifikası süresi dolmuş', 'TLS-Zertifikat abgelaufen'), sev: 'Yüksek', aciklama: t('Site tarayıcılarca güvensiz kabul edilir; ziyaretçi kaybına yol açar.', 'Die Website wird von Browsern als unsicher eingestuft; das führt zu Besucherverlusten.') });
  for (const e of eolRisks) risks.push({ bulgu: e.bulgu, sev: e.sev, aciklama: e.aciklama });
  const keyOf = (headerName: string): SecKey | undefined => HEADER_ROWS.find((r) => r.header === headerName)?.key as SecKey | undefined;
  const covFor = (headerNames: string[]): string => {
    if (pageCount <= 1) return '';
    const counts = headerNames.map((h) => { const k = keyOf(h); return k ? headerAbsentCount.get(k) ?? pageCount : pageCount; });
    const n = Math.max(...counts);
    return t(
      ` Taranan ${pageCount} benzersiz sayfanın ${n === pageCount ? 'TAMAMINDA' : `${n}/${pageCount}'sinde`} eksik.`,
      ` Fehlt auf ${n === pageCount ? `ALLEN ${pageCount}` : `${n} von ${pageCount}`} geprüften einzigartigen Seiten.`,
    );
  };
  const critList: string[] = missingSec.filter((h) => h === 'Content-Security-Policy' || h === 'X-Frame-Options');
  if (critList.length) {
    const spaNote = isSpa && critList.includes('Content-Security-Policy') ? t(' Site JavaScript ağırlıklı bir SPA olduğundan CSP eksikliği XSS etkisini büyütür; önceliklendirilmesi önerilir.', ' Da die Website eine JavaScript-lastige SPA ist, vergrößert das Fehlen einer CSP die XSS-Auswirkung; eine Priorisierung wird empfohlen.') : '';
    risks.push({ bulgu: t(`Kritik güvenlik başlıkları eksik (${critList.join(', ')})`, `Kritische Sicherheits-Header fehlen (${critList.join(', ')})`), sev: 'Orta', aciklama: t(`XSS ve/veya clickjacking saldırılarına karşı tarayıcı seviyesinde savunma bulunmuyor.`, `Auf Browser-Ebene besteht keine Verteidigung gegen XSS- und/oder Clickjacking-Angriffe.`) + covFor(critList) + spaNote });
  }
  const otherMissing = missingSec.filter((h) => !critList.includes(h));
  if (otherMissing.length) risks.push({ bulgu: t(`Ek güvenlik başlıkları eksik (${otherMissing.join(', ')})`, `Weitere Sicherheits-Header fehlen (${otherMissing.join(', ')})`), sev: 'Orta', aciklama: t(`Savunma derinliği zayıf; tek tek düşük etkili olsa da birlikte saldırı yüzeyini genişletir.`, `Die Verteidigungstiefe ist schwach; einzeln geringfügig, vergrößern sie zusammen die Angriffsfläche.`) + covFor(otherMissing) });
  // (BÖLÜM 1) SAYFAYA-ÖZGÜ tutarsızlık: ana sayfada MEVCUT bir kritik başlık bazı alt sayfalarda EKSİK.
  if (perPageMissing.length) risks.push({ bulgu: t('Sayfaya özgü güvenlik başlığı tutarsızlığı', 'Seitenspezifische Inkonsistenz der Sicherheits-Header'), sev: 'Orta', aciklama: t(`Ana sayfada mevcut olan bir/birkaç kritik başlık bazı iç sayfalarda gönderilmiyor: ${perPageMissing.join(', ')}. Başlık politikası tüm yollarda tutarlı uygulanmalı (ör. sunucu bloğu genelinde, tek uç noktada değil).`, `Ein oder mehrere auf der Startseite vorhandene kritische Header werden auf einigen Unterseiten nicht gesendet: ${perPageMissing.join(', ')}. Die Header-Richtlinie sollte auf allen Pfaden konsistent angewendet werden (z. B. serverweit, nicht nur an einem Endpunkt).`) });
  if (disclosure.length) risks.push({ bulgu: t('Üçüncü taraf servis kimlikleri', 'Kennungen von Drittanbieterdiensten'), sev: 'Bilgilendirme', aciklama: t(`Ana sayfada ${disclosure.join('; ')} açıkça görülüyor. İstismar edilebilir açık değildir; yalnızca dış servis bağımlılıklarına dair farkındalık amacıyla listelenmiştir.`, `Auf der Startseite sind ${disclosure.join('; ')} offen sichtbar. Dies ist keine ausnutzbare Schwachstelle; sie wird nur zur Sensibilisierung für externe Dienstabhängigkeiten aufgeführt.`) });

  const riskSection = risks.length
    ? `| ${t('Bulgu', 'Befund')} | ${t('Şiddet', 'Schweregrad')} | ${t('Açıklama', 'Beschreibung')} |\n|-------|--------|----------|\n${risks.map((r) => `| ${r.bulgu} | ${de ? SEV_DE[r.sev] ?? r.sev : r.sev} | ${r.aciklama.replace(/\|/g, '\\|')} |`).join('\n')}`
    : t('Belirgin bir güvenlik riski öne çıkmadı; rapor yalnızca küçük iyileştirme fırsatlarını listeler.', 'Es ist kein deutliches Sicherheitsrisiko hervorgetreten; der Bericht listet nur kleine Verbesserungsmöglichkeiten auf.');

  // Yonetici ozeti
  const tlsProblem = tlsInf.hostnameMatch === false ? t('TLS sertifikası bu alan adıyla eşleşmiyor', 'Das TLS-Zertifikat stimmt nicht mit dieser Domain überein') : tlsInf.daysLeft != null && tlsInf.daysLeft < 0 ? t('TLS sertifikasının süresi dolmuş', 'Das TLS-Zertifikat ist abgelaufen') : '';
  // EOL, seviyeyi sürükleyen etkense (TLS/başlık sorunu yokken) badge gerekçesi EOL'i söylemeli.
  const eolDrives = eolRank > ({ low: 0, medium: 1, high: 2 } as const)[baseLevel];
  const riskReason =
    httpOnly
      ? t('site HTTPS desteklemiyor; iletişim şifresiz (düz metin) taşınıyor — dinlenebilir/değiştirilebilir. Öncelikli olarak HTTPS’e geçilmelidir.', 'die Website unterstützt kein HTTPS; die Kommunikation läuft unverschlüsselt (Klartext) — sie kann mitgelesen/verändert werden. Vorrangig sollte auf HTTPS umgestellt werden.')
      : eolDrives
        ? t('eski/desteksiz yazılım sürümü ifşa ediliyor (aşağıdaki bulgu tablosunda); bilinen güvenlik açıkları yamasız kalabilir — güncel, desteklenen sürüme yükseltilmelidir.', 'eine veraltete/nicht mehr unterstützte Softwareversion wird offengelegt (siehe Befundtabelle unten); bekannte Sicherheitslücken können ungepatcht bleiben — auf eine aktuelle, unterstützte Version aktualisieren.')
        : level === 'high'
          ? (tlsProblem ? t(`${tlsProblem} — ziyaretçilere doğrudan tarayıcı güvenlik uyarısı gösterebilir.`, `${tlsProblem} — Besuchern kann direkt eine Browser-Sicherheitswarnung angezeigt werden.`) : t('öncelikli giderilmesi gereken yüksek etkili bir bulgu tespit edildi (aşağıda).', 'ein hochwirksamer Befund, der vorrangig behoben werden sollte, wurde festgestellt (siehe unten).'))
          : level === 'medium'
            ? t('öncelikli giderilmesi önerilen önemli güvenlik başlığı eksiklikleri var; taşıma güvenliği (TLS) sağlam.', 'es bestehen wichtige Lücken bei Sicherheits-Headern, deren vorrangige Behebung empfohlen wird; die Transportsicherheit (TLS) ist solide.')
            : t('ciddi/kritik bir açık öne çıkmadı; yalnızca küçük iyileştirme fırsatları var.', 'es ist keine schwerwiegende/kritische Schwachstelle hervorgetreten; es gibt nur kleine Verbesserungsmöglichkeiten.');
  const bullets: string[] = [];
  bullets.push(`- **${t('Genel risk seviyesi', 'Gesamtrisikostufe')}: ${de ? RISK_WORD_DE[level] : RISK_WORD[level]}** — ${riskReason}`);
  if (httpOnly) bullets.push(t('- ⚠️ Bu hedef HTTPS (443) üzerinden yanıt vermedi; tarama **http:// üzerinden** yürütüldü. HTTPS eksikliği başlı başına bir bulgudur (aşağıda).', '- ⚠️ Dieses Ziel hat nicht über HTTPS (443) geantwortet; die Prüfung wurde **über http://** durchgeführt. Das Fehlen von HTTPS ist für sich genommen ein Befund (siehe unten).'));
  if (missingSec.length) bullets.push(t(`- ${missingSec.length}/6 önemli güvenlik başlığı eksik: ${missingSec.join(', ')}.`, `- ${missingSec.length}/6 wichtige Sicherheits-Header fehlen: ${missingSec.join(', ')}.`));
  else bullets.push(t('- Önerilen güvenlik başlıklarının tamamı mevcut.', '- Alle empfohlenen Sicherheits-Header sind vorhanden.'));
  if (pageCount > 1) bullets.push(t(`- **Kapsam:** Güvenlik başlığı ve sürüm imzası kontrolleri, ana sayfa dâhil **${pageCount} benzersiz sayfada** yürütüldü (tek sayfa değil).`, `- **Umfang:** Die Kontrollen von Sicherheits-Headern und Versionssignaturen wurden auf **${pageCount} einzigartigen Seiten** einschließlich der Startseite durchgeführt (nicht nur auf einer Seite).`));
  if (tlsInf.found) {
    const tlsState =
      tlsInf.hostnameMatch === false
        ? t('⚠️ sertifika hostname uyuşmazlığı (bkz. Kontrol Özeti)', '⚠️ Zertifikat-Hostname-Abweichung (siehe Kontrollübersicht)')
        : tlsInf.daysLeft != null && tlsInf.daysLeft < 0
        ? t(`⚠️ sertifika SÜRESİ DOLMUŞ (${Math.abs(tlsInf.daysLeft)} gün önce — bkz. Kontrol Özeti)`, `⚠️ Zertifikat ABGELAUFEN (vor ${Math.abs(tlsInf.daysLeft)} Tagen — siehe Kontrollübersicht)`)
        : tlsInf.daysLeft != null && tlsInf.daysLeft >= 0
        ? t(`sertifikası geçerli (${tlsInf.daysLeft} gün)`, `Zertifikat gültig (${tlsInf.daysLeft} Tage)`)
        : t('sertifika geçerlilik durumu belirlenemedi', 'Gültigkeitsstatus des Zertifikats nicht ermittelbar');
    bullets.push(`- TLS${de ? ':' : ''} ${tlsState}${tlsInf.protocol ? `, ${tlsInf.protocol}` : ''}.`);
  }
  bullets.push(`- **${t('Önerilen ilk adım', 'Empfohlener erster Schritt')}:** ` + (httpOnly ? t('Geçerli bir TLS sertifikası kurup tüm trafiği HTTPS’e taşıyın; ', 'Installieren Sie ein gültiges TLS-Zertifikat und leiten Sie den gesamten Verkehr auf HTTPS um; ') : t('Eksik HTTP güvenlik başlıklarını sunucu yapılandırmasına ekleyin; ', 'Ergänzen Sie die fehlenden HTTP-Sicherheits-Header in der Serverkonfiguration; ')) + t('adım adım hazır komutlar "AI Çözüm Önerileri" eklentisinde sunulur.', 'schrittweise fertige Befehle werden im Add-on „KI-Lösungsvorschläge" bereitgestellt.'));

  const genel =
    httpOnly
      ? t('Bu hedef HTTPS üzerinden yanıt vermiyor; iletişim şifresiz (düz metin) HTTP ile yürüyor. Bu, aynı ağdaki bir saldırganın trafiği dinlemesine/değiştirmesine ve oturum/şifre çalmasına olanak tanıyan ciddi bir eksiktir; modern tarayıcılar siteyi "Güvenli değil" olarak işaretler. Öncelik, geçerli bir TLS sertifikasıyla HTTPS’e geçmek ve HTTP→HTTPS yönlendirmesi + HSTS eklemektir. Diğer başlık kontrolleri http:// üzerinden yürütülmüştür.', 'Dieses Ziel antwortet nicht über HTTPS; die Kommunikation läuft über unverschlüsseltes (Klartext-)HTTP. Das ist ein gravierender Mangel, der es einem Angreifer im selben Netzwerk erlaubt, den Verkehr mitzulesen/zu verändern und Sitzungen/Passwörter zu stehlen; moderne Browser markieren die Website als „Nicht sicher". Priorität ist der Wechsel zu HTTPS mit einem gültigen TLS-Zertifikat sowie HTTP→HTTPS-Umleitung + HSTS. Die übrigen Header-Kontrollen wurden über http:// durchgeführt.')
      : level === 'high'
        ? t('Ziyaretçilere doğrudan güvenlik uyarısı gösterebilecek bir TLS sertifikası sorunu tespit edildi; acilen giderilmesi önerilir. Ayrıca eksik güvenlik başlıkları savunma derinliğini zayıflatıyor.', 'Es wurde ein TLS-Zertifikatsproblem festgestellt, das Besuchern direkt eine Sicherheitswarnung anzeigen kann; eine umgehende Behebung wird empfohlen. Zudem schwächen fehlende Sicherheits-Header die Verteidigungstiefe.')
        : level === 'medium'
          ? t('Öncelikli giderilmesi önerilen önemli güvenlik başlığı eksiklikleri var; taşıma güvenliği (TLS/HTTPS) genel olarak sağlam. Eksik başlıklar tek başına siteyi ele geçirmez ancak XSS/clickjacking gibi saldırıların başarı şansını artırır ve düşük maliyetli sunucu ayarlarıyla kapatılabilir.', 'Es bestehen wichtige Lücken bei Sicherheits-Headern, deren vorrangige Behebung empfohlen wird; die Transportsicherheit (TLS/HTTPS) ist insgesamt solide. Fehlende Header allein führen nicht zur Übernahme der Website, erhöhen aber die Erfolgschancen von Angriffen wie XSS/Clickjacking und lassen sich mit kostengünstigen Servereinstellungen schließen.')
          : t('Ciddi/kritik bir güvenlik açığı öne çıkmadı; rapor öncelikle savunma derinliğini artıracak küçük iyileştirme fırsatlarını listeler.', 'Es ist keine schwerwiegende/kritische Sicherheitslücke hervorgetreten; der Bericht listet vor allem kleine Verbesserungsmöglichkeiten zur Erhöhung der Verteidigungstiefe auf.');

  // (TUTARLILIK — disclaimer) Diğer 3 pasif paketle AYNI konumda (Yönetici Özeti'nin hemen altında).
  const disclaimer = t(
    `> **Kapsam ve sınır:** Bu paket **pasif, GET-tabanlı** bir dış gözlemdir; hiçbir aktif istismar veya prob denenmemiştir. Bir alanda "bulgu yok" ifadesi, aktif test yapılmadığı için **güvenli olduğunu KANITLAMAZ** — yalnızca dışarıdan gözlemlenen yapılandırmanın temiz olduğunu gösterir.\n\n`,
    `> **Umfang und Grenzen:** Dieses Paket ist eine **passive, GET-basierte** Außenbeobachtung; es wurde kein aktiver Exploit und keine Probe versucht. Die Aussage „kein Befund" in einem Bereich **BEWEIST NICHT**, dass er sicher ist, da kein aktiver Test durchgeführt wurde — sie zeigt lediglich, dass die von außen beobachtete Konfiguration sauber ist.\n\n`,
  );

  // (BÖLÜM 2 — POZİTİF GÜVENCE) Diğer 3 pakete ÖLÇEKLİ: yalnız header/TLS/sürüm alanları, üç-durum.
  // "Sorun bulunamadı"yı da şeffaf kıl — SADECE gerçek veriden. Kapsam GENİŞLEMEZ (yeni tür eklenmez).
  const hdrState = missingSec.length
    ? t(`⚠️ Bulgu var (${missingSec.length}/6 önerilen başlık eksik — yukarıda detaylı)`, `⚠️ Befund vorhanden (${missingSec.length}/6 empfohlene Header fehlen — oben im Detail)`)
    : t(`✅ Sorun bulunmadı (6/6 önerilen başlık mevcut)`, `✅ Kein Problem gefunden (6/6 empfohlene Header vorhanden)`);
  const tlsAssState = httpOnly
    ? t('⚠️ Bulgu var (HTTPS yanıt vermedi — şifresiz iletişim)', '⚠️ Befund vorhanden (HTTPS hat nicht geantwortet — unverschlüsselte Kommunikation)')
    : !tlsInf.found
      ? t('⚠️ İncelenemedi (443’e güvenli bağlantı kurulamadı — “temiz” DEĞİL)', '⚠️ Nicht prüfbar (keine sichere Verbindung zu 443 möglich — NICHT „sauber")')
      : tlsInf.hostnameMatch === false || (tlsInf.daysLeft != null && tlsInf.daysLeft < 0)
        ? t('⚠️ Bulgu var (sertifika sorunu — yukarıda detaylı)', '⚠️ Befund vorhanden (Zertifikatsproblem — oben im Detail)')
        : t('✅ Sorun bulunmadı (geçerli sertifika, hostname uyumlu)', '✅ Kein Problem gefunden (gültiges Zertifikat, Hostname übereinstimmend)');
  const verAssState = eolRisks.length
    ? t('⚠️ Bulgu var (eski/desteksiz sürüm imzası — yukarıda detaylı)', '⚠️ Befund vorhanden (veraltete/nicht unterstützte Versionssignatur — oben im Detail)')
    : t('✅ Sorun bulunmadı (bilinen eski/EOL sürüm imzası saptanmadı)', '✅ Kein Problem gefunden (keine bekannte veraltete/EOL-Versionssignatur festgestellt)');
  const assuranceSection = de
    ? `## POSITIVE ZUSICHERUNG — GEPRÜFTE BEREICHE\n\n` +
      `Auch die Bereiche ohne Befund eingeschlossen, wurden die Kontrollen des Basis-Scans tatsächlich auf **${pageCount} einzigartigen Seiten** einschließlich der Startseite ausgeführt. Die folgende Tabelle zeigt auch die „kein Problem gefunden"-Ergebnisse transparent:\n\n` +
      `| Kontrollbereich | Ergebnis |\n|---------------|-------|\n` +
      `| HTTP-Sicherheits-Header (auf ${pageCount} Seiten) | ${hdrState} |\n` +
      `| TLS / Zertifikat | ${tlsAssState} |\n` +
      `| Server-/Software-Versionssignatur (auf ${pageCount} Seiten) | ${verAssState} |\n\n` +
      `> **Drei-Zustands-Unterscheidung (Ehrlichkeit):** ✅ *Kein Problem gefunden* = Kontrolle lief, Ergebnis sauber · ⚠️ *Befund vorhanden* = oben im Detail · ⚠️ *Nicht prüfbar* = keine Daten erhebbar (bedeutet NICHT sicher).\n\n` +
      `### Was dieses Paket prüft — und was NICHT\n\n` +
      `**PRÜFT (passiv — nur Seitenabruf per GET, keine Probe/Payload wird gesendet):** HTTP-Sicherheits-Header, TLS-/Zertifikatsstatus (Gültigkeit · Hostname · TLS-Version), Server-/Software-Versionssignatur und Erkennung bekannter veralteter/EOL-Versionen — auf den ${pageCount} entdeckten Seiten.\n\n` +
      `**PRÜFT NICHT:** CORS-Richtlinie, Cookie-Flag-Details, Content-Security-Policy-Analyse, DNS-/E-Mail-Einträge (SPF/DKIM/DMARC) und die Suche nach offen liegenden sensiblen Dateien gehören zum Paket **Externe Angriffsfläche**; Subdomain-/API-/CVE-Erkundung zum Paket **Reconnaissance**; aktive Schwachstellenverifikation (SQLi-/XSS-/IDOR-Proben) zu den Paketen **Aktive Verifikation** und **Umfassender Pentest**. Dieser Bericht beruht auf passiver Beobachtung; „kein Befund" **BEWEIST NICHT**, dass die Website sicher ist, da kein aktiver Exploit versucht wurde.\n\n`
    : `## POZİTİF GÜVENCE — KONTROL EDİLEN ALANLAR\n\n` +
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
    `## ${t('YÖNETİCİ ÖZETİ', 'MANAGEMENTZUSAMMENFASSUNG')}\n\n${bullets.join('\n')}\n\n` +
    disclaimer +
    `## ${t('GENEL DEĞERLENDİRME', 'GESAMTBEWERTUNG')}\n\n**${t('Risk Seviyesi', 'Risikostufe')}: ${de ? RISK_WORD_DE[level] : RISK_WORD[level]}**\n\n${genel}\n\n` +
    `## ${t('HTTP GÜVENLİK BAŞLIKLARI', 'HTTP-SICHERHEITS-HEADER')}\n\n| ${t('Başlık', 'Header')} | ${t('Durum', 'Status')} | ${t('Açıklama', 'Beschreibung')} |\n|--------|-------|----------|\n${tableRows}\n\n` +
    `## ${t('TLS SERTİFİKA DURUMU', 'TLS-ZERTIFIKATSSTATUS')}\n\n${tlsSection}\n\n` +
    `## ${t('SUNUCU / TEKNOLOJİ İMZASI', 'SERVER-/TECHNOLOGIESIGNATUR')}\n\n${techSection}\n\n` +
    `## ${t('TESPİT EDİLEN RİSKLER', 'FESTGESTELLTE RISIKEN')}\n\n${riskSection}\n\n` +
    assuranceSection;

  const fixText = buildHeaderFixSuggestions(findings, hostname, locale);
  return { findings, fixText };
}
