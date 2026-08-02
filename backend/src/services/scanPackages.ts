/**
 * "Buton" paketleri kataloğu. Kullaniciya SERBEST prompt alani gosterilmiyor —
 * bu hem maliyet ongorulebilirligi hem de prompt injection / kapsam disi hedefe
 * yonlendirme riskini kapatiyor.
 *
 * TAMAMI PASIF (non-intrusive) ve DUSUK RISKLIDIR.
 *
 * DIL: Ajana giden IC talimatlar (SAFETY/BUDGET/FIX/FOCUS + promptTemplate govdeleri)
 * ARTIK HER ZAMAN INGILIZCE'dir (locale'den bagimsiz) — Ingilizce daha az token'a
 * bolunur ve ajan daha tutarli akil yurutur (maliyet/sure duser). Ajanin YANIT dili
 * ayrica belirlenir (bkz orchestrator langLine): tr locale'de ajan bulgulari/fix'i
 * dogrudan Turkce yazar (cok-dilli), ayri bir ceviri adimi GEREKMEZ.
 * ISTISNA: kvkk_hazirlik promptTemplate'i Turk hukuku terminolojisi icerdigi icin
 * TURKCE kalir (yalniz TR bolgesinde gosterilir).
 */

export interface ScanPackageDef {
  key:
    | 'basit_tarama'
    | 'ssl_tls'
    | 'header_leak'
    | 'dns_email'
    | 'cms_cve'
    | 'pci_hazirlik'
    | 'kvkk_hazirlik'
    | 'iso27001_hazirlik';
  displayName: string;
  description: string;
  priceMinorUnit: number; // kurus
  modelProvider: string; // PentAGI'de tanimli provider profil adi
  maxToolCalls: number; // flow bazinda yumusak tavan (worker.ts uygular)
  networkLayer?: boolean;
  fixSuggestionPriceMinorUnit?: number;
  // false ise musteriye SATILMAZ: paket listesinden gizlenir + siparis reddedilir.
  // iso27001/pci su an GEÇİCİ gizli — ajan yasaga ragmen POST deniyor, tarama
  // guvenlik geregi durduruluyor (rapor cikmiyor). Kalici cozum: PentAGI tool-level
  // GET-only patch'i (bkz PATCHES.md 'GET-only' plani). Patch dogrulaninca tekrar acilacak.
  available?: boolean;
  promptTemplate: (targetHostname: string) => string;
}

// Cikti dili bolgeden turetilir: tr -> tr, digerleri (us/ae/...) -> en.
export function localeFor(region: string | undefined | null): 'tr' | 'en' {
  return region === 'tr' ? 'tr' : 'en';
}

// Eklenti (fix suggestions) fiyati — PLACEHOLDER: taban fiyatin %50'si (Vedat onayina kadar).
export function fixSuggestionPrice(def: ScanPackageDef): number {
  return def.fixSuggestionPriceMinorUnit ?? Math.round(def.priceMinorUnit * 0.5);
}

const PACKAGE_I18N: Partial<Record<ScanPackageDef['key'], { displayName: string; description: string }>> = {
  basit_tarama: { displayName: 'Basic Scan', description: 'Fast passive pre-check: homepage security headers, TLS validity and server banner summary. The cheapest entry package, done in minutes.' },
  ssl_tls: { displayName: 'SSL/TLS Configuration Audit', description: 'Certificate validity/expiry, weak protocol and cipher suite usage, missing HSTS. A fully passive, non-intrusive encryption audit.' },
  header_leak: { displayName: 'Security Headers & Information Leakage', description: 'Missing security headers (CSP, X-Frame-Options, etc.) and passive check for accidentally exposed sensitive files (.git, .env, backups).' },
  dns_email: { displayName: 'DNS & Email Security', description: 'SPF/DKIM/DMARC gaps, DNSSEC and DNS misconfigurations. Valuable against email spoofing, fully passive.' },
  cms_cve: { displayName: 'CMS & Known-CVE Scan', description: 'CMS/framework fingerprinting, version detection and known-CVE mapping. DETECTION ONLY — no exploit is attempted.' },
  pci_hazirlik: { displayName: 'PCI-DSS Readiness Pre-Assessment', description: 'A passive readiness report mapping your external surface (TLS, headers, exposed files, known version issues, cookie/session security) to PCI-DSS requirements. NOT an official ASV/QSA test.' },
  iso27001_hazirlik: { displayName: 'ISO 27001 Readiness Checklist', description: 'A passive readiness report mapping externally observable technical controls to ISO 27001 Annex A. NOT an official certification/audit.' },
};

// kvkk_hazirlik EN sozlukte YOK — global menude gosterilmez (bkz orders.ts filtresi).
export function localizedPackage(def: ScanPackageDef, locale: 'tr' | 'en') {
  const t = locale === 'en' ? PACKAGE_I18N[def.key] : undefined;
  return { displayName: t?.displayName ?? def.displayName, description: t?.description ?? def.description };
}

const PROVIDER = process.env.PENTAGI_PROVIDER ?? 'cybertestify-anthropic';

// === IC TALIMAT SABITLERI (INGILIZCE) — kvkk haric tum paketler kullanir ========
// GET/HEAD/OPTIONS disi metotlar hem promptta yasak hem TEKNIK olarak engellidir
// (worker her-zaman-enforce + egress-proxy 405). Ajana SONUCU da soyluyoruz ki
// hic denemesin: bir POST/PUT/DELETE/PATCH girisimi taramayi RAPORSUZ sonlandirir.
const SAFETY_EN = `
STRICTLY FORBIDDEN: any exploitation, injection payloads (SQLi/XSS/SSRF, etc.),
authentication attempts, brute-force, directory/file FORCING, and — CRITICALLY —
ANY data-modifying/writing request. Use ONLY GET/HEAD/OPTIONS; POST/PUT/DELETE/PATCH
are prohibited AND technically blocked: a single such attempt is a policy violation
that IMMEDIATELY TERMINATES this scan with NO report. Also forbidden: load/stress/DoS
and accessing ANY target other than the specified host. Stay at the HOSTNAME/application
layer (not IP/port) to be safe on shared hosting. When in doubt, SKIP that step.`.trim();

const BUDGET_GUARD_EN = `
COMPLETION RULE (very important): Your tool-call budget is limited. Once you reach
about half of it, STOP opening new categories/exploration and START writing the report
with what you have. In every case, before ending the task you MUST write concrete
findings/summary text — never finish empty or half-done. If a category was not covered,
note it as "not reviewed" but still WRITE what you have.`.trim();

export const FIX_SUGGESTIONS_DELIM = '===FIX_SUGGESTIONS===';
const FIX_SUGGESTIONS_STEP_EN = `
FINAL STEP — FIX SUGGESTIONS: After writing all findings, output EXACTLY this line on
its own:
${FIX_SUGGESTIONS_DELIM}
and BELOW it, for each important finding write a concrete, actionable remediation
(with a SAFE config/code example when useful). ABSOLUTE RULE: this section is remediation
ONLY; it must NEVER contain runnable exploit code, attack payloads, or attack tooling.
If there are no findings, do not write the delimiter.`.trim();

// NOT: HAZIRLIK_FOCUS_EN kaldirildi — iso27001/pci promptlari artik DAR/deterministik
// (acikca "arastirma/arama yok, yalniz bu kontroller") oldugu icin ayri odak-kisiti
// gereksiz. kvkk (TR) hala HAZIRLIK_FOCUS_TR kullanir.

// === kvkk icin TURKCE sabitler (Turk hukuku baglami) ===========================
const SAFETY_TR = `
KESINLIKLE YASAK: her turlu istismar/exploitation, enjeksiyon (SQLi/XSS/SSRF vb.)
payload'lari, kimlik dogrulama denemesi, brute-force, dizin/dosya ZORLAMA ve —
KRITIK — veri degistiren/yazan HERHANGI bir istek. YALNIZCA GET/HEAD/OPTIONS kullan;
POST/PUT/DELETE/PATCH yasaktir VE teknik olarak engellidir: tek bir deneme bile
taramayi RAPORSUZ sonlandirir. Ayrica yuk/stres/DoS ve belirtilen host disindaki
hedeflere erisim yasaktir. Paylasimli hosting'e karsi IP/port degil HOSTNAME/uygulama
katmaninda kal. Suphedeysen o adimi ATLA.`.trim();

const BUDGET_GUARD_TR = `
TAMAMLAMA KURALI: Arac cagri butcen sinirli. Butcenin yaklasik yarisinda YENI kesif
ACMAYI BIRAK ve elindeki bulgularla raporu YAZMAYA BASLA. Her ihtimalde gorevi
bitirmeden ONCE somut bulgu/ozet yaz — asla bos/yarim birakma.`.trim();

const FIX_SUGGESTIONS_STEP_TR = `
EN SON ADIM — COZUM ONERILERI: Tum bulgulari yazdiktan SONRA tam olarak su satiri tek
basina yaz:
${FIX_SUGGESTIONS_DELIM}
ve altina her onemli bulgu icin somut duzeltme onerisi (gerektiginde GUVENLI config/kod
ornegiyle) yaz. MUTLAK KURAL: yalniz remediation; ASLA istismar kodu/payload icermez.
Bulgu yoksa delimiter'i yazma.`.trim();

const HAZIRLIK_FOCUS_TR = `
ODAK KURALI: Ilgili mevzuatin maddelerini ZATEN BILIYORSUN. Standardi/cerceveyi
internette ARASTIRMA, referans/blog/wiki GEZME (butce israfi + kapsam disi). Butceyi
yalnizca HEDEFI pasif inceleyip gozlemleri maddelerle eslemeye harca.`.trim();

export const SCAN_PACKAGES: ScanPackageDef[] = [
  {
    key: 'basit_tarama',
    displayName: 'Basit Tarama',
    description:
      'Hizli, pasif on-kontrol: ana sayfanin guvenlik basliklari, TLS gecerliligi ve ' +
      'sunucu banner ozeti. Birkac dakikada biten en ucuz giris paketi.',
    priceMinorUnit: 49900,
    modelProvider: PROVIDER,
    maxToolCalls: 25,
    promptTemplate: (host) => `
This is a FAST, PASSIVE and SHORT pre-check — NOT a deep scan. Send a normal GET request
ONLY to the HOMEPAGE of the single target below and summarize these passive facts:
HTTP security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options), server/tech
banner, and whether the TLS certificate is valid.

Use AT MOST 2-3 tools, then finish IMMEDIATELY. Do NOT open new subtasks.
${SAFETY_EN}
${BUDGET_GUARD_EN}
${FIX_SUGGESTIONS_STEP_EN}

Output: write a SHORT bullet summary and COMPLETE the task immediately.

Target: ${host}
`.trim(),
  },
  {
    key: 'ssl_tls',
    displayName: 'SSL/TLS Yapılandırma Denetimi',
    description:
      'Sertifika gecerliligi/suresi, zayif protokol ve cipher suite kullanimi, HSTS ' +
      'eksikligi. Tamamen pasif, saldirgan olmayan bir sifreleme denetimi.',
    priceMinorUnit: 79900,
    modelProvider: PROVIDER,
    maxToolCalls: 18,
    promptTemplate: (host) => `
Perform a PASSIVE SSL/TLS configuration audit against the single target below only.
Using tools like testssl.sh / sslyze / openssl if available, otherwise by observing the
TLS handshake manually, evaluate:
- Certificate: validity, expiry date, chain/CA, hostname match
- Supported protocols (whether legacy TLS 1.0/1.1 are enabled)
- Weak/outdated cipher suites
- Presence and duration of the HSTS header
${SAFETY_EN}
${BUDGET_GUARD_EN}
${FIX_SUGGESTIONS_STEP_EN}

Output: list findings by severity with a short recommendation list. Finish within about
12 tool calls and COMPLETE the task.

Target: ${host}
`.trim(),
  },
  {
    key: 'header_leak',
    displayName: 'Güvenlik Başlıkları & Bilgi Sızıntısı',
    description:
      'Eksik guvenlik header\'lari (CSP, X-Frame-Options vb.) ve yanlislikla acikta ' +
      'kalmis hassas dosyalarin (.git, .env, yedek) pasif kontrolu.',
    priceMinorUnit: 79900,
    modelProvider: PROVIDER,
    maxToolCalls: 18,
    promptTemplate: (host) => `
Perform a PASSIVE check against the single target below only:
1) HTTP security headers: Content-Security-Policy, Strict-Transport-Security,
   X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
   Which are missing/weak?
2) For KNOWN standard paths only, do a single GET each (NO directory forcing/brute-force):
   /robots.txt, /.git/config, /.env, /backup.zip, /.DS_Store — are they accessible?
${SAFETY_EN}
${BUDGET_GUARD_EN}
${FIX_SUGGESTIONS_STEP_EN}

Output: list missing headers and any exposed files by severity with concrete advice.
Finish within about 12 tool calls and COMPLETE the task.

Target: ${host}
`.trim(),
  },
  {
    key: 'dns_email',
    displayName: 'DNS & E-posta Güvenliği',
    description:
      'SPF/DKIM/DMARC eksiklikleri, DNSSEC ve DNS yanlis yapilandirmalari. E-posta ' +
      'sahteciligine (spoofing) karsi isletmeler icin degerli, tamamen pasif.',
    priceMinorUnit: 99900,
    modelProvider: PROVIDER,
    maxToolCalls: 18,
    promptTemplate: (host) => `
Perform a PASSIVE DNS/email-security check for the domain of the single target below
(using tools like dig/nslookup — QUERY ONLY, never modify any record):
- Is there an SPF record, is it correct (single TXT, -all/~all policy)?
- Is there a DMARC record (_dmarc.${host}), and what is its policy (none/quarantine/reject)?
- DKIM: observe records for common selectors (default, google, selector1/2)
- Is DNSSEC enabled, are the MX records reasonable?
${SAFETY_EN}
${BUDGET_GUARD_EN}
${FIX_SUGGESTIONS_STEP_EN}

Output: summarize each finding (SPF/DKIM/DMARC/DNSSEC) with status + recommendation in a
table. Finish within about 12 tool calls and COMPLETE the task.

Target: ${host}
`.trim(),
  },
  {
    key: 'cms_cve',
    displayName: 'CMS & Bilinen CVE Taraması',
    description:
      'WordPress/Joomla gibi CMS ve framework parmak izi, surum tespiti ve bilinen ' +
      'CVE eslemesi. SADECE TESPIT — hicbir exploit denenmez.',
    priceMinorUnit: 149900,
    modelProvider: PROVIDER,
    maxToolCalls: 25,
    promptTemplate: (host) => `
Perform PASSIVE fingerprinting and known-vulnerability DETECTION against the single
target below (whatweb / wappalyzer style passive observation + version hints on public pages):
- Which CMS/framework is running (WordPress, Joomla, Drupal, Laravel, etc.)?
- Detectable version information
- KNOWN CVEs for that version(s) (mapping/reporting ONLY)
- Plugin/theme version hints (if any)

IMPORTANT: Do NOT exploit/verify the detected CVEs — only report "this version is known to
have these CVEs".
${SAFETY_EN}
${BUDGET_GUARD_EN}
${FIX_SUGGESTIONS_STEP_EN}

Output: detected technology + version + known-CVE list (with CVSS) + update advice.
Finish within about 18 tool calls and COMPLETE the task.

Target: ${host}
`.trim(),
  },
  {
    key: 'pci_hazirlik',
    displayName: 'PCI-DSS Hazırlık Ön-Değerlendirmesi',
    description:
      'Dis yuzeyinizi (TLS/sifreleme, guvenlik basliklari, acikta hassas dosyalar, ' +
      'bilinen surum zafiyetleri, cerez/oturum guvenligi) PCI-DSS maddeleriyle ' +
      'eslestiren pasif bir hazirlik raporu. RESMI ASV/QSA testi DEGILDIR.',
    priceMinorUnit: 249900,
    modelProvider: PROVIDER,
    // DAR/deterministik prompt — genis kesif YOK, dusuk tavan odaklanmayi zorlar.
    maxToolCalls: 25,
    available: false, // dar-prompt testi gecince true yapilacak (bkz HANDOFF)

    promptTemplate: (host) => `
Run a PASSIVE, NARROW, FIXED "PCI-DSS READINESS PRE-ASSESSMENT" on the SINGLE target
below. This is a fixed checklist — NOT open-ended research. Do NOT use web search, do NOT
browse any other site, do NOT open new subtasks. Inspect ONLY ${host} with GET/HEAD requests.

Do EXACTLY these checks on ${host} and map each to a PCI-DSS requirement:
1. TLS version/cipher/certificate -> Req 4.2.1 (strong cryptography in transit)
2. HTTP security headers (HSTS/CSP/X-Frame-Options/X-Content-Type-Options) -> Req 6.4
3. Cookie flags (Secure/HttpOnly/SameSite) on any Set-Cookie -> Req 8 (session security)
4. Server banner / default pages disclosing versions -> Req 2.2 (secure configuration)
5. Exposed sensitive files via a single GET each (/.git/config, /.env, /backup.zip) -> Req 3 (data exposure)

After these 5 checks, immediately WRITE the report and FINISH. Nothing else.
${SAFETY_EN}
${BUDGET_GUARD_EN}
${FIX_SUGGESTIONS_STEP_EN}

Output (Markdown table): "PCI Requirement | Finding | Status (Pass/Attention/Missing) | Recommendation".
End note: "Not an official PCI compliance test; internal network/CDE, segmentation, ASV
scanning and penetration testing are OUT OF SCOPE."

Target: ${host}
`.trim(),
  },
  {
    key: 'kvkk_hazirlik',
    displayName: 'KVKK Ön Uyum Kontrolü',
    description:
      'Kisisel veri isleyen formlar, cerez rizasi/aydinlatma metni, veri saklama ' +
      've iletisim/veri sorumlusu bilgilerinin pasif kontrolu. Hukuki danismanlik ' +
      'DEGILDIR — farkindalik ve eksik tespiti amaclidir.',
    priceMinorUnit: 199900,
    modelProvider: PROVIDER,
    maxToolCalls: 45,
    // ISTISNA: Turk hukuku terminolojisi — bu promptTemplate TURKCE kalir (Turkce
    // sabitleri kullanir). Yalniz TR bolgesinde gosterilir.
    promptTemplate: (host) => `
Yalnizca asagidaki TEK hedefin HERKESE ACIK sayfalarini PASIF gozlemleyerek bir
"KVKK ON UYUM KONTROLU" yap. Bu HUKUKI DANISMANLIK DEGILDIR; amac disaridan
gorulebilen eksikleri KVKK ilkeleriyle eslestirmek.
${HAZIRLIK_FOCUS_TR}

Sadece normal GET ile gozlemle:
- Aydinlatma metni / Gizlilik politikasi sayfasi var mi, erisilebilir mi?
- Cerez rizasi (consent) banner'i var mi; rizadan ONCE izleyici cerez birakiliyor mu?
- Kisisel veri toplayan formlar (iletisim, uyelik) HTTPS uzerinde mi; acik rizaya
  atif var mi?
- Veri sorumlusu / iletisim / VERBIS atifi gozlemleniyor mu?
- Ucuncu taraf izleyiciler (analytics, pixel) gozlemleniyor mu?
${SAFETY_TR}
${BUDGET_GUARD_TR}
${FIX_SUGGESTIONS_STEP_TR}

Cikti (Markdown tablo): "KVKK Ilkesi/Konu | Gozlem | Durum (Uygun/Dikkat/Eksik) |
Oneri". Sonda: "Bu rapor hukuki gorus/uyum beyani degildir; nihai degerlendirme
icin KVKK uzmani/avukat gerekir" notu. En fazla ~36 arac cagrisinda bitir.

Hedef: ${host}
`.trim(),
  },
  {
    key: 'iso27001_hazirlik',
    displayName: 'ISO 27001 Hazırlık Kontrol Listesi',
    description:
      'Disaridan gozlemlenebilen teknik kontrollerin ISO 27001 Ek-A maddeleriyle ' +
      'eslestirildigi pasif hazirlik raporu. RESMI sertifikasyon/denetim DEGILDIR.',
    priceMinorUnit: 299900,
    modelProvider: PROVIDER,
    // DAR/deterministik prompt (bkz asagi) — genis kesif YOK, bu yuzden dusuk tavan
    // yeterli ve odaklanmayi zorlar (header_leak gibi guvenilir tamamlanir).
    maxToolCalls: 25,
    available: false, // dar-prompt testi gecince true yapilacak (bkz HANDOFF)

    promptTemplate: (host) => `
Run a PASSIVE, NARROW, FIXED ISO/IEC 27001 Annex A readiness spot-check on the SINGLE
target below. This is a fixed checklist — NOT open-ended research. Do NOT use web search,
do NOT browse any other site, do NOT open new subtasks, do NOT look up the ISO standard
online (you already know it). Inspect ONLY ${host} with GET/HEAD requests.

Do EXACTLY these checks on ${host} and map each to an Annex A clause:
1. TLS certificate valid + modern protocol (TLS 1.2/1.3)? -> A.8.24 (cryptography)
2. HTTP security headers present (HSTS, CSP, X-Frame-Options, X-Content-Type-Options)? -> A.8.23/A.8.9
3. Server/technology banner disclosing versions? -> A.8.9 (secure configuration)
4. Obvious exposed files via a single GET each (/.git/config, /.env, /robots.txt)? -> A.8.12 (data leakage)
5. Is a privacy/security policy page reachable? -> A.5.1 (policies)

After these 5 checks, immediately WRITE the report and FINISH. Nothing else.
${SAFETY_EN}
${BUDGET_GUARD_EN}
${FIX_SUGGESTIONS_STEP_EN}

Output (Markdown table): "Annex A Clause | Observation | Status | Recommendation". End note:
"Not an official ISO 27001 audit/certification; ISMS scope, documentation and internal
processes are OUT OF SCOPE."

Target: ${host}
`.trim(),
  },
];

export function getPackageDef(key: string): ScanPackageDef {
  const def = SCAN_PACKAGES.find((p) => p.key === key);
  if (!def) throw new Error(`Bilinmeyen paket: ${key}`);
  return def;
}
