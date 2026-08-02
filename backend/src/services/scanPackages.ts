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
    | 'iso27001_hazirlik'
    | 'cors_cookie'
    | 'csp_analiz';
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
  cors_cookie: { displayName: 'CORS & Cookie Security', description: 'Passive check of CORS headers (risky Access-Control-Allow-Origin patterns, credentials combo) and cookie flags (Secure/HttpOnly/SameSite). Fully passive.' },
  csp_analiz: { displayName: 'CSP (Content Security Policy) Analysis', description: 'Passive analysis of the Content-Security-Policy header: presence, weakening directives (unsafe-inline/unsafe-eval), missing default-src. Fully passive.' },
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
layer (not IP/port) to be safe on shared hosting. When in doubt, SKIP that step.
NO INSTALLS: do NOT install or attempt to install ANY tool/package (no apt/apt-get,
pip/pip3, npm, go install, git clone of tools, curl|bash, downloading binaries, etc.).
Use ONLY tools already present in the container (curl, wget, openssl, dig, nslookup, host,
python3 stdlib). If a specialized tool is missing, do NOT install it — use a standard tool
already available or SKIP that specific check and note it as "not reviewed (tool
unavailable)". Spending your tool-call budget on setup/installation is FORBIDDEN.`.trim();

const BUDGET_GUARD_EN = `
COMPLETION & OUTPUT RULE (HIGHEST PRIORITY): Writing the final findings report AND the
${FIX_SUGGESTIONS_DELIM} section is your #1 deliverable — more important than extra probing.
Do ONLY minimal probing, then IMMEDIATELY write the complete report AND fix-suggestions IN
THE SAME step. Do NOT split the final report or fix-suggestions into a separate later
step/subtask — a later subtask may run out of budget and NEVER execute (this loses the whole
deliverable). Your tool-call budget is limited; once you reach about half, STOP exploring and
WRITE. Never finish empty or half-done; if a category was not covered, note it "not reviewed"
but still write what you have.
SINGLE CLEAN REPORT: Produce ONE fluent, professional, customer-facing report as if written
start-to-finish in a single sitting, grouped by severity. The customer must NOT see our
internal workflow — NEVER use process/meta language such as "Subtask"/"SubTask N",
"TASK COMPLETED", "Next step", "verification step", "success status", or workflow step
numbers. Write findings directly, not as a log of completed steps.`.trim();

export const FIX_SUGGESTIONS_DELIM = '===FIX_SUGGESTIONS===';
const FIX_SUGGESTIONS_STEP_EN = `
MANDATORY FIX SUGGESTIONS (do NOT skip when there are findings): In the SAME step, right
after the findings, output EXACTLY this line on its own:
${FIX_SUGGESTIONS_DELIM}
and BELOW it, for EACH important finding write a concrete, actionable remediation (with a
SAFE config/code example when useful). This is a PAID deliverable — never omit it, never
leave it for a later subtask. ABSOLUTE RULE: remediation ONLY; it must NEVER contain runnable
exploit code, attack payloads, or attack tooling. Only if there are genuinely NO findings at
all, omit the delimiter.`.trim();

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
katmaninda kal. Suphedeysen o adimi ATLA.
KURULUM YOK: Gorev icin HICBIR arac/paket kurma veya kurmayi DENEME (apt/apt-get, pip/pip3,
npm, git clone, curl|bash, ikili indirme vb.). YALNIZCA container'da HAZIR bulunan standart
araclarla (curl, wget, openssl, dig, nslookup, host, python3 stdlib) calis. Eksik ozel arac
varsa KURMA — standart bir aracla yap ya da o kontrolu ATLA ("incelenmedi (arac yok)" notu
dus). Butceyi kuruluma harcamak YASAK.`.trim();

const BUDGET_GUARD_TR = `
TAMAMLAMA & CIKTI KURALI (EN YUKSEK ONCELIK): Nihai bulgu raporunu VE ${FIX_SUGGESTIONS_DELIM}
bolumunu yazmak 1 numarali teslimatin — ek incelemeden daha onemli. YALNIZCA minimum inceleme
yap, sonra tam raporu VE cozum onerilerini AYNI adimda HEMEN yaz. Nihai raporu ya da cozum
onerilerini AYRI/GEC bir adima/subtask'a BIRAKMA — sonraki bir adim butce bitince HIC
calismayabilir (tum teslimat kaybolur). Butcenin yaklasik yarisinda kesfi BIRAK ve YAZ. Asla
bos/yarim birakma; bir kategori incelenmediyse "incelenmedi" not dus ama elindekini yaz.
TEK TEMIZ RAPOR: Tek, akici, profesyonel, MUSTERIYE yonelik bir rapor yaz — sanki bastan sona
tek oturusta yazilmis gibi, siddete gore gruplu. Musteri ic is akisimizi GORMEMELI: "Alt-Gorev"/
"Subtask N", "GOREV TAMAMLANDI", "Sonraki adim", "dogrulama adimi", "basari durumu" gibi surec/
meta ifadeler ASLA kullanma. Bulgulari dogrudan yaz, tamamlanan adimlarin gunlugu gibi degil.`.trim();

const FIX_SUGGESTIONS_STEP_TR = `
ZORUNLU COZUM ONERILERI (bulgu varsa ATLAMA): Bulgularin hemen ardindan, AYNI adimda, tam
olarak su satiri tek basina yaz:
${FIX_SUGGESTIONS_DELIM}
ve altina HER onemli bulgu icin somut duzeltme onerisi (gerektiginde GUVENLI config/kod
ornegiyle) yaz. Bu UCRETLI bir teslimat — asla atlama, asla sonraki bir adima birakma.
MUTLAK KURAL: yalniz remediation; ASLA istismar kodu/payload icermez. Yalniz gercekten HIC
bulgu yoksa delimiter'i yazma.`.trim();

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
    // 25->40: TLS denetimi cok adimli (cert + TLS1.0/1.1/1.2/1.3 probe + cipher + HSTS +
    // NIHAI rapor + FIX_SUGGESTIONS yazimi). 25'te ajan arastirma subtask'larinda butceyi
    // bitirip sentez+fix subtask'ina ULASAMIYORDU (rapor ham/surec-dili, fix bos geliyordu).
    // 40, sentez adiminin dogal tamamlanmasina alan birakir (bkz prompt: fix'i AYNI adimda yaz).
    maxToolCalls: 40,
    promptTemplate: (host) => `
Perform a PASSIVE SSL/TLS configuration audit against the single target below only.
Do NOT install testssl.sh, sslyze, nmap or any other tool, and do NOT attempt any install.
Use ONLY tools ALREADY present in the container — primarily "openssl s_client" and
"curl -Iv" — to observe the TLS handshake and evaluate:
- Certificate: validity, expiry date, chain/CA, hostname match
  (e.g. "echo | openssl s_client -connect ${host}:443 -servername ${host}" then read the cert)
- Supported protocols: probe legacy versions with "openssl s_client -connect ${host}:443
  -tls1_1" / "-tls1" and see whether the handshake succeeds
- Weak/outdated cipher suites (from the negotiated cipher and any suites you can observe)
- Presence and duration of the HSTS header (from "curl -Iv https://${host}")
If a specific check cannot be done with these pre-installed tools, SKIP it and note "not
reviewed (tool unavailable)" — NEVER install anything.
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
target below. Do NOT install whatweb, wappalyzer, nmap or any scanner — observe using ONLY
"curl"/GET on public pages: inspect response headers, HTML <meta generator> tags, script/asset
paths, and well-known version files (e.g. /readme.html, /CHANGELOG.txt) already reachable:
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
    maxToolCalls: 35,
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
    // 2026-08-02: collectFindings() kok duzeltmesi (report.ts) ssl_tls ile CANLI test
    // edilip dogrulandiktan SONRA tekrar acildi (madde 2A). Merkezi duzeltme oldugu
    // icin kvkk da ayni completion-toplama mantigindan yararlanir (ayri tarama testi
    // yapilmadi; Vedat elle spot-kontrol edecek).
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
    maxToolCalls: 35,
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
  {
    key: 'cors_cookie',
    displayName: 'CORS & Çerez Güvenliği',
    description:
      'Access-Control-Allow-Origin degeri (*/yansitilan origin gibi riskli desenler), ' +
      'credentials ile birlikte kullanimi ve cerez bayraklari (Secure/HttpOnly/SameSite) ' +
      'eksikligi. Tamamen pasif, saldirgan olmayan bir kontrol.',
    priceMinorUnit: 79900, // 799,00 TRY — PLACEHOLDER (Vedat onayi bekleniyor)
    modelProvider: PROVIDER,
    maxToolCalls: 25,
    available: true,
    promptTemplate: (host) => `
Run a PASSIVE, NARROW check of CORS and cookie security on the SINGLE target below. Use
GET/HEAD only; do NOT use web search, do NOT browse other sites, do NOT open subtasks.

Check ONLY ${host} — issue AT MOST 2-3 requests total, all against ${host}:
1. CORS: Send ONE GET to ${host} with the request header "Origin: https://probe.example"
   (this string is ONLY a header value to test reflection — do NOT resolve, visit, or scan
   that origin). Inspect the RESPONSE headers of ${host}: Is "Access-Control-Allow-Origin"
   present? Is its value "*" or does it REFLECT the supplied Origin (risky)? Is
   "Access-Control-Allow-Credentials: true" combined with a permissive/reflected origin
   (HIGH risk)?
2. Cookies: From the "Set-Cookie" response headers of ${host}, check the "Secure",
   "HttpOnly" and "SameSite" attributes. List which flags are MISSING per cookie.

Do NOT repeat requests or explore further. After these checks, immediately WRITE the report
and FINISH. Nothing else.
${SAFETY_EN}
${BUDGET_GUARD_EN}
${FIX_SUGGESTIONS_STEP_EN}

Output (Markdown): CORS findings + per-cookie missing flags, each with severity and a
concrete recommendation.

Target: ${host}
`.trim(),
  },
  {
    key: 'csp_analiz',
    displayName: 'CSP (İçerik Güvenlik Politikası) Analizi',
    description:
      'Content-Security-Policy basligi var mi; unsafe-inline/unsafe-eval gibi zayiflatici ' +
      'direktifler, default-src tanimli mi, eksik/zayif yapilandirma. Tamamen pasif.',
    priceMinorUnit: 79900, // 799,00 TRY — PLACEHOLDER (Vedat onayi bekleniyor)
    modelProvider: PROVIDER,
    maxToolCalls: 25,
    available: true,
    promptTemplate: (host) => `
Run a PASSIVE, NARROW analysis of the Content-Security-Policy (CSP) of the SINGLE target
below. Use GET/HEAD only; do NOT use web search, do NOT browse other sites, do NOT open subtasks.

Check ONLY ${host} (homepage GET):
1. Is a "Content-Security-Policy" response header present (also check a CSP <meta http-equiv>
   tag in the homepage HTML)?
2. If present: does it define "default-src"? Does it contain weakening directives such as
   "unsafe-inline" or "unsafe-eval"? Are any sources overly broad (e.g., "*" or bare "http:")?
3. If absent: note that no CSP is enforced (clickjacking/XSS mitigation gap).

After these checks, immediately WRITE the report and FINISH. Nothing else.
${SAFETY_EN}
${BUDGET_GUARD_EN}
${FIX_SUGGESTIONS_STEP_EN}

Output (Markdown): CSP presence, weak/missing directives, and concrete hardening
recommendations (example CSP).

Target: ${host}
`.trim(),
  },
];

export function getPackageDef(key: string): ScanPackageDef {
  const def = SCAN_PACKAGES.find((p) => p.key === key);
  if (!def) throw new Error(`Bilinmeyen paket: ${key}`);
  return def;
}
