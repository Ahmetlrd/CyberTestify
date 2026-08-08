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
    | 'csp_analiz'
    | 'subdomain_takeover'
    | 'api_discovery'
    | 'injection_verify'
    | 'idor_verify'
    | 'ssrf_verify'
    | 'file_upload_verify'
    | 'business_logic_verify'
    | 'race_massassign_verify'
    | 'rce_verify'
    | 'authenticated_scan'
    | 'autonomous_pentest';
  displayName: string;
  description: string;
  priceMinorUnit: number; // kurus
  modelProvider: string; // PentAGI'de tanimli provider profil adi
  maxToolCalls: number; // flow bazinda yumusak tavan (worker.ts uygular)
  // GUVENLIK PROFILI (Faz 1 altyapisi): flow'a hangi HTTP-metot politikasinin
  // uygulanacagini belirler. Belirtilmezse 'passive'.
  //  - 'passive'      : YALNIZCA GET/HEAD/OPTIONS. Veri degistiren hicbir metot yok
  //                     (mevcut tum paketler). Go guard + worker strict-halt zorlar.
  //  - 'active-light' : zafiyeti DOGRULAMAYA yonelik kontrollu POST/form serbest AMA
  //                     DELETE/PATCH + veri-yazan PUT + toplu veri cekme (exfil) +
  //                     DoS/flood KESINLIKLE yasak.
  //  - 'active-verify-only' : RCE/komut-enjeksiyonu KANITI icin EN SIKI — active-light'in
  //                     tumu + gercek komut calistirma payload'lari (ters kabuk, hassas
  //                     dosya, fetch|sh, yikim) da bloklu; yalniz kor kanit (sleep/canary).
  securityProfile?: 'passive' | 'active-light' | 'active-verify-only';
  networkLayer?: boolean;
  fixSuggestionPriceMinorUnit?: number;
  // false ise musteriye SATILMAZ: paket listesinden gizlenir + siparis reddedilir.
  // iso27001/pci su an GEÇİCİ gizli — ajan yasaga ragmen POST deniyor, tarama
  // guvenlik geregi durduruluyor (rapor cikmiyor). Kalici cozum: PentAGI tool-level
  // GET-only patch'i (bkz PATCHES.md 'GET-only' plani). Patch dogrulaninca tekrar acilacak.
  available?: boolean;
  // true ise paket LISTELENIR ama "Yakında" olarak gosterilir: satin ALINAMAZ (createOrder
  // reddeder), CTA pasif. Kod/prompt SILINMEZ — Vedat ilk-launch olgunlugu icin sonra acacak.
  comingSoon?: boolean;
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

export type SecurityProfile = 'passive' | 'active-light' | 'active-verify-only';

// Paketin guvenlik profili — belirtilmezse GUVENLI varsayilan 'passive'.
export function securityProfileFor(def: ScanPackageDef): SecurityProfile {
  return def.securityProfile ?? 'passive';
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
  subdomain_takeover: { displayName: 'Subdomain Takeover Scan', description: 'Passively discovers subdomains (via DNS + Certificate Transparency logs, NOT brute-force) and flags dangling CNAME records pointing to de-provisioned cloud resources (Heroku/S3/Azure, etc.). Fully passive.' },
  api_discovery: { displayName: 'API & Swagger Discovery', description: 'Looks for OpenAPI/Swagger docs at common paths (/swagger-ui.html, /openapi.json, etc.), extracts the listed endpoints and flags public, potentially sensitive ones. Passive GET.' },
  injection_verify: { displayName: 'Vulnerability Verification — Injection (SQLi/XSS)', description: 'Active-light check: sends limited, harmless proof-of-concept payloads to PROVE whether injection flaws exist. No data extraction, no data modification. Requires an authorization declaration.' },
  idor_verify: { displayName: 'Vulnerability Verification — Broken Access (IDOR)', description: 'Active-light check: probes predictable resource IDs to verify whether unauthorized access is possible. Never reads/stores the actual data. Requires an authorization declaration.' },
  ssrf_verify: { displayName: 'Vulnerability Verification — SSRF', description: 'Active-light check: proves whether server-side request forgery is possible via a controlled, harmless callback/DNS/timing proof. Never reaches or explores the internal network. Requires an authorization declaration.' },
  file_upload_verify: { displayName: 'Vulnerability Verification — File Upload', description: 'Active-light check: verifies whether file-upload points enforce type/size checks by submitting a harmless, non-executable test file. Never uploads or runs a real payload/webshell. Requires an authorization declaration.' },
  business_logic_verify: { displayName: 'Vulnerability Verification — Business Logic', description: 'Active-light check: proof-of-concept probes for common logic flaws (price/quantity tampering, step-skipping). Never completes a real transaction or writes data. Requires an authorization declaration.' },
  race_massassign_verify: { displayName: 'Vulnerability Verification — Race / Mass Assignment', description: 'Active-light check: a few parallel requests to detect race conditions, and observation of unexpected fields (e.g. isAdmin) being accepted. Never corrupts data or completes privilege escalation. Requires an authorization declaration.' },
  rce_verify: { displayName: 'Vulnerability Verification — RCE / Command Injection', description: 'Strictest active check: proves command injection ONLY via blind time-based or harmless canary evidence. NEVER runs a real command. Requires an authorization declaration.' },
  authenticated_scan: { displayName: 'Authenticated Scan (logged-in)', description: 'Active-light scan performed with a test-account session you provide. Credentials are encrypted, used only against your domain, and deleted after the scan. Requires an authorization declaration.' },
  autonomous_pentest: { displayName: 'Autonomous Multi-Step Pentest', description: 'The closest to a full autonomous, multi-step, chained-discovery engagement — within the same non-exploit limits (no exfil/DoS/auth-bypass/data change). Requires an authorization declaration.' },
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

export const FIX_SUGGESTIONS_DELIM = '===FIX_SUGGESTIONS===';

// === YONTEM DISIPLINI (merkezi, TUM paketlere) — orchestrator.ts her prompt'a locale'e
// gore ekler. Sebep: bir canli taramada ajan, dogrudan curl/openssl yerine "once tarama
// yapip raporu ureten bir Python scripti yazayim" yoluna sapip, script'teki bir string-
// formatlama hatasini ~15-20 kez tekrar tekrar "duzeltme" dongusunde TUM butceyi yakti ve
// bos rapor uretti (ham veri toplama dogruydu; sorun script-debug dongusuydu). Bu blok o
// anti-kalibi hem yasaklar hem de "2 denemeden fazla duzeltme yok, script'i terk et" kuralini koyar.
export const METHOD_GUARD_EN = `
METHOD DISCIPLINE (collect findings DIRECTLY — do NOT get stuck writing/debugging scripts):
Gather evidence with SIMPLE, INDIVIDUAL commands (curl, openssl, dig, nslookup, host) — one check
per command — and WRITE THE FINDINGS YOURSELF in your final step. Do NOT write a complex, multi-line
Python/Bash program that runs the scan and PRODUCES THE REPORT for you; the report is written by YOU
directly, never emitted by a script. If (and only if) you truly need a small script to batch a few
checks, keep it MINIMAL: no string formatting / f-strings / .format() / template placeholders — just
\`print\` the RAW output; never let the script interpret results or write prose. ANTI-LOOP RULE
(critical): do NOT try to fix the same script more than TWICE. If it still misbehaves after the 2nd
fix, ABANDON the script completely and continue with plain one-off commands using whatever raw data
you already have. Never burn your budget in a write→run→fix loop.`.trim();

export const METHOD_GUARD_TR = `
YONTEM DISIPLINI (bulgulari DOGRUDAN topla — script yazip debug etmede TAKILMA):
Kanitlari BASIT, TEKIL komutlarla topla (curl, openssl, dig, nslookup, host) — komut basina tek
kontrol — ve raporu SON adiminda KENDIN yaz. Taramayi yapip RAPORU SENIN YERINE ureten karmasik, cok
satirli bir Python/Bash programi YAZMA; raporu bir script DEGIL, DOGRUDAN SEN yazarsin. Gercekten
birkac kontrolu tek seferde yapmak icin kucuk bir script GEREKIYORSA en sade halde tut: string
formatlama / f-string / .format() / yer-tutucu KULLANMA — sadece ham ciktiyi \`print\` et; script'e
sonuc YORUMLATMA / rapor YAZDIRMA. DONGU YASAGI (kritik): ayni script'i IKIDEN fazla kez duzeltmeyi
DENEME. 2. duzeltmeden sonra hala calismiyorsa script'i TAMAMEN TERK ET ve elindeki ham veriyle tek
tek komutlarla devam et. Butceni yaz-calistir-duzelt dongusunde HARCAMA.`.trim();

// SABIT/DAR checklist paketlerinde (pasif) KESIN script YASAGI — gevsek "sade tut" degil,
// TAM yasak. nomorelink KVKK vakasi: ajan kvkk_audit.sh yazip etrafinda 14 verimsiz cagri
// yapip raporu yazamadan bitti. Bu blok orchestrator'da yalniz securityProfile='passive'
// paketlere eklenir (active-light DAHIL DEGIL — onlar script gerektirebilir).
export const NO_SCRIPT_HARD_EN = `
HARD RULE — NO SCRIPTS FOR THIS PACKAGE: This is a SMALL, FIXED checklist (~8-12 GET requests).
Do NOT write, create, or save ANY script file (.sh / .py / .js / .bash) — not for analysis, not
as a helper, not to "run all checks at once". Do NOT use cat>/heredoc to a script, chmod +x, or
run bash/sh/./<file>. Use ONLY direct, INDIVIDUAL commands (curl / openssl / dig / nslookup / host),
ONE command per check, and read each output directly. Writing a script here is FORBIDDEN and
UNNECESSARY — the checks are few and finish faster and more reliably with direct commands. If you
notice yourself writing/chmod'ing/running a script, STOP immediately and switch to direct one-off
commands.
NO REPEATED FETCH: Once you have GET a path (including the homepage), its output is ALREADY in your
context — do NOT fetch the same URL/path again. Never request the same path more than twice, even for
"just headers" or "just a grep": reuse the earlier output instead. If you truly need two different
views (e.g. body once, headers once), plan them from the start as ONE checklist — repeating the same
path 3+ times is FORBIDDEN and wastes the budget.
NO INTERMEDIATE/DRAFT FILES: Do NOT build the report (or any "findings table", "summary", ASCII-table,
or draft) via 'cat > file << EOF ... EOF' heredoc or any file write. That is the SAME escape pattern as
writing a script. The report is written DIRECTLY as your own final text output in the last step — never
assembled in a file, never "built" with a terminal command.`.trim();

export const NO_SCRIPT_HARD_TR = `
KESIN KURAL — BU PAKETTE SCRIPT YASAK: Bu, KUCUK ve SABIT bir kontrol listesidir (~8-12 GET).
HICBIR script dosyasi (.sh / .py / .js / .bash) YAZMA, olusturma veya kaydetme — ne analiz icin,
ne yardimci arac olarak, ne de "tum kontrolleri tek seferde yapmak" icin. cat>/heredoc ile script
yazma, chmod +x, bash/sh/./<dosya> ile CALISTIRMA da YASAK. SADECE dogrudan TEKIL komutlar kullan
(curl / openssl / dig / nslookup / host), komut basina TEK kontrol, ciktisini dogrudan gor. Bu pakette
script yazmak KESINLIKLE YASAKTIR ve GEREKSIZDIR — kontrol sayisi azdir, dogrudan komutlarla cok daha
hizli ve guvenilir biter. Kendini script yazarken/chmod'larken/calistirirken yakalarsan DERHAL DUR ve
dogrudan tekil komutlara gec.
AYNI URL'YE TEKRAR ISTEK YOK: Bir path'i (anasayfa dahil) BIR KEZ GET ettiysen ciktisi ZATEN
elinde/baglamindadir — AYNI URL/path'i TEKRAR CEKME. Ayni path'e IKIDEN fazla istek atma; "sadece
header" veya "sadece bir grep" icin bile onceki ciktiyi tekrar kullan. Gercekten iki farkli gorunum
gerekiyorsa (ör. bir kez govde, bir kez header) bunu en BASTAN TEK kontrol listesinde planla — ayni
path'i 3+ kez cekmek YASAKTIR ve butceyi bosa harcar.
ARA/TASLAK DOSYA YOK: Raporu (veya "bulgu tablosu", "ozet", ASCII-tablo, taslak gibi herhangi bir ara
urunu) 'cat > dosya << EOF ... EOF' heredoc'u ya da herhangi bir dosya yazimi ile INSA ETME. Bu, script
yazmakla AYNI kacis desenidir. Rapor, son adimda DOGRUDAN senin kendi metin ciktinla yazilir — asla bir
dosyada toplanmaz, asla bir terminal komutuyla "insa edilmez".`.trim();

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
numbers. Write findings directly, not as a log of completed steps.
NO COMPLIANCE CLAIMS (legal caution): This is a narrow, single-focus PASSIVE check — it CANNOT
establish conformance to any standard or regulation. Do NOT add a "Compliance & Standards"
conformance section, and NEVER assert the target "complies with" / "is compliant with" /
"meets" / "conforms to" OWASP, NIST, GDPR, PCI-DSS, ISO 27001, etc., and NEVER output a
"✓ compliant" status against a standard. Prefer to OMIT any standards-conformance section. If
a standard is genuinely relevant, mention it ONLY with cautious wording, e.g. "these specific
checks partially map to relevant clauses of X; a full compliance assessment requires a
comprehensive, dedicated audit." Phrases like "industry best practices" are fine as general
guidance, but never as a compliance verdict.`.trim();

const FIX_SUGGESTIONS_STEP_EN = `
MANDATORY FIX SUGGESTIONS (do NOT skip when there are findings): In the SAME step, right
after the findings, output EXACTLY this line on its own:
${FIX_SUGGESTIONS_DELIM}
and BELOW it, for EACH important finding write a concrete, actionable remediation (with a
SAFE config/code example when useful). This is a PAID deliverable — never omit it, never
leave it for a later subtask. ABSOLUTE RULE: remediation ONLY; it must NEVER contain runnable
exploit code, attack payloads, or attack tooling. Only if there are genuinely NO findings at
all, omit the delimiter.`.trim();

// === Hassas dosya (.git/.env/yedek) dogrulama — MERKEZI (header_leak/pci/iso kullanir).
// GERCEK yanlis-pozitif: nomorelink.com'da ISO "/.git/config, /.env HTTP 200 -> KRITIK acik"
// dedi; PCI ise icerigi inceleyip "hepsi ana sayfa HTML'i donuyor (catch-all), gercekte acik
// DEGIL" dedi (dogru). ISO yalniz status koduna bakip icerige BAKMAMISTI. Bu blok o hatayi onler.
const EXPOSED_FILE_VERIFY_EN = `
EXPOSED-FILE VERIFICATION (MANDATORY 2-step — avoids the #1 false positive on SPA/catch-all sites):
Many sites (especially SPAs) return HTTP 200 with the HOMEPAGE HTML for EVERY non-existent path
(catch-all routing). HTTP 200 ALONE DOES NOT MEAN A FILE IS EXPOSED. Before you report ANY sensitive
file (.git/config, .env, backup.zip, .DS_Store, wp-config.php, etc.) as exposed/accessible/critical,
you MUST do BOTH:
 (1) FETCH THE HOMEPAGE '/' first and remember its body (first few hundred chars) for comparison.
 (2) For each candidate file: GET it, then confirm BOTH of these, else it is NOT exposed:
     (a) CONTENT MATCHES THE FILE'S EXPECTED FORMAT — e.g. .git/config contains '[core]' or
         'repositoryformatversion='; .env has KEY=VALUE lines (^[A-Z_]+=); backup.zip starts with the
         ZIP magic 'PK'; .DS_Store contains 'Bud1'; wp-config.php contains "define('DB_...". If the
         body is HTML (<!doctype/<html) while a NON-HTML file is expected, it is NOT the real file.
     (b) CONTENT IS NOT (nearly) IDENTICAL TO THE HOMEPAGE '/'. If it equals the homepage (same first
         ~300 chars), it is catch-all routing → the file is NOT actually exposed.
Report a file as EXPOSED/critical ONLY when (a) format matches AND (b) it differs from the homepage.
Otherwise state it as "NOT accessible (HTTP 200 is catch-all/SPA, not the real file)". In the report,
say explicitly that you verified CONTENT, not just the status code.`.trim();

// === ACTIVE-LIGHT guvenlik blogu (Faz 3) — SAFETY_EN'in aksine KANIT-amacli zararsiz
// probe'lara IZIN verir; ama istismar/exfil/veri-degistirme/DoS/auth-bypass'i hem prompt
// hem TOOL SEVIYESINDE (passive_guard.go active-light) yasaklar. Yalniz active-light paketler.
const SAFETY_ACTIVE_LIGHT_EN = `
SCOPE & SAFETY (active-light VERIFICATION — prove presence, NEVER exploit): You MAY send a FEW
LIMITED, HARMLESS proof-of-concept probes to PROVE a vulnerability EXISTS. STRICTLY FORBIDDEN and
technically BLOCKED at the tool level: extracting real data (DB dump/enumerate; sqlmap --dump/
--dump-all/--os-shell/-a are blocked), modifying or deleting data (PUT/PATCH/DELETE and any write
are blocked), authentication bypass / session theft, and load/stress/DoS (ab/wrk/hping etc. blocked).
A single harmless POST test submission is allowed; PUT/DELETE/PATCH are NOT. Access ONLY the
specified host; stay at the HOSTNAME/application layer; never touch any other target. When in doubt,
SKIP. Report ONLY evidence of PRESENCE — never include any extracted/sensitive data (there must be none).
NO INSTALLS: do NOT install or attempt to install ANY tool/package (apt/pip/npm/go install/git clone/
curl|bash/downloading binaries). Use ONLY tools already present in the container; if a tool is missing,
SKIP that check ("not reviewed (tool unavailable)") — never install.`.trim();

// RCE/komut-enjeksiyonu KANITI — EN SIKI. Yalniz KOR kanit; gercek komut ASLA calistirilmaz.
const SAFETY_RCE_VERIFY_EN = `
STRICTEST SAFETY (RCE/command-injection VERIFICATION — BLIND PROOF ONLY): You may ONLY prove a
command-injection flaw via HARMLESS BLIND evidence: (a) TIME-BASED — inject a benign delay (e.g. a
"sleep 5"-style payload) and infer execution from the response time; or (b) a harmless CANARY string
echoed back. NEVER run a real command: NO file read/write, NO reading /etc/passwd or secrets, NO
network connection/reverse shell, NO fetch|sh, NO destructive commands, NO system changes — these are
ALSO blocked at the tool level for this package. Report ONLY: "command execution appears possible
(blind time/canary evidence)". Access ONLY the specified host. NO data extraction, NO exploitation.
NO INSTALLS: do NOT install any tool/package; use only what is present, else SKIP.`.trim();

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
meta ifadeler ASLA kullanma. Bulgulari dogrudan yaz, tamamlanan adimlarin gunlugu gibi degil.
UYUM BEYANI YOK (hukuki tedbir): Bu, dar ve tek-odakli bir PASIF kontroldur — hicbir standarda/
mevzuata uyumlulugu KANITLAYAMAZ. Ayri bir "Uyum ve Standartlar" bolumu EKLEME; hedefin OWASP,
NIST, KVKK/GDPR, PCI-DSS, ISO 27001 vb. ile "uyumludur"/"uyumlu"/"karsilar"/"uygundur" oldugunu
ASLA iddia etme ve bir standarda karsi "✓ uyumlu" durumu YAZMA. Standart-uyum bolumunu tercihen
HIC koyma. Bir standart gercekten ilgiliyse YALNIZCA temkinli dille an: "bu kontroller X'in ilgili
maddeleriyle KISMEN ortusur; tam uyumluluk degerlendirmesi kapsamli, ayri bir denetim gerektirir."
"Endustri en iyi uygulamalari" gibi genel ifadeler kabul edilir ama uyum HUKMU olarak degil.`.trim();

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
    promptTemplate: (host) => `This is a FAST, PASSIVE and SHORT pre-check package (Basit Tarama) — NOT a deep scan.
GOAL: Produce a clean, professional, customer-facing security pre-check report in TURKISH for the single homepage of the target below. The report must look like it was written by a senior security analyst in one sitting.
STRICT SCOPE (do not expand):
1. HTTP security headers on the homepage only (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection, Content-Type)
2. TLS certificate validity, expiry, chain, protocol version and cipher
3. Server / CDN / technology fingerprint visible from response headers and HTML (passive only)
4. Very light information disclosure visible on the homepage (e.g. obvious API endpoints in preconnect/link tags)
FORBIDDEN (any violation = immediate termination, no report):
- Any non-GET/HEAD/OPTIONS request
- Exploitation, injection, authentication, brute-force, directory forcing
- Installing any tool or package
- Writing or executing scripts (.sh/.py/.js/.bash)
- Re-fetching the same URL more than once
- Building draft/intermediate files via heredoc (cat > file << EOF or similar)
- Accessing any host other than the given target
- Claiming compliance with any standard (OWASP, NIST, KVKK, PCI, ISO, etc.)
TOOL BUDGET: Maximum 25 tool calls. After ~12 calls STOP all new discovery and write the final report. Prefer 1-command-per-check (curl, openssl, dig). Never write scripts.
HARD RULE — NEVER SUBMIT A PARTIAL REPORT: The final report MUST be written as ONE complete, uninterrupted piece of output, from "YÖNETİCİ ÖZETİ" through the very end (including the ===FIX_SUGGESTIONS=== line). If you sense you are close to the tool-call budget or output-length limit, STOP gathering new evidence immediately and write a SHORTER but still 100% COMPLETE report using only what you already have — every mandatory section must be present, even if brief. Never end your output mid-sentence, mid-table, or mid-section. A short-but-complete report is always correct; a long-but-truncated report is always wrong.
OUTPUT RULES (HIGHEST PRIORITY):
- FINALIZE PROPERLY: the report is captured only when you write it as the RESULT/completion of your task step. After gathering evidence, you MUST write the COMPLETE final report (from "YÖNETİCİ ÖZETİ" through the ===FIX_SUGGESTIONS=== line) as your completion output. Do NOT just gather evidence and then stop or go idle — a scan that ends without a written final report is a FAILURE. Do NOT defer the report or fix-suggestions to a separate later subtask; write everything now, in one piece.
- Language: FULLY TURKISH (bulgular, özet, risk açıklamaları).
- No internal process language ("Subtask", "TASK COMPLETED", "Next step", tool logs, etc.).
- No false positives. If evidence is weak or ambiguous, mark as "İnceleme gerekli" or omit.
- Risk rating must be honest and consistent with findings:
  - Kritik / Yüksek → missing critical protections that enable easy attacks (e.g. no CSP + no X-Frame-Options while interactive content exists)
  - Orta → several important headers missing or certificate expiring soon
  - Düşük → only minor or informational issues
  Never output "Düşük Risk" when multiple high-impact headers are missing.
MANDATORY REPORT STRUCTURE (exactly in this order):
1. YÖNETİCİ ÖZETİ (3-5 short bullets)
   - Overall risk level + one-sentence justification
   - Most important 2-3 findings
   - One clear next-action recommendation
2. GENEL DEĞERLENDİRME
   - Risk level badge text (Düşük / Orta / Yüksek)
   - 1-2 sentence summary
3. HTTP GÜVENLİK BAŞLIKLARI
   - Table or clean list: Header | Durum | Kısa açıklama
   - Only state what was actually observed
4. TLS SERTİFİKA DURUMU
   - Validity, days remaining, hostname match, issuer, TLS version, cipher
   - Clear warning if expiry < 45 days
5. SUNUCU / TEKNOLOJİ İMZASI
   - CDN, framework, analytics, obvious passive fingerprints
   - Only what is visible without active probing
6. TESPİT EDİLEN RİSKLER (grouped by severity)
   - Yüksek / Orta / Bilgilendirme
   - Each item: short title + 1-2 sentence impact explanation
   - No speculative claims
7. ===FIX_SUGGESTIONS===
   - This section is a PAID add-on ("AI Çözüm Önerileri").
   - CRITICAL MARKER RULE: Write the marker ===FIX_SUGGESTIONS=== EXACTLY ONCE, on its OWN line, immediately before this section — it is an internal split control token, NOT visible customer text. NEVER write this marker anywhere else and NEVER reference it inline in prose (do NOT write things like "see the fix marker"); if you must refer to this section in the text above, call it "AI Çözüm Önerileri bölümü".
   - If the order includes the paid add-on flag → write concrete, safe, actionable remediation for each important finding (config examples allowed, never exploit code).
   - If the paid flag is NOT present → output exactly this line and nothing more under it:
     Bu bölüm kilitli — "AI Çözüm Önerileri" eklentisi satın alınınca rapora eklenir.
Keep the whole report SHORT and scannable (target: 1.5–2.5 pages when rendered). Prefer clarity over volume.
Target: ${host}
`,
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
   (For .git/.env/backups apply the EXPOSED-FILE VERIFICATION below — HTTP 200 is NOT enough.)
${SAFETY_EN}
${BUDGET_GUARD_EN}
${EXPOSED_FILE_VERIFY_EN}
${FIX_SUGGESTIONS_STEP_EN}

Output: list missing headers and any GENUINELY exposed files (content-verified) by severity with concrete advice.
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
    priceMinorUnit: 299900,
    modelProvider: PROVIDER,
    // DAR/deterministik + kvkk disiplini (2026-08-03): sentez adimini AC BIRAKMAMAK icin
    // biraz bol tavan (bkz kvkk kok neden).
    maxToolCalls: 40,
    available: true,

    promptTemplate: (host) => `
Run a PASSIVE, NARROW, FIXED "PCI-DSS READINESS PRE-ASSESSMENT" on the SINGLE target below.
This is a FIXED CHECKLIST — NOT open-ended research. HARD CONSTRAINTS: do NOT open new subtasks;
do NOT crawl/scan the whole site; do NOT use web search. Inspect ONLY ${host} — the homepage plus
at most the few specific paths listed below. A TOTAL of ~5-8 GET/HEAD requests is enough; do not wander.

Do EXACTLY these checks on ${host} and map each to a PCI-DSS requirement (observation ONLY — this
does NOT establish compliance):
1. TLS version/cipher/certificate -> Req 4.2.1 (strong cryptography in transit)
2. HTTP security headers (HSTS/CSP/X-Frame-Options/X-Content-Type-Options) -> Req 6.4
3. Cookie flags (Secure/HttpOnly/SameSite) on any Set-Cookie -> Req 8 (session security)
4. Server banner / default pages disclosing versions -> Req 2.2 (secure configuration)
5. Exposed sensitive files via a single GET each (/.git/config, /.env, /backup.zip) -> Req 3 (data exposure)
   — apply the EXPOSED-FILE VERIFICATION below; a bare HTTP 200 is NOT proof of exposure.

After these 5 checks, IMMEDIATELY and in the SAME step write the single report AND the
${FIX_SUGGESTIONS_DELIM} section, then FINISH. Do NOT open a separate "write report" subtask;
do nothing else.
${SAFETY_EN}
${BUDGET_GUARD_EN}
${EXPOSED_FILE_VERIFY_EN}
${FIX_SUGGESTIONS_STEP_EN}

Output (Markdown table): "PCI-DSS Requirement | Observation | Observable control (Present/Partial/Absent) |
Recommendation". Use ONLY Present/Partial/Absent for what is externally observable — NEVER write
"compliant"/"pass"/"conformant". End note (MANDATORY): "This is an externally observable READINESS
pre-assessment — NOT an official PCI-DSS/ASV/QSA test and NOT a statement of compliance. Internal
network/CDE, segmentation, ASV scanning and penetration testing are OUT OF SCOPE; a full compliance
assessment requires a comprehensive, dedicated audit."

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
    priceMinorUnit: 249900,
    modelProvider: PROVIDER,
    maxToolCalls: 45,
    // 2026-08-02: collectFindings() kok duzeltmesi (report.ts) ssl_tls ile CANLI test
    // edilip dogrulandiktan SONRA tekrar acildi (madde 2A). Merkezi duzeltme oldugu
    // icin kvkk da ayni completion-toplama mantigindan yararlanir (ayri tarama testi
    // yapilmadi; Vedat elle spot-kontrol edecek).
    // ISTISNA: Turk hukuku terminolojisi — bu promptTemplate TURKCE kalir (Turkce
    // sabitleri kullanir). Yalniz TR bolgesinde gosterilir.
    promptTemplate: (host) => `
Asagidaki TEK hedef icin SABIT, DAR bir "KVKK ON UYUM KONTROLU" yap. Bu ac-uclu arastirma
DEGIL, SABIT bir kontrol listesidir. KRITIK KISITLAR: YENI SUBTASK ACMA; tum siteyi TARAMA/
crawl ETME; internette ARASTIRMA yapma. ${host} ANA SAYFASINI incele; ayrica gizlilik/aydinlatma
ve cerez politikasi sayfalarini (ana sayfada linkliyse) ve asagida (madde 4) belirtilen SABIT
iletisim/hakkimizda yollarini TEK GET ile kontrol et. TOPLAM ~8-12 GET yeterli; wordlist/brute
ve gereksiz sayfa gezme YOK. Bu HUKUKI DANISMANLIK DEGILDIR; amac
disaridan gorulebilen eksikleri KVKK ilkeleriyle eslestirmek.
${HAZIRLIK_FOCUS_TR}

Su 5 kontrolu YAP (yalnizca normal GET ile gozlem):
1. Aydinlatma metni / Gizlilik politikasi sayfasi var mi, erisilebilir mi?
2. Cerez rizasi (consent) banner'i var mi; ana sayfa yanitinda rizadan ONCE izleyici cerez
   (Set-Cookie) birakiliyor mu?
3. Kisisel veri toplayan formlar (iletisim/uyelik) HTTPS uzerinde mi; acik rizaya atif var mi?
4. Veri sorumlusu / iletisim / VERBIS atifi gozlemleniyor mu? KAPSAM: ana sayfaya EK OLARAK
   su yaygin yollari da TEK GET ile dene ve icerikte sirket adi / e-posta / telefon / adres
   ara: /iletisim, /contact, /hakkimizda, /about, /kvkk. Bir alt sayfada bulursan "Uygun" say.
5. Ucuncu taraf izleyiciler (analytics, pixel, GTM) ana sayfa HTML'inde gozlemleniyor mu?

DURUSTLUK KURALI (KRITIK): Kontrol ettigin yerlerde bir sey GORMEDIYSEN, "yoktur/bulunmamaktadir"
gibi KESIN bir YOKLUK iddiasi ETME. Bunun yerine kontrolun KAPSAMINI durustce belirt:
"Kontrol edilen sayfalarda (ana sayfa + /iletisim, /hakkimizda) gozlemlenmedi; baska bir sayfada
mevcutsa bu kontrol kapsami disinda kalmis olabilir." Yalnizca gercekten bakip bulamadigin seyler
icin bunu yaz; buldugun seyleri net "Uygun" isaretle.

Bu kontrollerden SONRA HEMEN, AYNI adimda, tek raporu VE cozum onerilerini yaz ve BITIR — ayri
bir "rapor yazma" subtask'i ACMA, baska hicbir sey yapma.
${SAFETY_TR}
${BUDGET_GUARD_TR}
${FIX_SUGGESTIONS_STEP_TR}

CIKTI YAPISI (bu SIRAYLA, TAM TURKCE karakterlerle — İ/ı/ş/ç/ğ/ü/ö dogru kullan):

## Yönetici Özeti
En kritik 3-4 bulguyu TEK SATIRLIK madde olarak yaz (kisa, teknik olmayan, is diliyle), sonra:
**Öncelikli Aksiyon:** [tek cümlede en acil yapilmasi gereken]

## Bulgular
Markdown tablo — sutunlar TAM olarak: "KVKK İlkesi/Konu | Gözlem | Durum | Öneri".
Durum sutunu SADECE su üç degerden biri olsun (baska kelime YOK, ikon/emoji YOK, ✓/❌/🚨 YOK):
"Uygun", "Dikkat", "Eksik". Durum hucresine SADECE bu tek kelimeyi yaz (ör. "Eksik"), "❌ UYUMSUZ"
veya "✓ UYGUN" GIBI yazma.

KESIN DIL YASAKLARI (UYUM BEYANI YOK — hukuki risk):
- "uyumlu / uyumludur / uyumsuz / uyumsuzdur / compliant / non-compliant" gibi KESIN UYUM HUKMU
  veren kelimeleri raporun HICBIR yerinde KULLANMA. Durum icin yalniz Uygun/Dikkat/Eksik.
- "İHLAL" kelimesini ve "KVKK İhlali" gibi baslik/ibareleri KULLANMA. Bunun yerine notr "Gözlemlenen
  Eksiklikler" de. "Art. 5 ihlal edildi" GIBI kesin hukum CUMLESI KURMA.
- KVKK madde numarasina atif SERBEST ama SADECE TEMKINLI dille: "Bu gözlem, KVKK m.5 ile kısmen
  örtüşüyor olabilir" gibi; asla "bu madde ihlal edilmiştir" deme.
- IC-SUREC ifadeleri (Subtask 417, Alt-Görev N, "araç sınırları ... bekliyor", "sonraki adımlar")
  MUSTERI RAPORUNA YAZILMAZ. Statik GET ile gorulemeyen icerik varsa surec-DISI, anlamli bir dille
  yaz: "SPA/JavaScript ile yuklenen icerikler pasif GET ile gozlemlenemedi" gibi ("Subtask" kelimesi
  GECMESIN).
(Not: risk seviyesi ve kontrol özeti kutusu OTOMATIK/kod tarafindan eklenir — SEN "uyum skoru"
GIBI bir ozet CUMLESI/hata notu YAZMA; yalnizca gözlem + Durum + öneri.)

Sonra cozum onerileri bolumu (delimiterden sonra) SU YAPIDA:

## Önerilen Aksiyonlar
Öncelik sirali, İŞ DİLİYLE, her biri 1-2 cümle (kod YOK). Ornek bicim:
"**Çerez Rızası Banner'ı (Yüksek Öncelik):** Sayfa yüklenir yüklenmez rıza banner'ı gösterilmeli;
rıza alınana kadar üçüncü taraf izleyiciler yüklenmemeli. Teknik detay için Ek-A'ya bakınız."

## Ek-A: Teknik Uygulama Detayları
Yalnizca GEREKLI oldugunda KISA, GENERIK kod snippet'leri koy. Hedefe özel GERÇEK kimlikleri
(GTM/Pixel/Analytics ID'leri gibi) KULLANMA — placeholder yaz (ör. GTM-XXXXXXX, PIXEL_ID).
Tam production kod DEGIL, öz/kisa örnek yeterli.

Rapor sonunda: "Bu rapor hukuki görüş/uyum beyanı değildir; nihai değerlendirme için KVKK
uzmanı/avukat gerekir." notu.

Hedef: ${host}
`.trim(),
  },
  {
    key: 'iso27001_hazirlik',
    displayName: 'ISO 27001 Hazırlık Kontrol Listesi',
    description:
      'Disaridan gozlemlenebilen teknik kontrollerin ISO 27001 Ek-A maddeleriyle ' +
      'eslestirildigi pasif hazirlik raporu. RESMI sertifikasyon/denetim DEGILDIR.',
    priceMinorUnit: 349900,
    modelProvider: PROVIDER,
    // DAR/deterministik + kvkk disiplini (2026-08-03): sentez adimini AC BIRAKMAMAK icin
    // biraz bol tavan (bkz kvkk kok neden — 35 dar kalirsa rapor yazilmadan bitebilir).
    maxToolCalls: 40,
    available: true,

    promptTemplate: (host) => `
Run a PASSIVE, NARROW, FIXED ISO/IEC 27001 Annex A readiness spot-check on the SINGLE target
below. This is a FIXED CHECKLIST — NOT open-ended research. HARD CONSTRAINTS: do NOT open new
subtasks; do NOT crawl/scan the whole site; do NOT use web search or look up the ISO standard
online (you already know it). Inspect ONLY ${host} — the homepage plus at most the few specific
paths listed below. A TOTAL of ~5-8 GET/HEAD requests is enough; do not wander.

Do EXACTLY these checks on ${host} and map each to an Annex A clause (observation ONLY — this
does NOT establish conformance):
1. TLS certificate valid + modern protocol (TLS 1.2/1.3)? -> A.8.24 (cryptography)
2. HTTP security headers present (HSTS, CSP, X-Frame-Options, X-Content-Type-Options)? -> A.8.23/A.8.9
3. Server/technology banner disclosing versions? -> A.8.9 (secure configuration)
4. Obvious exposed files via a single GET each (/.git/config, /.env, /robots.txt)? -> A.8.12 (data leakage)
   — apply the EXPOSED-FILE VERIFICATION below; a bare HTTP 200 is NOT proof of exposure.
5. Is a privacy/security policy page reachable? -> A.5.1 (policies)

After these 5 checks, IMMEDIATELY and in the SAME step write the single report AND the
${FIX_SUGGESTIONS_DELIM} section, then FINISH. Do NOT open a separate "write report" subtask;
do nothing else.
${SAFETY_EN}
${BUDGET_GUARD_EN}
${EXPOSED_FILE_VERIFY_EN}
${FIX_SUGGESTIONS_STEP_EN}

Output (Markdown table): "Annex A Clause | Observation | Observable control (Present/Partial/Absent) |
Recommendation". Use ONLY Present/Partial/Absent for what is externally observable — NEVER write
"compliant"/"pass"/"conformant". End note (MANDATORY): "This is an externally observable READINESS
spot-check — NOT an ISO 27001 audit/certification and NOT a statement of compliance. ISMS scope,
documentation, internal processes and any control not observable from outside are OUT OF SCOPE;
a full conformance assessment requires a comprehensive, dedicated audit."

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
  {
    // FAZ 2 (2026-08-03) — dusuk riskli active-light-adayligi ama PASIF yeterli.
    key: 'subdomain_takeover',
    displayName: 'Subdomain Takeover Taraması',
    description:
      'Hedefin alt alan adlarini (DNS + Sertifika Seffafligi/CT loglari uzerinden, ' +
      'brute-force DEGIL) pasif kesfeder; "bosta dusmus" (dangling) CNAME kayitlarini ' +
      '(silinmis Heroku/S3/Azure vb. kaynaga isaret eden) tespit eder. Tamamen pasif.',
    priceMinorUnit: 149900, // 1.499,00 TRY — Vedat ONAYLADI (2026-08-03)
    modelProvider: PROVIDER,
    maxToolCalls: 35,
    securityProfile: 'passive',
    // Scope hazir: crt.sh zaten SCOPE_ALLOWLIST'te (config.ts) + hedefin alt alan adlari
    // isInScope'ta kapsam-ici (host.endsWith('.'+target)) + DNS resolver'lar allowlist'te.
    available: true,
    promptTemplate: (host) => `
Run a PASSIVE, NARROW subdomain-takeover check for the DOMAIN of the single target below. This
is a FIXED checklist. HARD CONSTRAINTS: do NOT open new subtasks; do NOT brute-force/wordlist
subdomains; do NOT scan/crawl; use ONLY passive sources. For THIS package, querying Certificate
Transparency logs and DNS for subdomains of ${host} is the INTENDED passive scope.

Steps (passive only):
1. Enumerate subdomains from PASSIVE sources ONLY: Certificate Transparency logs
   (e.g. GET https://crt.sh/?q=%25.${host}&output=json) plus any DNS records you can observe.
   Do NOT guess/brute-force names.
2. For each discovered subdomain, resolve DNS and check for a CNAME (dig CNAME <sub>).
3. Flag DANGLING records: a CNAME pointing to a de-provisioned/unclaimed third-party resource
   (*.herokuapp.com, *.s3.amazonaws.com, *.github.io, *.azurewebsites.net, *.cloudfront.net,
   Netlify, Fastly, etc.) that returns NXDOMAIN or a known "no such app/bucket" fingerprint =
   potential subdomain takeover. DETECTION ONLY — never CLAIM/register any resource.

After these checks, IMMEDIATELY and in the SAME step write the single report AND the
${FIX_SUGGESTIONS_DELIM} section, then FINISH. Do NOT open a separate "write report" subtask.
${SAFETY_EN}
${BUDGET_GUARD_EN}
${FIX_SUGGESTIONS_STEP_EN}

Output (Markdown table): "Subdomain | CNAME target | Status (resolves/dangling/clean) | Severity |
Recommendation".

Target domain (derive the registrable domain from): ${host}
`.trim(),
  },
  {
    key: 'api_discovery',
    displayName: 'API & Swagger Keşfi',
    description:
      'Yaygin yollarda (/swagger-ui.html, /api/v1/docs, /openapi.json vb.) OpenAPI/Swagger ' +
      'dokumani arar; varsa listelenen endpointleri cikarir ve kimlik dogrulamasi ' +
      'gerektirmeyen (halka acik) hassas olabilecek uclari isaretler. Pasif GET.',
    priceMinorUnit: 129900, // 1.299,00 TRY — Vedat ONAYLADI (2026-08-03)
    modelProvider: PROVIDER,
    maxToolCalls: 30,
    securityProfile: 'passive',
    available: true,
    promptTemplate: (host) => `
Run a PASSIVE, NARROW API/OpenAPI-documentation discovery on the SINGLE target below. FIXED
checklist. HARD CONSTRAINTS: do NOT open new subtasks; do NOT brute-force/fuzz large wordlists;
do NOT scan/crawl the whole site; GET only. Check ONLY ${host}.

Steps:
1. With a single GET each, probe these WELL-KNOWN documentation paths (no fuzzing beyond this
   short list): /swagger-ui.html, /swagger/index.html, /api/docs, /api/v1/docs, /openapi.json,
   /swagger.json, /v2/api-docs, /v3/api-docs, /api-docs, /redoc, /.well-known/openapi.json.
2. If an OpenAPI/Swagger document is found, extract the declared endpoints (path + method).
3. Flag endpoints that appear PUBLIC (no auth/security requirement declared) AND potentially
   sensitive (admin, user, export, internal, debug, token, upload, etc.). DETECTION ONLY — do
   NOT call/exercise those endpoints, do NOT send POST/write requests, just report from the doc.

After these checks, IMMEDIATELY and in the SAME step write the single report AND the
${FIX_SUGGESTIONS_DELIM} section, then FINISH. Do NOT open a separate "write report" subtask.
${SAFETY_EN}
${BUDGET_GUARD_EN}
${FIX_SUGGESTIONS_STEP_EN}

Output (Markdown): whether an API doc was found + where; a table "Endpoint | Method | Auth
required? | Sensitivity | Note"; and hardening recommendations (protect docs, require auth).

Target: ${host}
`.trim(),
  },
  {
    // FAZ 3 — ilk ACTIVE-LIGHT paket. Zafiyeti DOGRULAR, ISTISMAR ETMEZ. Zorunlu
    // yetkilendirme beyani olmadan siparis olusturulamaz (bkz orders.ts + orchestrator).
    key: 'injection_verify',
    displayName: 'Zafiyet Doğrulama — Enjeksiyon (SQLi/XSS)',
    description:
      'Aktif-hafif kontrol: tespit edilen giris noktalarina ZARARSIZ kanit-amacli test ' +
      'payload’lari gonderip enjeksiyon (SQLi/XSS) zafiyetinin VAR OLDUGUNU dogrular. Veri ' +
      'CEKMEZ, veri SILMEZ/DEGISTIRMEZ. Yetkilendirme beyani gerektirir.',
    priceMinorUnit: 399900, // PLACEHOLDER (Vedat onayi bekleniyor)
    modelProvider: PROVIDER,
    maxToolCalls: 45,
    securityProfile: 'active-light',
    available: true,
    promptTemplate: (host) => `
Run a NARROW, ACTIVE-LIGHT vulnerability VERIFICATION for injection flaws (SQLi/XSS) on the SINGLE
target below. GOAL: PROVE whether a vulnerability EXISTS — NEVER exploit it. FIXED checklist.
HARD CONSTRAINTS: do NOT open new subtasks; do NOT crawl the whole site; ~8-12 requests total.

Steps:
1. Identify a FEW public input points (URL query parameters, visible form fields) — a handful only.
2. For each, send ONE harmless proof-of-concept probe and look for EVIDENCE of a flaw:
   - SQLi: a database ERROR message, or a measurable timing difference from a benign time-based probe.
   - XSS: the probe value REFLECTED UNENCODED in the HTML response.
   (If you use sqlmap, DETECTION ONLY: --batch; NEVER --dump/--dump-all/--os-shell/-a — blocked at tool level.)
3. Report ONLY the evidence of PRESENCE (which parameter, what evidence). There must be NO extracted data.

After these checks, IMMEDIATELY and in the SAME step write the single report AND the
${FIX_SUGGESTIONS_DELIM} section, then FINISH. Do NOT open a separate "write report" subtask.
${SAFETY_ACTIVE_LIGHT_EN}
${BUDGET_GUARD_EN}
${FIX_SUGGESTIONS_STEP_EN}

Output (Markdown table): "Input Point | Type (SQLi/XSS) | Evidence | Severity | Recommendation".
State clearly that this confirms PRESENCE only and a full manual assessment is advised. NEVER include
any extracted/sensitive data.

Target: ${host}
`.trim(),
  },
  {
    key: 'idor_verify',
    displayName: 'Zafiyet Doğrulama — Yetkisiz Erişim (IDOR)',
    description:
      'Aktif-hafif kontrol: hedefte tahmin edilebilir kaynak kimlikleri (or. /api/user/123) ' +
      'olup olmadigini tespit eder, kimligi degistirip yetkisiz erisimin mumkun olup olmadigini ' +
      'DOGRULAR. Erisilen gercek/hassas veriyi RAPORA YAZMAZ. Yetkilendirme beyani gerektirir.',
    priceMinorUnit: 399900, // PLACEHOLDER (Vedat onayi bekleniyor)
    modelProvider: PROVIDER,
    maxToolCalls: 45,
    securityProfile: 'active-light',
    available: true,
    promptTemplate: (host) => `
Run a NARROW, ACTIVE-LIGHT vulnerability VERIFICATION for broken access control / IDOR on the SINGLE
target below. GOAL: PROVE whether unauthorized access is possible — NEVER exfiltrate data. FIXED
checklist. HARD CONSTRAINTS: do NOT open new subtasks; do NOT crawl the whole site; ~8-12 requests total.

Steps:
1. Identify a FEW endpoints that reference a predictable resource ID (e.g. /api/user/123, ?id=NNN).
2. For a couple of them, change ONLY the ID to a neighbouring value and observe whether the ACCESS
   BEHAVIOUR changes (e.g. another record becomes reachable without authorization). GET only.
3. Report ONLY the OBSERVATION ("this endpoint appears exposed to unauthorized access") — do NOT show,
   quote, or store the actual returned data. If content is sensitive, describe the TYPE only, never values.

After these checks, IMMEDIATELY and in the SAME step write the single report AND the
${FIX_SUGGESTIONS_DELIM} section, then FINISH. Do NOT open a separate "write report" subtask.
${SAFETY_ACTIVE_LIGHT_EN}
${BUDGET_GUARD_EN}
${FIX_SUGGESTIONS_STEP_EN}

Output (Markdown table): "Endpoint | ID pattern | Observation | Severity | Recommendation". NEVER include
any real/sensitive data — only the access-control observation.

Target: ${host}
`.trim(),
  },
  {
    key: 'ssrf_verify',
    displayName: 'Zafiyet Doğrulama — SSRF',
    description:
      'Aktif-hafif: dis istek tetikleyebilecek noktalari (URL/webhook/import) tespit eder ve ' +
      'KONTROLLU zararsiz bir kanit (DNS/timing ya da kendi callback) ile SSRF varligini dogrular. ' +
      'Ic aga gercek erisim/kesif YASAK. Yetkilendirme beyani gerektirir.',
    priceMinorUnit: 449900,
    modelProvider: PROVIDER,
    maxToolCalls: 30,
    securityProfile: 'active-light',
    available: true,
    comingSoon: true,
    promptTemplate: (host) => `
Run a NARROW, ACTIVE-LIGHT SSRF VERIFICATION on the SINGLE target below. GOAL: PROVE whether the server
can be made to issue an outbound request — NEVER reach into or explore the internal network. FIXED checklist.
HARD CONSTRAINTS: do NOT open new subtasks; ~8-12 requests total.

Steps:
1. Identify a FEW inputs that may trigger a server-side fetch (url=, webhook, import-from-URL, image proxy).
2. For each, provide a CONTROLLED, HARMLESS proof target and infer SSRF from EVIDENCE only:
   - a unique DNS/HTTP callback hit you can attribute, OR a measurable timing difference. Do NOT target
     internal/cloud-metadata addresses (169.254.169.254, localhost, RFC1918) to actually reach them.
3. Report ONLY presence evidence. NEVER pivot, port-scan, or read internal responses.

After these checks, IMMEDIATELY and in the SAME step write the single report AND the
${FIX_SUGGESTIONS_DELIM} section, then FINISH. Do NOT open a separate "write report" subtask.
${SAFETY_ACTIVE_LIGHT_EN}
${BUDGET_GUARD_EN}
${FIX_SUGGESTIONS_STEP_EN}

Output (Markdown table): "Input | Evidence (DNS/timing) | Severity | Recommendation".
Target: ${host}
`.trim(),
  },
  {
    key: 'file_upload_verify',
    displayName: 'Zafiyet Doğrulama — Dosya Yükleme',
    description:
      'Aktif-hafif: dosya yukleme noktalarinda tip/boyut kontrolu var mi; ZARARSIZ, calismayan bir ' +
      'test dosyasi kabul ediliyor mu dogrular. Gercek payload/webshell YUKLEME/CALISTIRMA YASAK. ' +
      'Yetkilendirme beyani gerektirir.',
    priceMinorUnit: 449900,
    modelProvider: PROVIDER,
    maxToolCalls: 30,
    securityProfile: 'active-light',
    available: true,
    comingSoon: true,
    promptTemplate: (host) => `
Run a NARROW, ACTIVE-LIGHT FILE-UPLOAD VERIFICATION on the SINGLE target below. GOAL: check whether upload
points enforce type/size validation — NEVER upload a real payload/webshell. FIXED checklist. HARD
CONSTRAINTS: do NOT open new subtasks; ~8-12 requests total.

Steps:
1. Identify a FEW file-upload endpoints.
2. Submit a HARMLESS, NON-EXECUTABLE test file (e.g. an empty/inert file with a script-like extension but
   NO code) and observe whether it is ACCEPTED and whether validation (type/size) exists. A single POST
   upload is permitted; NEVER upload runnable code, NEVER try to execute anything.
3. Report ONLY whether validation appears missing/weak. Do NOT access or execute any uploaded file.

After these checks, IMMEDIATELY and in the SAME step write the single report AND the
${FIX_SUGGESTIONS_DELIM} section, then FINISH. Do NOT open a separate "write report" subtask.
${SAFETY_ACTIVE_LIGHT_EN}
${BUDGET_GUARD_EN}
${FIX_SUGGESTIONS_STEP_EN}

Output (Markdown table): "Endpoint | Validation observed | Accepted test file? | Severity | Recommendation".
Target: ${host}
`.trim(),
  },
  {
    key: 'business_logic_verify',
    displayName: 'Zafiyet Doğrulama — İş Mantığı',
    description:
      'Aktif-hafif: fiyat/miktar manipulasyonu, adim atlama gibi yaygin is-mantigi hatalarina ' +
      'KANIT-amacli tek-seferlik istekler. Gercek islem TAMAMLATMA/veri YAZMA YASAK. Yetkilendirme gerektirir.',
    priceMinorUnit: 599900,
    modelProvider: PROVIDER,
    maxToolCalls: 30,
    securityProfile: 'active-light',
    available: true,
    comingSoon: true,
    promptTemplate: (host) => `
Run a NARROW, ACTIVE-LIGHT BUSINESS-LOGIC VERIFICATION on the SINGLE target below. GOAL: prove whether
common logic flaws exist — NEVER complete a real transaction or write persistent data. FIXED checklist.
HARD CONSTRAINTS: do NOT open new subtasks; ~8-12 requests total.

Steps (proof-of-concept, single requests):
1. Price/quantity tampering: does the server RE-VALIDATE a manipulated price/quantity, or accept it? Observe
   the immediate response ONLY; do NOT complete checkout/payment.
2. Step-skipping: can a later step (e.g. order confirmation) be requested WITHOUT the prerequisite step?
   Observe whether it is ALLOWED — do NOT finalize the action.
3. Report ONLY the observation ("this step appears skippable / value appears trusted client-side").

After these checks, IMMEDIATELY and in the SAME step write the single report AND the
${FIX_SUGGESTIONS_DELIM} section, then FINISH. Do NOT open a separate "write report" subtask.
${SAFETY_ACTIVE_LIGHT_EN}
${BUDGET_GUARD_EN}
${FIX_SUGGESTIONS_STEP_EN}

Output (Markdown table): "Scenario | Observation | Severity | Recommendation".
Target: ${host}
`.trim(),
  },
  {
    key: 'race_massassign_verify',
    displayName: 'Zafiyet Doğrulama — Race / Mass Assignment',
    description:
      'Aktif-hafif: SINIRLI (2-3) paralel istekle race condition, ve request body’ye beklenmeyen bir ' +
      'alanin (or. isAdmin) kabul edilip edilmedigini gozlemler. Veri BOZMA/yetki YUKSELTME YASAK.',
    priceMinorUnit: 599900,
    modelProvider: PROVIDER,
    maxToolCalls: 30,
    securityProfile: 'active-light',
    available: true,
    comingSoon: true,
    promptTemplate: (host) => `
Run a NARROW, ACTIVE-LIGHT RACE-CONDITION / MASS-ASSIGNMENT VERIFICATION on the SINGLE target below. GOAL:
prove whether these flaws exist — NEVER corrupt data or actually escalate privileges. FIXED checklist. HARD
CONSTRAINTS: do NOT open new subtasks; keep it minimal.

Steps:
1. Race: pick ONE idempotent-looking action and send a SMALL number (2-3) of parallel requests; observe
   whether it is processed more than once / inconsistently. Do NOT loop or flood (that is blocked).
2. Mass assignment: on ONE request, add an unexpected field (e.g. "isAdmin": true, "role":"admin") to the
   body and observe whether it is ACCEPTED/reflected — do NOT complete a real privilege change.
3. Report ONLY the observation.

After these checks, IMMEDIATELY and in the SAME step write the single report AND the
${FIX_SUGGESTIONS_DELIM} section, then FINISH. Do NOT open a separate "write report" subtask.
${SAFETY_ACTIVE_LIGHT_EN}
${BUDGET_GUARD_EN}
${FIX_SUGGESTIONS_STEP_EN}

Output (Markdown table): "Test (race/mass-assign) | Observation | Severity | Recommendation".
Target: ${host}
`.trim(),
  },
  {
    key: 'rce_verify',
    displayName: 'Zafiyet Doğrulama — RCE / Komut Enjeksiyonu',
    description:
      'EN SIKI aktif kontrol: RCE/komut enjeksiyonunu YALNIZCA kor (zaman-tabanli sleep veya zararsiz ' +
      'canary) kanitla dogrular. Gercek komut ASLA calistirilmaz. Yetkilendirme beyani gerektirir.',
    priceMinorUnit: 699900,
    modelProvider: PROVIDER,
    maxToolCalls: 30,
    securityProfile: 'active-verify-only',
    available: true,
    comingSoon: true,
    promptTemplate: (host) => `
Run the STRICTEST, ACTIVE-VERIFY-ONLY RCE / command-injection VERIFICATION on the SINGLE target below.
GOAL: prove — by BLIND evidence ONLY — whether command execution is possible. NEVER run a real command.
FIXED checklist. HARD CONSTRAINTS: do NOT open new subtasks; ~8-12 requests total.

Steps (blind proof ONLY):
1. Identify a FEW inputs that could reach a system command.
2. For each, use ONLY a harmless BLIND probe: a time-delay payload (infer execution from response time) OR a
   unique canary string echoed back. NEVER read files, open network connections, or run any real command —
   such payloads are BLOCKED at the tool level for this package.
3. Report ONLY: "command execution appears possible (blind time/canary evidence)" with the parameter.

After these checks, IMMEDIATELY and in the SAME step write the single report AND the
${FIX_SUGGESTIONS_DELIM} section, then FINISH. Do NOT open a separate "write report" subtask.
${SAFETY_RCE_VERIFY_EN}
${BUDGET_GUARD_EN}
${FIX_SUGGESTIONS_STEP_EN}

Output (Markdown table): "Input | Blind evidence (timing/canary) | Severity | Recommendation".
Target: ${host}
`.trim(),
  },
  {
    key: 'authenticated_scan',
    displayName: 'Kimlik Doğrulamalı (Login’li) Tarama',
    description:
      'Verdiginiz bir TEST hesabinin oturumuyla aktif-hafif tarama. Kimlik bilgileri SIFRELI saklanir, ' +
      'yalniz sizin domaininize karsi kullanilir ve tarama bitince SILINIR. Yetkilendirme beyani gerektirir.',
    priceMinorUnit: 849900,
    modelProvider: PROVIDER,
    maxToolCalls: 40,
    securityProfile: 'active-light',
    available: true,
    comingSoon: true,
    promptTemplate: (host) => `
Run an ACTIVE-LIGHT AUTHENTICATED scan on the SINGLE target below using the TEST-ACCOUNT credentials that
will be provided in a separate login instruction appended below. HARD CONSTRAINTS: log in ONLY against
${host}; NEVER send the credentials anywhere else; do NOT open new subtasks; keep it focused.

Steps:
1. Log in to ${host} with the provided test credentials (form/API login).
2. With the authenticated session, perform an active-light verification of authenticated areas (broken access
   between roles, IDOR on authenticated endpoints, sensitive functions reachable). VERIFY presence ONLY.
3. NEVER change/delete account data, NEVER exfiltrate other users’ data, NEVER escalate for real.

After these checks, IMMEDIATELY and in the SAME step write the single report AND the
${FIX_SUGGESTIONS_DELIM} section, then FINISH. Do NOT open a separate "write report" subtask.
${SAFETY_ACTIVE_LIGHT_EN}
${BUDGET_GUARD_EN}
${FIX_SUGGESTIONS_STEP_EN}

Output (Markdown table): "Authenticated finding | Evidence | Severity | Recommendation".
Target: ${host}
`.trim(),
  },
  {
    key: 'autonomous_pentest',
    displayName: 'Tam Otonom, Çok Adımlı Pentest',
    description:
      'PentAGI’nin cok-adimli, hafiza tutan, zincirleme otonom moduna en yakin paket. Zincirleme kesif ' +
      'serbest AMA istismar/exfil/DoS/auth-bypass/veri-degistirme YINE YASAK (aktif-hafif sinirlar). ' +
      'Yetkilendirme beyani gerektirir.',
    priceMinorUnit: 1599900,
    modelProvider: PROVIDER,
    // Cok-adimli/zincirleme -> yuksek tavan (dar paketlerin aksine planlama serbest).
    maxToolCalls: 90,
    securityProfile: 'active-light',
    available: true,
    comingSoon: true,
    promptTemplate: (host) => `
Run an AUTONOMOUS, MULTI-STEP, chained security assessment on the SINGLE target below. Unlike the narrow
packages, you MAY plan across MULTIPLE steps, keep context/memory, and chain discovery → verification. BUT the
non-exploit safety limits STILL fully apply: NEVER extract real data, NEVER modify/delete data, NEVER bypass
auth for real, NEVER DoS. Every proof must be active-light "prove presence, don't exploit".

Approach:
1. Recon the externally reachable surface, then chain: for each promising lead, VERIFY the vulnerability with a
   harmless proof (as in the focused packages: injection/IDOR/SSRF/logic/etc.).
2. Prioritise breadth then depth; stay within budget; when about half the budget is used, START writing the report.
3. Access ONLY ${host} and its in-scope subdomains.

When done, write ONE consolidated, professional report grouped by severity AND the ${FIX_SUGGESTIONS_DELIM}
section. Never expose the internal workflow or any extracted data.
${SAFETY_ACTIVE_LIGHT_EN}
${BUDGET_GUARD_EN}
${FIX_SUGGESTIONS_STEP_EN}

Output (Markdown): an executive summary + a findings table "Finding | Type | Evidence | Severity | Recommendation".
Target: ${host}
`.trim(),
  },
];

export function getPackageDef(key: string): ScanPackageDef {
  const def = SCAN_PACKAGES.find((p) => p.key === key);
  if (!def) throw new Error(`Bilinmeyen paket: ${key}`);
  return def;
}
