/**
 * Kapsam (scope) kontrol yardimcilari — saf, test edilebilir fonksiyonlar.
 *
 * Amac: PentAGI ajaninin log/komut ciktilarindan ERISTIGI ag hedeflerini cikarip,
 * bunlarin izin verilen kapsamda (dogrulanan hostname + cozumlenen IP'ler + mesru
 * referans/altyapi allowlist'i) olup olmadigini kontrol etmek. Kapsam disi bir
 * hedef bulunursa worker flow'u durdurur (enforce) veya loglar (monitor).
 */

const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;

/** Metin icinden ag hedefi adaylari: URL host'lari + ciplak IPv4 adresleri. */
export function extractTargets(text: string | null | undefined): string[] {
  if (!text) return [];
  const found = new Set<string>();
  // URL'lerin host kismi (http/https)
  const urlRe = /\bhttps?:\/\/([^/\s"'`)\]}<>]+)/gi;
  let m: RegExpExecArray | null;
  while ((m = urlRe.exec(text)) !== null) {
    const raw = m[1].split('@').pop() ?? '';
    // Yalnizca GECERLI host karakterlerini (harf/rakam/nokta/tire) al: JSON-escaped
    // args'ta host'un hemen ardindan '\n', ',', ':port' gibi cop gelebilir; bunlari
    // host'a dahil etmek kapsam-ICI hedefi bile yanlis-pozitif isaretliyordu
    // (or. "nomorelink.com\\n\\nrequired"). Bastaki gecerli host bolumunu ayikla.
    const host = (raw.match(/^[A-Za-z0-9.-]+/)?.[0] ?? '');
    if (host) found.add(host.toLowerCase());
  }
  // Ciplak IPv4 (bir komutta hedef olarak gecen)
  const ipRe = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
  while ((m = ipRe.exec(text)) !== null) {
    found.add(m[0]);
  }
  return [...found];
}

/** Ozel/loopback/link-local adresler kapsam disi sayilmaz (sandbox altyapisi). */
export function isPrivateOrLoopback(host: string): boolean {
  if (host === 'localhost' || host === '::1' || host === '0.0.0.0') return true;
  if (!IPV4.test(host)) return false;
  const [a, b] = host.split('.').map(Number);
  if (a === 127 || a === 10 || a === 0) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 169 && b === 254) return true;
  return false;
}

export interface Scope {
  hostname: string;
  ips: string[];
  allowlist: string[];
}

/** Son iki etiket (naive registrable domain — ccTLD'lerde kaba ama guvenli tarafta). */
function lastTwoLabels(host: string): string {
  return host.split('.').slice(-2).join('.');
}

/** Bir host, izin verilen kapsamda mi? */
export function isInScope(host: string, scope: Scope): boolean {
  host = host.toLowerCase().replace(/\.$/, '');
  if (!host) return true;
  if (isPrivateOrLoopback(host)) return true;

  if (IPV4.test(host)) {
    return scope.ips.includes(host);
  }
  const target = scope.hostname.toLowerCase();
  if (host === target || host.endsWith('.' + target)) return true;
  if (lastTwoLabels(host) === lastTwoLabels(target)) return true; // ayni kayitli alan
  if (scope.allowlist.some((a) => host === a || host.endsWith('.' + a))) return true;
  return false;
}

/** Verilen metinlerden kapsam DISI hedefleri dondurur (benzersiz). */
export function findOutOfScope(texts: Array<string | null | undefined>, scope: Scope): string[] {
  const out = new Set<string>();
  for (const t of texts) {
    for (const h of extractTargets(t)) {
      if (!isInScope(h, scope)) out.add(h);
    }
  }
  return [...out];
}

/**
 * Tool-call argumanlarindan YASAK HTTP metodu (POST/PUT/DELETE/PATCH) girisimlerini
 * tespit eder. Tum paketlerimiz PASIF (yalniz GET/HEAD/OPTIONS); veri degistiren
 * metot apacik bir ihlaldir. HTTP metodu NET bir sinyal (sayfa icindeki URL gecisi
 * gibi belirsiz degil) → yanlis-pozitif riski dusuk, ENFORCE edilebilir. Sadece
 * kesin desenlere bakariz (curl -X/-d, "method":"POST", ham istek satiri); "post"
 * kelimesinin URL icinde gecmesi (or. /wp/v2/posts) tetiklemez.
 */
const FORBIDDEN_METHODS = ['POST', 'PUT', 'DELETE', 'PATCH'];

// GET-only guard'in (passive_guard.go) tool sonucundaki imzasi. Guard bir komutu
// TOOL SEVIYESINDE reddettiyse bu ibare result'ta gorunur → o deneme ZATEN
// engellendi, worker'in AYRICA flow'u durdurmasina gerek yok (ajan GET ile devam
// edip raporu tamamlayabilsin). worker strict-halt YALNIZ guard'i ATLATAN (result'ta
// bu imza OLMAYAN, ama gerceklesmis) bir POST icin devreye girer (defense-in-depth).
const GUARD_BLOCK_MARKER = /passive scan policy|blocked at tool level/i;

/**
 * Guard tarafindan ENGELLENMEMIS (yani gerceklesmis olabilecek) yasak-metot
 * girisimlerini dondurur. items: tool-call {args, result}. Bir cagrida args yasak
 * metot iceriyor VE result guard-imzasi ICERMIYOR VE result BOS DEGIL (yani calisti)
 * ise ihlal sayilir. result bos ise (henuz sonuc yok) su an atlanir (yaris onleme).
 */
// KRITIK (2026-08-03 duzeltme): YALNIZCA gercek KOMUT CALISTIRAN tool'lari (terminal)
// tara. Onceden TUM tool-call args'i taraniyordu → ajanin PLANLAMA/RAPOR tool'larinin
// (subtask_list, coder, search, code_result) args'inda gecen dogal-dil + ORNEK curl
// komutlari (guvenlik raporu HTTP metotlarindan/remediation'dan bahseder) YANLIS-POZITIF
// "yasak metot" halt'i uretiyordu (ISO/PCI scope_violation). Gercek HTTP istegi yalniz
// terminal'de (curl/wget) yapilir; Go tool-guard da orada. Bu yuzden yalniz terminal taranir.
const HTTP_EXECUTOR_TOOLS = new Set(['terminal']);

// Bir yolun/komuttaki script dosya adlarini yakalar (py/sh/pl/rb/js/bash). Referans veren
// HER terminal cagrisi sayilir (yazma + chmod + cat + calistirma + test) — sadece "yeniden
// yazma" degil (bkz detectScriptDebugLoop; nomorelink KVKK vakasinin kapatilmasi).
const SCRIPT_FILE_RE = /([\w.\/-]+\.(?:py|sh|pl|rb|js|bash))\b/gi;

/**
 * Ayni script'in varyasyonlarini ayni "temel ada" indirger: dizin + uzanti atilir,
 * sondaki debug/versiyon ekleri (_v2, _fixed, _final, _2, -new ...) kaldirilir.
 * Boylece `audit.py`, `audit_fixed.py`, `audit_v2.py` hepsi `audit` sayilir.
 */
function normalizeScriptName(p: string): string {
  const file = p.split('/').pop() ?? p;
  const noExt = file.replace(/\.(py|sh|pl|rb|js|bash)$/i, '');
  return noExt
    .replace(/([_-]?(v?\d+|fixed|final|new|updated|corrected|revised|clean|test|tmp|copy))+$/gi, '')
    .toLowerCase();
}

/**
 * SCRIPT DEBUG-LOOP tespiti: ajan ayni script'i tekrar tekrar yazip/calistirip
 * "duzeltme" dongusune girerse (canli nomorelink vakasi — string-format hatasi ~15-20
 * kez tekrarlandi, tum butce yandi, bos rapor) bunu yakalar. YALNIZ terminal
 * tool-call'lari sayilir; ayni tool-call icinde ayni dosya bir kez sayilir. Bir
 * yaz→calistir dongusu dosyayi ~2 cagrida gecirdigi icin esik (varsayilan 6) ~3
 * donguye denk gelir — normal bir "yaz+calistir+bir kez tekrar dogrula" (3) altinda kalir,
 * yanlis-pozitif riski dusuktur. Esigi asan (en yuksek) temel adi dondurur, yoksa null.
 */
export function detectScriptDebugLoop(
  items: Array<{ name?: string | null; args: string | null | undefined }>,
  threshold: number,
): { base: string; count: number } | null {
  if (!threshold || threshold <= 0) return null;
  const counts = new Map<string, number>();
  for (const it of items) {
    if (it.name != null && !HTTP_EXECUTOR_TOOLS.has(it.name)) continue; // yalniz terminal
    const t = it.args;
    if (!t) continue;
    const seen = new Set<string>(); // ayni cagride ayni dosyayi 1 kez say
    SCRIPT_FILE_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = SCRIPT_FILE_RE.exec(t))) {
      const base = normalizeScriptName(m[1]);
      if (base) seen.add(base);
    }
    for (const b of seen) counts.set(b, (counts.get(b) ?? 0) + 1);
  }
  let worst: { base: string; count: number } | null = null;
  for (const [base, count] of counts) {
    if (count >= threshold && (!worst || count > worst.count)) worst = { base, count };
  }
  return worst;
}

// Bir komuttan HEDEF URL/path'i normalize eder: scheme + query + fragment atilir,
// host kucuk harfe iner, sondaki '/' (root haric) kaldirilir. Boylece
// `https://x.com/`, `http://X.com`, `https://x.com/?a=1` hepsi `x.com` sayilir;
// `https://x.com/kvkk/` -> `x.com/kvkk`. Yalniz TEKRAR-FETCH sayimi icin kullanilir.
export function normalizeUrlPath(u: string): string {
  let s = u.trim().replace(/^https?:\/\//i, '');
  s = s.split(/[?#]/)[0]; // query/fragment at
  s = s.replace(/["'`)\]}<>]+$/, ''); // sondaki cop
  const slash = s.indexOf('/');
  let host = slash === -1 ? s : s.slice(0, slash);
  let path = slash === -1 ? '' : s.slice(slash);
  host = host.toLowerCase().replace(/:\d+$/, ''); // portu yok say
  path = path.replace(/\/+$/, ''); // sondaki slash(lar)
  return host + path;
}

// TEKRAR-FETCH tespiti: SABIT/DAR (pasif) paketlerde ajan AYNI URL/path'i (ör. anasayfa)
// tekrar tekrar cekerse (canli nomorelink vakasi — anasayfa 5 kez) yeni bilgi olmadan
// butce yanar. detectScriptDebugLoop ile AYNI kaliba gore: yalniz terminal cagrilari,
// ayni cagride ayni path bir kez sayilir, esigi (>=threshold) asan path'i dondurur.
// Bir komut icindeki TUM URL'ler cikarilir (curl/wget/openssl/heredoc referanslari dahil).
export function detectRepeatedFetch(
  items: Array<{ name?: string | null; args: string | null | undefined }>,
  threshold: number,
): { url: string; count: number } | null {
  if (!threshold || threshold <= 0) return null;
  const urlRe = /\bhttps?:\/\/[^\s'"`)\]}<>]+/gi;
  const counts = new Map<string, number>();
  for (const it of items) {
    if (it.name != null && !HTTP_EXECUTOR_TOOLS.has(it.name)) continue; // yalniz terminal
    const t = it.args;
    if (!t) continue;
    const seen = new Set<string>();
    urlRe.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = urlRe.exec(t))) {
      const key = normalizeUrlPath(m[0]);
      if (key) seen.add(key);
    }
    for (const k of seen) counts.set(k, (counts.get(k) ?? 0) + 1);
  }
  let worst: { url: string; count: number } | null = null;
  for (const [url, count] of counts) {
    if (count >= threshold && (!worst || count > worst.count)) worst = { url, count };
  }
  return worst;
}

// Profil-farkinda yasak-metot filtresi. Aktif-hafif (active-light / active-verify-only) paketlerde
// egress-proxy POST'a IZIN VERIR (ACTIVE_LIGHT_METHODS); dolayisiyla worker da POST'u "kural ihlali"
// sayip taramayi DURDURMAMALI (aksi halde XSS/enjeksiyon POST probe'u hic calisamaz). PUT/PATCH/DELETE
// (yazma/silme/degistirme) HER profilde yasak kalir. Pasif profilde POST dahil hepsi yasak (degismedi).
export function forbiddenMethodsForProfile(methods: string[], profile: string | null | undefined): string[] {
  const isActive = profile === 'active-light' || profile === 'active-verify-only';
  return isActive ? methods.filter((m) => m.toUpperCase() !== 'POST') : methods;
}

export function findForbiddenMethods(
  items: Array<{ name?: string | null; args: string | null | undefined; result?: string | null }>,
): string[] {
  const hits = new Set<string>();
  for (const it of items) {
    // Yalnizca komut-calistiran tool (terminal). name yoksa (geriye-uyum) yine bakariz.
    if (it.name != null && !HTTP_EXECUTOR_TOOLS.has(it.name)) continue;
    const t = it.args;
    if (!t) continue;
    // Guard bu denemeyi zaten engellemis → gormezden gel (ajan toparlanabilir).
    if (it.result && GUARD_BLOCK_MARKER.test(it.result)) continue;
    // result henuz yok → guard sonucu olusmamis olabilir; su tick'te halt etme.
    if (!it.result) continue;
    for (const m of FORBIDDEN_METHODS) {
      // curl -X POST | -XPOST | --request POST | --method POST
      if (new RegExp(`-X\\s*['"]?${m}\\b|--request\\s+['"]?${m}\\b|--method\\s+['"]?${m}\\b`, 'i').test(t)) hits.add(m);
      // JSON gövdesi: "method":"POST"
      if (new RegExp(`["']method["']\\s*:\\s*["']${m}["']`, 'i').test(t)) hits.add(m);
      // Ham HTTP istek satiri: POST /path HTTP/1.1
      if (new RegExp(`\\b${m}\\s+/\\S*\\s+HTTP/`, 'i').test(t)) hits.add(m);
    }
    // curl'de veri gonderen bayraklar POST'u zorlar. GUARD ile AYNI proximity deseni:
    // curl ile bayrak AYNI komut parcasinda olmali (arada |;& yok). Eskiden "curl VE
    // bayrak herhangi bir yerde" idi -> rapor script'lerindeki ORNEK komutlar (curl ...
    // ve baska satirda -F ...) yanlis-pozitif POST uretiyordu (ISO scope_violation).
    // CASE-SENSITIVE (Go passive_guard.go ile TUTARLI): /i YOK — curl bayraklari harf
    // duyarli. -d/-F = WRITE; -D (--dump-header, salt-okunur) ve -f (--fail) YANLISLIKLA
    // yakalanmasin (yanlis-pozitif: zararsiz `curl -D dosya`/`-f` bloklaniyordu).
    if (/\bcurl\b[^|;&]*?(^|\s)(-d|--data(-raw|-binary|-urlencode)?|-F|--form)(\s|=)/.test(t)) hits.add('POST');
  }
  return [...hits];
}
