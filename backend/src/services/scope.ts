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
    let host = m[1].split('@').pop() ?? '';
    host = host.replace(/:\d+$/, ''); // port ayikla
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
