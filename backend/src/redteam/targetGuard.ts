/**
 * (OTONOM AI RED TEAM — 3b-ii HEDEF GUARD) Hedefi çöz + PINLE + her çözülen IP'yi yasak-aralık
 * kontrolünden geçir. Amaç: bir domain'in private/CyberTestify/metadata IP'ye çözülerek guard'ı
 * atlatmasını VE DNS-rebinding'i (guard-anında yetkili, saldırı-anında private) engellemek.
 *
 * KULLANIM: koşudan ÖNCE resolveAndPin(target) çağrılır; dönen pinnedIps SABİTLENİR. Egress
 * allow-target + PentAGI saldırısı YALNIZ pinlenen IP'lere yapılır — domain BİR DAHA çözülmez.
 *
 * Saf + enjekte edilebilir (resolver mock ile unit-test). LLM/DO/ağ yok (nodeResolver hariç).
 */
import net from 'node:net';
import dns from 'node:dns';

// Bilinen CyberTestify IP'leri (genişletilebilir). Prod public + eklenecekler.
export const CYBERTESTIFY_IPS = new Set<string>(['164.92.223.208']);
// PentAGI kontrol-düzlemi / droplet'in kendi IP'leri (env ile eklenebilir; VPC zaten 10/8 kapsanır).
const EXTRA_FORBIDDEN_IPS = new Set<string>(
  (process.env.REDTEAM_FORBIDDEN_IPS ?? '').split(',').map((s) => s.trim()).filter(Boolean),
);

function parseIpv4(s: string): number[] | null {
  const m = s.trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const b = m.slice(1, 5).map(Number);
  return b.every((n) => n >= 0 && n <= 255) ? b : null;
}

/** IPv6 → 16 bayt (:: genişletme + gömülü IPv4 desteği). Geçersizse null. */
function ipv6ToBytes(input: string): number[] | null {
  let ip = input.trim().toLowerCase().split('%')[0]; // zone-id at
  // gömülü IPv4 (::ffff:1.2.3.4 / ::1.2.3.4) → son iki gruba çevir
  const lastColon = ip.lastIndexOf(':');
  const tail = ip.slice(lastColon + 1);
  if (tail.includes('.')) {
    const v4 = parseIpv4(tail);
    if (!v4) return null;
    const g1 = ((v4[0] << 8) | v4[1]).toString(16);
    const g2 = ((v4[2] << 8) | v4[3]).toString(16);
    ip = ip.slice(0, lastColon + 1) + g1 + ':' + g2;
  }
  const dbl = ip.split('::');
  if (dbl.length > 2) return null;
  const head = dbl[0] ? dbl[0].split(':') : [];
  const tailG = dbl.length === 2 ? (dbl[1] ? dbl[1].split(':') : []) : [];
  let groups: string[];
  if (dbl.length === 2) {
    const missing = 8 - head.length - tailG.length;
    if (missing < 0) return null;
    groups = [...head, ...Array(missing).fill('0'), ...tailG];
  } else {
    groups = head;
  }
  if (groups.length !== 8) return null;
  const bytes: number[] = [];
  for (const g of groups) {
    if (g === '') return null;
    const n = parseInt(g, 16);
    if (Number.isNaN(n) || n < 0 || n > 0xffff || !/^[0-9a-f]{1,4}$/.test(g)) return null;
    bytes.push((n >> 8) & 0xff, n & 0xff);
  }
  return bytes;
}

function forbiddenIpv4(b: number[], ip: string): string | null {
  if (CYBERTESTIFY_IPS.has(ip)) return 'CyberTestify prod IP';
  if (EXTRA_FORBIDDEN_IPS.has(ip)) return 'yasaklı IP (kontrol-düzlemi)';
  if (b[0] === 10) return 'RFC1918 10.0.0.0/8 (özel/CyberTestify VPC)';
  if (b[0] === 172 && b[1] >= 16 && b[1] <= 31) return 'RFC1918 172.16.0.0/12 (özel)';
  if (b[0] === 192 && b[1] === 168) return 'RFC1918 192.168.0.0/16 (özel)';
  if (b[0] === 127) return 'loopback 127.0.0.0/8';
  if (b[0] === 169 && b[1] === 254) return 'link-local/metadata 169.254.0.0/16';
  if (b[0] === 100 && b[1] >= 64 && b[1] <= 127) return 'CGNAT 100.64.0.0/10';
  if (b[0] === 0) return 'unspecified 0.0.0.0/8';
  if (b[0] >= 224) return 'multicast/reserved (>=224.0.0.0)';
  return null;
}

function forbiddenIpv6(b: number[]): string | null {
  const allZero = b.every((x) => x === 0);
  if (allZero) return 'unspecified ::';
  if (b.slice(0, 15).every((x) => x === 0) && b[15] === 1) return 'loopback ::1';
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0x80) return 'link-local fe80::/10';
  if ((b[0] & 0xfe) === 0xfc) return 'unique-local fc00::/7 (metadata fd00:ec2::254 dahil)';
  if (b[0] === 0xff) return 'multicast ff00::/8';
  return null;
}

/** Tek bir IP yasak mı? { forbidden, reason }. IPv4-mapped IPv6 gömülü IPv4'e indirgenir. */
export function checkIp(ip: string): { forbidden: boolean; reason?: string } {
  const fam = net.isIP(ip);
  if (fam === 4) {
    const b = parseIpv4(ip);
    if (!b) return { forbidden: true, reason: 'geçersiz IPv4' };
    const r = forbiddenIpv4(b, ip);
    return r ? { forbidden: true, reason: r } : { forbidden: false };
  }
  if (fam === 6) {
    const b = ipv6ToBytes(ip);
    if (!b) return { forbidden: true, reason: 'geçersiz IPv6' };
    // IPv4-mapped ::ffff:a.b.c.d → gömülü IPv4'ü kontrol et
    if (b.slice(0, 10).every((x) => x === 0) && b[10] === 0xff && b[11] === 0xff) {
      const v4 = `${b[12]}.${b[13]}.${b[14]}.${b[15]}`;
      const r = forbiddenIpv4([b[12], b[13], b[14], b[15]], v4);
      return r ? { forbidden: true, reason: `IPv4-mapped ${v4}: ${r}` } : { forbidden: false };
    }
    const r = forbiddenIpv6(b);
    return r ? { forbidden: true, reason: r } : { forbidden: false };
  }
  return { forbidden: true, reason: 'geçersiz IP' };
}

export type Resolver = {
  resolve4: (host: string) => Promise<string[]>;
  resolve6: (host: string) => Promise<string[]>;
};
/** Gerçek DNS çözücü (canlı koşuda). Unit-test'te mock verilir. */
export const nodeResolver: Resolver = {
  resolve4: (h) => dns.promises.resolve4(h),
  resolve6: (h) => dns.promises.resolve6(h),
};

export type PinResult =
  | { ok: true; pinnedIps: string[]; family: { v4: string[]; v6: string[] } }
  | { ok: false; reason: string };

/**
 * Hedefi (domain ya da IP) çöz + PINLE. TÜM A + AAAA kayıtları çözülür; HERHANGİ biri yasaksa
 * TÜM hedef reddedilir (çok-IP kuralı). Dönen pinnedIps sabittir — çağıran bunları kullanır,
 * domaini bir daha ÇÖZMEZ (rebinding engeli).
 */
export async function resolveAndPin(target: string, resolver: Resolver = nodeResolver): Promise<PinResult> {
  const host = target.trim().replace(/^https?:\/\//i, '').split('/')[0].split(':')[0];
  if (!host) return { ok: false, reason: 'boş hedef' };

  // Hedef zaten IP ise: doğrudan kontrol et (çözme yok).
  const litFam = net.isIP(host);
  if (litFam) {
    const c = checkIp(host);
    if (c.forbidden) return { ok: false, reason: `hedef IP yasak (${host}): ${c.reason}` };
    return { ok: true, pinnedIps: [host], family: { v4: litFam === 4 ? [host] : [], v6: litFam === 6 ? [host] : [] } };
  }

  // Domain: TÜM A + AAAA çöz (biri boş olabilir; ikisi de boşsa çözülemedi).
  const [v4, v6] = await Promise.all([
    resolver.resolve4(host).catch(() => [] as string[]),
    resolver.resolve6(host).catch(() => [] as string[]),
  ]);
  const all = [...v4, ...v6];
  if (all.length === 0) return { ok: false, reason: `hedef çözülemedi (A/AAAA yok): ${host}` };

  for (const ip of all) {
    const c = checkIp(ip);
    if (c.forbidden) {
      // Çok-IP: HERHANGİ biri yasaksa TÜM hedefi reddet.
      return { ok: false, reason: `hedef ${host} yasak IP'ye çözülüyor (${ip}): ${c.reason}` };
    }
  }
  return { ok: true, pinnedIps: all, family: { v4, v6 } };
}
