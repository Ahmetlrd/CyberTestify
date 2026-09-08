/**
 * (LEAD E-POSTA KALİTESİ) Ana sayfa ücretsiz-tarama rapor adımında girilen e-postayı süzer.
 * AMAÇ: "yarak@gmail.com" gibi format-geçerli ama çöp/küfür/sahte girişleri engellemek (lead logunu
 * kirletmesin). Kullanıcıya SEBEP söylenmez (kibar "geçerli e-posta girin"); trole ipucu verilmez.
 *
 * İKİ SEVİYE:
 *  - classifyLeadEmail(): HARD BLOK — küfür / çöp kalıp / tek-kullanımlık domain / MX yok.
 *  - ROLE_LOCALPARTS: jenerik/rol mailbox (info@, admin@…) → SİLİNMEZ ama admin'de "şüpheli" işaretlenir.
 */
import { promises as dns } from 'node:dns';

// Küfür/troll — bariz, tek-anlamlı (substring güvenli).
const PROFANITY_SUBSTR = ['orospu', 'pezevenk', 'gavat', 'kahpe', 'yarrak', 'yarak', 'sikeyim', 'siktir', 'amcik', 'amcık', 'gotveren', 'götveren', 'pickurusu', 'piçkurusu', 'motherf', 'fuck', 'bitch', 'asshole', 'dickhead', 'wanker'];
// Küfür — SADECE tam token (kısa/çok-anlamlı; substring yanlış-pozitif yapar: "picture" → "pic").
const PROFANITY_TOKEN = new Set(['amk', 'aq', 'mk', 'sik', 'got', 'göt', 'pic', 'piç', 'oc', 'oç', 'yavsak', 'yavşak', 'penis', 'dick', 'cock', 'ass', 'cunt', 'shit', 'sikik']);
// Çöp / düşük-efor local-part (tam token).
const JUNK_TOKEN = new Set(['test', 'tests', 'deneme', 'asdf', 'asd', 'qwe', 'qwerty', 'aaa', 'aaaa', 'xxx', 'xxxx', 'abc', 'abcd', 'xyz', 'none', 'null', 'na', 'nan', 'sa', 'as', 'ss', 'dsa', 'zxc']);
// Tek-kullanımlık (disposable) domainler.
const DISPOSABLE = new Set(['mailinator.com', 'guerrillamail.com', '10minutemail.com', 'yopmail.com', 'temp-mail.org', 'tempmail.com', 'trashmail.com', 'getnada.com', 'sharklasers.com', 'maildrop.cc', 'dispostable.com', 'fakeinbox.com', 'throwawaymail.com', 'mailnesia.com', 'mohmal.com', 'emailondeck.com', 'moakt.com', 'tempr.email', 'discard.email', 'guerrillamail.info', 'grr.la', 'spam4.me', 'trbvm.com']);
// Jenerik/rol mailbox — düşük kaliteli lead → admin'de "şüpheli" (BLOK değil).
export const ROLE_LOCALPARTS = ['info', 'admin', 'contact', 'support', 'sales', 'hello', 'office', 'webmaster', 'postmaster', 'abuse', 'marketing', 'iletisim', 'destek', 'bilgi', 'satis', 'kariyer', 'hr', 'ik', 'muhasebe', 'finans', 'noreply', 'no-reply', 'mail'];
const ROLE_SET = new Set(ROLE_LOCALPARTS);

function parts(email: string) {
  const at = email.lastIndexOf('@');
  const local = email.slice(0, at).toLowerCase().trim();
  const domain = email.slice(at + 1).toLowerCase().trim();
  const norm = local.replace(/[.+_-]/g, '');
  const tokens = local.split(/[^a-z0-9çğıöşü]+/i).filter(Boolean);
  return { local, domain, norm, tokens };
}

/** MX var mı — FAIL-OPEN: DNS geçici hatası kullanıcıyı engellemez; yalnız alan/MX gerçekten yoksa false. */
async function domainAcceptsMail(domain: string): Promise<boolean> {
  const withA = async () => { try { const a = await dns.resolve4(domain); return !!a?.length; } catch { return false; } };
  try {
    const mx = await dns.resolveMx(domain);
    if (mx?.length) return true;
    return await withA();
  } catch (e: unknown) {
    const code = (e as { code?: string })?.code;
    if (code === 'ENOTFOUND' || code === 'NXDOMAIN') return false; // alan yok
    if (code === 'ENODATA') return await withA();                  // MX yok → A dene
    return true;                                                   // geçici DNS hatası → engelleme (fail-open)
  }
}

export async function classifyLeadEmail(email: string): Promise<{ block: boolean; reason?: string }> {
  const { domain, norm, tokens } = parts(email);
  if (!domain || !norm) return { block: true, reason: 'format' };
  if (DISPOSABLE.has(domain)) return { block: true, reason: 'disposable' };
  for (const w of PROFANITY_SUBSTR) if (norm.includes(w)) return { block: true, reason: 'profanity' };
  for (const tk of tokens) if (PROFANITY_TOKEN.has(tk)) return { block: true, reason: 'profanity' };
  if (tokens.length > 0 && tokens.every((t) => JUNK_TOKEN.has(t))) return { block: true, reason: 'junk' };
  if (/^\d+$/.test(norm)) return { block: true, reason: 'junk' };   // sadece rakam
  if (norm.length < 2) return { block: true, reason: 'junk' };
  if (/^(.)\1+$/.test(norm)) return { block: true, reason: 'junk' }; // aaaa, .....
  if (!(await domainAcceptsMail(domain))) return { block: true, reason: 'nomx' };
  return { block: false };
}

/** Rol/jenerik mailbox mı (admin'de "şüpheli" rozeti). BLOK değildir. */
export function isSuspiciousLeadEmail(email: string | null | undefined): boolean {
  if (!email) return false;
  return ROLE_SET.has(parts(email).local);
}
