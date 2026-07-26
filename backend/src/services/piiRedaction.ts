/**
 * PII (kisisel veri) maskeleme — saf, test edilebilir modul (scope.ts gibi).
 *
 * Amac: YAPISAL kisisel veriyi (email, TR telefon, TCKN, kredi karti, IBAN)
 * maskelemek. Bizim tarafimizda (report.ts — bulgu kaniti/evidence), hassas
 * verinin sifreli DB'mizde bile HAM tutulmamasi icin kullanilir. Ayni mantik,
 * PentAGI Go tarafinda (pii_redaction.go) veri Anthropic'e gitmeden ONCE de
 * uygulanir (bkz PATCHES.md).
 *
 * SINIR (kalinti risk): regex/checksum tabanlidir. Yapisal PII'yi yakalar;
 * serbest metindeki ISIM, ADRES gibi verileri YAKALAMAZ (NER kapsam disi).
 */

const RE_EMAIL = /[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,24}/gi;
const RE_PHONE_TR = /(?:\+?90[ \-]?|0)5\d{2}[ \-]?\d{3}[ \-]?\d{2}[ \-]?\d{2}/g;
const RE_ELEVEN = /\b\d{11}\b/g;
const RE_CARD = /\b\d(?:[ \-]?\d){12,18}\b/g;
const RE_IBAN_TR = /\bTR\d{2}(?: ?\d){22}\b/gi;

export function redactEmails(text: string): string {
  return text.replace(RE_EMAIL, '[EMAIL_REDACTED]');
}

export function redactPhones(text: string): string {
  return text.replace(RE_PHONE_TR, '[PHONE_REDACTED]');
}

export function redactTcKimlik(text: string): string {
  return text.replace(RE_ELEVEN, (m) => (isValidTckn(m) ? '[TCKN_REDACTED]' : m));
}

export function redactCardNumbers(text: string): string {
  return text.replace(RE_CARD, (m) => {
    const d = m.replace(/\D/g, '');
    return d.length >= 13 && d.length <= 19 && luhnValid(d) ? '[CARD_REDACTED]' : m;
  });
}

export function redactIban(text: string): string {
  return text.replace(RE_IBAN_TR, (m) => (isValidIban(m) ? '[IBAN_REDACTED]' : m));
}

/** Hepsini uygular. Sira: email → IBAN → kart → TCKN → telefon. */
export function redactAll(text: string): string {
  if (!text) return text;
  let s = redactEmails(text);
  s = redactIban(s);
  s = redactCardNumbers(s);
  s = redactTcKimlik(s);
  s = redactPhones(s);
  return s;
}

// --- Dogrulayicilar (false-positive azaltma) ------------------------------

export function isValidTckn(s: string): boolean {
  if (s.length !== 11 || s[0] === '0') return false;
  const d = [...s].map((c) => c.charCodeAt(0) - 48);
  if (d.some((n) => n < 0 || n > 9)) return false;
  const odd = d[0] + d[2] + d[4] + d[6] + d[8];
  const even = d[1] + d[3] + d[5] + d[7];
  const digit10 = (((odd * 7 - even) % 10) + 10) % 10;
  if (digit10 !== d[9]) return false;
  const total = d.slice(0, 10).reduce((a, b) => a + b, 0);
  return total % 10 === d[10];
}

export function luhnValid(s: string): boolean {
  let sum = 0;
  let alt = false;
  for (let i = s.length - 1; i >= 0; i--) {
    let n = s.charCodeAt(i) - 48;
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return s.length > 0 && sum % 10 === 0;
}

export function isValidIban(raw: string): boolean {
  const s = raw.toUpperCase().replace(/ /g, '');
  if (s.length < 15 || s.length > 34) return false;
  const rearranged = s.slice(4) + s.slice(0, 4);
  let digits = '';
  for (const ch of rearranged) {
    if (ch >= '0' && ch <= '9') digits += ch;
    else if (ch >= 'A' && ch <= 'Z') digits += (ch.charCodeAt(0) - 55).toString();
    else return false;
  }
  let rem = 0;
  for (const c of digits) rem = (rem * 10 + (c.charCodeAt(0) - 48)) % 97;
  return rem === 1;
}
