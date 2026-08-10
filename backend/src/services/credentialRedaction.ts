/**
 * (Tam Kapsamlı Pentest — FAZ A) KİMLİK BİLGİSİ REDAKSİYONU — log/metin sızıntı koruması.
 *
 * PII redaksiyonu (piiRedaction.ts) YAPISAL veriyi (email/telefon/TCKN/kart/IBAN) desenle maskeler.
 * Kimlik bilgisi (test hesabı kullanıcı adı/şifresi) ise DEĞER-tabanlıdır: rastgele bir string,
 * desenle yakalanamaz. Bu modül, BİLİNEN kimlik bilgisi değerlerini bir metinden maskeler — herhangi
 * bir log/aktivite/hata mesajı yazılmadan ÖNCE uygulanmalıdır.
 *
 * NOT (mimari): FAZ A'da ajana kimlik bilgisi GÖNDERİLMEZ (login otomasyonu FAZ B). Bu katman,
 * FAZ B'de login devreye girdiğinde (veya herhangi bir yerde yanlışlıkla) kimlik bilgisinin log'a
 * sızmasını önleyen REGRESYON KORUMASIDIR (bkz credentialRedaction.test.ts).
 */

const MIN_SECRET_LEN = 3; // çok kısa değerleri maskeleme (yanlış-pozitif/aşırı-redaksiyon riski)
const TOKEN = '[CREDENTIAL_REDACTED]';

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Bir gizli değerin aranacak biçimleri: ham hâli + JSON.stringify edilmiş gövdesi (dış tırnaklar
// hariç) — böylece `password="s3\"cret"` gibi kaçışlı gömülü formlar da yakalanır.
function needlesFor(secrets: Array<string | undefined | null>): string[] {
  const set = new Set<string>();
  for (const s of secrets) {
    const v = (s ?? '').trim();
    if (v.length < MIN_SECRET_LEN) continue;
    set.add(v);
    const j = JSON.stringify(v);
    set.add(j.slice(1, -1)); // dış tırnakları at, kaçışlı gövdeyi ekle
  }
  // Uzun değerleri önce maskele (kısa bir parça uzun bir değerin içindeyken bozulma olmasın).
  return [...set].filter(Boolean).sort((a, b) => b.length - a.length);
}

/** Metindeki bilinen kimlik bilgisi değerlerini [CREDENTIAL_REDACTED] ile değiştirir. */
export function redactSecrets(text: string, secrets: Array<string | undefined | null>): string {
  if (!text) return text;
  let out = text;
  for (const n of needlesFor(secrets)) {
    out = out.replace(new RegExp(escapeRegExp(n), 'g'), TOKEN);
  }
  return out;
}

/** Metin, verilen gizli değerlerden birini AÇIKTA içeriyor mu? (test/guard için) */
export function containsSecret(text: string, secrets: Array<string | undefined | null>): boolean {
  if (!text) return false;
  for (const n of needlesFor(secrets)) {
    if (text.includes(n)) return true;
  }
  return false;
}

/**
 * REGRESYON GUARD'ı: metin bir kimlik bilgisi değerini açıkta içeriyorsa THROW eder. Log yazımından
 * önce çağrılabilir (defense) ve testlerde "sızıntı olursa test kırılsın" kontratını sağlar.
 */
export function assertNoCredentialLeak(text: string, secrets: Array<string | undefined | null>): void {
  if (containsSecret(text, secrets)) {
    throw new Error('CREDENTIAL LEAK: kimlik bilgisi değeri log/metin içinde açıkta bulundu (redaksiyon atlandı).');
  }
}
