/**
 * piiRedaction birim testleri. Calistir: npx tsx src/services/piiRedaction.test.ts
 * Her pattern icin POZITIF (gercek format) ve NEGATIF (benzer ama gecersiz) senaryo.
 */
import {
  redactAll,
  redactEmails,
  redactPhones,
  redactTcKimlik,
  redactCardNumbers,
  redactIban,
  isValidTckn,
  luhnValid,
  isValidIban,
} from './piiRedaction.js';

let pass = 0;
let fail = 0;
function check(name: string, cond: boolean) {
  if (cond) {
    pass++;
  } else {
    fail++;
    console.log('FAIL:', name);
  }
}

// --- Email ---
check('email pozitif', redactEmails('mail: ali@ornek.com.tr son').includes('[EMAIL_REDACTED]'));
check('email negatif (@ yok)', !redactEmails('kullanici adi: ali_ornek').includes('[EMAIL_REDACTED]'));

// --- TR telefon ---
check('phone 0532 formatli', redactPhones('ara: 0532 123 45 67').includes('[PHONE_REDACTED]'));
check('phone +90 formatli', redactPhones('+905321234567').includes('[PHONE_REDACTED]'));
check('phone negatif (sabit hat degil/format disi)', !redactPhones('kod 1234567').includes('[PHONE_REDACTED]'));

// --- TCKN (checksum) ---
check('tckn gecerli (10000000078)', isValidTckn('10000000078'));
check('tckn gecersiz (11111111111 checksum tutmaz)', !isValidTckn('11111111111'));
check('tckn gecersiz (0 ile baslar)', !isValidTckn('01234567890'));
check('tckn redaksiyon pozitif', redactTcKimlik('kimlik 10000000078 tamam').includes('[TCKN_REDACTED]'));
check('tckn redaksiyon negatif (gecersiz 11 hane kalir)', redactTcKimlik('sayi 11111111111').includes('11111111111'));

// --- Kredi karti (Luhn) ---
check('luhn gecerli (4111111111111111)', luhnValid('4111111111111111'));
check('luhn gecersiz (4111111111111112)', !luhnValid('4111111111111112'));
check('kart redaksiyon pozitif', redactCardNumbers('kart 4111 1111 1111 1111 son').includes('[CARD_REDACTED]'));
check('kart redaksiyon negatif (luhn tutmaz kalir)', redactCardNumbers('4111 1111 1111 1112').includes('1112'));

// --- IBAN (mod-97) ---
check('iban gecerli (TR33...)', isValidIban('TR330006100519786457841326'));
check('iban gecersiz (son hane bozuk)', !isValidIban('TR330006100519786457841327'));
check('iban redaksiyon pozitif', redactIban('hesap TR33 0006 1005 1978 6457 8413 26 son').includes('[IBAN_REDACTED]'));

// --- redactAll birlesik ---
const mixed =
  'Iletisim ali@ornek.com, tel 0532 123 45 67, TCKN 10000000078, kart 4111111111111111, IBAN TR330006100519786457841326.';
const red = redactAll(mixed);
check('redactAll: email maskeli', red.includes('[EMAIL_REDACTED]'));
check('redactAll: phone maskeli', red.includes('[PHONE_REDACTED]'));
check('redactAll: tckn maskeli', red.includes('[TCKN_REDACTED]'));
check('redactAll: kart maskeli', red.includes('[CARD_REDACTED]'));
check('redactAll: iban maskeli', red.includes('[IBAN_REDACTED]'));
check('redactAll: ham email kalmadi', !red.includes('ali@ornek.com'));
check('redactAll: ham kart kalmadi', !red.includes('4111111111111111'));

console.log(`\n${pass} PASS / ${fail} FAIL`);
if (fail > 0) process.exit(1);
