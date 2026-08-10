/**
 * credentialRedaction birim testleri. Çalıştır: npx tsx src/services/credentialRedaction.test.ts
 *
 * KONTRAT (kullanıcı isteği): "prompt/log'a kimlik bilgisi yazılırsa test kırılsın" — regresyon
 * koruması. assertNoCredentialLeak, ham (maskelenmemiş) metinde THROW eder; redakte metinde etmez.
 */
import { redactSecrets, containsSecret, assertNoCredentialLeak } from './credentialRedaction.js';

let pass = 0;
let fail = 0;
function check(name: string, cond: boolean) {
  if (cond) pass++;
  else { fail++; console.log('FAIL:', name); }
}
function throws(fn: () => void): boolean {
  try { fn(); return false; } catch { return true; }
}

const USER = 'pentest_tester_01';
const PASS = 'S3cr3t!Passw0rd#42';

// 1) Temel maskeleme
const line1 = `LOGIN INSTRUCTION username=${USER} password=${PASS}`;
const red1 = redactSecrets(line1, [USER, PASS]);
check('kullanıcı adı maskelendi', !red1.includes(USER));
check('şifre maskelendi', !red1.includes(PASS));
check('token yerleştirildi', red1.includes('[CREDENTIAL_REDACTED]'));

// 2) JSON.stringify edilmiş (kaçışlı) gömülü form da yakalanır
const jsonLine = `creds=${JSON.stringify({ username: USER, password: PASS })}`;
const redJson = redactSecrets(jsonLine, [USER, PASS]);
check('JSON gövdesinde şifre maskelendi', !redJson.includes(PASS));
check('JSON gövdesinde kullanıcı maskelendi', !redJson.includes(USER));

// 3) Kaçış gerektiren özel karakterli şifre
const weird = 'a.b*c(d)e|f$g';
check('regex-özel karakterli şifre maskelendi', !redactSecrets(`x=${weird}`, [weird]).includes(weird));

// 4) containsSecret doğru sinyal verir
check('containsSecret: ham metinde sızıntı = true', containsSecret(line1, [USER, PASS]) === true);
check('containsSecret: redakte metinde sızıntı = false', containsSecret(red1, [USER, PASS]) === false);

// 5) REGRESYON GUARD'ı — sızıntı varsa THROW, redakte metinde THROW YOK
check('assertNoCredentialLeak: HAM metinde THROW eder (sızıntı yakalanır)', throws(() => assertNoCredentialLeak(line1, [USER, PASS])));
check('assertNoCredentialLeak: REDAKTE metinde THROW ETMEZ', !throws(() => assertNoCredentialLeak(red1, [USER, PASS])));

// 6) Aşırı-redaksiyon/gürültü önleme: çok kısa/boş değerler yok sayılır (crash yok)
check('kısa değer (<3) maskelenmez', redactSecrets('the a x', ['a', '']) === 'the a x');
check('boş metin güvenli', redactSecrets('', [USER]) === '');

console.log(`\n${pass} PASS / ${fail} FAIL`);
if (fail > 0) process.exit(1);
