import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import { prisma } from '../db.js';
import { config } from '../config.js';

/**
 * Domain sahiplik dogrulama servisi.
 *
 * Neden onemli: musteri "bu benim sitem" diyor ama bunu dogrulamadan
 * PentAGI'ye saldirtirsak, baskasinin sitesine izinsiz saldirtabiliriz.
 * Bu, hem hukuki risk (yetkisiz erisim) hem de itibar riski.
 *
 * Yontem: DNS TXT kaydi. Musteri zaten domain'i deploy ettiyse DNS panelinde
 * islem yapabiliyordur — bu segment icin makul bir varsayim.
 */

// ======================================================================================
// SADECE TEST/QA — resmi, herkese açık, KASITLI olarak zafiyetli bırakılmış pratik hedefler.
// Bu domainler (ve YALNIZ bunlar) için domain-sahiplik DNS-TXT doğrulaması ATLANIR; diğer
// TÜM kurallar (consent checkbox'ları, circuit breaker, "asla tamamlama" guard'ları) AYNEN
// uygulanır. Kolayca genişletilebilir/kaldırılabilir sabit liste — başka domain için ÇALIŞMAZ.
// Hepsi güvenlik testi PRATİĞİ için resmî olarak var olan sitelerdir (OWASP/Acunetix/PortSwigger/IBM).
// ======================================================================================
const KNOWN_PUBLIC_TEST_TARGETS = new Set<string>([
  'demo.owasp-juice.shop',   // OWASP Juice Shop resmi demo
  'juice-shop.herokuapp.com', // OWASP Juice Shop (Heroku)
  'testphp.vulnweb.com',      // Acunetix test sitesi (PHP)
  'testasp.vulnweb.com',      // Acunetix test sitesi (ASP)
  'testaspnet.vulnweb.com',   // Acunetix test sitesi (ASP.NET)
  'rest.vulnweb.com',         // Acunetix test sitesi (REST)
  'demo.testfire.net',        // IBM AltoroMutual demo
  'ginandjuice.shop',         // PortSwigger resmi demo
  'google-gruyere.appspot.com', // Google Gruyere — resmî web güvenliği codelab (kasıtlı zafiyetli)
  'test.cybertestify.com',    // KENDİ barındırdığımız OWASP Juice Shop (iç test/QA hedefi) — bkz Caddyfile
]);

/**
 * Kullanıcı alan adını serbest biçimde girebilir: "https://www.ornek.com/path?x=1", "ORNEK.COM/",
 * "ornek.com:443" vb. Hepsini ÇIPLAK host'a indir: şema, kullanıcı-bilgisi, port, path/query/fragment
 * ve baştaki "www." atılır; küçük harfe çevrilir; sondaki nokta silinir. Doğrulama (HOSTNAME_RE) ve
 * whitelist eşleşmesi HEP bu normalize edilmiş değer üzerinden yapılır ki "https://"/"www." yüzünden
 * "Ekle ve doğrula" reddedilmesin ve yanlış DNS-TXT adı istenmesin.
 */
const TR_ASCII: Record<string, string> = {
  'ç': 'c', 'Ç': 'c', 'ğ': 'g', 'Ğ': 'g', 'ı': 'i', 'İ': 'i',
  'ö': 'o', 'Ö': 'o', 'ş': 's', 'Ş': 's', 'ü': 'u', 'Ü': 'u',
};
/**
 * (Türkçe alan adı düzeltmesi) Kullanıcılar marka/isim alan adını Türkçe harf ya da BÜYÜK harfle
 * yazabilir (ör. "İpekbilgisayar", "meşe"); OYSA bu alan adları neredeyse her zaman ASCII kayıtlıdır
 * (ipekbilgisayar.com, mese.com). Türkçe'ye ÖZGÜ harfleri ASCII karşılığına katlarız (İ/ı→i, ş→s, ç→c,
 * ğ→g, ö→o, ü→u). DİKKAT: bu bir TAHMİN — çok nadir de olsa gerçek bir IDN (ör. güneş.com.tr = xn--...)
 * yerine ASCII'ye katlanabilir; TR pazarında ASCII baskın olduğu için bilinçli tercih. Türkçe-DIŞI
 * karakterler (Çince/Arapça/…) DOKUNULMAZ → sonraki punycode adımı onları IDN olarak korur.
 * toLowerCase()'ten ÖNCE çağrılmalı: JS'te 'İ'.toLowerCase() birleşik-noktalı bozuk çıktı verir.
 */
export function foldTurkishDomainChars(h: string): string {
  return h.replace(/[çÇğĞıİöÖşŞüÜ]/g, (c) => TR_ASCII[c] ?? c);
}

export function normalizeHostname(input: string): string {
  let h = foldTurkishDomainChars((input ?? '').trim()).toLowerCase();
  h = h.replace(/^[a-z][a-z0-9+.-]*:\/\//, ''); // şema (http:// https:// vs.)
  h = h.replace(/^[^/@]*@/, '');                // user:pass@ (varsa)
  h = h.replace(/[/?#].*$/, '');                // path / query / fragment
  h = h.replace(/:\d+$/, '');                   // :port
  h = h.replace(/^www\./, '');                  // baştaki www.
  h = h.replace(/\.+$/, '');                    // sondaki nokta(lar) (FQDN)
  // (IDN) Türkçe/uluslararası karakterli alan adlarını (ör. şirket.com.tr, öztürk.com) punycode'a çevir
  // → HOSTNAME_RE yalnız ASCII kabul ettiği için aksi halde "geçerli değil" diye reddediliyordu. Ücretsiz
  // taramanın new URL() ile zaten yaptığı şeyin AYNISI; ASCII girdiler AYNEN kalır (davranış değişmez).
  if (/[^\x00-\x7f]/.test(h)) {
    try { h = new URL('http://' + h).hostname; } catch { /* çevrilemezse olduğu gibi bırak → regex reddeder */ }
  }
  return h;
}

export function isKnownPublicTestTarget(hostname: string): boolean {
  return KNOWN_PUBLIC_TEST_TARGETS.has(normalizeHostname(hostname));
}

export function generateVerificationToken(): string {
  const random = crypto.randomBytes(16).toString('hex');
  return `${config.dnsVerificationPrefix}=${random}`;
}

export async function createDomainVerification(customerId: string, hostname: string) {
  const normalizedHost = normalizeHostname(hostname);

  // (FIX) Alan adı ZATEN VAR ve doğrulaması GEÇERLİ ise DOKUNMA — olduğu gibi döndür. Aksi halde
  // (eski davranış) upsert'ün update dalı token'ı yeniler + verifiedAt/status'u sıfırlardı; yani
  // onaylı bir alan adını "yeniden ekle" demek DOĞRULAMAYI SİLİP tekrar DNS doğrulamaya zorluyordu.
  // Not: normalizeHostname şemayı (http/https) ve www.'yi soyar -> http:// ve https:// AYNI kayda iner.
  const existing = await prisma.domain.findUnique({
    where: { customerId_hostname: { customerId, hostname: normalizedHost } },
  });
  if (existing && isVerificationStillValid(existing)) return existing;

  const token = generateVerificationToken();
  return prisma.domain.upsert({
    where: { customerId_hostname: { customerId, hostname: normalizedHost } },
    update: { verificationToken: token, status: 'pending', lastCheckedAt: null, verifiedAt: null },
    create: {
      customerId,
      hostname: normalizedHost,
      verificationToken: token,
      verificationMethod: 'dns_txt',
      status: 'pending',
    },
  });
}

export async function checkDomainVerification(domainId: string): Promise<boolean> {
  const domain = await prisma.domain.findUniqueOrThrow({ where: { id: domainId } });

  let verified = false;
  if (isKnownPublicTestTarget(domain.hostname)) {
    // TEST/QA whitelist: DNS-TXT sahiplik dogrulamasi ATLANIR (bkz KNOWN_PUBLIC_TEST_TARGETS).
    // IP cozumlemesi (scope kilidi icin) yine de asagida yapilir.
    verified = true;
  } else {
    try {
      // _pentest-verify.<domain> TXT kaydinda beklenen degeri ariyoruz.
      const records = await dns.resolveTxt(`_pentest-verify.${domain.hostname}`);
      const flat = records.map((r) => r.join(''));
      verified = flat.includes(domain.verificationToken);
    } catch {
      verified = false;
    }
  }

  // Dogrulaninca hedefin IP'lerini cozumleyip sakla — kapsam (scope) kontrolu
  // bu IP listesine dayaniyor (izin disi IP'ye erisimi worker tespit ediyor).
  let resolvedIps: string | undefined;
  if (verified) {
    try {
      const [v4, v6] = await Promise.all([
        dns.resolve4(domain.hostname).catch(() => [] as string[]),
        dns.resolve6(domain.hostname).catch(() => [] as string[]),
      ]);
      const ips = [...v4, ...v6];
      if (ips.length) resolvedIps = ips.join(',');
    } catch {
      resolvedIps = undefined;
    }
  }

  await prisma.domain.update({
    where: { id: domainId },
    data: {
      status: verified ? 'verified' : 'failed',
      verifiedAt: verified ? new Date() : null,
      lastCheckedAt: new Date(),
      ...(resolvedIps !== undefined ? { resolvedIps } : {}),
    },
  });

  return verified;
}

/**
 * Bir siparis olusturulmadan hemen once tekrar dogrulanmis mi diye kontrol.
 * Dogrulama X gunde bir sure asimina ugrasin diye (domain el degistirebilir).
 */
const VERIFICATION_TTL_DAYS = 30;

export function isVerificationStillValid(domain: { status: string; verifiedAt: Date | null; hostname?: string }): boolean {
  // TEST/QA whitelist: bilinen resmî pratik hedeflerinde sahiplik doğrulaması aranmaz.
  if (domain.hostname && isKnownPublicTestTarget(domain.hostname)) return true;
  if (domain.status !== 'verified' || !domain.verifiedAt) return false;
  const ageMs = Date.now() - domain.verifiedAt.getTime();
  return ageMs < VERIFICATION_TTL_DAYS * 24 * 60 * 60 * 1000;
}
