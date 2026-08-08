/**
 * (basit_tarama) DETERMINISTIK "AI Çözüm Önerileri" fallback uretici — ek LLM/maliyet YOK.
 *
 * Neden: Ajan raporda ===FIX_SUGGESTIONS=== bolumunu HER ZAMAN yazmiyor (guvenilmez). O
 * zaman rapora sifreli fix blogu kaydedilmiyor -> hasFixSuggestions=false -> musteri "AI
 * Çözüm Önerileri satin al / indir" kutusunu hic goremiyor. HTTP guvenlik basliklarinin
 * duzeltmesi ZATEN deterministik/standarttir; bu yuzden eksik basliklardan somut, guvenli
 * remediation'i KODDAN uretiriz. Boylece bolum HER raporda satin alinip indirilebilir.
 *
 * NOT: baslik parse mantigi pdf.ts assessBasit ile ayni yaklasimdadir (kucuk, sabit liste;
 * bilerek bagimsiz tutuldu — test edilmis assessBasit'e dokunmamak icin). Yeni baslik
 * eklenirse iki yeri de guncelle.
 */

type HeaderKey = 'hsts' | 'csp' | 'xfo' | 'xcto' | 'referrer' | 'permissions' | 'xxss';

const HEADER_MATCH: Array<{ key: HeaderKey; re: RegExp }> = [
  { key: 'csp', re: /content-security-policy|(?<![a-z-])csp(?![a-z])/i },
  { key: 'xfo', re: /x-frame-options/i },
  { key: 'xcto', re: /x-content-type-options/i },
  { key: 'hsts', re: /strict-transport-security|(?<![a-z-])hsts(?![a-z])/i },
  { key: 'referrer', re: /referrer-policy/i },
  { key: 'permissions', re: /permissions-policy|feature-policy/i },
  { key: 'xxss', re: /x-xss-protection/i },
];

function statusFrom(chunk: string): 'present' | 'absent' | null {
  const ABSENT = /(yok|eksik|absent|missing|❌|✗|✘|bulunmuyor|bulunma|mevcut de[ğg]il|tan[ıi]ml[ıi] de[ğg]il|ayarlanmam)/i;
  const PRESENT = /(var\b|mevcut|present|✅|✓|✔|ayarlanm[ıi][şs]|tan[ıi]ml[ıi]\b|set\b)/i;
  const m = chunk.match(/durum\s*[:：]\s*([^\n|]{0,24})/i);
  const probe = m ? m[1] : chunk;
  if (ABSENT.test(probe)) return 'absent';
  if (PRESENT.test(probe)) return 'present';
  if (ABSENT.test(chunk)) return 'absent';
  if (PRESENT.test(chunk)) return 'present';
  return null;
}

/** Rapordan guvenlik basliklarinin var/yok durumunu okur (tablo satiri VEYA "N. Baslik" + "Durum:"). */
export function parseSecurityHeaders(md: string): { present: Set<HeaderKey>; absent: Set<HeaderKey> } {
  const present = new Set<HeaderKey>();
  const absent = new Set<HeaderKey>();
  const lines = md.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const lead = lines[i].replace(/^[\s|>*_#-]*(?:\d+[.)]\s*)?[\s*_]*/, '');
    const hit = HEADER_MATCH.find((h) => h.re.test(lead.slice(0, 40)));
    if (!hit || present.has(hit.key) || absent.has(hit.key)) continue;
    const window = [lines[i], lines[i + 1] ?? '', lines[i + 2] ?? ''].join('\n');
    const st = statusFrom(window);
    if (st === 'present') present.add(hit.key);
    else if (st === 'absent') absent.add(hit.key);
  }
  return { present, absent };
}

// Her baslik icin somut, GUVENLI remediation (Nginx ornekli). Istismar/exploit kodu YOK.
const REMEDIATION: Record<HeaderKey, { title: string; body: string }> = {
  csp: {
    title: 'Content-Security-Policy (CSP) ekleyin',
    body:
      'XSS ve içerik enjeksiyonuna karşı en etkili tarayıcı savunmasıdır. Sitenize uygun temel bir politikayla başlayıp zamanla sıkılaştırın:\n\n' +
      '```nginx\nadd_header Content-Security-Policy "default-src \'self\'; img-src \'self\' data:; script-src \'self\'; style-src \'self\' \'unsafe-inline\'; frame-ancestors \'self\'" always;\n```\n\n' +
      'Üçüncü taraf script kullanıyorsanız (GTM, Analytics, Pixel) ilgili alan adlarını `script-src`/`connect-src`e ekleyin.',
  },
  xfo: {
    title: 'X-Frame-Options ekleyin',
    body:
      'Sayfanızın başka bir sitenin iframe’ine gömülüp clickjacking’e maruz kalmasını engeller:\n\n' +
      '```nginx\nadd_header X-Frame-Options "SAMEORIGIN" always;\n```\n\n' +
      'Modern alternatif olarak CSP `frame-ancestors \'self\'` de aynı korumayı sağlar.',
  },
  xcto: {
    title: 'X-Content-Type-Options ekleyin',
    body:
      'Tarayıcının MIME-type sniffing yapıp içeriği yanlış yorumlamasını (ve bunun açtığı XSS riskini) engeller:\n\n' +
      '```nginx\nadd_header X-Content-Type-Options "nosniff" always;\n```',
  },
  hsts: {
    title: 'Strict-Transport-Security (HSTS) ekleyin',
    body:
      'HTTPS’i zorunlu kılar ve SSL-stripping/MITM saldırılarını zorlaştırır. (Yalnızca siteniz tamamen HTTPS ise uygulayın.)\n\n' +
      '```nginx\nadd_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;\n```',
  },
  referrer: {
    title: 'Referrer-Policy ekleyin',
    body:
      'Dış bağlantılara giden `Referer` başlığındaki bilgi sızıntısını azaltır:\n\n' +
      '```nginx\nadd_header Referrer-Policy "strict-origin-when-cross-origin" always;\n```',
  },
  permissions: {
    title: 'Permissions-Policy ekleyin',
    body:
      'Tarayıcı API’lerini (kamera, mikrofon, konum vb.) kısıtlar; üçüncü taraf iframe’lerin istenmeyen erişimini engeller:\n\n' +
      '```nginx\nadd_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;\n```',
  },
  xxss: {
    title: 'X-XSS-Protection (savunma derinliği)',
    body:
      'Eski tarayıcılar için tarihi bir başlıktır; asıl koruma CSP’dedir. İsteğe bağlı olarak ekleyebilirsiniz:\n\n' +
      '```nginx\nadd_header X-XSS-Protection "1; mode=block" always;\n```',
  },
};

// Eksik basliklarin varsayilan onceligi (rapora yazim sirasi).
const ORDER: HeaderKey[] = ['csp', 'xfo', 'xcto', 'hsts', 'referrer', 'permissions', 'xxss'];

/**
 * Rapordaki (findings) eksik guvenlik basliklarindan DETERMINISTIK "AI Çözüm Önerileri"
 * markdown'i uretir. Ajan kendi fix'ini yazmadiginda cagrilir. Her zaman DOLU string doner
 * (parse hicbir sey bulamazsa onerilen temel baslik setini yazar) — boylece bolum her zaman
 * satin alinip indirilebilir.
 */
export function buildHeaderFixSuggestions(findingsMd: string, hostname: string): string {
  const { present, absent } = parseSecurityHeaders(findingsMd);
  // Ele alinacaklar: acikca "Yok" isaretliler; hicbiri yoksa "present degil" olan onerilenler;
  // o da yoksa (parse bos) tum onerilen temel set.
  let targets = ORDER.filter((k) => absent.has(k));
  if (targets.length === 0) targets = ORDER.filter((k) => !present.has(k) && k !== 'xxss');
  if (targets.length === 0) targets = ['csp', 'xfo', 'xcto', 'referrer', 'permissions'];

  const items = targets
    .map((k, i) => `### ${i + 1}. ${REMEDIATION[k].title}\n\n${REMEDIATION[k].body}`)
    .join('\n\n');

  const combined = targets
    .filter((k) => k !== 'xxss')
    .map((k) => {
      const line: Record<HeaderKey, string> = {
        csp: 'add_header Content-Security-Policy "default-src \'self\'; frame-ancestors \'self\'" always;',
        xfo: 'add_header X-Frame-Options "SAMEORIGIN" always;',
        xcto: 'add_header X-Content-Type-Options "nosniff" always;',
        hsts: 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
        referrer: 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
        permissions: 'add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;',
        xxss: '',
      };
      return line[k];
    })
    .filter(Boolean)
    .join('\n');

  return (
    `Aşağıdaki öneriler, ${hostname} ana sayfasında tespit edilen eksik güvenlik başlıklarını gidermeye yöneliktir. ` +
    `Örnekler Nginx içindir; farklı bir sunucu/hosting kullanıyorsanız aynı başlıkları o platformun yöntemiyle ekleyin.\n\n` +
    `${items}\n\n` +
    `### Tümünü birleştiren Nginx yapılandırması\n\n` +
    `Sunucu bloğunuza (server { ... }) ekleyip \`nginx -t\` ile doğrulayın, ardından \`systemctl reload nginx\` ile yeniden yükleyin:\n\n` +
    '```nginx\n' +
    `${combined}\n` +
    '```\n\n' +
    `Değişikliklerden sonra tarayıcı geliştirici araçları (Network sekmesi) veya \`curl -I https://${hostname}\` ile başlıkların yanıta eklendiğini doğrulayın.`
  );
}
