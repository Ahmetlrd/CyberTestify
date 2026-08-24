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
  const ABSENT = /(yok|eksik|absent|missing|❌|✗|✘|bulunmuyor|bulunma|mevcut de[ğg]il|tan[ıi]ml[ıi] de[ğg]il|ayarlanmam|fehlt|nicht vorhanden|nicht gesetzt)/i;
  const PRESENT = /(var\b|mevcut|present|✅|✓|✔|ayarlanm[ıi][şs]|tan[ıi]ml[ıi]\b|set\b|vorhanden|gesetzt)/i;
  const m = chunk.match(/(?:durum|status)\s*[:：]\s*([^\n|]{0,24})/i);
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

// Almanca remediation metinleri (kod ornekleri AYNI; yalniz aciklama/baslik cevrildi).
const REMEDIATION_DE: Record<HeaderKey, { title: string; body: string }> = {
  csp: {
    title: 'Content-Security-Policy (CSP) hinzufügen',
    body:
      'Die wirksamste Browser-Verteidigung gegen XSS und Content-Injection. Beginnen Sie mit einer zur Website passenden Basisrichtlinie und verschärfen Sie sie mit der Zeit:\n\n' +
      '```nginx\nadd_header Content-Security-Policy "default-src \'self\'; img-src \'self\' data:; script-src \'self\'; style-src \'self\' \'unsafe-inline\'; frame-ancestors \'self\'" always;\n```\n\n' +
      'Wenn Sie Drittanbieter-Skripte verwenden (GTM, Analytics, Pixel), fügen Sie die entsprechenden Domains zu `script-src`/`connect-src` hinzu.',
  },
  xfo: {
    title: 'X-Frame-Options hinzufügen',
    body:
      'Verhindert, dass Ihre Seite in das iframe einer fremden Website eingebettet und für Clickjacking missbraucht wird:\n\n' +
      '```nginx\nadd_header X-Frame-Options "SAMEORIGIN" always;\n```\n\n' +
      'Als moderne Alternative bietet CSP `frame-ancestors \'self\'` denselben Schutz.',
  },
  xcto: {
    title: 'X-Content-Type-Options hinzufügen',
    body:
      'Verhindert, dass der Browser per MIME-Type-Sniffing Inhalte falsch interpretiert (und das damit verbundene XSS-Risiko):\n\n' +
      '```nginx\nadd_header X-Content-Type-Options "nosniff" always;\n```',
  },
  hsts: {
    title: 'Strict-Transport-Security (HSTS) hinzufügen',
    body:
      'Erzwingt HTTPS und erschwert SSL-Stripping-/MITM-Angriffe. (Nur anwenden, wenn Ihre Website vollständig über HTTPS läuft.)\n\n' +
      '```nginx\nadd_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;\n```',
  },
  referrer: {
    title: 'Referrer-Policy hinzufügen',
    body:
      'Reduziert den Informationsabfluss über den `Referer`-Header bei externen Links:\n\n' +
      '```nginx\nadd_header Referrer-Policy "strict-origin-when-cross-origin" always;\n```',
  },
  permissions: {
    title: 'Permissions-Policy hinzufügen',
    body:
      'Schränkt Browser-APIs (Kamera, Mikrofon, Standort usw.) ein; verhindert unerwünschte Zugriffe durch Drittanbieter-iframes:\n\n' +
      '```nginx\nadd_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;\n```',
  },
  xxss: {
    title: 'X-XSS-Protection (Defense-in-Depth)',
    body:
      'Ein historischer Header für ältere Browser; der eigentliche Schutz liegt in der CSP. Kann optional ergänzt werden:\n\n' +
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
export function buildHeaderFixSuggestions(findingsMd: string, hostname: string, locale: string = 'tr'): string {
  const de = locale === 'de';
  const R = de ? REMEDIATION_DE : REMEDIATION;
  const { present, absent } = parseSecurityHeaders(findingsMd);
  // Ele alinacaklar: acikca "Yok" isaretliler; hicbiri yoksa "present degil" olan onerilenler;
  // o da yoksa (parse bos) tum onerilen temel set.
  let targets = ORDER.filter((k) => absent.has(k));
  if (targets.length === 0) targets = ORDER.filter((k) => !present.has(k) && k !== 'xxss');
  if (targets.length === 0) targets = ['csp', 'xfo', 'xcto', 'referrer', 'permissions'];

  const items = targets
    .map((k, i) => `### ${i + 1}. ${R[k].title}\n\n${R[k].body}`)
    .join('\n\n');

  // Kanonik baslik adi + degeri (tum platform ornekleri bundan uretilir — tek kaynak).
  const HV: Record<HeaderKey, { name: string; value: string }> = {
    csp: { name: 'Content-Security-Policy', value: "default-src 'self'; frame-ancestors 'self'" },
    xfo: { name: 'X-Frame-Options', value: 'SAMEORIGIN' },
    xcto: { name: 'X-Content-Type-Options', value: 'nosniff' },
    hsts: { name: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' },
    referrer: { name: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
    permissions: { name: 'Permissions-Policy', value: 'geolocation=(), microphone=(), camera=()' },
    xxss: { name: 'X-XSS-Protection', value: '1; mode=block' },
  };
  const keys = targets.filter((k) => k !== 'xxss');

  const combined = keys.map((k) => `add_header ${HV[k].name} "${HV[k].value}" always;`).join('\n');
  // Firebase Hosting (firebase.json) + Vercel (vercel.json) — JSON key/value dizisi
  const jsonHeaders = keys.map((k) => `          { "key": "${HV[k].name}", "value": "${HV[k].value}" }`).join(',\n');
  // Next.js (next.config.js) — tek tirnak
  const nextHeaders = keys.map((k) => `          { key: '${HV[k].name}', value: '${HV[k].value}' }`).join(',\n');
  // Apache (.htaccess)
  const apache = keys.map((k) => `Header always set ${HV[k].name} "${HV[k].value}"`).join('\n');
  // IIS (web.config) — ASP.NET/Windows sunucular için (imza IIS ise platform-uygun tek blok).
  const iis = keys.map((k) => `      <add name="${HV[k].name}" value="${HV[k].value}" />`).join('\n');

  return (
    (de
      ? `Die folgenden Empfehlungen dienen der Behebung der auf der Startseite von ${hostname} festgestellten fehlenden Sicherheits-Header. ` +
        `Zu jedem Header folgt zuerst eine kurze Erläuterung, dann ein Nginx-Beispiel; am Ende finden Sie fertige Blöcke für andere Plattformen (Firebase, Vercel, Next.js, Apache). Kopieren Sie den zu Ihrem Server passenden Block.\n\n`
      : `Aşağıdaki öneriler, ${hostname} ana sayfasında tespit edilen eksik güvenlik başlıklarını gidermeye yöneliktir. ` +
        `Her başlık için önce kısa açıklama, ardından Nginx örneği verilmiştir; en sonda Nginx dışı platformlar (Firebase, Vercel, Next.js, Apache) için hazır bloklar bulabilirsiniz. Kendi sunucunuza uygun olanı kopyalayın.\n\n`) +
    `${items}\n\n` +
    (de ? `### Kombinierte Konfiguration — Nginx\n\n` : `### Tümünü birleştiren yapılandırma — Nginx\n\n`) +
    (de
      ? `In Ihren Server-Block (server { ... }) einfügen, mit \`nginx -t\` prüfen und anschließend mit \`systemctl reload nginx\` neu laden:\n\n`
      : `Sunucu bloğunuza (server { ... }) ekleyip \`nginx -t\` ile doğrulayın, ardından \`systemctl reload nginx\` ile yeniden yükleyin:\n\n`) +
    '```nginx\n' + `${combined}\n` + '```\n\n' +
    (de ? `### Fertige Konfiguration für andere Plattformen\n\n` : `### Diğer platformlar için hazır yapılandırma\n\n`) +
    (de
      ? `Falls Ihr Server nicht Nginx ist, können Sie dieselben Header mit einem der folgenden fertigen Blöcke hinzufügen.\n\n`
      : `Aynı başlıkları, sunucunuz Nginx değilse aşağıdaki hazır bloklardan uygun olanıyla ekleyebilirsiniz.\n\n`) +
    `**Firebase Hosting — \`firebase.json\`:**\n\n` +
    '```json\n' +
    `{\n  "hosting": {\n    "headers": [\n      {\n        "source": "**",\n        "headers": [\n${jsonHeaders}\n        ]\n      }\n    ]\n  }\n}\n` +
    '```\n\n' +
    `**Vercel — \`vercel.json\`:**\n\n` +
    '```json\n' +
    `{\n  "headers": [\n    {\n      "source": "/(.*)",\n      "headers": [\n${jsonHeaders}\n      ]\n    }\n  ]\n}\n` +
    '```\n\n' +
    `**Next.js — \`next.config.js\`:**\n\n` +
    '```js\n' +
    `module.exports = {\n  async headers() {\n    return [\n      {\n        source: '/(.*)',\n        headers: [\n${nextHeaders}\n        ],\n      },\n    ];\n  },\n};\n` +
    '```\n\n' +
    `**Apache — \`.htaccess\` (mod_headers):**\n\n` +
    '```apache\n' + `${apache}\n` + '```\n\n' +
    `**IIS / ASP.NET — \`web.config\`:**\n\n` +
    '```xml\n' + `<configuration>\n  <system.webServer>\n    <httpProtocol>\n      <customHeaders>\n${iis}\n      </customHeaders>\n    </httpProtocol>\n  </system.webServer>\n</configuration>\n` + '```\n\n' +
    (de
      ? `Prüfen Sie nach den Änderungen mit den Browser-Entwicklertools (Tab „Network") oder mit \`curl -I https://${hostname}\`, dass die Header in der Antwort enthalten sind.`
      : `Değişikliklerden sonra tarayıcı geliştirici araçları (Network sekmesi) veya \`curl -I https://${hostname}\` ile başlıkların yanıta eklendiğini doğrulayın.`)
  );
}
