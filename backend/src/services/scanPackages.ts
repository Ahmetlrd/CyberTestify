/**
 * "Buton" paketleri kataloğu. Kullaniciya SERBEST prompt alani gosterilmiyor —
 * bu hem maliyet ongorulebilirligi hem de prompt injection / kapsam disi hedefe
 * yonlendirme riskini kapatiyor.
 *
 * TAMAMI PASIF (non-intrusive) ve DUSUK RISKLIDIR. Her paket, ortak SAFETY
 * kisitini tasir: yalnizca dogrulanan hostname, DoS/exploit/kapsam-disi YASAK.
 *
 * modelProvider = PentAGI'de tanimli provider profil ADI (model adi degil).
 * Bizim instance'ta profil adi: "nomorelink-test" (en ucuz Anthropic modeline
 * ayarli).
 */

export interface ScanPackageDef {
  key:
    | 'basit_tarama'
    | 'ssl_tls'
    | 'header_leak'
    | 'dns_email'
    | 'cms_cve'
    | 'pci_hazirlik'
    | 'kvkk_hazirlik'
    | 'iso27001_hazirlik';
  displayName: string;
  description: string;
  priceMinorUnit: number; // kurus
  modelProvider: string; // PentAGI'de tanimli provider profil adi
  maxToolCalls: number; // flow bazinda yumusak tavan (worker.ts uygular)
  // true ise: ham ag/port (IP+port) katmani icerir → Host header'a saygi duymaz,
  // paylasimli hosting'te komsu siteleri etkileyebilir. Bu paketler yalnizca
  // hostingType='dedicated' hedeflerde acilir (bkz orders.ts). Su anki tum
  // paketler HTTP/uygulama katmanidir (Host'a bagli) → false.
  networkLayer?: boolean;
  promptTemplate: (targetHostname: string) => string;
}

// PentAGI Providers ekranindaki profil adiyla BIREBIR eslesmeli (createFlow'a
// aynen gider; eslesmezse tarama "provider bulunamadi" ile patlar). Prod'da
// profil adi 'cybertestify-anthropic'. Isim degisirse PENTAGI_PROVIDER env'i
// ile kod degistirmeden gecersin.
const PROVIDER = process.env.PENTAGI_PROVIDER ?? 'cybertestify-anthropic';

// Her pakette AYNEN tasinan hukuki/teknik guvenlik kisiti.
const SAFETY = `
KESINLIKLE YASAK: her turlu istismar/exploitation, enjeksiyon (SQLi/XSS/SSRF vb.)
payload'lari, kimlik dogrulama denemesi, brute-force, dizin/dosya ZORLAMA,
veri degistiren/yazan istekler (POST/PUT/DELETE), yuk/stres/DoS ve kapsam disi
(belirtilen host disindaki) HERHANGI bir hedefe erisim. Paylasimli hosting
ihtimaline karsi IP/port degil, HOSTNAME/uygulama katmaninda kal. Suphedeysen o
adimi ATLA.`.trim();

export const SCAN_PACKAGES: ScanPackageDef[] = [
  {
    key: 'basit_tarama',
    displayName: 'Basit Tarama',
    description:
      'Hizli, pasif on-kontrol: ana sayfanin guvenlik basliklari, TLS gecerliligi ve ' +
      'sunucu banner ozeti. Birkac dakikada biten en ucuz giris paketi.',
    priceMinorUnit: 49900, // 499,00 TRY
    modelProvider: PROVIDER,
    // 12 cok dusuktu: PentAGI overhead'i (docker secimi, terminal init, ekran
    // goruntusu, sayfa cekme) tavani ajan BULGULARINI YAZMADAN tuketiyordu → her
    // rapor "incomplete" + bos cikiyordu. Pasif kontrol + ozet icin 25 yeterli.
    maxToolCalls: 25,
    promptTemplate: (host) => `
Bu bir HIZLI, PASIF ve KISA on-kontroldur — derin tarama DEGIL. Yalnizca
asagidaki TEK hedefin ANA SAYFASINA normal bir GET istegi atip su pasif bilgileri
ozetle: HTTP guvenlik basliklari (HSTS, CSP, X-Frame-Options, X-Content-Type-Options),
sunucu/teknoloji banner'i ve TLS sertifikasinin gecerli olup olmadigi.

EN FAZLA 2-3 ARACLA ISLEM yap, sonra HEMEN bitir. Yeni alt gorevler ACMA.
${SAFETY}

Cikti: birkac maddelik KISA bir ozet yaz ve GOREVI HEMEN TAMAMLA.

Hedef: ${host}
`.trim(),
  },
  {
    key: 'ssl_tls',
    displayName: 'SSL/TLS Yapılandırma Denetimi',
    description:
      'Sertifika gecerliligi/suresi, zayif protokol ve cipher suite kullanimi, HSTS ' +
      'eksikligi. Tamamen pasif, saldirgan olmayan bir sifreleme denetimi.',
    priceMinorUnit: 79900, // 799,00 TRY
    modelProvider: PROVIDER,
    maxToolCalls: 18,
    promptTemplate: (host) => `
Yalnizca asagidaki TEK hedefe karsi PASIF bir SSL/TLS yapilandirma denetimi yap.
Varsa testssl.sh / sslyze / openssl gibi araclarla; yoksa manuel TLS el sikismasi
gozlemiyle sunlari degerlendir:
- Sertifika: gecerlilik, son kullanma tarihi, zincir/CA, hostname eslesmesi
- Desteklenen protokoller (TLS 1.0/1.1 gibi eskilerin acik olup olmadigi)
- Zayif/eskimis cipher suite'ler
- HSTS basliginin varligi ve suresi
${SAFETY}

Cikti: bulgulari onem derecesine gore siralayip kisa oneri listesiyle sun.
En fazla ~12 arac cagrisinda bitir ve GOREVI TAMAMLA.

Hedef: ${host}
`.trim(),
  },
  {
    key: 'header_leak',
    displayName: 'Güvenlik Başlıkları & Bilgi Sızıntısı',
    description:
      'Eksik guvenlik header\'lari (CSP, X-Frame-Options vb.) ve yanlislikla acikta ' +
      'kalmis hassas dosyalarin (.git, .env, yedek) pasif kontrolu.',
    priceMinorUnit: 79900, // 799,00 TRY
    modelProvider: PROVIDER,
    maxToolCalls: 18,
    promptTemplate: (host) => `
Yalnizca asagidaki TEK hedefe karsi PASIF bir kontrol yap:
1) HTTP guvenlik basliklari: Content-Security-Policy, Strict-Transport-Security,
   X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
   Hangileri eksik/zayif?
2) Yanlislikla acikta kalmis olabilecek SADECE BILINEN yollar icin tek seferlik
   GET ile kontrol (dizin ZORLAMA/brute-force YOK): /robots.txt, /.git/config,
   /.env, /backup.zip, /.DS_Store gibi standart dosyalar erisilebilir mi?
${SAFETY}

Cikti: eksik header'lari ve varsa acik dosyalari onem sirasiyla, somut oneriyle
listele. En fazla ~12 arac cagrisinda bitir ve GOREVI TAMAMLA.

Hedef: ${host}
`.trim(),
  },
  {
    key: 'dns_email',
    displayName: 'DNS & E-posta Güvenliği',
    description:
      'SPF/DKIM/DMARC eksiklikleri, DNSSEC ve DNS yanlis yapilandirmalari. E-posta ' +
      'sahteciligine (spoofing) karsi isletmeler icin degerli, tamamen pasif.',
    priceMinorUnit: 99900, // 999,00 TRY
    modelProvider: PROVIDER,
    maxToolCalls: 18,
    promptTemplate: (host) => `
Yalnizca asagidaki TEK hedefin alan adi icin PASIF DNS/e-posta guvenligi kontrolu
yap (dig/nslookup gibi araclarla, sadece SORGU — hicbir kayit degistirme):
- SPF kaydi var mi, dogru mu (tek TXT, -all/~all politikasi)?
- DMARC kaydi (_dmarc.${host}) var mi, politikasi (none/quarantine/reject) ne?
- DKIM: yaygin selector'larla (default, google, selector1/2) kayit gozlemle
- DNSSEC etkin mi, MX kayitlari makul mu?
${SAFETY}

Cikti: her bulguyu (SPF/DKIM/DMARC/DNSSEC) durum + oneriyle tabloda ozetle.
En fazla ~12 arac cagrisinda bitir ve GOREVI TAMAMLA.

Hedef: ${host}
`.trim(),
  },
  {
    key: 'cms_cve',
    displayName: 'CMS & Bilinen CVE Taraması',
    description:
      'WordPress/Joomla gibi CMS ve framework parmak izi, surum tespiti ve bilinen ' +
      'CVE eslemesi. SADECE TESPIT — hicbir exploit denenmez.',
    priceMinorUnit: 149900, // 1.499,00 TRY
    modelProvider: PROVIDER,
    maxToolCalls: 25,
    promptTemplate: (host) => `
Yalnizca asagidaki TEK hedefe karsi PASIF parmak izi ve bilinen zafiyet TESPITI
yap (whatweb / wappalyzer tarzi pasif gozlem + acik sayfalardaki surum ipuclari):
- Calisan CMS/framework nedir (WordPress, Joomla, Drupal, Laravel vb.)?
- Tespit edilebilen surum bilgisi
- Bu surum(ler)e ait BILINEN CVE'ler (yalnizca eslestirme/raporlama)
- Eklenti/tema surum ipuclari (varsa)

ONEMLI: Tespit edilen CVE'leri DENEME/DOGRULAMA amacli ISTISMAR ETME — sadece
"bu surumde su CVE'ler bilinmektedir" diye raporla.
${SAFETY}

Cikti: tespit edilen teknoloji + surum + bilinen CVE listesi (CVSS ile) + guncelleme
onerisi. En fazla ~18 arac cagrisinda bitir ve GOREVI TAMAMLA.

Hedef: ${host}
`.trim(),
  },
  {
    key: 'pci_hazirlik',
    displayName: 'PCI-DSS Hazırlık Ön-Değerlendirmesi',
    description:
      'Dis yuzeyinizi (TLS/sifreleme, guvenlik basliklari, acikta hassas dosyalar, ' +
      'bilinen surum zafiyetleri, cerez/oturum guvenligi) PCI-DSS maddeleriyle ' +
      'eslestiren pasif bir hazirlik raporu. RESMI ASV/QSA testi DEGILDIR.',
    priceMinorUnit: 249900, // 2.499,00 TRY
    modelProvider: PROVIDER,
    maxToolCalls: 40,
    promptTemplate: (host) => `
Yalnizca asagidaki TEK hedefe karsi PASIF bir "PCI-DSS HAZIRLIK ON-DEGERLENDIRMESI"
yap. Bu RESMI bir PCI ASV taramasi veya sizma testi DEGILDIR; amac disaridan
gozlemlenebilen kontrolleri ilgili PCI-DSS maddeleriyle eslestirmek.

Sadece normal GET istekleriyle sunlari kontrol edip PCI maddesine esle:
- TLS surumu/cipher/sertifika -> Req 4.2.1 (aktarimda guclu sifreleme)
- HTTP guvenlik basliklari -> Req 6.4 / genel web korumasi
- Cerez bayraklari (Secure/HttpOnly/SameSite) -> Req 8 / oturum guvenligi
- Sunucu banner / varsayilan sayfalar -> Req 2.2 (guvenli yapilandirma)
- Bilinen surum CVE'leri (banner'dan) -> Req 6.2/6.3
- Acikta kalan hassas dosyalar (.git/.env/yedek) -> Req 3 / veri aciga cikma
${SAFETY}

Cikti (Markdown tablo): "PCI Maddesi | Bulgu | Durum (Uygun/Dikkat/Eksik) | Oneri".
Sonda: "Bu rapor resmi PCI uyumluluk testi degildir; ic ag/CDE, segmentasyon, ASV
taramasi ve sizma testi KAPSAM DISIDIR" notu. En fazla ~30 arac cagrisinda bitir.

Hedef: ${host}
`.trim(),
  },
  {
    key: 'kvkk_hazirlik',
    displayName: 'KVKK Ön Uyum Kontrolü',
    description:
      'Kisisel veri isleyen formlar, cerez rizasi/aydinlatma metni, veri saklama ' +
      've iletisim/veri sorumlusu bilgilerinin pasif kontrolu. Hukuki danismanlik ' +
      'DEGILDIR — farkindalik ve eksik tespiti amaclidir.',
    priceMinorUnit: 199900, // 1.999,00 TRY
    modelProvider: PROVIDER,
    maxToolCalls: 30,
    promptTemplate: (host) => `
Yalnizca asagidaki TEK hedefin HERKESE ACIK sayfalarini PASIF gozlemleyerek bir
"KVKK ON UYUM KONTROLU" yap. Bu HUKUKI DANISMANLIK DEGILDIR; amac disaridan
gorulebilen eksikleri KVKK ilkeleriyle eslestirmek.

Sadece normal GET ile gozlemle:
- Aydinlatma metni / Gizlilik politikasi sayfasi var mi, erisilebilir mi?
- Cerez rizasi (consent) banner'i var mi; rizadan ONCE izleyici cerez birakiliyor mu?
- Kisisel veri toplayan formlar (iletisim, uyelik) HTTPS uzerinde mi; acik rizaya
  atif var mi?
- Veri sorumlusu / iletisim / VERBIS atifi gozlemleniyor mu?
- Ucuncu taraf izleyiciler (analytics, pixel) gozlemleniyor mu?
${SAFETY}

Cikti (Markdown tablo): "KVKK Ilkesi/Konu | Gozlem | Durum (Uygun/Dikkat/Eksik) |
Oneri". Sonda: "Bu rapor hukuki gorus/uyum beyani degildir; nihai degerlendirme
icin KVKK uzmani/avukat gerekir" notu. En fazla ~22 arac cagrisinda bitir.

Hedef: ${host}
`.trim(),
  },
  {
    key: 'iso27001_hazirlik',
    displayName: 'ISO 27001 Hazırlık Kontrol Listesi',
    description:
      'Disaridan gozlemlenebilen teknik kontrollerin ISO 27001 Ek-A maddeleriyle ' +
      'eslestirildigi pasif hazirlik raporu. RESMI sertifikasyon/denetim DEGILDIR.',
    priceMinorUnit: 299900, // 2.999,00 TRY
    modelProvider: PROVIDER,
    maxToolCalls: 30,
    promptTemplate: (host) => `
Yalnizca asagidaki TEK hedefe karsi PASIF gozlemle, disaridan gorulebilen teknik
kontrolleri ISO/IEC 27001 Ek-A ile eslestiren bir "HAZIRLIK KONTROL LISTESI" cikar.
Bu RESMI bir sertifikasyon denetimi DEGILDIR.

Gozlemler ve eslesme ornekleri:
- TLS/sifreleme, guvenli aktarim -> A.8 (kriptografi/iletisim guvenligi)
- Guvenlik basliklari, guvenli yapilandirma -> A.8 (teknik onlemler)
- Bilgi sizintisi/acik dosyalar -> A.5/A.8 (erisim, varlik yonetimi)
- Gizlilik/guvenlik politikasi sayfasi gorunurlugu -> A.5 (politikalar)
${SAFETY}

Cikti (Markdown tablo): "Ek-A Maddesi | Gozlem | Durum | Oneri". Sonda: "Bu rapor
resmi ISO 27001 denetimi/sertifikasyonu degildir; ISMS kapsami, dokumantasyon ve
ic surecler KAPSAM DISIDIR" notu. En fazla ~22 arac cagrisinda bitir.

Hedef: ${host}
`.trim(),
  },
];

export function getPackageDef(key: string): ScanPackageDef {
  const def = SCAN_PACKAGES.find((p) => p.key === key);
  if (!def) throw new Error(`Bilinmeyen paket: ${key}`);
  return def;
}
