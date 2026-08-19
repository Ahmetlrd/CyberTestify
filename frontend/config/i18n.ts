import type { Lang, RegionConfig } from './regions';

/**
 * Basit, tip-güvenli i18n sözlüğü. Arapça (RTL) eklenince yeni bir dil anahtarı
 * + `dir: 'rtl'` yeterli olacak şekilde yapılandırıldı (Faz-2 TODO, bkz HANDOFF).
 */
export interface Dict {
  nav: { how: string; why: string; packages: string; login: string; cta: string; panel: string; logout: string; profile: string; otonom: string };
  hero: {
    badge: string;
    titleA: string;
    titleHi: string;
    titleB: string;
    subtitle: string;
    ctaPrimary: string;
    ctaSecondary: string;
    trust: [string, string, string];
  };
  auto: {
    eyebrow: string;
    titleA: string;
    titleHi: string;
    titleB: string;
    subtitle: string;
    tradTitle: string;
    trad: [string, string, string, string];
    oursTitle: string;
    ours: [string, string, string, string];
    ribbon: string;
    demo: string;
  };
  steps: { eyebrow: string; title: string; items: Array<{ t: string; d: string }>; stepWord: string };
  why: { eyebrow: string; title: string; subtitle: string; items: Array<{ t: string; d: string }> };
  finalCta: { title: string; subtitle: string; primary: string; secondary: string };
  footer: { tagline: string; questions: string; legal: string; disclaimer: string };
  pkg: {
    metaTitle: string;
    metaDesc: string;
    eyebrow: string;
    title: string;
    subtitle: string;
    trust: [string, string, string, string];
    popular: string;
    perScan: string;
    taxIncl: string;
    selectCta: string;
    byokBadge: string;
    byokTitle: string;
    byokDesc: string;
    soon: string;
    freeTitle: string;
    freeSubtitle: string;
    freeCta: string;
    loadError: string;
    startAnyway: string;
  };
  otonom: {
    metaTitle: string; metaDesc: string;
    eyebrow: string; title: string; subtitle: string;
    badges: [string, string, string]; comingSoon: string;
    warnTitle: string; warnPoints: [string, string, string, string, string];
    whatTitle: string; whatBody: string; whatFor: string;
    howTitle: string; howSteps: Array<{ t: string; d: string }>;
    evTitle: string; evKanitli: string; evBelirsiz: string; evHayalet: string;
    diffTitle: string; diffBody: string; diffPoints: [string, string, string];
    levelsTitle: string;
    levels: Array<{ name: string; tag: string; risk: string; technique: string; consistency: string; humanLoop: string; note: string }>;
    principleTitle: string; principleBody: string; disclaimer: string; triggerWord: string;
    lockedTitle: string; lockedBody: string;
    codeLabel: string; codePlaceholder: string; unlock: string; unlocking: string; invalid: string; unlockedMsg: string;
    panelTitle: string; panelSubtitle: string;
    domainLabel: string; domainPlaceholder: string; estimateCta: string; estimating: string;
    priceTitle: string; priceGuarantee: string; priceUnset: string; tierLabel: string; scoreLabel: string;
    envLabel: string; envTest: string; envStaging: string; envProd: string; levelLabel: string;
    ownConsent: string; riskConsent: string; prodS3Warn: string; prodS3Consent: string; prodRedirect: string;
    startCta: string; starting: string; stubTitle: string; stubBody: string; needConsents: string;
  };
}

const tr: Dict = {
  nav: { how: 'Nasıl Çalışır', why: 'Neden Biz', packages: 'Paketler', login: 'Giriş', cta: 'Ücretsiz Doğrula', panel: 'Panelim', logout: 'Çıkış', profile: 'Profil', otonom: 'Otonom AI Red Team' },
  hero: {
    badge: 'Yapay zekâ destekli otomasyon · İnsan pentester beklemeyin',
    titleA: 'Sitenizin güvenliğini,',
    titleHi: 'dakikalar içinde',
    titleB: 'yapay zekâ destekli taramayla test edin',
    subtitle:
      'Web siteniz için yapay zeka destekli, hızlı ve uygun fiyatlı güvenlik ön değerlendirmesi. Resmi pentest/denetim yerine geçmez; dakikalar içinde aksiyon alınabilir bir rapor üretir. Alan adınızı doğrulayın, paketinizi seçin, şifreli raporunuzu alın.',
    ctaPrimary: 'Ücretsiz Doğrula ve Başla',
    ctaSecondary: 'Nasıl Çalışır?',
    trust: ['KVKK’ya Uygun Veri İşleme', 'Uçtan Uca Şifreli Rapor', 'Sadece Doğrulanmış Alan Adları'],
  },
  auto: {
    eyebrow: 'Yapay Zekâ Destekli Otomasyon · Asıl Farkımız',
    titleA: 'Haftalarca beklemeyin.',
    titleHi: 'Dakikalar',
    titleB: 'içinde başlayın.',
    subtitle:
      'Rakiplerimiz insan pentester ekipleriyle çalışır — bu yüzden pahalı ve yavaştır. Biz yapay zekâ destekli, tamamen otomatik bir platformuz: hem çok daha ucuz, hem çok daha hızlı.',
    tradTitle: 'Geleneksel Pentest',
    trad: ['2–4 hafta bekleme süresi', '$2.000 – $6.000 arası maliyet', 'İnsan ekibiyle randevu / demo', 'Yılda yalnızca 1–2 kez'],
    oursTitle: 'CyberTestify',
    ours: ['Dakikalar içinde başlar', 'Saatler içinde biter', 'Yapay zekâ destekli otomatik kontroller', 'İstediğiniz an, sınırsız tekrar'],
    ribbon: 'SİZİN İÇİN',
    demo: 'Gerçek zamanlı — tarama çalışırken:',
  },
  steps: {
    eyebrow: 'Nasıl Çalışır',
    title: 'Dört adımda, baştan sona',
    stepWord: 'ADIM',
    items: [
      { t: 'Alan adınızı doğrulayın', d: 'DNS TXT kaydıyla sahipliğinizi kanıtlayın — dakikalar sürer.' },
      { t: 'Paketinizi seçin', d: 'Sabit kapsam, sabit fiyat. Sürpriz maliyet yok.' },
      { t: 'Otomatik güvenlik taraması', d: 'Yapay zekâ destekli tarama saniyeler içinde başlar, arka planda çalışır.' },
      { t: 'Şifreli raporunuzu indirin', d: 'Uçtan uca şifreli, size özel tek kullanımlık kodla açılır.' },
    ],
  },
  why: {
    eyebrow: 'Neden Biz',
    title: 'İddia değil, teknik önlem',
    subtitle: 'Rakiplerin çoğu güvenliği söyler. Biz onu koda gömdük.',
    items: [
      { t: 'Kapsam Kilidi', d: 'Taramalarımız yalnızca sizin doğruladığınız alan adına erişebilir — teknik olarak başka hiçbir hedefe dokunamaz.' },
      { t: 'Kişisel Veri Koruması', d: 'Tarama sırasında karşılaşılan kişisel veriler, yapay zekaya ulaşmadan önce otomatik olarak maskelenir.' },
      { t: 'Şifreli, Tek Seferlik Teslim', d: 'Raporunuz uçtan uca şifrelenir; yalnızca size özel tek kullanımlık bir kodla açılır.' },
    ],
  },
  finalCta: {
    title: 'Sitenizi test etmeye hazır mısınız?',
    subtitle: 'Doğrulama ücretsiz. Yalnızca taramayı başlattığınızda ödeme yaparsınız.',
    primary: 'Ücretsiz Doğrula ve Başla',
    secondary: 'Fiyatları Gör →',
  },
  footer: {
    tagline:
      'Yalnızca sahipliğini doğruladığınız alan adına karşı, yapay zekâ destekli otomatik güvenlik ön-değerlendirmesi. Resmi denetim/sertifikasyon yerine geçmez.',
    questions: 'Sorularınız mı var?',
    legal: 'Yasal',
    disclaimer: 'Güvenlik ön-değerlendirme hizmeti.',
  },
  pkg: {
    metaTitle: 'Fiyatlar — Web Sitesi Güvenlik Tarama Paketleri | CyberTestify',
    metaDesc:
      'Sabit kapsam, sabit fiyat, sürpriz maliyet yok. Yapay zekâ destekli otomatik web sitesi güvenlik tarama paketleri ve fiyatları.',
    eyebrow: 'Fiyatlar',
    title: 'Şeffaf, sabit fiyatlandırma',
    subtitle: 'Kapsam sabit, fiyat sabit, sürpriz maliyet yok. Tüm fiyatlara vergiler dahildir.',
    trust: ['🇹🇷 Yerli sunucu', '💬 Türkçe destek', '🧾 e-Arşiv faturalı', '🔒 Uçtan uca şifreli rapor'],
    popular: 'Popüler',
    perScan: '/ tarama',
    taxIncl: 'vergiler dahil',
    selectCta: 'Satın Al',
    byokBadge: 'Gelişmiş Kullanıcılar İçin',
    byokTitle: 'Kendi API Anahtarınla (BYOK)',
    byokDesc: 'Kendi API anahtarınızla daha geniş kapsamlı tarama. Teknik kullanıcılar için; maliyet kontrolü sizde.',
    soon: 'Yakında',
    freeTitle: 'Doğrulama ücretsiz',
    freeSubtitle: 'Yalnızca taramayı başlattığınızda ödeme yaparsınız. Alan adınızı doğrulayarak başlayın.',
    freeCta: 'Ücretsiz Doğrula ve Başla',
    loadError: 'Paketler şu an yüklenemedi.',
    startAnyway: 'Yine de başlayın →',
  },
  otonom: {
    metaTitle: 'Otonom AI Red Team — Deneysel Otonom Pentest | CyberTestify',
    metaDesc: 'Gerçek saldırı tekniklerini otonom yürüten deneysel AI red-team katmanı. Deterministik değildir; her bulgu ham kanıta bağlanır. Yalnız sahibi/yetkili olduğunuz hedeflerde.',
    eyebrow: 'Deneysel Katman',
    title: 'Otonom AI Red Team',
    subtitle: '6 deterministik paketten ayrı, deneysel bir katman: gerçek saldırı tekniklerini otonom bir AI ajanı yürütür ve her bulguyu ham kanıtına bağlar. Şu an yalnız erişimi olanlara açık.',
    badges: ['Deneysel', 'Yüksek Kapsam', 'Deterministik Değil'],
    comingSoon: 'YAKINDA',
    warnTitle: 'Başlatmadan önce okuyun',
    warnPoints: [
      'Bu katman GERÇEK saldırı tekniklerini çalıştırır — simülasyon değil.',
      'Deterministik DEĞİLDİR: aynı hedefte her koşu farklı adım ve sonuç üretebilir.',
      'Canlı (prod) ortamda risk taşır: beklenmeyen istek, yük veya yan etki olabilir.',
      'Yalnızca SAHİBİ olduğunuz ya da YAZILI yetkiniz bulunan hedeflerde kullanın.',
      'Her bulgu ham kanıtla sunulur; kanıtsız iddia rapora BULGU olarak girmez.',
    ],
    whatTitle: 'Ne / kime',
    whatBody: 'Otonom bir AI ajanı hedefinizi bir saldırgan gibi keşfeder, hipotez kurar ve güvenli sınırlar içinde dener. Amaç kapsam ve derinlik: deterministik paketlerin sabit kontrol listesinin ötesine geçen, bağlama-özel yollar.',
    whatFor: 'Kimler için: kendi sistemini derinlemesine sınamak isteyen ve deneysel bir aracın deterministik-olmayan doğasını kabul eden ekipler. Uyumluluk veya sertifikasyon amacıyla değildir.',
    howTitle: 'Nasıl çalışır',
    howSteps: [
      { t: 'Keşif', d: 'Ajan hedefi pasif ve aktif olarak haritalar, saldırı yüzeyini çıkarır.' },
      { t: 'Hipotez ve deneme', d: 'Olası zafiyetler için güvenli sınırlar içinde gerçek teknikleri dener.' },
      { t: 'Kanıt-bağlama', d: 'Her adımın ham çıktısı (istek/yanıt, terminal) saklanır.' },
      { t: 'Sınıflandırma', d: 'Bulgular ham kanıta göre üç katmana ayrılır.' },
    ],
    evTitle: 'Kanıt-bağlama · üç katman',
    evKanitli: 'Kanıtlı — ham kanıtta deterministik imza var. Rapora bulgu olarak girer.',
    evBelirsiz: 'Belirsiz — kanıt var ama kesin imza yok. Silinmez; insan incelemesine gider.',
    evHayalet: 'Hayalet — ajan iddia etti ama ham izde karşılığı yok. Elenir, rapora girmez.',
    diffTitle: '6 paketten farkı',
    diffBody: '6 deterministik paket sabit ve tekrarlanabilir bir kontrol listesi çalıştırır — aynı girdide aynı sonucu verir ve uygunluk/rapor için güvenilirdir. Bu katman farklıdır:',
    diffPoints: [
      'Deterministik paketler: sabit kapsam, tekrarlanabilir, öngörülebilir fiyat.',
      'Bu katman: keşif-güdümlü, deterministik değil, geniş ve değişken kapsam.',
      'İkisi birbirini tamamlar; bu katman deterministik paketlerin yerine geçmez.',
    ],
    levelsTitle: 'Üç risk seviyesi',
    levels: [
      { name: 'S1 · Güvenli', tag: 'En düşük risk', risk: 'Düşük — çoğunlukla okuma ve az-etkili denemeler', technique: 'Pasif + hafif aktif göstergeler', consistency: 'Görece kararlı', humanLoop: 'Otomatik; kritik adımlarda onay', note: '' },
      { name: 'S2 · Dengeli', tag: 'Önerilen varsayılan', risk: 'Orta — kontrollü aktif teknikler', technique: 'Aktif doğrulama + sınırlı sömürü denemesi', consistency: 'Değişken', humanLoop: 'Riskli adımlarda insan onayı', note: '' },
      { name: 'S3 · Agresif', tag: 'İleri düzey', risk: 'Yüksek — derin, ısrarcı teknikler', technique: 'Geniş sömürü yüzeyi, zincirleme denemeler', consistency: 'Belirgin değişken', humanLoop: 'Sık insan onayı önerilir', note: 'Yalnız izole test/staging ortamı önerilir; canlı prod önerilmez.' },
    ],
    principleTitle: 'Kanıt ve dürüstlük ilkesi',
    principleBody: 'Hiçbir bulgu ajanın sözüne dayanmaz; yalnız saklanan ham kanıta dayanır. Belirsiz bulgular gizlice silinmez, insana açık biçimde işaretlenir. Kanıtsız iddia rapora girmez.',
    disclaimer: 'Bu deneysel bir özelliktir; resmi bir denetim, sızma testi sertifikasyonu ya da uygunluk belgesi değildir. Sonuçlar deterministik değildir ve garanti içermez.',
    triggerWord: 'içermez',
    lockedTitle: 'Bu özellik şu an davetli erişimindedir',
    lockedBody: 'Otonom AI Red Team paneli herkese açık değildir. Erişiminiz varsa panel bu sayfadan açılır.',
    codeLabel: 'Erişim kodu',
    codePlaceholder: 'Erişim kodunuzu girin',
    unlock: 'Paneli aç',
    unlocking: 'Doğrulanıyor…',
    invalid: 'Kod geçersiz.',
    unlockedMsg: 'Panel açıldı.',
    panelTitle: 'Otonom Red Team paneli',
    panelSubtitle: 'Bu aşamada gerçek koşu başlatılmaz — akış (sahiplik, onay, ortam, fiyat) hazırlanır; orkestrasyon yakında (3b-ii) bağlanır.',
    domainLabel: 'Hedef alan adı',
    domainPlaceholder: 'example.com',
    estimateCta: 'Fiyat bandını göster',
    estimating: 'Hesaplanıyor…',
    priceTitle: 'Tahmini fiyat bandı',
    priceGuarantee: 'Öneri — garanti değil. Pasif sinyallerden türetilir, ekstra tarama yapılmaz.',
    priceUnset: 'Fiyat aralığı henüz ayarlanmadı (placeholder).',
    tierLabel: 'Kademe',
    scoreLabel: 'Kompleksite skoru',
    envLabel: 'Ortam',
    envTest: 'Test',
    envStaging: 'Staging',
    envProd: 'Prod (canlı)',
    levelLabel: 'Risk seviyesi',
    ownConsent: 'Bu hedefin sahibiyim ya da yazılı yetkim var.',
    riskConsent: 'Riskleri ve deterministik-olmadığını okudum, kabul ediyorum.',
    prodS3Warn: 'Prod + Agresif (S3) yüksek risk taşır. İzole test/staging şiddetle önerilir.',
    prodS3Consent: 'Prod ortamında S3 agresif tekniklerin ek riskini açıkça kabul ediyorum.',
    prodRedirect: 'Canlı prod için S1 veya S2 önerilir.',
    startCta: 'Otonom koşuyu hazırla',
    starting: 'Hazırlanıyor…',
    stubTitle: 'Hazırlanıyor',
    stubBody: 'Otonom orkestrasyon yakında etkinleşecek (3b-ii). Bu aşamada gerçek koşu başlatılmaz.',
    needConsents: 'Devam etmek için sahiplik ve risk onaylarını işaretleyin.',
  },
};

const en: Dict = {
  nav: { how: 'How It Works', why: 'Why Us', packages: 'Pricing', login: 'Log in', cta: 'Verify Free', panel: 'My Panel', logout: 'Log out', profile: 'Profile', otonom: 'Autonomous AI Red Team' },
  hero: {
    badge: 'AI-assisted automation · No waiting for a human pentester',
    titleA: 'Test your website’s security with',
    titleHi: 'AI-assisted scanning',
    titleB: 'starting in minutes',
    subtitle:
      'AI-powered, fast and affordable security pre-assessment for your website. Not a substitute for a formal pentest/audit; it produces an actionable report in minutes. Verify your domain, pick a package, get your encrypted report.',
    ctaPrimary: 'Verify Free & Start',
    ctaSecondary: 'How It Works?',
    trust: ['Privacy-First', 'End-to-End Encrypted Report', 'Verified Domains Only'],
  },
  auto: {
    eyebrow: 'AI-Assisted Automation · Our Real Difference',
    titleA: 'Don’t wait for weeks.',
    titleHi: 'Start in minutes.',
    titleB: '',
    subtitle:
      'Competitors rely on human pentester teams — so they’re expensive and slow. We’re a fully automated, AI-assisted platform: far cheaper and far faster.',
    tradTitle: 'Traditional Pentest',
    trad: ['2–4 weeks lead time', '$2,000 – $6,000 cost', 'Scheduling with a human team', 'Only 1–2 times a year'],
    oursTitle: 'CyberTestify',
    ours: ['Starts in minutes', 'Finishes in hours', 'AI-assisted automated checks', 'Anytime, unlimited re-runs'],
    ribbon: 'FOR YOU',
    demo: 'Real-time — the scan at work:',
  },
  steps: {
    eyebrow: 'How It Works',
    title: 'Four steps, end to end',
    stepWord: 'STEP',
    items: [
      { t: 'Verify your domain', d: 'Prove ownership with a DNS TXT record — takes minutes.' },
      { t: 'Pick your package', d: 'Fixed scope, fixed price. No surprise costs.' },
      { t: 'Automated security scan', d: 'The AI-assisted scan starts in seconds and runs in the background.' },
      { t: 'Download your encrypted report', d: 'End-to-end encrypted, opened with your one-time code.' },
    ],
  },
  why: {
    eyebrow: 'Why Us',
    title: 'Not a claim — a technical control',
    subtitle: 'Most competitors say they’re secure. We built it into the code.',
    items: [
      { t: 'Scope Lock', d: 'Our scans can only reach the domain you verified — technically unable to touch any other target.' },
      { t: 'Personal Data Protection', d: 'Personal data encountered during a scan is automatically masked before it reaches the AI.' },
      { t: 'Encrypted, One-Time Delivery', d: 'Your report is end-to-end encrypted and opened only with a one-time code unique to you.' },
    ],
  },
  finalCta: {
    title: 'Ready to test your site?',
    subtitle: 'Verification is free. You only pay when you start a scan.',
    primary: 'Verify Free & Start',
    secondary: 'See Pricing →',
  },
  footer: {
    tagline:
      'An AI-assisted, automated security pre-assessment, run only against a domain you have verified. Not a substitute for a formal audit/certification.',
    questions: 'Have questions?',
    legal: 'Legal',
    disclaimer: 'Security pre-assessment service.',
  },
  pkg: {
    metaTitle: 'Pricing — Website Security Scan Packages | CyberTestify',
    metaDesc:
      'Fixed scope, fixed price, no surprise costs. AI-assisted automated website security scan packages and pricing.',
    eyebrow: 'Pricing',
    title: 'Transparent, fixed pricing',
    subtitle: 'Fixed scope, fixed price, no surprise costs.',
    trust: ['⚡ AI-assisted automation', '💬 Fast support', '🧾 Invoiced', '🔒 End-to-end encrypted report'],
    popular: 'Popular',
    perScan: '/ scan',
    taxIncl: 'taxes included',
    selectCta: 'Buy Now',
    byokBadge: 'For Advanced Users',
    byokTitle: 'Bring Your Own Key (BYOK)',
    byokDesc: 'A broader scan with your own API key. For technical users; cost control is yours.',
    soon: 'Soon',
    freeTitle: 'Verification is free',
    freeSubtitle: 'You only pay when you start a scan. Get started by verifying your domain.',
    freeCta: 'Verify Free & Start',
    loadError: 'Packages could not be loaded right now.',
    startAnyway: 'Start anyway →',
  },
  otonom: {
    metaTitle: 'Autonomous AI Red Team — Experimental Autonomous Pentest | CyberTestify',
    metaDesc: 'An experimental AI red-team layer that autonomously runs real attack techniques. It is non-deterministic; every finding is bound to raw evidence. Only for targets you own or are authorized to test.',
    eyebrow: 'Experimental Layer',
    title: 'Autonomous AI Red Team',
    subtitle: 'Separate from the 6 deterministic packages: an experimental layer where an autonomous AI agent runs real attack techniques and binds every finding to its raw evidence. Currently available to invited access only.',
    badges: ['Experimental', 'High Scope', 'Non-Deterministic'],
    comingSoon: 'COMING SOON',
    warnTitle: 'Read before you start',
    warnPoints: [
      'This layer runs REAL attack techniques — not a simulation.',
      'It is NON-DETERMINISTIC: each run on the same target may take different steps and yield different results.',
      'It carries risk on live (prod) environments: unexpected requests, load or side effects are possible.',
      'Use it ONLY on targets you OWN or have WRITTEN authorization to test.',
      'Every finding is presented with raw evidence; unproven claims never enter the report as findings.',
    ],
    whatTitle: 'What / for whom',
    whatBody: 'An autonomous AI agent explores your target like an attacker, forms hypotheses and tries them within safe bounds. The goal is scope and depth: context-specific paths beyond the fixed checklist of the deterministic packages.',
    whatFor: 'For whom: teams that want to deeply probe their own systems and accept the non-deterministic nature of an experimental tool. Not intended for compliance or certification.',
    howTitle: 'How it works',
    howSteps: [
      { t: 'Recon', d: 'The agent maps the target passively and actively, extracting the attack surface.' },
      { t: 'Hypothesize and try', d: 'It tries real techniques for likely weaknesses within safe bounds.' },
      { t: 'Evidence binding', d: 'The raw output of each step (request/response, terminal) is stored.' },
      { t: 'Classification', d: 'Findings are split into three tiers by raw evidence.' },
    ],
    evTitle: 'Evidence binding · three tiers',
    evKanitli: 'Proven — a deterministic signature exists in the raw evidence. Enters the report as a finding.',
    evBelirsiz: 'Uncertain — evidence exists but no conclusive signature. Not deleted; sent to human review.',
    evHayalet: 'Ghost — the agent claimed it but there is no trace in the raw evidence. Eliminated, never reported.',
    diffTitle: 'How it differs from the 6 packages',
    diffBody: 'The 6 deterministic packages run a fixed, repeatable checklist — same input yields the same result, reliable for compliance and reporting. This layer is different:',
    diffPoints: [
      'Deterministic packages: fixed scope, repeatable, predictable price.',
      'This layer: discovery-driven, non-deterministic, broad and variable scope.',
      'They complement each other; this layer does not replace the deterministic packages.',
    ],
    levelsTitle: 'Three risk levels',
    levels: [
      { name: 'S1 · Safe', tag: 'Lowest risk', risk: 'Low — mostly reading and low-impact probes', technique: 'Passive + light active indicators', consistency: 'Relatively stable', humanLoop: 'Automatic; approval on critical steps', note: '' },
      { name: 'S2 · Balanced', tag: 'Recommended default', risk: 'Medium — controlled active techniques', technique: 'Active verification + limited exploitation attempts', consistency: 'Variable', humanLoop: 'Human approval on risky steps', note: '' },
      { name: 'S3 · Aggressive', tag: 'Advanced', risk: 'High — deep, persistent techniques', technique: 'Broad exploitation surface, chained attempts', consistency: 'Highly variable', humanLoop: 'Frequent human approval recommended', note: 'Recommended only on isolated test/staging; live prod is not advised.' },
    ],
    principleTitle: 'Evidence and honesty principle',
    principleBody: 'No finding rests on the agent\'s word; only on stored raw evidence. Uncertain findings are never silently deleted — they are openly flagged for a human. Unproven claims never enter the report.',
    disclaimer: 'This is an experimental feature; it is not an official audit, penetration-test certification or compliance document. Results are non-deterministic and carry no guarantee.',
    triggerWord: 'guarantee',
    lockedTitle: 'This feature is currently invite-only',
    lockedBody: 'The Autonomous AI Red Team panel is not public. If you have access, the panel opens from this page.',
    codeLabel: 'Access code',
    codePlaceholder: 'Enter your access code',
    unlock: 'Open panel',
    unlocking: 'Verifying…',
    invalid: 'Invalid code.',
    unlockedMsg: 'Panel unlocked.',
    panelTitle: 'Autonomous Red Team panel',
    panelSubtitle: 'No real run starts at this stage — the flow (ownership, consent, environment, price) is prepared; orchestration connects soon (3b-ii).',
    domainLabel: 'Target domain',
    domainPlaceholder: 'example.com',
    estimateCta: 'Show price band',
    estimating: 'Calculating…',
    priceTitle: 'Estimated price band',
    priceGuarantee: 'A suggestion — not a guarantee. Derived from passive signals; no extra scan is run.',
    priceUnset: 'Price range not set yet (placeholder).',
    tierLabel: 'Tier',
    scoreLabel: 'Complexity score',
    envLabel: 'Environment',
    envTest: 'Test',
    envStaging: 'Staging',
    envProd: 'Prod (live)',
    levelLabel: 'Risk level',
    ownConsent: 'I own this target or have written authorization.',
    riskConsent: 'I have read and accept the risks and the non-deterministic nature.',
    prodS3Warn: 'Prod + Aggressive (S3) is high risk. Isolated test/staging is strongly recommended.',
    prodS3Consent: 'I explicitly accept the additional risk of S3 aggressive techniques on a prod environment.',
    prodRedirect: 'S1 or S2 is recommended for live prod.',
    startCta: 'Prepare autonomous run',
    starting: 'Preparing…',
    stubTitle: 'Preparing',
    stubBody: 'Autonomous orchestration will be enabled soon (3b-ii). No real run starts at this stage.',
    needConsents: 'Check the ownership and risk consents to continue.',
  },
};

const DICTS: Record<Lang, Dict> = { tr, en };

export function getDict(region: RegionConfig): Dict {
  return DICTS[region.lang];
}

/** Bölge para birimine göre biçimlendirme (Intl). */
export function formatMoney(amountMinorUnit: number, region: RegionConfig): string {
  return new Intl.NumberFormat(region.locale, {
    style: 'currency',
    currency: region.currency,
    maximumFractionDigits: 0,
  }).format(amountMinorUnit / 100);
}
