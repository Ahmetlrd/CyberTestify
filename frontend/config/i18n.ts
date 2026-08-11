import type { Lang, RegionConfig } from './regions';

/**
 * Basit, tip-güvenli i18n sözlüğü. Arapça (RTL) eklenince yeni bir dil anahtarı
 * + `dir: 'rtl'` yeterli olacak şekilde yapılandırıldı (Faz-2 TODO, bkz HANDOFF).
 */
export interface Dict {
  nav: { how: string; why: string; packages: string; login: string; cta: string; panel: string; logout: string };
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
}

const tr: Dict = {
  nav: { how: 'Nasıl Çalışır', why: 'Neden Biz', packages: 'Paketler', login: 'Giriş', cta: 'Ücretsiz Doğrula', panel: 'Panelim', logout: 'Çıkış' },
  hero: {
    badge: 'Yapay zekâ destekli otomasyon · İnsan pentester beklemeyin',
    titleA: 'Sitenizin güvenliğini,',
    titleHi: 'dakikalar içinde',
    titleB: 'yapay zekâ destekli taramayla başlatın',
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
    subtitle: 'Kapsam sabit, fiyat sabit, sürpriz maliyet yok. Tüm fiyatlar vergiler dahildir.',
    trust: ['🇹🇷 Yerli sunucu', '💬 Türkçe destek', '🧾 e-Arşiv faturalı', '🔒 Uçtan uca şifreli rapor'],
    popular: 'Popüler',
    perScan: '/ tarama',
    taxIncl: 'vergiler dahil',
    selectCta: 'Satın Al',
    byokBadge: 'Gelişmiş Kullanıcılar İçin',
    byokTitle: 'Kendi API Anahtarınla (BYOK)',
    byokDesc: 'Kendi Anthropic anahtarınızla daha geniş kapsamlı tarama. Teknik kullanıcılar için; maliyet kontrolü sizde.',
    soon: 'Yakında',
    freeTitle: 'Doğrulama ücretsiz',
    freeSubtitle: 'Yalnızca taramayı başlattığınızda ödeme yaparsınız. Alan adınızı doğrulayarak başlayın.',
    freeCta: 'Ücretsiz Doğrula ve Başla',
    loadError: 'Paketler şu an yüklenemedi.',
    startAnyway: 'Yine de başlayın →',
  },
};

const en: Dict = {
  nav: { how: 'How It Works', why: 'Why Us', packages: 'Pricing', login: 'Log in', cta: 'Verify Free', panel: 'My Panel', logout: 'Log out' },
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
    byokDesc: 'A broader scan with your own Anthropic key. For technical users; cost control is yours.',
    soon: 'Soon',
    freeTitle: 'Verification is free',
    freeSubtitle: 'You only pay when you start a scan. Get started by verifying your domain.',
    freeCta: 'Verify Free & Start',
    loadError: 'Packages could not be loaded right now.',
    startAnyway: 'Start anyway →',
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
