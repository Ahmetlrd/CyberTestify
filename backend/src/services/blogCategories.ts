/**
 * (BLOG KATEGORİ TAKSONOMİSİ + DETERMİNİSTİK TAHMİN — LLM YOK)
 * Hem görsel etiketleme (Fotolar sayfası dropdown) hem de makale içeriğinden otomatik kategori tahmini
 * AYNI sabit listeyi kullanır → görsel↔makale eşleşmesi güvenilir olur (yazım hatası riski yok).
 *
 * guessCategory: başlık (ağırlık 3) + içerik (ağırlık 1) üzerinde anahtar-kelime skoru; en yüksek skorlu
 * kategori seçilir. Hiç eşleşme yoksa 'genel'. I-güvenli küçük harf (Türkçe I sorunu için, bkz pdf.ts lcMatch).
 * Anahtar kelimeler tr+de+en — çok-dilli blog için üç dilde de çalışır.
 */

export type BlogCategory = {
  slug: string;
  label: { tr: string; de: string; en: string };
  keywords: string[]; // hepsi küçük-harf; başlık+içerikte aranır (kelime-içi eşleşme)
};

// I-güvenli küçük harf: Türkçe 'İ/I' → 'i' (aksi halde İngilizce anahtarlar eşleşmez).
export function lc(s: string): string {
  return (s || '').replace(/[İI]/g, 'i').toLowerCase();
}

export const BLOG_CATEGORIES: BlogCategory[] = [
  {
    slug: 'web-guvenligi',
    label: { tr: 'Web Güvenliği', de: 'Web-Sicherheit', en: 'Web Security' },
    keywords: ['xss', 'sql injection', 'sql enjeksiyon', 'sqli', 'owasp', 'csrf', 'ssrf', 'web uygulama',
      'web application', 'web-anwendung', 'cross-site', 'enjeksiyon', 'injection', 'zafiyet', 'güvenlik açığı',
      'schwachstelle', 'vulnerability', 'clickjacking', 'cookie', 'çerez', 'security header', 'güvenlik başlığı'],
  },
  {
    slug: 'sizma-testi',
    label: { tr: 'Sızma Testi', de: 'Penetrationstest', en: 'Penetration Testing' },
    keywords: ['sızma test', 'pentest', 'penetration', 'penetrationstest', 'red team', 'kırmızı takım',
      'exploit', 'istismar', 'zafiyet tara', 'vulnerability scan', 'schwachstellen', 'etik hack', 'ethical hack',
      'saldırı simül', 'attack simulation', 'recon', 'keşif', 'metasploit', 'burp'],
  },
  {
    slug: 'phishing',
    label: { tr: 'Phishing & Sosyal Mühendislik', de: 'Phishing & Social Engineering', en: 'Phishing & Social Engineering' },
    keywords: ['phishing', 'oltalama', 'sosyal mühendislik', 'social engineering', 'social-engineering',
      'dolandırıc', 'scam', 'betrug', 'sahte e-posta', 'fake email', 'spear phishing', 'smishing', 'vishing',
      'kimlik avı', 'identitätsdiebstahl'],
  },
  {
    slug: 'kimlik-erisim',
    label: { tr: 'Kimlik & Erişim', de: 'Identität & Zugriff', en: 'Identity & Access' },
    keywords: ['2fa', 'mfa', 'çok faktör', 'multi-factor', 'zwei-faktor', 'totp', 'parola', 'şifre', 'password',
      'passwort', 'kimlik doğrula', 'authentication', 'authentifizierung', 'yetkilendirme', 'authorization',
      'sso', 'oauth', 'passkey', 'brute force', 'kaba kuvvet', 'erişim kontrol', 'access control'],
  },
  {
    slug: 'ag-guvenligi',
    label: { tr: 'Ağ Güvenliği', de: 'Netzwerksicherheit', en: 'Network Security' },
    keywords: ['ağ güvenlik', 'network security', 'netzwerk', 'firewall', 'güvenlik duvar', 'ddos', 'vpn',
      'port tara', 'port scan', 'ids', 'ips', 'tls', 'ssl', 'sertifika', 'certificate', 'zertifikat', 'dns',
      'man-in-the-middle', 'ortadaki adam'],
  },
  {
    slug: 'fidye-zararli',
    label: { tr: 'Fidye & Zararlı Yazılım', de: 'Ransomware & Malware', en: 'Ransomware & Malware' },
    keywords: ['ransomware', 'fidye', 'malware', 'zararlı yazılım', 'schadsoftware', 'virüs', 'virus', 'trojan',
      'truva', 'worm', 'solucan', 'spyware', 'casus yazılım', 'rootkit', 'botnet', 'şifreleme saldır', 'wiper'],
  },
  {
    slug: 'bulut-guvenligi',
    label: { tr: 'Bulut Güvenliği', de: 'Cloud-Sicherheit', en: 'Cloud Security' },
    keywords: ['bulut güvenlik', 'cloud security', 'cloud', 'bulut', 'aws', 'azure', 'gcp', 'kubernetes', 'k8s',
      'konteyner', 'container', 'docker', 's3', 'iam', 'serverless', 'sunucusuz'],
  },
  {
    slug: 'kvkk-uyum',
    label: { tr: 'KVKK & Uyumluluk', de: 'DSGVO & Compliance', en: 'GDPR & Compliance' },
    keywords: ['kvkk', 'gdpr', 'dsgvo', 'uyumluluk', 'compliance', 'iso 27001', 'iso27001', 'denetim', 'audit',
      'mevzuat', 'regulation', 'veri koruma', 'data protection', 'datenschutz', 'pci dss', 'pci-dss', 'nis2',
      'kişisel veri', 'personal data', 'personenbezogene'],
  },
  {
    slug: 'veri-sizintisi',
    label: { tr: 'Veri Sızıntısı', de: 'Datenleck', en: 'Data Breach' },
    keywords: ['veri ihlal', 'veri sızıntı', 'data breach', 'datenleck', 'datenpanne', 'leak', 'sızdırıl',
      'exposed data', 'açığa çıkan veri', 'credential leak', 'kimlik bilgisi sızıntı', 'dark web', 'karanlık web'],
  },
  {
    slug: 'genel',
    label: { tr: 'Genel', de: 'Allgemein', en: 'General' },
    keywords: [], // fallback — hiçbir kategori eşleşmezse
  },
];

export const CATEGORY_SLUGS = BLOG_CATEGORIES.map((c) => c.slug);

export function isValidCategory(slug: unknown): slug is string {
  return typeof slug === 'string' && CATEGORY_SLUGS.includes(slug);
}

export function categoryLabel(slug: string, lang = 'tr'): string {
  const c = BLOG_CATEGORIES.find((x) => x.slug === slug);
  if (!c) return slug;
  return c.label[(lang as 'tr' | 'de' | 'en')] ?? c.label.tr;
}

/**
 * İçerikten DETERMİNİSTİK kategori tahmini (LLM yok). Başlık ağırlık 3, içerik ağırlık 1.
 * En yüksek skorlu kategori; skor 0 ise 'genel'.
 */
export function guessCategory(title: string, content: string): string {
  const t = lc(title);
  const b = lc(content).slice(0, 8000); // ilk ~8KB yeter (performans)
  let best = 'genel';
  let bestScore = 0;
  for (const cat of BLOG_CATEGORIES) {
    if (cat.slug === 'genel') continue;
    let score = 0;
    for (const kw of cat.keywords) {
      const k = lc(kw);
      if (t.includes(k)) score += 3;
      if (b.includes(k)) score += 1;
    }
    if (score > bestScore) { bestScore = score; best = cat.slug; }
  }
  return best;
}
