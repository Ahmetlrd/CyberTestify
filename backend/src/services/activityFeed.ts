import { redactAll } from './piiRedaction.js';

/**
 * Ham PentAGI tool-call loglarını, teknik olmayan müşteriye gösterilebilecek
 * DOSTANE, genel kategorili kısa cümlelere indirger. Ham komut/çıktı ASLA
 * gösterilmez (anlaşılmaz + PII sızma riski + tekniği ifşa etmenin faydası yok).
 *
 * KRİTİK: Buradan çıkan HER metin, ekrana gitmeden önce redactAll'dan geçer —
 * aynen rapor üretiminde olduğu gibi (defense-in-depth; kategori cümleleri sabit
 * olsa da kural istisnasız uygulanır).
 */

const CATEGORY: Array<{ match: RegExp; text: string }> = [
  { match: /tls|ssl|cert|https/i, text: 'TLS/sertifika yapılandırması inceleniyor' },
  { match: /header|csp|hsts/i, text: 'HTTP güvenlik başlıkları kontrol ediliyor' },
  { match: /dns|spf|dkim|dmarc|mx/i, text: 'DNS ve e-posta güvenliği değerlendiriliyor' },
  { match: /cve|vuln|exploit|nuclei/i, text: 'Bilinen güvenlik açıkları kontrol ediliyor' },
  { match: /cookie|session|auth/i, text: 'Çerez ve oturum güvenliği inceleniyor' },
  { match: /form|input|xss|sqli|inject/i, text: 'Form girdileri ve girdi doğrulama test ediliyor' },
  { match: /whatweb|wappalyzer|fingerprint|cms|wordpress|joomla/i, text: 'Sunucu ve teknoloji parmak izi çıkarılıyor' },
  { match: /report|summary|\bwrite\b|finding/i, text: 'Bulgular derleniyor ve rapor hazırlanıyor' },
  { match: /nmap|masscan|\bports?\b/i, text: 'Ağ/port erişilebilirliği kontrol ediliyor' },
  { match: /curl|wget|http|fetch|browser|page|crawl|robots/i, text: 'Web sunucusu yapılandırması inceleniyor' },
  { match: /terminal|bash|shell|exec|run|command/i, text: 'Tarama adımı yürütülüyor' },
];

const FALLBACK = 'Güvenlik kontrolü yürütülüyor';

export interface ActivityItem {
  seq: number;
  text: string;
}

function friendly(name: string): string {
  return CATEGORY.find((c) => c.match.test(name ?? ''))?.text ?? FALLBACK;
}

/**
 * toolCallLogs -> dostane, redakte, ardışık-tekrarı bastırılmış aktivite akışı
 * (en fazla `max` satır; en yenileri).
 */
export function buildActivityFeed(
  toolCalls: Array<{ name: string | null }>,
  max = 12,
): ActivityItem[] {
  const items: ActivityItem[] = [];
  let last = '';
  let seq = 0;
  for (const tc of toolCalls) {
    // Kategori cümlesi sabit olsa da kural gereği redactAll'dan geçir.
    const text = redactAll(friendly(tc.name ?? ''));
    if (text === last) continue; // ardışık aynı kategoriyi tekrar etme
    last = text;
    items.push({ seq: seq++, text });
  }
  return items.slice(-max);
}
