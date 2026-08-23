/**
 * (Tam Kapsamlı Pentest — Faz 4 / Bölüm 2) DİNAMİK FİYATLANDIRMA — pasif kompleksite skoru → fiyat ÖNERİSİ.
 * YALNIZ 6. pakete (Tam Kapsamlı) özel. Diğer 5 paketin SABİT fiyatı bu modülden ETKİLENMEZ.
 *
 * İlkeler:
 *  - Skor yalnız PASİF sinyallerden (mevcut pasif recon/corpus verisi) — EKSTRA aktif tarama/saldırı YOK.
 *  - Deterministik: aynı sinyaller → aynı skor → aynı kademe (rastgelelik yok).
 *  - Şeffaf: her sinyalin kaç puan kattığı `breakdown` ile görünür (kara-kutu değil).
 *  - Eşikler ve TL rakamları PLACEHOLDER: hepsi `PRICING_CFG`'de tek yerde; Vedat onaylayıp ayarlar.
 *    Koda gömülü sabit fiyat YOK. Fiyat bir "öneri"dir, garanti değil.
 */

export type PassivePricingSignals = {
  uniqueEndpoints: number;   // keşfedilen benzersiz iç sayfa/uç sayısı (pasif)
  realApiEndpoints: number;  // gerçek (mined) API uç adedi
  authSurface: boolean;      // login/parola yüzeyi var mı
  subdomains: number;        // gözlemlenen alt-alan adedi
  techDiversity: number;     // farklı teknoloji/harici-host/kütüphane çeşitliliği
};

// ————————————————————— PLACEHOLDER KONFİG (Vedat ayarlar) —————————————————————
// weights: her sinyalin birim puanı. caps: bir sinyalin katabileceği MAKS puan (tek sinyal domine etmesin).
// tiers.maxScore: kademe üst eşiği (dahil). priceMinTL/priceMaxTL: null = Vedat girecek (placeholder).
export const PRICING_CFG = {
  currency: 'TL',
  weights: { uniqueEndpoints: 1, realApiEndpoints: 4, authSurface: 20, subdomains: 3, techDiversity: 2 },
  caps: { uniqueEndpoints: 30, realApiEndpoints: 40, authSurface: 20, subdomains: 24, techDiversity: 20 },
  // Kademeler artan sırada; skor <= maxScore olan İLK kademe seçilir (sonuncu = üst-sınır).
  tiers: [
    { key: 'kucuk', label: 'Küçük', maxScore: 30, priceMinTL: null as number | null, priceMaxTL: null as number | null },
    { key: 'orta', label: 'Orta', maxScore: 70, priceMinTL: null as number | null, priceMaxTL: null as number | null },
    { key: 'buyuk', label: 'Büyük', maxScore: 110, priceMinTL: null as number | null, priceMaxTL: null as number | null },
    { key: 'kurumsal', label: 'Kurumsal', maxScore: Number.POSITIVE_INFINITY, priceMinTL: null as number | null, priceMaxTL: null as number | null },
  ],
  note: 'Fiyatlar ÖNERİDİR (garanti değil). Eşikler ve TL rakamları placeholder — Vedat onaylayıp ayarlayacak. Yalnız 6. pakete özeldir; diğer 5 paketin sabit fiyatı değişmez.',
};

export type PricingBreakdownRow = { signal: keyof PassivePricingSignals; value: number; points: number; capped: boolean };
export type PricingSuggestion = {
  score: number;
  breakdown: PricingBreakdownRow[];
  tier: { key: string; label: string };
  priceRange: { minTL: number | null; maxTL: number | null; placeholder: boolean };
  note: string;
};

/** Saf/deterministik: sinyaller → skor + kademe + fiyat aralığı (öneri). */
export function suggestPricingFromSignals(sig: PassivePricingSignals, cfg = PRICING_CFG): PricingSuggestion {
  const w = cfg.weights, cap = cfg.caps;
  const raw: Array<{ signal: keyof PassivePricingSignals; value: number; uncapped: number; capMax: number }> = [
    { signal: 'uniqueEndpoints', value: sig.uniqueEndpoints, uncapped: sig.uniqueEndpoints * w.uniqueEndpoints, capMax: cap.uniqueEndpoints },
    { signal: 'realApiEndpoints', value: sig.realApiEndpoints, uncapped: sig.realApiEndpoints * w.realApiEndpoints, capMax: cap.realApiEndpoints },
    { signal: 'authSurface', value: sig.authSurface ? 1 : 0, uncapped: (sig.authSurface ? 1 : 0) * w.authSurface, capMax: cap.authSurface },
    { signal: 'subdomains', value: sig.subdomains, uncapped: sig.subdomains * w.subdomains, capMax: cap.subdomains },
    { signal: 'techDiversity', value: sig.techDiversity, uncapped: sig.techDiversity * w.techDiversity, capMax: cap.techDiversity },
  ];
  const breakdown: PricingBreakdownRow[] = raw.map((r) => {
    const points = Math.min(r.uncapped, r.capMax);
    return { signal: r.signal, value: r.value, points, capped: r.uncapped > r.capMax };
  });
  const score = breakdown.reduce((a, b) => a + b.points, 0);
  const tier = cfg.tiers.find((t) => score <= t.maxScore) ?? cfg.tiers[cfg.tiers.length - 1];
  return {
    score,
    breakdown,
    tier: { key: tier.key, label: tier.label },
    priceRange: { minTL: tier.priceMinTL, maxTL: tier.priceMaxTL, placeholder: tier.priceMinTL === null || tier.priceMaxTL === null },
    note: cfg.note,
  };
}

// ————————————————————— PASİF SİNYAL TÜRETME (mevcut corpus'tan; ekstra tarama YOK) —————————————————————
import { fetchClientCorpus } from './jsAnalysis.js';
import { mineApiPaths } from './apiSecurityChecks.js';
import { getOrgDomain } from './emailDnsChecks.js';

const INTERNAL_PATH_RE = /["'`](\/[a-z0-9][\w/.-]{0,80})["'`]/gi;
const AUTH_HINT_RE = /type=["']password["']|name=["']?(password|passwd|pwd)|\/login\b|\/signin\b|\/auth\b|oturum a[çc]|giri[şs] yap/i;

/** Hedefin PASİF corpus'undan (cache'li, ekstra istek yok) fiyatlandırma sinyalleri türetir. */
export async function derivePricingSignals(host: string): Promise<PassivePricingSignals> {
  const corpus = await fetchClientCorpus(host);
  if (!corpus.reachable) return { uniqueEndpoints: 0, realApiEndpoints: 0, authSurface: false, subdomains: 0, techDiversity: 0 };
  const text = corpus.homeHtml + '\n' + corpus.sameOriginJs.map((f) => f.body).join('\n') + '\n' + corpus.inlineScripts.join('\n');

  // Benzersiz iç uç/sayfa (asset uzantıları elenir)
  const paths = new Set<string>();
  for (const m of text.matchAll(INTERNAL_PATH_RE)) {
    const p = m[1].split(/[?#]/)[0];
    if (/\.(js|css|png|jpe?g|svg|gif|webp|ico|woff2?|map|json|mp4|pdf)$/i.test(p)) continue;
    if (p.length > 80) continue;
    paths.add(p);
  }
  const realApiEndpoints = mineApiPaths(text).length;
  const authSurface = AUTH_HINT_RE.test(text);

  // Alt-alanlar: corpus'ta geçen mutlak URL'lerden org-alanın alt-alanları (deterministik, DNS taraması yok)
  const org = getOrgDomain(host);
  const subs = new Set<string>();
  for (const m of text.matchAll(/https?:\/\/([a-z0-9.-]+\.[a-z]{2,})/gi)) {
    const h = m[1].toLowerCase();
    if (h === org || h === `www.${org}`) continue;
    if (h.endsWith(`.${org}`)) subs.add(h);
  }

  // Teknoloji çeşitliliği: farklı harici script host + tespit edilen kütüphane sayısı (kaba, pasif)
  const extHosts = new Set<string>();
  for (const s of corpus.externalScripts) { try { extHosts.add(new URL(s).hostname.toLowerCase()); } catch { /* yoksay */ } }

  return {
    uniqueEndpoints: paths.size,
    realApiEndpoints,
    authSurface,
    subdomains: subs.size,
    techDiversity: extHosts.size,
  };
}

/** Uçtan uca: hedef → pasif sinyaller → fiyat önerisi (6. paket için). */
export async function suggestPricingForHost(host: string): Promise<{ signals: PassivePricingSignals; suggestion: PricingSuggestion }> {
  const signals = await derivePricingSignals(host);
  return { signals, suggestion: suggestPricingFromSignals(signals) };
}

// ════════════════════ (P0-A) OTONOM AI RED TEAM — S1 KARMAŞIKLIK-BAZLI FİYAT ════════════════════
// S1 MÜHENDİSLİK CAP'İNE (900s/$2.50/30 çağrı) DOKUNMAZ — yalnız MÜŞTERİDEN alınan fiyat, hedefin
// ölçülen pasif karmaşıklığına göre üç KESİN kademede esner (öneri bandı değil, net fiyat). Üst sınır
// 2.500 ₺ hiçbir koşulda aşılmaz. Pasif sinyaller yukarıdaki derivePricingSignals'tan gelir (cache'li
// corpus; PentAGI/droplet ÇALIŞMAZ — ödeme öncesi ucuz ön-kontrol). Deterministik + şeffaf (reason).
export const S1_PRICING = {
  currency: 'TL',
  capTL: 2500,
  tiers: [
    { key: 'basit', label: 'Basit', priceTL: 750, desc: 'Tek/az sayfa, az uç-nokta, login yüzeyi yok' },
    { key: 'orta', label: 'Orta', priceTL: 1500, desc: 'Birden fazla form/uç-nokta veya login sayfası mevcut' },
    { key: 'karmasik', label: 'Karmaşık', priceTL: 2500, desc: 'Çok sayıda uç-nokta / çoklu modül / e-ticaret ölçeği' },
  ],
};

export type S1PriceResult = {
  tier: { key: string; label: string; desc: string };
  priceTL: number;
  currency: string;
  reason: string;                 // neden bu kademe (şeffaf — kara-kutu değil)
  signals: PassivePricingSignals; // ön-kontrol ham sinyalleri (divergence loglama için saklanır)
  estEndpoints: number;           // ön-kontrolün gördüğü uç-nokta tahmini (gerçek koşuyla karşılaştırma için)
};

/** Saf/deterministik: pasif sinyaller → S1 kademe + NET fiyat (cap 2500). Eşikler koda gömülü ama şeffaf. */
export function s1PriceFromSignals(sig: PassivePricingSignals): S1PriceResult {
  const endpoints = sig.uniqueEndpoints + sig.realApiEndpoints;   // toplam keşfedilen uç yüzeyi
  const auth = sig.authSurface;                                   // login/parola yüzeyi
  const rich = sig.subdomains + sig.techDiversity;               // çoklu modül / e-ticaret sinyali
  let key: 'basit' | 'orta' | 'karmasik';
  let reason: string;
  if (endpoints >= 25 || rich >= 12 || (auth && endpoints >= 12)) {
    key = 'karmasik';
    reason = `${endpoints} uç-nokta${auth ? ' + login' : ''}${rich >= 12 ? ' + çoklu modül/teknoloji' : ''} → yüksek kapsam`;
  } else if (endpoints >= 6 || auth) {
    key = 'orta';
    reason = `${endpoints} uç-nokta${auth ? ' + login sayfası' : ''} → orta kapsam`;
  } else {
    key = 'basit';
    reason = `${endpoints} uç-nokta, login yüzeyi yok → düşük kapsam`;
  }
  const tier = S1_PRICING.tiers.find((t) => t.key === key)!;
  return {
    tier: { key: tier.key, label: tier.label, desc: tier.desc },
    priceTL: Math.min(tier.priceTL, S1_PRICING.capTL),           // (P0-A/5) tavan hiçbir koşulda aşılmaz
    currency: S1_PRICING.currency,
    reason,
    signals: sig,
    estEndpoints: endpoints,
  };
}

/** Uçtan uca: hedef → ucuz pasif ön-kontrol → S1 net fiyat (ödeme ekranı ÖNCESİ). */
export async function s1PriceForHost(host: string): Promise<S1PriceResult> {
  const signals = await derivePricingSignals(host);
  return s1PriceFromSignals(signals);
}
