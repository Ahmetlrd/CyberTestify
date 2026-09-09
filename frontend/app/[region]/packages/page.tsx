import Link from 'next/link';
import { notFound } from 'next/navigation';
import { VISIBLE_REGION_CODES, isRegionCode, getRegion } from '../../../config/regions';
import { getDict, formatMoney } from '../../../config/i18n';
import { JsonLd } from '../../../components/JsonLd';
import { renderEmphasis, stripEmphasis } from '../../../lib/richText';
import { PackageCompare, type CompareCol } from '../../../components/packages/PackageCompare';
import { PackageFocus } from '../../../components/packages/PackageFocus';

type Pkg = { key: string; displayName: string; description: string; priceMinorUnit: number; currency?: string; comingSoon?: boolean; bundleOnly?: boolean; bundleName?: string | null };
type Bundle = {
  key: string; displayName: string; description: string; discountPct: number;
  members: Array<{ key: string; displayName: string }>;
  selectable: boolean; selectableModules: Array<{ key: string; displayName: string }> | null; category?: string;
  originalMinorUnit: number; amountMinorUnit: number; currency: string; comingSoon?: boolean; popular?: boolean; flagship?: boolean; contactOnly?: boolean;
};

const API = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000';

export function generateStaticParams() {
  return VISIBLE_REGION_CODES.map((region) => ({ region }));
}

export function generateMetadata({ params }: { params: { region: string } }) {
  const region = getRegion(params.region);
  const d = getDict(region).pkg;
  const SITE = 'https://cybertestify.com';
  const url = `${SITE}/${region.code}/packages`;
  return {
    title: d.metaTitle,
    description: d.metaDesc,
    alternates: {
      canonical: url,
      languages: { tr: `${SITE}/tr/packages`, de: `${SITE}/de/packages`, en: `${SITE}/en/packages`, 'x-default': `${SITE}/tr/packages` },
    },
    openGraph: { type: 'website', siteName: 'CyberTestify', url, title: d.metaTitle, description: d.metaDesc, locale: region.lang === 'tr' ? 'tr_TR' : region.lang === 'de' ? 'de_DE' : 'en_US' },
    twitter: { card: 'summary_large_image', title: d.metaTitle, description: d.metaDesc },
  };
}

async function getPackages(region: string): Promise<Pkg[]> {
  try {
    const r = await fetch(`${API}/orders/packages?region=${region}`, { cache: 'no-store' });
    if (!r.ok) return [];
    return (await r.json()) as Pkg[];
  } catch {
    return [];
  }
}

async function getBundles(region: string): Promise<Bundle[]> {
  try {
    const r = await fetch(`${API}/orders/bundles?region=${region}`, { cache: 'no-store' });
    if (!r.ok) return [];
    return (await r.json()) as Bundle[];
  } catch {
    return [];
  }
}

// Aktif basit_tarama promo kodu (varsa) — Basit Tarama kartında kampanya olarak gösterilir.
export default async function PackagesPage({ params }: { params: { region: string } }) {
  if (!isRegionCode(params.region)) notFound();
  const region = getRegion(params.region);
  const d = getDict(region).pkg;
  const packages = await getPackages(region.code);
  const bundles = await getBundles(region.code);
  // SATIS MODELI: tekil satis KAPALI — SADECE basit_tarama tekil ("6. paket") satilir; digerleri
  // yalniz bundle icinde. basit_tarama'yi accordion'dan AYIR, bundle'larin yanina belirgin kart yap.
  // SATIS MODELI: SADECE paketler. basit_tarama giris-seviyesi bir PAKET olarak grid'in
  // BASINDA gosterilir (ayriksi "6. paket" degil). Diger tekil paketler UI'da GORUNMEZ;
  // yalnizca ornek raporlari (PDF) sunulur.
  const tr = region.code === 'tr';
  // (Çok-bölge) 3-yönlü metin seçimi: tr → Türkçe, de → Almanca, diğer (us/ae) → İngilizce.
  // Böylece /de'de İngilizce yerine Almanca gösterilir; /tr metni HİÇ değişmez.
  const t3 = (trText: string, deText: string, enText: string) => (region.lang === 'de' ? deText : tr ? trText : enText);
  const basit = packages.find((p) => p.key === 'basit_tarama');
  // Ornek rapor: PAKET/BUNDLE bazinda TEK PDF (tek tek kontrol DEGIL). basit + aktif bundle'lar.
  const sampleItems: Array<{ key: string; displayName: string }> = [];
  if (basit) sampleItems.push({ key: basit.key, displayName: basit.displayName });
  for (const b of bundles) if (!b.comingSoon) sampleItems.push({ key: b.key, displayName: b.displayName });

  // ===== (KARŞILAŞTIRMA) Paketleri BİRBİRİYLE kıyaslayan tablo + sihirbaz verisi =====
  // TÜM değerler GERÇEK tanımlardan: fiyat (API), üye kontrol sayısı, kategori, örnek rapor varlığı
  // (sampleItems ile AYNI kural). Rakip ürün/şirket adı GEÇMEZ — yalnız kendi paketlerimiz kıyaslanır.
  // Süre satırı BİLEREK YOK: paket tanımlarında paket-bazlı süre verisi bulunmuyor, uydurulmaz.
  const kindLabel = (cat?: string) =>
    cat === 'active-light' ? t3('Aktif-hafif doğrulama', 'Aktiv-leichte Verifikation', 'Active-light verification')
      : cat === 'compliance' ? t3('Uyum ön-değerlendirmesi', 'Compliance-Vorabbewertung', 'Compliance pre-assessment')
        : t3('Pasif gözlem', 'Passive Beobachtung', 'Passive observation');
  // Kısa kapsam + "kime uygun": gerçek paket açıklamalarından YOĞUNLAŞTIRILDI (yeni iddia eklenmedi).
  const META: Record<string, { scope: string; fit: string }> = {
    basit_tarama: {
      scope: t3('HTTP güvenlik başlıkları, SSL/TLS, sunucu & teknoloji ifşası', 'HTTP-Sicherheits-Header, SSL/TLS, Server- & Technologie-Offenlegung', 'HTTP security headers, SSL/TLS, server & technology exposure'),
      fit: t3('İlk kez tarama yaptıracaklar', 'Für den ersten Scan', 'First-time scans'),
    },
    bundle_surface: {
      scope: t3('SSL/TLS, güvenlik başlıkları, DNS/e-posta, CORS, CSP', 'SSL/TLS, Sicherheits-Header, DNS/E-Mail, CORS, CSP', 'SSL/TLS, security headers, DNS/email, CORS, CSP'),
      fit: t3('Dış yüzey yapılandırmasını toplu görmek isteyenler', 'Wer die externe Konfiguration gesamthaft sehen will', 'Teams wanting the full external configuration picture'),
    },
    bundle_recon: {
      scope: t3('Alt alan adı devralma, API keşfi, CMS/bilinen CVE', 'Subdomain-Übernahme, API-Discovery, CMS/bekannte CVE', 'Subdomain takeover, API discovery, CMS/known CVE'),
      fit: t3('Saldırı yüzeyini haritalamak isteyenler', 'Wer die Angriffsfläche kartieren will', 'Teams mapping their attack surface'),
    },
    bundle_compliance: {
      scope: t3('KVKK, PCI-DSS ve ISO 27001 ön-uyum kontrolleri', 'PCI-DSS- und ISO-27001-Bereitschaftsprüfungen', 'PCI-DSS and ISO 27001 readiness checks'),
      fit: t3('Denetim öncesi hazırlık yapanlar', 'Vorbereitung vor dem Audit', 'Preparing ahead of an audit'),
    },
    bundle_active_verify: {
      scope: t3('Enjeksiyon, IDOR, SSRF, dosya yükleme, iş mantığı, race, RCE (login’siz yüzey)', 'Injektion, IDOR, SSRF, Datei-Upload, Geschäftslogik, Race, RCE (ohne Login)', 'Injection, IDOR, SSRF, file upload, business logic, race, RCE (no-login surface)'),
      fit: t3('Zafiyetin gerçekten var olduğunu kanıtlatmak isteyenler', 'Wer den Nachweis einer Schwachstelle braucht', 'Teams needing proof a weakness is real'),
    },
    bundle_full_pentest: {
      scope: t3('Test hesabıyla login sonrası derin tarama + API (OWASP API Top 10)', 'Tiefer Scan nach Login mit Testkonto + API (OWASP API Top 10)', 'Deep post-login scan with a test account + API (OWASP API Top 10)'),
      fit: t3('Kapsamlı kurumsal denetim isteyenler', 'Wer eine umfassende Unternehmensprüfung will', 'Teams wanting a comprehensive assessment'),
    },
  };
  const badgeOf = (b: Bundle) =>
    // (METIN) "Amiral gemisi" alakasiz duruyordu — kartin rozetiyle AYNI ifade kullanilir.
    b.flagship ? t3('En Kapsamlı Paket', 'Umfangreichstes Paket', 'Most Complete') : b.popular ? t3('Popüler', 'Beliebt', 'Popular') : undefined;

  const compareCols: CompareCol[] = [];
  if (basit && !basit.comingSoon) {
    compareCols.push({
      key: basit.key, name: basit.displayName,
      price: t3('Ücretsiz', 'Kostenlos', 'Free'),
      kind: kindLabel('passive'),
      checks: t3('Giriş seviyesi', 'Einstiegsniveau', 'Entry level'),
      scope: META.basit_tarama.scope, sample: true, dnsRequired: false, experimental: false,
      fit: META.basit_tarama.fit, href: `/${region.code}#hemen-dene`,
    });
  }
  for (const b of bundles) {
    if (b.comingSoon || b.contactOnly) continue;
    const m = META[b.key];
    compareCols.push({
      key: b.key, name: b.displayName,
      price: formatMoney(b.amountMinorUnit, region),
      kind: kindLabel(b.category),
      checks: t3(`${b.members.length} kontrol`, `${b.members.length} Prüfungen`, `${b.members.length} checks`),
      scope: m?.scope ?? stripEmphasis(b.description).slice(0, 90),
      sample: true,
      // (GERÇEK KURAL) Aktif-hafif paketlerde DNS sahiplik doğrulaması ZORUNLU; pasif/uyumda değil.
      dnsRequired: b.category === 'active-light',
      experimental: false,
      fit: m?.fit ?? '',
      href: `/order?bundle=${b.key}`,
      badge: badgeOf(b),
    });
  }
  // (Otonom AI Red Team) YALNIZ /tr — sayfası /de ve /en'de 404 döndüğü için o bölgelerde sütun da yok.
  // Değerler gerçek ürün tanımından: S1 fiyat aralığı ve tekniği (i18n otonom bölümüyle aynı).
  const redTeamKey = tr ? 'redteam_s1' : null;
  if (redTeamKey) {
    compareCols.push({
      key: redTeamKey,
      name: 'Otonom AI Red Team · S1',
      price: 'Karmaşıklığa göre ₺750–2.500',
      kind: 'Otonom (deneysel)',
      checks: 'S1 · Pasif + hafif aktif göstergeler',
      scope: 'Otonom AI ajanı hedefi güvenli sınırlar içinde sınar; bulgular ham kanıta bağlanır.',
      sample: false, dnsRequired: true, experimental: true,
      fit: 'Deneysel otonom tekniği kabul edenler',
      href: `/${region.code}/otonom-red-team`,
      badge: 'Deneysel',
    });
  }

  // (JSON-LD) Hizmetler — Service ItemList. Fiyat "baslangic" olarak esnek ifade edilir
  // (Offer priceSpecification.minPrice + "baslangic fiyati" aciklamasi; kesin taahhut degil).
  const SITE = 'https://cybertestify.com';
  const svc = (name: string, description: string, minMinor: number) => ({
    '@type': 'Service',
    name,
    serviceType: t3('Web güvenliği ön-değerlendirme', 'Web-Sicherheits-Vorabbewertung', 'Web security pre-assessment'),
    description,
    provider: { '@type': 'Organization', name: 'CyberTestify', url: SITE },
    areaServed: region.code === 'de' ? 'DE' : region.code === 'en' ? 'GB' : 'TR',
    offers: {
      '@type': 'Offer',
      priceCurrency: region.currency,
      priceSpecification: { '@type': 'PriceSpecification', minPrice: (minMinor / 100).toFixed(2), priceCurrency: region.currency, description: t3('Başlangıç fiyatı', 'Ab-Preis', 'Starting price') },
      url: `${SITE}/${region.code}/packages`,
    },
  });
  const serviceItems = [
    ...(basit && !basit.comingSoon ? [svc(basit.displayName, stripEmphasis(basit.description), 0)] : []),
    ...bundles.filter((b: any) => !b.comingSoon).map((b: any) => svc(b.displayName, stripEmphasis(b.description), b.amountMinorUnit)),
  ];
  const servicesLd = {
    '@context': 'https://schema.org',
    '@type': 'ItemList',
    itemListElement: serviceItems.map((item, i) => ({ '@type': 'ListItem', position: i + 1, item })),
  };

  return (
    <>
      {serviceItems.length > 0 && <JsonLd data={servicesLd} />}
      <section className="relative overflow-hidden bg-gradient-to-b from-brand-deep to-brand pt-16 pb-32 text-white sm:pt-20 sm:pb-40">
        <div aria-hidden className="pointer-events-none absolute left-1/2 top-[-200px] h-[520px] w-[820px] -translate-x-1/2 rounded-full bg-[radial-gradient(circle,rgba(245,166,35,0.2),transparent_65%)]" />
        <div className="container-page relative text-center">
          <p className="font-mono text-[11px] font-semibold uppercase tracking-[0.16em] text-accent">{d.eyebrow}</p>
          <h1 className="mx-auto mt-3.5 max-w-3xl text-[34px] font-extrabold leading-[1.08] tracking-[-0.02em] sm:text-[46px]">{d.title}</h1>
          <p className="mx-auto mt-3 max-w-[480px] text-base leading-relaxed text-white/70">{d.subtitle}</p>
          <div className="mt-7 flex flex-wrap items-center justify-center gap-2">
            {d.trust.map((t) => (
              <span key={t} className="inline-flex items-center gap-2 rounded-full border border-white/[0.18] bg-white/[0.06] px-3.5 py-1.5 text-[12.5px] font-semibold text-white/85">
                <span className="h-1.5 w-1.5 rounded-full bg-accent" />{t}
              </span>
            ))}
          </div>
        </div>
      </section>

      <section className="container-page pb-16 pt-0">
        {bundles.length > 0 && (
          <div className="relative z-[1] -mt-24 mb-14 sm:-mt-28">
            <PackageFocus />
            <div className="grid items-start gap-6 md:grid-cols-2 lg:grid-cols-3">
              {/* Basit Tarama — giris seviyesi PAKET (grid'in ilk karti; ayriksi degil). */}
              {basit && !basit.comingSoon && (
                <div id="pkg-basit_tarama" className="card relative flex flex-col border-2 border-line p-6 scroll-mt-24 transition-transform hover:-translate-y-1">
                  <span className="mb-3 inline-flex w-fit rounded-pill bg-ink-soft px-3 py-1 text-xs font-bold text-white">
                    {t3('Giriş', 'Einstieg', 'Entry')}
                  </span>
                  <h3 className="text-lg font-bold text-brand">{basit.displayName}</h3>
                  <p className="mt-2 text-sm leading-relaxed text-ink-soft">
                    {t3(
                      'Web sitenizin dış güvenlik duruşunu hızlıca ölçmek ve temel riskleri kapatmak için ideal başlangıç paketi.',
                      'Das ideale Einstiegspaket, um die externe Sicherheitslage Ihrer Website schnell einzuschätzen und grundlegende Risiken zu schließen.',
                      'The ideal starter package to quickly gauge your site’s external security posture and close basic risks.')}
                  </p>
                  <div className="mt-3 rounded-card bg-brand-50/50 px-3 py-2 text-xs text-ink-soft">
                    <span className="font-semibold">{t3('Kapsam', 'Umfang', 'Scope')}:</span>{' '}
                    {t3(
                      'HTTP güvenlik başlıkları · SSL/TLS yapılandırması · Sunucu & teknoloji ifşası · Temel yapılandırma dosyaları (robots.txt, assetlinks) · Platforma özel hazır düzeltme kodları (Nginx, IIS, Vercel vb.).',
                      'HTTP-Sicherheitsheader · SSL/TLS-Konfiguration · Server- & Technologie-Preisgabe · Grundlegende Konfigurationsdateien (robots.txt, assetlinks) · Plattform-spezifische, einsatzbereite Fix-Snippets (Nginx, IIS, Vercel usw.).',
                      'HTTP security headers · SSL/TLS configuration · Server & tech disclosure · Basic config files (robots.txt, assetlinks) · Platform-specific ready-to-use fix snippets (Nginx, IIS, Vercel, etc.).')}
                  </div>
                  <div className="mt-4">
                    <div>
                      <span className="text-3xl font-extrabold text-accent-600">{t3('Ücretsiz', 'Kostenlos', 'Free')}</span>
                      <span className="ml-1 text-xs text-ink-muted">{t3('anlık ön-tarama', 'Sofort-Vorabscan', 'instant pre-scan')}</span>
                    </div>
                    <div className="mt-1.5 text-[11px] text-ink-soft">
                      {t3(
                        'Dış yüzey ön-değerlendirmesidir; aktif sızma testi veya derinlemesine kod denetimi içermez.',
                        'Eine Vorabbewertung der externen Oberfläche; kein aktiver Penetrationstest und keine tiefe Code-Prüfung.',
                        'An external-surface pre-assessment; no active penetration test or in-depth code audit.')}
                    </div>
                  </div>
                  <Link href={`/${region.code}#hemen-dene`} className="btn-dark mt-6 w-full">
                    {t3('Hemen Dene', 'Jetzt testen', 'Try Now')}
                  </Link>
                  <a
                    href={`${API}/orders/sample-report/${basit.key}?v=lansman1&region=${region.code}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="mt-3 flex w-full items-center justify-center gap-1.5 rounded-pill border border-line px-4 py-2.5 text-sm font-semibold text-ink-soft transition hover:border-brand hover:text-brand"
                  >
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden>
                      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                      <path d="M14 2v6h6" />
                    </svg>
                    {t3('Örnek raporu gör', 'Musterbericht ansehen', 'View sample report')}
                  </a>
                </div>
              )}
              {bundles.map((b) => {
                const savedMinor = b.originalMinorUnit - b.amountMinorUnit;
                const hasSaving = savedMinor > 0; // recon gibi nihai > tekil-toplam ise indirim GOSTERILMEZ
                const savedPct = hasSaving && b.originalMinorUnit > 0 ? Math.round((savedMinor / b.originalMinorUnit) * 100) : 0;
                const popular = !!b.popular && !b.comingSoon;
                const flagship = !!b.flagship && !b.comingSoon;
                const premium = popular || flagship;
                return (
                  <div
                    key={b.key}
                    id={`pkg-${b.key}`}
                    className={`card relative flex flex-col p-6 scroll-mt-24 transition-transform hover:-translate-y-1 ${
                      flagship ? 'border-2 border-brand shadow-lg ring-2 ring-brand/30 bg-brand-50/40'
                        : popular ? 'border-2 border-accent shadow-md ring-2 ring-accent/25 bg-amber-50/40'
                        : 'border-2 border-accent/40'
                    } ${b.comingSoon ? 'opacity-90' : ''}`}
                  >
                    {b.comingSoon ? (
                      <span className="mb-3 inline-flex w-fit rounded-pill bg-brand px-3 py-1 text-xs font-bold text-white">
                        {t3('Yakında', 'Bald', 'Soon')}
                      </span>
                    ) : flagship ? (
                      <span className="mb-3 flex flex-wrap items-center gap-1.5">
                        <span className="whitespace-nowrap rounded-pill bg-brand px-3 py-1 text-xs font-bold text-white">
                          ★ {t3('En Kapsamlı Paket', 'Umfangreichstes Paket', 'Most Complete')}
                        </span>
                        {hasSaving && (
                          <span className="whitespace-nowrap rounded-pill bg-accent px-2.5 py-1 text-xs font-bold text-white">
                            %{savedPct} {t3('avantaj', 'Rabatt', 'off')}
                          </span>
                        )}
                      </span>
                    ) : popular ? (
                      <span className="mb-3 flex flex-wrap items-center gap-1.5">
                        <span className="whitespace-nowrap rounded-pill bg-accent px-3 py-1 text-xs font-bold text-white">
                          ★ {t3('Popüler', 'Beliebt', 'Popular')}
                        </span>
                        {hasSaving && (
                          <span className="whitespace-nowrap rounded-pill bg-brand px-2.5 py-1 text-xs font-bold text-white">
                            %{savedPct} {t3('avantaj', 'Rabatt', 'off')}
                          </span>
                        )}
                      </span>
                    ) : hasSaving ? (
                      <span className="mb-3 flex flex-wrap items-center gap-1.5">
                        <span className="whitespace-nowrap rounded-pill bg-brand px-3 py-1 text-xs font-bold text-white">
                          %{savedPct} {t3('avantaj', 'Rabatt', 'off')}
                        </span>
                        {/* (USOM/SGB — YALNIZCA /tr) Keşif kartı olgusal rozet; %avantaj ile aynı kümede (yeşil+amber uyumu). /de-/en'de yok. */}
                        {tr && b.key === 'bundle_recon' && (
                          <span className="whitespace-nowrap rounded-pill bg-accent px-2.5 py-1 text-xs font-bold text-white">
                            USOM Eşleme
                          </span>
                        )}
                      </span>
                    ) : tr && b.key === 'bundle_recon' && !b.comingSoon ? (
                      <span className="mb-3 inline-flex w-fit rounded-pill bg-accent px-3 py-1 text-xs font-bold text-white">
                        USOM Eşleme
                      </span>
                    ) : null}
                    <h3 className="text-lg font-bold text-brand">{b.displayName}</h3>
                    <p className="mt-2 text-sm leading-relaxed text-ink-soft">{renderEmphasis(b.description)}</p>
                    {b.selectable ? (
                      <div className="mt-3 rounded-card border border-accent/40 bg-accent-soft/30 px-3 py-2 text-xs text-ink-soft">
                        <span className="font-semibold">{t3('İçerik seçilebilir', 'Inhalt wählbar', 'Content is selectable')}</span>{' '}
                        — {t3(
                          `${(b.selectableModules ?? []).map((m) => m.displayName).join(' / ')}'den istediğinizi seçin`,
                          `wählen Sie beliebige aus ${(b.selectableModules ?? []).map((m) => m.displayName).join(' / ')}`,
                          `pick any of ${(b.selectableModules ?? []).map((m) => m.displayName).join(' / ')}`)}
                      </div>
                    ) : b.key === 'bundle_recon' ? (
                      // (Keşif) İçindekiler = gerçek kapsam maddeleri (üye adları değil). CT ayrı teslimat
                      // DEĞİL — subdomain envanterinin yöntemi olarak 1. maddenin içinde (ikinci kez sayma).
                      <div className="mt-3 rounded-card bg-brand-50/50 px-3 py-2 text-xs text-ink-soft">
                        <span className="font-semibold">{t3('İçindekiler', 'Enthält', 'Includes')}:</span>
                        <ul className="mt-1.5 space-y-1">
                          {(region.lang === 'de'
                            ? [
                                'Scan auf aufgegebene Subdomains (Subdomain Takeover) — Subdomain-Inventar aus Certificate-Transparency-Logs',
                                'Erkennung öffentlicher API- / Swagger-Dokumentation',
                                'CMS- & Technologie-Fingerprint-Analyse',
                                'Erkennung administrativer/sensibler Pfade aus der Sitemap',
                              ]
                            : tr
                            ? [
                                'Terk edilmiş alt domain (Subdomain Takeover) taraması — Certificate Transparency loglarından alt domain envanteri',
                                'Açık API / Swagger dokümantasyon keşfi',
                                'CMS & teknoloji parmak izi analizi',
                                'Site haritasından idari/hassas yol tespiti',
                              ]
                            : [
                                'Abandoned subdomain (takeover) scan — subdomain inventory from Certificate Transparency logs',
                                'Public API / Swagger documentation discovery',
                                'CMS & technology fingerprint analysis',
                                'Admin/sensitive path detection from the site map',
                              ]
                          ).map((it) => (
                            <li key={it} className="flex gap-1.5">
                              <span className="mt-0.5 text-accent-600">·</span>
                              <span>{it}</span>
                            </li>
                          ))}
                        </ul>
                        <p className="mt-2 border-t border-line/60 pt-2 text-[11px] italic text-ink-muted">
                          {t3(
                            'Pasif dış yüzey keşfidir; aktif uç nokta enjeksiyonu veya kimlik doğrulamalı test içermez.',
                            'Passive Erkundung der externen Oberfläche; keine aktive Endpunkt-Injection und keine authentifizierten Tests.',
                            'Passive external-surface discovery; no active endpoint injection or authenticated testing.')}
                        </p>
                      </div>
                    ) : b.key === 'bundle_full_pentest' ? (
                      // (Tam Kapsamlı) İncelenen alanlar = gerçekten çalıştırdığımız kapsam (Faz 0–5).
                      // Üye adları yerine dürüst kapsam maddeleri + sınırlar/güvence.
                      <div className="mt-3 rounded-card bg-brand-50/50 px-3 py-2 text-xs text-ink-soft">
                        <span className="font-semibold">{t3('İncelenen alanlar', 'Was wir prüfen', 'What we examine')}:</span>
                        <ul className="mt-1.5 space-y-1">
                          {(region.lang === 'de'
                            ? [
                                'Authentifizierter Tiefen-Scan — Cookie/Session/Autorisierung, authentifizierte Injection (SQLi/XSS) und IDOR-Indikatoren, Forced Browsing, Rechteausweitung, mehrstufige Geschäftslogik',
                                'Client-Side & JS-Analyse — JS-Bundle-/Secret-Scan, Source-Map-Preisgabe, bekannte verwundbare Bibliotheken, DOM-XSS/postMessage/Browser-Storage, SRI / Reverse-Tabnabbing / Open-Redirect',
                                'Session, CSRF & Authentifizierungs-Tiefe — CSRF, Session-Entropie/Fixation, Konto-Enumeration, schwache Sperrung, Passwortrichtlinie, MFA-Beobachtung',
                                'API-Sicherheit (OWASP API Top 10) — BOLA/BFLA, übermäßige Datenpreisgabe (BOPLA), Rate-Limit, Shadow-API-Versionen, GraphQL-Introspection',
                                'CORS, Sicherheitsheader & TLS — CORS-Fehlkonfiguration, HSTS / Clickjacking / CSP-Schwäche, TLS-Protokoll- und Cipher-Konfiguration',
                                'Konfiguration & Preisgabe — Backup-/Altdateien, Admin-Oberflächen, Host-Header-Injection, HTTP-Methoden-Erkennung, Cache-Indikatoren, Kommentar-/Metadaten-Leck',
                                'E-Mail, DNS & Subdomain — DMARC/SPF/DKIM-Richtlinienstärke, MTA-STS, DNSSEC, CAA, Subdomain-Takeover (Dangling DNS)',
                              ]
                            : tr
                            ? [
                                'Kimlik Doğrulamalı Derin Tarama — çerez/oturum/yetki, authenticated enjeksiyon (SQLi/XSS) ve IDOR göstergeleri, forced browsing, yetki yükseltme, çok-adımlı iş mantığı',
                                'Client-Side & JS Analizi — JS bundle/sır taraması, source map ifşası, bilinen zafiyetli kütüphaneler, DOM-XSS/postMessage/tarayıcı-depolama, SRI / reverse-tabnabbing / open-redirect',
                                'Oturum, CSRF & Kimlik-Doğrulama Derinliği — CSRF, oturum entropi/fixation, hesap enumerasyonu, zayıf kilitleme, parola politikası, MFA gözlemi',
                                'API Güvenliği (OWASP API Top 10) — BOLA/BFLA, aşırı veri ifşası (BOPLA), rate-limit, shadow API sürümleri, GraphQL introspection',
                                'CORS, Güvenlik Başlıkları & TLS — CORS yanlış yapılandırması, HSTS / clickjacking / CSP zayıflığı, TLS protokol ve cipher yapılandırması',
                                'Yapılandırma & İfşa — yedek/eski dosyalar, admin arayüzleri, host-header injection, HTTP method keşfi, önbellek göstergeleri, yorum/metadata sızıntısı',
                                'E-posta, DNS & Subdomain — DMARC/SPF/DKIM politika gücü, MTA-STS, DNSSEC, CAA, subdomain takeover (dangling DNS)',
                              ]
                            : [
                                'Authenticated Deep Scan — cookie/session/authorization, authenticated injection (SQLi/XSS) and IDOR indicators, forced browsing, privilege escalation, multi-step business logic',
                                'Client-Side & JS Analysis — JS bundle/secret scan, source-map exposure, known-vulnerable libraries, DOM-XSS/postMessage/browser-storage, SRI / reverse-tabnabbing / open-redirect',
                                'Session, CSRF & Authentication Depth — CSRF, session entropy/fixation, account enumeration, weak lockout, password policy, MFA observation',
                                'API Security (OWASP API Top 10) — BOLA/BFLA, excessive data exposure (BOPLA), rate-limit, shadow API versions, GraphQL introspection',
                                'CORS, Security Headers & TLS — CORS misconfiguration, HSTS / clickjacking / CSP weakness, TLS protocol and cipher configuration',
                                'Configuration & Exposure — backup/old files, admin interfaces, host-header injection, HTTP method discovery, cache indicators, comment/metadata leakage',
                                'Email, DNS & Subdomain — DMARC/SPF/DKIM policy strength, MTA-STS, DNSSEC, CAA, subdomain takeover (dangling DNS)',
                              ]
                          ).map((it) => (
                            <li key={it} className="flex gap-1.5">
                              <span className="mt-0.5 text-accent-600">·</span>
                              <span>{it}</span>
                            </li>
                          ))}
                        </ul>
                        <p className="mt-2 border-t border-line/60 pt-2 text-[11px] text-ink-muted">
                          {t3(
                            'Sınırlar & güvence: “Kanıtla, istismar etme.” Gerçek veri değiştirme/silme veya ödeme tamamlama kod seviyesinde engellidir. Cross-account (başka kullanıcının verisi) IDOR kapsam dışıdır. Kimlik bilgileriniz şifreli/geçici saklanır, tarama bitince silinir; yetkilendirme beyanı zorunludur.',
                            'Grenzen & Zusicherung: „Nachweisen, nicht ausnutzen.“ Echte Datenänderung/-löschung oder Zahlungsabschluss sind auf Code-Ebene blockiert. Cross-Account-IDOR (Daten anderer Nutzer) ist außerhalb des Scope. Zugangsdaten werden verschlüsselt/temporär gespeichert und nach dem Scan gelöscht; eine Autorisierungserklärung ist erforderlich.',
                            'Limits & assurance: “Prove, don’t exploit.” Real data changes/deletion or payment completion are blocked at the code level. Cross-account IDOR (another user’s data) is out of scope. Credentials are stored encrypted/temporarily and deleted after the scan; an authorization declaration is required.')}
                        </p>
                        <p className="mt-1.5 text-[11px] italic text-ink-muted">
                          {t3(
                            'Önemli — TEST hesabı: 2FA’sız, sınırlı yetkili, ana/üretim hesabınız olmayan, tek kullanımlık bir hesap gerekir. Kapsam notu: sonuçlar hedefin mimarisine göre değişir; authenticated yüzeyi sınırlı/SPA ağırlıklı sitelerde bazı kontroller “kapsam dışı / incelenemedi” raporlanır — bu normaldir.',
                            'Wichtig — TEST-Konto: Es wird ein Einmal-Konto ohne 2FA, mit minimalen Rechten und NICHT Ihr Produktivkonto benötigt. Hinweis zum Umfang: Ergebnisse hängen von der Architektur des Ziels ab; bei Seiten mit begrenzter authentifizierter Oberfläche/SPA werden einige Prüfungen als „außerhalb des Scope / nicht geprüft“ berichtet — das ist normal.',
                            'Important — TEST account: a no-2FA, least-privilege, single-use account that is NOT your production account. Scope note: results vary with the target’s architecture; on sites with limited authenticated surface/SPA, some checks are reported as “out of scope / not scanned” — this is normal.')}
                        </p>
                      </div>
                    ) : b.members.length > 0 ? (
                      <div className="mt-3 rounded-card bg-brand-50/50 px-3 py-2 text-xs text-ink-soft">
                        <span className="font-semibold">{t3('İçindekiler', 'Enthält', 'Includes')}:</span>{' '}
                        {b.members.map((m) => m.displayName).join(' · ')}
                      </div>
                    ) : null}
                    <div className="mt-4">
                      {b.comingSoon ? (
                        b.contactOnly ? (
                          <div>
                            <span className="text-xl font-extrabold text-ink">
                              {t3('Kuruma özel teklif', 'Individuelles Unternehmensangebot', 'Custom enterprise quote')}
                            </span>
                            <p className="mt-1 text-xs text-ink-soft">
                              {t3(
                                'Self-servis değildir; kapsam ve yetkilendirme önceden birlikte belirlenir.',
                                'Kein Self-Service; Umfang und Autorisierung werden vorab gemeinsam festgelegt.',
                                'Not self-service; scope and authorization are agreed in advance.')}
                            </p>
                          </div>
                        ) : (
                          <p className="text-sm text-ink-soft">
                            {t3(
                              'Bu kombine paket yakında açılacak; içindeki kontroller olgunlaştıkça sunulacak.',
                              'Dieses Paket wird bald verfügbar sein; es wird angeboten, sobald seine Prüfungen ausgereift sind.',
                              'This bundle is coming soon; offered as its checks mature.')}
                          </p>
                        )
                      ) : (
                        <>
                          <div className="flex items-baseline gap-2">
                            {/* Kompakt indirim: yalnizca ustu-cizili referans + nihai fiyat (metin kalabaligi yok). */}
                            {hasSaving && (
                              <span className="text-sm text-ink-muted line-through">{formatMoney(b.originalMinorUnit, region)}</span>
                            )}
                            <span className="text-3xl font-extrabold text-ink">{formatMoney(b.amountMinorUnit, region)}</span>
                            <span className="text-xs text-ink-muted">{t3('KDV Dahil', 'inkl. MwSt.', 'incl. tax')}</span>
                          </div>
                          <div className="mt-1 text-[11px] text-ink-soft">
                            {t3('Ödeme sonrası kısa süre içinde başlar', 'Startet kurz nach der Zahlung', 'Starts shortly after payment')}
                          </div>
                        </>
                      )}
                    </div>
                    {b.comingSoon ? (
                      <span className="btn-ghost mt-6 w-full cursor-default">{t3('Yakında', 'Bald verfügbar', 'Coming soon')}</span>
                    ) : (
                      <>
                        <Link href={`/verify?bundle=${b.key}`} className="btn-primary mt-6 w-full">
                          {t3('Satın Al', 'Jetzt kaufen', 'Buy Now')}
                        </Link>
                        <a
                          href={`${API}/orders/sample-report/${b.key}?v=lansman1&region=${region.code}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="mt-3 flex w-full items-center justify-center gap-1.5 rounded-pill border border-line px-4 py-2.5 text-sm font-semibold text-ink-soft transition hover:border-brand hover:text-brand"
                        >
                          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden>
                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                            <path d="M14 2v6h6" />
                          </svg>
                          {t3('Örnek raporu gör', 'Musterbericht ansehen', 'View sample report')}
                        </a>
                      </>
                    )}
                  </div>
                );
              })}
            </div>

          </div>
        )}

        {bundles.length === 0 && (
          <p className="mb-10 text-center text-sm text-ink-muted">
            {d.loadError}{' '}
            <Link href="/register" className="text-accent-600 underline">
              {d.startAnyway}
            </Link>
          </p>
        )}

        {/* (KARŞILAŞTIRMA) Paket kartları KALDIRILMADI; bu bölüm EK olarak altlarına gelir. */}
        {compareCols.length > 1 && (
          <PackageCompare
            cols={compareCols}
            redTeamKey={redTeamKey}
            labels={{
              eyebrow: t3('Karşılaştırma', 'Vergleich', 'Comparison'),
              title: t3('Paketleri yan yana karşılaştırın', 'Pakete nebeneinander vergleichen', 'Compare packages side by side'),
              subtitle: t3(
                'Hangi paketin neyi kapsadığını tek tabloda görün. Değerler paket tanımlarından gelir.',
                'Sehen Sie in einer Tabelle, was jedes Paket abdeckt. Die Werte stammen aus den Paketdefinitionen.',
                'See what each package covers in one table. Values come from the package definitions.'),
              rowPrice: t3('Fiyat (KDV dahil)', 'Preis (inkl. MwSt.)', 'Price (VAT incl.)'),
              rowKind: t3('Test türü', 'Testart', 'Test type'),
              rowChecks: t3('Kontrol sayısı', 'Anzahl Prüfungen', 'Number of checks'),
              rowScope: t3('Kapsam', 'Umfang', 'Scope'),
              rowEvidence: t3('Kanıta dayalı bulgu', 'Nachweisbasierte Befunde', 'Evidence-based findings'),
              rowSample: t3('Örnek rapor (PDF)', 'Musterbericht (PDF)', 'Sample report (PDF)'),
              rowDns: t3('DNS sahiplik doğrulaması', 'DNS-Inhaberschaftsprüfung', 'DNS ownership verification'),
              rowExperimental: t3('Yöntem', 'Methode', 'Method'),
              rowFit: t3('Kime uygun', 'Für wen geeignet', 'Best suited for'),
              yes: t3('Var', 'Ja', 'Yes'), no: t3('Yok', 'Nein', 'No'),
              deterministic: t3('Deterministik', 'Deterministisch', 'Deterministic'),
              experimentalTag: t3('Deneysel', 'Experimentell', 'Experimental'),
              view: t3('İncele', 'Ansehen', 'View'),
              scrollHint: t3('Tabloyu yandan kaydırabilirsiniz.', 'Sie können die Tabelle seitlich scrollen.', 'You can scroll the table sideways.'),
              wizTitle: t3('Size uygun paketi bulun', 'Finden Sie das passende Paket', 'Find the right package'),
              wizIntro: t3('Üç soru; yönlendirme amaçlıdır, kesin bir taahhüt değildir.', 'Drei Fragen; dient der Orientierung, keine verbindliche Zusage.', 'Three questions; guidance only, not a commitment.'),
              wizQ1: t3('İlk kez tarama yaptırıyor musunuz?', 'Ist dies Ihr erster Scan?', 'Is this your first scan?'),
              wizQ2: t3('Önceliğiniz nedir?', 'Was ist Ihre Priorität?', 'What is your priority?'),
              wizQ3: t3('Deneysel/otonom teknikleri kabul eder misiniz?', 'Akzeptieren Sie experimentelle/autonome Techniken?', 'Do you accept experimental/autonomous techniques?'),
              wizFirstYes: t3('Evet', 'Ja', 'Yes'), wizFirstNo: t3('Hayır', 'Nein', 'No'),
              wizExpYes: t3('Evet', 'Ja', 'Yes'), wizExpNo: t3('Hayır', 'Nein', 'No'),
              wizGoals: [
                { id: 'quick', label: t3('Hızlı genel kontrol', 'Schnelle Grundprüfung', 'Quick general check') },
                { id: 'surface', label: t3('Dış yüzey yapılandırması', 'Externe Konfiguration', 'External configuration') },
                { id: 'discovery', label: t3('Saldırı yüzeyi keşfi', 'Angriffsflächen-Discovery', 'Attack surface discovery') },
                { id: 'compliance', label: t3('Uyum/denetim hazırlığı', 'Compliance-/Audit-Vorbereitung', 'Compliance/audit readiness') },
                { id: 'proof', label: t3('Zafiyet kanıtı', 'Schwachstellen-Nachweis', 'Proof of a weakness') },
                { id: 'deep', label: t3('Login sonrası derin denetim', 'Tiefe Prüfung nach Login', 'Deep post-login assessment') },
              ],
              wizResult: t3('Önerilen paket', 'Empfohlenes Paket', 'Recommended package'),
              wizAlso: t3('Ayrıca değerlendirebilirsiniz:', 'Ebenfalls möglich:', 'You may also consider:'),
              wizReset: t3('Yeniden başla', 'Neu starten', 'Start over'),
              wizPick: t3('Bu paketi seç', 'Dieses Paket wählen', 'Choose this package'),
            }}
          />
        )}

        {/* ORNEK RAPORLAR — PAKET/BUNDLE bazinda TEK ornek PDF (tek tek kontrol DEGIL). */}
        {sampleItems.length > 0 && (
          <div className="mb-14">
            <div className="mb-6 text-center">
              <p className="eyebrow">{t3('Örnek Raporlar', 'Musterberichte', 'Sample Reports')}</p>
              <h2 className="mt-2 text-2xl font-extrabold text-brand sm:text-3xl">
                {t3('Ne alacağınızı önceden görün', 'Sehen Sie vorab, was Sie erhalten', 'See what you get')}
              </h2>
              <p className="mx-auto mt-2 max-w-xl text-sm text-ink-soft">
                {t3(
                  'Her paketin örnek raporunu, satın almadan PDF olarak inceleyin.',
                  'Sehen Sie den Musterbericht jedes Pakets vor dem Kauf als PDF an.',
                  'Preview each package’s sample report as a PDF before buying.')}
              </p>
            </div>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {sampleItems.map((c) => (
                <a
                  key={c.key}
                  href={`${API}/orders/sample-report/${c.key}?v=lansman1&region=${region.code}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="card flex items-center justify-between gap-3 p-4 transition-colors hover:border-accent/60"
                >
                  <span className="text-sm font-semibold text-brand">{c.displayName}</span>
                  <span className="inline-flex shrink-0 items-center gap-1 text-xs font-semibold text-accent-600">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden>
                      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                      <path d="M14 2v6h6" />
                    </svg>
                    PDF
                  </span>
                </a>
              ))}
            </div>
          </div>
        )}

        <div className="mt-16 overflow-hidden rounded-[22px] bg-gradient-to-br from-brand-deep to-brand px-8 py-14 text-center text-white shadow-card">
          <p className="font-mono text-[11px] font-semibold uppercase tracking-[0.16em] text-accent">{t3('Başlamak için', 'Zum Start', 'To begin')}</p>
          <h2 className="mt-3 text-3xl font-extrabold tracking-tight sm:text-4xl">{d.freeTitle}</h2>
          <p className="mx-auto mt-3 max-w-md leading-relaxed text-white/75">{d.freeSubtitle}</p>
          <Link href="/register" className="btn-primary mt-7">
            {d.freeCta}
          </Link>
        </div>
      </section>
    </>
  );
}
