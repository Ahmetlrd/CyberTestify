import Link from 'next/link';
import { notFound } from 'next/navigation';
import { VISIBLE_REGION_CODES, isRegionCode, getRegion } from '../../../config/regions';
import { getDict, formatMoney } from '../../../config/i18n';
import { JsonLd } from '../../../components/JsonLd';
import { renderEmphasis, stripEmphasis } from '../../../lib/richText';

type Pkg = { key: string; displayName: string; description: string; priceMinorUnit: number; currency?: string; comingSoon?: boolean; bundleOnly?: boolean; bundleName?: string | null };
type Bundle = {
  key: string; displayName: string; description: string; discountPct: number;
  members: Array<{ key: string; displayName: string }>;
  selectable: boolean; selectableModules: Array<{ key: string; displayName: string }> | null;
  originalMinorUnit: number; amountMinorUnit: number; currency: string; comingSoon?: boolean; popular?: boolean; flagship?: boolean; contactOnly?: boolean;
};

const API = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000';

export function generateStaticParams() {
  return VISIBLE_REGION_CODES.map((region) => ({ region }));
}

export function generateMetadata({ params }: { params: { region: string } }) {
  const region = getRegion(params.region);
  const d = getDict(region).pkg;
  const url = `https://cybertestify.com/${region.code}/packages`;
  return {
    title: d.metaTitle,
    description: d.metaDesc,
    alternates: { canonical: url },
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
  // Faz 5b'ye kadar fiyatlar yalnızca TRY tabanlı; TR dışı bölgelerde gösterge niteliğinde.
  const indicative = region.currency !== 'TRY';

  // (JSON-LD) Hizmetler — Service ItemList. Fiyat "baslangic" olarak esnek ifade edilir
  // (Offer priceSpecification.minPrice + "baslangic fiyati" aciklamasi; kesin taahhut degil).
  const SITE = 'https://cybertestify.com';
  const svc = (name: string, description: string, minMinor: number) => ({
    '@type': 'Service',
    name,
    serviceType: 'Web güvenliği ön-değerlendirme',
    description,
    provider: { '@type': 'Organization', name: 'CyberTestify', url: SITE },
    areaServed: 'TR',
    offers: {
      '@type': 'Offer',
      priceCurrency: region.currency,
      priceSpecification: { '@type': 'PriceSpecification', minPrice: (minMinor / 100).toFixed(2), priceCurrency: region.currency, description: 'Başlangıç fiyatı' },
      url: `${SITE}/${region.code}/packages`,
    },
  });
  const serviceItems = [
    ...(basit && !basit.comingSoon ? [svc(basit.displayName, stripEmphasis(basit.description), basit.priceMinorUnit)] : []),
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
      <section className="bg-brand-50/60 py-16">
        <div className="container-page text-center">
          <p className="eyebrow">{d.eyebrow}</p>
          <h1 className="mx-auto mt-3 max-w-2xl text-4xl font-extrabold text-brand sm:text-5xl">{d.title}</h1>
          <p className="mx-auto mt-4 max-w-xl text-lg text-ink-soft">{d.subtitle}</p>
          <div className="mt-6 flex flex-wrap items-center justify-center gap-2.5">
            {d.trust.map((t) => (
              <span key={t} className="badge">
                {t}
              </span>
            ))}
          </div>
        </div>
      </section>

      <section className="container-page py-16">
        {indicative && (
          <p className="mb-8 rounded-card border border-accent/40 bg-accent-soft/40 px-4 py-3 text-center text-sm text-ink-soft">
            {region.lang === 'de'
              ? 'Die Preise sind Richtwerte und werden vor dem Start in dieser Region regional kalibriert.'
              : 'Prices are indicative and will be regionally calibrated before launch in this region.'}
          </p>
        )}

        {bundles.length > 0 && (
          <div className="mb-14">
            <div className="mb-8 text-center">
              <p className="eyebrow">{t3('Paketlerimiz', 'Unsere Pakete', 'Our Packages')}</p>
              <h2 className="mt-2 text-2xl font-extrabold text-brand sm:text-3xl">
                {t3('İhtiyacınıza uygun paketi seçin', 'Wählen Sie das passende Paket', 'Choose the package that fits you')}
              </h2>
              <p className="mx-auto mt-2 max-w-xl text-sm text-ink-soft">
                {t3(
                  'Her paket ilgili kontrolleri birlikte, indirimli sunar. Hızlı bir ön bakış için Basit Tarama ile başlayabilirsiniz.',
                  'Jedes Paket bündelt die passenden Prüfungen zu einem vergünstigten Preis. Für einen schnellen Überblick starten Sie mit dem Basis-Scan.',
                  'Each package bundles its checks together at a discount. Start with the Basic Scan for a quick preview.')}
              </p>
            </div>
            <div className="grid items-stretch gap-6 md:grid-cols-2 lg:grid-cols-3">
              {/* Basit Tarama — giris seviyesi PAKET (grid'in ilk karti; ayriksi degil). */}
              {basit && !basit.comingSoon && (
                <div className="card relative flex flex-col border-2 border-line p-6">
                  <span className="absolute -top-3 left-6 rounded-pill bg-ink-soft px-3 py-1 text-xs font-bold text-white">
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
                  <div className="mt-4 flex-1">
                    <div>
                      <span className="text-3xl font-extrabold text-ink">{formatMoney(basit.priceMinorUnit, region)}</span>
                      <span className="ml-1 text-xs text-ink-muted">{t3('KDV Dahil', 'inkl. MwSt.', 'incl. tax')}</span>
                    </div>
                    <div className="mt-1.5 text-[11px] text-ink-soft">
                      {t3(
                        'Dış yüzey ön-değerlendirmesidir; aktif sızma testi veya derinlemesine kod denetimi içermez.',
                        'Eine Vorabbewertung der externen Oberfläche; kein aktiver Penetrationstest und keine tiefe Code-Prüfung.',
                        'An external-surface pre-assessment; no active penetration test or in-depth code audit.')}
                    </div>
                  </div>
                  <a
                    href={`${API}/orders/sample-report/${basit.key}?v=lansman1&region=${region.code}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="mt-6 flex w-full items-center justify-center gap-1.5 rounded-pill bg-gradient-to-r from-amber-400 to-orange-500 px-4 py-2.5 text-sm font-bold text-white shadow-sm transition hover:brightness-105"
                  >
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden>
                      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                      <path d="M14 2v6h6" />
                    </svg>
                    {t3('Örnek raporu gör', 'Musterbericht ansehen', 'View sample report')}
                  </a>
                  <Link href={`/verify?package=${basit.key}`} className="btn-outline mt-3 w-full">
                    {t3('Satın Al', 'Jetzt kaufen', 'Buy Now')}
                  </Link>
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
                    className={`card relative flex flex-col p-6 ${
                      flagship ? 'border-2 border-brand shadow-lg ring-2 ring-brand/25 bg-brand-50/20'
                        : popular ? 'border-2 border-accent shadow-md ring-2 ring-accent/25'
                        : 'border-2 border-accent/40'
                    } ${b.comingSoon ? 'opacity-90' : ''}`}
                  >
                    {b.comingSoon ? (
                      <span className="absolute -top-3 left-6 rounded-pill bg-brand px-3 py-1 text-xs font-bold text-white">
                        {t3('Yakında', 'Bald', 'Soon')}
                      </span>
                    ) : flagship ? (
                      <span className="absolute -top-3 left-6 flex items-center gap-1.5">
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
                      <span className="absolute -top-3 left-6 flex items-center gap-1.5">
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
                      <span className="absolute -top-3 left-6 rounded-pill bg-brand px-3 py-1 text-xs font-bold text-white">
                        %{savedPct} {t3('avantaj', 'Rabatt', 'off')}
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
                    <div className="mt-4 flex-1">
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
                        <a
                          href={`${API}/orders/sample-report/${b.key}?v=lansman1&region=${region.code}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="mt-6 flex w-full items-center justify-center gap-1.5 rounded-pill bg-gradient-to-r from-amber-400 to-orange-500 px-4 py-2.5 text-sm font-bold text-white shadow-sm transition hover:brightness-105"
                        >
                          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden>
                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                            <path d="M14 2v6h6" />
                          </svg>
                          {t3('Örnek raporu gör', 'Musterbericht ansehen', 'View sample report')}
                        </a>
                        <Link href={`/verify?bundle=${b.key}`} className="btn-primary mt-3 w-full">
                          {t3('Satın Al', 'Jetzt kaufen', 'Buy Now')}
                        </Link>
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

        <div className="mt-14 rounded-[20px] bg-brand-deep px-8 py-12 text-center text-white">
          <h2 className="text-2xl font-extrabold sm:text-3xl">{d.freeTitle}</h2>
          <p className="mx-auto mt-2 max-w-md text-white/75">{d.freeSubtitle}</p>
          <Link href="/register" className="btn-primary mt-7">
            {d.freeCta}
          </Link>
        </div>
      </section>
    </>
  );
}
