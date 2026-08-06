import Link from 'next/link';
import { notFound } from 'next/navigation';
import { REGION_CODES, isRegionCode, getRegion } from '../../../config/regions';
import { getDict, formatMoney } from '../../../config/i18n';
import { CategoryAccordions } from '../../../components/CategoryAccordions';

type Pkg = { key: string; displayName: string; description: string; priceMinorUnit: number; currency?: string; comingSoon?: boolean; bundleOnly?: boolean; bundleName?: string | null };
type Bundle = {
  key: string; displayName: string; description: string; discountPct: number;
  members: Array<{ key: string; displayName: string }>;
  selectable: boolean; selectableModules: Array<{ key: string; displayName: string }> | null;
  originalMinorUnit: number; amountMinorUnit: number; currency: string; comingSoon?: boolean;
};

const API = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000';
const POPULAR_KEY = 'pci_hazirlik';

export function generateStaticParams() {
  return REGION_CODES.map((region) => ({ region }));
}

export function generateMetadata({ params }: { params: { region: string } }) {
  const region = getRegion(params.region);
  const d = getDict(region).pkg;
  return { title: d.metaTitle, description: d.metaDesc };
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
  const basit = packages.find((p) => p.key === 'basit_tarama');
  const accordionPackages = packages.filter((p) => p.key !== 'basit_tarama');
  // Faz 5b'ye kadar fiyatlar yalnızca TRY tabanlı; TR dışı bölgelerde gösterge
  // niteliğinde (PackagePricing tablosu + bölgesel kalibrasyon gelecek).
  const indicative = region.currency !== 'TRY';

  return (
    <>
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
            Prices are indicative and will be regionally calibrated before launch in this region.
          </p>
        )}

        {bundles.length > 0 && (
          <div className="mb-14">
            <div className="mb-6 text-center">
              <p className="eyebrow">{region.code === 'tr' ? 'Kombine Paketler' : 'Combined Bundles'}</p>
              <h2 className="mt-2 text-2xl font-extrabold text-brand sm:text-3xl">
                {region.code === 'tr' ? 'Birden fazla kontrolü birlikte alın, indirim kazanın' : 'Bundle multiple checks and save'}
              </h2>
              <p className="mx-auto mt-2 max-w-xl text-sm text-ink-soft">
                {region.code === 'tr'
                  ? 'Tekil paketler aynen alınabilir; kombine paketler birden fazlasını daha uygun fiyata sunar.'
                  : 'Single packages remain available; bundles offer several together at a lower price.'}
              </p>
            </div>
            <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
              {bundles.map((b) => {
                // X/Y/Z otomatik: tekil toplam (X), paket (Y), avantaj yuzdesi/tutari (Z).
                const savedMinor = b.originalMinorUnit - b.amountMinorUnit;
                const savedPct = b.originalMinorUnit > 0 ? Math.round((savedMinor / b.originalMinorUnit) * 100) : 0;
                return (
                  <div key={b.key} className={`card relative flex flex-col border-2 border-accent/40 p-6 ${b.comingSoon ? 'opacity-90' : ''}`}>
                    {b.comingSoon ? (
                      <span className="absolute -top-3 left-6 rounded-pill bg-brand px-3 py-1 text-xs font-bold text-white">
                        {region.code === 'tr' ? 'Yakında' : 'Soon'}
                      </span>
                    ) : (
                      <span className="absolute -top-3 left-6 rounded-pill bg-brand px-3 py-1 text-xs font-bold text-white">
                        %{savedPct} {region.code === 'tr' ? 'avantaj' : 'off'}
                      </span>
                    )}
                    <h3 className="text-lg font-bold text-brand">{b.displayName}</h3>
                    <p className="mt-2 text-sm leading-relaxed text-ink-soft">{b.description}</p>
                    {b.selectable ? (
                      <div className="mt-3 rounded-card border border-accent/40 bg-accent-soft/30 px-3 py-2 text-xs text-ink-soft">
                        <span className="font-semibold">{region.code === 'tr' ? 'İçerik seçilebilir' : 'Content is selectable'}</span>{' '}
                        — {region.code === 'tr'
                          ? `${(b.selectableModules ?? []).map((m) => m.displayName).join(' / ')}'den istediğinizi seçin`
                          : `pick any of ${(b.selectableModules ?? []).map((m) => m.displayName).join(' / ')}`}
                      </div>
                    ) : (
                      <div className="mt-3 rounded-card bg-brand-50/50 px-3 py-2 text-xs text-ink-soft">
                        <span className="font-semibold">{region.code === 'tr' ? 'İçindekiler' : 'Includes'}:</span>{' '}
                        {b.members.map((m) => m.displayName).join(' · ')}
                      </div>
                    )}
                    <div className="mt-4 flex-1">
                      {b.comingSoon ? (
                        <p className="text-sm text-ink-soft">
                          {region.code === 'tr'
                            ? 'Bu kombine paket yakında açılacak; içindeki kontroller olgunlaştıkça sunulacak.'
                            : 'This bundle is coming soon; offered as its checks mature.'}
                        </p>
                      ) : (
                        <>
                          <div>
                            <span className="text-3xl font-extrabold text-ink">{formatMoney(b.amountMinorUnit, region)}</span>
                            <span className="ml-1 text-xs text-ink-muted">{region.currency === 'TRY' ? 'KDV Dahil' : 'incl. tax'}</span>
                          </div>
                          {/* Otomatik indirim satiri: Tek tek alinsaydi X -> Paket Y (%Z avantaj) */}
                          <div className="mt-1.5 text-xs text-emerald-700">
                            {region.code === 'tr' ? (
                              <>
                                Tek tek alınsaydı <span className="line-through">{formatMoney(b.originalMinorUnit, region)}</span> →{' '}
                                <strong>{formatMoney(b.amountMinorUnit, region)}</strong> ({formatMoney(savedMinor, region)} / %{savedPct} avantaj)
                              </>
                            ) : (
                              <>
                                Separately <span className="line-through">{formatMoney(b.originalMinorUnit, region)}</span> →{' '}
                                <strong>{formatMoney(b.amountMinorUnit, region)}</strong> (save {formatMoney(savedMinor, region)} / {savedPct}%)
                              </>
                            )}
                          </div>
                          <div className="mt-1 text-[11px] text-ink-soft">
                            {region.code === 'tr'
                              ? 'Tahmini süre: içeriğe göre değişir (üye taramalar sırayla çalışır)'
                              : 'Est. time: varies by content (member scans run sequentially)'}
                          </div>
                        </>
                      )}
                    </div>
                    {b.comingSoon ? (
                      <span className="btn-ghost mt-6 w-full cursor-default">{region.code === 'tr' ? 'Yakında' : 'Coming soon'}</span>
                    ) : (
                      <Link href={`/verify?bundle=${b.key}`} className="btn-primary mt-6 w-full">
                        {region.code === 'tr' ? 'Satın Al' : 'Buy Now'}
                      </Link>
                    )}
                  </div>
                );
              })}
            </div>

            {/* 6. PAKET: basit_tarama — bundle'lar disinda tekil alinabilen TEK paket. Belirgin,
                bundle grid'inin hemen altinda, deneme-amacli giris seviyesi kart. */}
            {basit && !basit.comingSoon && (
              <div className="mt-10">
                <div className="mb-4 text-center">
                  <p className="text-sm font-medium text-ink-soft">
                    {region.code === 'tr'
                      ? 'Sadece hızlı bir ön bakış mı istiyorsunuz? ↓'
                      : 'Just want a quick preview first? ↓'}
                  </p>
                </div>
                <div className="mx-auto max-w-2xl">
                  <div className="card flex flex-col gap-4 border-2 border-brand/25 bg-brand-50/40 p-6 sm:flex-row sm:items-center sm:justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <span className="rounded-pill bg-brand px-3 py-1 text-xs font-bold text-white">
                          {region.code === 'tr' ? 'Giriş Seviyesi' : 'Entry Level'}
                        </span>
                        <h3 className="text-lg font-bold text-brand">{basit.displayName}</h3>
                      </div>
                      <p className="mt-2 text-sm leading-relaxed text-ink-soft">
                        {region.code === 'tr'
                          ? 'Ucuz, hızlı bir deneme taraması — CyberTestify’ı denemek için ideal. Yalnızca ana sayfanın güvenlik başlıkları, TLS geçerliliği ve sunucu banner özetini gösterir. Kapsamlı bir denetim değildir (ön izleme niteliğindedir); derinlemesine inceleme için yukarıdaki kombine paketleri tercih edin.'
                          : 'A cheap, fast trial scan — ideal to try CyberTestify. Covers only the homepage’s security headers, TLS validity and server banner summary. It is a preview, not a comprehensive audit; for depth choose a bundle above.'}
                      </p>
                    </div>
                    <div className="flex flex-col items-start sm:items-end">
                      <div>
                        <span className="text-3xl font-extrabold text-ink">{formatMoney(basit.priceMinorUnit, region)}</span>
                        <span className="ml-1 text-xs text-ink-muted">{region.currency === 'TRY' ? 'KDV Dahil' : 'incl. tax'}</span>
                      </div>
                      <Link href={`/verify?package=${basit.key}`} className="btn-primary mt-3 w-full sm:w-auto">
                        {region.code === 'tr' ? 'Satın Al' : 'Buy Now'}
                      </Link>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Bundle icerigi referansi (tekil satis KAPALI — asagisi yalnizca "hangi paket
                hangi bundle'da" bilgisidir). */}
            <div className="mt-10 text-center">
              <p className="text-sm font-medium text-ink-soft">
                {region.code === 'tr'
                  ? 'Kombine paketlerin içindeki tekil kontroller aşağıda listelenir (tekil satış kapalıdır; bu kontroller ilgili paket içinde sunulur) ↓'
                  : 'The individual checks inside each bundle are listed below (sold only within their bundle) ↓'}
              </p>
            </div>
          </div>
        )}

        {packages.length === 0 ? (
          <p className="text-center text-sm text-ink-muted">
            {d.loadError}{' '}
            <Link href="/register" className="text-accent-600 underline">
              {d.startAnyway}
            </Link>
          </p>
        ) : (
          <>
            {/* Tekil kontroller — kategori akordeonlari (varsayilan KAPALI) */}
            <CategoryAccordions packages={accordionPackages} regionCode={region.code} apiUrl={API} />

            {/* BYOK (yakinda) — kategorilerin altinda ayri kart */}
            <div className="card mt-6 flex flex-col border-dashed p-6 md:max-w-md">
              <span className="badge w-fit">{d.byokBadge}</span>
              <h2 className="mt-3 text-lg font-bold text-brand">{d.byokTitle}</h2>
              <p className="mt-2 flex-1 text-sm leading-relaxed text-ink-soft">{d.byokDesc}</p>
              <span className="btn-ghost mt-6 w-full cursor-default">{d.soon}</span>
            </div>
          </>
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
