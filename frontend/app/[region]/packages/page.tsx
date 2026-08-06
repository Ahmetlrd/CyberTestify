import Link from 'next/link';
import { notFound } from 'next/navigation';
import { REGION_CODES, isRegionCode, getRegion } from '../../../config/regions';
import { getDict, formatMoney } from '../../../config/i18n';

type Pkg = { key: string; displayName: string; description: string; priceMinorUnit: number; currency?: string; comingSoon?: boolean; bundleOnly?: boolean; bundleName?: string | null };
type Bundle = {
  key: string; displayName: string; description: string; discountPct: number;
  members: Array<{ key: string; displayName: string }>;
  selectable: boolean; selectableModules: Array<{ key: string; displayName: string }> | null;
  originalMinorUnit: number; amountMinorUnit: number; currency: string; comingSoon?: boolean; popular?: boolean;
};

const API = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000';

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
  // SATIS MODELI: SADECE paketler. basit_tarama giris-seviyesi bir PAKET olarak grid'in
  // BASINDA gosterilir (ayriksi "6. paket" degil). Diger tekil paketler UI'da GORUNMEZ;
  // yalnizca ornek raporlari (PDF) sunulur.
  const tr = region.code === 'tr';
  const basit = packages.find((p) => p.key === 'basit_tarama');
  // Ornek rapor: PAKET/BUNDLE bazinda TEK PDF (tek tek kontrol DEGIL). basit + aktif bundle'lar.
  const sampleItems: Array<{ key: string; displayName: string }> = [];
  if (basit) sampleItems.push({ key: basit.key, displayName: basit.displayName });
  for (const b of bundles) if (!b.comingSoon) sampleItems.push({ key: b.key, displayName: b.displayName });
  // Faz 5b'ye kadar fiyatlar yalnızca TRY tabanlı; TR dışı bölgelerde gösterge niteliğinde.
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
            <div className="mb-8 text-center">
              <p className="eyebrow">{tr ? 'Paketlerimiz' : 'Our Packages'}</p>
              <h2 className="mt-2 text-2xl font-extrabold text-brand sm:text-3xl">
                {tr ? 'İhtiyacınıza uygun paketi seçin' : 'Choose the package that fits you'}
              </h2>
              <p className="mx-auto mt-2 max-w-xl text-sm text-ink-soft">
                {tr
                  ? 'Her paket ilgili kontrolleri birlikte, indirimli sunar. Hızlı bir ön bakış için Basit Tarama ile başlayabilirsiniz.'
                  : 'Each package bundles its checks together at a discount. Start with the Basic Scan for a quick preview.'}
              </p>
            </div>
            <div className="grid items-stretch gap-6 md:grid-cols-2 lg:grid-cols-3">
              {/* Basit Tarama — giris seviyesi PAKET (grid'in ilk karti; ayriksi degil). */}
              {basit && !basit.comingSoon && (
                <div className="card relative flex flex-col border-2 border-line p-6">
                  <span className="absolute -top-3 left-6 rounded-pill bg-ink-soft px-3 py-1 text-xs font-bold text-white">
                    {tr ? 'Giriş' : 'Entry'}
                  </span>
                  <h3 className="text-lg font-bold text-brand">{basit.displayName}</h3>
                  <p className="mt-2 text-sm leading-relaxed text-ink-soft">
                    {tr
                      ? 'Hızlı, ucuz bir deneme taraması — CyberTestify’ı denemek için ideal.'
                      : 'A fast, cheap trial scan — ideal to try CyberTestify.'}
                  </p>
                  <div className="mt-3 rounded-card bg-brand-50/50 px-3 py-2 text-xs text-ink-soft">
                    <span className="font-semibold">{tr ? 'Kapsam' : 'Scope'}:</span>{' '}
                    {tr ? 'Güvenlik başlıkları · TLS geçerliliği · sunucu banner özeti' : 'Security headers · TLS validity · server banner'}
                  </div>
                  <div className="mt-4 flex-1">
                    <div>
                      <span className="text-3xl font-extrabold text-ink">{formatMoney(basit.priceMinorUnit, region)}</span>
                      <span className="ml-1 text-xs text-ink-muted">{region.currency === 'TRY' ? 'KDV Dahil' : 'incl. tax'}</span>
                    </div>
                    <div className="mt-1.5 text-[11px] text-ink-soft">
                      {tr ? 'Ön izleme niteliğindedir; kapsamlı bir denetim değildir.' : 'A preview, not a comprehensive audit.'}
                    </div>
                  </div>
                  <Link href={`/verify?package=${basit.key}`} className="btn-outline mt-6 w-full">
                    {tr ? 'Satın Al' : 'Buy Now'}
                  </Link>
                </div>
              )}
              {bundles.map((b) => {
                const savedMinor = b.originalMinorUnit - b.amountMinorUnit;
                const hasSaving = savedMinor > 0; // recon gibi nihai > tekil-toplam ise indirim GOSTERILMEZ
                const savedPct = hasSaving && b.originalMinorUnit > 0 ? Math.round((savedMinor / b.originalMinorUnit) * 100) : 0;
                const popular = !!b.popular && !b.comingSoon;
                return (
                  <div
                    key={b.key}
                    className={`card relative flex flex-col p-6 ${
                      popular ? 'border-2 border-accent shadow-md ring-2 ring-accent/25' : 'border-2 border-accent/40'
                    } ${b.comingSoon ? 'opacity-90' : ''}`}
                  >
                    {b.comingSoon ? (
                      <span className="absolute -top-3 left-6 rounded-pill bg-brand px-3 py-1 text-xs font-bold text-white">
                        {tr ? 'Yakında' : 'Soon'}
                      </span>
                    ) : popular ? (
                      <span className="absolute -top-3 left-6 rounded-pill bg-accent px-3 py-1 text-xs font-bold text-white">
                        ★ {tr ? 'Popüler' : 'Popular'}
                      </span>
                    ) : hasSaving ? (
                      <span className="absolute -top-3 left-6 rounded-pill bg-brand px-3 py-1 text-xs font-bold text-white">
                        %{savedPct} {tr ? 'avantaj' : 'off'}
                      </span>
                    ) : null}
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
                          {/* Indirim satiri YALNIZCA gercek tasarruf varsa (nihai < tekil-toplam). */}
                          {hasSaving && (
                            <div className="mt-1.5 text-xs text-emerald-700">
                              {tr ? (
                                <>
                                  Tek tek toplam <span className="line-through">{formatMoney(b.originalMinorUnit, region)}</span> →{' '}
                                  <strong>{formatMoney(b.amountMinorUnit, region)}</strong> ({formatMoney(savedMinor, region)} / %{savedPct} avantaj)
                                </>
                              ) : (
                                <>
                                  Separately <span className="line-through">{formatMoney(b.originalMinorUnit, region)}</span> →{' '}
                                  <strong>{formatMoney(b.amountMinorUnit, region)}</strong> (save {formatMoney(savedMinor, region)} / {savedPct}%)
                                </>
                              )}
                            </div>
                          )}
                          <div className="mt-1 text-[11px] text-ink-soft">
                            {tr
                              ? 'Tahmini süre: içeriğe göre değişir (kontroller sırayla çalışır)'
                              : 'Est. time: varies by content (checks run sequentially)'}
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
              <p className="eyebrow">{tr ? 'Örnek Raporlar' : 'Sample Reports'}</p>
              <h2 className="mt-2 text-2xl font-extrabold text-brand sm:text-3xl">
                {tr ? 'Ne alacağınızı önceden görün' : 'See what you get'}
              </h2>
              <p className="mx-auto mt-2 max-w-xl text-sm text-ink-soft">
                {tr
                  ? 'Her paketin örnek raporunu, satın almadan PDF olarak inceleyin.'
                  : 'Preview each package’s sample report as a PDF before buying.'}
              </p>
            </div>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {sampleItems.map((c) => (
                <a
                  key={c.key}
                  href={`${API}/orders/sample-report/${c.key}`}
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
