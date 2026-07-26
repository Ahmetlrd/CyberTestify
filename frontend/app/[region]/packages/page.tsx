import Link from 'next/link';
import { notFound } from 'next/navigation';
import { REGION_CODES, isRegionCode, getRegion } from '../../../config/regions';
import { getDict, formatMoney } from '../../../config/i18n';

type Pkg = { key: string; displayName: string; description: string; priceMinorUnit: number; currency?: string };

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

export default async function PackagesPage({ params }: { params: { region: string } }) {
  if (!isRegionCode(params.region)) notFound();
  const region = getRegion(params.region);
  const d = getDict(region).pkg;
  const packages = await getPackages(region.code);
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

        {packages.length === 0 ? (
          <p className="text-center text-sm text-ink-muted">
            {d.loadError}{' '}
            <Link href="/register" className="text-accent-600 underline">
              {d.startAnyway}
            </Link>
          </p>
        ) : (
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
            {packages.map((p) => {
              const popular = p.key === POPULAR_KEY;
              return (
                <div key={p.key} className={`card relative flex flex-col p-6 ${popular ? 'ring-2 ring-accent' : ''}`}>
                  {popular && (
                    <span className="absolute -top-3 left-6 rounded-pill bg-accent px-3 py-1 text-xs font-bold text-ink">
                      {d.popular}
                    </span>
                  )}
                  <h2 className="text-lg font-bold text-brand">{p.displayName}</h2>
                  <p className="mt-2 flex-1 text-sm leading-relaxed text-ink-soft">{p.description}</p>
                  <div className="mt-5">
                    <span className="text-3xl font-extrabold text-ink">{formatMoney(p.priceMinorUnit, region)}</span>
                    <span className="ml-1 text-xs text-ink-muted">{d.perScan}</span>
                  </div>
                  <Link href="/register" className={`mt-6 w-full ${popular ? 'btn-primary' : 'btn-outline'}`}>
                    {d.selectCta}
                  </Link>
                </div>
              );
            })}

            <div className="card flex flex-col border-dashed p-6">
              <span className="badge w-fit">{d.byokBadge}</span>
              <h2 className="mt-3 text-lg font-bold text-brand">{d.byokTitle}</h2>
              <p className="mt-2 flex-1 text-sm leading-relaxed text-ink-soft">{d.byokDesc}</p>
              <span className="btn-ghost mt-6 w-full cursor-default">{d.soon}</span>
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
