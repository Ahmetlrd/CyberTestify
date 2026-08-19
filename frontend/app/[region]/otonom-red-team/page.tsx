import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { VISIBLE_REGION_CODES, isRegionCode, getRegion } from '../../../config/regions';
import { getDict } from '../../../config/i18n';
import { RedTeamGate } from '../../../components/otonom/RedTeamGate';

export function generateStaticParams() {
  return VISIBLE_REGION_CODES.map((region) => ({ region }));
}

export function generateMetadata({ params }: { params: { region: string } }): Metadata {
  const region = isRegionCode(params.region) ? getRegion(params.region) : getRegion('tr');
  const d = getDict(region).otonom;
  const url = `https://cybertestify.com/${region.code}/otonom-red-team`;
  return {
    title: d.metaTitle,
    description: d.metaDesc,
    alternates: { canonical: url },
    // Deneysel/davetli özellik → arama motorlarına açık indeksleme YOK.
    robots: { index: false, follow: false },
  };
}

export default function OtonomRedTeamPage({ params }: { params: { region: string } }) {
  if (!isRegionCode(params.region)) notFound();
  const region = getRegion(params.region);
  const d = getDict(region).otonom;

  return (
    <main className="bg-canvas">
      {/* Hero */}
      <section className="border-b border-line bg-brand-deep text-white">
        <div className="container-page py-14 sm:py-20">
          <div className="flex flex-wrap items-center gap-2">
            <span className="eyebrow text-accent">{d.eyebrow}</span>
          </div>
          <h1 className="mt-3 max-w-3xl text-balance text-3xl font-extrabold tracking-tight sm:text-5xl">{d.title}</h1>
          <p className="mt-4 max-w-2xl text-base text-white/80 sm:text-lg">{d.subtitle}</p>
          <div className="mt-6 flex flex-wrap gap-2">
            {d.badges.map((b) => (
              <span key={b} className="rounded-pill border border-white/25 bg-white/10 px-3 py-1 text-xs font-bold uppercase tracking-wide">
                {b}
              </span>
            ))}
          </div>
        </div>
      </section>

      <div className="container-page space-y-14 py-14 sm:py-20">
        {/* Güçlü uyarı kutusu */}
        <section className="rounded-card border-2 border-amber-400 bg-amber-50 p-6">
          <h2 className="text-lg font-extrabold text-amber-900">⚠ {d.warnTitle}</h2>
          <ul className="mt-3 space-y-2">
            {d.warnPoints.map((p) => (
              <li key={p} className="flex gap-2 text-sm text-amber-900">
                <span aria-hidden className="mt-0.5 font-bold">
                  •
                </span>
                <span>{p}</span>
              </li>
            ))}
          </ul>
        </section>

        {/* Ne / kime */}
        <section className="grid gap-6 lg:grid-cols-2">
          <div className="card p-6">
            <h2 className="text-lg font-bold text-ink">{d.whatTitle}</h2>
            <p className="mt-2 text-sm text-ink-soft">{d.whatBody}</p>
            <p className="mt-3 text-sm text-ink-muted">{d.whatFor}</p>
          </div>
          <div className="card p-6">
            <h2 className="text-lg font-bold text-ink">{d.diffTitle}</h2>
            <p className="mt-2 text-sm text-ink-soft">{d.diffBody}</p>
            <ul className="mt-3 space-y-2">
              {d.diffPoints.map((p) => (
                <li key={p} className="flex gap-2 text-sm text-ink-soft">
                  <span aria-hidden className="mt-0.5 text-brand">
                    →
                  </span>
                  <span>{p}</span>
                </li>
              ))}
            </ul>
          </div>
        </section>

        {/* Nasıl çalışır + kanıt-bağlama */}
        <section>
          <h2 className="text-xl font-bold text-ink">{d.howTitle}</h2>
          <div className="mt-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {d.howSteps.map((s, i) => (
              <div key={s.t} className="card p-5">
                <div className="text-xs font-bold text-accent-600">{i + 1}</div>
                <div className="mt-1 font-semibold text-ink">{s.t}</div>
                <p className="mt-1 text-sm text-ink-soft">{s.d}</p>
              </div>
            ))}
          </div>
          <div className="mt-4 card p-6">
            <h3 className="font-bold text-ink">{d.evTitle}</h3>
            <div className="mt-3 grid gap-3 sm:grid-cols-3">
              <div className="rounded-card border border-green-300 bg-green-50 p-3 text-sm text-green-900">{d.evKanitli}</div>
              <div className="rounded-card border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900">{d.evBelirsiz}</div>
              <div className="rounded-card border border-line bg-canvas p-3 text-sm text-ink-muted">{d.evHayalet}</div>
            </div>
          </div>
        </section>

        {/* 3 risk seviyesi */}
        <section>
          <h2 className="text-xl font-bold text-ink">{d.levelsTitle}</h2>
          <div className="mt-4 grid gap-4 lg:grid-cols-3">
            {d.levels.map((lv) => (
              <div key={lv.name} className="card flex flex-col p-6">
                <div className="flex items-baseline justify-between gap-2">
                  <h3 className="text-lg font-extrabold text-brand">{lv.name}</h3>
                  <span className="rounded-pill bg-brand-50 px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wide text-brand">
                    {lv.tag}
                  </span>
                </div>
                <dl className="mt-4 space-y-3 text-sm">
                  <Row label="Risk" value={lv.risk} />
                  <Row label="Teknik" value={lv.technique} />
                  <Row label="Tutarlılık" value={lv.consistency} />
                  <Row label="Human-in-loop" value={lv.humanLoop} />
                </dl>
                {lv.note && (
                  <p className="mt-4 rounded-card border border-amber-300 bg-amber-50 p-3 text-xs font-medium text-amber-900">{lv.note}</p>
                )}
              </div>
            ))}
          </div>
        </section>

        {/* Beta kapısı / panel (interaktif) */}
        <section id="panel" className="mx-auto max-w-2xl">
          <RedTeamGate d={d} />
        </section>

        {/* Kanıt & dürüstlük ilkesi + disclaimer */}
        <section className="card p-6">
          <h2 className="text-lg font-bold text-ink">{d.principleTitle}</h2>
          <p className="mt-2 text-sm text-ink-soft">{d.principleBody}</p>
          <p className="mt-4 border-t border-line pt-4 text-xs text-ink-muted">{d.disclaimer}</p>
        </section>
      </div>
    </main>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-[11px] font-semibold uppercase tracking-wide text-ink-muted">{label}</dt>
      <dd className="mt-0.5 text-ink-soft">{value}</dd>
    </div>
  );
}
