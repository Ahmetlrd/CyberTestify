import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import Link from 'next/link';
import { VISIBLE_REGION_CODES, isRegionCode, getRegion } from '../../../config/regions';
import { getDict } from '../../../config/i18n';
import { RedTeamGate } from '../../../components/otonom/RedTeamGate';
import { DisclaimerReveal } from '../../../components/otonom/DisclaimerReveal';

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

// Seviyeye göre risk rengi (S1 yeşil / S2 amber / S3 kırmızı) — binder şiddet paletiyle akraba.
const LEVEL_ACCENT = [
  { stripe: 'bg-emerald-500', ring: 'border-emerald-400/60', badge: 'bg-emerald-100 text-emerald-800', dot: 'text-emerald-500' },
  { stripe: 'bg-amber-500', ring: 'border-amber-400/60', badge: 'bg-amber-100 text-amber-800', dot: 'text-amber-500' },
  { stripe: 'bg-red-500', ring: 'border-red-400/60', badge: 'bg-red-100 text-red-800', dot: 'text-red-500' },
];

export default function OtonomRedTeamPage({ params }: { params: { region: string } }) {
  if (!isRegionCode(params.region)) notFound();
  const region = getRegion(params.region);
  const d = getDict(region).otonom;
  const packagesHref = `/${region.code}/packages`;

  return (
    <main className="bg-canvas">
      {/* ————————————————————————— HERO ————————————————————————— */}
      <section className="bg-brand-deep text-white">
        <div className="container-page py-16 sm:py-24">
          <span className="eyebrow text-accent">{d.eyebrow}</span>
          <h1 className="mt-3 max-w-3xl text-balance text-4xl font-extrabold tracking-tight sm:text-5xl">{d.title}</h1>
          <p className="mt-4 max-w-2xl text-pretty text-base text-white/75 sm:text-lg">{d.subtitle}</p>

          <div className="mt-6 flex flex-wrap gap-2">
            {d.badges.map((b) => (
              <span key={b} className="rounded-pill border border-amber-300/40 px-3 py-1 text-[11px] font-bold uppercase tracking-wide text-amber-200">
                {b}
              </span>
            ))}
          </div>

          <div className="mt-8 flex flex-wrap items-center gap-3">
            <a href="#panel" className="btn btn-primary">{d.heroCtaPrimary}</a>
            <a href="#how" className="btn btn-ghost text-white/90 ring-1 ring-inset ring-white/25 hover:bg-white/10">{d.heroCtaSecondary}</a>
          </div>
          <p className="mt-4 text-xs text-white/50">{d.heroFootnote}</p>
        </div>
      </section>

      {/* ————————————— İnce uyarı şeridi (büyük sarı kutu yerine) ————————————— */}
      <div className="border-y border-amber-300 bg-amber-50">
        <div className="container-page flex items-center gap-2 py-2.5 text-[13px] font-medium text-amber-900">
          <span aria-hidden>⚠</span>
          <span>{d.stickyWarn}</span>
        </div>
      </div>

      <div className="container-page space-y-20 py-16 sm:py-24">
        {/* ————————————————————— Ne / kime (kısa lead) ————————————————————— */}
        <section className="mx-auto max-w-3xl text-center">
          <h2 className="text-2xl font-bold text-ink sm:text-3xl">{d.whatTitle}</h2>
          <p className="mt-3 text-ink-soft">{d.whatBody}</p>
          <p className="mt-3 text-sm text-ink-muted">{d.whatFor}</p>
        </section>

        {/* ————————————————————— S1 / S2 / S3 kartları (kalp) ————————————————————— */}
        <section id="levels" className="scroll-mt-24">
          <div className="mx-auto max-w-2xl text-center">
            <h2 className="text-2xl font-bold text-ink sm:text-3xl">{d.levelsTitle}</h2>
            <p className="mt-2 text-sm text-ink-muted">{d.levelsSubtitle}</p>
          </div>
          <div className="mt-8 grid gap-5 lg:grid-cols-3">
            {d.levels.map((lv, i) => {
              const a = LEVEL_ACCENT[i] ?? LEVEL_ACCENT[0];
              return (
                <div
                  key={lv.name}
                  className={`card flex flex-col overflow-hidden p-0 ${lv.available ? `ring-1 ${a.ring}` : 'opacity-90'}`}
                >
                  <div className={`h-1.5 w-full ${a.stripe}`} />
                  <div className="flex flex-1 flex-col p-6">
                    <div className="flex items-center justify-between gap-2">
                      <h3 className="text-lg font-extrabold text-ink">{lv.name}</h3>
                      <span className={`rounded-pill px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wide ${a.badge}`}>{lv.tag}</span>
                    </div>
                    <div className="mt-3 text-xl font-extrabold text-brand">{lv.price}</div>

                    <dl className="mt-5 space-y-3 border-t border-line pt-4 text-sm">
                      <Row label="Risk" value={lv.risk} dot={a.dot} />
                      <Row label="Teknik" value={lv.technique} dot={a.dot} />
                      <Row label="Tutarlılık" value={lv.consistency} dot={a.dot} />
                      <Row label="Human-in-loop" value={lv.humanLoop} dot={a.dot} />
                    </dl>

                    {lv.note && (
                      <p className="mt-4 rounded-card border border-red-200 bg-red-50 p-3 text-xs font-medium text-red-800">{lv.note}</p>
                    )}

                    <div className="mt-auto pt-6">
                      {lv.available ? (
                        <a href="#panel" className="btn btn-primary w-full">{lv.cta}</a>
                      ) : (
                        <span className="btn btn-outline pointer-events-none w-full cursor-not-allowed opacity-50">{lv.cta}</span>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </section>

        {/* ————————————————————— Nasıl çalışır (4 adım) ————————————————————— */}
        <section id="how" className="scroll-mt-24">
          <h2 className="text-2xl font-bold text-ink sm:text-3xl">{d.howTitle}</h2>
          <div className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {d.howSteps.map((s, i) => (
              <div key={s.t} className="card p-5">
                <div className="flex h-8 w-8 items-center justify-center rounded-full bg-brand text-sm font-bold text-white">{i + 1}</div>
                <div className="mt-3 font-semibold text-ink">{s.t}</div>
                <p className="mt-1 text-sm text-ink-soft">{s.d}</p>
              </div>
            ))}
          </div>
        </section>

        {/* ————————————————————— Kanıt-bağlama (üç katman) ————————————————————— */}
        <section>
          <h2 className="text-2xl font-bold text-ink sm:text-3xl">{d.evTitle}</h2>
          <div className="mt-6 grid gap-4 sm:grid-cols-3">
            <div className="rounded-card border-l-4 border-emerald-500 bg-emerald-50 p-4 text-sm text-emerald-900">
              <div className="font-bold">Kanıtlı</div>
              <p className="mt-1">{d.evKanitli}</p>
            </div>
            <div className="rounded-card border-l-4 border-amber-500 bg-amber-50 p-4 text-sm text-amber-900">
              <div className="font-bold">Belirsiz</div>
              <p className="mt-1">{d.evBelirsiz}</p>
            </div>
            <div className="rounded-card border-l-4 border-line bg-canvas p-4 text-sm text-ink-muted">
              <div className="font-bold line-through decoration-1">Hayalet</div>
              <p className="mt-1">{d.evHayalet}</p>
            </div>
          </div>
        </section>

        {/* ————————————————————— 6 paketten fark (tablo) ————————————————————— */}
        <section>
          <h2 className="text-2xl font-bold text-ink sm:text-3xl">{d.compareTitle}</h2>
          <p className="mt-3 max-w-2xl text-sm text-ink-soft">{d.diffBody}</p>
          <div className="mt-6 overflow-x-auto">
            <table className="w-full min-w-[560px] border-collapse text-sm">
              <thead>
                <tr>
                  <th className="w-40 border-b border-line px-3 py-3 text-left font-semibold text-ink-muted"></th>
                  <th className="border-b border-line px-3 py-3 text-left font-bold text-ink">{d.compareCol1}</th>
                  <th className="border-b-2 border-brand px-3 py-3 text-left font-bold text-brand">{d.compareCol2}</th>
                </tr>
              </thead>
              <tbody>
                {d.compareRows.map((r) => (
                  <tr key={r.k} className="align-top">
                    <td className="border-b border-line px-3 py-3 text-[11px] font-semibold uppercase tracking-wide text-ink-muted">{r.k}</td>
                    <td className="border-b border-line px-3 py-3 text-ink-soft">{r.a}</td>
                    <td className="border-b border-line bg-brand-50/40 px-3 py-3 font-medium text-ink">{r.b}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Link href={packagesHref} className="mt-4 inline-block text-sm font-semibold text-accent-600 hover:underline">{d.compareLink}</Link>
        </section>

        {/* ————————————————————— Başlatmadan önce (kompakt uyarı) ————————————————————— */}
        <section className="rounded-card border border-amber-300 bg-amber-50/60 p-6">
          <h2 className="text-base font-bold text-amber-900">⚠ {d.warnTitle}</h2>
          <ul className="mt-3 grid gap-x-6 gap-y-2 sm:grid-cols-2">
            {d.warnPoints.map((p) => (
              <li key={p} className="flex gap-2 text-sm text-amber-900">
                <span aria-hidden className="mt-0.5 font-bold">•</span>
                <span>{p}</span>
              </li>
            ))}
          </ul>
        </section>

        {/* ————————————————————— Satın alma paneli (beta kapısı) ————————————————————— */}
        <section id="panel" className="mx-auto max-w-2xl scroll-mt-24">
          <RedTeamGate d={d} />
        </section>

        {/* ————————————————————— Kanıt & dürüstlük ilkesi + disclaimer ————————————————————— */}
        <section className="card p-6">
          <h2 className="text-lg font-bold text-ink">{d.principleTitle}</h2>
          <p className="mt-2 text-sm text-ink-soft">{d.principleBody}</p>
          <DisclaimerReveal text={d.disclaimer} word={d.triggerWord} className="mt-4 border-t border-line pt-4 text-xs text-ink-muted" />
        </section>
      </div>

      {/* ————————————————————— Son CTA bandı ————————————————————— */}
      <section className="bg-brand-deep">
        <div className="container-page flex flex-col items-center gap-4 py-14 text-center">
          <h2 className="max-w-xl text-balance text-2xl font-bold text-white">{d.ctaBandTitle}</h2>
          <a href="#panel" className="btn btn-primary">{d.ctaBandBtn}</a>
        </div>
      </section>
    </main>
  );
}

function Row({ label, value, dot }: { label: string; value: string; dot: string }) {
  return (
    <div className="flex gap-2">
      <span aria-hidden className={`mt-0.5 shrink-0 ${dot}`}>▪</span>
      <div>
        <dt className="text-[11px] font-semibold uppercase tracking-wide text-ink-muted">{label}</dt>
        <dd className="mt-0.5 text-ink-soft">{value}</dd>
      </div>
    </div>
  );
}
