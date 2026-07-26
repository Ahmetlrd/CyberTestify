import { LiveDemo } from './LiveDemo';
import type { RegionConfig } from '../../config/regions';
import { getDict } from '../../config/i18n';

function Icon({ name, className }: { name: string; className?: string }) {
  const paths: Record<string, string> = {
    clock: 'M12 7v5l3 2M12 3a9 9 0 100 18 9 9 0 000-18z',
    bolt: 'M13 2L4 14h7l-1 8 9-12h-7l1-8z',
  };
  return (
    <svg viewBox="0 0 24 24" className={className} fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d={paths[name]} />
    </svg>
  );
}

export function AutonomousSection({ region }: { region: RegionConfig }) {
  const d = getDict(region).auto;

  return (
    <section className="container-page py-20">
      <div className="mx-auto max-w-2xl text-center">
        <p className="eyebrow">{d.eyebrow}</p>
        <h2 className="mt-3 text-3xl font-extrabold leading-tight text-brand sm:text-[2.6rem]">
          {d.titleA}
          <br className="hidden sm:block" /> <span className="text-accent-600">{d.titleHi}</span> {d.titleB}
        </h2>
        <p className="mt-4 text-lg text-ink-soft">{d.subtitle}</p>
      </div>

      <div className="mx-auto mt-12 grid max-w-4xl gap-5 sm:grid-cols-2">
        {/* Geleneksel — soluk / yavaş */}
        <div className="rounded-card border border-line bg-[#F2F1EC] p-7 opacity-90 grayscale">
          <div className="flex items-center gap-2 text-ink-muted">
            <Icon name="clock" className="h-5 w-5" />
            <span className="text-sm font-bold uppercase tracking-wide">{d.tradTitle}</span>
          </div>
          <ul className="mt-5 space-y-3">
            {d.trad.map((t) => (
              <li key={t} className="flex items-center gap-3 text-ink-muted">
                <Icon name="clock" className="h-5 w-5 shrink-0 opacity-50" />
                <span className="text-sm">{t}</span>
              </li>
            ))}
          </ul>
        </div>

        {/* CyberTestify — canlı / hızlı */}
        <div className="relative overflow-hidden rounded-card border-2 border-brand-300 bg-white p-7 shadow-glow">
          <span className="absolute -right-9 top-4 rotate-45 bg-accent px-10 py-1 text-[11px] font-bold text-ink">
            {d.ribbon}
          </span>
          <div className="flex items-center gap-2 text-brand">
            <Icon name="bolt" className="h-5 w-5 text-accent-600" />
            <span className="text-sm font-bold uppercase tracking-wide">{d.oursTitle}</span>
          </div>
          <ul className="mt-5 space-y-3">
            {d.ours.map((t) => (
              <li key={t} className="flex items-center gap-3 text-ink">
                <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-accent-soft">
                  <Icon name="bolt" className="h-3.5 w-3.5 text-accent-600" />
                </span>
                <span className="text-sm font-medium">{t}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>

      <div className="mx-auto mt-10 max-w-2xl">
        <p className="mb-3 text-center text-sm font-medium text-ink-muted">{d.demo}</p>
        <LiveDemo lang={region.lang} />
      </div>
    </section>
  );
}
