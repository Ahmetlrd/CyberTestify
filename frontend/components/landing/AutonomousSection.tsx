import { LiveDemo } from './LiveDemo';

const TRADITIONAL = [
  ['2–4 hafta bekleme süresi', 'clock'],
  ['$2.000 – $6.000 arası maliyet', 'money'],
  ['İnsan ekibiyle randevu / demo', 'people'],
  ['Yılda yalnızca 1–2 kez', 'calendar'],
];

const OURS = [
  ['Dakikalar içinde başlar', 'bolt'],
  ['Saatler içinde biter', 'bolt'],
  ['Tamamen otonom AI ajanları', 'bolt'],
  ['İstediğiniz an, sınırsız tekrar', 'bolt'],
];

function Icon({ name, className }: { name: string; className?: string }) {
  const paths: Record<string, string> = {
    clock: 'M12 7v5l3 2M12 3a9 9 0 100 18 9 9 0 000-18z',
    money: 'M12 3v18M8 8h6a2 2 0 010 4H9a2 2 0 000 4h7',
    people: 'M9 11a3 3 0 100-6 3 3 0 000 6zM2 21v-1a5 5 0 015-5h4a5 5 0 015 5v1M17 11a3 3 0 10-1-5.8',
    calendar: 'M7 3v3M17 3v3M4 8h16M5 6h14v14H5z',
    bolt: 'M13 2L4 14h7l-1 8 9-12h-7l1-8z',
  };
  return (
    <svg viewBox="0 0 24 24" className={className} fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d={paths[name]} />
    </svg>
  );
}

export function AutonomousSection() {
  return (
    <section className="container-page py-20">
      <div className="mx-auto max-w-2xl text-center">
        <p className="eyebrow">Tamamen Otonom AI · Asıl Farkımız</p>
        <h2 className="mt-3 text-3xl font-extrabold leading-tight text-brand sm:text-[2.6rem]">
          Haftalarca beklemeyin.
          <br className="hidden sm:block" /> <span className="text-accent-600">Dakikalar</span> içinde başlayın.
        </h2>
        <p className="mt-4 text-lg text-ink-soft">
          Rakiplerimiz insan pentester ekipleriyle çalışır — bu yüzden pahalı ve yavaştır. Biz
          tamamen otonom yapay zekayız: hem çok daha ucuz, hem çok daha hızlı.
        </p>
      </div>

      {/* Yan yana karsilastirma: soluk (geleneksel) vs canli (biz) */}
      <div className="mx-auto mt-12 grid max-w-4xl gap-5 sm:grid-cols-2">
        {/* Geleneksel — soluk / yavas */}
        <div className="rounded-card border border-line bg-[#F2F1EC] p-7 opacity-90 grayscale">
          <div className="flex items-center gap-2 text-ink-muted">
            <Icon name="clock" className="h-5 w-5" />
            <span className="text-sm font-bold uppercase tracking-wide">Geleneksel Pentest</span>
          </div>
          <ul className="mt-5 space-y-3">
            {TRADITIONAL.map(([t, ic]) => (
              <li key={t} className="flex items-center gap-3 text-ink-muted">
                <Icon name={ic} className="h-5 w-5 shrink-0 opacity-60" />
                <span className="text-sm">{t}</span>
              </li>
            ))}
          </ul>
        </div>

        {/* CyberTestify — canli / hizli */}
        <div className="relative overflow-hidden rounded-card border-2 border-brand-300 bg-white p-7 shadow-glow">
          <span className="absolute -right-9 top-4 rotate-45 bg-accent px-10 py-1 text-[11px] font-bold text-ink">
            SİZİN İÇİN
          </span>
          <div className="flex items-center gap-2 text-brand">
            <Icon name="bolt" className="h-5 w-5 text-accent-600" />
            <span className="text-sm font-bold uppercase tracking-wide">CyberTestify</span>
          </div>
          <ul className="mt-5 space-y-3">
            {OURS.map(([t]) => (
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

      {/* Canli demo — "gercekten calisiyor" hissi */}
      <div className="mx-auto mt-10 max-w-2xl">
        <p className="mb-3 text-center text-sm font-medium text-ink-muted">
          Gerçek zamanlı — ajan çalışırken:
        </p>
        <LiveDemo />
      </div>
    </section>
  );
}
