import Link from 'next/link';
import { AutonomousSection } from '../components/landing/AutonomousSection';

const DOT_BG = {
  backgroundImage: 'radial-gradient(rgba(255,255,255,0.08) 1px, transparent 1px)',
  backgroundSize: '22px 22px',
};

function Hero() {
  return (
    <section className="relative overflow-hidden bg-brand-deep text-white">
      <div className="pointer-events-none absolute inset-0" style={DOT_BG} />
      <div
        className="pointer-events-none absolute -right-40 -top-40 h-96 w-96 rounded-full opacity-30 blur-3xl"
        style={{ background: 'radial-gradient(circle, #1C6B60, transparent 70%)' }}
      />
      <div className="container-page relative py-20 sm:py-28">
        <div className="mx-auto max-w-3xl text-center">
          <span className="badge animate-fade-up border-white/15 bg-white/10 text-white/85">
            <span className="h-1.5 w-1.5 rounded-full bg-accent" /> Tamamen otonom AI · İnsan pentester beklemeyin
          </span>
          <h1 className="animate-fade-up mt-6 text-4xl font-extrabold leading-[1.08] sm:text-5xl md:text-[3.4rem]">
            Sitenizin güvenliğini,{' '}
            <span className="text-accent">5 dakikada</span> otonom yapay zeka ile test edin
          </h1>
          <p className="animate-fade-up mx-auto mt-6 max-w-xl text-lg leading-relaxed text-white/75">
            Karmaşık demo görüşmesi yok, satış ekibi beklemek yok. Alan adınızı doğrulayın, paketinizi
            seçin, şifreli raporunuzu alın.
          </p>
          <div className="animate-fade-up mt-9 flex flex-col items-center justify-center gap-3 sm:flex-row">
            <Link href="/register" className="btn-primary w-full sm:w-auto">
              Ücretsiz Doğrula ve Başla
            </Link>
            <Link href="#nasil-calisir" className="btn w-full border border-white/25 text-white hover:bg-white/10 sm:w-auto">
              Nasıl Çalışır?
            </Link>
          </div>
        </div>

        {/* Güven şeridi */}
        <div className="mx-auto mt-14 flex max-w-2xl flex-wrap items-center justify-center gap-x-8 gap-y-3 text-sm text-white/70">
          {[
            ['KVKK Uyumlu', 'M9 12l2 2 4-4'],
            ['Uçtan Uca Şifreli Rapor', 'M12 2l7 4v6c0 4.5-3 7.8-7 9-4-1.2-7-4.5-7-9V6l7-4z'],
            ['Sadece Doğrulanmış Alan Adları', 'M4 12l6 6L20 6'],
          ].map(([label, d]) => (
            <span key={label} className="flex items-center gap-2">
              <svg viewBox="0 0 24 24" className="h-4 w-4 text-accent" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d={d} />
              </svg>
              {label}
            </span>
          ))}
        </div>
      </div>
    </section>
  );
}

const STEPS = [
  { t: 'Alan adınızı doğrulayın', d: 'DNS TXT kaydıyla sahipliğinizi kanıtlayın — dakikalar sürer.', icon: 'M3 12h4l3 8 4-16 3 8h4' },
  { t: 'Paketinizi seçin', d: 'Sabit kapsam, sabit fiyat. Sürpriz maliyet yok.', icon: 'M4 6h16M4 12h16M4 18h10' },
  { t: 'Otonom AI taraması', d: 'Yapay zeka ajanları saniyeler içinde başlar, arka planda çalışır.', icon: 'M12 3a4 4 0 014 4v1a5 5 0 01-8 0V7a4 4 0 014-4zM6 21v-2a6 6 0 0112 0v2' },
  { t: 'Şifreli raporunuzu indirin', d: 'Uçtan uca şifreli, size özel tek kullanımlık kodla açılır.', icon: 'M6 10V7a6 6 0 1112 0v3M5 10h14v10H5z' },
];

function HowItWorks() {
  return (
    <section id="nasil-calisir" className="container-page scroll-mt-20 py-20">
      <div className="mx-auto max-w-2xl text-center">
        <p className="eyebrow">Nasıl Çalışır</p>
        <h2 className="mt-3 text-3xl font-extrabold text-brand sm:text-4xl">Dört adımda, baştan sona</h2>
      </div>
      <div className="mt-12 grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
        {STEPS.map((s, i) => (
          <div key={s.t} className="card p-6">
            <div className="flex h-11 w-11 items-center justify-center rounded-card bg-brand-50 text-brand">
              <svg viewBox="0 0 24 24" className="h-6 w-6" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <path d={s.icon} />
              </svg>
            </div>
            <div className="mt-4 text-xs font-bold text-accent-600">ADIM {i + 1}</div>
            <h3 className="mt-1 font-bold text-ink">{s.t}</h3>
            <p className="mt-2 text-sm leading-relaxed text-ink-soft">{s.d}</p>
          </div>
        ))}
      </div>
    </section>
  );
}

const REASONS = [
  {
    t: 'Kapsam Kilidi',
    d: 'Taramalarımız yalnızca sizin doğruladığınız alan adına erişebilir — teknik olarak başka hiçbir hedefe dokunamaz.',
    glow: true,
    icon: 'M12 2l7 4v6c0 4.5-3 7.8-7 9-4-1.2-7-4.5-7-9V6l7-4zM9 12l2 2 4-4',
  },
  {
    t: 'Kişisel Veri Koruması',
    d: 'Tarama sırasında karşılaşılan kişisel veriler, yapay zekaya ulaşmadan önce otomatik olarak maskelenir.',
    icon: 'M12 2l7 4v6c0 4.5-3 7.8-7 9-4-1.2-7-4.5-7-9V6l7-4zM12 8v4M12 15h.01',
  },
  {
    t: 'Şifreli, Tek Seferlik Teslim',
    d: 'Raporunuz uçtan uca şifrelenir; yalnızca size özel tek kullanımlık bir kodla açılır.',
    icon: 'M6 10V7a6 6 0 1112 0v3M5 10h14v10H5zM12 14v3',
  },
];

function WhyUs() {
  return (
    <section id="neden-biz" className="scroll-mt-20 bg-brand-50/60 py-20">
      <div className="container-page">
        <div className="mx-auto max-w-2xl text-center">
          <p className="eyebrow">Neden Biz</p>
          <h2 className="mt-3 text-3xl font-extrabold text-brand sm:text-4xl">
            İddia değil, teknik önlem
          </h2>
          <p className="mt-4 text-ink-soft">
            Rakiplerin çoğu güvenliği <em>söyler</em>. Biz onu koda gömdük.
          </p>
        </div>
        <div className="mt-12 grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
          {REASONS.map((r) => (
            <div
              key={r.t}
              className={`card p-6 ${r.glow ? 'border-brand-300 shadow-glow' : ''}`}
            >
              <div
                className={`flex h-11 w-11 items-center justify-center rounded-card ${
                  r.glow ? 'bg-brand text-accent' : 'bg-brand-50 text-brand'
                }`}
              >
                <svg viewBox="0 0 24 24" className="h-6 w-6" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
                  <path d={r.icon} />
                </svg>
              </div>
              <h3 className="mt-4 font-bold text-ink">{r.t}</h3>
              <p className="mt-2 text-sm leading-relaxed text-ink-soft">{r.d}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function FinalCTA() {
  return (
    <section className="container-page py-8 pb-20">
      <div className="relative overflow-hidden rounded-[20px] bg-brand-deep px-8 py-14 text-center text-white">
        <div className="pointer-events-none absolute inset-0" style={DOT_BG} />
        <div className="relative">
          <h2 className="text-3xl font-extrabold sm:text-4xl">Sitenizi test etmeye hazır mısınız?</h2>
          <p className="mx-auto mt-3 max-w-lg text-white/75">
            Doğrulama ücretsiz. Yalnızca taramayı başlattığınızda ödeme yaparsınız.
          </p>
          <div className="mt-8 flex flex-col items-center justify-center gap-3 sm:flex-row">
            <Link href="/register" className="btn-primary w-full sm:w-auto">
              Ücretsiz Doğrula ve Başla
            </Link>
            <Link href="/packages" className="btn w-full border border-white/25 text-white hover:bg-white/10 sm:w-auto">
              Fiyatları Gör →
            </Link>
          </div>
        </div>
      </div>
    </section>
  );
}

export default function HomePage() {
  return (
    <>
      <Hero />
      <AutonomousSection />
      <HowItWorks />
      <WhyUs />
      <FinalCTA />
    </>
  );
}
