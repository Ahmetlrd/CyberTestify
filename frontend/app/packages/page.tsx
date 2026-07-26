import Link from 'next/link';

export const metadata = {
  title: 'Fiyatlar — Web Sitesi Güvenlik Tarama Paketleri | CyberTestify',
  description:
    'Sabit kapsam, sabit fiyat, sürpriz maliyet yok. Otonom yapay zeka ile web sitesi güvenlik tarama paketleri ve fiyatları (TRY). Yerli sunucu, Türkçe destek, e-Arşiv faturalı.',
};

type Pkg = { key: string; displayName: string; description: string; priceMinorUnit: number };

const API = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000';
const POPULAR_KEY = 'pci_hazirlik';

async function getPackages(): Promise<Pkg[]> {
  try {
    const r = await fetch(`${API}/orders/packages`, { cache: 'no-store' });
    if (!r.ok) return [];
    return (await r.json()) as Pkg[];
  } catch {
    return [];
  }
}

const TRUST = ['🇹🇷 Yerli sunucu', '💬 Türkçe destek', '🧾 e-Arşiv faturalı', '🔒 Uçtan uca şifreli rapor'];

export default async function PackagesPage() {
  const packages = await getPackages();

  return (
    <>
      <section className="bg-brand-50/60 py-16">
        <div className="container-page text-center">
          <p className="eyebrow">Fiyatlar</p>
          <h1 className="mx-auto mt-3 max-w-2xl text-4xl font-extrabold text-brand sm:text-5xl">
            Şeffaf, sabit fiyatlandırma
          </h1>
          <p className="mx-auto mt-4 max-w-xl text-lg text-ink-soft">
            Kapsam sabit, fiyat sabit, sürpriz maliyet yok. Tüm fiyatlar vergiler dahildir.
          </p>
          <div className="mt-6 flex flex-wrap items-center justify-center gap-2.5">
            {TRUST.map((t) => (
              <span key={t} className="badge">
                {t}
              </span>
            ))}
          </div>
        </div>
      </section>

      <section className="container-page py-16">
        {packages.length === 0 ? (
          <p className="text-center text-sm text-ink-muted">
            Paketler şu an yüklenemedi.{' '}
            <Link href="/register" className="text-accent-600 underline">
              Yine de başlayın →
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
                      Popüler
                    </span>
                  )}
                  <h2 className="text-lg font-bold text-brand">{p.displayName}</h2>
                  <p className="mt-2 flex-1 text-sm leading-relaxed text-ink-soft">{p.description}</p>
                  <div className="mt-5">
                    <span className="text-3xl font-extrabold text-ink">
                      {(p.priceMinorUnit / 100).toLocaleString('tr-TR')}
                    </span>
                    <span className="ml-1 text-sm font-medium text-ink-muted">TRY</span>
                    <span className="ml-1 text-xs text-ink-muted">/ tarama</span>
                  </div>
                  <Link href="/register" className={`mt-6 w-full ${popular ? 'btn-primary' : 'btn-outline'}`}>
                    Seç ve Doğrula
                  </Link>
                </div>
              );
            })}

            {/* BYOK — gelişmiş kullanıcı kartı */}
            <div className="card flex flex-col border-dashed p-6">
              <span className="badge w-fit">Gelişmiş Kullanıcılar İçin</span>
              <h2 className="mt-3 text-lg font-bold text-brand">Kendi API Anahtarınla (BYOK)</h2>
              <p className="mt-2 flex-1 text-sm leading-relaxed text-ink-soft">
                Kendi Anthropic anahtarınızla daha geniş kapsamlı tarama. Teknik kullanıcılar için;
                maliyet kontrolü sizde.
              </p>
              <span className="mt-6 w-full btn-ghost cursor-default">Yakında</span>
            </div>
          </div>
        )}

        <div className="mt-14 rounded-[20px] bg-brand-deep px-8 py-12 text-center text-white">
          <h2 className="text-2xl font-extrabold sm:text-3xl">Doğrulama ücretsiz</h2>
          <p className="mx-auto mt-2 max-w-md text-white/75">
            Yalnızca taramayı başlattığınızda ödeme yaparsınız. Alan adınızı doğrulayarak başlayın.
          </p>
          <Link href="/register" className="btn-primary mt-7">
            Ücretsiz Doğrula ve Başla
          </Link>
        </div>
      </section>
    </>
  );
}
