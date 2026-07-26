'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { api } from '../../lib/api';

type Pkg = { key: string; displayName: string; description: string; priceMinorUnit: number };

const POPULAR_KEY = 'pci_hazirlik';

export function PricingPreview() {
  const [packages, setPackages] = useState<Pkg[]>([]);
  const [error, setError] = useState(false);

  useEffect(() => {
    api.listPackages().then(setPackages).catch(() => setError(true));
  }, []);

  return (
    <section id="paketler" className="container-page scroll-mt-20 py-20">
      <div className="mx-auto max-w-2xl text-center">
        <p className="eyebrow">Paketler</p>
        <h2 className="mt-3 text-3xl font-extrabold text-brand sm:text-4xl">
          Sabit kapsam, sabit fiyat, sürpriz yok
        </h2>
        <p className="mt-4 text-ink-soft">
          İhtiyacınıza uygun paketi seçin; doğrulama sonrası tek tıkla başlatın. Tüm fiyatlar
          vergiler dahildir.
        </p>
      </div>

      {error && (
        <p className="mt-8 text-center text-sm text-ink-muted">
          Paketler şu an yüklenemedi. <Link href="/register" className="text-accent-600 underline">Yine de başlayın →</Link>
        </p>
      )}

      <div className="mt-12 grid gap-6 md:grid-cols-2 lg:grid-cols-3">
        {packages.map((p) => {
          const popular = p.key === POPULAR_KEY;
          return (
            <div
              key={p.key}
              className={`card relative flex flex-col p-6 ${popular ? 'ring-2 ring-accent' : ''}`}
            >
              {popular && (
                <span className="absolute -top-3 left-6 rounded-pill bg-accent px-3 py-1 text-xs font-bold text-ink">
                  Popüler
                </span>
              )}
              <h3 className="text-lg font-bold text-brand">{p.displayName}</h3>
              <p className="mt-2 flex-1 text-sm leading-relaxed text-ink-soft">{p.description}</p>
              <div className="mt-5">
                <span className="text-3xl font-extrabold text-ink">
                  {(p.priceMinorUnit / 100).toLocaleString('tr-TR')}
                </span>
                <span className="ml-1 text-sm font-medium text-ink-muted">TRY</span>
                <span className="ml-1 text-xs text-ink-muted">/ tarama · vergiler dahil</span>
              </div>
              <Link href="/register" className={`mt-6 ${popular ? 'btn-primary' : 'btn-outline'} w-full`}>
                Seç ve Doğrula
              </Link>
            </div>
          );
        })}

        {/* BYOK — gelişmiş kullanıcı kartı (ayrı, en sonda) */}
        <div className="card flex flex-col border-dashed p-6">
          <span className="badge w-fit">Gelişmiş Kullanıcılar İçin</span>
          <h3 className="mt-3 text-lg font-bold text-brand">Kendi API Anahtarınla (BYOK)</h3>
          <p className="mt-2 flex-1 text-sm leading-relaxed text-ink-soft">
            Kendi Anthropic anahtarınızla, daha geniş kapsamlı bir tarama. Teknik kullanıcılar için;
            maliyet kontrolü sizde.
          </p>
          <Link href="/register" className="btn-ghost mt-6 w-full">
            Yakında →
          </Link>
        </div>
      </div>
    </section>
  );
}
