'use client';

import { useState } from 'react';
import Link from 'next/link';

/**
 * (Paketler sayfası) Paketleri BİRBİRİYLE kıyaslayan tablo + kural-tabanlı "size uygun paket" sihirbazı.
 * Ana sayfadaki genel "vs geleneksel pentest" anlatısını TEKRARLAMAZ; buradaki amaç "hangi paket bana
 * uygun" sorusunu netleştirmek. Rakip ürün/şirket adı GEÇMEZ — yalnız kendi paketlerimiz kıyaslanır.
 *
 * TÜM metinler sunucudan (t3 ile) lokalize gelir → bileşende hardcode dil YOK.
 * Tüm değerler gerçek paket tanımlarından türetilir (fiyat/kontrol sayısı/kategori) — uydurma yok.
 */
export type CompareCol = {
  key: string;
  name: string;
  price: string;
  kind: string;        // Test türü (Pasif / Aktif-hafif / Uyum / Otonom)
  checks: string;      // "5 kontrol" vb.
  scope: string;       // kısa kapsam özeti
  sample: boolean;     // örnek rapor PDF var mı
  dnsRequired: boolean;
  experimental: boolean;
  fit: string;         // kime uygun
  href: string;
  badge?: string;
};

export type CompareLabels = {
  eyebrow: string; title: string; subtitle: string;
  rowPrice: string; rowKind: string; rowChecks: string; rowScope: string; rowEvidence: string;
  rowSample: string; rowDns: string; rowExperimental: string; rowFit: string;
  yes: string; no: string; deterministic: string; experimentalTag: string;
  view: string; scrollHint: string; recoBadge: string;
  // Sihirbaz
  wizTitle: string; wizIntro: string; wizQ1: string; wizQ2: string; wizQ3: string;
  wizFirstYes: string; wizFirstNo: string;
  wizGoals: Array<{ id: string; label: string }>;
  wizExpYes: string; wizExpNo: string;
  wizResult: string; wizAlso: string; wizReset: string; wizPick: string;
};

export function PackageCompare({ cols, labels, redTeamKey }: { cols: CompareCol[]; labels: CompareLabels; redTeamKey: string | null }) {
  const L = labels;

  // --- Sihirbaz (deterministik kural tablosu; LLM yok, abartılı vaat yok) ---
  const [first, setFirst] = useState<boolean | null>(null);
  const [goal, setGoal] = useState<string | null>(null);
  const [exp, setExp] = useState<boolean | null>(null);
  const showExp = !!redTeamKey; // Deneysel soru yalniz Red Team olan bolgede (TR) anlamli
  const answered = first !== null && goal !== null && (showExp ? exp !== null : true);

  // Hedef -> paket anahtarı (birebir, gerçek paketlere)
  const GOAL_MAP: Record<string, string> = {
    quick: 'basit_tarama',
    surface: 'bundle_surface',
    discovery: 'bundle_recon',
    compliance: 'bundle_compliance',
    proof: 'bundle_active_verify',
    deep: 'bundle_full_pentest',
  };
  const primaryKey = goal ? GOAL_MAP[goal] : null;
  const primary = cols.find((c) => c.key === primaryKey) ?? null;
  // İkincil öneri: (a) ilk kez tarama + ileri paket seçtiyse başlangıç paketi, (b) deneyseli kabul
  // ediyorsa ve Red Team bu bölgede varsa onu EK seçenek olarak göster (yerine geçmez).
  const secondaries: typeof cols = [];
  if (first === true && primaryKey && primaryKey !== 'basit_tarama') {
    const b = cols.find((c) => c.key === 'basit_tarama');
    if (b) secondaries.push(b);
  }
  if (exp === true && redTeamKey) {
    const rt = cols.find((c) => c.key === redTeamKey);
    if (rt) secondaries.push(rt);
  }

  const Check = ({ on }: { on: boolean }) => (
    <span className={on ? 'font-bold text-emerald-600' : 'text-ink-muted'} aria-label={on ? L.yes : L.no}>
      {on ? '✓' : '✗'}
    </span>
  );

  const ROWS: Array<{ label: string; render: (c: CompareCol) => React.ReactNode }> = [
    { label: L.rowPrice, render: (c) => <span className="font-bold text-brand">{c.price}</span> },
    { label: L.rowKind, render: (c) => c.kind },
    { label: L.rowChecks, render: (c) => c.checks },
    { label: L.rowScope, render: (c) => <span className="text-ink-soft">{c.scope}</span> },
    { label: L.rowEvidence, render: () => <Check on={true} /> },
    { label: L.rowSample, render: (c) => <Check on={c.sample} /> },
    { label: L.rowDns, render: (c) => <Check on={c.dnsRequired} /> },
    {
      label: L.rowExperimental,
      render: (c) =>
        c.experimental ? (
          <span className="inline-block rounded-pill bg-amber-100 px-2 py-0.5 text-[11px] font-bold text-amber-800">{L.experimentalTag}</span>
        ) : (
          <span className="text-ink-soft">{L.deterministic}</span>
        ),
    },
    { label: L.rowFit, render: (c) => <span className="text-ink-soft">{c.fit}</span> },
  ];

  return (
    <section id="karsilastirma" className="mt-20 scroll-mt-24 border-t border-line pt-14">
      {/* Bölüm başlığı: sayfa içinde kaybolmasın diye ortalanmış, rozetli ve büyük punto. */}
      <div className="text-center">
        <span className="inline-block rounded-pill bg-accent-soft px-4 py-1.5 text-xs font-extrabold uppercase tracking-widest text-brand">
          {L.eyebrow}
        </span>
        <h2 className="mt-4 text-3xl font-extrabold tracking-tight text-brand sm:text-4xl">{L.title}</h2>
        <p className="mx-auto mt-3 max-w-2xl text-base leading-relaxed text-ink-soft">{L.subtitle}</p>
      </div>

      {/* ================= SİHİRBAZ ================= */}
      <div className="mt-8 rounded-2xl border border-line bg-white p-5 shadow-card sm:p-6">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h3 className="text-base font-bold text-brand">{L.wizTitle}</h3>
            <p className="mt-1 text-sm text-ink-soft">{L.wizIntro}</p>
          </div>
          {primary && (
            <span className="inline-flex items-center gap-2 self-start rounded-full border border-accent/40 bg-accent-soft/60 px-3 py-1.5 text-xs font-bold text-brand">
              <span className="font-mono text-[10px] uppercase tracking-wider text-accent-600">{L.recoBadge}</span>
              {primary.name}
            </span>
          )}
        </div>

        <div className="mt-5 space-y-5">
          <div>
            <div className="flex items-center gap-2"><span aria-hidden className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-brand text-[11px] font-bold text-white">1</span><p className="text-sm font-bold text-brand">{L.wizQ1}</p></div>
            <div className="mt-2 flex flex-wrap gap-2">
              {[{ v: true, l: L.wizFirstYes }, { v: false, l: L.wizFirstNo }].map((o) => (
                <button key={String(o.v)} type="button" onClick={() => setFirst(o.v)}
                  className={`rounded-pill border px-3.5 py-1.5 text-sm font-semibold transition ${first === o.v ? 'border-accent bg-accent text-white' : 'border-line bg-canvas text-ink-soft hover:border-accent hover:text-brand'}`}>
                  {o.l}
                </button>
              ))}
            </div>
          </div>

          <div>
            <div className="flex items-center gap-2"><span aria-hidden className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-brand text-[11px] font-bold text-white">2</span><p className="text-sm font-bold text-brand">{L.wizQ2}</p></div>
            <div className="mt-2 flex flex-wrap gap-2">
              {L.wizGoals.filter((g) => cols.some((c) => c.key === GOAL_MAP[g.id])).map((g) => (
                <button key={g.id} type="button" onClick={() => setGoal(g.id)}
                  className={`rounded-pill border px-3.5 py-1.5 text-sm font-semibold transition ${goal === g.id ? 'border-accent bg-accent text-white' : 'border-line bg-canvas text-ink-soft hover:border-accent hover:text-brand'}`}>
                  {g.label}
                </button>
              ))}
            </div>
          </div>

          {showExp && (
          <div>
            <div className="flex items-center gap-2"><span aria-hidden className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-brand text-[11px] font-bold text-white">3</span><p className="text-sm font-bold text-brand">{L.wizQ3}</p></div>
            <div className="mt-2 flex flex-wrap gap-2">
              {[{ v: true, l: L.wizExpYes }, { v: false, l: L.wizExpNo }].map((o) => (
                <button key={String(o.v)} type="button" onClick={() => setExp(o.v)}
                  className={`rounded-pill border px-3.5 py-1.5 text-sm font-semibold transition ${exp === o.v ? 'border-accent bg-accent text-white' : 'border-line bg-canvas text-ink-soft hover:border-accent hover:text-brand'}`}>
                  {o.l}
                </button>
              ))}
            </div>
          </div>
          )}
        </div>

        {answered && primary && (
          <div className="mt-5 rounded-card border border-accent/40 bg-white p-4">
            <p className="text-xs font-bold uppercase tracking-wide text-ink-muted">{L.wizResult}</p>
            <div className="mt-2 flex flex-wrap items-center justify-between gap-3">
              <div className="min-w-0">
                <p className="text-lg font-extrabold text-brand">{primary.name}</p>
                <p className="mt-0.5 text-sm text-ink-soft">{primary.price} · {primary.scope}</p>
              </div>
              <Link href={primary.href} className="btn-primary shrink-0 px-5">{L.wizPick}</Link>
            </div>
            {secondaries.length > 0 && (
              <div className="mt-4 border-t border-line pt-3">
                <p className="text-xs font-semibold text-ink-muted">{L.wizAlso}</p>
                <ul className="mt-1.5 space-y-1.5">
                  {secondaries.map((s) => (
                    <li key={s.key} className="flex flex-wrap items-center gap-x-2 text-sm">
                      <Link href={s.href} className="font-semibold text-accent-600 hover:underline">{s.name}</Link>
                      <span className="text-ink-muted">· {s.price}</span>
                      {s.experimental && (
                        <span className="rounded-pill bg-amber-100 px-2 py-0.5 text-[11px] font-bold text-amber-800">{L.experimentalTag}</span>
                      )}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            <button type="button" onClick={() => { setFirst(null); setGoal(null); setExp(null); }}
              className="mt-3 text-xs font-semibold text-ink-muted underline hover:text-ink">{L.wizReset}</button>
          </div>
        )}
      </div>

      {/* ================= TABLO — masaüstü ================= */}
      <p className="mt-10 text-xs text-ink-muted md:hidden">{L.scrollHint}</p>
      <div className="mt-4 hidden overflow-x-auto md:block">
        <table className="w-full min-w-[820px] border-collapse text-sm">
          <thead>
            <tr>
              <th className="sticky left-0 z-10 border-b border-line bg-canvas p-3 text-left text-xs font-bold uppercase tracking-wide text-ink-muted">&nbsp;</th>
              {cols.map((c) => (
                <th key={c.key} className={`border-b border-line p-3 text-left align-bottom ${c.key === primaryKey ? 'bg-accent-soft/40' : ''}`}>
                  <span className="block font-extrabold text-brand">{c.name}</span>
                  {c.badge && (
                    <span className={`mt-1 inline-block rounded-pill px-2 py-0.5 text-[10px] font-bold ${c.experimental ? 'bg-amber-100 text-amber-800' : 'bg-accent-soft text-brand'}`}>{c.badge}</span>
                  )}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {ROWS.map((r, i) => (
              <tr key={r.label} className={i % 2 ? 'bg-brand-50/30' : ''}>
                <th scope="row" className="sticky left-0 z-10 border-b border-line/70 bg-inherit p-3 text-left text-xs font-bold uppercase tracking-wide text-ink-muted">{r.label}</th>
                {cols.map((c) => (
                  <td key={c.key} className={`border-b border-line/70 p-3 align-top ${c.key === primaryKey ? 'bg-accent-soft/30' : ''}`}>{r.render(c)}</td>
                ))}
              </tr>
            ))}
            <tr>
              <th scope="row" className="sticky left-0 z-10 bg-canvas p-3">&nbsp;</th>
              {cols.map((c) => (
                <td key={c.key} className={`p-3 align-top ${c.key === primaryKey ? 'bg-accent-soft/40' : ''}`}>
                  <Link href={c.href} className={`${c.key === primaryKey ? 'btn-primary' : 'btn-outline'} w-full justify-center text-xs`}>{L.view}</Link>
                </td>
              ))}
            </tr>
          </tbody>
        </table>
      </div>

      {/* ================= KARTLAR — mobil ================= */}
      <div className="mt-4 space-y-3 md:hidden">
        {cols.map((c) => (
          <div key={c.key} className="card p-4">
            <div className="flex flex-wrap items-center gap-2">
              <p className="font-extrabold text-brand">{c.name}</p>
              {c.badge && (
                <span className={`rounded-pill px-2 py-0.5 text-[10px] font-bold ${c.experimental ? 'bg-amber-100 text-amber-800' : 'bg-accent-soft text-brand'}`}>{c.badge}</span>
              )}
            </div>
            <dl className="mt-3 space-y-1.5 text-sm">
              {ROWS.map((r) => (
                <div key={r.label} className="flex items-start justify-between gap-3">
                  <dt className="shrink-0 text-xs font-semibold uppercase tracking-wide text-ink-muted">{r.label}</dt>
                  <dd className="text-right">{r.render(c)}</dd>
                </div>
              ))}
            </dl>
            <Link href={c.href} className="btn-outline mt-4 w-full justify-center text-xs">{L.view}</Link>
          </div>
        ))}
      </div>

    </section>
  );
}
