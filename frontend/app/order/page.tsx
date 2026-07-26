'use client';

import { useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { api } from '../../lib/api';

type Pkg = { key: string; displayName: string; description: string; priceMinorUnit: number };

export default function OrderPage() {
  const router = useRouter();
  const domainId = useSearchParams().get('domainId');
  const [packages, setPackages] = useState<Pkg[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [authConsent, setAuthConsent] = useState(false);
  const [contractConsent, setContractConsent] = useState(false);
  const [withdrawalConsent, setWithdrawalConsent] = useState(false);
  const allConsents = authConsent && contractConsent && withdrawalConsent;

  useEffect(() => {
    if (typeof window !== 'undefined' && !window.localStorage.getItem('token')) {
      router.push('/login');
      return;
    }
    api.listPackages().then(setPackages).catch((err) => setError(err.message));
  }, [router]);

  async function handleStart() {
    if (!domainId || busy) return;
    if (!selected) return setError('Lütfen bir paket seçin.');
    if (!allConsents) return setError('Devam etmek için üç onayın tümünü işaretlemelisiniz.');
    setBusy(true);
    setError(null);
    try {
      const res = await api.createOrder(domainId, selected, {
        ownershipConfirmed: authConsent,
        distanceContractAccepted: contractConsent,
        withdrawalWaived: withdrawalConsent,
      });
      window.location.href = res.paymentPageUrl;
    } catch (err: any) {
      setError(err.message);
      setBusy(false);
    }
  }

  const consents: Array<[boolean, (v: boolean) => void, React.ReactNode]> = [
    [
      authConsent,
      setAuthConsent,
      <>
        Bu alan adının <strong>ve bağlı altyapısının</strong> münhasır sahibi olduğumu veya adına
        işlem yapmaya yasal olarak yetkili olduğumu; yalnızca bu alan adı kapsamında saldırgan olmayan
        pasif bir tarama yapılmasına rıza gösterdiğimi beyan ederim.
      </>,
    ],
    [
      contractConsent,
      setContractConsent,
      <>
        <Link href="/legal/on-bilgilendirme" target="_blank" className="text-accent-600 underline">
          Ön Bilgilendirme Formu
        </Link>{' '}
        ve{' '}
        <Link href="/legal/mesafeli-satis" target="_blank" className="text-accent-600 underline">
          Mesafeli Satış Sözleşmesi
        </Link>
        &apos;ni okudum, onaylıyorum.
      </>,
    ],
    [
      withdrawalConsent,
      setWithdrawalConsent,
      <>
        Hizmetin dijital olarak <strong>anında ifa</strong> edildiğini; açık onayımla ifasına hemen
        başlanacağını ve md. 15 uyarınca <strong>cayma hakkımı kullanamayacağımı</strong> kabul ediyorum.
      </>,
    ],
  ];

  return (
    <main className="container-page max-w-3xl py-14">
      <h1 className="text-3xl font-extrabold text-brand">Taramanızı Başlatın</h1>
      {!domainId && (
        <p className="mt-3 rounded-card border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
          Önce site sahipliğinizi doğrulamalısınız.{' '}
          <Link href="/verify" className="font-semibold underline">
            Doğrulamaya git →
          </Link>
        </p>
      )}

      {/* Paket seçimi */}
      <h2 className="mt-8 text-sm font-bold uppercase tracking-wide text-ink-muted">1 · Paket seçin</h2>
      <div className="mt-3 grid gap-3 sm:grid-cols-2">
        {packages.map((p) => {
          const on = selected === p.key;
          return (
            <button
              key={p.key}
              type="button"
              onClick={() => setSelected(p.key)}
              className={`card p-4 text-left transition ${on ? 'ring-2 ring-accent' : 'hover:border-brand-300'}`}
            >
              <div className="flex items-start justify-between gap-2">
                <span className="font-bold text-brand">{p.displayName}</span>
                <span className={`mt-0.5 h-4 w-4 shrink-0 rounded-full border ${on ? 'border-accent bg-accent' : 'border-line'}`} />
              </div>
              <p className="mt-1 text-xs leading-relaxed text-ink-soft">{p.description}</p>
              <p className="mt-2 font-bold text-ink">
                {(p.priceMinorUnit / 100).toLocaleString('tr-TR')} TRY{' '}
                <span className="text-xs font-normal text-ink-muted">· vergiler dahil</span>
              </p>
            </button>
          );
        })}
      </div>

      {/* Onaylar */}
      <h2 className="mt-8 text-sm font-bold uppercase tracking-wide text-ink-muted">2 · Onaylar</h2>
      <div className="mt-3 space-y-2.5">
        {consents.map(([val, setVal, node], i) => (
          <label key={i} className="flex items-start gap-3 rounded-card border border-line bg-brand-50/50 p-3.5 text-sm text-ink-soft">
            <input type="checkbox" checked={val} onChange={(e) => setVal(e.target.checked)} className="mt-0.5 h-4 w-4 accent-brand" />
            <span>{node}</span>
          </label>
        ))}
      </div>

      {error && <p className="mt-4 text-sm text-red-600">{error}</p>}

      <button
        onClick={handleStart}
        disabled={!domainId || busy || !selected || !allConsents}
        className="btn-primary mt-6 w-full disabled:cursor-not-allowed disabled:opacity-50 sm:w-auto"
      >
        {busy ? 'Başlatılıyor…' : 'Taramayı Başlat'}
      </button>
      <p className="mt-3 text-xs text-ink-muted">Ödeme onaylandığında tarama otomatik ve anında başlar.</p>
    </main>
  );
}
