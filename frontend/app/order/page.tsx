'use client';

import { useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { api } from '../../lib/api';
import { readRegionCookie } from '../../lib/region';
import { getRegion, type RegionCode } from '../../config/regions';
import { formatMoney } from '../../config/i18n';

type Pkg = { key: string; displayName: string; description: string; priceMinorUnit: number; currency?: string };

export default function OrderPage() {
  const router = useRouter();
  const domainId = useSearchParams().get('domainId');
  const [packages, setPackages] = useState<Pkg[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [region, setRegion] = useState<RegionCode>('tr');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [authConsent, setAuthConsent] = useState(false);
  const [contractConsent, setContractConsent] = useState(false);
  const [withdrawalConsent, setWithdrawalConsent] = useState(false);
  const allConsents = authConsent && contractConsent && withdrawalConsent;

  // Düzenli (periyodik) tarama seçeneği
  const [recurring, setRecurring] = useState(false);
  const [intervalDays, setIntervalDays] = useState(7); // haftalık
  const [runs, setRuns] = useState(4);

  useEffect(() => {
    if (typeof window !== 'undefined' && !window.localStorage.getItem('token')) {
      router.push('/login');
      return;
    }
    const rc = readRegionCookie();
    setRegion(rc);
    api.listPackages(rc).then(setPackages).catch((err) => setError(err.message));
  }, [router]);

  async function handleStart() {
    if (!domainId || busy) return;
    if (!selected) return setError('Lütfen bir paket seçin.');
    if (!allConsents) return setError('Devam etmek için üç onayın tümünü işaretlemelisiniz.');
    setBusy(true);
    setError(null);
    try {
      if (recurring) {
        // Düzenli tarama: N tekrarlık kayıt oluştur; ilk tarama worker tarafından
        // kısa süre içinde başlar (concurrency=1 kuyruğuna girer).
        await api.createSchedule({ domainId, packageKey: selected, intervalDays, runs, region });
        router.push('/schedules');
        return;
      }
      const res = await api.createOrder(
        domainId,
        selected,
        {
          ownershipConfirmed: authConsent,
          distanceContractAccepted: contractConsent,
          withdrawalWaived: withdrawalConsent,
        },
        region,
      );
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
                {formatMoney(p.priceMinorUnit, getRegion(region))}{' '}
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

      {/* Düzenli tekrar (opsiyonel) */}
      <h2 className="mt-8 text-sm font-bold uppercase tracking-wide text-ink-muted">3 · Tekrar</h2>
      <div className="mt-3 space-y-2.5">
        <label className={`flex items-center gap-3 rounded-card border p-3.5 text-sm ${!recurring ? 'border-brand-300 bg-brand-50/50' : 'border-line'}`}>
          <input type="radio" checked={!recurring} onChange={() => setRecurring(false)} className="h-4 w-4 accent-brand" />
          <span className="font-medium text-ink">Tek seferlik tarama</span>
        </label>
        <label className={`flex items-center gap-3 rounded-card border p-3.5 text-sm ${recurring ? 'border-brand-300 bg-brand-50/50' : 'border-line'}`}>
          <input type="radio" checked={recurring} onChange={() => setRecurring(true)} className="h-4 w-4 accent-brand" />
          <span className="font-medium text-ink">Düzenli tekrarla</span>
        </label>
        {recurring && (
          <div className="rounded-card border border-line bg-white p-4">
            <div className="flex flex-wrap items-end gap-4">
              <div>
                <label className="label">Sıklık</label>
                <select value={intervalDays} onChange={(e) => setIntervalDays(Number(e.target.value))} className="field">
                  <option value={7}>Haftalık</option>
                  <option value={14}>İki haftada bir</option>
                  <option value={30}>Aylık</option>
                </select>
              </div>
              <div>
                <label className="label">Kaç tarama (peşin)</label>
                <input
                  type="number"
                  min={1}
                  max={52}
                  value={runs}
                  onChange={(e) => setRuns(Math.max(1, Math.min(52, Number(e.target.value))))}
                  className="field w-28"
                />
              </div>
            </div>
            <p className="mt-3 text-xs text-ink-muted">
              {runs} tarama için baştan ödeme yaparsınız; ilki hemen, sonrakiler seçtiğiniz sıklıkta
              çalışır. (Minimum sıklık: haftalık.)
            </p>
          </div>
        )}
      </div>

      {error && <p className="mt-4 text-sm text-red-600">{error}</p>}

      <button
        onClick={handleStart}
        disabled={!domainId || busy || !selected || !allConsents}
        className="btn-primary mt-6 w-full disabled:cursor-not-allowed disabled:opacity-50 sm:w-auto"
      >
        {busy ? 'Başlatılıyor…' : recurring ? 'Düzenli Taramayı Kur' : 'Taramayı Başlat'}
      </button>
      <p className="mt-3 text-xs text-ink-muted">
        {recurring
          ? 'İlk tarama hemen başlar; kayıtlarınızı “Zamanlanmış taramalarım” ekranından yönetebilirsiniz.'
          : 'Ödeme onaylandığında tarama otomatik ve anında başlar.'}
      </p>
    </main>
  );
}
