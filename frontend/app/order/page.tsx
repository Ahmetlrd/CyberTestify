'use client';

import { useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { api } from '../../lib/api';
import { readRegionCookie } from '../../lib/region';
import { getRegion, type RegionCode } from '../../config/regions';
import { formatMoney } from '../../config/i18n';

type ActiveTest = { scope: { does: string[]; doesNot: string[] }; riskText: string; consentVersion: string };
type Pkg = {
  key: string; displayName: string; description: string; priceMinorUnit: number; currency?: string;
  securityProfile?: 'passive' | 'active-light'; activeTest?: ActiveTest | null;
};

// datetime-local `min` icin yerel saatte YYYY-MM-DDTHH:mm — gecmis tarihleri
// tarayici soluklastirir/secilemez yapar.
function minDateTimeLocal(): string {
  const d = new Date();
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}

export default function OrderPage() {
  const router = useRouter();
  const domainId = useSearchParams().get('domainId');
  const [packages, setPackages] = useState<Pkg[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [region, setRegion] = useState<RegionCode>('tr');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // (Is 2) Kredi bakiyesi + "krediyle öde" secenegi.
  const [balance, setBalance] = useState(0);
  const [creditUnit, setCreditUnit] = useState(99900);
  const [useCredits, setUseCredits] = useState(false);

  // (Faz 3 v2) active-light — tek risk-kabul checkbox'i (ek alan yok).
  const [atRisk, setAtRisk] = useState(false);
  // (#5) authenticated_scan — test hesabi kimlik bilgileri.
  const [authUser, setAuthUser] = useState('');
  const [authPass, setAuthPass] = useState('');

  const [authConsent, setAuthConsent] = useState(false);
  const [contractConsent, setContractConsent] = useState(false);
  const [withdrawalConsent, setWithdrawalConsent] = useState(false);
  const allConsents = authConsent && contractConsent && withdrawalConsent;

  // Düzenli (periyodik) tarama seçeneği
  const [recurring, setRecurring] = useState(false);
  const [intervalDays, setIntervalDays] = useState(7); // haftalık
  const [runs, setRuns] = useState(4);

  // Başlangıç zamanı: hemen mi, ileri tarih mi
  const [startMode, setStartMode] = useState<'now' | 'later'>('now');
  const [startAt, setStartAt] = useState(''); // datetime-local değeri

  useEffect(() => {
    if (typeof window !== 'undefined' && !window.localStorage.getItem('token')) {
      router.push('/login');
      return;
    }
    const rc = readRegionCookie();
    setRegion(rc);
    api.listPackages(rc).then(setPackages).catch((err) => setError(err.message));
    api.getCredits().then((c) => { setBalance(c.balance); setCreditUnit(c.creditUnitValueMinor); }).catch(() => {});
  }, [router]);

  const selectedPkg = packages.find((p) => p.key === selected);
  const isActiveLight = selectedPkg?.securityProfile === 'active-light';
  const needsAuthCreds = selected === 'authenticated_scan';
  const activeConsentOk = (!isActiveLight || atRisk) && (!needsAuthCreds || (authUser.trim() && authPass));
  const creditsNeeded = selectedPkg ? Math.max(1, Math.round(selectedPkg.priceMinorUnit / creditUnit)) : 0;
  // Kredi ile odeme yalnizca tek-seferlik/hemen taramada (zamanlanmis akis prepaid farkli).
  const canUseCredits = balance >= creditsNeeded && creditsNeeded > 0 && !recurring && startMode === 'now';

  async function handleStart() {
    if (!domainId || busy) return;
    if (!selected) return setError('Lütfen bir paket seçin.');
    if (!allConsents) return setError('Devam etmek için üç onayın tümünü işaretlemelisiniz.');
    if (isActiveLight && (recurring || startMode === 'later')) return setError('Aktif-test paketleri zamanlanamaz; tek seferlik ve hemen çalıştırılır.');
    if (!activeConsentOk) return setError('Aktif test için risk kabul kutusunu işaretlemelisiniz.');
    // İleri tarih seçildiyse geçerli ve gelecekte olmalı.
    let startAtIso: string | undefined;
    if (startMode === 'later') {
      const t = new Date(startAt);
      if (!startAt || Number.isNaN(t.getTime()) || t.getTime() <= Date.now()) {
        return setError('İleri tarih için gelecekte bir tarih/saat seçin.');
      }
      startAtIso = t.toISOString();
    }
    setBusy(true);
    setError(null);
    try {
      // Düzenli tarama VEYA ileri tarihli tek atış → zamanlama motoruna gider
      // (aynı concurrency=1 kuyruğu, doğrulama tazeliği kontrolü, prepaid-N).
      if (recurring || startMode === 'later') {
        await api.createSchedule({
          domainId,
          packageKey: selected,
          intervalDays: recurring ? intervalDays : 7, // tek atışta yok sayılır (runs=1)
          runs: recurring ? runs : 1,
          startAt: startAtIso,
          region,
        });
        router.push('/schedules');
        return;
      }
      const payWithCredits = useCredits && canUseCredits;
      const res = await api.createOrder(
        domainId,
        selected,
        {
          ownershipConfirmed: authConsent,
          distanceContractAccepted: contractConsent,
          withdrawalWaived: withdrawalConsent,
        },
        region,
        payWithCredits,
        isActiveLight ? { riskAccepted: atRisk } : undefined,
        needsAuthCreds ? { username: authUser.trim(), password: authPass } : undefined,
      );
      // Krediyle odendiyse odeme sayfasi YOK — dogrudan siparis detayina git.
      if (res.paidWithCredits) {
        router.push(`/dashboard/${res.orderId}`);
        return;
      }
      window.location.href = res.paymentPageUrl!;
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

      {/* Başlangıç zamanı */}
      <h2 className="mt-8 text-sm font-bold uppercase tracking-wide text-ink-muted">
        4 · Başlangıç {recurring && <span className="font-normal normal-case text-ink-muted">(ilk tarama)</span>}
      </h2>
      <div className="mt-3 space-y-2.5">
        <label className={`flex items-center gap-3 rounded-card border p-3.5 text-sm ${startMode === 'now' ? 'border-brand-300 bg-brand-50/50' : 'border-line'}`}>
          <input type="radio" checked={startMode === 'now'} onChange={() => setStartMode('now')} className="h-4 w-4 accent-brand" />
          <span className="font-medium text-ink">Hemen başlat</span>
        </label>
        <label className={`flex items-center gap-3 rounded-card border p-3.5 text-sm ${startMode === 'later' ? 'border-brand-300 bg-brand-50/50' : 'border-line'}`}>
          <input type="radio" checked={startMode === 'later'} onChange={() => setStartMode('later')} className="h-4 w-4 accent-brand" />
          <span className="font-medium text-ink">Belirli bir tarihte başlat</span>
        </label>
        {startMode === 'later' && (
          <div className="rounded-card border border-line bg-white p-4">
            <label className="label">Başlangıç tarihi ve saati</label>
            <input
              type="datetime-local"
              value={startAt}
              min={minDateTimeLocal()}
              onChange={(e) => setStartAt(e.target.value)}
              className="field"
            />
            <p className="mt-2 text-xs text-ink-muted">
              Tarama seçtiğiniz zamana en yakın kontrol turunda (birkaç dakika içinde) başlar.
            </p>
          </div>
        )}
      </div>

      {/* (Faz 3) Active-light yetkilendirme beyani — pasif onaylarin USTUNE, ayri blok */}
      {isActiveLight && selectedPkg?.activeTest && (
        <div className="mt-6 rounded-card border-2 border-accent/60 bg-accent-soft/30 p-5">
          <h3 className="text-base font-bold text-brand">Aktif Test Yetkilendirmesi (zorunlu)</h3>
          <p className="mt-1 text-sm text-ink-soft">
            Bu paket, zafiyeti <strong>doğrulamak</strong> için sınırlı aktif test istekleri gönderir. Devam etmek için
            kapsamı okuyup beyanı doldurmalısınız.
          </p>
          <div className="mt-3 grid gap-3 sm:grid-cols-2">
            <div className="rounded-card bg-white/70 p-3">
              <p className="text-xs font-bold uppercase tracking-wide text-brand-500">Bu tarama NE YAPAR</p>
              <ul className="mt-1 space-y-1 text-sm text-ink-soft">
                {selectedPkg.activeTest.scope.does.map((d) => (
                  <li key={d}>✅ {d}</li>
                ))}
              </ul>
            </div>
            <div className="rounded-card bg-white/70 p-3">
              <p className="text-xs font-bold uppercase tracking-wide text-red-600">Bu tarama NE YAPMAZ</p>
              <ul className="mt-1 space-y-1 text-sm text-ink-soft">
                {selectedPkg.activeTest.scope.doesNot.map((d) => (
                  <li key={d}>⛔ {d}</li>
                ))}
              </ul>
            </div>
          </div>
          <label className="mt-3 flex cursor-pointer items-start gap-2 text-sm font-medium text-ink">
            <input type="checkbox" checked={atRisk} onChange={(e) => setAtRisk(e.target.checked)} className="mt-0.5" />
            <span>{selectedPkg.activeTest.riskText}</span>
          </label>
          <p className="mt-2 text-xs text-ink-muted">
            Onayınız; hesabınız, zaman damgası, IP ve metin sürümü ile birlikte otomatik olarak kayıt altına alınır
            (ek bilgi girmenize gerek yoktur). İsterseniz bir yetkilendirme PDF’i olarak siparişinize bağlanır.
          </p>
          {needsAuthCreds && (
            <div className="mt-4 border-t border-accent/30 pt-4">
              <p className="text-sm font-semibold text-brand">Test hesabı bilgileri (login’li tarama için)</p>
              <p className="mt-1 text-xs text-ink-muted">
                Bilgiler şifrelenerek saklanır, yalnızca <strong>{selectedPkg.displayName}</strong> için ve yalnızca
                hedef domaininize karşı kullanılır, tarama başlayınca sistemden silinir.
              </p>
              <div className="mt-2 grid gap-3 sm:grid-cols-2">
                <input value={authUser} onChange={(e) => setAuthUser(e.target.value)} placeholder="Test kullanıcı adı" className="field" autoComplete="off" />
                <input value={authPass} onChange={(e) => setAuthPass(e.target.value)} placeholder="Test şifresi" type="password" className="field" autoComplete="new-password" />
              </div>
            </div>
          )}
        </div>
      )}

      {/* (Is 2) Kredi bakiyesi + krediyle öde */}
      {balance > 0 && (
        <div className="mt-5 rounded-card border border-brand-100 bg-brand-50/50 px-4 py-3 text-sm">
          <div className="flex items-center justify-between">
            <span className="text-ink-soft">Kredi bakiyeniz</span>
            <span className="font-bold text-brand">{balance} kredi</span>
          </div>
          {selected && canUseCredits && (
            <label className="mt-2 flex cursor-pointer items-start gap-2">
              <input type="checkbox" checked={useCredits} onChange={(e) => setUseCredits(e.target.checked)} className="mt-0.5" />
              <span className="text-ink-soft">
                Bu taramayı <strong>{creditsNeeded} kredi</strong> kullanarak öde (ödeme adımı atlanır).
              </span>
            </label>
          )}
          {selected && creditsNeeded > 0 && balance < creditsNeeded && !recurring && startMode === 'now' && (
            <p className="mt-2 text-xs text-ink-muted">Bu paket {creditsNeeded} kredi gerektirir; bakiyeniz yetersiz.</p>
          )}
        </div>
      )}

      {error && <p className="mt-4 text-sm text-red-600">{error}</p>}

      <button
        onClick={handleStart}
        disabled={!domainId || busy || !selected || !allConsents || !activeConsentOk}
        className="btn-primary mt-6 w-full disabled:cursor-not-allowed disabled:opacity-50 sm:w-auto"
      >
        {busy
          ? 'Başlatılıyor…'
          : recurring
            ? 'Düzenli Taramayı Kur'
            : startMode === 'later'
              ? 'Taramayı Zamanla'
              : 'Taramayı Başlat'}
      </button>
      <p className="mt-3 text-xs text-ink-muted">
        {recurring || startMode === 'later'
          ? 'Kayıtlarınızı “Zamanlanmış taramalarım” ekranından görüntüleyip iptal edebilirsiniz.'
          : 'Ödeme onaylandığında tarama otomatik ve anında başlar.'}
      </p>
    </main>
  );
}
