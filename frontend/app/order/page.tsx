'use client';

import { useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { api } from '../../lib/api';
import { readRegionCookie } from '../../lib/region';
import { getRegion, type RegionCode } from '../../config/regions';
import { formatMoney } from '../../config/i18n';
import { DynamicContract } from '../../components/DynamicContract';
import { PACKAGE_CATEGORIES } from '../../components/CategoryAccordions';

type ActiveTest = { scope: { does: string[]; doesNot: string[] }; riskText: string; consentVersion: string };
type Pkg = {
  key: string; displayName: string; description: string; priceMinorUnit: number; currency?: string;
  securityProfile?: 'passive' | 'active-light'; activeTest?: ActiveTest | null; comingSoon?: boolean;
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
  const sp = useSearchParams();
  const domainId = sp.get('domainId');
  // Paketler sayfasindan "Satin Al" ile tasinan on-secim (paket veya bundle).
  const preselectPackage = sp.get('package');
  const preselectBundle = sp.get('bundle');
  const [packages, setPackages] = useState<Pkg[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  // Kombine paket (bundle) modu — bir bundle secilince tekil akis (recurring/kredi/promo) gizlenir.
  const [bundles, setBundles] = useState<any[]>([]);
  const [selectedBundle, setSelectedBundle] = useState<any | null>(null);
  const [bundleModules, setBundleModules] = useState<string[]>([]);
  // Tekil paket kategori akordeonlari (paketler sayfasiyla ayni duzen) — varsayilan KAPALI.
  const [openCats, setOpenCats] = useState<Record<string, boolean>>({});
  const [region, setRegion] = useState<RegionCode>('tr');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // (Is 2) Kredi bakiyesi + "krediyle öde" secenegi.
  const [balance, setBalance] = useState(0);
  const [creditUnit, setCreditUnit] = useState(99900);
  const [useCredits, setUseCredits] = useState(false);
  // Promosyon kodu (checkout onizleme + siparise gecirme).
  const [promoInput, setPromoInput] = useState('');
  const [promo, setPromo] = useState<{ valid: boolean; error?: string; code?: string; discountMinorUnit?: number; finalAmountMinorUnit?: number } | null>(null);
  const [promoBusy, setPromoBusy] = useState(false);

  // (Faz 3 v2) active-light — tek risk-kabul checkbox'i (ek alan yok).
  const [atRisk, setAtRisk] = useState(false);
  // (#5) authenticated_scan — test hesabi kimlik bilgileri.
  const [authUser, setAuthUser] = useState('');
  const [authPass, setAuthPass] = useState('');

  // Sahiplik beyani (TCK 243 — guvenlik) ayri; iyzico'nun bekledigi 2 ODEME-onay
  // checkbox'i: (1) On Bilgilendirme+Mesafeli+Iptal/Iade, (2) KVKK/Gizlilik.
  const [authConsent, setAuthConsent] = useState(false);
  const [contractConsent, setContractConsent] = useState(false); // On Bilgi + Mesafeli + Iptal/Iade
  const [kvkkConsent, setKvkkConsent] = useState(false); // Gizlilik + KVKK Aydinlatma
  const [showContract, setShowContract] = useState(false);
  const allConsents = authConsent && contractConsent && kvkkConsent;

  // Düzenli (periyodik) tarama seçeneği
  const [recurring, setRecurring] = useState(false);
  const [intervalDays, setIntervalDays] = useState(7); // haftalık
  const [runs, setRuns] = useState(4);

  // Başlangıç zamanı: hemen mi, ileri tarih mi
  const [startMode, setStartMode] = useState<'now' | 'later'>('now');
  const [startAt, setStartAt] = useState(''); // datetime-local değeri

  // (#4) Kuyruk yogunlugu — esik asilmissa nazik uyari (engelleme YOK).
  const [queue, setQueue] = useState<{ busy: boolean; etaMinutes: number; queuedCount: number } | null>(null);

  useEffect(() => {
    if (typeof window !== 'undefined' && !window.localStorage.getItem('token')) {
      router.push('/login');
      return;
    }
    const rc = readRegionCookie();
    setRegion(rc);
    api.listPackages(rc).then((pk) => {
      setPackages(pk);
      // "Satin Al" ile gelen tekil paketi ON-SEC (kullanici tekrar secmesin). "Yakında" ise ETME.
      const pre = pk.find((p) => p.key === preselectPackage);
      if (pre && !pre.comingSoon) {
        setSelected(preselectPackage);
        setSelectedBundle(null);
      }
    }).catch((err) => setError(err.message));
    api.listBundles(rc).then((bs) => {
      setBundles(bs);
      // "Satin Al" ile gelen bundle'i ON-SEC. "Yakında" ise ETME.
      if (preselectBundle) {
        const b = bs.find((x: any) => x.key === preselectBundle);
        if (b && !b.comingSoon) { setSelectedBundle(b); setSelected(null); }
      }
    }).catch(() => {});
    api.getCredits().then((c) => { setBalance(c.balance); setCreditUnit(c.creditUnitValueMinor); }).catch(() => {});
    api.getQueueStatus().then(setQueue).catch(() => {}); // sessiz — uyari opsiyonel
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [router]);

  const selectedPkg = packages.find((p) => p.key === selected);
  const isActiveLight = selectedPkg?.securityProfile === 'active-light';
  // (#4) Uluslararasi odeme (Paddle) henuz canli degil — TR disi bolgede nazik "yakinda".
  const intlComingSoon = region !== 'tr';
  const needsAuthCreds = selected === 'authenticated_scan';
  const activeConsentOk = (!isActiveLight || atRisk) && (!needsAuthCreds || (authUser.trim() && authPass));
  const creditsNeeded = selectedPkg ? Math.max(1, Math.round(selectedPkg.priceMinorUnit / creditUnit)) : 0;
  // Kredi ile odeme yalnizca tek-seferlik/hemen taramada (zamanlanmis akis prepaid farkli).
  const canUseCredits = balance >= creditsNeeded && creditsNeeded > 0 && !recurring && startMode === 'now';

  async function applyPromo() {
    if (!promoInput.trim() || !selected) return;
    setPromoBusy(true);
    try {
      const r = await api.previewPromo(promoInput.trim(), selected, region);
      setPromo(r);
    } catch {
      setPromo({ valid: false, error: 'Kod kontrol edilemedi.' });
    } finally {
      setPromoBusy(false);
    }
  }

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
          withdrawalWaived: contractConsent, // birlesik odeme-onay checkbox'i cayma feragatini de kapsar
        },
        region,
        payWithCredits,
        isActiveLight ? { riskAccepted: atRisk } : undefined,
        needsAuthCreds ? { username: authUser.trim(), password: authPass } : undefined,
        promo?.valid ? promo.code : undefined,
      );
      // Krediyle VEYA %100 promo ile odendiyse odeme sayfasi YOK — dogrudan siparis detayina git.
      if (res.paidWithCredits || res.paidWithPromo) {
        router.push(`/dashboard/${res.orderId}`);
        return;
      }
      window.location.href = res.paymentPageUrl!;
    } catch (err: any) {
      setError(err.message);
      setBusy(false);
    }
  }

  async function handleBundleStart() {
    if (!domainId || busy || !selectedBundle) return;
    if (!allConsents) return setError('Devam etmek için üç onayın tümünü işaretlemelisiniz.');
    const isAL = selectedBundle.category === 'active-light';
    if (isAL && !atRisk) return setError('Aktif test için risk kabul kutusunu işaretlemelisiniz.');
    const needsAuth = selectedBundle.members?.some((m: any) => m.key === 'authenticated_scan');
    if (needsAuth && (!authUser.trim() || !authPass)) return setError('Bu paket için test hesabı bilgileri gerekli.');
    if (selectedBundle.selectable && bundleModules.length === 0) return setError('En az bir modül seçin.');
    setBusy(true);
    setError(null);
    try {
      const res = await api.createBundleOrder({
        domainId,
        bundleKey: selectedBundle.key,
        selectedModules: selectedBundle.selectable ? bundleModules : undefined,
        ownershipConfirmed: authConsent,
        distanceContractAccepted: contractConsent,
        withdrawalWaived: contractConsent,
        region,
        activeTestConsent: isAL ? { riskAccepted: atRisk } : undefined,
        authCredentials: needsAuth ? { username: authUser.trim(), password: authPass } : undefined,
        promoCode: promo?.valid ? promo.code : undefined,
      });
      // %100 promo -> odeme YOK, dogrudan siparis paneli. Aksi halde ODEME EKRANINA
      // (/pay) git — tum uye siparisleri ?bundle= ile toplam tutarla gosterilir.
      if (res.paidWithPromo) {
        router.push(`/dashboard/${res.orderIds[0]}`);
      } else {
        router.push(`/pay/${res.orderIds[0]}?bundle=${res.orderIds.join(',')}`);
      }
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
        </Link>
        ,{' '}
        <Link href="/legal/mesafeli-satis" target="_blank" className="text-accent-600 underline">
          Mesafeli Satış Sözleşmesi
        </Link>{' '}
        ve{' '}
        <Link href="/legal/iptal-iade" target="_blank" className="text-accent-600 underline">
          İptal/İade Koşulları
        </Link>
        ’nı okudum, kabul ediyorum. Hizmetin dijital olarak <strong>anında ifa</strong> edildiğini ve
        ifasına başlandıktan sonra <strong>cayma hakkımı kullanamayacağımı</strong> kabul ediyorum.
      </>,
    ],
    [
      kvkkConsent,
      setKvkkConsent,
      <>
        Kişisel verilerimin{' '}
        <Link href="/legal/gizlilik" target="_blank" className="text-accent-600 underline">
          Gizlilik Politikası
        </Link>{' '}
        ve{' '}
        <Link href="/legal/kvkk-aydinlatma" target="_blank" className="text-accent-600 underline">
          KVKK Aydınlatma Metni
        </Link>{' '}
        kapsamında işlenmesini kabul ediyorum.
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

      {/* Kombine paketler (opsiyonel) — birden fazla kontrolü indirimli birlikte al */}
      {bundles.length > 0 && (
        <>
          <h2 className="mt-8 text-sm font-bold uppercase tracking-wide text-ink-muted">
            Kombine Paketler <span className="font-normal normal-case text-ink-muted">(opsiyonel — indirimli)</span>
          </h2>
          <div className="mt-3 grid gap-3 sm:grid-cols-2">
            {bundles.map((b) => {
              const on = selectedBundle?.key === b.key;
              if (b.comingSoon) {
                return (
                  <div key={b.key} className="card cursor-default p-4 text-left opacity-80">
                    <div className="flex items-start justify-between gap-2">
                      <span className="font-bold text-brand">{b.displayName}</span>
                      <span className="rounded-pill bg-brand px-2 py-0.5 text-[10px] font-bold text-white">Yakında</span>
                    </div>
                    <p className="mt-1 text-xs leading-relaxed text-ink-soft">{b.description}</p>
                    <p className="mt-2 text-xs font-semibold text-ink-muted">Yakında açılacak</p>
                  </div>
                );
              }
              return (
                <button
                  key={b.key}
                  type="button"
                  onClick={() => { setSelectedBundle(on ? null : b); setSelected(null); setBundleModules([]); }}
                  className={`card p-4 text-left transition ${on ? 'ring-2 ring-brand' : 'hover:border-brand-300'}`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <span className="font-bold text-brand">{b.displayName}</span>
                    <span className="rounded-pill bg-brand px-2 py-0.5 text-[10px] font-bold text-white">%{b.discountPct}</span>
                  </div>
                  <p className="mt-1 text-xs leading-relaxed text-ink-soft">{b.description}</p>
                  <p className="mt-2 text-ink">
                    <span className="text-xs text-ink-muted line-through">{formatMoney(b.originalMinorUnit, getRegion(region))}</span>{' '}
                    <span className="font-bold">{formatMoney(b.amountMinorUnit, getRegion(region))}</span>
                  </p>
                  <p className="mt-1 text-[11px] text-ink-muted">Tahmini süre: içeriğe göre değişir (üyeler sırayla)</p>
                </button>
              );
            })}
          </div>
          {selectedBundle && selectedBundle.selectable && selectedBundle.selectableModules && (
            <div className="mt-3 rounded-card border border-line bg-white p-4">
              <p className="text-sm font-semibold text-ink">Modülleri seçin (en az 1):</p>
              <div className="mt-2 space-y-2">
                {selectedBundle.selectableModules.map((m: any) => (
                  <label key={m.key} className="flex items-center gap-2 text-sm text-ink-soft">
                    <input
                      type="checkbox"
                      checked={bundleModules.includes(m.key)}
                      onChange={(e) =>
                        setBundleModules((prev) => (e.target.checked ? [...prev, m.key] : prev.filter((k) => k !== m.key)))
                      }
                    />
                    {m.displayName}
                  </label>
                ))}
              </div>
            </div>
          )}
          {selectedBundle && !selectedBundle.selectable && (
            <p className="mt-2 text-xs text-ink-muted">
              İçindekiler: {selectedBundle.members.map((m: any) => m.displayName).join(' · ')}
            </p>
          )}
          {selectedBundle && selectedBundle.category === 'active-light' && (
            <div className="mt-3 rounded-card border border-amber-300/60 bg-amber-50 px-4 py-3 text-sm">
              <label className="flex items-start gap-2">
                <input type="checkbox" checked={atRisk} onChange={(e) => setAtRisk(e.target.checked)} className="mt-0.5" />
                <span>
                  Bu paket aktif-hafif doğrulama kontrolleri içerir; yalnızca sahibi/yetkilisi olduğum hedefe karşı
                  çalıştırılmasına ve ilgili riskleri kabul ettiğime dair beyanı onaylıyorum. (Tüm modüller için tek beyan.)
                </span>
              </label>
              {selectedBundle.members.some((m: any) => m.key === 'authenticated_scan') && (
                <div className="mt-3 grid gap-2 sm:grid-cols-2">
                  <input placeholder="Test hesabı kullanıcı adı" value={authUser} onChange={(e) => setAuthUser(e.target.value)} className="field" />
                  <input type="password" placeholder="Test hesabı şifresi" value={authPass} onChange={(e) => setAuthPass(e.target.value)} className="field" />
                </div>
              )}
            </div>
          )}
        </>
      )}

      {/* Paket seçimi */}
      <h2 className="mt-8 text-sm font-bold uppercase tracking-wide text-ink-muted">
        {bundles.length > 0 ? 'veya tek paket seçin' : '1 · Paket seçin'}
      </h2>
      <div className="mt-3 space-y-3">
        {PACKAGE_CATEGORIES.map((cat) => {
          const items = cat.keys.map((k) => packages.find((p) => p.key === k)).filter(Boolean) as Pkg[];
          if (items.length === 0) return null;
          // Secili paket bu kategorideyse acik tut; aksi halde kullanici tercihine gore.
          const hasSelected = items.some((p) => p.key === selected);
          const isOpen = !!openCats[cat.id] || hasSelected;
          return (
            <div key={cat.id} className="overflow-hidden rounded-card border border-line bg-white">
              <button
                type="button"
                onClick={() => setOpenCats((o) => ({ ...o, [cat.id]: !o[cat.id] }))}
                aria-expanded={isOpen}
                className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left transition hover:bg-brand-50/40"
              >
                <span className="flex flex-wrap items-center gap-2">
                  <span className="text-sm font-bold text-brand">{cat.tr}</span>
                  <span className="text-xs text-ink-muted">· {items.length} kontrol içerir · Tahmini süre {cat.estTr}</span>
                  {cat.auth && (
                    <span className="rounded-pill bg-amber-100 px-2 py-0.5 text-[10px] font-bold text-amber-800">⚠ Yetkilendirme Beyanı Gerekir</span>
                  )}
                  {hasSelected && <span className="rounded-pill bg-accent px-2 py-0.5 text-[10px] font-bold text-ink">seçili</span>}
                </span>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" className={`shrink-0 text-ink-muted transition-transform ${isOpen ? 'rotate-180' : ''}`} aria-hidden>
                  <path d="M6 9l6 6 6-6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </button>
              {isOpen && (
                <div className="border-t border-line p-4">
                  <p className="mb-3 text-xs text-ink-soft">{cat.descTr}</p>
                  <div className="grid gap-3 sm:grid-cols-2">
                  {items.map((p) => {
                    const on = selected === p.key;
                    if (p.comingSoon) {
                      // "Yakında": secilemez, fiyat gosterilmez.
                      return (
                        <div key={p.key} className="card cursor-default p-4 text-left opacity-80">
                          <div className="flex items-start justify-between gap-2">
                            <span className="font-bold text-brand">{p.displayName}</span>
                            <span className="shrink-0 rounded-pill bg-brand px-2 py-0.5 text-[10px] font-bold text-white">Yakında</span>
                          </div>
                          <p className="mt-1 text-xs leading-relaxed text-ink-soft">{p.description}</p>
                          <p className="mt-2 text-xs font-semibold text-ink-muted">Yakında açılacak</p>
                        </div>
                      );
                    }
                    return (
                      <button
                        key={p.key}
                        type="button"
                        onClick={() => { setSelected(p.key); setSelectedBundle(null); }}
                        className={`card p-4 text-left transition ${on ? 'ring-2 ring-accent' : 'hover:border-brand-300'}`}
                      >
                        <div className="flex items-start justify-between gap-2">
                          <span className="font-bold text-brand">{p.displayName}</span>
                          <span className={`mt-0.5 h-4 w-4 shrink-0 rounded-full border ${on ? 'border-accent bg-accent' : 'border-line'}`} />
                        </div>
                        <p className="mt-1 text-xs leading-relaxed text-ink-soft">{p.description}</p>
                        <p className="mt-2 font-bold text-ink">
                          {formatMoney(p.priceMinorUnit, getRegion(region))}{' '}
                          <span className="text-xs font-normal text-ink-muted">· KDV Dahildir</span>
                        </p>
                        <p className="mt-1 text-[11px] text-ink-muted">Tahmini süre: {cat.estTr}</p>
                      </button>
                    );
                  })}
                  </div>
                </div>
              )}
            </div>
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
      {selectedPkg && (
        <div className="mt-3">
          <button type="button" onClick={() => setShowContract((v) => !v)} className="text-xs font-semibold text-accent-600 underline">
            {showContract ? 'Bu siparişe özel sözleşmeyi gizle' : 'Bu siparişe özel Mesafeli Satış Sözleşmesi’ni görüntüle'}
          </button>
          {showContract && (
            <DynamicContract
              serviceName={selectedPkg.displayName}
              priceLabel={formatMoney(selectedPkg.priceMinorUnit, getRegion(region))}
              region={region}
            />
          )}
        </div>
      )}

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

      {selected && !intlComingSoon && (
        <div className="mt-5 rounded-card border border-brand-100 bg-white px-4 py-3 text-sm">
          <label className="label">Promosyon kodu (opsiyonel)</label>
          <div className="mt-1 flex gap-2">
            <input
              value={promoInput}
              onChange={(e) => { setPromoInput(e.target.value); setPromo(null); }}
              placeholder="Kodunuz"
              className="field flex-1 uppercase"
            />
            <button
              type="button"
              onClick={applyPromo}
              disabled={promoBusy || !promoInput.trim()}
              className="btn-dark disabled:opacity-50"
            >
              {promoBusy ? '…' : 'Uygula'}
            </button>
          </div>
          {promo && !promo.valid && <p className="mt-2 text-xs text-red-600">{promo.error}</p>}
          {promo && promo.valid && (
            <p className="mt-2 text-xs text-emerald-700">
              Kod uygulandı — indirim {formatMoney(promo.discountMinorUnit ?? 0, getRegion(region))}. Yeni tutar:{' '}
              <strong>{formatMoney(promo.finalAmountMinorUnit ?? 0, getRegion(region))}</strong>
              {promo.finalAmountMinorUnit === 0 && ' — ödeme adımı atlanır, tarama hemen kuyruğa alınır.'}
            </p>
          )}
        </div>
      )}

      {queue?.busy && !intlComingSoon && (
        <div className="mt-6 rounded-card border border-amber-300/60 bg-amber-50 px-4 py-3 text-sm text-ink-soft">
          <strong>Şu an yoğunuz.</strong> Taramalar sırayla yapılıyor ve kuyrukta {queue.queuedCount} sipariş
          bekliyor; tahmini bekleme süresi{' '}
          <strong>
            {queue.etaMinutes >= 60
              ? `~${Math.round((queue.etaMinutes / 60) * 10) / 10} saat`
              : `~${queue.etaMinutes} dakika`}
          </strong>
          . Yine de sipariş verebilirsiniz — sıranız gelince taramanız otomatik başlar ve durumu bu panelden
          takip edebilirsiniz.
        </div>
      )}

      {intlComingSoon && (
        <div className="mt-6 rounded-card border border-accent/40 bg-accent-soft/40 px-4 py-3 text-sm text-ink-soft">
          <strong>Online payment for your region is coming soon.</strong> Card payments are currently available for
          Türkiye only. Please contact us at{' '}
          <a href="mailto:support@cybertestify.com" className="text-accent-600 underline">
            support@cybertestify.com
          </a>{' '}
          to arrange your scan in the meantime.
        </div>
      )}

      {error && <p className="mt-4 text-sm text-red-600">{error}</p>}

      <button
        onClick={selectedBundle ? handleBundleStart : handleStart}
        disabled={
          selectedBundle
            ? !domainId || busy || !allConsents || intlComingSoon ||
              (selectedBundle.category === 'active-light' && !atRisk) ||
              (selectedBundle.selectable && bundleModules.length === 0)
            : !domainId || busy || !selected || !allConsents || !activeConsentOk || intlComingSoon
        }
        className="btn-primary mt-6 w-full disabled:cursor-not-allowed disabled:opacity-50 sm:w-auto"
      >
        {busy
          ? 'Başlatılıyor…'
          : selectedBundle
            ? 'Paketi Satın Al'
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

      {/* Güvenli ödeme rozeti + iyzico resmi logoları (Visa/Mastercard/Troy dahil) */}
      <div className="mt-6 flex flex-wrap items-center gap-x-5 gap-y-3 rounded-card border border-line bg-brand-50/40 px-4 py-3 text-xs text-ink-soft">
        <span className="inline-flex items-center gap-1.5 font-semibold text-brand">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden>
            <path d="M12 2l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V5l7-3z" fill="#123F3A" />
            <path d="M9 12l2 2 4-4" stroke="#F5A623" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" fill="none" />
          </svg>
          Güvenli Ödeme (256-bit SSL)
        </span>
        <img src="/iyzico/iyzico_ile_ode_colored_horizontal.svg" alt="iyzico ile Öde" className="h-6 w-auto" width={210} height={31} />
        <img src="/iyzico/logo_band_colored.svg" alt="Visa, Mastercard, Troy" className="h-auto w-auto max-w-full" width={456} height={32} />
      </div>
      <p className="mt-2 text-xs text-ink-muted">
        Tüm fiyatlar <strong>KDV dahildir</strong>. Ödemeniz onaylandığında faturanız e-posta ile iletilecektir.
      </p>
    </main>
  );
}
