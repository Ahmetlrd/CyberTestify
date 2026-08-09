'use client';

import { useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { api } from '../../lib/api';
import { readRegionCookie } from '../../lib/region';
import { getRegion, type RegionCode } from '../../config/regions';
import { formatMoney } from '../../config/i18n';
import { DynamicContract } from '../../components/DynamicContract';

type ActiveTest = { scope: { does: string[]; doesNot: string[] }; riskText: string; consentVersion: string };
type Pkg = {
  key: string; displayName: string; description: string; priceMinorUnit: number; currency?: string;
  securityProfile?: 'passive' | 'active-light'; activeTest?: ActiveTest | null; comingSoon?: boolean; bundleOnly?: boolean;
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
  const [withdrawalConsent, setWithdrawalConsent] = useState(false); // AYRI: cayma hakki feragati
  const [crossBorderConsent, setCrossBorderConsent] = useState(false); // AYRI: KVKK m.9 yurt disi acik riza
  const [kvkkConsent, setKvkkConsent] = useState(false); // Gizlilik + KVKK Aydinlatma
  const [showContract, setShowContract] = useState(false);
  const allConsents = authConsent && contractConsent && withdrawalConsent && crossBorderConsent && kvkkConsent;

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
  // SATIS MODELI: tekil kontrol satisi YOK — secilebilir TEK "tekil" paket basit_tarama (giris).
  const basitPkg = packages.find((p) => p.key === 'basit_tarama');
  // Tekil satilabilen aktif-hafif kontroller (injection_verify + idor_verify) — secilebilir kartlar.
  const activeSingles = packages.filter((p) => (p.key === 'injection_verify' || p.key === 'idor_verify') && !p.comingSoon && !p.bundleOnly);
  const isActiveLight = selectedPkg?.securityProfile === 'active-light';
  // (#4) Uluslararasi odeme (Paddle) henuz canli degil — TR disi bolgede nazik "yakinda".
  const intlComingSoon = region !== 'tr';
  const needsAuthCreds = selected === 'authenticated_scan';
  const activeConsentOk = (!isActiveLight || atRisk) && (!needsAuthCreds || (authUser.trim() && authPass));
  const creditsNeeded = selectedPkg ? Math.max(1, Math.round(selectedPkg.priceMinorUnit / creditUnit)) : 0;
  // Kredi ile odeme yalnizca tek-seferlik/hemen taramada (zamanlanmis akis prepaid farkli).
  const canUseCredits = balance >= creditsNeeded && creditsNeeded > 0 && !recurring && startMode === 'now';

  async function applyPromo() {
    if (!promoInput.trim() || (!selected && !selectedBundle)) return;
    setPromoBusy(true);
    try {
      const target = selectedBundle ? { bundleKey: selectedBundle.key } : { packageKey: selected! };
      const r = await api.previewPromo(promoInput.trim(), target, region);
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
    if (!allConsents) return setError('Devam etmek için onayların tümünü işaretlemelisiniz.');
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
          withdrawalWaived: withdrawalConsent, // AYRI cayma feragati checkbox'i
          crossBorderTransfer: crossBorderConsent, // KVKK m.9 yurt disi acik riza checkbox'i
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
      // (0) E-posta dogrulanmamis -> satin alma engellendi (409). Dogrulama ekranina yonlendir.
      if (err?.emailUnverified) {
        router.push(`/verify-email?next=${encodeURIComponent(window.location.pathname + window.location.search)}`);
        return;
      }
      setError(err.message);
      setBusy(false);
    }
  }

  async function handleBundleStart() {
    if (!domainId || busy || !selectedBundle) return;
    if (!allConsents) return setError('Devam etmek için onayların tümünü işaretlemelisiniz.');
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
        withdrawalWaived: withdrawalConsent, // AYRI cayma feragati
        crossBorderTransfer: crossBorderConsent, // KVKK m.9 yurt disi acik riza
        region,
        activeTestConsent: isAL ? { riskAccepted: atRisk } : undefined,
        authCredentials: needsAuth ? { username: authUser.trim(), password: authPass } : undefined,
        promoCode: promo?.valid ? promo.code : undefined,
      });
      // %100 promo -> odeme YOK, dogrudan siparis paneli. Aksi halde: TR'de backend TEK gercek
      // iyzico CheckoutForm baslatir (paymentPageUrl) -> oraya yonlendir (tekil akisla ayni).
      // paymentPageUrl yoksa (TR disi placeholder) eski /pay bundle ekranina dus.
      if (res.paidWithPromo) {
        router.push(`/dashboard/${res.orderIds[0]}`);
      } else if (res.paymentPageUrl) {
        window.location.href = res.paymentPageUrl;
      } else {
        router.push(`/pay/${res.orderIds[0]}?bundle=${res.orderIds.join(',')}`);
      }
    } catch (err: any) {
      // (0) E-posta dogrulanmamis -> satin alma engellendi (409). Dogrulama ekranina yonlendir.
      if (err?.emailUnverified) {
        router.push(`/verify-email?next=${encodeURIComponent(window.location.pathname + window.location.search)}`);
        return;
      }
      setError(err.message);
      setBusy(false);
    }
  }

  const consents: Array<[boolean, (v: boolean) => void, React.ReactNode]> = [
    [
      authConsent,
      setAuthConsent,
      isActiveLight ? (
        <>
          Bu alan adının <strong>ve altyapısının</strong> sahibi veya yetkilisiyim; bu hedefe
          <strong> aktif-hafif doğrulama testi</strong> yapılmasına rıza gösteriyorum.
        </>
      ) : (
        <>
          Bu alan adının <strong>ve altyapısının</strong> sahibi veya yetkilisiyim; yalnızca bu hedefe
          <strong> pasif</strong> tarama yapılmasına rıza gösteriyorum.
        </>
      ),
    ],
    [
      contractConsent,
      setContractConsent,
      <>
        <Link href="/legal/on-bilgilendirme" target="_blank" className="font-semibold text-accent-600 underline">Ön Bilgilendirme</Link>,{' '}
        <Link href="/legal/mesafeli-satis" target="_blank" className="font-semibold text-accent-600 underline">Mesafeli Satış</Link> ve{' '}
        <Link href="/legal/iptal-iade" target="_blank" className="font-semibold text-accent-600 underline">İptal/İade</Link>{' '}
        koşullarını okudum, kabul ediyorum.
      </>,
    ],
    [
      // AYRI, spesifik cayma hakki feragati onayi (sozlesme onayindan bagimsiz — Mesafeli
      // Sozlesmeler Yon. m.15/ğ; iptal-iade metniyle uyumlu).
      withdrawalConsent,
      setWithdrawalConsent,
      <>
        Hizmetin cayma süresi dolmadan, <strong>onayımla derhal başlatılmasını</strong> istiyorum ve
        bu durumda <strong>cayma hakkımı kaybedeceğimi</strong> kabul ediyorum.
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
    [
      // KVKK m.9 — yurt disi (Anthropic/ABD) veri aktarimi ACIK RIZA (ayri, bagimsiz checkbox).
      crossBorderConsent,
      setCrossBorderConsent,
      <>
        Tarama komutlarımın işlenmesi amacıyla kişisel verilerimin{' '}
        <strong>yurt dışına (Anthropic, PBC — ABD)</strong> aktarılmasına{' '}
        <strong>KVKK m. 9 kapsamında açıkça rıza</strong> gösteriyorum.
      </>,
    ],
  ];

  // --- Ozet/CTA (sabit kenar karti + mobil alt cubuk) icin turetilmis degerler ---
  const activeBundles = bundles.filter((b) => !b.comingSoon);
  const soonBundles = bundles.filter((b) => b.comingSoon);
  const selName = selectedBundle ? selectedBundle.displayName : selectedPkg ? selectedPkg.displayName : null;
  const intervalLabel = intervalDays === 7 ? 'Haftalık' : intervalDays === 14 ? 'İki haftada bir' : 'Aylık';
  const freqLabel = selectedBundle || !recurring ? 'Tek seferlik' : `${intervalLabel} · ${runs} tarama`;
  const startLabel =
    !selectedBundle && startMode === 'later' && startAt
      ? new Date(startAt).toLocaleString('tr-TR', { dateStyle: 'short', timeStyle: 'short' })
      : 'Hemen';
  const payWithCreditsNow = !selectedBundle && useCredits && canUseCredits;
  const baseAmountMinor = selectedBundle ? selectedBundle.amountMinorUnit : selectedPkg ? selectedPkg.priceMinorUnit : 0;
  // Promo (tekil paket VEYA bundle) gecerliyse indirimli tutari goster.
  const unitAmountMinor =
    (selectedBundle || selectedPkg) && promo?.valid && promo.finalAmountMinorUnit != null
      ? promo.finalAmountMinorUnit
      : baseAmountMinor;
  const totalMinor = !selectedBundle && recurring ? unitAmountMinor * runs : unitAmountMinor;
  const ctaDisabled = selectedBundle
    ? !domainId || busy || !allConsents || intlComingSoon ||
      (selectedBundle.category === 'active-light' && !atRisk) ||
      (selectedBundle.selectable && bundleModules.length === 0)
    : !domainId || busy || !selected || !allConsents || !activeConsentOk || intlComingSoon;
  const ctaLabel = busy
    ? 'Başlatılıyor…'
    : selectedBundle
      ? 'Paketi Satın Al'
      : recurring
        ? 'Düzenli Taramayı Kur'
        : startMode === 'later'
          ? 'Taramayı Zamanla'
          : 'Taramayı Başlat';
  const onCta = () => (selectedBundle ? handleBundleStart() : handleStart());

  // Tek paket kart bileseni (basit + aktif bundle'lar ortak gorunum)
  const bundleCard = (b: any) => {
    const on = selectedBundle?.key === b.key;
    return (
      <button
        key={b.key}
        type="button"
        onClick={() => { setSelectedBundle(on ? null : b); setSelected(null); setBundleModules([]); setPromo(null); }}
        className={`card relative flex flex-col p-4 text-left transition ${
          on ? 'ring-2 ring-brand' : b.popular ? 'border-accent hover:border-accent' : 'hover:border-brand-300'
        }`}
      >
        {b.popular ? (
          <span className="absolute -top-3 left-6 rounded-pill bg-accent px-3 py-0.5 text-[10px] font-bold text-white">★ Popüler</span>
        ) : b.discountPct > 0 ? (
          <span className="absolute -top-3 left-6 rounded-pill bg-brand px-3 py-0.5 text-[10px] font-bold text-white">%{b.discountPct}</span>
        ) : null}
        <span className="font-bold text-brand">{b.displayName}</span>
        <p className="mt-1 text-xs leading-relaxed text-ink-soft">{b.description}</p>
        <p className="mt-1.5 flex-1 text-[11px] text-ink-muted">
          İçindekiler: {b.members.map((m: any) => m.displayName).join(' · ')}
        </p>
        <p className="mt-2 text-ink">
          {b.discountPct > 0 && (
            <span className="text-xs text-ink-muted line-through">{formatMoney(b.originalMinorUnit, getRegion(region))}</span>
          )}{' '}
          <span className="font-bold">{formatMoney(b.amountMinorUnit, getRegion(region))}</span>
          <span className="text-xs font-normal text-ink-muted"> · KDV Dahil</span>
        </p>
      </button>
    );
  };

  return (
    <main className="container-page max-w-6xl py-10 pb-28 lg:py-14 lg:pb-14">
      <div>
        <h1 className="text-2xl font-extrabold text-brand sm:text-3xl">Taramanızı Başlatın</h1>
        <p className="mt-1 text-sm text-ink-soft">Paketi seçin, onayları işaretleyin ve güvenli ödemeye geçin.</p>
      </div>

      {!domainId && (
        <p className="mt-4 rounded-card border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
          Önce site sahipliğinizi doğrulamalısınız.{' '}
          <Link href="/verify" className="font-semibold underline">
            Doğrulamaya git →
          </Link>
        </p>
      )}

      <div className="mt-6 grid gap-8 lg:grid-cols-[minmax(0,1fr)_340px] lg:gap-10">
        {/* ================= SOL: form adimlari ================= */}
        <div className="min-w-0">
      {/* Paket seçimi — SADECE paketler: Basit Tarama (giriş) + kombine paketler. Tekil kontrol satışı YOK. */}
      <h2 className="text-sm font-bold uppercase tracking-wide text-ink-muted">1 · Paket seçin</h2>
      <div className="mt-3 grid items-stretch gap-3 sm:grid-cols-2">
        {/* Basit Tarama — giriş seviyesi paket (tek "tekil" paket) */}
        {basitPkg && !basitPkg.comingSoon && (
          <button
            type="button"
            onClick={() => { setSelected(basitPkg.key); setSelectedBundle(null); setBundleModules([]); setPromo(null); }}
            className={`card relative flex flex-col p-4 text-left transition ${selected === basitPkg.key ? 'ring-2 ring-accent' : 'hover:border-brand-300'}`}
          >
            <span className="absolute -top-3 left-6 rounded-pill bg-ink-soft px-3 py-0.5 text-[10px] font-bold text-white">Giriş</span>
            <span className="font-bold text-brand">{basitPkg.displayName}</span>
            <p className="mt-1 flex-1 text-xs leading-relaxed text-ink-soft">
              Hızlı, ucuz deneme taraması — ön izleme niteliğindedir (kapsamlı denetim değildir).
            </p>
            <p className="mt-2 font-bold text-ink">
              {formatMoney(basitPkg.priceMinorUnit, getRegion(region))}{' '}
              <span className="text-xs font-normal text-ink-muted">· KDV Dahil</span>
            </p>
          </button>
        )}
        {/* Tekil aktif-hafif kontroller (injection_verify + idor_verify) — secilebilir. */}
        {activeSingles.map((p) => (
          <button
            key={p.key}
            type="button"
            onClick={() => { setSelected(p.key); setSelectedBundle(null); setBundleModules([]); setPromo(null); }}
            className={`card relative flex flex-col p-4 text-left transition ${selected === p.key ? 'ring-2 ring-accent' : 'hover:border-brand-300'}`}
          >
            <span className="absolute -top-3 left-6 rounded-pill bg-accent px-3 py-0.5 text-[10px] font-bold text-white">Aktif</span>
            <span className="font-bold text-brand">{p.displayName}</span>
            <p className="mt-1 flex-1 text-xs leading-relaxed text-ink-soft">
              Aktif-hafif doğrulama (kanıtla — istismar etme); yalnızca yetkili olduğunuz hedefte.
            </p>
            <p className="mt-2 font-bold text-ink">
              {formatMoney(p.priceMinorUnit, getRegion(region))}{' '}
              <span className="text-xs font-normal text-ink-muted">· KDV Dahil</span>
            </p>
          </button>
        ))}
        {activeBundles.map((b) => bundleCard(b))}
      </div>
      {/* "Yakında" paketler — devre disi, gri, SONA alindi (secilemez). */}
      {soonBundles.length > 0 && (
        <div className="mt-5">
          <p className="text-[11px] font-bold uppercase tracking-wide text-ink-muted">Yakında</p>
          <div className="mt-2 grid items-stretch gap-3 sm:grid-cols-2">
            {soonBundles.map((b) => (
              <div
                key={b.key}
                aria-disabled="true"
                className="card relative flex cursor-not-allowed flex-col border-dashed bg-brand-50/30 p-4 text-left opacity-60"
              >
                <span className="absolute -top-3 left-6 rounded-pill bg-ink-muted px-3 py-0.5 text-[10px] font-bold text-white">Yakında</span>
                <span className="font-bold text-ink-soft">{b.displayName}</span>
                <p className="mt-1 flex-1 text-xs leading-relaxed text-ink-muted">{b.description}</p>
                <p className="mt-2 text-xs font-semibold text-ink-muted">Şu an satışa kapalı</p>
              </div>
            ))}
          </div>
        </div>
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

      {/* Tekrar + Başlangıç YALNIZ tekil paket için (bundle'lar hemen çalışır, zamanlanamaz). */}
      {!selectedBundle && (
      <>
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
      </>
      )}

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

      {(selected || selectedBundle) && !intlComingSoon && (
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

        </div>{/* ===== SOL kolon sonu ===== */}

        {/* ================= SAĞ: kaydırmada sabit özet (masaüstü) ================= */}
        <aside className="hidden lg:block">
          <div className="sticky top-6 space-y-3">
            <div className="rounded-card border border-line bg-white p-5 shadow-sm">
              <p className="text-xs font-bold uppercase tracking-wide text-ink-muted">Sipariş Özeti</p>
              {selName ? (
                <>
                  <p className="mt-2 text-base font-bold text-brand">{selName}</p>
                  <dl className="mt-3 space-y-1.5 text-sm">
                    <div className="flex justify-between gap-2">
                      <dt className="text-ink-muted">Sıklık</dt>
                      <dd className="text-right font-medium text-ink">{freqLabel}</dd>
                    </div>
                    <div className="flex justify-between gap-2">
                      <dt className="text-ink-muted">Başlangıç</dt>
                      <dd className="text-right font-medium text-ink">{startLabel}</dd>
                    </div>
                    {selectedBundle && (
                      <div className="flex justify-between gap-2">
                        <dt className="text-ink-muted">İçerik</dt>
                        <dd className="text-right font-medium text-ink">{selectedBundle.members.length} tarama</dd>
                      </div>
                    )}
                  </dl>
                  <div className="mt-3 border-t border-line pt-3">
                    {payWithCreditsNow ? (
                      <div className="flex items-baseline justify-between">
                        <span className="text-sm text-ink-muted">Ödeme</span>
                        <span className="text-lg font-extrabold text-brand">{creditsNeeded} kredi</span>
                      </div>
                    ) : (
                      <div className="flex items-baseline justify-between">
                        <span className="text-sm text-ink-muted">{recurring ? `Toplam · ${runs} tarama` : 'Toplam'}</span>
                        <span className="text-2xl font-extrabold text-brand">{formatMoney(totalMinor, getRegion(region))}</span>
                      </div>
                    )}
                    <p className="mt-0.5 text-right text-[11px] text-ink-muted">KDV dahildir</p>
                  </div>
                </>
              ) : (
                <p className="mt-2 text-sm text-ink-soft">Devam etmek için bir paket seçin.</p>
              )}
              <button onClick={onCta} disabled={ctaDisabled} className="btn-primary mt-4 w-full disabled:cursor-not-allowed disabled:opacity-50">
                {ctaLabel}
              </button>
              <p className="mt-2 text-center text-[11px] text-ink-muted">
                {recurring || startMode === 'later'
                  ? 'Zamanlanmış taramalarım ekranından yönetebilirsiniz.'
                  : 'Ödeme onaylanınca tarama otomatik başlar.'}
              </p>
            </div>

            {/* Güven şeridi — DÜRÜST sinyaller (uydurma istatistik/puan YOK) */}
            <div className="rounded-card border border-line bg-brand-50/40 p-4 text-xs text-ink-soft">
              <ul className="space-y-1.5">
                <li className="flex items-center gap-2">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" className="shrink-0" aria-hidden><path d="M12 2l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V5l7-3z" fill="#123F3A"/><path d="M9 12l2 2 4-4" stroke="#F5A623" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" fill="none"/></svg>
                  256-bit SSL · iyzico güvenli ödeme
                </li>
                <li className="flex items-center gap-2">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#123F3A" strokeWidth="2" className="shrink-0" aria-hidden><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>
                  Kart bilgileri iyzico’da işlenir, bizde saklanmaz
                </li>
                <li className="flex items-center gap-2">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#1C6B60" strokeWidth="2" className="shrink-0" aria-hidden><circle cx="12" cy="12" r="9"/><path d="M8 12l2.5 2.5L16 9" strokeLinecap="round" strokeLinejoin="round"/></svg>
                  KVKK uyumlu · veriler şifreli saklanır
                </li>
              </ul>
              <div className="mt-3 flex flex-wrap items-center gap-3">
                <img src="/iyzico/iyzico_ile_ode_colored_horizontal.svg" alt="iyzico ile Öde" className="h-5 w-auto" width={175} height={26} />
                <img src="/iyzico/logo_band_colored.svg" alt="Visa, Mastercard, Troy" className="h-4 w-auto max-w-full" width={228} height={16} />
              </div>
            </div>
          </div>
        </aside>
      </div>{/* ===== grid sonu ===== */}

      {/* ================= MOBİL: kaydırmada sabit alt çubuk (özet + CTA) ================= */}
      <div className="fixed inset-x-0 bottom-0 z-40 border-t border-line bg-white/95 px-4 py-2.5 shadow-[0_-4px_16px_rgba(0,0,0,0.06)] backdrop-blur lg:hidden">
        <div className="mx-auto flex max-w-6xl items-center justify-between gap-3">
          <div className="min-w-0">
            <p className="truncate text-xs font-semibold text-brand">{selName ?? 'Paket seçilmedi'}</p>
            <p className="text-sm font-extrabold text-ink">
              {payWithCreditsNow ? `${creditsNeeded} kredi` : formatMoney(totalMinor, getRegion(region))}
              <span className="ml-1 text-[10px] font-normal text-ink-muted">KDV dahil</span>
            </p>
          </div>
          <button onClick={onCta} disabled={ctaDisabled} className="btn-primary shrink-0 px-5 disabled:cursor-not-allowed disabled:opacity-50">
            {ctaLabel}
          </button>
        </div>
      </div>
    </main>
  );
}
