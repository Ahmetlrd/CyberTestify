'use client';

import { useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { api } from '../../lib/api';
import { renderEmphasis } from '../../lib/richText';
import { readRegionCookie } from '../../lib/region';
import { getRegion, type RegionCode } from '../../config/regions';
import { formatMoney } from '../../config/i18n';
import { DynamicContract } from '../../components/DynamicContract';

type ActiveTest = { scope: { does: string[]; doesNot: string[] }; riskText: string; consentVersion: string };
type Pkg = {
  key: string; displayName: string; description: string; priceMinorUnit: number; currency?: string;
  securityProfile?: 'passive' | 'active-light'; activeTest?: ActiveTest | null; comingSoon?: boolean; bundleOnly?: boolean;
  crossBorderAi?: boolean; // yurt dışı AI'ya veri gidiyor mu (KVKK m.9 açık rıza gerekli mi)
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
  // Kombine paket (bundle) modu — bir bundle secilince tekil akis (recurring/promo) gizlenir.
  const [bundles, setBundles] = useState<any[]>([]);
  const [selectedBundle, setSelectedBundle] = useState<any | null>(null);
  const [bundleModules, setBundleModules] = useState<string[]>([]);
  // Tekil paket kategori akordeonlari (paketler sayfasiyla ayni duzen) — varsayilan KAPALI.
  const [region, setRegion] = useState<RegionCode>('tr');
  // Sipariş özetinde hangi alan adının taranacağını AÇIKÇA göster (domainId'den çözülür).
  const [hostname, setHostname] = useState<string | null>(null);
  // Seçili alan adı DNS ile doğrulanmış mı (AKTİF paket çelik kapısı için UI göstergesi).
  const [domainVerified, setDomainVerified] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Promosyon kodu (checkout onizleme + siparise gecirme).
  const [promoInput, setPromoInput] = useState('');
  const [promo, setPromo] = useState<{ valid: boolean; error?: string; code?: string; discountMinorUnit?: number; finalAmountMinorUnit?: number } | null>(null);
  const [promoBusy, setPromoBusy] = useState(false);

  // (Faz 3 v2) active-light — tek risk-kabul checkbox'i (ek alan yok).
  const [atRisk, setAtRisk] = useState(false);
  // (Aktif Doğrulama Paketi) ödeme-öncesi düşük-kapsam ön-kontrolü.
  const [scopeLow, setScopeLow] = useState<boolean | null>(null); // null=henüz kontrol edilmedi
  const [scopeChecking, setScopeChecking] = useState(false); // ön-kontrol devam ediyor (SPA'da headless render ~birkaç sn)
  const [lowScopeAck, setLowScopeAck] = useState(false);
  // (TÜM paketler) ödeme-öncesi ERİŞİLEBİLİRLİK ön-kontrolü: hedef 443/80 yanıt vermiyorsa tarama
  // "İncelenemedi" (boş) sonuç verir; müşteri ödemeden önce uyarılmalı (yine de devam edebilir).
  const [reachable, setReachable] = useState<boolean | null>(null); // null=bilinmiyor/kontrol edilmedi
  const [unreachableAck, setUnreachableAck] = useState(false);
  // (#5) authenticated_scan — test hesabi kimlik bilgileri.
  const [authUser, setAuthUser] = useState('');
  const [authPass, setAuthPass] = useState('');
  // (ÖDEME ÖNCESİ TEST GİRİŞİ) tek buton + tek satır sonuç — BLOKLAMAZ, sadece bilgilendirir.
  const [loginCheck, setLoginCheck] = useState<'idle' | 'checking' | 'ok' | 'fail'>('idle');
  const [loginCheckMsg, setLoginCheckMsg] = useState<string>('');
  // (Tam Kapsamlı Pentest — FAZ A) kimlik-doğrulamalı/otonom paketlerde 3 EK onay.
  const [credShare, setCredShare] = useState(false);
  const [testAcct, setTestAcct] = useState(false);
  const [elevRisk, setElevRisk] = useState(false);
  // authConsentsOk aşağıda (selUsesForeignAi tanımlandıktan SONRA) hesaplanır — credShare (kimlik
  // bilgisi yurt dışı AI aktarımı rızası) YALNIZ yurt dışı AI kullanılıyorsa zorunludur.

  // Sahiplik beyani (TCK 243 — guvenlik) ayri; iyzico'nun bekledigi 2 ODEME-onay
  // checkbox'i: (1) On Bilgilendirme+Mesafeli+Iptal/Iade, (2) KVKK/Gizlilik.
  const [authConsent, setAuthConsent] = useState(false);
  const [contractConsent, setContractConsent] = useState(false); // On Bilgi + Mesafeli + Iptal/Iade
  const [withdrawalConsent, setWithdrawalConsent] = useState(false); // AYRI: cayma hakki feragati
  const [crossBorderConsent, setCrossBorderConsent] = useState(false); // AYRI: KVKK m.9 yurt disi acik riza
  const [kvkkConsent, setKvkkConsent] = useState(false); // Gizlilik + KVKK Aydinlatma
  const [showContract, setShowContract] = useState(false);

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
    api.getQueueStatus().then(setQueue).catch(() => {}); // sessiz — uyari opsiyonel
    // Doğrulanmış domain listesinden domainId'nin hostname'ini çöz (özet + mobil çubukta göster).
    if (domainId) {
      api.listDomains()
        .then((ds) => { const d = ds.find((x) => x.id === domainId); if (d) { setHostname(d.hostname); setDomainVerified(d.valid); } })
        .catch(() => {});
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [router]);

  // Ödeme öncesi hızlı ön-kontrol. ERİŞİLEBİLİRLİK (reachable) TÜM paketler için kontrol edilir —
  // hedef 443/80 yanıt vermiyorsa tarama "İncelenemedi" (boş) sonuç verir, müşteri önceden uyarılır.
  // DÜŞÜK KAPSAM (lowSignal) yalnız Aktif Doğrulama için anlamlıdır (giriş noktası bulmaya dayalı).
  useEffect(() => {
    setLowScopeAck(false);
    setScopeLow(null);
    setReachable(null);
    setUnreachableAck(false);
    setScopeChecking(false);
    if (!domainId || !(selected || selectedBundle)) return; // domain + herhangi bir paket seçili
    let cancelled = false;
    setScopeChecking(true);
    api.scopeEstimate(domainId)
      .then((r) => {
        if (cancelled) return;
        setReachable(r.reachable);
        setScopeLow(selectedBundle?.key === 'bundle_active_verify' ? r.lowSignal : false);
      })
      .catch(() => { if (!cancelled) { setReachable(null); setScopeLow(false); } }) // hata -> engelleme yok
      .finally(() => { if (!cancelled) setScopeChecking(false); });
    return () => { cancelled = true; };
  }, [domainId, selected, selectedBundle?.key]);

  const selectedPkg = packages.find((p) => p.key === selected);
  // SATIS MODELI: tekil kontrol satisi YOK — secilebilir TEK "tekil" paket basit_tarama (giris).
  const basitPkg = packages.find((p) => p.key === 'basit_tarama');
  const isActiveLight = selectedPkg?.securityProfile === 'active-light';
  // (#4) Uluslararasi odeme (Paddle) henuz canli degil — TR disi bolgede nazik "yakinda".
  const intlComingSoon = region !== 'tr';
  const needsAuthCreds = selected === 'authenticated_scan';

  // (İŞ 3) Onay GRUPLAMA — UI'da ≤3 checkbox. Sunucu-tarafı zorunluluk DEĞİŞMEZ: her grup, altındaki
  // TÜM bireysel onay state'lerini birlikte set eder (ownership/contract/kvkk/atRisk/testAcct/elevRisk/
  // crossBorder/credShare/withdrawal). En hassas iki AÇIK RIZA (KVKK m.9 yurt dışı + cayma feragati)
  // hukuken AYRI checkbox olarak kalır; kalanlar tek "genel kabul" altında gruplanır.
  const isActiveLightSel = isActiveLight || selectedBundle?.category === 'active-light';
  const needsAuthSel = needsAuthCreds || !!selectedBundle?.members?.some((m: any) => m.key === 'authenticated_scan');
  // (LOGİNSİZ TEST) Test hesabı bilgileri artık OPSİYONEL — sitede login mekanizması olmayabilir. Bilgi
  // girilmişse kimlik-doğrulamalı, boşsa loginsiz (kimlik-doğrulamasız) tarama yapılır. hasCreds bunu ayırır:
  // creds varsa test-hesabı onayları/kimlik gönderimi devreye girer, yoksa hiçbiri zorunlu değildir.
  const hasCreds = !!(authUser.trim() && authPass);
  // (KVKK m.9) Seçili paket/bundle yurt dışı AI'ya veri gönderiyor mu? Sadece o zaman m.9 açık rıza gerekir.
  const selUsesForeignAi = !!(selectedBundle ? selectedBundle.crossBorderAi : selectedPkg?.crossBorderAi);
  // (BUG FIX) Kimlik-doğrulamalı testte 2 zorunlu beyan: TEST hesabı + yüksek-risk. credShare (kimlik
  // bilgisi YURT DIŞI AI aktarımı rızası) yalnız yurt dışı AI KULLANILIYORSA gerekir — advisory kapalıyken
  // o kutu hiç gösterilmez, dolayısıyla credShare hiç set edilemez; onu zorunlu tutmak butonu kilitliyordu.
  const authConsentsOk = testAcct && elevRisk && (!selUsesForeignAi || credShare);
  const activeConsentOk = (!isActiveLight || atRisk) && (!needsAuthCreds || !hasCreds || authConsentsOk);
  const allConsents =
    authConsent && contractConsent && withdrawalConsent && kvkkConsent && (!selUsesForeignAi || crossBorderConsent);
  // Grup 1 — Genel kabul (ownership + mesafeli/ön-bilgi + KVKK aydınlatma + [aktif-test riski] + [test hesabı beyanı]).
  const groupGeneralChecked =
    authConsent && contractConsent && kvkkConsent && (!isActiveLightSel || atRisk) && (!needsAuthSel || !hasCreds || (testAcct && elevRisk));
  const setGroupGeneral = (v: boolean) => {
    setAuthConsent(v); setContractConsent(v); setKvkkConsent(v);
    if (isActiveLightSel) setAtRisk(v);
    if (needsAuthSel) { setTestAcct(v); setElevRisk(v); }
  };
  // Grup 2 — AYRI: KVKK m.9 yurt dışı açık rıza. YALNIZ yurt dışı AI kullanan pakette gösterilir/
  // zorunludur; deterministik paketlerde veri yurt dışına gitmediği için gerekmez (otomatik geçer).
  const groupCrossBorderChecked = !selUsesForeignAi || (crossBorderConsent && (!needsAuthSel || !hasCreds || credShare));
  const setGroupCrossBorder = (v: boolean) => { setCrossBorderConsent(v); if (needsAuthSel) setCredShare(v); };
  // Grup 3 — AYRI: mesafeli satış cayma hakkı feragati (withdrawalConsent) — doğrudan.
  // (Aktif Doğrulama Paketi) düşük-kapsam uyarısı gösterilecek mi (ön-kontrol düşük sinyal döndüyse).
  const showLowScopeWarning = selectedBundle?.key === 'bundle_active_verify' && scopeLow === true;
  // (TÜM paketler) hedef ödeme öncesi ön-kontrolde erişilemiyorsa uyar (tarama boş/"İncelenemedi" verir).
  const showUnreachableWarning = reachable === false;

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
        isActiveLight ? { riskAccepted: atRisk, ...(needsAuthCreds && hasCreds ? { credentialSharingAccepted: credShare, testAccountDeclared: testAcct, elevatedRiskAccepted: elevRisk } : {}) } : undefined,
        needsAuthCreds && hasCreds ? { username: authUser.trim(), password: authPass } : undefined, // loginsizse gönderilmez
        promo?.valid ? promo.code : undefined,
      );
      // %100 promo ile odendiyse odeme sayfasi YOK — dogrudan siparis detayina git.
      if (res.paidWithPromo) {
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
    // (LOGİNSİZ TEST) creds opsiyonel: boşsa loginsiz devam. Girildiyse ek onaylar gerekir.
    if (needsAuth && hasCreds && !authConsentsOk) return setError('Test hesabı bilgisi girdiniz — kimlik-doğrulamalı test için ek onayları (test hesabı beyanı ve yüksek-risk kabulü) işaretleyin. (Ya da bilgileri boş bırakıp loginsiz devam edin.)');
    if (selectedBundle.selectable && bundleModules.length === 0) return setError('En az bir modül seçin.');
    if (showLowScopeWarning && !lowScopeAck) return setError('Devam etmek için ön kontrol uyarısını onaylamalısınız.');
    if (showUnreachableWarning && !unreachableAck) return setError('Hedefe erişilemiyor — devam etmek için uyarıyı onaylamalısınız.');
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
        activeTestConsent: isAL ? { riskAccepted: atRisk, ...(needsAuth && hasCreds ? { credentialSharingAccepted: credShare, testAccountDeclared: testAcct, elevatedRiskAccepted: elevRisk } : {}) } : undefined,
        authCredentials: needsAuth && hasCreds ? { username: authUser.trim(), password: authPass } : undefined, // loginsizse gönderilmez
        promoCode: promo?.valid ? promo.code : undefined,
        lowScopeAcknowledged: showLowScopeWarning ? lowScopeAck : undefined,
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

  // (İŞ 3) 3 GRUPLU onay — her label birden fazla bireysel state'i birlikte set eder (sunucu payload'ı
  // AYNEN korunur). Grup 1 = genel kabul; Grup 2/3 = hukuken AYRI açık rızalar (KVKK m.9 + cayma feragati).
  const consentGroups: Array<{ checked: boolean; set: (v: boolean) => void; node: React.ReactNode }> = [
    {
      checked: groupGeneralChecked,
      set: setGroupGeneral,
      node: (
        <>
          <strong>Okudum, onaylıyorum:</strong> Bu alan adının <strong>ve altyapısının</strong> sahibi/yetkilisiyim ve
          bu hedefe {isActiveLightSel ? <>bir <strong>aktif-hafif doğrulama testi</strong></> : <><strong>pasif</strong> tarama</>} yapılmasına
          rıza gösteriyorum;{' '}
          <Link href="/legal/on-bilgilendirme" target="_blank" className="font-semibold text-accent-600 underline">Ön Bilgilendirme</Link>,{' '}
          <Link href="/legal/mesafeli-satis" target="_blank" className="font-semibold text-accent-600 underline">Mesafeli Satış</Link>,{' '}
          <Link href="/legal/iptal-iade" target="_blank" className="font-semibold text-accent-600 underline">İptal/İade</Link>{' '}
          koşullarını ve{' '}
          <Link href="/legal/gizlilik" target="_blank" className="font-semibold text-accent-600 underline">Gizlilik Politikası</Link> /{' '}
          <Link href="/legal/kvkk-aydinlatma" target="_blank" className="font-semibold text-accent-600 underline">KVKK Aydınlatma Metni</Link>’ni
          okudum, kabul ediyorum.
          {isActiveLightSel && <> Bu paketin <strong>daha yüksek risk</strong> taşıyan aktif test istekleri gönderdiğini kabul ediyorum.</>}
          {needsAuthSel && <> Vereceğim hesabın üretim/ana hesabım <strong>olmadığını</strong>, sınırlı yetkili tek-kullanımlık bir <strong>TEST hesabı</strong> olduğunu beyan ederim.</>}
        </>
      ),
    },
    // AYRI (hukuken): yurt dışı AI açık rızası — YALNIZ yurt dışı AI kullanan pakette gösterilir
    // (deterministik paketlerde veri yurt dışına gitmediği için bu kutu hiç çıkmaz).
    ...(selUsesForeignAi
      ? [{
          checked: groupCrossBorderChecked,
          set: setGroupCrossBorder,
          node: (
            <>
              <strong>Yapay zekâ analizi:</strong> Bu pakette tarama verilerim{needsAuthSel && <> ve verdiğim <strong>test hesabı bilgilerim</strong></>}, analiz için <strong>yurt dışında yerleşik bir yapay zekâ hizmetine</strong> aktarılır; buna açıkça rıza gösteriyorum.{needsAuthSel && ' Bilgilerim şifreli saklanır ve tarama sonrası silinir.'}
            </>
          ),
        }]
      : []),
    {
      // AYRI (hukuken): mesafeli satış cayma hakkı feragati (Mesafeli Sözleşmeler Yön. m.15/ğ).
      checked: withdrawalConsent,
      set: setWithdrawalConsent,
      node: (
        <>
          <strong>Cayma hakkı:</strong> Hizmetin cayma süresi dolmadan <strong>onayımla derhal başlatılmasını</strong> istiyorum
          ve bu durumda <strong>cayma hakkımı kaybedeceğimi</strong> kabul ediyorum.
        </>
      ),
    },
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
  const baseAmountMinor = selectedBundle ? selectedBundle.amountMinorUnit : selectedPkg ? selectedPkg.priceMinorUnit : 0;
  // Promo (tekil paket VEYA bundle) gecerliyse indirimli tutari goster.
  const unitAmountMinor =
    (selectedBundle || selectedPkg) && promo?.valid && promo.finalAmountMinorUnit != null
      ? promo.finalAmountMinorUnit
      : baseAmountMinor;
  const totalMinor = !selectedBundle && recurring ? unitAmountMinor * runs : unitAmountMinor;
  // (Kullanıcı isteği) AKTİF paket + DOĞRULANMAMIŞ alan adı: "Satın Al" HİÇ tıklanmasın. Ödeme-sonra-tut
  // yerine, kullanıcı önce doğrulamaya yönlendirilir. Bu durumda buy CTA'sı yerine "Doğrula" butonu çıkar
  // ve /verify'da o alan adının DNS paneline odaklanır (domainId param).
  const needsDomainVerify = isActiveLightSel && !!domainId && domainVerified === false;
  const verifyHref = domainId
    ? `/verify?domainId=${domainId}&${selectedBundle ? `bundle=${selectedBundle.key}` : `package=${selected}`}`
    : '/verify';
  // (TÜM paketler) ön-kontrol bitene kadar bekle; erişilemez uyarısı onaylanmadan ödeme yok.
  const preCheckGate = scopeChecking || (showUnreachableWarning && !unreachableAck);
  const ctaDisabled = selectedBundle
    ? !domainId || busy || !allConsents || intlComingSoon || needsDomainVerify ||
      (selectedBundle.category === 'active-light' && !atRisk) ||
      // (LOGİNSİZ TEST) kimlik-doğrulamalı üye: creds OPSİYONEL. Girildiyse ek onaylar gerekir; boşsa loginsiz geçer.
      (selectedBundle.members?.some((m: any) => m.key === 'authenticated_scan') && hasCreds && !authConsentsOk) ||
      (selectedBundle.selectable && bundleModules.length === 0) ||
      (showLowScopeWarning && !lowScopeAck) || // düşük-kapsam uyarısı onaylanmadan ödeme yok
      preCheckGate
    : !domainId || busy || !selected || !allConsents || !activeConsentOk || intlComingSoon || needsDomainVerify || preCheckGate;
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

  // (İŞ 3 · Sorun A) "Satın Al" neden pasif? Müşteri tahmin etmesin — net sebep + onaylara kaydırma.
  const scrollToTarget = (id: string) => document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'center' });
  const allGroupsChecked = groupGeneralChecked && groupCrossBorderChecked && withdrawalConsent;
  // (MOBİL) Buton neden pasif? Uyarı/onay AŞAĞIDA olabilir; hint'e `target` verip mobil alt-çubukta da
  // "→ oraya kaydır" yapıyoruz. Aksi halde ön-kontrol uyarısının onay kutusuna ulaşılamayıp kilitleniyordu.
  const disabledHint: { text: string; scroll: boolean; target?: string } | null = (() => {
    if (!(selected || selectedBundle) || busy) return null;
    if (!domainId) return { text: 'Önce site sahipliğinizi doğrulayın.', scroll: false };
    if (selectedBundle?.selectable && bundleModules.length === 0) return { text: 'Paket içeriğini seçin.', scroll: false };
    // (LOGİNSİZ TEST) test hesabı bilgisi artık zorunlu değil — boş bırakılırsa loginsiz devam edilir (uyarı formda).
    if (!allGroupsChecked) return { text: 'Devam etmek için aşağıdaki onayları işaretleyin →', scroll: true, target: 'onaylar' };
    if (showLowScopeWarning && !lowScopeAck) return { text: 'Ön kontrol uyarısını okuyup onaylayın →', scroll: true, target: 'oncontrol-uyari' };
    if (showUnreachableWarning && !unreachableAck) return { text: 'Erişim uyarısını okuyup onaylayın →', scroll: true, target: 'oncontrol-uyari' };
    if (scopeChecking) return { text: 'Ön kontrol yapılıyor…', scroll: false };
    return null;
  })();

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
        <p className="mt-1 text-xs leading-relaxed text-ink-soft">{renderEmphasis(b.description)}</p>
        {b.key === 'bundle_recon' ? (
          <div className="mt-1.5 flex-1 text-[11px] text-ink-muted">
            İçindekiler:
            <ul className="mt-1 space-y-0.5">
              <li>· Terk edilmiş alt domain (Subdomain Takeover) taraması — CT loglarından alt domain envanteri</li>
              <li>· Açık API / Swagger dokümantasyon keşfi</li>
              <li>· CMS &amp; teknoloji parmak izi analizi</li>
              <li>· Site haritasından idari/hassas yol tespiti</li>
            </ul>
            <p className="mt-1.5 italic">Pasif dış yüzey keşfidir; aktif uç nokta enjeksiyonu veya kimlik doğrulamalı test içermez.</p>
          </div>
        ) : (
          <p className="mt-1.5 flex-1 text-[11px] text-ink-muted">
            İçindekiler: {b.members.map((m: any) => m.displayName).join(' · ')}
          </p>
        )}
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

  // (Tam Kapsamlı Pentest — FAZ A) Kimlik-doğrulamalı paketlerde: "test hesabı" uyarısı + kimlik
  // bilgisi girişleri + 3 EK onay. Kimlik-doğrulamalı üye seçiliyken gösterilir (comingSoon paket
  // FAZ E'de açıldığında canlı olur; şimdilik hazır).
  // (ÖDEME ÖNCESİ TEST GİRİŞİ) Girilen test hesabıyla kendi doğrulanmış domainine 1 login dener.
  // BLOKLAMAZ — sonuç bilgilendirmedir (yanlış-negatif olabilir; gerçek tarama daha kapsamlıdır).
  async function runLoginCheck() {
    if (!domainId || !authUser.trim() || !authPass || loginCheck === 'checking') return;
    setLoginCheck('checking');
    setLoginCheckMsg('');
    try {
      const r = await api.precheckLogin(domainId, authUser.trim(), authPass);
      if (r.ok) {
        setLoginCheck('ok');
        setLoginCheckMsg('Test hesabıyla giriş doğrulandı.');
      } else {
        setLoginCheck('fail');
        setLoginCheckMsg(
          r.reason === 'bad_credentials' ? 'Bu kullanıcı adı/şifreyle giriş yapılamadı — bilgileri kontrol edin.'
          : r.reason === 'two_factor' ? 'Hesapta 2FA görünüyor — 2FA’sız bir test hesabı verin.'
          : r.reason === 'no_login_endpoint' ? 'Otomatik giriş formu bulunamadı — yine de devam edebilirsiniz (tarama daha kapsamlı deneyecektir).'
          : r.reason === 'timeout' ? 'Doğrulama uzun sürdü — yine de devam edebilirsiniz (gerçek tarama daha kapsamlı deneyecektir).'
          : 'Giriş şu an doğrulanamadı — yine de devam edebilirsiniz.',
        );
      }
    } catch {
      // (HIZ) İstemci zaman aşımı (AbortError) dahil — takılı kalmaz, bilgilendirici mesaj.
      setLoginCheck('fail');
      setLoginCheckMsg('Doğrulama uzun sürdü — yine de devam edebilirsiniz (gerçek tarama daha kapsamlı deneyecektir).');
    }
  }

  const authCredBlock = (
    <div className="mt-3 space-y-4 rounded-card border-2 border-brand/20 bg-brand-50/50 p-4 sm:p-5">
      <p className="flex items-center gap-2 text-sm font-bold text-brand">
        <span className="inline-flex h-6 w-6 items-center justify-center rounded-full bg-brand text-xs text-white">🔑</span>
        Test hesabı bilgileri <span className="font-normal text-ink-muted">(opsiyonel)</span>
      </p>
      {/* (LOGİNSİZ TEST) Opsiyonel olduğunu net söyle — sitede login olmayabilir. */}
      <div className="rounded-card border border-brand-200 bg-white/70 px-4 py-3 text-sm text-ink-soft">
        <p>
          Bu alan <strong>opsiyoneldir</strong>. Sitenizde bir <strong>giriş (login) mekanizması yoksa</strong> boş bırakın —
          tarama <strong>loginsiz (kimlik-doğrulamasız)</strong> yapılır. Giriş varsa, oturum-içi kontroller için bir
          <strong> TEST hesabı</strong> girebilirsiniz.
        </p>
      </div>
      {/* Uyarı — güçlü kontrast: sol accent bar + koyu kırmızı başlık + koyu metin */}
      <div className="rounded-card border border-red-300 border-l-4 border-l-red-600 bg-red-50 px-4 py-3 text-red-900">
        <p className="text-sm font-bold text-red-700">⚠️ Yalnız TEST hesabı girin — ana/üretim hesabınızı DEĞİL</p>
        <p className="mt-1 text-sm">
          Bu tarama için oluşturulmuş, <strong>sınırlı yetkili, tek-kullanımlık</strong> bir hesap kullanın; şifresini tarama sonrası değiştirin.
        </p>
        <p className="mt-1.5 text-xs text-red-800">
          <strong>2FA’sı olmayan</strong> bir hesap verin. Kimlik bilgileriniz <strong>şifreli</strong> saklanır ve tarama sonrası <strong>silinir</strong>.
        </p>
      </div>
      {/* Etiketli girişler — beyaz alanlar tint zemine karşı belirgin */}
      <div className="grid gap-3 sm:grid-cols-2">
        <label className="block">
          <span className="label !mb-1 !text-ink">Kullanıcı adı / e-posta</span>
          <input placeholder="test@örnek.com" value={authUser} onChange={(e) => { setAuthUser(e.target.value); setLoginCheck('idle'); }} className="field border-line/80" autoComplete="off" />
        </label>
        <label className="block">
          <span className="label !mb-1 !text-ink">Şifre</span>
          <input type="password" placeholder="Test hesabı şifresi" value={authPass} onChange={(e) => { setAuthPass(e.target.value); setLoginCheck('idle'); }} className="field border-line/80" autoComplete="new-password" />
        </label>
      </div>
      {/* (ÖDEME ÖNCESİ TEST GİRİŞİ) tek buton + tek satır sonuç — ek checkbox/uyarı YOK, bloklamaz. */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
        <button
          type="button"
          onClick={runLoginCheck}
          disabled={!domainId || !authUser.trim() || !authPass || loginCheck === 'checking'}
          className="btn-dark shrink-0 text-sm disabled:cursor-not-allowed disabled:opacity-50"
        >
          {loginCheck === 'checking' ? (
            <span className="flex items-center gap-2">
              <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-white/40 border-t-white" />
              Giriş deneniyor…
            </span>
          ) : (
            'Test girişini doğrula (opsiyonel)'
          )}
        </button>
        {loginCheck === 'checking' && (
          <span className="text-xs text-ink-muted">Giriş formu aranıp deneniyor — birkaç saniye sürebilir…</span>
        )}
        {loginCheck === 'ok' && (
          <span className="rounded-pill bg-emerald-100 px-3 py-1 text-sm font-semibold text-emerald-800">✓ {loginCheckMsg}</span>
        )}
        {loginCheck === 'fail' && (
          <span className="rounded-pill bg-amber-100 px-3 py-1 text-sm font-medium text-amber-900">{loginCheckMsg}</span>
        )}
      </div>
      {/* (LOGİNSİZ TEST) Bilgi girilmediyse küçük uyarı — tarama loginsiz yapılacak. */}
      {!hasCreds && (
        <p className="text-xs font-medium text-ink-muted">
          ℹ️ Test hesabı bilgisi girmediniz — tarama <strong>loginsiz (kimlik-doğrulamasız)</strong> yapılacak. Sitenizde giriş yoksa bu normaldir.
        </p>
      )}
      {/* (İŞ 3) Test-hesabı beyanı + kimlik-bilgisi yurt dışı açık rıza + yüksek-risk kabulü aşağıdaki
          "2 · Onaylar" bölümündeki gruplu checkbox'larda (sunucu-tarafı alanlar AYNEN korunur). */}
    </div>
  );

  return (
    <main className="container-page max-w-6xl py-10 pb-28 lg:py-14 lg:pb-14">
      <div>
        <h1 className="text-2xl font-extrabold text-brand sm:text-3xl">Taramanızı Başlatın</h1>
        <p className="mt-1 text-sm text-ink-soft">Paketi seçin, onayları işaretleyin ve güvenli ödemeye geçin.</p>
      </div>

      {!domainId && (
        <p className="mt-4 rounded-card border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
          Önce taranacak bir alan adı seçin.{' '}
          <Link href="/verify" className="font-semibold underline">
            Alan adı seç →
          </Link>
        </p>
      )}

      {/* (PASİF/AKTİF AYRIMI) Doğrulama gereksinimi — paket tipine göre net mesaj. */}
      {domainId && (selected || selectedBundle) && (
        isActiveLightSel ? (
          domainVerified ? (
            <p className="mt-4 flex items-center gap-2 rounded-card border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm font-medium text-emerald-800">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" className="shrink-0" aria-hidden><path d="M20 6 9 17l-5-5" /></svg>
              Alan adı DNS ile doğrulandı — aktif tarama ödeme onayından sonra başlar.
            </p>
          ) : (
            <div className="mt-4 rounded-card border border-amber-300 bg-amber-50 px-4 py-3 text-sm text-amber-900/90">
              <p className="font-bold text-amber-900">Bu paket aktif problar gönderir — DNS doğrulaması gerekir</p>
              <p className="mt-1 leading-relaxed">
                Alan adı sahipliğinizi DNS ile doğrulamadan aktif tarama (enjeksiyon/oturum denemeleri)
                <strong> başlamaz</strong> — ödeme alınsa bile sipariş <strong>“alan adı doğrulaması bekleniyor”</strong>
                durumunda tutulur, doğrulanınca <strong>otomatik başlar</strong>.
              </p>
              <Link href={verifyHref} className="mt-2 inline-flex items-center gap-1 font-semibold text-amber-900 underline">
                Şimdi DNS ile doğrula →
              </Link>
            </div>
          )
        ) : (
          <p className="mt-4 flex items-center gap-2 rounded-card border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm font-medium text-emerald-800">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" className="shrink-0" aria-hidden><path d="M20 6 9 17l-5-5" /></svg>
            Bu paket için doğrulama gerekmez — ödeme onaylanınca tarama hemen başlar.
          </p>
        )
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
                <p className="mt-1 flex-1 text-xs leading-relaxed text-ink-muted">{renderEmphasis(b.description)}</p>
                <p className="mt-2 text-xs font-semibold text-ink-muted">Şu an satışa kapalı</p>
              </div>
            ))}
          </div>
        </div>
      )}
      {/* (İŞ 3) Aktif-hafif risk kabulü aşağıdaki gruplu onaya taşındı; burada YALNIZ (varsa) test-hesabı
          giriş alanları gösterilir (kimlik-doğrulamalı bundle üyesi için). */}
      {selectedBundle?.members?.some((m: any) => m.key === 'authenticated_scan') && (
        <div className="mt-3 rounded-card border border-amber-300/60 bg-amber-50 px-4 py-3 text-sm">
          <p className="text-sm font-semibold text-brand">Test hesabı bilgileri</p>
          {authCredBlock}
        </div>
      )}

      {/* KAPSAM NETLIGI — Aktif Doğrulama Paketi seçiliyken HER müşteri, ÖDEME ÖNCESİ görür
          (düşük-sinyal ön-kontrol uyarısından bağımsız; o uyarı ek olarak gösterilir). */}
      {selectedBundle?.key === 'bundle_active_verify' && (
        <div className="mt-3 rounded-card border-2 border-amber-400 bg-amber-50 px-4 py-3 text-sm text-amber-900/90">
          <p className="font-bold text-amber-900">💡 Şeffaflık &amp; Kapsam — ödemeden önce okuyun</p>
          <p className="mt-1 leading-relaxed">
            Bu paket, web sitenizin <strong>herkese açık (login gerektirmeyen) dış saldırı yüzeyini</strong>{' '}
            zararsız problarla test eder — dışa açık arama, form, API ve login/kayıt akışı üzerindeki enjeksiyon,
            yetkilendirme ve mantık riskleri.
          </p>
          <p className="mt-2 leading-relaxed">
            Sitenizde dışa açık <strong>arama, form, API veya id-tabanlı uç nokta bulunmuyorsa</strong>, içerikte
            listelenen <strong>IDOR / İş Mantığı / Dosya Yükleme / Race</strong> gibi kontroller raporda{' '}
            <strong>“İncelenemedi”</strong> görünebilir. Bu bir <strong>hata değildir</strong> — sitenizin dış
            yüzey yapısının doğal sonucudur (test edilecek açık bir giriş noktası olmaması).
          </p>
          <p className="mt-2 leading-relaxed">
            Oturum içi (kullanıcı girişi <strong>sonrası</strong>) derin yetkilendirme/iş-mantığı testleri için{' '}
            <strong>Tam Kapsamlı Pentest</strong> paketini seçin.
          </p>
        </div>
      )}

      {/* (FAZ E) TAM KAPSAMLI PENTEST — bu paket diğerlerinden DAVRANIŞ olarak farklı; müşteri
          ödeme öncesi NET bilsin: inceleme süreci + test hesabı + sınırlı-otonom ajan. */}
      {selectedBundle?.key === 'bundle_full_pentest' && (
        <div className="mt-3 space-y-2 rounded-card border border-brand-200 bg-brand-50/50 px-4 py-3 text-sm text-ink-soft">
          <p><strong className="text-ink">İnceleme süreci:</strong> Bu paket, güvenlik nedeniyle sipariş sonrası
          <strong>ödeme onaylanınca hemen</strong> başlar.</p>
          <p><strong className="text-ink">Test hesabı:</strong> Kimlik doğrulamalı test için bir <strong>TEST hesabı</strong>
          (ana/üretim hesabınız DEĞİL; 2FA’sız, sınırlı yetkili, tek-kullanımlık) vermelisiniz. Kimlik bilgileriniz
          <strong> şifreli/geçici</strong> saklanır ve tarama sonrası silinir.</p>
          <p><strong className="text-ink">Yöntem:</strong> Login sonrası çerez/oturum/yetki, authenticated enjeksiyon ve IDOR,
          yetki yükseltme ve çok-adımlı iş mantığı göstergeleri <strong>deterministik güvenlik kontrolleriyle</strong> incelenir.
          Gerçek veri/hesap değişikliği ve ödeme tamamlama <strong>kod seviyesinde engellidir</strong> — bu bir otonom/sınırsız
          pentest değildir.</p>
          <p><strong className="text-ink">Opsiyonel AI katmanı:</strong> İki kontrolde (yetki yükseltme + çok-adımlı iş mantığı)
          isteğe bağlı, hafif bir <strong>yapay zekâ danışma katmanı</strong> vardır; <strong>varsayılan olarak kapalıdır</strong> ve
          yalnız açıkken ek, doğrulanabilir bir gösterge bulduğunda devreye girer. Kapalıyken sonuçlar <strong>tam deterministik
          authenticated kontrollerle</strong> üretilir — normal ve beklenen davranıştır, rapor bunu şeffaf gösterir.</p>
          <p><strong className="text-ink">Kapsam:</strong> <strong>Cross-account</strong> (başka bir kullanıcının verisine
          erişim) IDOR bu sürümün kapsamı dışındadır.</p>
        </div>
      )}

      {/* Onaylar — (İŞ 3) ≤3 gruplu checkbox; sunucu-tarafı bireysel zorunluluk korunur. */}
      <h2 id="onaylar" className="mt-8 scroll-mt-24 text-sm font-bold uppercase tracking-wide text-ink-muted">2 · Onaylar</h2>
      {(selected || selectedBundle) && !allConsents && (
        <p className="mt-2 rounded-card border border-amber-300 bg-amber-50 px-3.5 py-2 text-xs font-semibold text-amber-800">
          Devam etmek için aşağıdaki {consentGroups.length} onayı işaretleyin.
        </p>
      )}
      <div className="mt-3 space-y-2.5">
        {consentGroups.map(({ checked, set, node }, i) => (
          <label key={i} className={`flex items-start gap-3 rounded-card border p-3.5 text-sm text-ink-soft transition ${checked ? 'border-brand-200 bg-brand-50/50' : 'border-amber-300 bg-amber-50/40'}`}>
            <input type="checkbox" checked={checked} onChange={(e) => set(e.target.checked)} className="mt-0.5 h-4 w-4 accent-brand" />
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
          {/* (İŞ 3) Risk kabulü aşağıdaki "2 · Onaylar" gruplu checkbox'ına taşındı. */}
          <p className="mt-3 rounded-card bg-white/70 p-3 text-xs text-ink-soft">{selectedPkg.activeTest.riskText}</p>
          <p className="mt-2 text-xs text-ink-muted">
            Onayınız; hesabınız, zaman damgası, IP ve metin sürümü ile birlikte otomatik olarak kayıt altına alınır
            (ek bilgi girmenize gerek yoktur). İsterseniz bir yetkilendirme PDF’i olarak siparişinize bağlanır.
          </p>
          {needsAuthCreds && (
            <div className="mt-4 border-t border-accent/30 pt-4">
              <p className="text-sm font-semibold text-brand">Test hesabı bilgileri</p>
              {authCredBlock}
            </div>
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
          Sipariş verebilirsiniz — <strong>taramanız en kısa sürede başlayacaktır</strong> ve durumu bu panelden
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

      {/* ÖN KONTROL UYARILARI — ana kolonda (mobil DÂHİL görünür). aside masaüstü-only olduğundan
          buraya taşındı; aksi halde mobilde onay kutusuna ulaşılamayıp sistem kilitleniyordu. */}
              {scopeChecking && (
                <p className="mt-3 text-center text-xs text-ink-muted">Hedefinize ulaşılıyor mu, ön kontrol yapılıyor…</p>
              )}
              {showUnreachableWarning && (
                <div id="oncontrol-uyari" className="mt-4 scroll-mt-24 rounded-card border-2 border-rose-400 bg-rose-50 p-4 text-sm">
                  <p className="font-bold text-rose-900">🚫 Hedefinize şu an dışarıdan ulaşılamıyor</p>
                  <p className="mt-1 leading-relaxed text-rose-900/90">
                    Sitenizin ana adresi (<strong>443/HTTPS ve 80/HTTP</strong>) şu an yanıt vermiyor. Bu bir hata
                    değildir — sitenizin <strong>yayında olmadığı, kapalı olduğu ya da bizim erişimimizi
                    engellediği</strong> anlamına gelir. Tarama şu an başlatılırsa dışarıdan test edilecek bir yüzey
                    bulunamayacağı için rapor büyük olasılıkla <strong>boş / "İncelenemedi"</strong> gelir.
                  </p>
                  <p className="mt-2 leading-relaxed text-rose-900/90">
                    <strong>Önerimiz:</strong> sitenizin yayında ve erişilebilir olduğundan emin olun, sonra bu sayfayı
                    yenileyip tekrar deneyin. Erişim sorununun geçici olduğunu düşünüyorsanız yine de devam edebilirsiniz.
                  </p>
                  <label className="mt-3 flex cursor-pointer items-start gap-2 font-medium text-rose-900">
                    <input type="checkbox" checked={unreachableAck} onChange={(e) => setUnreachableAck(e.target.checked)} className="mt-0.5" />
                    <span>Erişim sorununu anladım; yine de şimdi başlatmak istiyorum.</span>
                  </label>
                </div>
              )}
              {showLowScopeWarning && (
                <div id="oncontrol-uyari" className="mt-4 scroll-mt-24 rounded-card border-2 border-amber-400 bg-amber-50 p-4 text-sm">
                  <p className="font-bold text-amber-900">⚠️ Önemli Ön Kontrol</p>
                  <p className="mt-1 leading-relaxed text-amber-900/90">
                    Sitenizde otomatik hızlı taramada <strong>test edilebilir giriş noktası</strong> (form, query
                    parametresi, sayısal ID içeren uç nokta) <strong>neredeyse hiç bulunamadı</strong>. Bu genellikle
                    sitenin <strong>JavaScript ile render edilen (SPA)</strong> bir yapıya sahip olmasından kaynaklanır.
                  </p>
                  <p className="mt-2 leading-relaxed text-amber-900/90">
                    Tarama yine de çalıştırılacaktır, ancak çoğu kontrol <strong>"kapsam dışı / incelenemedi"</strong>{' '}
                    olarak sonuçlanabilir. Ödenen tutar <strong>bulgu garantisi değildir</strong>; kapsamlı bir
                    değerlendirme sürecinin tamamı içindir.
                  </p>
                  <label className="mt-3 flex cursor-pointer items-start gap-2 font-medium text-amber-900">
                    <input type="checkbox" checked={lowScopeAck} onChange={(e) => setLowScopeAck(e.target.checked)} className="mt-0.5" />
                    <span>Devam etmek istiyorum.</span>
                  </label>
                </div>
              )}


      {/* MOBİL: sol kolon sonunda (özet kolonu masaüstünde görünür; mobilde sabit alt çubuk var). */}
      {error && <p className="mt-4 rounded-card border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700 lg:hidden">{error}</p>}

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
                    {hostname && (
                      <div className="flex justify-between gap-2">
                        <dt className="text-ink-muted">Alan adı</dt>
                        <dd className="text-right font-semibold text-ink break-all">{hostname}</dd>
                      </div>
                    )}
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
                    <div className="flex items-baseline justify-between">
                      <span className="text-sm text-ink-muted">{recurring ? `Toplam · ${runs} tarama` : 'Toplam'}</span>
                      <span className="text-2xl font-extrabold text-brand">{formatMoney(totalMinor, getRegion(region))}</span>
                    </div>
                    <p className="mt-0.5 text-right text-[11px] text-ink-muted">KDV dahildir</p>
                  </div>
                </>
              ) : (
                <p className="mt-2 text-sm text-ink-soft">Devam etmek için bir paket seçin.</p>
              )}
              {needsDomainVerify ? (
                <button onClick={() => router.push(verifyHref)} className="btn-primary mt-4 flex w-full items-center justify-center gap-1.5">
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden><path d="M12 2l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V5l7-3z" /><path d="M9 12l2 2 4-4" /></svg>
                  Alan adını doğrula
                </button>
              ) : (
                <button onClick={onCta} disabled={ctaDisabled} className="btn-primary mt-4 w-full disabled:cursor-not-allowed disabled:opacity-50">
                  {ctaLabel}
                </button>
              )}
              {needsDomainVerify ? (
                <p className="mt-2 text-center text-[11px] text-amber-700">
                  Aktif tarama için önce alan adı sahipliğinizi DNS ile doğrulayın — doğrulandıktan sonra satın alabilirsiniz.
                </p>
              ) : disabledHint ? (
                disabledHint.scroll ? (
                  <button type="button" onClick={() => scrollToTarget(disabledHint.target ?? 'onaylar')} className="mt-2 w-full rounded-card border border-amber-300 bg-amber-50 px-3 py-2 text-center text-xs font-semibold text-amber-800 hover:bg-amber-100">
                    {disabledHint.text}
                  </button>
                ) : (
                  <p className="mt-2 text-center text-[11px] font-semibold text-amber-700">{disabledHint.text}</p>
                )
              ) : (
                <p className="mt-2 text-center text-[11px] text-ink-muted">
                  {recurring || startMode === 'later'
                    ? 'Zamanlanmış taramalarım ekranından yönetebilirsiniz.'
                    : 'Ödeme onaylanınca tarama otomatik başlar.'}
                </p>
              )}
              {/* Ödeme/başlatma hatası — CTA'nın HEMEN ALTINDA (masaüstü özet kolonunda). */}
              {error && <p className="mt-3 rounded-card border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{error}</p>}
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
                  KVKK’ya uygun · veriler şifreli saklanır
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
            {hostname && <p className="truncate text-[11px] text-ink-muted">{hostname}</p>}
            <p className="text-sm font-extrabold text-ink">
              {formatMoney(totalMinor, getRegion(region))}
              <span className="ml-1 text-[10px] font-normal text-ink-muted">KDV dahil</span>
            </p>
          </div>
          {needsDomainVerify ? (
            <button type="button" onClick={() => router.push(verifyHref)} className="btn-primary shrink-0 px-5">
              Doğrula
            </button>
          ) : disabledHint?.scroll ? (
            <button type="button" onClick={() => scrollToTarget(disabledHint.target ?? 'onaylar')} className="shrink-0 rounded-pill border border-amber-400 bg-amber-50 px-4 py-2 text-xs font-semibold text-amber-800">
              {disabledHint.text}
            </button>
          ) : (
            <button onClick={onCta} disabled={ctaDisabled} className="btn-primary shrink-0 px-5 disabled:cursor-not-allowed disabled:opacity-50">
              {ctaLabel}
            </button>
          )}
        </div>
        {disabledHint && !disabledHint.scroll && (
          <p className="mx-auto mt-1 max-w-6xl text-[11px] font-semibold text-amber-700">{disabledHint.text}</p>
        )}
      </div>
    </main>
  );
}
