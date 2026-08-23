'use client';

import { useEffect, useState } from 'react';
import { api, BETA_TOKEN_KEY } from '../../lib/api';
import { RT_REVEAL_EVENT } from './DisclaimerReveal';
import type { Dict } from '../../config/i18n';

type D = Dict['otonom'];
type Level = 'S1' | 'S2' | 'S3';
type Env = 'test' | 'staging' | 'prod';

/**
 * (OTONOM AI RED TEAM — 3b-i) Beta kapısı + panel — interaktif ada.
 * KRİTİK: Erişim kodu (CYBER-TEST-2026) BU DOSYADA/istemcide YOKTUR. "Paneli aç" sadece
 * girilen kodu backend'e yollar; backend .env'deki BETA_ACCESS_CODE ile karşılaştırır ve
 * başarılıysa sunucu-imzalı bir grant token döner. Panel görünür olsa bile bu fazda GERÇEK
 * koşu tetiklenmez — /start yalnız "Hazırlanıyor" stub'ı döner.
 */
export function RedTeamGate({ d }: { d: D }) {
  const [unlocked, setUnlocked] = useState(false);
  const [hydrated, setHydrated] = useState(false);

  useEffect(() => {
    setUnlocked(!!window.localStorage.getItem(BETA_TOKEN_KEY));
    setHydrated(true);
  }, []);

  if (!hydrated) {
    return <div className="card p-6 text-sm text-ink-muted">…</div>;
  }
  return unlocked ? <Panel d={d} onLock={() => setUnlocked(false)} /> : <Locked d={d} onUnlock={() => setUnlocked(true)} />;
}

/* ————————————————— KİLİTLİ DURUM (public "Yakında") ————————————————— */
function Locked({ d, onUnlock }: { d: D; onUnlock: () => void }) {
  const [showCode, setShowCode] = useState(false);
  const [code, setCode] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Gizli tetik: disclaimer'daki "içermez" kelimesine 3-tık -> DisclaimerReveal olay yayınlar,
  // burada dinleyip kod alanını açarız (yalnız görünürlük; kod istemcide DEĞİL).
  useEffect(() => {
    const onReveal = () => setShowCode(true);
    window.addEventListener(RT_REVEAL_EVENT, onReveal);
    return () => window.removeEventListener(RT_REVEAL_EVENT, onReveal);
  }, []);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const r = await api.betaUnlock(code.trim());
      window.localStorage.setItem(BETA_TOKEN_KEY, r.betaToken);
      onUnlock();
    } catch (err) {
      setError((err as Error).message || d.invalid);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="card overflow-hidden">
      <div className="flex flex-col items-center gap-4 p-8 text-center">
        {/* Yalnız etiket — tıklama tetiği DEĞİL (gizli tetik disclaimer'daki kelimede). */}
        <span className="rounded-pill bg-brand px-4 py-1.5 text-xs font-extrabold uppercase tracking-wide text-accent">
          {d.comingSoon}
        </span>
        <h3 className="text-xl font-bold text-ink">{d.lockedTitle}</h3>
        <p className="max-w-md text-sm text-ink-soft">{d.lockedBody}</p>

        {showCode && (
          <form onSubmit={submit} className="mt-2 w-full max-w-sm text-left">
            <label className="label" htmlFor="rt-code">
              {d.codeLabel}
            </label>
            <input
              id="rt-code"
              className="field"
              type="password"
              autoComplete="off"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder={d.codePlaceholder}
            />
            {error && <p className="form-error mt-1">{error}</p>}
            <button type="submit" disabled={loading || !code.trim()} className="btn btn-primary mt-3 w-full">
              {loading ? d.unlocking : d.unlock}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}

/* ————————————————— AÇIK PANEL — GERÇEK S1 SATIN ALMA (ödeme + admin onay akışı) ————————————————— */
function Panel({ d, onLock }: { d: D; onLock: () => void }) {
  const [domain, setDomain] = useState('');
  const [priceLoading, setPriceLoading] = useState(false);
  const [price, setPrice] = useState<Awaited<ReturnType<typeof api.betaS1Price>> | null>(null);
  const [priceErr, setPriceErr] = useState<string | null>(null);

  const [own, setOwn] = useState(false);
  const [risk, setRisk] = useState(false);
  const [distance, setDistance] = useState(false);
  const [withdrawal, setWithdrawal] = useState(false);
  const [cross, setCross] = useState(false);

  const [promo, setPromo] = useState('');
  const [buying, setBuying] = useState(false);
  const [buyErr, setBuyErr] = useState<string | null>(null);

  const canBuy = !!price && own && risk && distance && withdrawal && cross;

  // Domain değişince eski fiyatı geçersiz kıl (yanlış fiyatla satın alma olmasın).
  function onDomainChange(v: string) { setDomain(v); if (price) setPrice(null); }

  async function loadPrice(e: React.FormEvent) {
    e.preventDefault();
    setPriceErr(null); setPrice(null); setPriceLoading(true);
    try { setPrice(await api.betaS1Price(domain.trim())); }
    catch (err) { setPriceErr((err as Error).message); }
    finally { setPriceLoading(false); }
  }

  async function buy() {
    setBuyErr(null);
    if (!canBuy) { setBuyErr('Önce fiyatı hesaplayın ve tüm onayları işaretleyin.'); return; }
    setBuying(true);
    try {
      const dom = await api.createDomain(domain.trim()); // idempotent — kayıtlıysa mevcut domainId döner
      const order = await api.createOrder(
        dom.domainId,
        'redteam_s1',
        { ownershipConfirmed: true, distanceContractAccepted: true, withdrawalWaived: true, crossBorderTransfer: true },
        'tr',
        { riskAccepted: true },
        undefined,
        promo.trim() || undefined,
      );
      // %100 promo → doğrudan panel; aksi halde iyzico ödeme sayfasına yönlen.
      if (order.paymentPageUrl) { window.location.href = order.paymentPageUrl; return; }
      window.location.href = `/dashboard/${order.orderId}`;
    } catch (err) {
      const msg = (err as Error).message || 'Satın alma başlatılamadı.';
      if (/401|oturum|giriş yap|unauthor/i.test(msg)) {
        window.location.href = `/login?next=${encodeURIComponent('/otonom-red-team')}`;
        return;
      }
      setBuyErr(msg);
    } finally { setBuying(false); }
  }

  const chk = (v: boolean, set: (b: boolean) => void, label: React.ReactNode) => (
    <label className="flex items-start gap-2 text-sm text-ink-soft">
      <input type="checkbox" className="mt-0.5" checked={v} onChange={(e) => set(e.target.checked)} />
      <span>{label}</span>
    </label>
  );

  return (
    <div className="card p-6 sm:p-8">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h3 className="text-xl font-bold text-ink">Otonom AI Red Team — Satın Al</h3>
          <p className="mt-1 text-sm text-ink-soft">Hedefinizi girin, karmaşıklık-bazlı fiyatı görün, ödeyin. Tarama bitince raporunuz önce ekibimizce gözden geçirilir, sonra size açılır.</p>
        </div>
        <button type="button" onClick={() => { window.localStorage.removeItem(BETA_TOKEN_KEY); onLock(); }} className="btn btn-ghost shrink-0 text-xs">✕</button>
      </div>

      {/* Seviye seçimi: S1 beta (aktif), S2/S3 yakında (kapalı) */}
      <fieldset className="mt-6">
        <legend className="label">Seviye</legend>
        <div className="grid gap-2 sm:grid-cols-3">
          <div className="rounded-card border-2 border-brand bg-brand-50 p-3">
            <div className="flex items-center gap-2"><span className="text-sm font-bold text-ink">S1</span><span className="rounded-pill bg-brand px-2 py-0.5 text-[10px] font-bold uppercase text-white">Beta</span></div>
            <div className="text-[11px] text-ink-muted">Pasif + hafif-aktif · deneysel</div>
          </div>
          {(['S2', 'S3'] as const).map((lv) => (
            <div key={lv} className="rounded-card border border-line bg-surface p-3 opacity-60">
              <div className="flex items-center gap-2"><span className="text-sm font-bold text-ink-muted">{lv}</span><span className="rounded-pill bg-ink-muted/20 px-2 py-0.5 text-[10px] font-bold uppercase text-ink-muted">Yakında</span></div>
              <div className="text-[11px] text-ink-muted">{lv === 'S2' ? 'Aktif doğrulama (dengeli)' : 'Geniş yüzey (agresif)'}</div>
            </div>
          ))}
        </div>
      </fieldset>

      {/* Domain → karmaşıklık-bazlı NET fiyat */}
      <form onSubmit={loadPrice} className="mt-6">
        <label className="label" htmlFor="rt-domain">Hedef alan adı</label>
        <div className="flex gap-2">
          <input id="rt-domain" className="field flex-1" value={domain} onChange={(e) => onDomainChange(e.target.value)} placeholder="ornek.com" />
          <button type="submit" disabled={priceLoading || domain.trim().length < 3} className="btn btn-outline shrink-0">
            {priceLoading ? 'Hesaplanıyor…' : 'Fiyatı gör'}
          </button>
        </div>
        {priceErr && <p className="form-error mt-1">{priceErr}</p>}
        {price && (
          <div className="mt-3 rounded-card border border-accent/40 bg-accent-soft/40 p-4">
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <span className="font-semibold text-ink">Fiyat (karmaşıklık-bazlı)</span>
              <span className="text-xs text-ink-muted">Kademe: <b>{price.tier.label}</b></span>
            </div>
            <div className="mt-1 text-2xl font-extrabold text-brand">₺{price.priceTL.toLocaleString('tr-TR')}</div>
            <p className="mt-1 text-xs text-ink-muted">{price.reason}. Üst sınır ₺2.500 — ödeme öncesi sabittir, sürpriz fatura yoktur.</p>
          </div>
        )}
      </form>

      {/* Zorunlu onaylar (siparişle aynı hukuki set) */}
      <div className="mt-6 space-y-2.5">
        {chk(own, setOwn, 'Hedef alan adının/altyapının sahibi veya yetkili temsilcisiyim; bu testi yürütmeye yetkim var.')}
        {chk(risk, setRisk, 'Bunun DENEYSEL, deterministik-olmayan bir tarama olduğunu ve resmi bir sızma testi/denetim yerine geçmediğini kabul ediyorum.')}
        {chk(distance, setDistance, <>Mesafeli Satış Sözleşmesi ve Ön Bilgilendirme Formu'nu okudum, onaylıyorum.</>)}
        {chk(withdrawal, setWithdrawal, 'Hizmet ödemeden hemen sonra başladığı için cayma hakkımdan feragat ediyorum.')}
        {chk(cross, setCross, 'Tarama verimin, güvenlik analizi için yurt dışındaki (ABD) yapay zekâ sağlayıcısına aktarılmasına açık rıza veriyorum (KVKK m.9).')}
      </div>

      {/* Promosyon kodu (opsiyonel) — kod GÖSTERİLMEZ, boş alan (6 paket akışıyla aynı). */}
      <div className="mt-5">
        <label className="label" htmlFor="rt-promo">Promosyon kodu (opsiyonel)</label>
        <input id="rt-promo" className="field w-full uppercase" value={promo} onChange={(e) => setPromo(e.target.value)} placeholder="KODUNUZ" autoCapitalize="characters" />
      </div>

      {buyErr && <p className="form-error mt-3">{buyErr}</p>}
      <button type="button" onClick={buy} disabled={buying || !canBuy} className="btn btn-primary mt-4 w-full">
        {buying ? 'Yönlendiriliyor…' : !price ? 'Önce fiyatı görün' : promo.trim() ? 'Kodu Uygula ve Başlat' : `₺${price.priceTL.toLocaleString('tr-TR')} — Öde ve Başlat`}
      </button>
    </div>
  );
}
