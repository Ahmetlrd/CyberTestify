'use client';

import { useEffect, useState } from 'react';
import { api, BETA_TOKEN_KEY } from '../../lib/api';
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
  const [taps, setTaps] = useState(0);
  const [code, setCode] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Gizli tetik: rozete 3 kez tıklanınca kod alanı GÖRÜNÜR olur (yalnız görünürlük; kod istemcide değil).
  function tapBadge() {
    setTaps((n) => {
      const next = n + 1;
      if (next >= 3) setShowCode(true);
      return next;
    });
  }

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
        <button
          type="button"
          onClick={tapBadge}
          aria-label={d.comingSoon}
          className="select-none rounded-pill bg-brand px-4 py-1.5 text-xs font-extrabold uppercase tracking-wide text-accent transition active:scale-95"
        >
          {d.comingSoon}
        </button>
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

/* ————————————————— AÇIK PANEL (yine de gerçek koşu YOK — stub) ————————————————— */
function Panel({ d, onLock }: { d: D; onLock: () => void }) {
  const [domain, setDomain] = useState('');
  const [estimating, setEstimating] = useState(false);
  const [estimate, setEstimate] = useState<Awaited<ReturnType<typeof api.betaEstimate>> | null>(null);
  const [estError, setEstError] = useState<string | null>(null);

  const [level, setLevel] = useState<Level>('S2');
  const [env, setEnv] = useState<Env>('test');
  const [own, setOwn] = useState(false);
  const [risk, setRisk] = useState(false);
  const [prodAck, setProdAck] = useState(false);

  const [starting, setStarting] = useState(false);
  const [startError, setStartError] = useState<string | null>(null);
  const [stub, setStub] = useState<{ title: string; body: string } | null>(null);

  const s3prod = level === 'S3' && env === 'prod';
  const canStart = own && risk && (!s3prod || prodAck);

  async function runEstimate(e: React.FormEvent) {
    e.preventDefault();
    setEstError(null);
    setEstimating(true);
    setEstimate(null);
    try {
      setEstimate(await api.betaEstimate(domain.trim()));
    } catch (err) {
      setEstError((err as Error).message);
    } finally {
      setEstimating(false);
    }
  }

  async function start() {
    setStartError(null);
    setStub(null);
    if (!canStart) {
      setStartError(d.needConsents);
      return;
    }
    setStarting(true);
    try {
      const r = await api.betaStart({
        domain: domain.trim() || 'example.com',
        level,
        environment: env,
        ownershipConfirmed: own,
        riskAccepted: risk,
        prodElevatedAccepted: s3prod ? prodAck : undefined,
      });
      // 3b-i: started === false her zaman. Gerçek koşu YOK.
      setStub({ title: d.stubTitle, body: r.message || d.stubBody });
    } catch (err) {
      setStartError((err as Error).message);
    } finally {
      setStarting(false);
    }
  }

  const priceBand = (() => {
    const sug = estimate?.suggestion;
    if (!sug) return null;
    const { priceRange } = sug;
    return (
      <div className="mt-3 rounded-card border border-accent/40 bg-accent-soft/40 p-4">
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <span className="font-semibold text-ink">{d.priceTitle}</span>
          <span className="text-xs text-ink-muted">
            {d.tierLabel}: <b>{sug.tier.label}</b> · {d.scoreLabel}: <b>{sug.score}</b>
          </span>
        </div>
        <div className="mt-1 text-lg font-extrabold text-brand">
          {priceRange.placeholder || priceRange.minTL == null || priceRange.maxTL == null
            ? d.priceUnset
            : `₺${priceRange.minTL.toLocaleString('tr-TR')} – ₺${priceRange.maxTL.toLocaleString('tr-TR')}`}
        </div>
        <p className="mt-1 text-xs text-ink-muted">{d.priceGuarantee}</p>
      </div>
    );
  })();

  return (
    <div className="card p-6 sm:p-8">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h3 className="text-xl font-bold text-ink">{d.panelTitle}</h3>
          <p className="mt-1 text-sm text-ink-soft">{d.panelSubtitle}</p>
        </div>
        <button
          type="button"
          onClick={() => {
            window.localStorage.removeItem(BETA_TOKEN_KEY);
            onLock();
          }}
          className="btn btn-ghost shrink-0 text-xs"
        >
          ✕
        </button>
      </div>

      {/* Domain → fiyat bandı (pasif) */}
      <form onSubmit={runEstimate} className="mt-6">
        <label className="label" htmlFor="rt-domain">
          {d.domainLabel}
        </label>
        <div className="flex gap-2">
          <input
            id="rt-domain"
            className="field flex-1"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder={d.domainPlaceholder}
          />
          <button type="submit" disabled={estimating || domain.trim().length < 3} className="btn btn-outline shrink-0">
            {estimating ? d.estimating : d.estimateCta}
          </button>
        </div>
        {estError && <p className="form-error mt-1">{estError}</p>}
        {priceBand}
      </form>

      {/* Risk seviyesi */}
      <fieldset className="mt-6">
        <legend className="label">{d.levelLabel}</legend>
        <div className="grid gap-2 sm:grid-cols-3">
          {d.levels.map((lv, i) => {
            const key = (['S1', 'S2', 'S3'] as Level[])[i];
            const active = level === key;
            return (
              <button
                key={key}
                type="button"
                onClick={() => setLevel(key)}
                className={`rounded-card border p-3 text-left transition ${
                  active ? 'border-brand bg-brand-50' : 'border-line bg-surface hover:border-brand-300'
                }`}
              >
                <div className="text-sm font-bold text-ink">{lv.name}</div>
                <div className="text-[11px] font-semibold uppercase tracking-wide text-accent-600">{lv.tag}</div>
              </button>
            );
          })}
        </div>
      </fieldset>

      {/* Ortam */}
      <fieldset className="mt-5">
        <legend className="label">{d.envLabel}</legend>
        <div className="flex flex-wrap gap-2">
          {([['test', d.envTest], ['staging', d.envStaging], ['prod', d.envProd]] as [Env, string][]).map(([key, lbl]) => (
            <button
              key={key}
              type="button"
              onClick={() => setEnv(key)}
              className={`rounded-pill border px-4 py-1.5 text-sm font-medium transition ${
                env === key ? 'border-brand bg-brand text-white' : 'border-line bg-surface text-ink-soft hover:border-brand-300'
              }`}
            >
              {lbl}
            </button>
          ))}
        </div>
        {env === 'prod' && level !== 'S3' && <p className="mt-2 text-xs text-ink-muted">{d.prodRedirect}</p>}
      </fieldset>

      {/* S3 + prod → ek açık uyarı + onay */}
      {s3prod && (
        <div className="mt-4 rounded-card border-2 border-amber-400 bg-amber-50 p-4">
          <p className="text-sm font-semibold text-amber-900">{d.prodS3Warn}</p>
          <label className="mt-2 flex items-start gap-2 text-sm text-amber-900">
            <input type="checkbox" className="mt-0.5" checked={prodAck} onChange={(e) => setProdAck(e.target.checked)} />
            <span>{d.prodS3Consent}</span>
          </label>
        </div>
      )}

      {/* Sahiplik / risk onayı (zorunlu) */}
      <div className="mt-5 space-y-2">
        <label className="flex items-start gap-2 text-sm text-ink-soft">
          <input type="checkbox" className="mt-0.5" checked={own} onChange={(e) => setOwn(e.target.checked)} />
          <span>{d.ownConsent}</span>
        </label>
        <label className="flex items-start gap-2 text-sm text-ink-soft">
          <input type="checkbox" className="mt-0.5" checked={risk} onChange={(e) => setRisk(e.target.checked)} />
          <span>{d.riskConsent}</span>
        </label>
      </div>

      {startError && <p className="form-error mt-3">{startError}</p>}
      <button type="button" onClick={start} disabled={starting || !canStart} className="btn btn-primary mt-4 w-full">
        {starting ? d.starting : d.startCta}
      </button>

      {/* 3b-i STUB — gerçek koşu YOK */}
      {stub && (
        <div className="mt-4 rounded-card border border-brand-300 bg-brand-50 p-4 text-center">
          <div className="text-sm font-bold text-brand">{stub.title}</div>
          <p className="mt-1 text-sm text-ink-soft">{stub.body}</p>
        </div>
      )}
    </div>
  );
}
