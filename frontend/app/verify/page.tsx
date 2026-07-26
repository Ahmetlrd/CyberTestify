'use client';

import { useCallback, useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { api } from '../../lib/api';

type Domain = {
  id: string;
  hostname: string;
  status: string;
  verifiedAt: string | null;
  valid: boolean;
  instructions: { recordName: string; recordValue: string };
};

export default function VerifyHub() {
  const router = useRouter();
  const [domains, setDomains] = useState<Domain[]>([]);
  const [loading, setLoading] = useState(true);
  const [newHostname, setNewHostname] = useState('');
  const [openId, setOpenId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [showAdd, setShowAdd] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    const list = await api.listDomains();
    setDomains(list);
    return list;
  }, []);

  useEffect(() => {
    if (typeof window !== 'undefined' && !window.localStorage.getItem('token')) {
      router.push('/login');
      return;
    }
    refresh()
      .catch((e: any) => setError(e.message))
      .finally(() => setLoading(false));
  }, [router, refresh]);

  async function addDomain(e: React.FormEvent) {
    e.preventDefault();
    if (!newHostname.trim() || busy) return;
    setBusy(true);
    setError(null);
    try {
      const res = await api.createDomain(newHostname.trim());
      setNewHostname('');
      setShowAdd(false);
      await refresh();
      setOpenId(res.domainId);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function check(id: string) {
    setBusy(true);
    setError(null);
    try {
      const { verified } = await api.verifyDomain(id);
      await refresh();
      if (verified) router.push(`/order?domainId=${id}`);
      else setError('Kayıt henüz görünmüyor. DNS yayılımı biraz sürebilir; birazdan tekrar deneyin.');
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  function logout() {
    window.localStorage.removeItem('token');
    router.push('/');
  }

  const validDomains = domains.filter((d) => d.valid);
  const pendingDomains = domains.filter((d) => !d.valid);

  return (
    <main className="container-page max-w-2xl py-14">
      <div className="flex items-center justify-between">
        <div>
          <p className="eyebrow">Panelim</p>
          <h1 className="mt-1 text-2xl font-extrabold text-brand">Taramaya Başla</h1>
        </div>
        <button type="button" onClick={logout} className="btn-ghost text-sm">
          Çıkış
        </button>
      </div>

      {loading ? (
        <div className="mt-8 h-32 animate-pulse rounded-card bg-brand-50" />
      ) : (
        <>
          {/* Geçerli (doğrulanmış) domainler → doğrudan tarama */}
          {validDomains.length > 0 && (
            <section className="mt-8">
              <h2 className="text-sm font-bold uppercase tracking-wide text-ink-muted">
                Doğrulanmış alan adların
              </h2>
              <div className="mt-3 space-y-2.5">
                {validDomains.map((d) => (
                  <div key={d.id} className="card flex items-center justify-between gap-3 p-4">
                    <div>
                      <div className="font-semibold text-ink">{d.hostname}</div>
                      <span className="mt-0.5 inline-flex items-center gap-1 text-xs font-medium text-emerald-600">
                        <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" /> Doğrulandı · geçerli
                      </span>
                    </div>
                    <button onClick={() => router.push(`/order?domainId=${d.id}`)} className="btn-primary shrink-0">
                      Taramayı Başlat
                    </button>
                  </div>
                ))}
              </div>
            </section>
          )}

          {/* Doğrulama bekleyen / süresi dolan */}
          {pendingDomains.length > 0 && (
            <section className="mt-8">
              <h2 className="text-sm font-bold uppercase tracking-wide text-ink-muted">
                Doğrulama bekleyen
              </h2>
              <div className="mt-3 space-y-2.5">
                {pendingDomains.map((d) => {
                  const expired = d.status === 'verified' && !d.valid;
                  const open = openId === d.id;
                  return (
                    <div key={d.id} className="card p-4">
                      <div className="flex items-center justify-between gap-3">
                        <div>
                          <div className="font-semibold text-ink">{d.hostname}</div>
                          <span className={`mt-0.5 text-xs font-medium ${expired ? 'text-red-600' : 'text-amber-600'}`}>
                            {expired ? 'Süresi doldu — yeniden doğrula' : 'Henüz doğrulanmadı'}
                          </span>
                        </div>
                        <button onClick={() => setOpenId(open ? null : d.id)} className="btn-outline shrink-0 text-sm">
                          {open ? 'Gizle' : 'Doğrula'}
                        </button>
                      </div>
                      {open && (
                        <div className="mt-4 border-t border-line pt-4">
                          <p className="text-sm text-ink-soft">DNS panelinize aşağıdaki <strong>TXT</strong> kaydını ekleyin:</p>
                          <div className="mt-2 space-y-2 rounded-card bg-brand-deep p-3.5 font-mono text-xs text-white/90">
                            <div>
                              <span className="text-white/45">Ad:</span>{' '}
                              <span className="break-all text-emerald-300">{d.instructions.recordName}</span>
                            </div>
                            <div>
                              <span className="text-white/45">Değer:</span>{' '}
                              <span className="break-all text-accent">{d.instructions.recordValue}</span>
                            </div>
                          </div>
                          <button onClick={() => check(d.id)} disabled={busy} className="btn-primary mt-3 disabled:opacity-60">
                            {busy ? 'Kontrol ediliyor…' : 'Doğrulamayı kontrol et'}
                          </button>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </section>
          )}

          {/* Yeni alan adı ekle */}
          <section className="mt-8">
            {!showAdd ? (
              <button onClick={() => setShowAdd(true)} className="btn-outline">
                + Yeni alan adı ekle
              </button>
            ) : (
              <form onSubmit={addDomain} className="card p-5">
                <label className="label">Yeni alan adı</label>
                <div className="flex flex-col gap-2 sm:flex-row">
                  <input
                    required
                    placeholder="ornek.com"
                    className="field flex-1"
                    value={newHostname}
                    onChange={(e) => setNewHostname(e.target.value)}
                  />
                  <button type="submit" disabled={busy} className="btn-primary disabled:opacity-60">
                    {busy ? 'Ekleniyor…' : 'Ekle ve doğrula'}
                  </button>
                </div>
              </form>
            )}
          </section>

          {domains.length === 0 && !showAdd && (
            <p className="mt-4 text-sm text-ink-muted">
              Henüz alan adın yok. Başlamak için bir alan adı ekleyip doğrula.
            </p>
          )}
        </>
      )}

      {error && <p className="form-error mt-6">{error}</p>}
    </main>
  );
}
