'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { api } from '../../lib/api';

export default function VerifyPage() {
  const router = useRouter();

  useEffect(() => {
    if (typeof window !== 'undefined' && !window.localStorage.getItem('token')) {
      router.push('/login');
    }
  }, [router]);

  function handleLogout() {
    window.localStorage.removeItem('token');
    router.push('/login');
  }

  const [hostname, setHostname] = useState('');
  const [instructions, setInstructions] = useState<{ recordName: string; recordValue: string } | null>(null);
  const [domainId, setDomainId] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const res = await api.createDomain(hostname);
      setDomainId(res.domainId);
      setInstructions(res.instructions);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function handleVerify() {
    if (!domainId) return;
    setError(null);
    setBusy(true);
    try {
      const res = await api.verifyDomain(domainId);
      setStatus(res.verified ? 'verified' : 'failed');
      if (res.verified) router.push(`/order?domainId=${domainId}`);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="container-page max-w-xl py-16">
      <div className="flex items-center justify-between">
        <div>
          <p className="eyebrow">Adım 1 / 3</p>
          <h1 className="mt-1 text-2xl font-extrabold text-brand">Site Sahipliğini Doğrula</h1>
        </div>
        <button type="button" onClick={handleLogout} className="btn-ghost text-sm">
          Çıkış
        </button>
      </div>

      <div className="card mt-6 p-6">
        {!instructions ? (
          <form onSubmit={handleCreate} className="space-y-4">
            <p className="text-sm text-ink-soft">
              Yalnızca sahibi olduğunuz alan adına tarama yapılır. Alan adınızı girin, size özel bir
              DNS doğrulama kaydı üretelim.
            </p>
            <div>
              <label className="label">Alan adı</label>
              <input
                required
                placeholder="ornek.com"
                className="field"
                value={hostname}
                onChange={(e) => setHostname(e.target.value)}
              />
            </div>
            <button type="submit" disabled={busy} className="btn-primary w-full disabled:opacity-60 sm:w-auto">
              {busy ? 'Oluşturuluyor…' : 'Doğrulama kaydı üret'}
            </button>
          </form>
        ) : (
          <div className="space-y-4">
            <p className="text-sm text-ink-soft">
              DNS panelinize aşağıdaki <strong>TXT</strong> kaydını ekleyin:
            </p>
            <div className="space-y-2 rounded-card bg-brand-deep p-4 font-mono text-xs text-white/90">
              <div>
                <span className="text-white/45">Kayıt adı:</span> <span className="break-all text-emerald-300">{instructions.recordName}</span>
              </div>
              <div>
                <span className="text-white/45">Değer:</span> <span className="break-all text-accent">{instructions.recordValue}</span>
              </div>
            </div>
            <p className="text-sm text-ink-muted">Kayıt yayıldıktan sonra (birkaç dakika sürebilir) kontrol edin:</p>
            <button onClick={handleVerify} disabled={busy} className="btn-primary w-full disabled:opacity-60 sm:w-auto">
              {busy ? 'Kontrol ediliyor…' : 'Doğrulamayı kontrol et'}
            </button>
            {status === 'failed' && (
              <p className="form-error">Kayıt henüz görünmüyor. DNS yayılımı biraz sürebilir; birazdan tekrar deneyin.</p>
            )}
          </div>
        )}

        {error && <p className="form-error mt-4">{error}</p>}
      </div>
    </main>
  );
}
