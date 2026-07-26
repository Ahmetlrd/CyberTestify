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
  const [instructions, setInstructions] = useState<{ recordName: string; recordValue: string } | null>(
    null,
  );
  const [domainId, setDomainId] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const res = await api.createDomain(hostname);
      setDomainId(res.domainId);
      setInstructions(res.instructions);
    } catch (err: any) {
      setError(err.message);
    }
  }

  async function handleVerify() {
    if (!domainId) return;
    setError(null);
    try {
      const res = await api.verifyDomain(domainId);
      setStatus(res.verified ? 'verified' : 'failed');
      if (res.verified) router.push(`/packages?domainId=${domainId}`);
    } catch (err: any) {
      setError(err.message);
    }
  }

  return (
    <main className="container-page max-w-xl py-16">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h1>Site Sahipliğini Doğrula</h1>
        <button type="button" onClick={handleLogout} style={{ height: 32 }}>
          Çıkış
        </button>
      </div>
      {!instructions && (
        <form onSubmit={handleCreate}>
          <label>Domain (örn. ornek.com)</label>
          <input required value={hostname} onChange={(e) => setHostname(e.target.value)} />
          <button type="submit">Doğrulama kaydı üret</button>
        </form>
      )}

      {instructions && (
        <div>
          <p>DNS panelinize aşağıdaki TXT kaydını ekleyin:</p>
          <pre>
            {instructions.recordName}
            {'\n'}
            {instructions.recordValue}
          </pre>
          <p>Kayıt yayıldıktan sonra (birkaç dakika sürebilir):</p>
          <button onClick={handleVerify}>Doğrulamayı kontrol et</button>
          {status === 'failed' && <p style={{ color: 'crimson' }}>Kayıt henüz görünmüyor, birazdan tekrar deneyin.</p>}
        </div>
      )}

      {error && <p style={{ color: 'crimson' }}>{error}</p>}
    </main>
  );
}
