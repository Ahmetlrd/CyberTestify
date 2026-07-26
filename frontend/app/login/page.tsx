'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { api } from '../../lib/api';

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const { token } = await api.login(email, password);
      window.localStorage.setItem('token', token);
      router.push('/verify');
    } catch (err: any) {
      setError(err.message);
      setBusy(false);
    }
  }

  return (
    <main className="container-page max-w-md py-16">
      <div className="card p-8">
        <h1 className="text-2xl font-extrabold text-brand">Giriş Yap</h1>
        <p className="mt-1 text-sm text-ink-muted">Hesabınıza erişin ve taramanızı yönetin.</p>
        <form onSubmit={handleSubmit} className="mt-6 space-y-4">
          <div>
            <label className="label">E-posta</label>
            <input type="email" required className="field" value={email} onChange={(e) => setEmail(e.target.value)} />
          </div>
          <div>
            <label className="label">Şifre</label>
            <input type="password" required className="field" value={password} onChange={(e) => setPassword(e.target.value)} />
          </div>
          {error && <p className="form-error">{error}</p>}
          <button type="submit" disabled={busy} className="btn-primary w-full disabled:opacity-60">
            {busy ? 'Giriş yapılıyor…' : 'Giriş yap'}
          </button>
        </form>
      </div>
      <p className="mt-5 text-center text-sm text-ink-soft">
        Hesabınız yok mu?{' '}
        <Link href="/register" className="font-semibold text-accent-600 hover:underline">
          Ücretsiz kayıt olun
        </Link>
      </p>
    </main>
  );
}
