'use client';

import { Suspense, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { api } from '../../lib/api';
import { PasswordInput } from '../../components/PasswordInput';

function ResetForm() {
  const router = useRouter();
  const token = useSearchParams().get('token') || '';
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (password.length < 8) return setError('Şifre en az 8 karakter olmalıdır.');
    if (password !== confirm) return setError('Şifreler eşleşmiyor.');
    setBusy(true);
    try {
      const { token: authToken } = await api.resetPassword(token, password);
      // Surtunmesiz: yeni sifreyle otomatik giris.
      window.localStorage.setItem('token', authToken);
      router.push('/verify');
    } catch (err: any) {
      setError(err.message);
      setBusy(false);
    }
  }

  if (!token) {
    return (
      <div className="card p-8">
        <h1 className="text-2xl font-extrabold text-brand">Geçersiz bağlantı</h1>
        <p className="mt-2 text-sm text-ink-soft">Sıfırlama bağlantısı eksik veya hatalı. Lütfen yeniden talep edin.</p>
        <Link href="/forgot-password" className="btn-primary mt-6 inline-flex">Yeni bağlantı iste</Link>
      </div>
    );
  }

  return (
    <div className="card p-8">
      <h1 className="text-2xl font-extrabold text-brand">Yeni Şifre Belirle</h1>
      <p className="mt-1 text-sm text-ink-muted">Hesabınız için yeni bir şifre oluşturun.</p>
      <form onSubmit={handleSubmit} className="mt-6 space-y-4">
        <div>
          <label className="label">Yeni şifre</label>
          <PasswordInput required autoComplete="new-password" value={password} onChange={setPassword} />
        </div>
        <div>
          <label className="label">Yeni şifre (tekrar)</label>
          <PasswordInput required autoComplete="new-password" value={confirm} onChange={setConfirm} />
        </div>
        {error && <p className="form-error">{error}</p>}
        <button type="submit" disabled={busy} className="btn-primary w-full disabled:opacity-60">
          {busy ? 'Kaydediliyor…' : 'Şifreyi güncelle'}
        </button>
      </form>
    </div>
  );
}

export default function ResetPasswordPage() {
  return (
    <main className="container-page max-w-md py-16">
      <Suspense fallback={<div className="card p-8 text-sm text-ink-muted">Yükleniyor…</div>}>
        <ResetForm />
      </Suspense>
    </main>
  );
}
