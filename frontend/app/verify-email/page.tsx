'use client';

import { Suspense, useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { api } from '../../lib/api';

function VerifyEmailForm() {
  const router = useRouter();
  const next = useSearchParams().get('next') || '/verify';
  const [email, setEmail] = useState<string>('');
  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [resendBusy, setResendBusy] = useState(false);

  useEffect(() => {
    if (typeof window !== 'undefined' && !window.localStorage.getItem('token')) {
      router.replace('/login');
      return;
    }
    // Zaten dogrulanmissa dogrudan devam ettir; degilse e-postayi goster.
    api.me()
      .then((m) => {
        if (m.emailVerified) router.replace(next);
        else setEmail(m.email);
      })
      .catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function handleVerify(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setInfo(null);
    if (!/^\d{6}$/.test(code)) return setError('Kod 6 haneli olmalıdır.');
    setBusy(true);
    try {
      await api.verifyEmail(code);
      router.push(next);
    } catch (err: any) {
      setError(err.message);
      setBusy(false);
    }
  }

  async function handleResend() {
    setError(null);
    setInfo(null);
    setResendBusy(true);
    try {
      await api.resendVerification();
      setInfo('Yeni bir doğrulama kodu gönderildi. Gelen kutunuzu (ve spam klasörünü) kontrol edin.');
    } catch (err: any) {
      setError(err.message);
    } finally {
      setResendBusy(false);
    }
  }

  return (
    <div className="card p-8">
      <h1 className="text-2xl font-extrabold text-brand">E-postanızı Doğrulayın</h1>
      <p className="mt-1 text-sm text-ink-muted">
        {email ? <>Doğrulama kodunu <strong>{email}</strong> adresine gönderdik.</> : 'Doğrulama kodunu e-posta adresinize gönderdik.'}{' '}
        Kod 15 dakika geçerlidir.
      </p>
      <form onSubmit={handleVerify} className="mt-6 space-y-4">
        <div>
          <label className="label">6 haneli kod</label>
          <input
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={6}
            placeholder="000000"
            className="field text-center font-mono text-2xl tracking-[0.4em]"
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
          />
        </div>
        {error && <p className="form-error">{error}</p>}
        {info && <p className="text-sm text-emerald-700">{info}</p>}
        <button type="submit" disabled={busy} className="btn-primary w-full disabled:opacity-60">
          {busy ? 'Doğrulanıyor…' : 'Doğrula ve devam et'}
        </button>
      </form>
      <div className="mt-5 flex items-center justify-between text-sm">
        <button onClick={handleResend} disabled={resendBusy} className="font-semibold text-accent-600 hover:underline disabled:opacity-60">
          {resendBusy ? 'Gönderiliyor…' : 'Kodu tekrar gönder'}
        </button>
        <Link href="/verify" className="text-ink-soft hover:underline">Daha sonra</Link>
      </div>
      <p className="mt-4 text-xs text-ink-muted">
        Panelinizi gezebilirsiniz; ancak <strong>satın alma</strong> için e-posta doğrulaması gereklidir.
      </p>
    </div>
  );
}

export default function VerifyEmailPage() {
  return (
    <main className="container-page max-w-md py-16">
      <Suspense fallback={<div className="card p-8 text-sm text-ink-muted">Yükleniyor…</div>}>
        <VerifyEmailForm />
      </Suspense>
    </main>
  );
}
