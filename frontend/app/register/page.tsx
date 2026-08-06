'use client';

import { useState, useEffect } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { api } from '../../lib/api';
import { PasswordInput } from '../../components/PasswordInput';
import { GoogleButton } from '../../components/GoogleButton';

export default function RegisterPage() {
  const router = useRouter();
  // ?next: satın-alma akışında paket niyeti kayıt sonrası da korunsun (yoksa /verify).
  const next = useSearchParams().get('next') || '/verify';
  useEffect(() => {
    if (typeof window !== 'undefined' && window.localStorage.getItem('token')) {
      router.replace(next);
    }
  }, [router, next]);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [terms, setTerms] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    // Sifre tekrari client-side dogrulama — eslesmiyorsa gonderme.
    if (password !== confirm) {
      setError('Şifreler eşleşmiyor — lütfen iki alana da aynı şifreyi girin.');
      return;
    }
    if (!terms) {
      setError('Devam etmek için Kullanım Koşulları ve KVKK Aydınlatma Metni onayı gereklidir.');
      return;
    }
    setBusy(true);
    try {
      const res = await api.register(email, password, terms);
      window.localStorage.setItem('token', res.token);
      // YENI hesap (emailVerified=false) -> once dogrulama ekrani. Mevcut/verified -> next.
      if (res.emailVerified === false) router.push(`/verify-email?next=${encodeURIComponent(next)}`);
      else router.push(next);
    } catch (err: any) {
      setError(err.message);
      setBusy(false);
    }
  }

  return (
    <main className="container-page max-w-md py-16">
      <div className="card p-8">
        <h1 className="text-2xl font-extrabold text-brand">Hesap Oluştur</h1>
        <p className="mt-1 text-sm text-ink-muted">Doğrulama ücretsiz — dakikalar içinde başlayın.</p>
        <div className="mt-6">
          <GoogleButton next={next} label="Google ile kaydol" />
        </div>
        <div className="my-5 flex items-center gap-3 text-xs text-ink-muted">
          <span className="h-px flex-1 bg-line" /> veya <span className="h-px flex-1 bg-line" />
        </div>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="label">E-posta</label>
            <input type="email" required className="field" value={email} onChange={(e) => setEmail(e.target.value)} />
          </div>
          <div>
            <label className="label">Şifre (en az 8 karakter)</label>
            <PasswordInput required minLength={8} autoComplete="new-password" value={password} onChange={setPassword} />
          </div>
          <div>
            <label className="label">Şifre (Tekrar)</label>
            <PasswordInput
              required
              minLength={8}
              autoComplete="new-password"
              value={confirm}
              onChange={setConfirm}
            />
            {confirm.length > 0 && confirm !== password && (
              <p className="mt-1 text-xs text-red-600">Şifreler eşleşmiyor.</p>
            )}
          </div>

          <label className="flex items-start gap-2.5 text-sm text-ink-soft">
            <input type="checkbox" checked={terms} onChange={(e) => setTerms(e.target.checked)} className="mt-0.5 h-4 w-4 accent-brand" />
            <span>
              <Link href="/legal/kullanim-kosullari" target="_blank" className="text-accent-600 underline">
                Kullanım Koşulları
              </Link>
              &apos;nı ve{' '}
              <Link href="/legal/kvkk-aydinlatma" target="_blank" className="text-accent-600 underline">
                KVKK Aydınlatma Metni
              </Link>
              &apos;ni okudum, kabul ediyorum.
            </span>
          </label>

          {error && <p className="form-error">{error}</p>}
          <button type="submit" disabled={!terms || busy} className="btn-primary w-full disabled:opacity-60">
            {busy ? 'Kaydolunuyor…' : 'Kayıt ol'}
          </button>
        </form>
      </div>
      <p className="mt-5 text-center text-sm text-ink-soft">
        Zaten hesabınız var mı?{' '}
        <Link href={`/login?next=${encodeURIComponent(next)}`} className="font-semibold text-accent-600 hover:underline">
          Giriş yapın
        </Link>
      </p>
    </main>
  );
}
