'use client';

import { useState, useEffect } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { api } from '../../lib/api';
import { PasswordInput } from '../../components/PasswordInput';
import { GoogleButton } from '../../components/GoogleButton';
import { readRegionCookie } from '../../lib/region';
import { getRegion } from '../../config/regions';

// (Çok-bölge) Client sayfa; dili cookie'den okur (hydration-safe: 'tr' başlar, mount sonrası set).
const T = {
  tr: {
    title: 'Giriş Yap', subtitle: 'Hesabınıza erişin ve taramanızı yönetin.',
    google: 'Google ile devam et',
    googleError: 'Google ile giriş tamamlanamadı. Lütfen tekrar deneyin.',
    or: 'veya', email: 'E-posta', password: 'Şifre', forgot: 'Şifremi unuttum',
    submitting: 'Giriş yapılıyor…', submit: 'Giriş yap',
    noAccount: 'Hesabınız yok mu?', register: 'Ücretsiz kayıt olun',
  },
  de: {
    title: 'Anmelden', subtitle: 'Greifen Sie auf Ihr Konto zu und verwalten Sie Ihren Scan.',
    google: 'Mit Google fortfahren',
    googleError: 'Die Anmeldung mit Google konnte nicht abgeschlossen werden. Bitte versuchen Sie es erneut.',
    or: 'oder', email: 'E-Mail', password: 'Passwort', forgot: 'Passwort vergessen',
    submitting: 'Anmeldung läuft…', submit: 'Anmelden',
    noAccount: 'Noch kein Konto?', register: 'Kostenlos registrieren',
  },
} as const;

export default function LoginPage() {
  const router = useRouter();
  const [lang, setLang] = useState<'tr' | 'de'>('tr');
  useEffect(() => { setLang(getRegion(readRegionCookie()).lang === 'de' ? 'de' : 'tr'); }, []);
  const t = T[lang];
  // Satın-alma akışı vb. için: ?next varsa login sonrası oraya dön (yoksa /verify).
  const sp = useSearchParams();
  const next = sp.get('next') || '/verify';
  const oauthError = sp.get('error');
  useEffect(() => {
    if (typeof window !== 'undefined' && window.localStorage.getItem('token')) {
      router.replace(next);
    }
  }, [router, next]);
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
      router.push(next);
    } catch (err: any) {
      setError(err.message);
      setBusy(false);
    }
  }

  return (
    <main className="container-page max-w-md py-16">
      <div className="card p-8">
        <h1 className="text-2xl font-extrabold text-brand">{t.title}</h1>
        <p className="mt-1 text-sm text-ink-muted">{t.subtitle}</p>
        {oauthError === 'google' && (
          <p className="mt-4 rounded-card border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
            {t.googleError}
          </p>
        )}
        <div className="mt-6">
          <GoogleButton next={next} label={t.google} />
        </div>
        <div className="my-5 flex items-center gap-3 text-xs text-ink-muted">
          <span className="h-px flex-1 bg-line" /> {t.or} <span className="h-px flex-1 bg-line" />
        </div>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="label">{t.email}</label>
            <input type="email" required className="field" value={email} onChange={(e) => setEmail(e.target.value)} />
          </div>
          <div>
            <div className="flex items-center justify-between">
              <label className="label">{t.password}</label>
              <Link href="/forgot-password" className="text-xs font-semibold text-accent-600 hover:underline">
                {t.forgot}
              </Link>
            </div>
            <PasswordInput required autoComplete="current-password" value={password} onChange={setPassword} />
          </div>
          {error && <p className="form-error">{error}</p>}
          <button type="submit" disabled={busy} className="btn-primary w-full disabled:opacity-60">
            {busy ? t.submitting : t.submit}
          </button>
        </form>
      </div>
      <p className="mt-5 text-center text-sm text-ink-soft">
        {t.noAccount}{' '}
        <Link href={`/register?next=${encodeURIComponent(next)}`} className="font-semibold text-accent-600 hover:underline">
          {t.register}
        </Link>
      </p>
    </main>
  );
}
