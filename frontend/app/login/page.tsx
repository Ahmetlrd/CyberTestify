'use client';

import { useState, useEffect } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { api } from '../../lib/api';
import { PasswordInput } from '../../components/PasswordInput';
import { GoogleButton } from '../../components/GoogleButton';
import { OtpInput } from '../../components/OtpInput';
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
    twofaTitle: 'İki faktörlü doğrulama', twofaHint: 'Authenticator uygulamanızdaki 6 haneli kodu girin. Telefonunuz yoksa bir kurtarma kodu da girebilirsiniz.',
    verify: 'Doğrula ve gir', verifying: 'Doğrulanıyor…', back: '← Geri',
    recoveryUse: 'Telefonum yok — kurtarma kodu gir', recoveryBack: '← Authenticator kodu kullan', recoveryHint: 'Bir kurtarma kodunuzu girin.',
  },
  de: {
    title: 'Anmelden', subtitle: 'Greifen Sie auf Ihr Konto zu und verwalten Sie Ihren Scan.',
    google: 'Mit Google fortfahren',
    googleError: 'Die Anmeldung mit Google konnte nicht abgeschlossen werden. Bitte versuchen Sie es erneut.',
    or: 'oder', email: 'E-Mail', password: 'Passwort', forgot: 'Passwort vergessen',
    submitting: 'Anmeldung läuft…', submit: 'Anmelden',
    noAccount: 'Noch kein Konto?', register: 'Kostenlos registrieren',
    twofaTitle: 'Zwei-Faktor-Authentifizierung', twofaHint: 'Geben Sie den 6-stelligen Code aus Ihrer Authenticator-App ein. Ohne Telefon können Sie auch einen Wiederherstellungscode eingeben.',
    verify: 'Bestätigen und anmelden', verifying: 'Wird überprüft…', back: '← Zurück',
    recoveryUse: 'Kein Telefon — Wiederherstellungscode eingeben', recoveryBack: '← Authenticator-Code verwenden', recoveryHint: 'Geben Sie einen Wiederherstellungscode ein.',
  },
  en: {
    title: 'Sign in', subtitle: 'Access your account and manage your scan.',
    google: 'Continue with Google',
    googleError: 'Sign-in with Google could not be completed. Please try again.',
    or: 'or', email: 'Email', password: 'Password', forgot: 'Forgot password',
    submitting: 'Signing in…', submit: 'Sign in',
    noAccount: 'Don\'t have an account?', register: 'Register for free',
    twofaTitle: 'Two-factor authentication', twofaHint: 'Enter the 6-digit code from your authenticator app. Without your phone, you can also enter a recovery code.',
    verify: 'Verify and sign in', verifying: 'Verifying…', back: '← Back',
    recoveryUse: 'No phone — enter a recovery code', recoveryBack: '← Use authenticator code', recoveryHint: 'Enter one of your recovery codes.',
  },
} as const;

export default function LoginPage() {
  const router = useRouter();
  const [lang, setLang] = useState<'tr' | 'de' | 'en'>('tr');
  useEffect(() => { const l = getRegion(readRegionCookie()).lang; setLang(l === 'de' ? 'de' : l === 'en' ? 'en' : 'tr'); }, []);
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
  // (2FA) 2FA açık müşteride ikinci adım: stage token + kod.
  const [twofa, setTwofa] = useState<{ stageToken: string } | null>(null);
  const [code, setCode] = useState('');
  const [useRecovery, setUseRecovery] = useState(false); // 6-haneli TOTP yerine kurtarma kodu girişi
  // (2FA — Google) OAuth 2FA ara-token'ı google/done'dan sessionStorage ile gelir → kod adımını aç.
  useEffect(() => {
    if (typeof window === 'undefined' || sp.get('twofa') !== '1') return;
    try {
      const st = window.sessionStorage.getItem('twofa_stage');
      if (st) { window.sessionStorage.removeItem('twofa_stage'); setTwofa({ stageToken: st }); }
    } catch { /* noop */ }
  }, [sp]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const r = await api.login(email, password);
      if (r.twofaRequired && r.stageToken) { setTwofa({ stageToken: r.stageToken }); setBusy(false); return; }
      if (r.token) { window.localStorage.setItem('token', r.token); router.push(next); return; }
      setError('Beklenmeyen yanıt.'); setBusy(false);
    } catch (err: any) {
      setError(err.message);
      setBusy(false);
    }
  }

  async function handleVerify(e: React.FormEvent) {
    e.preventDefault();
    setError(null); setBusy(true);
    try {
      const { token } = await api.login2fa(twofa!.stageToken, code.trim());
      window.localStorage.setItem('token', token);
      router.push(next);
    } catch (err: any) { setError(err.message); setBusy(false); }
  }

  return (
    <main className="container-page max-w-md py-16">
      {twofa ? (
        <div className="card p-8">
          <h1 className="text-2xl font-extrabold text-brand">{t.twofaTitle}</h1>
          <p className="mt-1 text-sm text-ink-muted">{useRecovery ? t.recoveryHint : t.twofaHint}</p>
          <form onSubmit={handleVerify} className="mt-6 space-y-4">
            {useRecovery ? (
              <input
                inputMode="text" autoFocus placeholder="xxxxx-xxxxx" value={code}
                onChange={(e) => setCode(e.target.value)}
                className="field text-center text-lg tracking-[0.2em]"
                style={{ fontFamily: 'ui-monospace, monospace' }}
              />
            ) : (
              <OtpInput value={code} onChange={setCode} autoFocus onComplete={() => { /* kullanıcı Doğrula'ya basar */ }} />
            )}
            {error && <p className="form-error">{error}</p>}
            <button type="submit" disabled={busy || (!useRecovery && code.length !== 6) || (useRecovery && code.trim().length < 6)} className="btn-primary w-full disabled:opacity-60">
              {busy ? t.verifying : t.verify}
            </button>
            <button type="button" onClick={() => { setUseRecovery(!useRecovery); setCode(''); setError(null); }} className="w-full text-xs text-ink-muted hover:underline">
              {useRecovery ? t.recoveryBack : t.recoveryUse}
            </button>
            <button type="button" onClick={() => { setTwofa(null); setCode(''); setUseRecovery(false); setError(null); }} className="w-full text-sm text-ink-soft hover:underline">
              {t.back}
            </button>
          </form>
        </div>
      ) : (
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
      )}
      {!twofa && (
        <p className="mt-5 text-center text-sm text-ink-soft">
          {t.noAccount}{' '}
          <Link href={`/register?next=${encodeURIComponent(next)}`} className="font-semibold text-accent-600 hover:underline">
            {t.register}
          </Link>
        </p>
      )}
    </main>
  );
}
