'use client';

import { Suspense, useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { api } from '../../lib/api';
import { readRegionCookie } from '../../lib/region';
import { getRegion } from '../../config/regions';

// (Çok-bölge) Bu sayfa bölge-öneksiz (cookie tabanlı). Dil cookie'den türetilir (login/register ile aynı desen).
const T = {
  tr: {
    title: 'E-postanızı Doğrulayın',
    sentTo: (email: string) => (<>Doğrulama kodunu <strong>{email}</strong> adresine gönderdik.</>),
    sentGeneric: 'Doğrulama kodunu e-posta adresinize gönderdik.',
    validity: 'Kod 15 dakika geçerlidir.',
    codeLabel: '6 haneli kod',
    verify: 'Doğrula ve devam et',
    verifying: 'Doğrulanıyor…',
    resend: 'Kodu tekrar gönder',
    resending: 'Gönderiliyor…',
    later: 'Daha sonra',
    footerHtml: (<>Panelinizi gezebilirsiniz; ancak <strong>satın alma</strong> için e-posta doğrulaması gereklidir.</>),
    errLen: 'Kod 6 haneli olmalıdır.',
    resent: 'Yeni bir doğrulama kodu gönderildi. Gelen kutunuzu (ve spam klasörünü) kontrol edin.',
    loading: 'Yükleniyor…',
  },
  de: {
    title: 'E-Mail bestätigen',
    sentTo: (email: string) => (<>Wir haben einen Bestätigungscode an <strong>{email}</strong> gesendet.</>),
    sentGeneric: 'Wir haben einen Bestätigungscode an Ihre E-Mail-Adresse gesendet.',
    validity: 'Der Code ist 15 Minuten gültig.',
    codeLabel: '6-stelliger Code',
    verify: 'Bestätigen und fortfahren',
    verifying: 'Wird bestätigt…',
    resend: 'Code erneut senden',
    resending: 'Wird gesendet…',
    later: 'Später',
    footerHtml: (<>Sie können Ihr Dashboard erkunden; für einen <strong>Kauf</strong> ist die E-Mail-Bestätigung jedoch erforderlich.</>),
    errLen: 'Der Code muss 6-stellig sein.',
    resent: 'Ein neuer Bestätigungscode wurde gesendet. Bitte prüfen Sie Ihren Posteingang (und den Spam-Ordner).',
    loading: 'Wird geladen…',
  },
  en: {
    title: 'Verify Your Email',
    sentTo: (email: string) => (<>We sent a verification code to <strong>{email}</strong>.</>),
    sentGeneric: 'We sent a verification code to your email address.',
    validity: 'The code is valid for 15 minutes.',
    codeLabel: '6-digit code',
    verify: 'Verify and continue',
    verifying: 'Verifying…',
    resend: 'Resend code',
    resending: 'Sending…',
    later: 'Later',
    footerHtml: (<>You can explore your dashboard; however, email verification is required to <strong>make a purchase</strong>.</>),
    errLen: 'The code must be 6 digits.',
    resent: 'A new verification code has been sent. Please check your inbox (and spam folder).',
    loading: 'Loading…',
  },
} as const;

function useLang(): 'tr' | 'de' | 'en' {
  const [lang, setLang] = useState<'tr' | 'de' | 'en'>('tr');
  useEffect(() => { const l = getRegion(readRegionCookie()).lang; setLang(l === 'de' ? 'de' : l === 'en' ? 'en' : 'tr'); }, []);
  return lang;
}

function VerifyEmailForm() {
  const router = useRouter();
  const next = useSearchParams().get('next') || '/verify';
  const lang = useLang();
  const t = T[lang];
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
    if (!/^\d{6}$/.test(code)) return setError(t.errLen);
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
      setInfo(t.resent);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setResendBusy(false);
    }
  }

  return (
    <div className="card p-8">
      <h1 className="text-2xl font-extrabold text-brand">{t.title}</h1>
      <p className="mt-1 text-sm text-ink-muted">
        {email ? t.sentTo(email) : t.sentGeneric}{' '}
        {t.validity}
      </p>
      <form onSubmit={handleVerify} className="mt-6 space-y-4">
        <div>
          <label className="label">{t.codeLabel}</label>
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
          {busy ? t.verifying : t.verify}
        </button>
      </form>
      <div className="mt-5 flex items-center justify-between text-sm">
        <button onClick={handleResend} disabled={resendBusy} className="font-semibold text-accent-600 hover:underline disabled:opacity-60">
          {resendBusy ? t.resending : t.resend}
        </button>
        <Link href="/verify" className="text-ink-soft hover:underline">{t.later}</Link>
      </div>
      <p className="mt-4 text-xs text-ink-muted">
        {t.footerHtml}
      </p>
    </div>
  );
}

export default function VerifyEmailPage() {
  return (
    <main className="container-page max-w-md py-16">
      <Suspense fallback={<div className="card p-8 text-sm text-ink-muted">Loading…</div>}>
        <VerifyEmailForm />
      </Suspense>
    </main>
  );
}
