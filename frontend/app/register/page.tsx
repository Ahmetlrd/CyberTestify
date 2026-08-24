'use client';

import { useState, useEffect } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { api } from '../../lib/api';
import { PasswordInput } from '../../components/PasswordInput';
import { GoogleButton } from '../../components/GoogleButton';
import { Turnstile, type TurnstileHandle } from '../../components/Turnstile';
import { useRef } from 'react';
import { readRegionCookie } from '../../lib/region';
import { getRegion } from '../../config/regions';

// (Çok-bölge) Client sayfa; dili cookie'den (hydration-safe). /de'de onay metni AGB+Datenschutz'a
// bağlanır (KVKK DEĞİL); doğrulama mesajları Almanca.
const T = {
  tr: {
    title: 'Hesap Oluştur', subtitle: 'Doğrulama ücretsiz — dakikalar içinde başlayın.',
    google: 'Google ile kaydol', or: 'veya', email: 'E-posta',
    password: 'Şifre (en az 8 karakter)', confirm: 'Şifre (Tekrar)', mismatch: 'Şifreler eşleşmiyor.',
    termsPre: '', link1: 'Kullanım Koşulları', termsMid: "'nı ve ", link2: 'KVKK Aydınlatma Metni', termsPost: "'ni okudum, kabul ediyorum.",
    errMismatch: 'Şifreler eşleşmiyor — lütfen iki alana da aynı şifreyi girin.',
    errTerms: 'Devam etmek için Kullanım Koşulları ve KVKK Aydınlatma Metni onayı gereklidir.',
    errCaptcha: 'Lütfen doğrulama kutusunu tamamlayın.',
    submitting: 'Kaydolunuyor…', waiting: 'Doğrulama bekleniyor…', submit: 'Kayıt ol',
    haveAccount: 'Zaten hesabınız var mı?', login: 'Giriş yapın',
    link1Href: '/legal/kullanim-kosullari', link2Href: '/legal/kvkk-aydinlatma',
  },
  de: {
    title: 'Konto erstellen', subtitle: 'Die Verifizierung ist kostenlos — starten Sie in Minuten.',
    google: 'Mit Google registrieren', or: 'oder', email: 'E-Mail',
    password: 'Passwort (mindestens 8 Zeichen)', confirm: 'Passwort (Wiederholung)', mismatch: 'Passwörter stimmen nicht überein.',
    termsPre: 'Ich habe die ', link1: 'AGB', termsMid: ' und die ', link2: 'Datenschutzerklärung', termsPost: ' gelesen und akzeptiere sie.',
    errMismatch: 'Passwörter stimmen nicht überein — bitte geben Sie in beide Felder dasselbe Passwort ein.',
    errTerms: 'Zum Fortfahren ist die Zustimmung zu den AGB und der Datenschutzerklärung erforderlich.',
    errCaptcha: 'Bitte schließen Sie die Verifizierung ab.',
    submitting: 'Registrierung läuft…', waiting: 'Verifizierung ausstehend…', submit: 'Registrieren',
    haveAccount: 'Bereits ein Konto?', login: 'Anmelden',
    link1Href: '/de/legal/agb', link2Href: '/de/legal/datenschutz',
  },
} as const;

export default function RegisterPage() {
  const router = useRouter();
  const [lang, setLang] = useState<'tr' | 'de'>('tr');
  useEffect(() => { setLang(getRegion(readRegionCookie()).lang === 'de' ? 'de' : 'tr'); }, []);
  const t = T[lang];
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
  const [token, setToken] = useState<string | null>(null); // Turnstile (bot koruması)
  const turnstile = useRef<TurnstileHandle>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    // Sifre tekrari client-side dogrulama — eslesmiyorsa gonderme.
    if (password !== confirm) {
      setError(t.errMismatch);
      return;
    }
    if (!terms) {
      setError(t.errTerms);
      return;
    }
    if (!token) {
      setError(t.errCaptcha);
      return;
    }
    setBusy(true);
    try {
      const res = await api.register(email, password, terms, token);
      window.localStorage.setItem('token', res.token);
      // YENI hesap (emailVerified=false) -> once dogrulama ekrani. Mevcut/verified -> next.
      if (res.emailVerified === false) router.push(`/verify-email?next=${encodeURIComponent(next)}`);
      else router.push(next);
    } catch (err: any) {
      setError(err.message);
      setBusy(false);
      setToken(null); turnstile.current?.reset(); // token tek-kullanımlık → yenile
    }
  }

  return (
    <main className="container-page max-w-md py-16">
      <div className="card p-8">
        <h1 className="text-2xl font-extrabold text-brand">{t.title}</h1>
        <p className="mt-1 text-sm text-ink-muted">{t.subtitle}</p>
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
            <label className="label">{t.password}</label>
            <PasswordInput required minLength={8} autoComplete="new-password" value={password} onChange={setPassword} />
          </div>
          <div>
            <label className="label">{t.confirm}</label>
            <PasswordInput
              required
              minLength={8}
              autoComplete="new-password"
              value={confirm}
              onChange={setConfirm}
            />
            {confirm.length > 0 && confirm !== password && (
              <p className="mt-1 text-xs text-red-600">{t.mismatch}</p>
            )}
          </div>

          <label className="flex items-start gap-2.5 text-sm text-ink-soft">
            <input type="checkbox" checked={terms} onChange={(e) => setTerms(e.target.checked)} className="mt-0.5 h-4 w-4 accent-brand" />
            <span>
              {t.termsPre}
              <Link href={t.link1Href} target="_blank" className="text-accent-600 underline">{t.link1}</Link>
              {t.termsMid}
              <Link href={t.link2Href} target="_blank" className="text-accent-600 underline">{t.link2}</Link>
              {t.termsPost}
            </span>
          </label>

          {/* Bot koruması (Turnstile) — token gelene kadar buton kilitli. */}
          <Turnstile ref={turnstile} onToken={setToken} action="register" />

          {error && <p className="form-error">{error}</p>}
          <button type="submit" disabled={!terms || !token || busy} className="btn-primary w-full disabled:opacity-60">
            {busy ? t.submitting : !token ? t.waiting : t.submit}
          </button>
        </form>
      </div>
      <p className="mt-5 text-center text-sm text-ink-soft">
        {t.haveAccount}{' '}
        <Link href={`/login?next=${encodeURIComponent(next)}`} className="font-semibold text-accent-600 hover:underline">
          {t.login}
        </Link>
      </p>
    </main>
  );
}
