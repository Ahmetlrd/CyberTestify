'use client';

import { Suspense, useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { api } from '../../lib/api';
import { PasswordInput } from '../../components/PasswordInput';
import { readRegionCookie } from '../../lib/region';
import { getRegion } from '../../config/regions';

// (Çok-bölge) Bölge-öneksiz (cookie tabanlı) sayfa — dil cookie'den türetilir.
const T = {
  tr: {
    invalidTitle: 'Geçersiz bağlantı',
    invalidBody: 'Sıfırlama bağlantısı eksik veya hatalı. Lütfen yeniden talep edin.',
    requestNew: 'Yeni bağlantı iste',
    title: 'Yeni Şifre Belirle',
    subtitle: 'Hesabınız için yeni bir şifre oluşturun.',
    newPass: 'Yeni şifre',
    newPassAgain: 'Yeni şifre (tekrar)',
    saving: 'Kaydediliyor…',
    save: 'Şifreyi güncelle',
    errLen: 'Şifre en az 8 karakter olmalıdır.',
    errMismatch: 'Şifreler eşleşmiyor.',
    loading: 'Yükleniyor…',
  },
  de: {
    invalidTitle: 'Ungültiger Link',
    invalidBody: 'Der Reset-Link fehlt oder ist fehlerhaft. Bitte fordern Sie ihn erneut an.',
    requestNew: 'Neuen Link anfordern',
    title: 'Neues Passwort festlegen',
    subtitle: 'Erstellen Sie ein neues Passwort für Ihr Konto.',
    newPass: 'Neues Passwort',
    newPassAgain: 'Neues Passwort (Wiederholung)',
    saving: 'Wird gespeichert…',
    save: 'Passwort aktualisieren',
    errLen: 'Das Passwort muss mindestens 8 Zeichen lang sein.',
    errMismatch: 'Die Passwörter stimmen nicht überein.',
    loading: 'Wird geladen…',
  },
  en: {
    invalidTitle: 'Invalid link',
    invalidBody: 'The reset link is missing or invalid. Please request a new one.',
    requestNew: 'Request a new link',
    title: 'Set a New Password',
    subtitle: 'Create a new password for your account.',
    newPass: 'New password',
    newPassAgain: 'New password (repeat)',
    saving: 'Saving…',
    save: 'Update password',
    errLen: 'The password must be at least 8 characters.',
    errMismatch: 'The passwords do not match.',
    loading: 'Loading…',
  },
} as const;

function ResetForm() {
  const router = useRouter();
  const token = useSearchParams().get('token') || '';
  const [lang, setLang] = useState<'tr' | 'de' | 'en'>('tr');
  useEffect(() => { const l = getRegion(readRegionCookie()).lang; setLang(l === 'de' ? 'de' : l === 'en' ? 'en' : 'tr'); }, []);
  const t = T[lang];
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (password.length < 8) return setError(t.errLen);
    if (password !== confirm) return setError(t.errMismatch);
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
        <h1 className="text-2xl font-extrabold text-brand">{t.invalidTitle}</h1>
        <p className="mt-2 text-sm text-ink-soft">{t.invalidBody}</p>
        <Link href="/forgot-password" className="btn-primary mt-6 inline-flex">{t.requestNew}</Link>
      </div>
    );
  }

  return (
    <div className="card p-8">
      <h1 className="text-2xl font-extrabold text-brand">{t.title}</h1>
      <p className="mt-1 text-sm text-ink-muted">{t.subtitle}</p>
      <form onSubmit={handleSubmit} className="mt-6 space-y-4">
        <div>
          <label className="label">{t.newPass}</label>
          <PasswordInput required autoComplete="new-password" value={password} onChange={setPassword} />
        </div>
        <div>
          <label className="label">{t.newPassAgain}</label>
          <PasswordInput required autoComplete="new-password" value={confirm} onChange={setConfirm} />
        </div>
        {error && <p className="form-error">{error}</p>}
        <button type="submit" disabled={busy} className="btn-primary w-full disabled:opacity-60">
          {busy ? t.saving : t.save}
        </button>
      </form>
    </div>
  );
}

export default function ResetPasswordPage() {
  return (
    <main className="container-page max-w-md py-16">
      <Suspense fallback={<div className="card p-8 text-sm text-ink-muted">Loading…</div>}>
        <ResetForm />
      </Suspense>
    </main>
  );
}
