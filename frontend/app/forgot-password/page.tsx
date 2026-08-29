'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { api } from '../../lib/api';
import { readRegionCookie } from '../../lib/region';
import { getRegion } from '../../config/regions';

// (Çok-bölge) Bölge-öneksiz (cookie tabanlı) sayfa — dil cookie'den türetilir (login/register ile aynı desen).
const T = {
  tr: {
    title: 'Şifremi Unuttum',
    sentHtml: (<>Bu e-posta ile bir hesap varsa, şifre sıfırlama bağlantısı gönderildi. Gelen kutunuzu (ve spam klasörünü) kontrol edin. Bağlantı <strong>1 saat</strong> geçerlidir.</>),
    backToLogin: 'Girişe dön',
    intro: 'Hesap e-postanızı girin; size şifrenizi sıfırlamanız için bir bağlantı gönderelim.',
    email: 'E-posta',
    sending: 'Gönderiliyor…',
    send: 'Sıfırlama bağlantısı gönder',
  },
  de: {
    title: 'Passwort vergessen',
    sentHtml: (<>Falls ein Konto mit dieser E-Mail existiert, wurde ein Link zum Zurücksetzen des Passworts gesendet. Bitte prüfen Sie Ihren Posteingang (und den Spam-Ordner). Der Link ist <strong>1 Stunde</strong> gültig.</>),
    backToLogin: 'Zurück zur Anmeldung',
    intro: 'Geben Sie die E-Mail-Adresse Ihres Kontos ein; wir senden Ihnen einen Link zum Zurücksetzen des Passworts.',
    email: 'E-Mail',
    sending: 'Wird gesendet…',
    send: 'Link zum Zurücksetzen senden',
  },
  en: {
    title: 'Forgot Password',
    sentHtml: (<>If an account exists with this email, a password reset link has been sent. Please check your inbox (and spam folder). The link is valid for <strong>1 hour</strong>.</>),
    backToLogin: 'Back to sign in',
    intro: 'Enter your account email and we’ll send you a link to reset your password.',
    email: 'Email',
    sending: 'Sending…',
    send: 'Send reset link',
  },
} as const;

export default function ForgotPasswordPage() {
  const [lang, setLang] = useState<'tr' | 'de' | 'en'>('tr');
  useEffect(() => { const l = getRegion(readRegionCookie()).lang; setLang(l === 'de' ? 'de' : l === 'en' ? 'en' : 'tr'); }, []);
  const t = T[lang];
  const [email, setEmail] = useState('');
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    // Backend HER ZAMAN {ok:true} doner (enumeration korumasi) — hata gostermeyiz, hep "gonderildi" ekrani.
    try {
      await api.forgotPassword(email);
    } catch {
      /* generic — yine de "gonderildi" goster */
    }
    setSent(true);
    setBusy(false);
  }

  return (
    <main className="container-page max-w-md py-16">
      <div className="card p-8">
        <h1 className="text-2xl font-extrabold text-brand">{t.title}</h1>
        {sent ? (
          <>
            <p className="mt-3 text-sm text-ink-soft">{t.sentHtml}</p>
            <Link href="/login" className="btn-outline mt-6 inline-flex">{t.backToLogin}</Link>
          </>
        ) : (
          <>
            <p className="mt-1 text-sm text-ink-muted">{t.intro}</p>
            <form onSubmit={handleSubmit} className="mt-6 space-y-4">
              <div>
                <label className="label">{t.email}</label>
                <input type="email" required className="field" value={email} onChange={(e) => setEmail(e.target.value)} />
              </div>
              <button type="submit" disabled={busy} className="btn-primary w-full disabled:opacity-60">
                {busy ? t.sending : t.send}
              </button>
            </form>
            <p className="mt-5 text-center text-sm text-ink-soft">
              <Link href="/login" className="font-semibold text-accent-600 hover:underline">{t.backToLogin}</Link>
            </p>
          </>
        )}
      </div>
    </main>
  );
}
