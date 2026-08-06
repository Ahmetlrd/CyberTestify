'use client';

import { useState } from 'react';
import Link from 'next/link';
import { api } from '../../lib/api';

export default function ForgotPasswordPage() {
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
        <h1 className="text-2xl font-extrabold text-brand">Şifremi Unuttum</h1>
        {sent ? (
          <>
            <p className="mt-3 text-sm text-ink-soft">
              Bu e-posta ile bir hesap varsa, şifre sıfırlama bağlantısı gönderildi. Gelen kutunuzu (ve
              spam klasörünü) kontrol edin. Bağlantı <strong>1 saat</strong> geçerlidir.
            </p>
            <Link href="/login" className="btn-outline mt-6 inline-flex">Girişe dön</Link>
          </>
        ) : (
          <>
            <p className="mt-1 text-sm text-ink-muted">
              Hesap e-postanızı girin; size şifrenizi sıfırlamanız için bir bağlantı gönderelim.
            </p>
            <form onSubmit={handleSubmit} className="mt-6 space-y-4">
              <div>
                <label className="label">E-posta</label>
                <input type="email" required className="field" value={email} onChange={(e) => setEmail(e.target.value)} />
              </div>
              <button type="submit" disabled={busy} className="btn-primary w-full disabled:opacity-60">
                {busy ? 'Gönderiliyor…' : 'Sıfırlama bağlantısı gönder'}
              </button>
            </form>
            <p className="mt-5 text-center text-sm text-ink-soft">
              <Link href="/login" className="font-semibold text-accent-600 hover:underline">Girişe dön</Link>
            </p>
          </>
        )}
      </div>
    </main>
  );
}
