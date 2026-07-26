'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { api } from '../../lib/api';

export default function RegisterPage() {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [terms, setTerms] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (!terms) {
      setError('Devam etmek için Kullanım Koşulları ve KVKK Aydınlatma Metni onayı gereklidir.');
      return;
    }
    try {
      const { token } = await api.register(email, password, terms);
      window.localStorage.setItem('token', token);
      router.push('/verify');
    } catch (err: any) {
      setError(err.message);
    }
  }

  return (
    <main className="container-page max-w-md py-16">
      <h1>Hesap Oluştur</h1>
      <form onSubmit={handleSubmit}>
        <div>
          <label>E-posta</label>
          <input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
        </div>
        <div>
          <label>Şifre (en az 8 karakter)</label>
          <input
            type="password"
            required
            minLength={8}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>

        <label style={{ display: 'flex', gap: 8, alignItems: 'flex-start', margin: '14px 0', fontSize: 14 }}>
          <input type="checkbox" checked={terms} onChange={(e) => setTerms(e.target.checked)} style={{ marginTop: 3 }} />
          <span>
            <Link href="/legal/kullanim-kosullari" target="_blank">Kullanım Koşulları</Link>&apos;nı ve{' '}
            <Link href="/legal/kvkk-aydinlatma" target="_blank">KVKK Aydınlatma Metni</Link>&apos;ni okudum, kabul ediyorum.
          </span>
        </label>

        {error && <p style={{ color: 'crimson' }}>{error}</p>}
        <button type="submit" disabled={!terms}>Kayıt ol</button>
      </form>
    </main>
  );
}
