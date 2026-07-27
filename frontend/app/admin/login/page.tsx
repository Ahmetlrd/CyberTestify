'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { adminApi, ADMIN_TOKEN_KEY } from '../../../lib/adminApi';

export default function AdminLogin() {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true); setError(null);
    try {
      const { token } = await adminApi.login(email.trim().toLowerCase(), password);
      window.localStorage.setItem(ADMIN_TOKEN_KEY, token);
      router.replace('/admin/dashboard');
    } catch (err: any) {
      setError(err.message || 'Giriş başarısız.');
      setBusy(false);
    }
  }

  const input: React.CSSProperties = { width: '100%', padding: '10px 12px', borderRadius: 8, border: '1px solid #334155', background: '#0f172a', color: '#e2e8f0', fontSize: 14, marginTop: 6 };

  return (
    <div style={{ minHeight: '100vh', display: 'grid', placeItems: 'center', background: '#0f172a', fontFamily: 'ui-sans-serif, system-ui, sans-serif' }}>
      <form onSubmit={submit} style={{ width: 340, background: '#1e293b', border: '1px solid #334155', borderRadius: 12, padding: 28, color: '#e2e8f0' }}>
        <h1 style={{ fontSize: 18, fontWeight: 700, color: '#fff', margin: '0 0 4px' }}>CyberTestify · Admin</h1>
        <p style={{ fontSize: 13, color: '#94a3b8', margin: '0 0 20px' }}>İç yönetim paneli — yalnızca yetkili erişim.</p>
        <label style={{ fontSize: 13, color: '#cbd5e1' }}>E-posta
          <input style={input} type="email" required value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" />
        </label>
        <label style={{ fontSize: 13, color: '#cbd5e1', display: 'block', marginTop: 14 }}>Şifre
          <input style={input} type="password" required value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
        </label>
        {error && <p style={{ color: '#fca5a5', fontSize: 13, marginTop: 14 }}>{error}</p>}
        <button type="submit" disabled={busy} style={{ width: '100%', marginTop: 20, padding: '10px', borderRadius: 8, border: 'none', background: '#38bdf8', color: '#0f172a', fontWeight: 700, fontSize: 14, cursor: 'pointer', opacity: busy ? 0.6 : 1 }}>
          {busy ? 'Giriş yapılıyor…' : 'Giriş yap'}
        </button>
      </form>
    </div>
  );
}
