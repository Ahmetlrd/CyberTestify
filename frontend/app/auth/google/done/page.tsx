'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';

// Backend Google callback'i buraya FRAGMENT ile yonlendirir: /auth/google/done#token=...&next=...
// Token FRONTEND origin'inin localStorage'ina yazilir (backend origin'inden yazilamaz), sonra
// 'next'e gecilir. Fragment sunucuya/Referer'a gitmez → token log'lara sizmaz.
export default function GoogleDonePage() {
  const router = useRouter();
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const frag = new URLSearchParams(window.location.hash.replace(/^#/, ''));
    const token = frag.get('token');
    const next = frag.get('next') || '/verify';
    // (2FA) 2FA açık hesap: backend tam token yerine stageToken yolladı → login sayfasında kod iste.
    if (frag.get('twofa') === '1' && frag.get('stageToken')) {
      try { window.sessionStorage.setItem('twofa_stage', frag.get('stageToken')!); } catch { /* noop */ }
      window.history.replaceState(null, '', window.location.pathname);
      router.replace(`/login?twofa=1&next=${encodeURIComponent(next.startsWith('/') ? next : '/verify')}`);
      return;
    }
    if (token) {
      window.localStorage.setItem('token', token);
      // hash'i temizle (token adres cubugunda kalmasin), sonra yonlendir.
      window.history.replaceState(null, '', window.location.pathname);
      router.replace(next.startsWith('/') ? next : '/verify');
    } else {
      router.replace('/login?error=google');
    }
  }, [router]);

  return (
    <main className="container-page max-w-md py-24 text-center">
      <p className="text-sm text-ink-muted">Google ile giriş tamamlanıyor…</p>
    </main>
  );
}
