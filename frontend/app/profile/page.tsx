'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { api } from '../../lib/api';

/**
 * Basit profil/hesap sayfası. Amaç: "giriş yapılmış mı" net görünsün + hesap bilgisi ve
 * hızlı eylemler (Panelim, Çıkış) TEK yerde toplu dursun. Token yoksa /login'e yönlenir;
 * token ölüyse api.me() 401 döner → api.ts token'ı siler → /login'e yönleniriz (döngü yok).
 */
export default function ProfilePage() {
  const router = useRouter();
  const [me, setMe] = useState<{ email: string; emailVerified: boolean } | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (typeof window !== 'undefined' && !window.localStorage.getItem('token')) {
      router.replace('/login?next=/profile');
      return;
    }
    api
      .me()
      .then(setMe)
      .catch(() => {
        // 401 → api.ts token'ı sildi; giriş sayfasına dön.
        router.replace('/login?next=/profile');
      })
      .finally(() => setLoading(false));
  }, [router]);

  function logout() {
    if (typeof window !== 'undefined') window.localStorage.removeItem('token');
    router.push('/');
  }

  return (
    <main className="container-page max-w-lg py-16">
      <p className="eyebrow">Hesabım</p>
      <h1 className="mt-2 text-3xl font-extrabold text-brand">Profil</h1>

      {loading ? (
        <div className="mt-8 h-40 animate-pulse rounded-card bg-brand-50" />
      ) : me ? (
        <div className="mt-8 space-y-6">
          {/* Oturum durumu — "login miyiz" net görünsün */}
          <div className="flex items-center gap-3 rounded-card border border-emerald-200 bg-emerald-50 px-4 py-3">
            <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-emerald-500 text-white">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" aria-hidden>
                <path d="M20 6 9 17l-5-5" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </span>
            <div>
              <p className="text-sm font-bold text-emerald-900">Giriş yapıldı</p>
              <p className="text-xs text-emerald-800/80">Oturumunuz aktif.</p>
            </div>
          </div>

          {/* Hesap bilgisi */}
          <div className="rounded-card border border-line bg-white">
            <div className="flex items-center justify-between border-b border-line px-4 py-3">
              <span className="text-xs font-medium text-ink-muted">E-posta</span>
              <span className="text-sm font-semibold text-ink">{me.email}</span>
            </div>
            <div className="flex items-center justify-between px-4 py-3">
              <span className="text-xs font-medium text-ink-muted">E-posta doğrulaması</span>
              {me.emailVerified ? (
                <span className="inline-flex items-center gap-1 text-sm font-semibold text-emerald-700">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" aria-hidden><path d="M20 6 9 17l-5-5" strokeLinecap="round" strokeLinejoin="round" /></svg>
                  Doğrulandı
                </span>
              ) : (
                <span className="text-sm font-semibold text-amber-700">Beklemede</span>
              )}
            </div>
          </div>

          {/* Hızlı eylemler */}
          <div className="flex flex-col gap-3">
            <Link href="/verify" className="btn-primary w-full justify-center">Panelim (Alan adlarım ve taramalar)</Link>
            <button onClick={logout} className="btn-outline w-full justify-center">Çıkış Yap</button>
          </div>

          <p className="text-center text-[11px] text-ink-muted">
            Destek: <a href="mailto:support@cybertestify.com" className="text-accent-600 underline">support@cybertestify.com</a>
          </p>
        </div>
      ) : null}
    </main>
  );
}
