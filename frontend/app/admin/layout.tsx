'use client';

import { useEffect, useState } from 'react';
import { usePathname, useRouter } from 'next/navigation';
import Link from 'next/link';
import { ADMIN_TOKEN_KEY } from '../../lib/adminApi';

const NAV = [
  { href: '/admin/dashboard', label: 'Özet' },
  { href: '/admin/customers', label: 'Müşteriler' },
  { href: '/admin/orders', label: 'Siparişler' },
  { href: '/admin/scope-violations', label: 'Kapsam İhlalleri' },
];

export default function AdminLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const isLogin = pathname === '/admin/login';
  const [ready, setReady] = useState(false);

  useEffect(() => {
    if (isLogin) { setReady(true); return; }
    if (typeof window !== 'undefined' && !window.localStorage.getItem(ADMIN_TOKEN_KEY)) {
      router.replace('/admin/login');
      return;
    }
    setReady(true);
  }, [isLogin, pathname, router]);

  if (isLogin) return <>{children}</>;
  if (!ready) return null;

  function logout() {
    window.localStorage.removeItem(ADMIN_TOKEN_KEY);
    router.replace('/admin/login');
  }

  return (
    <div style={{ minHeight: '100vh', background: '#0f172a', color: '#e2e8f0', fontFamily: 'ui-sans-serif, system-ui, sans-serif' }}>
      <header style={{ display: 'flex', alignItems: 'center', gap: 20, padding: '12px 20px', background: '#1e293b', borderBottom: '1px solid #334155' }}>
        <strong style={{ color: '#fff', letterSpacing: 0.3 }}>CyberTestify · Admin</strong>
        <nav style={{ display: 'flex', gap: 4, flex: 1, flexWrap: 'wrap' }}>
          {NAV.map((n) => {
            const on = pathname === n.href;
            return (
              <Link key={n.href} href={n.href} style={{
                padding: '6px 12px', borderRadius: 6, fontSize: 14, textDecoration: 'none',
                color: on ? '#0f172a' : '#cbd5e1', background: on ? '#38bdf8' : 'transparent', fontWeight: on ? 600 : 400,
              }}>{n.label}</Link>
            );
          })}
        </nav>
        <button onClick={logout} style={{ padding: '6px 12px', borderRadius: 6, fontSize: 14, background: '#334155', color: '#e2e8f0', border: 'none', cursor: 'pointer' }}>
          Çıkış
        </button>
      </header>
      <main style={{ padding: 24, maxWidth: 1200, margin: '0 auto' }}>{children}</main>
    </div>
  );
}
