'use client';

import { useEffect, useState } from 'react';
import { usePathname, useRouter } from 'next/navigation';
import Link from 'next/link';

type Labels = { login: string; cta: string; panel: string; logout: string };

/**
 * Giriş durumuna göre Nav'ın sağ tarafı. Token localStorage'da olduğu için bu
 * client tarafta okunur; her sayfa geçişinde (pathname) yeniden kontrol edilir —
 * böylece login/logout sonrası Nav anında güncellenir.
 */
export function AuthNav({ labels }: { labels: Labels }) {
  const pathname = usePathname();
  const router = useRouter();
  const [loggedIn, setLoggedIn] = useState<boolean | null>(null);

  useEffect(() => {
    setLoggedIn(typeof window !== 'undefined' && !!window.localStorage.getItem('token'));
  }, [pathname]);

  function logout() {
    window.localStorage.removeItem('token');
    setLoggedIn(false);
    router.push('/');
  }

  // İlk (hydration) render — yanlış içerik göstermemek için boş yer tutucu.
  if (loggedIn === null) return <span className="h-9 w-28" aria-hidden />;

  if (loggedIn) {
    return (
      <>
        <button onClick={logout} className="btn-ghost">
          {labels.logout}
        </button>
        <Link href="/verify" className="btn-primary">
          {labels.panel}
        </Link>
      </>
    );
  }

  return (
    <>
      <Link href="/login" className="btn-ghost">
        {labels.login}
      </Link>
      <Link href="/register" className="btn-primary">
        {labels.cta}
      </Link>
    </>
  );
}
