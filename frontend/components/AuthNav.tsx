'use client';

import { useEffect, useState } from 'react';
import { usePathname } from 'next/navigation';
import Link from 'next/link';

type Labels = { login: string; cta: string; panel: string; logout: string; profile: string };

/**
 * Giriş durumuna göre Nav'ın sağ tarafı. Token localStorage'da olduğu için bu
 * client tarafta okunur; her sayfa geçişinde (pathname) yeniden kontrol edilir —
 * böylece login/logout sonrası Nav anında güncellenir. 401'de api.ts token'ı sildiği
 * için ölü oturumda da doğru (çıkış yapılmış) görünür.
 */
export function AuthNav({ labels }: { labels: Labels }) {
  const pathname = usePathname();
  const [loggedIn, setLoggedIn] = useState<boolean | null>(null);

  useEffect(() => {
    setLoggedIn(typeof window !== 'undefined' && !!window.localStorage.getItem('token'));
  }, [pathname]);

  // İlk (hydration) render — yanlış içerik göstermemek için boş yer tutucu.
  if (loggedIn === null) return <span className="h-9 w-28" aria-hidden />;

  // Giriş yapılmışsa "Giriş/Kayıt" GÖSTERİLMEZ (aksi halde /login'e gidip /verify'a sekme
  // yaratıyordu). Bunun yerine Panelim + Profil. Çıkış, Profil sayfasında toplu durur.
  if (loggedIn) {
    return (
      <>
        <Link href="/verify" className="btn-ghost">
          {labels.panel}
        </Link>
        <Link href="/profile" className="btn-primary inline-flex items-center gap-1.5">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden>
            <circle cx="12" cy="8" r="4" /><path d="M4 21v-1a6 6 0 0 1 6-6h4a6 6 0 0 1 6 6v1" />
          </svg>
          {labels.profile}
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
