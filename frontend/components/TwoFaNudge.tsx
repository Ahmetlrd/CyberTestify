'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { api } from '../lib/api';
import { readRegionCookie } from '../lib/region';
import { getRegion } from '../config/regions';

// (2FA nudge — hafif hatırlatma) Yüksek-güven anında (rapor görüntüleme) TEK seferlik, KAPATILABİLİR
// bilgi şeridi. Nag/dark-pattern YOK: "Şimdi / Sonra / Bir daha gösterme". 2FA açık müşteriye hiç
// gösterilmez (backend show=false döner). Tercih backend'de KALICI saklanır. Hiçbir işlemi bloklamaz.
const NT = {
  tr: {
    msg: 'Raporlarınız gizlidir. Hesabınızı iki faktörlü doğrulama (2FA) ile koruyabilirsiniz — ücretsiz.',
    now: 'Şimdi etkinleştir', later: 'Sonra hatırlat', never: 'Bir daha gösterme',
  },
  de: {
    msg: 'Ihre Berichte sind vertraulich. Sie können Ihr Konto mit Zwei-Faktor-Authentifizierung (2FA) schützen — kostenlos.',
    now: 'Jetzt aktivieren', later: 'Später erinnern', never: 'Nicht mehr anzeigen',
  },
  en: {
    msg: 'Your reports are confidential. You can protect your account with two-factor authentication (2FA) — free.',
    now: 'Enable now', later: 'Remind me later', never: 'Don’t show again',
  },
} as const;

export function TwoFaNudge() {
  const router = useRouter();
  const [show, setShow] = useState(false);
  const [lang, setLang] = useState<'tr' | 'de' | 'en'>('tr');

  useEffect(() => {
    const l = getRegion(readRegionCookie()).lang;
    setLang(l === 'de' ? 'de' : l === 'en' ? 'en' : 'tr');
    if (typeof window === 'undefined' || !window.localStorage.getItem('token')) return;
    api.twofaNudge().then((r) => setShow(!!r.show)).catch(() => setShow(false));
  }, []);

  if (!show) return null;
  const t = NT[lang];
  const later = () => { setShow(false); api.twofaNudgeRemind().catch(() => {}); };
  const never = () => { setShow(false); api.twofaNudgeDismiss().catch(() => {}); };

  return (
    <div className="mb-4 flex flex-col gap-3 rounded-card border border-accent/40 bg-accent-soft/30 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
      <p className="flex items-start gap-2 text-sm text-ink">
        <span aria-hidden className="mt-0.5"></span>
        <span>{t.msg}</span>
      </p>
      <div className="flex shrink-0 flex-wrap items-center gap-2">
        <button onClick={() => router.push('/profile')} className="rounded-pill bg-accent px-3 py-1.5 text-xs font-bold text-white hover:opacity-90">{t.now}</button>
        <button onClick={later} className="rounded-pill border border-line px-3 py-1.5 text-xs font-semibold text-ink-soft hover:bg-white">{t.later}</button>
        <button onClick={never} className="text-xs font-medium text-ink-muted hover:underline">{t.never}</button>
      </div>
    </div>
  );
}
