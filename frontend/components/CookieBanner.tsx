'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { noticeDismissed, dismissNotice, GA_ID, CLARITY_ID, OPEN_PREFS_EVENT } from '../lib/consent';
import { readRegionCookie } from '../lib/region';
import { getRegion, REGION_CODES } from '../config/regions';

// (Çok-bölge) Çerez notu metinleri — /de tamamen Almanca (Sie-Form), /en İngilizce.
// policyHref: her bölgenin çerezleri kapsayan hukuki sayfası (TR ayrı çerez sayfası; DE veri koruma;
// EN gizlilik) — bölge-önekli ki /de'de /tr sayfasına kaymasın.
const CB_T = {
  tr: { aria: 'Çerez bilgilendirmesi', body: 'Deneyiminizi iyileştirmek için çerezler kullanıyoruz.', policy: 'Çerez Politikası', ok: 'Tamam', policyHref: '/tr/legal/cerez' },
  de: { aria: 'Cookie-Hinweis', body: 'Wir verwenden Cookies, um Ihr Erlebnis zu verbessern.', policy: 'Cookie-Richtlinie', ok: 'Akzeptieren', policyHref: '/de/legal/datenschutz' },
  en: { aria: 'Cookie notice', body: 'We use cookies to improve your experience.', policy: 'Cookie Policy', ok: 'Accept', policyHref: '/en/legal/privacy' },
} as const;

/**
 * Çerez BİLGİLENDİRME notu (gating YOK). Analitik/ölçüm (GA + Clarity) her zaman açıktır; bu not
 * yalnızca kullanıcıyı bilgilendirir. "Tamam" ile kapatılır (tekrar gösterilmez), footer'daki
 * "Çerez tercihleri" ile yeniden açılabilir. İzleme aracı hiç kurulmadıysa (env boş) gösterilmez.
 *
 * Tasarım: ekranın altına yapışık, TEK SATIR kompakt şerit (metin+link solda inline, buton sağda) —
 * mobilde dikey alan yemesin. Renk: koyu yarı-saydam (backdrop-blur).
 */
export function CookieBanner() {
  const [show, setShow] = useState(false);
  const analyticsEnabled = !!GA_ID || !!CLARITY_ID;

  // (BUG DÜZELTME) Aktif dili URL'den TÜRET: kök layout client-navigasyonda yeniden render EDİLMEDİĞİ için
  // bölge değişince cookie güncellense de bu bileşen ESKİ dilde kalıyordu (metin/buton/link). Footer/Nav
  // ile aynı desen: URL bölge-önekliyse ondan, değilse (order/admin/kurumsal) cookie'ye düş.
  const pathname = usePathname();
  const seg = (pathname ?? '/').split('/')[1] ?? '';
  const lg = (REGION_CODES as readonly string[]).includes(seg) ? getRegion(seg).lang : getRegion(readRegionCookie()).lang;
  const lang: 'tr' | 'de' | 'en' = lg === 'de' ? 'de' : lg === 'en' ? 'en' : 'tr';
  const t = CB_T[lang];

  useEffect(() => {
    if (analyticsEnabled && !noticeDismissed()) setShow(true);
    const reopen = () => setShow(true);
    window.addEventListener(OPEN_PREFS_EVENT, reopen);
    return () => window.removeEventListener(OPEN_PREFS_EVENT, reopen);
  }, [analyticsEnabled]);

  if (!show) return null;

  const close = () => { dismissNotice(); setShow(false); };

  return (
    <div
      role="dialog"
      aria-label={t.aria}
      className="fixed inset-x-0 bottom-0 z-[60] border-t border-white/10 backdrop-blur"
      style={{ backgroundColor: 'rgba(15,23,26,0.92)' }}
    >
      <div className="mx-auto flex max-w-4xl items-center gap-3 px-4 py-2">
        <p className="min-w-0 flex-1 text-xs leading-snug text-white/85 sm:text-[13px]">
          {t.body}{' '}
          <Link href={t.policyHref} className="whitespace-nowrap font-medium text-amber-300 underline underline-offset-2 hover:text-amber-200">
            {t.policy}
          </Link>
        </p>
        <button
          type="button"
          onClick={close}
          className="shrink-0 rounded-md bg-amber-400 px-3.5 py-1.5 text-xs font-bold text-[#123F3A] hover:bg-amber-300 sm:text-[13px]"
        >
          {t.ok}
        </button>
      </div>
    </div>
  );
}
