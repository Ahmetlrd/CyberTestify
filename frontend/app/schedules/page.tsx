'use client';

import { useCallback, useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { api } from '../../lib/api';
import { readRegionCookie } from '../../lib/region';
import { getRegion } from '../../config/regions';

type Schedule = {
  id: string;
  hostname: string;
  packageKey: string;
  intervalDays: number;
  remainingRuns: number;
  nextRunAt: string;
  active: boolean;
};

// (Çok-bölge) Bölge-öneksiz (cookie tabanlı) sayfa — dil cookie'den türetilir.
const T = {
  tr: {
    eyebrow: 'Panelim',
    title: 'Zamanlanmış Taramalarım',
    back: '← Panele dön',
    empty: 'Henüz zamanlanmış taramanız yok. Bir taramayı başlatırken “Düzenli tekrarla” seçeneğini kullanabilirsiniz.',
    freq: { 7: 'Haftalık', 14: 'İki haftada bir', 30: 'Aylık' } as Record<number, string>,
    everyNDays: (n: number) => `${n} günde bir`,
    remaining: (n: number) => `kalan ${n} tarama`,
    next: 'sonraki',
    cancel: 'İptal et',
    passive: 'Pasif',
    locale: 'tr-TR',
  },
  de: {
    eyebrow: 'Mein Dashboard',
    title: 'Meine geplanten Scans',
    back: '← Zurück zum Dashboard',
    empty: 'Sie haben noch keine geplanten Scans. Beim Starten eines Scans können Sie die Option „Regelmäßig wiederholen“ verwenden.',
    freq: { 7: 'Wöchentlich', 14: 'Alle zwei Wochen', 30: 'Monatlich' } as Record<number, string>,
    everyNDays: (n: number) => `alle ${n} Tage`,
    remaining: (n: number) => `${n} Scans übrig`,
    next: 'nächster',
    cancel: 'Kündigen',
    passive: 'Inaktiv',
    locale: 'de-DE',
  },
  en: {
    eyebrow: 'My dashboard',
    title: 'My Scheduled Scans',
    back: '← Back to dashboard',
    empty: 'You don’t have any scheduled scans yet. When starting a scan you can use the “Repeat regularly” option.',
    freq: { 7: 'Weekly', 14: 'Every two weeks', 30: 'Monthly' } as Record<number, string>,
    everyNDays: (n: number) => `every ${n} days`,
    remaining: (n: number) => `${n} scans left`,
    next: 'next',
    cancel: 'Cancel',
    passive: 'Inactive',
    locale: 'en-GB',
  },
} as const;

export default function SchedulesPage() {
  const router = useRouter();
  const [lang, setLang] = useState<'tr' | 'de' | 'en'>('tr');
  useEffect(() => { const l = getRegion(readRegionCookie()).lang; setLang(l === 'de' ? 'de' : l === 'en' ? 'en' : 'tr'); }, []);
  const t = T[lang];
  const [schedules, setSchedules] = useState<Schedule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null); // sayfa-yükleme hatası (başlık altında)
  const [msg, setMsg] = useState<{ id: string; text: string } | null>(null); // iptal hatası — kartın altında

  const refresh = useCallback(async () => {
    const list = await api.listSchedules();
    setSchedules(list);
  }, []);

  useEffect(() => {
    if (typeof window !== 'undefined' && !window.localStorage.getItem('token')) {
      router.push('/login');
      return;
    }
    refresh()
      .catch((e: any) => setError(e.message))
      .finally(() => setLoading(false));
  }, [router, refresh]);

  async function cancel(id: string) {
    setMsg(null);
    try {
      await api.cancelSchedule(id);
      await refresh();
    } catch (e: any) {
      setMsg({ id, text: e.message });
    }
  }

  return (
    <main className="container-page max-w-2xl py-14">
      <div className="flex items-center justify-between">
        <div>
          <p className="eyebrow">{t.eyebrow}</p>
          <h1 className="mt-1 text-2xl font-extrabold text-brand">{t.title}</h1>
        </div>
        <Link href="/verify" className="btn-ghost text-sm">
          {t.back}
        </Link>
      </div>

      {error && <p className="form-error mt-4">{error}</p>}

      {loading ? (
        <div className="mt-8 h-24 animate-pulse rounded-card bg-brand-50" />
      ) : schedules.length === 0 ? (
        <p className="mt-8 text-sm text-ink-muted">{t.empty}</p>
      ) : (
        <div className="mt-8 space-y-2.5">
          {schedules.map((s) => (
            <div key={s.id} className="card p-4">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div className="min-w-0">
                  <div className="truncate font-semibold text-ink">{s.hostname}</div>
                  <div className="mt-0.5 text-xs text-ink-muted">
                    {t.freq[s.intervalDays] ?? t.everyNDays(s.intervalDays)} · {t.remaining(s.remainingRuns)}
                    {s.active && (
                      <> · {t.next}: {new Date(s.nextRunAt).toLocaleDateString(t.locale)}</>
                    )}
                  </div>
                </div>
                {s.active ? (
                  <button onClick={() => cancel(s.id)} className="btn-outline shrink-0 text-sm">
                    {t.cancel}
                  </button>
                ) : (
                  <span className="badge shrink-0">{t.passive}</span>
                )}
              </div>
              {msg?.id === s.id && (
                <p className="mt-3 rounded-card border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{msg.text}</p>
              )}
            </div>
          ))}
        </div>
      )}
    </main>
  );
}
