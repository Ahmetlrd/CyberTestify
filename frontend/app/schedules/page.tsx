'use client';

import { useCallback, useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { api } from '../../lib/api';

type Schedule = {
  id: string;
  hostname: string;
  packageKey: string;
  intervalDays: number;
  remainingRuns: number;
  nextRunAt: string;
  active: boolean;
};

const FREQ: Record<number, string> = { 7: 'Haftalık', 14: 'İki haftada bir', 30: 'Aylık' };

export default function SchedulesPage() {
  const router = useRouter();
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
          <p className="eyebrow">Panelim</p>
          <h1 className="mt-1 text-2xl font-extrabold text-brand">Zamanlanmış Taramalarım</h1>
        </div>
        <Link href="/verify" className="btn-ghost text-sm">
          ← Panele dön
        </Link>
      </div>

      {error && <p className="form-error mt-4">{error}</p>}

      {loading ? (
        <div className="mt-8 h-24 animate-pulse rounded-card bg-brand-50" />
      ) : schedules.length === 0 ? (
        <p className="mt-8 text-sm text-ink-muted">
          Henüz zamanlanmış taramanız yok. Bir taramayı başlatırken “Düzenli tekrarla” seçeneğini
          kullanabilirsiniz.
        </p>
      ) : (
        <div className="mt-8 space-y-2.5">
          {schedules.map((s) => (
            <div key={s.id} className="card p-4">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div className="min-w-0">
                  <div className="truncate font-semibold text-ink">{s.hostname}</div>
                  <div className="mt-0.5 text-xs text-ink-muted">
                    {FREQ[s.intervalDays] ?? `${s.intervalDays} günde bir`} · kalan {s.remainingRuns} tarama
                    {s.active && (
                      <> · sonraki: {new Date(s.nextRunAt).toLocaleDateString('tr-TR')}</>
                    )}
                  </div>
                </div>
                {s.active ? (
                  <button onClick={() => cancel(s.id)} className="btn-outline shrink-0 text-sm">
                    İptal et
                  </button>
                ) : (
                  <span className="badge shrink-0">Pasif</span>
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
