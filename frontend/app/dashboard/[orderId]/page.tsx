'use client';

import { useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import { api } from '../../../lib/api';
import { StatusTracker } from '../../../components/dashboard/StatusTracker';
import { ScopeCertificate } from '../../../components/dashboard/ScopeCertificate';

const TERMINAL = new Set(['scan_completed', 'scan_failed', 'scope_violation', 'report_purged']);

const HEADLINE: Record<string, string> = {
  awaiting_payment: 'Ödeme bekleniyor',
  paid: 'Ödeme alındı — tarama hazırlanıyor',
  scan_queued: 'Sırada bekliyor',
  scan_running: 'Taramanız çalışıyor',
  scan_completed: 'Raporunuz hazır',
  scan_failed: 'Tarama tamamlanamadı',
  scope_violation: 'Tarama güvenlik nedeniyle durduruldu',
  report_purged: 'Rapor saklama süresi doldu',
};

function LockIcon({ open }: { open: boolean }) {
  return (
    <svg viewBox="0 0 24 24" className="h-7 w-7 text-brand transition-all duration-500" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <rect x="5" y="11" width="14" height="10" rx="2" />
      <path
        className="transition-all duration-500 origin-center"
        d={open ? 'M8 11V7a4 4 0 017.9-1' : 'M8 11V7a4 4 0 018 0v4'}
      />
      {open && <path d="M12 15v2" className="text-accent" stroke="currentColor" />}
    </svg>
  );
}

export default function OrderDashboard({ params }: { params: { orderId: string } }) {
  const router = useRouter();
  const [order, setOrder] = useState<any>(null);
  const [accessSecret, setAccessSecret] = useState('');
  const [unlocked, setUnlocked] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (typeof window !== 'undefined' && !window.localStorage.getItem('token')) {
      router.push('/login');
      return;
    }
    async function load() {
      try {
        const o = await api.getOrder(params.orderId);
        setOrder(o);
        if (o.report?.devAccessSecret) setAccessSecret((prev) => prev || o.report.devAccessSecret);
        if (TERMINAL.has(o.status) && timer.current) {
          clearInterval(timer.current);
          timer.current = null;
        }
      } catch (err: any) {
        setError(err.message);
      }
    }
    load();
    timer.current = setInterval(load, 5000);
    return () => {
      if (timer.current) clearInterval(timer.current);
    };
  }, [params.orderId, router]);

  async function handleDownload() {
    setError(null);
    try {
      const blob = await api.downloadReport(params.orderId, accessSecret);
      setUnlocked(true);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `rapor-${params.orderId}.md`;
      a.click();
    } catch (err: any) {
      setError(err.message);
    }
  }

  if (!order && !error) {
    return (
      <main className="container-page max-w-xl py-16">
        <div className="h-40 animate-pulse rounded-card bg-brand-50" />
      </main>
    );
  }

  const status = order?.status as string;
  const hostname = order?.domain?.hostname ?? 'hedef';
  const active = status === 'scan_running' || status === 'paid' || status === 'scan_queued';

  let feed: Array<{ seq: number; text: string }> = [];
  try {
    if (order?.flow?.activityFeed) feed = JSON.parse(order.flow.activityFeed);
  } catch {
    feed = [];
  }

  return (
    <main className="container-page max-w-xl py-16">
      <p className="eyebrow">Sipariş Durumu</p>
      <h1 className="mt-2 text-3xl font-extrabold text-brand">
        {status === 'scan_completed' && order?.report?.incomplete
          ? 'Rapor hazır — ancak eksik'
          : HEADLINE[status] ?? status}
      </h1>
      {order && <p className="mt-1 text-sm text-ink-muted">Hedef: {hostname}</p>}

      <div className="mt-8">
        <StatusTracker status={status} />
      </div>

      {active && (
        <>
          <p className="mt-4 rounded-card bg-brand-50/70 px-4 py-3 text-sm text-ink-soft">
            Tarama arka planda çalışıyor. Bu sayfa otomatik güncelleniyor — kapatabilirsiniz; sonuç
            hazır olduğunda erişim kodu e-postanıza gönderilecek.
          </p>

          {/* Canlı aktivite — landing'deki terminal görünümüyle aynı; içerik GERÇEK
              (worker'ın ürettiği redakte/kategorilenmiş akış), her 5 sn güncellenir. */}
          <div className="mt-4 overflow-hidden rounded-card border border-white/10 bg-[#0A1F1C] shadow-lg">
            <div className="flex items-center gap-2 border-b border-white/10 px-4 py-3">
              <span className="h-3 w-3 rounded-full bg-red-400/70" />
              <span className="h-3 w-3 rounded-full bg-accent/70" />
              <span className="h-3 w-3 rounded-full bg-emerald-400/70" />
              <span className="ml-3 text-xs font-medium text-white/40">cybertestify — live scan</span>
            </div>
            <div className="min-h-[180px] p-5 font-mono text-[13px] leading-7">
              <div className="text-white/45" dir="ltr">$ cybertestify scan {hostname}</div>
              <div className="text-emerald-300" dir="ltr">✓ Alan adı sahipliği doğrulandı</div>
              {feed.length === 0 ? (
                <div className="text-white/80" dir="ltr">
                  → Tarama başlatılıyor…
                  <span className="ml-1 inline-block h-4 w-2 translate-y-0.5 animate-pulse bg-accent/80" />
                </div>
              ) : (
                feed.map((it, i) => (
                  <div key={it.seq} className="text-white/80" dir="ltr">
                    → {it.text}
                    {i === feed.length - 1 && (
                      <span className="ml-1 inline-block h-4 w-2 translate-y-0.5 animate-pulse bg-accent/80" />
                    )}
                  </div>
                ))
              )}
            </div>
            <div className="border-t border-white/10 px-5 py-3 text-xs text-white/40">
              Teknik loglar güvenlik ve gizlilik nedeniyle gizlenmiştir; yalnızca genel aktivite gösterilir.
            </div>
          </div>
        </>
      )}

      {status === 'scan_completed' && (
        <div className="mt-8 space-y-6">
          {order.report?.incomplete && (
            <div className="rounded-card border border-amber-300 bg-amber-50 px-4 py-3.5 text-sm text-amber-900">
              <strong>⚠️ Bu tarama eksik tamamlandı.</strong>{' '}
              {order.report.incompleteReason ??
                'Tarama beklenenden erken sonlandı ve rapor içeriği eksik/boş olabilir.'}{' '}
              Ücret iadesi veya taramanın yeniden çalıştırılması için{' '}
              <a href="mailto:destek@cybertestify.com" className="font-semibold underline">
                destek@cybertestify.com
              </a>{' '}
              ile iletişime geçin (sipariş no: {order.id}).
            </div>
          )}

          <ScopeCertificate hostname={hostname} flow={order.flow} />

          {/* Rapor teslim — kilit mikro-etkilesimi */}
          <div className="card p-6">
            <div className="flex items-center gap-3">
              <span className={`flex h-12 w-12 items-center justify-center rounded-full ${unlocked ? 'bg-emerald-50' : 'bg-brand-50'}`}>
                <LockIcon open={unlocked} />
              </span>
              <div>
                <h2 className="font-bold text-ink">{unlocked ? 'Rapor indirildi ✓' : 'Şifreli raporunuz hazır'}</h2>
                <p className="text-xs text-ink-muted">Tek kullanımlık erişim koduyla açılır</p>
              </div>
            </div>

            {order.report?.devAccessSecret && (
              <div className="mt-4 rounded-card border border-accent/40 bg-accent-soft/50 p-3 text-xs text-ink-soft">
                <strong>Geliştirme modu:</strong> E-posta servisi henüz bağlı olmadığı için erişim
                kodunuz burada gösterilip kutuya dolduruldu. Gerçek sistemde yalnızca e-posta ile gelir.
                <div className="mt-1 font-mono text-ink">{order.report.devAccessSecret}</div>
              </div>
            )}

            <div className="mt-4 flex flex-col gap-2 sm:flex-row">
              <input
                value={accessSecret}
                onChange={(e) => setAccessSecret(e.target.value)}
                placeholder="Erişim kodu"
                className="flex-1 rounded-card border border-line bg-white px-3.5 py-2.5 text-sm outline-none focus:border-brand-300 focus:ring-2 focus:ring-brand-100"
              />
              <button onClick={handleDownload} disabled={!accessSecret} className="btn-primary disabled:opacity-50">
                Raporu indir
              </button>
            </div>
          </div>
        </div>
      )}

      {status === 'scope_violation' && (
        <p className="mt-6 rounded-card border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800">
          Tarama, kapsam dışı bir hedefe erişim girişimi tespit edildiği için güvenlik gereği
          durduruldu. Bu, sizi ve üçüncü tarafları koruyan bilinçli bir önlemdir.
        </p>
      )}

      {status === 'scan_failed' && (
        <p className="mt-6 rounded-card border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
          Tarama tamamlanamadı. Lütfen tekrar deneyin veya{' '}
          <a href="mailto:destek@cybertestify.com" className="font-semibold underline">
            destek
          </a>{' '}
          ile iletişime geçin.
        </p>
      )}

      {error && <p className="mt-4 text-sm text-red-600">{error}</p>}
    </main>
  );
}
