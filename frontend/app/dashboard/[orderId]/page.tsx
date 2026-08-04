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
  const [busyFix, setBusyFix] = useState(false);
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

  function downloadBlob(blob: Blob, name: string) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    a.click();
  }

  async function handleDownload() {
    setError(null);
    try {
      const blob = await api.downloadReport(params.orderId, accessSecret);
      setUnlocked(true);
      // Rapor artik PDF olarak uretiliyor (bkz backend reports.ts /download).
      downloadBlob(blob, `cybertestify-rapor-${params.orderId}.pdf`);
    } catch (err: any) {
      setError(err.message);
    }
  }

  // (3) AI Cozum Onerileri: satin al (unlock) -> siparisi yenile.
  async function handleUnlockFix() {
    setBusyFix(true);
    setError(null);
    try {
      await api.unlockFixSuggestions(params.orderId);
      const o = await api.getOrder(params.orderId);
      setOrder(o);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setBusyFix(false);
    }
  }

  async function handleDownloadFix() {
    setError(null);
    try {
      const blob = await api.downloadFixSuggestions(params.orderId, accessSecret);
      downloadBlob(blob, `cozum-onerileri-${params.orderId}.md`);
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

      {status === 'scan_queued' && order?.queue && (
        <div className="mt-4 rounded-card border border-accent/40 bg-accent-soft/40 px-4 py-3 text-sm text-ink-soft">
          {(() => {
            const ahead = order.queue.peopleAhead ?? 0;
            const eta = order.queue.etaMinutes;
            const hasEta = typeof eta === 'number' && eta > 0;
            const etaLabel = hasEta
              ? eta >= 60
                ? `yaklaşık ${Math.round((eta / 60) * 10) / 10} saat`
                : `yaklaşık ${eta} dakika`
              : null;
            if (ahead > 0) {
              return (
                <>
                  <strong>Şu an önünüzde {ahead} tarama var.</strong>{' '}
                  {etaLabel
                    ? <>Tahminen <strong>{etaLabel}</strong> sonra taramanız başlayacak. </>
                    : <>Taramanız kısa süre içinde başlayacak. </>}
                  Taramalar tek tek yapıldığı için sıra size gelince otomatik başlar; bu sayfa güncel kalır,
                  kapatsanız bile durumu buradan takip edebilirsiniz.
                </>
              );
            }
            return (
              <>
                <strong>Sıra sizde — taramanız birazdan başlıyor.</strong> Bu sayfa otomatik güncelleniyor.
              </>
            );
          })()}
        </div>
      )}

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
                <strong>Tek kullanımlık erişim kodunuz:</strong> Bu kod ayrıca e-posta ile de tarafınıza iletilir.
                Kolaylık olması için aşağıdaki kutuya otomatik dolduruldu.
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

          {/* (3) Ücretli eklenti: AI Çözüm Önerileri */}
          {order.report?.hasFixSuggestions && (
            <div className="card p-6">
              <h2 className="font-bold text-ink">AI Çözüm Önerileri</h2>
              <p className="mt-1 text-xs text-ink-muted">
                Bulgularınız için somut, uygulanabilir düzeltme adımları (güvenli kod/config örnekleriyle).
              </p>
              {order.report.fixSuggestionsUnlocked ? (
                <>
                  <button onClick={handleDownloadFix} disabled={!accessSecret} className="btn-primary mt-4 disabled:opacity-50">
                    Çözüm önerilerini indir
                  </button>
                  {!accessSecret && (
                    <p className="mt-2 text-xs text-ink-muted">Önce yukarıdaki erişim kodunu girin.</p>
                  )}
                </>
              ) : (
                <>
                  <div className="mt-3 rounded-card border border-line bg-brand-50/40 px-4 py-3 text-sm text-ink-soft">
                    🔒 Bu içerik kilitli.{' '}
                    {order.report.fixSuggestionPriceMinorUnit != null && (
                      <strong>
                        {(order.report.fixSuggestionPriceMinorUnit / 100).toLocaleString('tr-TR')} {order.currency}
                      </strong>
                    )}{' '}
                    karşılığında açılır.
                  </div>
                  <button onClick={handleUnlockFix} disabled={busyFix} className="btn-primary mt-3 disabled:opacity-60">
                    {busyFix ? 'İşleniyor…' : 'Satın al ve aç'}
                  </button>
                  <p className="mt-2 text-xs text-ink-muted">Ödeme şu an sandbox/test modundadır.</p>
                </>
              )}
            </div>
          )}
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
