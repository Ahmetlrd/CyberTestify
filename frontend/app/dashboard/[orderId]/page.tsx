'use client';

import { useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import { api } from '../../../lib/api';

const STATUS_LABELS: Record<string, string> = {
  awaiting_payment: 'Ödeme bekleniyor',
  paid: 'Ödeme alındı, tarama hazırlanıyor',
  scan_running: 'Tarama devam ediyor',
  scan_completed: 'Tarama tamamlandı',
  scan_failed: 'Tarama tamamlanamadı',
};

const TERMINAL = new Set(['scan_completed', 'scan_failed']);

export default function OrderDashboard({ params }: { params: { orderId: string } }) {
  const router = useRouter();
  const [order, setOrder] = useState<any>(null);
  const [accessSecret, setAccessSecret] = useState('');
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
        // DEV modu: e-posta ile gelmesi gereken erisim sifresi panelde donuyorsa
        // indirme kutusunu otomatik dolduralim (musteri deneyimini kolaylastirir).
        if (o.report?.devAccessSecret) {
          setAccessSecret((prev) => prev || o.report.devAccessSecret);
        }
        if (TERMINAL.has(o.status) && timer.current) {
          clearInterval(timer.current);
          timer.current = null;
        }
      } catch (err: any) {
        setError(err.message);
      }
    }

    load();
    // Tarama bitene kadar her 5 sn'de bir durumu tazele.
    timer.current = setInterval(load, 5000);
    return () => {
      if (timer.current) clearInterval(timer.current);
    };
  }, [params.orderId, router]);

  async function handleDownload() {
    setError(null);
    try {
      const blob = await api.downloadReport(params.orderId, accessSecret);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `rapor-${params.orderId}.md`;
      a.click();
    } catch (err: any) {
      setError(err.message);
    }
  }

  if (!order && !error) return <main>Yükleniyor...</main>;

  return (
    <main>
      <h1>Sipariş Durumu</h1>
      {order && (
        <>
          <p>
            Durum: <strong>{STATUS_LABELS[order.status] ?? order.status}</strong>
          </p>

          {(order.status === 'scan_running' || order.status === 'paid') && (
            <p style={{ color: '#666' }}>
              Tarama arka planda çalışıyor. Bu sayfa otomatik olarak güncelleniyor,
              kapatabilirsiniz — sonuç hazır olduğunda erişim şifresi e-postanıza gönderilecek.
            </p>
          )}

          {order.status === 'scan_completed' && (
            <div>
              <p>Raporunuz hazır. E-posta ile gönderilen tek seferlik erişim şifresini girin:</p>
              {order.report?.devAccessSecret && (
                <p
                  style={{
                    background: '#fff8e1',
                    border: '1px solid #f0d000',
                    borderRadius: 6,
                    padding: 10,
                    fontSize: 13,
                  }}
                >
                  <strong>Geliştirme modu:</strong> E-posta servisi henüz bağlı olmadığı için
                  erişim şifreniz burada gösteriliyor ve kutuya otomatik dolduruldu. Gerçek
                  sistemde bu şifre yalnızca e-posta ile gelir.
                  <br />
                  <code>{order.report.devAccessSecret}</code>
                </p>
              )}
              <input
                style={{ width: '100%', maxWidth: 420 }}
                value={accessSecret}
                onChange={(e) => setAccessSecret(e.target.value)}
              />
              <div style={{ marginTop: 8 }}>
                <button onClick={handleDownload}>Raporu indir</button>
              </div>
            </div>
          )}

          {order.status === 'scan_failed' && (
            <p style={{ color: 'crimson' }}>
              Tarama tamamlanamadı. Lütfen tekrar deneyin veya destek ile iletişime geçin.
            </p>
          )}
        </>
      )}

      {error && <p style={{ color: 'crimson' }}>{error}</p>}
    </main>
  );
}
