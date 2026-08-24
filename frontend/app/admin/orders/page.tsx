'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { adminApi } from '../../../lib/adminApi';
import { H1, Table, Pager, StatusBadge, fmtDate } from '../../../components/admin/ui';

const STATUSES = ['', 'awaiting_payment', 'awaiting_domain_verification', 'paid', 'scan_queued', 'scan_running', 'awaiting_admin_review', 'scan_completed', 'scan_failed', 'scope_violation', 'report_delivered', 'report_purged', 'refunded'];

export default function AdminOrders() {
  const [page, setPage] = useState(1);
  const [status, setStatus] = useState('');
  const [data, setData] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [refunding, setRefunding] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null); // onay/retry/görüntüle işlemi süren sipariş id
  const [note, setNote] = useState<string | null>(null);

  function load() {
    adminApi.orders(page, status).then(setData).catch((e) => setError(e.message));
  }
  useEffect(() => { load(); /* eslint-disable-next-line */ }, [page, status]);

  // (İÇ KALİTE KAPISI) Raporu ADMIN olarak görüntüle (AI dahil açık) — yeni sekmede PDF.
  async function viewReport(id: string) {
    setBusy(id + ':view'); setNote(null);
    try {
      const blob = await adminApi.reportPdfBlob(id);
      const url = URL.createObjectURL(blob);
      window.open(url, '_blank', 'noopener');
      setTimeout(() => URL.revokeObjectURL(url), 60_000);
    } catch (e: any) { setNote(`Hata: ${e.message}`); } finally { setBusy(null); }
  }

  // Onayla → müşteriye açılır + erişim kodu e-postası gider.
  async function approve(id: string) {
    if (!confirm('Bu raporu ONAYLA ve müşteriye aç?\n\nErişim kodu e-postası müşteriye ŞİMDİ gönderilecek.')) return;
    setBusy(id + ':approve'); setNote(null);
    try {
      const r = await adminApi.approveReport(id);
      setNote(`Rapor onaylandı ve müşteriye açıldı. Erişim kodu e-postası: ${r.mailed ? 'gönderildi' : 'GÖNDERİLEMEDI (log’a bakın)'}.`);
      load();
    } catch (e: any) { setNote(`Hata: ${e.message}`); } finally { setBusy(null); }
  }

  // Yeniden dene → baştan tarar (müşteri ekranı "hala taranıyor" görmeye devam eder).
  async function retry(id: string) {
    if (!confirm('Bu siparişi baştan TARA?\n\nMevcut rapor silinir, tarama yeniden çalışır. Müşteri bu süreçte “hala taranıyor” görür.')) return;
    setBusy(id + ':retry'); setNote(null);
    try {
      const r = await adminApi.retryScan(id);
      setNote(r.queued ? 'Yeniden tarama KUYRUĞA alındı (aktif tarama var).' : 'Yeniden tarama başlatıldı.');
      load();
    } catch (e: any) { setNote(`Hata: ${e.message}`); } finally { setBusy(null); }
  }

  // (E) Iade olarak isaretle — iyzico iadesi ELLE yapildiktan SONRA. Onay + musteriye mail.
  async function refund(id: string) {
    if (!confirm('Bu siparişi İADE EDİLDİ olarak işaretle ve müşteriye iade bildirim e-postası gönder?\n\n(iyzico panelinden iadeyi zaten yaptığınızdan emin olun.)')) return;
    setRefunding(id); setNote(null);
    try {
      const r = await adminApi.refundOrder(id);
      setNote(r.alreadyRefunded ? 'Zaten iade işaretliydi.' : `İade işaretlendi. Mail: ${r.mailed ? 'gönderildi' : 'gönderilemedi (log’a bakın)'}.`);
      load();
    } catch (e: any) { setNote(`Hata: ${e.message}`); } finally { setRefunding(null); }
  }

  return (
    <>
      <H1>Siparişler</H1>
      <div style={{ marginBottom: 12 }}>
        <label style={{ fontSize: 13, color: '#94a3b8', marginRight: 8 }}>Durum:</label>
        <select
          value={status}
          onChange={(e) => { setStatus(e.target.value); setPage(1); }}
          style={{ padding: '6px 10px', borderRadius: 6, background: '#0f172a', color: '#e2e8f0', border: '1px solid #334155', fontSize: 13 }}
        >
          {STATUSES.map((s) => <option key={s} value={s}>{s || 'Tümü'}</option>)}
        </select>
      </div>
      {error ? <p style={{ color: '#fca5a5' }}>{error}</p>
        : !data ? <p style={{ color: '#94a3b8' }}>Yükleniyor…</p>
        : <>
            {note && <p style={{ color: '#a3e635', fontSize: 13, marginBottom: 8 }}>{note}</p>}
            {data.reportReviewsPending > 0 && (
              <p style={{ color: '#0f172a', background: '#fbbf24', fontWeight: 800, fontSize: 13, padding: '8px 12px', borderRadius: 8, marginBottom: 10 }}>
                Rapor onayı bekleyen: {data.reportReviewsPending} — “rapor onayı bekliyor” durumundaki siparişleri inceleyip onaylayın.
              </p>
            )}
            {data.refundRequestsPending > 0 && (
              <p style={{ color: '#0f172a', background: '#f59e0b', fontWeight: 700, fontSize: 13, padding: '8px 12px', borderRadius: 8, marginBottom: 10 }}>
                🔔 Bekleyen iade talebi: {data.refundRequestsPending} — aşağıda “İADE TALEBİ” etiketli siparişler.
              </p>
            )}
            <Table
              columns={['Müşteri', 'Hedef', 'Paket', 'Durum', 'Not', 'Tarih', 'İşlem']}
              rows={data.items.map((o: any) => [
                o.customerEmail,
                <span key="h" style={{ display: 'inline-flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
                  {o.hostname}
                  {o.region && (
                    <span title={`Bölge: ${o.region}`} style={{ background: '#1e293b', color: '#93c5fd', fontSize: 10, fontWeight: 800, padding: '2px 6px', borderRadius: 999, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                      {o.region}
                    </span>
                  )}
                </span>,
                o.packageName,
                <span key="s" style={{ display: 'inline-flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
                  <StatusBadge status={o.status} />
                  {o.refundRequestedAt && o.status !== 'refunded' && (
                    <span style={{ background: '#f59e0b', color: '#0f172a', fontSize: 10, fontWeight: 800, padding: '2px 6px', borderRadius: 999 }}>İADE TALEBİ</span>
                  )}
                </span>,
                <span key="n" style={{ fontSize: 11, color: '#94a3b8' }}>
                  {o.refundRequestReason ? `İade: ${o.refundRequestReason}` : o.failureReason ? `Hata: ${o.failureReason}` : ''}
                  {typeof o.attemptCount === 'number' && o.attemptCount > 1 ? ` (deneme: ${o.attemptCount})` : ''}
                </span>,
                fmtDate(o.createdAt),
                <span key="act" style={{ display: 'inline-flex', gap: 6, flexWrap: 'wrap' }}>
                  {o.status === 'awaiting_admin_review' && (
                    <button
                      onClick={() => approve(o.id)}
                      disabled={busy === o.id + ':approve'}
                      style={{ padding: '4px 10px', borderRadius: 6, background: '#166534', color: '#dcfce7', border: '1px solid #22c55e', fontSize: 12, fontWeight: 700, cursor: 'pointer' }}
                    >
                      {busy === o.id + ':approve' ? '…' : '✓ Onayla'}
                    </button>
                  )}
                  {o.hasReport && (
                    <button
                      onClick={() => viewReport(o.id)}
                      disabled={busy === o.id + ':view'}
                      style={{ padding: '4px 10px', borderRadius: 6, background: '#1e3a8a', color: '#dbeafe', border: '1px solid #3b82f6', fontSize: 12, fontWeight: 700, cursor: 'pointer' }}
                    >
                      {busy === o.id + ':view' ? '…' : 'Raporu görüntüle'}
                    </button>
                  )}
                  {['awaiting_admin_review', 'scan_completed', 'report_delivered', 'scan_failed', 'scope_violation'].includes(o.status) && (
                    <button
                      onClick={() => retry(o.id)}
                      disabled={busy === o.id + ':retry'}
                      style={{ padding: '4px 10px', borderRadius: 6, background: '#78350f', color: '#fef3c7', border: '1px solid #d97706', fontSize: 12, fontWeight: 700, cursor: 'pointer' }}
                    >
                      {busy === o.id + ':retry' ? '…' : 'Yeniden dene'}
                    </button>
                  )}
                  <Link
                    href={`/admin/orders/${o.id}/logs`}
                    style={{ padding: '4px 10px', borderRadius: 6, background: '#334155', color: '#e2e8f0', border: '1px solid #475569', fontSize: 12, fontWeight: 700, textDecoration: 'none' }}
                  >
                    Tarama Logu
                  </Link>
                  {o.status === 'refunded' ? (
                    <span style={{ color: '#94a3b8', fontSize: 12 }}>iade edildi</span>
                  ) : (
                    <button
                      onClick={() => refund(o.id)}
                      disabled={refunding === o.id}
                      style={{ padding: '4px 10px', borderRadius: 6, background: '#7f1d1d', color: '#fecaca', border: '1px solid #b91c1c', fontSize: 12, cursor: 'pointer' }}
                    >
                      {refunding === o.id ? '…' : 'İade işaretle'}
                    </button>
                  )}
                </span>,
              ])}
            />
            <Pager page={data.page} pageSize={data.pageSize} total={data.total} onPage={setPage} />
          </>}
    </>
  );
}
