'use client';

import { useEffect, useState } from 'react';
import { adminApi } from '../../../lib/adminApi';
import { H1, Table, Pager, StatusBadge, fmtDate } from '../../../components/admin/ui';

const STATUSES = ['', 'awaiting_payment', 'paid', 'scan_queued', 'scan_running', 'scan_completed', 'scan_failed', 'scope_violation', 'report_delivered', 'report_purged', 'refunded'];

export default function AdminOrders() {
  const [page, setPage] = useState(1);
  const [status, setStatus] = useState('');
  const [data, setData] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [refunding, setRefunding] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);

  function load() {
    adminApi.orders(page, status).then(setData).catch((e) => setError(e.message));
  }
  useEffect(() => { load(); /* eslint-disable-next-line */ }, [page, status]);

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
            <Table
              columns={['Müşteri', 'Hedef', 'Paket', 'Durum', 'Tool', 'Tarih', 'İşlem']}
              rows={data.items.map((o: any) => [
                o.customerEmail,
                o.hostname,
                o.packageName,
                <StatusBadge key="s" status={o.status} />,
                o.toolCallCount ?? '—',
                fmtDate(o.createdAt),
                o.status === 'refunded' ? (
                  <span key="r" style={{ color: '#94a3b8', fontSize: 12 }}>iade edildi</span>
                ) : (
                  <button
                    key="r"
                    onClick={() => refund(o.id)}
                    disabled={refunding === o.id}
                    style={{ padding: '4px 10px', borderRadius: 6, background: '#7f1d1d', color: '#fecaca', border: '1px solid #b91c1c', fontSize: 12, cursor: 'pointer' }}
                  >
                    {refunding === o.id ? '…' : 'İade işaretle'}
                  </button>
                ),
              ])}
            />
            <Pager page={data.page} pageSize={data.pageSize} total={data.total} onPage={setPage} />
          </>}
    </>
  );
}
