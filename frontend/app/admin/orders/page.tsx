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

  useEffect(() => {
    adminApi.orders(page, status).then(setData).catch((e) => setError(e.message));
  }, [page, status]);

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
            <Table
              columns={['Müşteri', 'Hedef', 'Paket', 'Durum', 'Tool', 'Tarih']}
              rows={data.items.map((o: any) => [
                o.customerEmail,
                o.hostname,
                o.packageName,
                <StatusBadge key="s" status={o.status} />,
                o.toolCallCount ?? '—',
                fmtDate(o.createdAt),
              ])}
            />
            <Pager page={data.page} pageSize={data.pageSize} total={data.total} onPage={setPage} />
          </>}
    </>
  );
}
