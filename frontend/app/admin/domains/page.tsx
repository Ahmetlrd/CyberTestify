'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { adminApi } from '../../../lib/adminApi';
import { H1, Table, Pager, StatusBadge, fmtDate } from '../../../components/admin/ui';

export default function AdminDomains() {
  const [page, setPage] = useState(1);
  const [q, setQ] = useState('');
  const [query, setQuery] = useState('');
  const [data, setData] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    adminApi.domains(page, query).then(setData).catch((e) => setError(e.message));
  }, [page, query]);

  return (
    <>
      <H1>Alan Adları</H1>
      <form
        onSubmit={(e) => { e.preventDefault(); setPage(1); setQuery(q.trim()); }}
        style={{ display: 'flex', gap: 8, marginBottom: 14 }}
      >
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="hostname ara…"
          style={{ flex: 1, maxWidth: 320, padding: '6px 10px', borderRadius: 6, border: '1px solid #334155', background: '#0f172a', color: '#e2e8f0', fontSize: 13 }} />
        <button type="submit" style={{ padding: '6px 14px', borderRadius: 6, border: '1px solid #334155', background: '#1e293b', color: '#e2e8f0', cursor: 'pointer', fontSize: 13 }}>Ara</button>
      </form>
      {error && <p style={{ color: '#fca5a5' }}>{error}</p>}
      {!data ? <p style={{ color: '#94a3b8' }}>Yükleniyor…</p> : (
        <>
          <Table
            columns={['Alan adı', 'Müşteri', 'Durum', 'Çözülen IP', 'Hosting', 'Sipariş', 'Kayıt']}
            rows={data.items.map((d: any) => [
              <b key="h" style={{ color: '#e2e8f0' }}>{d.hostname}</b>,
              <Link key="c" href={`/admin/customers/${d.customerId}`} style={{ color: '#7dd3fc' }}>{d.customerEmail}</Link>,
              <StatusBadge key="s" status={d.status} />,
              d.resolvedIps || '—', d.hostingType || '—', d.orderCount, fmtDate(d.createdAt),
            ])}
          />
          <Pager page={data.page} pageSize={data.pageSize} total={data.total} onPage={setPage} />
        </>
      )}
    </>
  );
}
