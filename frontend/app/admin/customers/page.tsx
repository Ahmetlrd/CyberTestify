'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { adminApi } from '../../../lib/adminApi';
import { H1, Table, Pager, fmtDate } from '../../../components/admin/ui';

export default function AdminCustomers() {
  const [page, setPage] = useState(1);
  const [data, setData] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    adminApi.customers(page).then(setData).catch((e) => setError(e.message));
  }, [page]);

  if (error) return <><H1>Müşteriler</H1><p style={{ color: '#fca5a5' }}>{error}</p></>;
  if (!data) return <><H1>Müşteriler</H1><p style={{ color: '#94a3b8' }}>Yükleniyor…</p></>;

  return (
    <>
      <H1>Müşteriler</H1>
      <Table
        columns={['E-posta', 'Kayıt', 'Alan adı', 'Sipariş', '']}
        rows={data.items.map((c: any) => [
          <Link key={c.id} href={`/admin/customers/${c.id}`} style={{ color: '#7dd3fc', fontWeight: 600 }}>{c.email}</Link>,
          fmtDate(c.createdAt), c.domainCount, c.orderCount,
          <Link key="d" href={`/admin/customers/${c.id}`} style={{ color: '#94a3b8' }}>detay →</Link>,
        ])}
      />
      <Pager page={data.page} pageSize={data.pageSize} total={data.total} onPage={setPage} />
    </>
  );
}
