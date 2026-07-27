'use client';

import { useEffect, useState } from 'react';
import { adminApi } from '../../../lib/adminApi';
import { H1, Table, Pager, StatusBadge, fmtDate } from '../../../components/admin/ui';

export default function AdminScopeViolations() {
  const [page, setPage] = useState(1);
  const [data, setData] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    adminApi.scopeViolations(page).then(setData).catch((e) => setError(e.message));
  }, [page]);

  if (error) return <><H1>Kapsam İhlalleri</H1><p style={{ color: '#fca5a5' }}>{error}</p></>;
  if (!data) return <><H1>Kapsam İhlalleri</H1><p style={{ color: '#94a3b8' }}>Yükleniyor…</p></>;

  return (
    <>
      <H1>Kapsam İhlalleri (audit log)</H1>
      <p style={{ fontSize: 13, color: '#94a3b8', margin: '0 0 12px' }}>
        Seviye-3 (tool-args) tespiti. Not: <code>monitor</code> modunda bu kayıtlar audit amaçlıdır; gerçek engelleme Seviye-1 egress-proxy'dedir.
      </p>
      <Table
        columns={['Zaman', 'Müşteri', 'Kapsam (hedef)', 'İşaretlenen', 'Sipariş', 'Flow']}
        rows={data.items.map((v: any) => [
          fmtDate(v.startedAt),
          v.customerEmail,
          v.hostname,
          <span key="t" style={{ color: '#f97316', wordBreak: 'break-all' }}>{v.target}</span>,
          <StatusBadge key="s" status={v.orderStatus} />,
          v.flowId,
        ])}
      />
      <Pager page={data.page} pageSize={data.pageSize} total={data.total} onPage={setPage} />
    </>
  );
}
