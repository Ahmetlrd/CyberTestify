'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { adminApi } from '../../../lib/adminApi';
import { H1, Table, Pager, fmtDate } from '../../../components/admin/ui';

const ACTION_LABEL: Record<string, string> = { view_pdf: 'raporu görüntüledi (PDF)', approve_release: 'onayladı + açtı' };

export default function AdminReportAccess() {
  const [page, setPage] = useState(1);
  const [data, setData] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    adminApi.reportAccessLogs(page).then(setData).catch((e) => setError(e.message));
  }, [page]);

  return (
    <>
      <H1>Rapor Erişim Audit</H1>
      <p style={{ fontSize: 12, color: '#64748b', margin: '-8px 0 14px' }}>
        Her admin rapor-erişimi burada değiştirilemez şekilde kayıtlıdır (kim · ne zaman · hangi rapor · hangi müşteri). Gizli anahtar/şifre asla kaydedilmez.
      </p>
      {error && <p style={{ color: '#fca5a5' }}>{error}</p>}
      {!data ? <p style={{ color: '#94a3b8' }}>Yükleniyor…</p> : (
        <>
          <Table
            columns={['Zaman', 'Admin', 'Eylem', 'Müşteri', 'Sipariş/Rapor', 'IP']}
            rows={data.items.map((l: any) => [
              fmtDate(l.at),
              <code key="a" style={{ color: '#c4b5fd', fontSize: 12 }}>{l.adminId.slice(0, 10)}…</code>,
              ACTION_LABEL[l.action] ?? l.action,
              <Link key="c" href={`/admin/customers/${l.customerId}`} style={{ color: '#7dd3fc' }}>{l.customerEmail}</Link>,
              <span key="r" style={{ fontSize: 11, color: '#94a3b8' }}>{l.orderId.slice(0, 8)}… / {l.reportId.slice(0, 8)}…</span>,
              l.ip || '—',
            ])}
          />
          <Pager page={data.page} pageSize={data.pageSize} total={data.total} onPage={setPage} />
        </>
      )}
    </>
  );
}
