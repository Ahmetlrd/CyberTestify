'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { adminApi } from '../../../lib/adminApi';
import { H1, Table, Pager, fmtDate } from '../../../components/admin/ui';

const RT_COLOR: Record<string, string> = {
  completed: '#22c55e', running: '#38bdf8', binding: '#38bdf8', reporting: '#38bdf8',
  provisioning: '#eab308', hardening: '#eab308', queued: '#94a3b8',
  failed: '#ef4444', torn_down: '#64748b',
  aborted: '#f97316', // (bağımsız watchdog hardkill) — hata DEĞİL, cap/watchdog ZORLA durdurdu
};
function RtBadge({ status }: { status: string | null }) {
  if (!status) return <span style={{ color: '#64748b' }}>—</span>;
  const c = RT_COLOR[status] ?? '#94a3b8';
  return <span style={{ display: 'inline-block', padding: '2px 8px', borderRadius: 999, fontSize: 12, fontWeight: 600, color: '#0f172a', background: c }}>{status}</span>;
}

export default function AdminRedTeam() {
  const [page, setPage] = useState(1);
  const [data, setData] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const load = () => adminApi.redteamJobs(page).then(setData).catch((e) => setError(e.message));
    load();
    const t = setInterval(load, 10000); // liste periyodik tazelenir
    return () => clearInterval(t);
  }, [page]);

  return (
    <>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <H1>Otonom Red Team — İşler</H1>
        <Link href="/admin/redteam/new" style={{ padding: '8px 16px', borderRadius: 8, background: '#0369a1', color: '#fff', fontWeight: 700, fontSize: 13 }}>+ Yeni koşu</Link>
      </div>
      <p style={{ fontSize: 12, color: '#64748b', margin: '-8px 0 14px' }}>
        Canlı gözlem: veri, orchestrator'ın SSH kontrol-kanalından çektiği (droplet→CyberTestify PUSH yok) verilerden gelir. Yalnız admin görür.
      </p>
      {error && <p style={{ color: '#fca5a5' }}>{error}</p>}
      {!data ? <p style={{ color: '#94a3b8' }}>Yükleniyor…</p> : (
        <>
          <Table
            columns={['Hedef', 'Seviye', 'Ortam', 'Durum', 'Faz', 'Çağrı', 'Maliyet', 'Egress', 'Oluşturma', '']}
            rows={data.items.map((j: any) => [
              <b key="d" style={{ color: '#e2e8f0' }}>{j.domain}</b>,
              j.level, j.environment,
              <RtBadge key="s" status={j.status} />,
              j.phase || '—',
              j.llmCalls ?? '—',
              j.costUsd != null ? `$${Number(j.costUsd).toFixed(2)}` : '—',
              j.egressCyberBlocked === true ? '✓ izole' : j.egressCyberBlocked === false ? '⚠ SIZINTI' : '—',
              fmtDate(j.createdAt),
              <Link key="l" href={`/admin/redteam/${j.id}`} style={{ color: '#7dd3fc' }}>izle →</Link>,
            ])}
          />
          <Pager page={data.page} pageSize={data.pageSize} total={data.total} onPage={setPage} />
        </>
      )}
    </>
  );
}
