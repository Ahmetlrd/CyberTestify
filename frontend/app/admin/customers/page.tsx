'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { adminApi } from '../../../lib/adminApi';
import { H1, Table, Pager, fmtDate } from '../../../components/admin/ui';

type Target = { id: string; email: string; domainCount: number; orderCount: number };

export default function AdminCustomers() {
  const [page, setPage] = useState(1);
  const [data, setData] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  // Silme onay penceresi: hedef müşteri + e-posta teyidi + durum.
  const [target, setTarget] = useState<Target | null>(null);
  const [confirmText, setConfirmText] = useState('');
  const [busy, setBusy] = useState(false);
  const [modalError, setModalError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = () => adminApi.customers(page).then(setData).catch((e) => setError(e.message));
  useEffect(() => { load(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [page]);

  async function doDelete() {
    if (!target) return;
    setBusy(true);
    setModalError(null);
    try {
      const r = await adminApi.customerDelete(target.id, confirmText.trim());
      const d = r.deleted;
      setNotice(`${r.email} silindi — ${d.orders} sipariş, ${d.reports} rapor, ${d.domains} alan adı, ${d.schedules} plan.`);
      setTarget(null);
      setConfirmText('');
      await load();
    } catch (e: any) {
      setModalError(e.message);
    } finally {
      setBusy(false);
    }
  }

  if (error) return <><H1>Müşteriler</H1><p style={{ color: '#fca5a5' }}>{error}</p></>;
  if (!data) return <><H1>Müşteriler</H1><p style={{ color: '#94a3b8' }}>Yükleniyor…</p></>;

  const matches = !!target && confirmText.trim().toLowerCase() === target.email.toLowerCase();

  return (
    <>
      <H1>Müşteriler</H1>
      {notice && (
        <p style={{ margin: '0 0 12px', padding: '8px 12px', borderRadius: 8, background: '#064e3b', color: '#a7f3d0', fontSize: 13 }}>
          {notice}
        </p>
      )}
      <Table
        columns={['E-posta', 'Kayıt', 'Alan adı', 'Sipariş', '', '']}
        rows={data.items.map((c: any) => [
          <Link key={c.id} href={`/admin/customers/${c.id}`} style={{ color: '#7dd3fc', fontWeight: 600 }}>{c.email}</Link>,
          fmtDate(c.createdAt), c.domainCount, c.orderCount,
          <Link key="d" href={`/admin/customers/${c.id}`} style={{ color: '#94a3b8' }}>detay →</Link>,
          <button
            key="del"
            type="button"
            onClick={() => { setTarget({ id: c.id, email: c.email, domainCount: c.domainCount, orderCount: c.orderCount }); setConfirmText(''); setModalError(null); }}
            style={{ padding: '4px 10px', borderRadius: 6, border: '1px solid #7f1d1d', background: '#450a0a', color: '#fca5a5', fontSize: 12, fontWeight: 600, cursor: 'pointer' }}
          >
            Sil
          </button>,
        ])}
      />
      <Pager page={data.page} pageSize={data.pageSize} total={data.total} onPage={setPage} />

      {/* ONAY PENCERESİ — geri alınamaz işlem: e-posta yazılmadan "Kalıcı olarak sil" AÇILMAZ. */}
      {target && (
        <div
          style={{ position: 'fixed', inset: 0, zIndex: 100, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'rgba(2,6,23,0.75)', padding: 16 }}
          onClick={() => { if (!busy) setTarget(null); }}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{ width: '100%', maxWidth: 460, borderRadius: 12, border: '1px solid #7f1d1d', background: '#0f172a', padding: 20, color: '#e2e8f0' }}
          >
            <h2 style={{ margin: 0, fontSize: 17, fontWeight: 800, color: '#fca5a5' }}>Müşteriyi kalıcı olarak sil?</h2>
            <p style={{ marginTop: 10, fontSize: 13.5, lineHeight: 1.6, color: '#cbd5e1' }}>
              <strong style={{ color: '#e2e8f0' }}>{target.email}</strong> hesabı ve buna bağlı{' '}
              <strong>{target.orderCount} sipariş</strong>, <strong>{target.domainCount} alan adı</strong>,
              tüm <strong>raporlar</strong>, planlı taramalar, onaylar ve fatura talepleri
              <strong style={{ color: '#fca5a5' }}> geri alınamaz şekilde</strong> silinecek.
            </p>
            <p style={{ marginTop: 12, fontSize: 12.5, color: '#94a3b8' }}>
              Onaylamak için müşterinin e-postasını yazın:
            </p>
            <input
              value={confirmText}
              onChange={(e) => setConfirmText(e.target.value)}
              placeholder={target.email}
              autoFocus
              style={{ marginTop: 6, width: '100%', boxSizing: 'border-box', padding: '9px 11px', borderRadius: 8, border: `1px solid ${matches ? '#15803d' : '#334155'}`, background: '#020617', color: '#e2e8f0', fontSize: 13.5, fontFamily: 'ui-monospace, monospace' }}
            />
            {modalError && <p style={{ marginTop: 10, fontSize: 13, color: '#fca5a5' }}>{modalError}</p>}
            <div style={{ marginTop: 16, display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
              <button
                type="button"
                onClick={() => setTarget(null)}
                disabled={busy}
                style={{ padding: '8px 14px', borderRadius: 8, border: '1px solid #334155', background: 'transparent', color: '#cbd5e1', fontSize: 13, fontWeight: 600, cursor: busy ? 'not-allowed' : 'pointer' }}
              >
                Vazgeç
              </button>
              <button
                type="button"
                onClick={doDelete}
                disabled={!matches || busy}
                style={{ padding: '8px 14px', borderRadius: 8, border: 'none', background: !matches || busy ? '#4c1d1d' : '#b91c1c', color: !matches || busy ? '#94a3b8' : '#fff', fontSize: 13, fontWeight: 700, cursor: !matches || busy ? 'not-allowed' : 'pointer' }}
              >
                {busy ? 'Siliniyor…' : 'Kalıcı olarak sil'}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
